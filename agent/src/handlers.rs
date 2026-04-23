use base64::Engine;
use common::{config::Config, AuditEvent, Command, CryptoSession, Outcome};
use lazy_static::lazy_static;
use module_loader::Plugin;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use super::{fsops, shell};

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

lazy_static! {
    static ref SHELL_SESSIONS: Mutex<HashMap<String, Arc<Mutex<shell::ShellSession>>>> =
        Mutex::new(HashMap::new());
    static ref LOADED_PLUGINS: Mutex<HashMap<String, Arc<Box<dyn Plugin + Send + Sync>>>> =
        Mutex::new(HashMap::new());
    pub static ref SHUTDOWN_NOTIFY: Arc<tokio::sync::Notify> = Arc::new(tokio::sync::Notify::new());
}

fn sanitize_action(cmd: &Command) -> String {
    match cmd {
        Command::WriteFile { path, .. } => format!("WriteFile(path={path:?})"),
        Command::ShellInput { session_id, .. } => format!("ShellInput(session={session_id})"),
        Command::ReadFile { path } => format!("ReadFile(path={path:?})"),
        other => format!("{other:?}"),
    }
}

pub(crate) fn make_audit(action: &str, outcome: Outcome, details: &str, operator_id: &str) -> AuditEvent {
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
) -> Result<String, String> {
    if !is_valid_module_id(&module_name) {
        return Err(format!(
            "ModulePush rejected: invalid module_name '{}' (allowed: [a-zA-Z0-9_-]{{1,128}})",
            module_name
        ));
    }
    match module_loader::load_plugin(encrypted_blob, crypto) {
        Ok(plugin) => {
            LOADED_PLUGINS
                .lock()
                .unwrap()
                .insert(module_name.clone(), Arc::new(plugin));
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
) -> (Result<String, String>, AuditEvent) {
    let action = sanitize_action(&command);

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
            let hosts = super::net_discovery::arp_scan().unwrap_or_default();
            Ok(serde_json::json!({ "arp_hosts": hosts }).to_string())
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
                let path = Path::new(&cfg.module_cache_dir).join(format!("{}.so", module_id));
                let path_str = path.to_string_lossy().into_owned();
                match fsops::read_file(&path_str, &cfg).await {
                    Err(e) => Err(format!("Failed to read module blob: {e}")),
                    Ok(blob) => match module_loader::load_plugin(&blob, &crypto) {
                        Ok(plugin) => {
                            LOADED_PLUGINS
                                .lock()
                                .unwrap()
                                .insert(module_id.clone(), Arc::new(plugin));
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
            // before calling execute() so other plugin operations (DeployModule,
            // subsequent ExecutePlugin calls) are not serialised behind a
            // long-running plugin execution.
            let maybe_plugin = {
                let plugins = LOADED_PLUGINS.lock().unwrap();
                plugins.get(plugin_id).map(Arc::clone)
            };
            match maybe_plugin {
                Some(plugin) => (**plugin).execute(args).map_err(|e| e.to_string()),
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

        Command::Shutdown => { SHUTDOWN_NOTIFY.notify_one(); Ok("Agent shutdown sequence initiated".to_string()) },
    };

    let (outcome, details) = match &result {
        Ok(s) => (Outcome::Success, s.as_str()),
        Err(e) => (Outcome::Failure, e.as_str()),
    };
    let audit = make_audit(&action, outcome, details, operator_id);
    (result, audit)
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
        let (res, audit) = handle_command(
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
        let blob_path = cache.path().join("test_mod.so");
        std::fs::write(&blob_path, b"not-a-real-plugin").unwrap();

        let cfg = Config {
            allowed_paths: vec![cache.path().to_string_lossy().into_owned()],
            module_cache_dir: cache.path().to_string_lossy().into_owned(),
            ..Config::default()
        };
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let cfg_arc = Arc::new(TokioMutex::new(cfg));

        let (res, _audit) = handle_command(
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
}
