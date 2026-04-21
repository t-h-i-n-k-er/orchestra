use base64::Engine;
use common::{config::Config, AuditEvent, Command, CryptoSession, Outcome};
use lazy_static::lazy_static;
use module_loader::Plugin;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use super::{fsops, shell};

lazy_static! {
    static ref SHELL_SESSIONS: Mutex<HashMap<String, Arc<Mutex<shell::ShellSession>>>> =
        Mutex::new(HashMap::new());
    static ref LOADED_PLUGINS: Mutex<HashMap<String, Box<dyn Plugin + Send + Sync>>> =
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

fn make_audit(action: &str, outcome: Outcome, details: &str) -> AuditEvent {
    let agent_id = System::host_name().unwrap_or_else(|| "unknown".to_string());
    AuditEvent::new(&agent_id, "admin", action, details, outcome)
}

fn is_path_allowed(path: &str, config: &Config) -> bool {
    config.allowed_paths.iter().any(|a| path.starts_with(a.as_str()))
}

pub async fn handle_command(
    crypto: Arc<CryptoSession>,
    config: Arc<TokioMutex<Config>>,
    command: Command,
) -> (Result<String, String>, AuditEvent) {
    let action = sanitize_action(&command);

    let result: Result<String, String> = match command {
        Command::Ping => Ok("pong".to_string()),
        Command::GetSystemInfo => handle_system_info(),
        Command::RunApprovedScript { ref script } => handle_run_approved_script(script),

        Command::ListDirectory { ref path } => {
            let cfg = config.lock().await;
            if !is_path_allowed(path, &cfg) {
                Err("Path not permitted by policy".to_string())
            } else {
                match fsops::list_directory(path).await {
                    Ok(entries) => Ok(serde_json::to_string(&entries).unwrap_or_default()),
                    Err(e) => Err(e.to_string()),
                }
            }
        }

        Command::ReadFile { ref path } => {
            let cfg = config.lock().await;
            if !is_path_allowed(path, &cfg) {
                Err("Path not permitted by policy".to_string())
            } else {
                match fsops::read_file(path).await {
                    Ok(content) => Ok(base64::engine::general_purpose::STANDARD.encode(&content)),
                    Err(e) => Err(e.to_string()),
                }
            }
        }

        Command::WriteFile { ref path, ref content } => {
            let cfg = config.lock().await;
            if !is_path_allowed(path, &cfg) {
                Err("Path not permitted by policy".to_string())
            } else {
                match fsops::write_file(path, content).await {
                    Ok(_) => Ok("success".to_string()),
                    Err(e) => Err(e.to_string()),
                }
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

        Command::ShellInput { ref session_id, ref data } => {
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
        Command::GetHciLogBuffer => super::hci_logging::get_log_buffer(),
        #[cfg(not(feature = "hci-research"))]
        Command::GetHciLogBuffer => Err("hci-research feature not enabled".to_string()),

        Command::DeployModule { ref module_id } => {
            let path = format!("./target/debug/lib{}.so", module_id);
            match fsops::read_file(&path).await {
                Err(e) => Err(format!("Failed to read module blob: {e}")),
                Ok(blob) => match module_loader::load_plugin(&blob, &crypto) {
                    Ok(plugin) => {
                        LOADED_PLUGINS.lock().unwrap().insert(module_id.clone(), plugin);
                        Ok("Module deployed".to_string())
                    }
                    Err(e) => Err(e.to_string()),
                },
            }
        }

        Command::ExecutePlugin { ref plugin_id, ref args } => {
            let plugins = LOADED_PLUGINS.lock().unwrap();
            match plugins.get(plugin_id) {
                Some(plugin) => plugin.execute(args).map_err(|e| e.to_string()),
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

        Command::Shutdown => std::process::exit(0),
    };

    let (outcome, details) = match &result {
        Ok(s) => (Outcome::Success, s.as_str()),
        Err(e) => (Outcome::Failure, e.as_str()),
    };
    let audit = make_audit(&action, outcome, details);
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
