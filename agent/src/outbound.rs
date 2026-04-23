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
use uuid::Uuid;

// Compile-time constants injected by the Builder (may be absent in manual builds).
const BAKED_ADDR: Option<&str> = option_env!("ORCHESTRA_C_ADDR");
const BAKED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");
const BAKED_CERT_FP: Option<&str> = option_env!("ORCHESTRA_C_CERT_FP");


const MAX_BACKOFF_SECS: u64 = 64;

/// Resolve the server address: runtime env var beats compile-time constant.
pub fn resolve_addr() -> Option<String> {
    std::env::var("ORCHESTRA_C")
        .ok()
        .or_else(|| BAKED_ADDR.map(str::to_string))
}

/// Resolve the pre-shared secret: runtime env var beats compile-time constant.
pub fn resolve_secret() -> Option<String> {
    std::env::var("ORCHESTRA_SECRET")
        .ok()
        .or_else(|| BAKED_SECRET.map(str::to_string))
}

/// Connect once, run the agent command loop until transport error or
/// clean shutdown. Returns `Ok(())` on a clean `Shutdown` command.
async fn connect_once(addr: &str, secret: &str, agent_id: &str) -> Result<()> {
    info!("outbound-c: connecting to Control Center addr={addr} agent_id={agent_id}");

    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    // Build a TLS client config.  When `server_cert_fingerprint` is configured
    // in agent.toml, pin the server's end-entity certificate by its SHA-256
    // fingerprint (prevents MITM even without a trusted CA).  Without a
    // fingerprint the agent falls back to validating the certificate against the
    // system's native root CA store, which prevents trivial interception while
    // remaining compatible with certificates issued by enterprise PKIs.
    let tls_config: rustls::ClientConfig = {
        let cfg = crate::config::load_config()?;
        let fingerprint = cfg.server_cert_fingerprint.or_else(|| BAKED_CERT_FP.map(|s| s.to_string()));
        if let Some(fp) = fingerprint {
            info!("outbound-c: using certificate pinning (fingerprint configured)");
            let verifier = common::tls_transport::PinnedCertVerifier::from_hex(&fp)
                .map_err(|e| anyhow::anyhow!("invalid server_cert_fingerprint: {e}"))?;
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
                .with_no_client_auth()
        } else {
            warn!(
                "outbound-c: server_cert_fingerprint not configured — \
                 falling back to system root CA verification. \
                 Set server_cert_fingerprint in agent.toml for certificate pinning."
            );
            let mut root_store = rustls::RootCertStore::empty();
            let certs = rustls_native_certs::load_native_certs();
            if let Some(err) = certs.errors.first() {
                warn!(
                    "Some errors occurred compiling system root certificates: {}",
                    err
                );
            }
            if certs.certs.is_empty() {
                return Err(anyhow::anyhow!(
                    "failed to load any native root certificates"
                ));
            }
            for cert in certs.certs {
                root_store.add(cert).ok(); // skip individual malformed certs
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    // Extract the hostname from `addr` (host:port) for SNI so the server can
    // select the correct certificate and we avoid false-positive monitoring alerts.
    let sni_host = addr.split(':').next().unwrap_or(addr);
    let domain = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server hostname '{sni_host}' for TLS SNI: {e}"))?
        .to_owned();
    let tls_stream = connector.connect(domain, stream).await?;

    let session = common::CryptoSession::from_shared_secret(secret.as_bytes());
    let mut tls_transport = common::tls_transport::TlsTransport::new(tls_stream, session);

    // Announce ourselves before handing the transport to the Agent.
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

    // Box the transport and run the normal agent loop.
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
