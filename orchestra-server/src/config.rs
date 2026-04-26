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
        }
    }
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let body = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&body)?)
    }
}
