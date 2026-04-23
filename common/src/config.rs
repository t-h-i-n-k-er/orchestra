use crate::normalized_transport::TrafficProfile;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub persistence_enabled: bool,
    #[serde(default = "default_module_repo")]
    pub module_repo_url: String,
    /// Base64-encoded AES-256 key used to decrypt signed capability modules.
    pub module_signing_key: Option<String>,
    /// Directory from which `DeployModule` loads pre-staged module blobs.
    /// Defaults to `~/.cache/orchestra/modules` on Unix and
    /// `%LOCALAPPDATA%\Orchestra\modules` on Windows.
    #[serde(default = "default_module_cache_dir")]
    pub module_cache_dir: String,
    /// Wire-level traffic shaping profile. See [`TrafficProfile`] and
    /// [`crate::normalized_transport`] for details.
    #[serde(default)]
    pub traffic_profile: TrafficProfile,
    /// If set, the agent will refuse to start unless the host machine is
    /// joined to this DNS domain (case-insensitive).
    #[serde(default)]
    pub required_domain: Option<String>,
    /// When `true`, the agent refuses to start when virtualization or
    /// sandbox artifacts are detected. Defaults to `false` because most
    /// legitimate enterprise endpoints today are virtualized.
    #[serde(default)]
    pub refuse_in_vm: bool,
    /// SHA-256 fingerprint (64 lowercase hex chars) of the Orchestra Control
    /// Center's TLS certificate. When set, `outbound-c` mode pins the server
    /// certificate instead of accepting any certificate.
    ///
    /// Generate with:
    ///   openssl x509 -in server.crt -outform DER | sha256sum
    #[serde(default)]
    pub server_cert_fingerprint: Option<String>,
    /// Maximum number of concurrent connections for port scanning.
    #[serde(default = "default_port_scan_concurrency")]
    pub port_scan_concurrency: usize,
    /// Timeout in milliseconds for each port connection during scans.
    #[serde(default = "default_port_scan_timeout")]
    pub port_scan_timeout_ms: u64,
}

fn default_allowed_paths() -> Vec<String> {
    vec!["/var/log".into(), "/home".into(), "/tmp".into()]
}

fn default_heartbeat() -> u64 {
    30
}

fn default_port_scan_concurrency() -> usize {
    50
}

fn default_port_scan_timeout() -> u64 {
    200
}

fn default_module_repo() -> String {
    "https://updates.example.com/modules".into()
}

pub fn default_module_cache_dir() -> String {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
        base.join("Orchestra")
            .join("modules")
            .to_string_lossy()
            .into_owned()
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        home.join(".cache")
            .join("orchestra")
            .join("modules")
            .to_string_lossy()
            .into_owned()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_paths: default_allowed_paths(),
            heartbeat_interval_secs: default_heartbeat(),
            persistence_enabled: false,
            module_repo_url: default_module_repo(),
            module_signing_key: None,
            module_cache_dir: default_module_cache_dir(),
            traffic_profile: TrafficProfile::default(),
            required_domain: None,
            refuse_in_vm: false,
            server_cert_fingerprint: None,
            port_scan_concurrency: default_port_scan_concurrency(),
            port_scan_timeout_ms: default_port_scan_timeout(),
        }
    }
}
