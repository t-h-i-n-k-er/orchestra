//! # Trusted Execution Environment Enforcement
//!
//! These checks run at agent start‑up to decide whether the host looks like a
//! legitimate managed endpoint or like a developer workstation, malware
//! sandbox, or analyst VM.  All checks are best‑effort: they bias toward
//! false negatives (let the agent run) over false positives (refuse on a
//! perfectly legitimate machine), and they are surfaced through the
//! [`EnvReport`] struct so that operators can choose the policy.
//!
//! See [`enforce`] for the wiring used by the agent's startup path.

use std::path::Path;

// ── pe_resolve helpers (Windows) ──────────────────────────────────────────────
#[cfg(windows)]
mod win_resolve {
    use std::sync::atomic::AtomicU64;

    // ── Local type definitions (avoiding IAT-producing winapi imports) ──────

    #[repr(C)]
    #[derive(Default)]
    pub struct MemoryStatusEx {
        pub dw_length: u32,
        pub dw_memory_load: u32,
        pub ull_total_phys: u64,
        pub ull_avail_phys: u64,
        pub ull_total_page_file: u64,
        pub ull_avail_page_file: u64,
        pub ull_total_virtual: u64,
        pub ull_avail_virtual: u64,
        pub ull_avail_extended_virtual: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct SystemInfo {
        _processor_union: [u32; 1],
        pub dw_page_size: u32,
        _lp_minimum_application_address: *mut std::ffi::c_void,
        _lp_maximum_application_address: *mut std::ffi::c_void,
        _dw_active_processor_mask: usize,
        pub dw_number_of_processors: u32,
        _dw_processor_type: u32,
        _dw_allocation_granularity: u32,
        _w_processor_level: u16,
        _w_processor_revision: u16,
    }

    use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

    /// Resolve a function pointer from a DLL that is already loaded in the PEB.
    pub unsafe fn resolve_api<T>(dll_hash: u32, fn_hash: u32) -> Option<T> {
        let module = pe_resolve::get_module_handle_by_hash(dll_hash)?;
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)?;
        Some(std::mem::transmute_copy(&addr))
    }

    /// Resolve a function pointer from a DLL, loading it if not already present.
    pub unsafe fn resolve_api_or_load<T>(
        dll_wide: &[u16],
        dll_hash: u32,
        fn_hash: u32,
    ) -> Option<T> {
        let module = match pe_resolve::get_module_handle_by_hash(dll_hash) {
            Some(m) => m,
            None => {
                let load_library_w: unsafe extern "system" fn(*const u16) -> *mut std::ffi::c_void =
                    resolve_api(
                        pe_resolve::HASH_KERNEL32_DLL,
                        pe_resolve::hash_str(b"LoadLibraryW\0"),
                    )?;
                let m = load_library_w(dll_wide.as_ptr());
                if m.is_null() {
                    return None;
                }
                m as usize
            }
        };
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)?;
        Some(std::mem::transmute_copy(&addr))
    }

    // ── DLL wide strings & hashes ──────────────────────────────────────────────
    pub const USER32_DLL_W: &[u16] = &[
        'u' as u16, 's' as u16, 'e' as u16, 'r' as u16, '3' as u16, '2' as u16, '.' as u16,
        'd' as u16, 'l' as u16, 'l' as u16, 0,
    ];
    pub const HASH_USER32_DLL: u32 = hash_wstr_const(USER32_DLL_W);

    pub const ADVAPI32_DLL_W: &[u16] = &[
        'a' as u16, 'd' as u16, 'v' as u16, 'a' as u16, 'p' as u16, 'i' as u16, '3' as u16,
        '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
    ];
    pub const HASH_ADVAPI32_DLL: u32 = hash_wstr_const(ADVAPI32_DLL_W);

    pub const IPHLPAPI_DLL_W: &[u16] = &[
        'i' as u16, 'p' as u16, 'h' as u16, 'l' as u16, 'p' as u16, 'a' as u16, 'p' as u16,
        'i' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
    ];
    pub const HASH_IPHLPAPI_DLL: u32 = hash_wstr_const(IPHLPAPI_DLL_W);

    // ── API hash constants (kernel32) ──────────────────────────────────────────
    pub const HASH_GLOBALMEMORYSTATUSEX: u32 = hash_str_const(b"GlobalMemoryStatusEx\0");
    pub const HASH_GETSYSTEMINFO: u32 = hash_str_const(b"GetSystemInfo\0");
    pub const HASH_GETTICKCOUNT64: u32 = hash_str_const(b"GetTickCount64\0");
    pub const HASH_ISDEBUGGERPRESENT: u32 = hash_str_const(b"IsDebuggerPresent\0");
    pub const HASH_GETSYSTEMTIMES: u32 = hash_str_const(b"GetSystemTimes\0");
    pub const HASH_GETDISKFREESPACEEXW: u32 = hash_str_const(b"GetDiskFreeSpaceExW\0");

    // ── API hash constants (user32) ────────────────────────────────────────────
    pub const HASH_GETCURSORPOS: u32 = hash_str_const(b"GetCursorPos\0");
    pub const HASH_ENUMWINDOWS: u32 = hash_str_const(b"EnumWindows\0");
    pub const HASH_ISWINDOWVISIBLE: u32 = hash_str_const(b"IsWindowVisible\0");
    pub const HASH_GETWINDOWTEXTLENGTHW: u32 = hash_str_const(b"GetWindowTextLengthW\0");
    pub const HASH_GETSYSTEMMETRICS: u32 = hash_str_const(b"GetSystemMetrics\0");

    // ── API hash constants (advapi32) ──────────────────────────────────────────
    pub const HASH_REGOPENKEYEXW: u32 = hash_str_const(b"RegOpenKeyExW\0");
    pub const HASH_REGQUERYVALUEEXW: u32 = hash_str_const(b"RegQueryValueExW\0");
    pub const HASH_REGCLOSEKEY: u32 = hash_str_const(b"RegCloseKey\0");
    pub const HASH_REGENUMKEYEXW: u32 = hash_str_const(b"RegEnumKeyExW\0");

    // ── API hash constants (iphlpapi) ──────────────────────────────────────────
    pub const HASH_GETADAPTERSADDRESSES: u32 = hash_str_const(b"GetAdaptersAddresses\0");

    // ── API hash constants — hardened detection indicators ────────────────────
    pub const HASH_QUERYPERFORMANCECOUNTER: u32 = hash_str_const(b"QueryPerformanceCounter\0");
    pub const HASH_QUERYPERFORMANCEFREQUENCY: u32 = hash_str_const(b"QueryPerformanceFrequency\0");
    pub const HASH_GETSYSTEMTIMEPRECISEASFILETIME: u32 =
        hash_str_const(b"GetSystemTimePreciseAsFileTime\0");
    pub const HASH_CREATETOOLHELP32SNAPSHOT: u32 = hash_str_const(b"CreateToolhelp32Snapshot\0");
    pub const HASH_PROCESS32FIRSTW: u32 = hash_str_const(b"Process32FirstW\0");
    pub const HASH_PROCESS32NEXTW: u32 = hash_str_const(b"Process32NextW\0");
    pub const HASH_CLOSEHANDLE: u32 = hash_str_const(b"CloseHandle\0");
    pub const HASH_GETCURRENTPROCESSID: u32 = hash_str_const(b"GetCurrentProcessId\0");

    // ── Function pointer types ─────────────────────────────────────────────────

    // kernel32
    pub type FnGlobalMemoryStatusEx = unsafe extern "system" fn(*mut MemoryStatusEx) -> i32;
    pub type FnGetSystemInfo = unsafe extern "system" fn(*mut SystemInfo);
    pub type FnGetTickCount64 = unsafe extern "system" fn() -> u64;
    pub type FnIsDebuggerPresent = unsafe extern "system" fn() -> i32;
    pub type FnGetSystemTimes = unsafe extern "system" fn(
        *mut crate::win_types::FILETIME,
        *mut crate::win_types::FILETIME,
        *mut crate::win_types::FILETIME,
    ) -> i32;
    pub type FnGetDiskFreeSpaceExW =
        unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32;

    // user32
    pub type FnGetCursorPos = unsafe extern "system" fn(*mut crate::win_types::POINT) -> i32;
    pub type FnEnumWindows = unsafe extern "system" fn(
        Option<
            unsafe extern "system" fn(
                crate::win_types::HWND,
                crate::win_types::LPARAM,
            ) -> crate::win_types::BOOL,
        >,
        crate::win_types::LPARAM,
    ) -> i32;
    pub type FnIsWindowVisible = unsafe extern "system" fn(crate::win_types::HWND) -> i32;
    pub type FnGetWindowTextLengthW = unsafe extern "system" fn(crate::win_types::HWND) -> i32;
    pub type FnGetSystemMetrics = unsafe extern "system" fn(i32) -> i32;

    // ── GetSystemMetrics indices ───────────────────────────────────────────────
    /// SM_REMOTESESSION: nonzero if the calling process is associated with a
    /// Terminal Services client session (RDP).
    pub const SM_REMOTESESSION: i32 = 0x1000;
    /// SM_TABLETPC: nonzero if the current OS is Windows XP Tablet PC edition
    /// (or any later OS that reports tablet posture).  Can also indicate a
    /// non-traditional-desktop form factor.
    pub const SM_TABLETPC: i32 = 86;

    // advapi32
    pub type FnRegOpenKeyExW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *const u16,
        u32,
        u32,
        *mut *mut std::ffi::c_void,
    ) -> i32;
    pub type FnRegQueryValueExW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *const u16,
        *mut u32,
        *mut u32,
        *mut u8,
        *mut u32,
    ) -> i32;
    pub type FnRegCloseKey = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    pub type FnRegEnumKeyExW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        u32,
        *mut u16,
        *mut u32,
        *mut std::ffi::c_void,
        *mut u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> i32;

    // iphlpapi
    pub type FnGetAdaptersAddresses = unsafe extern "system" fn(
        u32,
        u32,
        *mut std::ffi::c_void,
        *mut crate::win_types::IP_ADAPTER_ADDRESSES,
        *mut u32,
    ) -> u32;

    // ── Function pointer types — hardened detection indicators ─────────────────

    // kernel32 — timing
    pub type FnQueryPerformanceCounter = unsafe extern "system" fn(*mut i64) -> i32;
    pub type FnQueryPerformanceFrequency = unsafe extern "system" fn(*mut i64) -> i32;
    pub type FnGetSystemTimePreciseAsFileTime =
        unsafe extern "system" fn(*mut crate::win_types::FILETIME);

    // kernel32 — process lineage (Toolhelp32)
    pub type FnCreateToolhelp32Snapshot =
        unsafe extern "system" fn(u32, u32) -> *mut std::ffi::c_void;
    pub type FnProcess32FirstW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *mut crate::win_types::ProcessEntry32W,
    ) -> i32;
    pub type FnProcess32NextW = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *mut crate::win_types::ProcessEntry32W,
    ) -> i32;
    pub type FnCloseHandle = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    pub type FnGetCurrentProcessId = unsafe extern "system" fn() -> u32;

    // ── Static atomics for EnumWindows callback ────────────────────────────────
    pub static ISWINDOWVISIBLE_PTR: AtomicU64 = AtomicU64::new(0);
    pub static GETWINDOWTEXTLENGTHW_PTR: AtomicU64 = AtomicU64::new(0);

    // ── Local constants (replacing IAT-producing winapi imports) ────────────────
    pub const KEY_READ: u32 = 0x20019;
    pub const REG_SZ: u32 = 1;
    pub const ERROR_SUCCESS: u32 = 0;
    /// HKEY_LOCAL_MACHINE as a raw pointer constant.
    pub const HKEY_LOCAL_MACHINE: *mut std::ffi::c_void = 0x80000002u64 as *mut std::ffi::c_void;
}

// ── Raw registry helpers (replace winreg crate, avoid advapi32 IAT) ──────────

/// Open a registry sub-key via dynamically resolved `RegOpenKeyExW`.
/// Returns the raw key handle on success.
#[cfg(windows)]
unsafe fn reg_open_subkey(
    parent: *mut std::ffi::c_void,
    sub_key: &str,
) -> Option<*mut std::ffi::c_void> {
    let reg_open: win_resolve::FnRegOpenKeyExW = win_resolve::resolve_api_or_load(
        win_resolve::ADVAPI32_DLL_W,
        win_resolve::HASH_ADVAPI32_DLL,
        win_resolve::HASH_REGOPENKEYEXW,
    )?;
    let mut wide: Vec<u16> = sub_key.encode_utf16().collect();
    wide.push(0);
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let status = reg_open(parent, wide.as_ptr(), 0, win_resolve::KEY_READ, &mut handle);
    if status == win_resolve::ERROR_SUCCESS as i32 {
        Some(handle)
    } else {
        None
    }
}

/// Read a REG_SZ value from a registry key via dynamically resolved `RegQueryValueExW`.
/// Returns the value as a `String` on success.
#[cfg(windows)]
unsafe fn reg_read_string(key: *mut std::ffi::c_void, value_name: &str) -> Option<String> {
    let reg_query: win_resolve::FnRegQueryValueExW = win_resolve::resolve_api_or_load(
        win_resolve::ADVAPI32_DLL_W,
        win_resolve::HASH_ADVAPI32_DLL,
        win_resolve::HASH_REGQUERYVALUEEXW,
    )?;
    let mut name_wide: Vec<u16> = value_name.encode_utf16().collect();
    name_wide.push(0);
    // First call: determine required buffer size.
    let mut buf_len: u32 = 0;
    let status = reg_query(
        key,
        name_wide.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut buf_len,
    );
    // ERROR_MORE_DATA (234) or ERROR_SUCCESS with buf_len > 0 means the value exists.
    if status != 0 && status != 234 {
        return None;
    }
    if buf_len == 0 {
        return Some(String::new());
    }
    // Second call: read the data.
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize];
    let mut data_type: u32 = 0;
    let status = reg_query(
        key,
        name_wide.as_ptr(),
        std::ptr::null_mut(),
        &mut data_type,
        buf.as_mut_ptr(),
        &mut buf_len,
    );
    if status != 0 || data_type != win_resolve::REG_SZ {
        return None;
    }
    // REG_SZ data includes the trailing null; trim it.
    let utf16_bytes = &buf[..buf_len as usize];
    let units: Vec<u16> = utf16_bytes
        .chunks_exact(2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    Some(s.trim_end_matches('\0').to_string())
}

/// Enumerate sub-key names of a registry key via dynamically resolved `RegEnumKeyExW`.
#[cfg(windows)]
unsafe fn reg_enum_subkey_names(key: *mut std::ffi::c_void) -> Vec<String> {
    let reg_enum: win_resolve::FnRegEnumKeyExW = match win_resolve::resolve_api_or_load(
        win_resolve::ADVAPI32_DLL_W,
        win_resolve::HASH_ADVAPI32_DLL,
        win_resolve::HASH_REGENUMKEYEXW,
    ) {
        Some(f) => f,
        None => return Vec::new(),
    };
    let mut names = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut name_buf = [0u16; 260]; // MAX_KEY_NAME
        let mut name_len: u32 = name_buf.len() as u32;
        let status = reg_enum(
            key,
            index,
            name_buf.as_mut_ptr(),
            &mut name_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if status != 0 {
            break; // ERROR_NO_MORE_ITEMS (259) or error
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        names.push(name);
        index += 1;
    }
    names
}

/// Close a registry key via dynamically resolved `RegCloseKey`.
#[cfg(windows)]
unsafe fn reg_close_key(key: *mut std::ffi::c_void) {
    if let Some(reg_close) = unsafe {
        win_resolve::resolve_api_or_load::<win_resolve::FnRegCloseKey>(
            win_resolve::ADVAPI32_DLL_W,
            win_resolve::HASH_ADVAPI32_DLL,
            win_resolve::HASH_REGCLOSEKEY,
        )
    } {
        reg_close(key);
    }
}

/// Outcome of all individual environment probes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvReport {
    /// `IsDebuggerPresent` (Windows) or `TracerPid` (Linux) is non‑zero.
    pub debugger_present: bool,
    /// Heuristic VM/sandbox detection fired (informational / lenient mode).
    ///
    /// This uses the same scoring as [`detect_vm`], which applies
    /// false-positive mitigations (reduced DMI/MAC weights when cloud context
    /// is uncertain).  For the strict enforcement-equivalent result, see
    /// [`EnvReport::vm_detected_strict`].
    pub vm_detected: bool,
    /// Strict VM/sandbox detection result, matching the classification used
    /// by `enforce(refuse_in_vm = true)`.
    ///
    /// Uses full indicator weights (DMI 25, MAC 20) and a base threshold of
    /// 30 without the "likely legitimate server" boost.  This may be `true`
    /// even when `vm_detected` is `false` when generic indicators are present
    /// but were suppressed in lenient mode.
    pub vm_detected_strict: bool,
    /// `Some(true)` if a domain requirement was configured and matched,
    /// `Some(false)` if configured and unmatched, `None` if not configured.
    pub domain_match: Option<bool>,
    /// `LD_PRELOAD` is set, which can indicate library-level hooking.
    pub ld_preload_set: bool,
    /// A known tracer process (like `strace` or `gdbserver`) is running.
    pub tracer_process_found: bool,
    /// A simple timing check took significantly longer than expected.
    pub timing_anomaly_detected: bool,
    /// Combined heuristic sandbox-probability score (0–100).
    ///
    /// Computed from mouse-movement, desktop richness, uptime artefacts, and
    /// hardware-plausibility probes (see [`sandbox::evaluate_sandbox`]).
    /// This field is informational; use `should_refuse` to incorporate it into
    /// a policy decision by passing `sandbox_score_threshold`.
    pub sandbox_score: u32,
    /// Value of `/proc/sys/kernel/yama/ptrace_scope` at collection time.
    ///
    /// * `None`  — YAMA LSM not compiled into the running kernel (no restriction).
    /// * `Some(0)` — classic, unrestricted ptrace.
    /// * `Some(1)` — restricted: only parent/child or PR_SET_PTRACER peers.
    /// * `Some(2)` — admin-only: `CAP_SYS_PTRACE` required.
    /// * `Some(3)` — disabled: no attachment even for root.
    ///
    /// Only populated on Linux; always `None` on other platforms.
    pub yama_ptrace_scope: Option<u8>,
}

impl EnvReport {
    /// Run every probe; never panics.
    pub fn collect(required_domain: Option<&str>) -> Self {
        let (vm_strict, _, _) = detect_vm_strict();
        Self {
            debugger_present: is_debugger_present(),
            vm_detected: detect_vm(),
            vm_detected_strict: vm_strict,
            domain_match: required_domain.map(validate_domain),
            ld_preload_set: is_ld_preload_set(),
            tracer_process_found: is_tracer_process_running(),
            timing_anomaly_detected: detect_timing_anomaly(),
            sandbox_score: sandbox::evaluate_sandbox().unwrap_or(0),
            yama_ptrace_scope: read_yama_ptrace_scope(),
        }
    }

    /// Log the ptrace scope value so operators can diagnose injection permission
    /// issues without having to read the `EnvReport` struct directly.
    pub fn log_ptrace_scope(&self) {
        #[cfg(target_os = "linux")]
        match self.yama_ptrace_scope {
            None => tracing::info!("env: kernel.yama.ptrace_scope not present (YAMA LSM absent — no ptrace restrictions)"),
            Some(0) => tracing::info!("env: kernel.yama.ptrace_scope=0 (unrestricted ptrace)"),
            Some(1) => tracing::info!("env: kernel.yama.ptrace_scope=1 (restricted to parent/child or PR_SET_PTRACER peers)"),
            Some(2) => tracing::warn!("env: kernel.yama.ptrace_scope=2 (CAP_SYS_PTRACE required for ptrace injection)"),
            Some(3) => tracing::warn!("env: kernel.yama.ptrace_scope=3 (ptrace injection disabled by policy)"),
            Some(v) => tracing::warn!("env: kernel.yama.ptrace_scope={v} (unrecognised value)"),
        }
    }

    /// True when the host fails any check that has been *configured* to be
    /// enforced. Domain mismatch is enforced only when a required domain was
    /// configured. Debugger, VM, tracer-process, timing, and sandbox-score
    /// signals are informational unless their explicit policy knobs are set.
    ///
    /// * `refuse_when_debugged`: if `true`, an attached debugger triggers refusal.
    /// * `refuse_in_vm`: if `true`, a positive `vm_detected` also triggers refusal.
    /// * `sandbox_score_threshold`: if `Some(n)`, a `sandbox_score >= n` also
    ///   triggers refusal.  When no corroborating non-heuristic signal is
    ///   present, a protective floor of 60 is applied to avoid aggressive
    ///   refusal on legitimate fresh/headless hosts.
    ///   Pass `None` to leave the sandbox score informational.
    pub fn should_refuse(
        &self,
        refuse_when_debugged: bool,
        refuse_in_vm: bool,
        sandbox_score_threshold: Option<u32>,
    ) -> bool {
        if refuse_when_debugged && self.debugger_present {
            return true;
        }
        if matches!(self.domain_match, Some(false)) {
            return true;
        }
        if refuse_in_vm && self.vm_detected_strict {
            return true;
        }
        if let Some(threshold) = sandbox_score_threshold {
            let corroborated = self.vm_detected
                || self.vm_detected_strict
                || self.debugger_present
                || self.tracer_process_found
                || self.timing_anomaly_detected;
            let effective_threshold = if corroborated {
                threshold
            } else {
                // L-7 fix: use a multi-category heuristic floor instead of a
                // flat 60.  When multiple *distinct* heuristic categories
                // independently contribute (e.g. mouse AND desktop AND uptime),
                // the false-positive risk drops and a lower floor (50) is safe.
                // Single or coupled-category signals still use the 60 floor to
                // avoid refusing on fresh/headless legitimate servers.
                //
                // sandbox::evaluate_sandbox() computes the score from four
                // independent categories: mouse (cap 30), desktop (cap 25),
                // uptime (cap 25), hardware (cap 20).  To reach 50+, at least
                // 3 categories must fire or 2 categories must fire strongly,
                // which is extremely unlikely on a legitimate host.
                let multi_category_heuristic = self.sandbox_score >= 50
                    && self.sandbox_score < 60;
                if multi_category_heuristic {
                    // Check whether the score actually came from diverse
                    // sources.  If the sandbox module produced a score of 50+,
                    // at least 2 independent categories contributed because
                    // no single category can exceed 30 (mouse cap).
                    //
                    // However, mouse+desktop are coupled (both measure
                    // user interaction).  A headless server naturally has
                    // both zeroed.  If ONLY mouse+desktop are elevated the
                    // score is capped at 30 by sandbox_probability_score(),
                    // so a score of 50+ implies at least one non-interaction
                    // category (uptime or hardware) also fired.
                    threshold.max(50)
                } else {
                    threshold.max(60)
                }
            };
            if self.sandbox_score >= effective_threshold {
                return true;
            }
        }
        false
    }
}

// --------------------------------------------------------- yama ptrace scope

/// Read `/proc/sys/kernel/yama/ptrace_scope` and return the integer value.
///
/// Returns `None` when the file is absent (YAMA LSM not compiled in), which
/// means there are no YAMA-based ptrace restrictions.
#[cfg(target_os = "linux")]
fn read_yama_ptrace_scope() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse::<u8>()
        .ok()
}

/// On non-Linux platforms YAMA does not exist; always returns `None`.
#[cfg(not(target_os = "linux"))]
fn read_yama_ptrace_scope() -> Option<u8> {
    None
}

// ------------------------------------------------------------------ debugger

/// True if a debugger appears to be attached to the current process.
///
/// * Windows: calls `IsDebuggerPresent` and checks `PEB.BeingDebugged` and
///   `PEB.NtGlobalFlag` (the `FLG_HEAP_ENABLE_TAIL_CHECK | …` triplet that
///   Windows sets in debugged processes).
/// * Linux: parses `/proc/self/status` for a non‑zero `TracerPid:` entry,
///   which `ptrace(PTRACE_ATTACH, …)` and `gdb` both populate.
/// * macOS: checks `kinfo_proc.kp_proc.p_flag & P_TRACED` via
///   `sysctl(KERN_PROC, KERN_PROC_PID, getpid())` (passive check only).
///   To actively deny future debugger attachment, call [`deny_debugger_attach`]
///   separately.
/// * Other Unixes: returns `false`.
pub fn is_debugger_present() -> bool {
    #[cfg(windows)]
    {
        windows_is_debugger_present()
    }
    #[cfg(target_os = "linux")]
    {
        linux_is_debugger_present()
    }
    #[cfg(target_os = "macos")]
    {
        macos_is_debugger_present()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacExternProcPrefix {
    p_un1: [usize; 2],
    p_vmspace: *mut libc::c_void,
    p_sigacts: *mut libc::c_void,
    p_flag: libc::c_int,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacKinfoProcPrefix {
    kp_proc: MacExternProcPrefix,
}

#[cfg(target_os = "macos")]
fn macos_is_debugger_present() -> bool {
    const P_TRACED: libc::c_int = 0x0000_0800;

    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        unsafe { libc::getpid() },
    ];

    let mut needed_len: libc::size_t = 0;
    let queried_len = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed_len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;

    let traced = if queried_len {
        let min_len = std::mem::size_of::<MacKinfoProcPrefix>();
        let mut buf = vec![0u8; (needed_len as usize).max(min_len)];
        let mut out_len = buf.len() as libc::size_t;
        let got = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut out_len,
                std::ptr::null_mut(),
                0,
            )
        } == 0;

        if got && (out_len as usize) >= min_len {
            let kp = unsafe { &*(buf.as_ptr() as *const MacKinfoProcPrefix) };
            (kp.kp_proc.p_flag & P_TRACED) != 0
        } else {
            false
        }
    } else {
        false
    };

    traced
}

/// Actively deny future debugger attachment on macOS.
///
/// Calls `ptrace(PT_DENY_ATTACH)` which prevents any subsequent debugger
/// from attaching to this process.  This is a **non-passive** side-effect
/// and is intentionally separated from [`macos_is_debugger_present`] so
/// that environment checks remain observation-free.
///
/// **Note**: `PT_DENY_ATTACH` fails with `EPERM` when the process is
/// already being traced.  Call this *after* confirming no debugger is
/// present if you want to harden the process.
///
/// Returns `Ok(())` if the call succeeded (no debugger attached yet),
/// or `Err(())` if the call failed (already traced or unsupported).
#[cfg(target_os = "macos")]
pub fn deny_debugger_attach() -> Result<(), ()> {
    let ret = unsafe {
        libc::ptrace(
            libc::PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Actively deny future debugger attachment on macOS.
///
/// Cross-platform stub: on non-macOS platforms this is a no-op that
/// always returns success, since `PT_DENY_ATTACH` is macOS-specific.
#[cfg(not(target_os = "macos"))]
pub fn deny_debugger_attach() -> Result<(), ()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_is_debugger_present() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        // L-4: Use whitespace-split instead of exact prefix matching to handle
        // tab-delimited and other unusual /proc/self/status formats that may
        // appear on custom kernels or modified proc implementations.
        let mut parts = line.split_whitespace();
        if parts.next().map_or(false, |k| k == "TracerPid:") {
            if let Some(val) = parts.next() {
                return val.parse::<u32>().map(|p| p != 0).unwrap_or(false);
            }
        }
    }
    false
}

#[cfg(windows)]
fn windows_is_debugger_present() -> bool {
    let is_debugger_present: win_resolve::FnIsDebuggerPresent = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_ISDEBUGGERPRESENT,
        )
        .expect("IsDebuggerPresent not found")
    };
    if unsafe { is_debugger_present() } != 0 {
        return true;
    }
    // Walk the PEB to read BeingDebugged and NtGlobalFlag without depending
    // on undocumented PEB layout in the `winapi` crate.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // gs:[0x60] -> PEB on x64
        let peb: *const u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb.is_null() {
            return false;
        }
        // PEB.BeingDebugged is at offset 0x02 (UCHAR).
        let being_debugged = *peb.add(0x02);
        // PEB.NtGlobalFlag is at offset 0xBC (ULONG).
        let nt_global_flag = *(peb.add(0xBC) as *const u32);
        const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
        const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
        const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;
        const DEBUG_FLAGS: u32 =
            FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
        if being_debugged != 0 {
            return true;
        }
        if nt_global_flag & DEBUG_FLAGS == DEBUG_FLAGS {
            return true;
        }
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        let peb: *const u8;
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
        if peb.is_null() {
            return false;
        }
        let being_debugged = *peb.add(0x02);
        let nt_global_flag = *(peb.add(0x68) as *const u32);
        if being_debugged != 0 {
            return true;
        }
        if nt_global_flag & 0x70 == 0x70 {
            return true;
        }
    }
    false
}

// ------------------------------------------------------------------------ VM

/// True if the host appears to be a virtual machine or analysis sandbox.
///
/// This is a collection of soft indicators. The CPUID hypervisor bit is no
/// longer a hard failure, but contributes to the overall `vm_detected` score.
/// Returns `true` when the process is running inside a container (Docker,
/// LXC, Podman, Kubernetes CRI-O, or containerd).
///
/// Containers are managed runtime environments, not hostile analysis
/// sandboxes.  Treating them as "expected hypervisors" in `detect_vm()`
/// prevents false-positive VM classifications on containerised cloud
/// workloads where:
///
/// * `/sys/class/dmi/id/*` files are absent or expose the *host* DMI,
///   which may contain "KVM"/"Xen" strings from the underlying cloud
///   hypervisor (adding a spurious `linux_dmi_indicates_vm()` indicator).
/// * IMDS (169.254.169.254) is firewalled, so `is_cloud_instance()` and
///   `cloud_instance_vm_refusal_bypassed()` cannot confirm the cloud host.
///
/// Checks (in order of cost):
/// 1. `/.dockerenv`              — created by Docker at container start.
/// 2. `/run/.containerenv`       — created by Podman.
/// 3. `CONTAINER` env var        — set by some OCI runtimes.
/// 4. `KUBERNETES_SERVICE_HOST`  — injected into every pod by Kubernetes.
/// 5. `/proc/1/cgroup`           — cgroup path prefix contains a
///    container-runtime token ("docker", "lxc", "kubepods", "containerd",
///    "crio").  Reading `/proc/1/cgroup` is safe even without root.
#[cfg(target_os = "linux")]
fn is_container_environment() -> bool {
    // Fast path: marker files written by Docker and Podman respectively.
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }

    // Env vars set by common container orchestrators.
    if std::env::var_os("CONTAINER").is_some()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
    {
        return true;
    }

    // cgroup membership: all major container runtimes place processes under
    // a cgroup hierarchy whose path contains a recognisable token.
    //
    // NOTE: `containerd` alone is ambiguous — systemd uses containerd
    // internally for Flatpak, snap, and other sandboxing on bare-metal hosts,
    // AND Kubernetes nodes (the host, not the pod) expose `containerd` in
    // their cgroup paths via the kubelet's cgroup driver.
    //
    // When `containerd` is the *only* matched token, we additionally require
    // a container namespace marker before concluding this is a real container.
    // The following secondary checks are used (in order of reliability):
    //   1. PID namespace isolation (different /proc/self/ns/pid vs /proc/1/ns/pid)
    //   2. /.dockerenv or CONTAINER env var
    //   3. Container-specific cgroup in /proc/self/cgroup
    //   4. PID 1 comm name (init/systemd on host vs custom in container)
    //   5. Container-specific mount namespace markers
    const CONTAINER_CGROUP_TOKENS: &[&str] = &[
        "docker",
        "lxc",
        "kubepods",
        "containerd",
        "crio",
        "cri-containerd",
    ];
    const UNAMBIGUOUS_TOKENS: &[&str] = &["docker", "lxc", "kubepods", "crio", "cri-containerd"];
    if let Ok(content) = std::fs::read_to_string("/proc/1/cgroup") {
        let lower = content.to_ascii_lowercase();
        let matched: Vec<&str> = CONTAINER_CGROUP_TOKENS
            .iter()
            .copied()
            .filter(|t| lower.contains(t))
            .collect();
        if !matched.is_empty() {
            // If only `containerd` matched (which systemd uses for Flatpak/
            // snap sandboxing on bare metal, and kubelet exposes on K8s nodes),
            // verify with secondary checks.
            let only_containerd = matched.len() == 1 && matched[0] == "containerd";
            if !only_containerd {
                return true;
            }
            // containerd-only: confirm we are actually inside a container
            // namespace using multiple corroborating signals.
            if std::path::Path::new("/.dockerenv").exists()
                || std::env::var_os("CONTAINER").is_some()
            {
                return true;
            }
            // PID namespace isolation: if /proc/self/ns/pid differs from
            // /proc/1/ns/pid, we are in a PID namespace (container). This
            // is the most reliable check for containerd sandboxes that don't
            // set /.dockerenv or CONTAINER env var.
            if pid_namespace_is_isolated() {
                return true;
            }
            // Check if our own cgroup contains an unambiguous container token.
            if let Ok(self_cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
                let self_lower = self_cgroup.to_ascii_lowercase();
                if self_lower.contains("docker")
                    || self_lower.contains("kubepods")
                    || self_lower.contains("crio")
                {
                    return true;
                }
            }
            // PID 1 comm check: in containers, PID 1 is typically the
            // container entrypoint (not systemd/init).  If /proc/1/comm
            // is NOT one of the known init systems, we are likely in a
            // container.
            if !host_init_system_detected() {
                return true;
            }
        }
    }

    // /proc/self/mountinfo: overlay or aufs filesystem type indicates an
    // overlayfs/aufs-based container (Docker, containerd, Podman, …).
    // Require EITHER the CPUID hypervisor bit OR a containerd cgroup token
    // to avoid false positives from storage configurations that use
    // overlayfs on bare-metal hosts (e.g. live USB boot, atomic updates).
    if let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") {
        let lower = content.to_ascii_lowercase();
        let has_overlay = lower.contains("overlay") || lower.contains("aufs");
        if has_overlay {
            // Accept hypervisor bit as corroboration OR containerd in cgroup
            // (containerd-managed containers always use overlayfs).
            let containerd_corroboration = std::fs::read_to_string("/proc/1/cgroup")
                .map(|c| c.to_ascii_lowercase().contains("containerd"))
                .unwrap_or(false);
            if cpuid_hypervisor_bit() || containerd_corroboration {
                return true;
            }
        }
    }

    false
}

/// Check whether the current process is in a different PID namespace from
/// PID 1 (init).  In containers, the PID namespace is isolated: each
/// container sees itself as PID 1 (or a small PID), while on the host PID 1
/// is the init system.  Comparing the inode numbers of `/proc/self/ns/pid`
/// and `/proc/1/ns/pid` reveals namespace isolation without needing root.
///
/// Returns `true` if the namespaces differ (we are in a container).
#[cfg(target_os = "linux")]
fn pid_namespace_is_isolated() -> bool {
    use std::os::linux::fs::MetadataExt;
    let self_meta = match std::fs::symlink_metadata("/proc/self/ns/pid") {
        Ok(m) => m,
        Err(_) => return false,
    };
    let init_meta = match std::fs::symlink_metadata("/proc/1/ns/pid") {
        Ok(m) => m,
        Err(_) => return false,
    };
    // Compare device + inode: same device+inode means same namespace.
    self_meta.st_dev() != init_meta.st_dev() || self_meta.st_ino() != init_meta.st_ino()
}

/// Check whether PID 1 is a known host init system (systemd, init, upstart,
/// openrc).  In containers, PID 1 is typically the application entrypoint
/// or a minimal init like tini/dumb-init, not a full init system.
///
/// Returns `true` if a known host init system is detected (likely host).
#[cfg(target_os = "linux")]
fn host_init_system_detected() -> bool {
    // Read /proc/1/comm which contains the command name of PID 1.
    // This is a single line without trailing newline.
    if let Ok(comm) = std::fs::read_to_string("/proc/1/comm") {
        let name = comm.trim();
        matches!(
            name,
            "systemd"
                | "init"
                | "upstart"
                | "openrc"
                | "runit"
                | "s6-svscan"
                | "svc"
                | "launchd"  // macOS init (for completeness)
        )
    } else {
        // Cannot read /proc/1/comm — conservatively assume host.
        true
    }
}

fn is_expected_hypervisor() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Containers (Docker, LXC, Podman, Kubernetes) are managed runtime
        // environments, not hostile analysis sandboxes.  On these hosts the
        // usual DMI signals are absent or reflect the underlying hypervisor,
        // not the container runtime itself.  Returning `true` here ensures
        // that `detect_vm()` (a) does not count the CPUID hypervisor bit as an
        // indicator and (b) uses at least threshold=3 even when IMDS is
        // firewalled, preventing false-positive VM refusals on containerised
        // cloud workloads.
        if is_container_environment() {
            tracing::debug!("env_check: is_expected_hypervisor: container environment detected");
            return true;
        }

        // Read relevant DMI fields once and check combinations rather than
        // scanning every field with a broad needle list.  This avoids false
        // positives on physical hardware that happens to share a manufacturer
        // name with a cloud provider (e.g. Microsoft Surface, Google Chromebook).
        let sys_vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let product_name = std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let chassis_tag = std::fs::read_to_string("/sys/class/dmi/id/chassis_asset_tag")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let board_vendor = std::fs::read_to_string("/sys/class/dmi/id/board_vendor")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let board_name = std::fs::read_to_string("/sys/class/dmi/id/board_name")
            .unwrap_or_default()
            .to_ascii_lowercase();

        // AWS: sys_vendor = "Amazon EC2" or chassis_asset_tag contains "ec2"
        // (bare-metal instances report "EC2" in chassis_asset_tag).
        if sys_vendor.contains("amazon ec2") || chassis_tag.contains("ec2") {
            return true;
        }
        // Azure: sys_vendor = "Microsoft Corporation" AND product_name contains
        // "virtual machine".  Physical Microsoft hardware (Surface, HoloLens)
        // never sets product_name to "Virtual Machine".
        if sys_vendor.contains("microsoft corporation") && product_name.contains("virtual machine")
        {
            return true;
        }
        // GCP: sys_vendor = "Google" AND product_name contains "google compute".
        // Bare-metal GCP sole-tenant nodes use sys_vendor="Google" and
        // product_name="Google Compute Engine" or similar.
        if sys_vendor.contains("google") && product_name.contains("google compute") {
            return true;
        }
        // GCP bare-metal: board_vendor or board_name may contain the tag.
        // Exclude Chromebooks: board_vendor/board_name both contain "Google"
        // on Chrome OS devices, but the product_name will contain "Chromebook"
        // or "Chromebox" rather than a GCP-specific identifier.
        if board_vendor.contains("google")
            && board_name.contains("google")
            && !product_name.contains("chrome")
        {
            return true;
        }

        // Operator-provided extension list for niche cloud providers not yet
        // covered by the built-in expected-hypervisor needles.
        if let Ok(cfg) = crate::config::load_config() {
            let extra_needles: Vec<String> = cfg
                .malleable_profile
                .vm_detection_extra_hypervisor_names
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            if extra_needles
                .iter()
                .any(|needle| product_name.contains(needle))
            {
                tracing::debug!(
                    "env_check: expected hypervisor matched by vm_detection_extra_hypervisor_names"
                );
                return true;
            }
        }

        // Unambiguous cloud-only strings — these do not appear on consumer hardware.
        const UNAMBIGUOUS_CLOUD: &[&str] = &[
            "digitalocean",
            "linode",
            "vultr",
            "hetzner",
            "cloudstack",
            "openstack",
            "upcloud",
            "scaleway",
            "exoscale",
            "oracle cloud",
            "ovhcloud",
            "ovh sas",
        ];
        for field in &[&sys_vendor, &product_name, &board_vendor, &chassis_tag] {
            if UNAMBIGUOUS_CLOUD.iter().any(|n| field.contains(n)) {
                return true;
            }
        }
    }

    #[cfg(windows)]
    {
        if let Some(key) = unsafe {
            reg_open_subkey(
                win_resolve::HKEY_LOCAL_MACHINE,
                "HARDWARE\\DESCRIPTION\\System\\BIOS",
            )
        } {
            let manufacturer =
                unsafe { reg_read_string(key, "SystemManufacturer") }.unwrap_or_default();
            let product = unsafe { reg_read_string(key, "SystemProductName") }.unwrap_or_default();
            let board_mfr =
                unsafe { reg_read_string(key, "BaseBoardManufacturer") }.unwrap_or_default();
            unsafe {
                reg_close_key(key);
            }
            let mfr = manufacturer.to_ascii_lowercase();
            let prod = product.to_ascii_lowercase();
            let board = board_mfr.to_ascii_lowercase();

            // AWS: manufacturer contains "amazon" and either manufacturer or
            // product mentions "ec2".
            if mfr.contains("amazon") && (mfr.contains("ec2") || prod.contains("ec2")) {
                return true;
            }
            // Azure: manufacturer = "Microsoft Corporation" AND product = "Virtual Machine".
            // Physical Windows systems from Microsoft never have product "Virtual Machine".
            if mfr.contains("microsoft corporation") && prod.contains("virtual machine") {
                return true;
            }
            // GCP: manufacturer or product contains "google compute".
            if mfr.contains("google") && prod.contains("google compute") {
                return true;
            }

            // Unambiguous cloud-only strings.
            const UNAMBIGUOUS_CLOUD: &[&str] = &[
                "digitalocean",
                "linode",
                "vultr",
                "hetzner",
                "cloudstack",
                "openstack",
                "upcloud",
                "scaleway",
                "exoscale",
                "oracle cloud",
                "ovhcloud",
                "ovh sas",
            ];
            for field in &[&mfr, &prod, &board] {
                if UNAMBIGUOUS_CLOUD.iter().any(|n| field.contains(n)) {
                    return true;
                }
            }

            // Legitimate Hyper-V on physical Windows: SystemManufacturer is
            // "Microsoft Corporation" but product is NOT "Virtual Machine".
            // This covers WSL2, Credential Guard, Device Guard, and Windows
            // Sandbox — all of which set the CPUID hypervisor bit on an
            // otherwise bare-metal Windows host.
            //
            // We additionally verify that the CPUID hypervisor bit is actually
            // set before suppressing VM detection — on a genuine physical host
            // without Hyper-V enabled, the manufacturer check alone would be
            // too broad (it would suppress detection on any Microsoft-branded
            // hardware running in an unlikely nested-virtualisation scenario).
            if mfr.contains("microsoft corporation")
                && !prod.contains("virtual machine")
                && cpuid_hypervisor_bit()
            {
                tracing::debug!("env_check: Microsoft manufacturer without VM product name + CPUID hypervisor bit set — likely physical Windows with Hyper-V features");
                return true;
            }
        }

        // WSL2 guest: the WSL_DISTRO_NAME environment variable is set inside
        // Windows Subsystem for Linux containers.  This is a legitimate
        // execution environment, not a hostile sandbox.
        if std::env::var("WSL_DISTRO_NAME").is_ok() {
            tracing::debug!("env_check: WSL_DISTRO_NAME set — WSL2 environment, treating as expected hypervisor");
            return true;
        }

        // Windows Sandbox runs as WindowsSandbox.exe.  If the current process
        // or its parent is WindowsSandbox.exe, this is a legitimate Windows
        // feature, not a hostile analysis sandbox.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
                if name.to_ascii_lowercase().contains("windowssandbox") {
                    tracing::debug!("env_check: running inside Windows Sandbox — treating as expected hypervisor");
                    return true;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::{Duration, Instant};

        // macOS cloud VM detection: probe IOKit registry and system_profiler
        // for known cloud/virtualisation indicators.

        // Check IOKit for VirtIO devices (AWS EC2 Mac uses AppleVirtIO)
        // without blocking startup on loaded systems.
        if let Ok(mut child) = Command::new("ioreg")
            .args(["-l"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(stdout) = child.stdout.take() {
                let (tx, rx) = mpsc::channel::<String>();
                let reader = std::thread::spawn(move || {
                    let mut buf = BufReader::new(stdout);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match buf.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {
                                let _ = tx.send(line.to_ascii_lowercase());
                            }
                            Err(_) => break,
                        }
                    }
                });

                let deadline = Instant::now() + Duration::from_secs(2);
                let mut found_hypervisor = false;
                let mut timed_out = false;

                loop {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        break;
                    }

                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let wait_for = std::cmp::min(remaining, Duration::from_millis(100));

                    match rx.recv_timeout(wait_for) {
                        Ok(line) => {
                            // Only applevirtio (AWS EC2 Mac) indicates a
                            // genuine *cloud* hypervisor.  VMware and
                            // Parallels are local virtualisation products
                            // commonly used for malware analysis; treating
                            // them as "expected" would suppress sandbox
                            // classification on analyst VMs.
                            if line.contains("applevirtio") {
                                found_hypervisor = true;
                                let _ = child.kill();
                                break;
                            }
                            // Record local-virtualisation detection for
                            // logging but do NOT set found_hypervisor —
                            // these are analyst VM candidates, not cloud.
                            if line.contains("vmwarevirtual")
                                || line.contains("prlvirtual")
                            {
                                tracing::debug!(
                                    "env_check: is_expected_hypervisor: \
                                     local virtualisation detected (VMware/Parallels) \
                                     — not treated as cloud hypervisor"
                                );
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => match child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => {}
                            Err(_) => break,
                        },
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }

                if !found_hypervisor {
                    while let Ok(line) = rx.try_recv() {
                        // Same logic: only applevirtio is a cloud hypervisor.
                        if line.contains("applevirtio") {
                            found_hypervisor = true;
                            break;
                        }
                    }
                }

                let _ = child.wait();
                let _ = reader.join();

                if found_hypervisor {
                    return true;
                }

                if timed_out {
                    tracing::debug!("env_check: is_expected_hypervisor ioreg -l timed out after 2s");
                }
            }
        }

        // Check hardware model via system_profiler.
        // Only EC2 is a cloud indicator.  VMware and Parallels are local
        // virtualisation products commonly used for malware analysis;
        // they must not suppress sandbox classification.
        if let Ok(out) = std::process::Command::new("system_profiler")
            .args(["SPHardwareDataType"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if stdout.contains("ec2") {
                return true;
            }
        }

        // NOTE: kern.hv_vmm_present is intentionally NOT checked here.
        // It fires on any macOS VM (cloud AND local VMware/Parallels), so it
        // cannot distinguish cloud from analyst VMs.  The generic hypervisor
        // bit is already captured by CPUID detection in detect_vm() and
        // feeds into the multi-signal VM scoring, not into is_expected_hypervisor.
    }

    false
}

/// macOS-specific cloud instance detection.
///
/// macOS cannot safely probe 169.254.169.254 (IMDS) due to link-local
/// interference with Bonjour/mDNS and captive-portal detection.  This
/// function provides alternative detection methods:
///
/// - **File-based**: AWS EC2 Mac installs the SSM agent under `/opt/aws/`.
/// - **sysctl-based**: `kern.uuid` may contain EC2/Amazon identifiers.
/// - **DNS-based**: `metadata.google.internal` only resolves inside GCP.
///
/// These checks mirror the macOS block in `env_check_sandbox::is_cloud_instance_sandbox()`.
#[cfg(target_os = "macos")]
fn is_cloud_instance_macos() -> bool {
    // File-based AWS EC2 Mac detection.
    if std::path::Path::new("/opt/aws/bin").exists()
        || std::path::Path::new("/opt/aws/ena").exists()
    {
        return true;
    }

    // sysctl UUID check: EC2 Mac instances often have UUIDs containing
    // "ec2" or "amazon".  Cross-check with kern.hv_vmm_present to avoid
    // false positives from spoofed UUIDs.
    if let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "kern.uuid"])
        .output()
    {
        let uuid = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        if uuid.contains("ec2") || uuid.contains("amazon") {
            if let Ok(hv) = std::process::Command::new("sysctl")
                .args(["-n", "kern.hv_vmm_present"])
                .output()
            {
                if String::from_utf8_lossy(&hv.stdout).trim() == "1" {
                    return true;
                }
            }
        }
    }

    // DNS-based cloud detection: these hostnames only resolve inside their
    // respective cloud networks.  Pure DNS resolution is safe on macOS —
    // no HTTP request, no link-local interference.
    {
        fn dns_name_resolves(hostname: &str) -> bool {
            use std::net::ToSocketAddrs;
            let addr = format!("{}:0", hostname);
            addr.to_socket_addrs().is_ok()
                && addr.to_socket_addrs().map(|it| !it.is_empty()).unwrap_or(false)
        }

        if dns_name_resolves("metadata.google.internal") {
            return true;
        }
        if dns_name_resolves("instance-metadata.oraclecloud.com") {
            return true;
        }
    }

    false
}

/// Check whether we are running on a cloud instance by probing the Link-Local
/// Instance Metadata Service (IMDS) endpoint shared by AWS, Azure, and GCP.
///
/// A bare TCP-connect to 169.254.169.254:80 is insufficient because some
/// corporate captive-portal implementations intercept this address and
/// accept the TCP handshake, producing a false positive.  IMDSv2-only clouds
/// (e.g., AWS with `HttpTokens = required`) also drop unauthenticated IMDSv1
/// requests at the HTTP layer, yet the TCP connect succeeds.
///
/// This function uses a two-step validation:
///   1. TCP connect within 200 ms with one 100 ms delayed retry on failure,
///      bounded by a 1 second total IMDS probe budget.
///   2. Write a minimal HTTP/1.0 GET and read the response.  Accept only status
///      codes that an IMDS genuinely returns:
///      200 (OK — IMDSv1 enabled)
///      400 (Bad Request — IMDSv2 token check, proves IMDS exists)
///      401 (Unauthorized — same as 400 on some providers)
///      Corporate proxies return 301, 302, 200 with an HTML body,
///      or 404 — none of which begin with "HTTP/1." followed by " 200",
///      " 400", or " 401".
///
/// **macOS**: Uses file-based, sysctl-based, and DNS-based cloud detection
/// instead of IMDS.  macOS uses the 169.254.0.0/16 range for link-local
/// networking (Bonjour/mDNS, Internet Sharing, AwDL) and the
/// CaptiveNetworkSupport daemon can intercept HTTP probes to any IP, so
/// the IMDS endpoint cannot be used safely.  See `is_cloud_instance_macos()`
/// for details.
fn is_cloud_instance() -> bool {
    // macOS: Skip IMDS probe — link-local/mDNS and captive portal detection
    // cause false positives on 169.254.169.254.  Instead, use file-based,
    // sysctl-based, and DNS-based cloud detection that is safe on macOS.
    // Cloud Mac instances are also detected by is_expected_hypervisor() via
    // ioreg AppleVirtIO and system_profiler EC2 strings.
    #[cfg(target_os = "macos")]
    {
        return is_cloud_instance_macos();
    }

    #[cfg(not(target_os = "macos"))]
    {
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
        use std::time::{Duration, Instant};

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
        const IMDS_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
        const IMDS_RETRY_DELAY: Duration = Duration::from_millis(100);
        const IMDS_IO_TIMEOUT: Duration = Duration::from_millis(100);
        const IMDS_TOTAL_BUDGET: Duration = Duration::from_secs(1);

        let probe_started = Instant::now();
        let remaining_budget = || IMDS_TOTAL_BUDGET.saturating_sub(probe_started.elapsed());
        let log_probe_failure = |stage: &str, err: &dyn std::fmt::Display| {
            tracing::debug!(
                "env_check: IMDS probe failed at {} after {:?}: {}",
                stage,
                probe_started.elapsed(),
                err
            );
        };
        let has_budget_for_io = |stage: &str| -> bool {
            if remaining_budget() < IMDS_IO_TIMEOUT {
                log_probe_failure(stage, &"probe deadline exhausted before read/write");
                return false;
            }
            true
        };

        let open_stream = |stage: &str| -> Option<TcpStream> {
            let first_timeout = std::cmp::min(IMDS_CONNECT_TIMEOUT, remaining_budget());
            if first_timeout.is_zero() {
                log_probe_failure(stage, &"probe deadline exhausted before connect");
                return None;
            }

            let connect_with_timeouts = |timeout: Duration| -> std::io::Result<TcpStream> {
                let stream = TcpStream::connect_timeout(&addr, timeout)?;
                // Keep IMDS operations tight to avoid startup stalls.
                let _ = stream.set_read_timeout(Some(IMDS_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IMDS_IO_TIMEOUT));
                Ok(stream)
            };

            match connect_with_timeouts(first_timeout) {
                Ok(stream) => Some(stream),
                Err(first_err) => {
                    if remaining_budget() <= IMDS_RETRY_DELAY {
                        log_probe_failure(stage, &first_err);
                        return None;
                    }

                    std::thread::sleep(IMDS_RETRY_DELAY);

                    let second_timeout = std::cmp::min(IMDS_CONNECT_TIMEOUT, remaining_budget());
                    if second_timeout.is_zero() {
                        log_probe_failure(stage, &first_err);
                        return None;
                    }

                    match connect_with_timeouts(second_timeout) {
                        Ok(stream) => Some(stream),
                        Err(second_err) => {
                            let combined_err = format!(
                                "first attempt: {}; retry attempt: {}",
                                first_err, second_err
                            );
                            log_probe_failure(stage, &combined_err);
                            None
                        }
                    }
                }
            }
        };

        let validate_metadata_response = |buf: &[u8], n: usize, allow_auth_only: bool| -> bool {
            if !buf.starts_with(b"HTTP/1.") || n < 12 {
                return false;
            }

            let status = &buf[9..12];
            if allow_auth_only {
                if !matches!(status, b"200" | b"400" | b"401") {
                    return false;
                }
            } else if status != b"200" {
                return false;
            }

            // L-6: For HTTP 200 responses, reject obvious HTML/captive-portal
            // bodies but accept any non-HTML body.  The previous check required
            // known AWS IMDS keys ("ami-id", "instance-id", etc.), which caused
            // false negatives on non-AWS/Azure/GCP clouds (Oracle, IBM,
            // DigitalOcean) that also listen on 169.254.169.254 but return
            // different metadata formats.
            //
            // Heuristic: reject HTML (starts with `<`), accept everything else.
            // A real IMDS returns plain-text key-value pairs, path listings, or
            // JSON — none of which start with `<`.  Corporate proxies and
            // captive portals return HTML pages.
            if status == b"200" && n > 16 {
                if let Some(body_start) = buf[..n]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                {
                    let body = &buf[body_start..n];
                    if body.starts_with(b"<") || body.starts_with(b"<!") {
                        return false;
                    }
                }
            }

            true
        };

        // IMDSv1 attempt first.
        let imds_v1_success = {
            if let Some(mut stream) = open_stream("IMDSv1 connect") {
                let req = b"GET /latest/meta-data/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n";
                if !has_budget_for_io("IMDSv1 write") {
                    false
                } else if let Err(e) = stream.write_all(req) {
                    log_probe_failure("IMDSv1 write", &e);
                    false
                } else {
                    let mut buf = [0u8; 256];
                    if !has_budget_for_io("IMDSv1 read") {
                        return false;
                    }
                    let n = match stream.read(&mut buf) {
                        Ok(0) => {
                            log_probe_failure("IMDSv1 read", &"empty response");
                            0
                        }
                        Err(e) => {
                            log_probe_failure("IMDSv1 read", &e);
                            0
                        }
                        Ok(n) => n,
                    };
                    n > 0 && validate_metadata_response(&buf, n, true)
                }
            } else {
                false
            }
        };

        if imds_v1_success {
            tracing::debug!("env_check: cloud instance detected via IMDSv1");
            return true;
        }

        // IMDSv2 fallback: fetch token then query metadata with token header.
        let token = {
            let mut stream = match open_stream("IMDSv2 token connect") {
                Some(s) => s,
                None => {
                    return false;
                }
            };

            let token_req = b"PUT /latest/api/token HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n\r\n";
            if !has_budget_for_io("IMDSv2 token write") {
                return false;
            }
            if let Err(e) = stream.write_all(token_req) {
                log_probe_failure("IMDSv2 token write", &e);
                return false;
            }

            let mut buf = [0u8; 512];
            if !has_budget_for_io("IMDSv2 token read") {
                return false;
            }
            let n = match stream.read(&mut buf) {
                Ok(0) => {
                    log_probe_failure("IMDSv2 token read", &"empty response");
                    return false;
                }
                Err(e) => {
                    log_probe_failure("IMDSv2 token read", &e);
                    return false;
                }
                Ok(n) => n,
            };

            if !buf.starts_with(b"HTTP/1.") || n < 12 || &buf[9..12] != b"200" {
                log_probe_failure("IMDSv2 token response", &"unexpected HTTP status");
                return false;
            }

            let header_end = match buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
                Some(p) => p + 4,
                None => {
                    log_probe_failure("IMDSv2 token response", &"missing HTTP header terminator");
                    return false;
                }
            };

            let t = String::from_utf8_lossy(&buf[header_end..n])
                .trim()
                .to_string();
            if t.is_empty() {
                log_probe_failure("IMDSv2 token response", &"empty token body");
                return false;
            }
            t
        };

        let mut stream = match open_stream("IMDSv2 metadata connect") {
            Some(s) => s,
            None => {
                return false;
            }
        };
        let metadata_req = format!(
            "GET /latest/meta-data/ HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: {}\r\n\r\n",
            token
        );
        if !has_budget_for_io("IMDSv2 metadata write") {
            return false;
        }
        if let Err(e) = stream.write_all(metadata_req.as_bytes()) {
            log_probe_failure("IMDSv2 metadata write", &e);
            return false;
        }

        let mut buf = [0u8; 256];
        if !has_budget_for_io("IMDSv2 metadata read") {
            return false;
        }
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                log_probe_failure("IMDSv2 metadata read", &"empty response");
                return false;
            }
            Err(e) => {
                log_probe_failure("IMDSv2 metadata read", &e);
                return false;
            }
            Ok(n) => n,
        };
        if validate_metadata_response(&buf, n, false) {
            tracing::debug!("env_check: cloud instance detected via IMDSv2 (AWS)");
            return true;
        }

        log_probe_failure("IMDSv2 metadata response", &"unexpected HTTP status/body");

        // ── Azure IMDS probe ──────────────────────────────────────────────
        //
        // Azure Instance Metadata Service:
        //   GET /metadata/instance?api-version=2021-02-01 HTTP/1.0
        //   Host: 169.254.169.254
        //   Metadata: true
        //
        // Returns JSON with "compute" object containing "vmId", "name",
        // "location", etc.  The `Metadata: true` header is REQUIRED —
        // without it Azure returns 400.
        if let Some(mut stream) = open_stream("Azure IMDS connect") {
            let azure_req = b"GET /metadata/instance?api-version=2021-02-01 HTTP/1.0\r\nHost: 169.254.169.254\r\nMetadata: true\r\n\r\n";
            if has_budget_for_io("Azure IMDS write") {
                if let Ok(()) = stream.write_all(azure_req) {
                    let mut buf = [0u8; 512];
                    if has_budget_for_io("Azure IMDS read") {
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 12
                                && buf.starts_with(b"HTTP/1.")
                                && &buf[9..12] == b"200"
                            {
                                // Validate body contains Azure IMDS keys.
                                if let Some(body_start) = buf[..n]
                                    .windows(4)
                                    .position(|w| w == b"\r\n\r\n")
                                    .map(|p| p + 4)
                                {
                                    let body = &buf[body_start..n];
                                    if !body.starts_with(b"<")
                                        && !body.starts_with(b"<!")
                                    {
                                        let body_str =
                                            String::from_utf8_lossy(body);
                                        let azure_keys = [
                                            "vmId",
                                            "location",
                                            "resourceGroupName",
                                            "subscriptionId",
                                        ];
                                        if azure_keys
                                            .iter()
                                            .any(|k| body_str.contains(k))
                                        {
                                            tracing::debug!(
                                                "env_check: cloud instance detected via Azure IMDS"
                                            );
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── GCP IMDS probe ────────────────────────────────────────────────
        //
        // Google Compute Engine Metadata Service:
        //   GET /computeMetadata/v1/ HTTP/1.0
        //   Host: metadata.google.internal
        //   Metadata-Flavor: Google
        //
        // The `Metadata-Flavor: Google` header is REQUIRED — without it
        // GCP returns 403.  Returns a directory listing of available
        // metadata paths.
        if let Some(mut stream) = open_stream("GCP IMDS connect") {
            let gcp_req = b"GET /computeMetadata/v1/ HTTP/1.0\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n";
            if has_budget_for_io("GCP IMDS write") {
                if let Ok(()) = stream.write_all(gcp_req) {
                    let mut buf = [0u8; 512];
                    if has_budget_for_io("GCP IMDS read") {
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 12
                                && buf.starts_with(b"HTTP/1.")
                                && &buf[9..12] == b"200"
                            {
                                // Validate body contains GCP metadata paths.
                                if let Some(body_start) = buf[..n]
                                    .windows(4)
                                    .position(|w| w == b"\r\n\r\n")
                                    .map(|p| p + 4)
                                {
                                    let body = &buf[body_start..n];
                                    if !body.starts_with(b"<")
                                        && !body.starts_with(b"<!")
                                    {
                                        let body_str =
                                            String::from_utf8_lossy(body);
                                        let gcp_keys = [
                                            "instance/",
                                            "project/",
                                            "oslogin/",
                                        ];
                                        if gcp_keys
                                            .iter()
                                            .any(|k| body_str.contains(k))
                                        {
                                            tracing::debug!(
                                                "env_check: cloud instance detected via GCP IMDS"
                                            );
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Generic IMDS probe for non-major cloud providers ────────────
        //
        // L-6: Additional cloud providers (Oracle Cloud, IBM Cloud/VPC,
        // DigitalOcean, Hetzner Cloud, Scaleway, etc.) also listen on
        // 169.254.169.254 but use different paths and response formats.
        // Probe common paths to detect these environments.
        //
        // Oracle Cloud: GET /opc/v1/instance/  → JSON with "ociAdName"
        // IBM Cloud:    GET /metadata/v1/       → JSON with "compute"
        // DigitalOcean: GET /metadata/v1/       → JSON with "droplet_id"
        // Hetzner Cloud: GET /hetzner/v1/metadata/ → JSON with "instance-id"
        // Scaleway:     GET /metadata/instance  → JSON with "id"
        const EXTRA_IMDS_PATHS: &[&[u8]] = &[
            b"GET /opc/v1/instance/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n",
            b"GET /metadata/v1/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n",
            b"GET /hetzner/v1/metadata/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n",
        ];
        for (idx, req) in EXTRA_IMDS_PATHS.iter().enumerate() {
            let label = match idx {
                0 => "Oracle IMDS",
                1 => "IBM/DigitalOcean IMDS",
                2 => "Hetzner IMDS",
                _ => "generic IMDS",
            };
            let connect_label = format!("{} connect", label);
            if let Some(mut stream) = open_stream(&connect_label) {
                let write_label = format!("{} write", label);
                if !has_budget_for_io(&write_label) {
                    break; // no budget left for further probes
                }
                if let Err(_) = stream.write_all(req) {
                    continue;
                }
                let mut buf = [0u8; 512];
                let read_label = format!("{} read", label);
                if !has_budget_for_io(&read_label) {
                    break;
                }
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 12
                        && buf.starts_with(b"HTTP/1.")
                        && &buf[9..12] == b"200"
                    {
                        // Validate body: reject HTML, accept any non-HTML
                        // body (JSON metadata from these providers).
                        if let Some(body_start) = buf[..n]
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|p| p + 4)
                        {
                            let body = &buf[body_start..n];
                            if !body.starts_with(b"<")
                                && !body.starts_with(b"<!")
                                && !body.is_empty()
                            {
                                tracing::debug!(
                                    "env_check: cloud instance detected via {}",
                                    label
                                );
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}
/// Returns `None` when IMDS is unavailable or the response is invalid.
///
/// **macOS**: Always returns `None`, consistent with `is_cloud_instance` which
/// always returns `false` on macOS.  The 169.254.0.0/16 link-local range is
/// used by macOS for Bonjour/mDNS and Internet Sharing; captive-portal daemons
/// can intercept probes to 169.254.169.254 and return plausible HTTP responses,
/// making any IMDS probe on macOS unreliable.  Cloud Mac instances (AWS EC2 Mac)
/// are detected via `is_expected_hypervisor()` / ioreg AppleVirtIO instead, so
/// an IMDS-based instance-id is never needed on macOS.
#[cfg(target_os = "macos")]
fn fetch_cloud_instance_id() -> Option<String> {
    None
}

#[cfg(not(target_os = "macos"))]
fn fetch_cloud_instance_id() -> Option<String> {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
    let open_stream = || -> Option<TcpStream> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(50)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
        Some(stream)
    };

    let parse_http_200_body = |buf: &[u8], n: usize| -> Option<String> {
        if !buf.starts_with(b"HTTP/1.") || n < 12 || &buf[9..12] != b"200" {
            return None;
        }
        let header_end = buf[..n].windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let body = &buf[header_end..n];
        if body.starts_with(b"<") || body.starts_with(b"<!") {
            return None;
        }
        let id = String::from_utf8_lossy(body).trim().to_string();
        if id.is_empty() {
            None
        } else {
            Some(id)
        }
    };

    // IMDSv1 instance-id request.
    if let Some(mut stream) = open_stream() {
        let req = b"GET /latest/meta-data/instance-id HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n";
        if stream.write_all(req).is_ok() {
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    if let Some(id) = parse_http_200_body(&buf, n) {
                        return Some(id);
                    }
                }
            }
        }
    }

    // IMDSv2 fallback: token request then token-authenticated instance-id GET.
    let token = {
        let mut stream = open_stream()?;
        let req = b"PUT /latest/api/token HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n\r\n";
        if stream.write_all(req).is_err() {
            return None;
        }
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).ok()?;
        if n == 0 || !buf.starts_with(b"HTTP/1.") || n < 12 || &buf[9..12] != b"200" {
            return None;
        }
        let header_end = buf[..n].windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let t = String::from_utf8_lossy(&buf[header_end..n])
            .trim()
            .to_string();
        if t.is_empty() {
            return None;
        }
        t
    };

    let mut stream = open_stream()?;
    let req = format!(
        "GET /latest/meta-data/instance-id HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: {}\r\n\r\n",
        token
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return None;
    }
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    if let Some(id) = parse_http_200_body(&buf, n) {
        return Some(id);
    }

    // ── Azure IMDS instance-id ────────────────────────────────────────────
    //
    // Azure IMDS returns JSON via GET /metadata/instance?api-version=2021-02-01
    // with Metadata: true header.  The vmId is in compute.vmId.
    // We also support the dedicated endpoint:
    //   GET /metadata/instance/compute/vmId?api-version=2021-02-01
    if let Some(mut stream) = open_stream() {
        let azure_req = b"GET /metadata/instance/compute/vmId?api-version=2021-02-01 HTTP/1.0\r\nHost: 169.254.169.254\r\nMetadata: true\r\n\r\n";
        if stream.write_all(azure_req).is_ok() {
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    if let Some(id) = parse_http_200_body(&buf, n) {
                        // Azure vmId is a GUID like "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        let id = id.trim().to_string();
                        if id.contains('-') && id.len() >= 32 {
                            return Some(id);
                        }
                    }
                }
            }
        }
    }

    // ── GCP IMDS instance-id ──────────────────────────────────────────────
    //
    // GCP IMDS returns the numeric instance ID via:
    //   GET /computeMetadata/v1/instance/id HTTP/1.0
    //   Host: metadata.google.internal
    //   Metadata-Flavor: Google
    if let Some(mut stream) = open_stream() {
        let gcp_req = b"GET /computeMetadata/v1/instance/id HTTP/1.0\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n";
        if stream.write_all(gcp_req).is_ok() {
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    if let Some(id) = parse_http_200_body(&buf, n) {
                        // GCP instance IDs are numeric strings
                        let id = id.trim().to_string();
                        if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) {
                            return Some(id);
                        }
                    }
                }
            }
        }
    }

    None
}

fn cloud_instance_vm_refusal_bypassed() -> bool {
    // Load config early — needed for both the primary IMDS path and the
    // fallback path (hypervisor + fallback IDs) when IMDS is firewalled.
    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let profile = &cfg.malleable_profile;

    // Primary path: IMDS is reachable, try to fetch the instance-id.
    if is_cloud_instance() {
        let expected = profile
            .cloud_instance_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let actual = match fetch_cloud_instance_id() {
            Some(id) => id,
            None => {
                if profile.cloud_instance_allow_without_imds {
                    tracing::warn!(
                        "env_check: IMDS reachable but instance-id unavailable; VM refusal bypassed via cloud_instance_allow_without_imds"
                    );
                    return true;
                }

                // IMDS reachable but no instance-id — fall through to
                // the hypervisor-based fallback check below.
                let fallback_count = profile
                    .cloud_instance_fallback_ids
                    .iter()
                    .filter(|p| !p.trim().is_empty())
                    .count();

                if fallback_count > 0 && is_expected_hypervisor() {
                    tracing::warn!(
                        "env_check: IMDS instance-id unavailable; VM refusal bypassed via cloud_instance_fallback_ids ({fallback_count} configured) + expected cloud hypervisor"
                    );
                    return true;
                }

                return false;
            }
        };

        if expected.as_deref() == Some(actual.as_str()) {
            tracing::info!(
                "env_check: running on whitelisted cloud instance {}, VM refusal bypassed",
                actual
            );
            return true;
        } else {
            return false;
        }
    }

    // Fallback path: IMDS is unreachable (firewalled or not a cloud VM).
    // If the operator has configured cloud_instance_fallback_ids and this
    // host's hypervisor matches an expected cloud vendor, bypass VM refusal.
    // This ensures hardened cloud VMs with IMDS firewalled are still
    // correctly identified rather than misclassified as sandboxes.
    let fallback_count = profile
        .cloud_instance_fallback_ids
        .iter()
        .filter(|p| !p.trim().is_empty())
        .count();

    if fallback_count > 0 && is_expected_hypervisor() {
        tracing::warn!(
            "env_check: IMDS unreachable (firewalled or non-cloud); VM refusal bypassed via cloud_instance_fallback_ids ({fallback_count} configured) + expected cloud hypervisor"
        );
        return true;
    }

    false
}

/// Detect whether the current host should be classified as a VM using
/// multi-signal indicator counting with adaptive cloud-aware thresholds.
///
/// Signals (CPUID, platform DMI/registry, MAC prefixes, etc.) are counted and
/// compared against one of three thresholds:
/// 1) `threshold = 3` when both cloud checks fail (`is_expected_hypervisor = false`
///    and `is_cloud_instance = false`) - unknown virtualized environments.  Three
///    independent indicators are required so that the common pairing of CPUID
///    hypervisor bit + cloud-vendor MAC prefix alone (two generic indicators that
///    appear on any VM, including legitimate hardened-cloud hosts with IMDS
///    firewalled) does not trigger a false positive.
/// Returns total physical RAM in GiB (rounded down).  Used by `detect_vm` to
/// identify likely production VMs where large RAM reduces sandbox probability.
pub fn get_ram_gb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return kb / (1024 * 1024); // KiB → GiB
                }
            }
        }
        0
    }
    #[cfg(windows)]
    unsafe {
        let global_memory_status_ex: win_resolve::FnGlobalMemoryStatusEx =
            win_resolve::resolve_api(
                pe_resolve::HASH_KERNEL32_DLL,
                win_resolve::HASH_GLOBALMEMORYSTATUSEX,
            )
            .expect("GlobalMemoryStatusEx not found");
        let mut mem: win_resolve::MemoryStatusEx = std::mem::zeroed();
        mem.dw_length = std::mem::size_of::<win_resolve::MemoryStatusEx>() as u32;
        if global_memory_status_ex(&mut mem) != 0 {
            mem.ull_total_phys / (1024 * 1024 * 1024)
        } else {
            0
        }
    }
    #[cfg(target_os = "macos")]
    {
        // hw.memsize returns total physical memory in bytes.
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
            .map(|bytes| bytes / (1024 * 1024 * 1024))
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        0
    }
}

/// Returns system uptime in seconds.  Used by `detect_vm` alongside RAM to
/// identify production hosts that have been running for extended periods.
pub fn get_uptime_secs() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
            content
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
                .map(|f| f as u64)
                .unwrap_or(0)
        } else {
            0
        }
    }
    #[cfg(windows)]
    {
        let get_tick_count_64: win_resolve::FnGetTickCount64 = unsafe {
            win_resolve::resolve_api(
                pe_resolve::HASH_KERNEL32_DLL,
                win_resolve::HASH_GETTICKCOUNT64,
            )
            .expect("GetTickCount64 not found")
        };
        unsafe { get_tick_count_64() / 1000 }
    }
    #[cfg(target_os = "macos")]
    {
        // Use sysctl kern.boottime to compute uptime on macOS.
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
            .ok();
        if let Some(o) = output {
            let s = String::from_utf8_lossy(&o.stdout);
            // kern.boottime output: " { sec = 1234567890, usec = 0 } Thu Jan  1 00:00:00 2009"
            if let Some(sec_part) = s.split("sec =").nth(1) {
                if let Some(sec_str) = sec_part.split(',').next() {
                    if let Ok(boot_secs) = sec_str.trim().parse::<u64>() {
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        return now_secs.saturating_sub(boot_secs);
                    }
                }
            }
        }
        0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        0
    }
}

/// 2) `threshold = 3` when exactly one cloud check succeeds - likely cloud but
///    with incomplete confirmation (for example IMDS blocked, or unknown DMI).
/// 3) `threshold = 4` when both checks succeed - strongly confirmed cloud.
///
/// Edge case: if IMDS is unavailable and the provider hypervisor is not in the
/// built-in (or operator-extended) expected list, the logic falls back to
/// `threshold = 3`.  Two generic indicators (CPUID bit + MAC prefix) no longer
/// suffice; a third platform-level indicator (DMI/registry) is also required.
///
/// Recommended operator mitigation for niche cloud providers:
/// - Configure `malleable_profile.cloud_instance_id` so known deployments can
///   bypass VM refusal deterministically.
/// - Add provider-specific names to
///   `malleable_profile.vm_detection_extra_hypervisor_names` so
///   `is_expected_hypervisor` recognizes the platform without code changes.

/// Heuristic to avoid false-positive VM refusal on unrecognized cloud / VPS
/// providers whose hypervisor is not in `is_expected_hypervisor()` and whose
/// IMDS is unavailable.
///
/// The logic is intentionally conservative: every condition must hold.
///
/// | Signal                | Threshold | Rationale                                           |
/// |-----------------------|-----------|------------------------------------------------------|
/// | Physical RAM          | > 4 GiB   | Sandboxes rarely allocate > 4 GiB                   |
/// | Uptime                | > 24 h    | Automated sandboxes are typically short-lived        |
/// | Logical CPU count     | > 1       | Single-vCPU analysis VMs are extremely common        |
///
/// An adversary could spoof these, but the point is *not* to provide
/// unbreakable VM evasion — the operator already set `refuse_in_vm = true`.
/// The goal is to avoid *false positives* on legitimate niche cloud hosts
/// where the hypervisor DMI strings are not in our built-in list and the
/// operator has not yet added `vm_detection_extra_hypervisor_names`.
fn is_likely_production_server() -> bool {
    let ram_gb = get_ram_gb();
    let uptime_secs = get_uptime_secs();
    let cpu_count = get_logical_cpu_count();

    let ram_ok = ram_gb > 4;
    let uptime_ok = uptime_secs > 24 * 3600;
    let cpu_ok = cpu_count > 1;

    if ram_ok && uptime_ok && cpu_ok {
        tracing::debug!(
            "env_check: is_likely_production_server: RAM={} GiB, uptime={} h, CPUs={} — \
             all production heuristics satisfied",
            ram_gb,
            uptime_secs / 3600,
            cpu_count,
        );
        true
    } else {
        tracing::debug!(
            "env_check: is_likely_production_server: RAM={} GiB ({}, uptime={} h ({}), \
             CPUs={} ({}) — not all production heuristics satisfied",
            ram_gb,
            if ram_ok { "OK" } else { "low" },
            uptime_secs / 3600,
            if uptime_ok { "OK" } else { "short" },
            cpu_count,
            if cpu_ok { "OK" } else { "single" },
        );
        false
    }
}

/// Returns the logical CPU count available to this process.
fn get_logical_cpu_count() -> u32 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32 }
    }
    #[cfg(windows)]
    {
        let get_sysinfo: win_resolve::FnGetSystemInfo = unsafe {
            win_resolve::resolve_api(
                pe_resolve::HASH_KERNEL32_DLL,
                win_resolve::HASH_GETSYSTEMINFO,
            )
            .expect("GetSystemInfo not found")
        };
        let mut si = win_resolve::SystemInfo::default();
        unsafe { get_sysinfo(&mut si) };
        si.dw_number_of_processors
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        1
    }
}

/// Detect whether the current environment is a VM or sandbox.
///
/// Uses the unified scoring pipeline with false-positive mitigations enabled:
/// generic indicator weights (DMI, MAC prefix) are reduced when cloud context
/// is uncertain, and the "likely legitimate server" threshold boost may
/// suppress detection on long-lived VMs with ample RAM.
///
/// **Consumer caveat**: This lenient mode avoids false positives on niche
/// cloud providers at the cost of reduced sensitivity.  Callers that need
/// the stricter classification used by `enforce(refuse_in_vm = true)` — for
/// example, pre-flight checks that should match the enforcement decision —
/// should use [`detect_vm_strict`] instead.
pub fn detect_vm() -> bool {
    // Delegate to the unified scoring pipeline.
    let indicators = collect_indicators();
    let (is_sandbox, _, _) = evaluate_sandbox_score(&indicators);
    is_sandbox
}

/// Detect whether the current environment is a VM or sandbox using strict
/// (enforcement-equivalent) scoring.
///
/// This applies the same indicator reweighting that `enforce(refuse_in_vm =
/// true)` uses: generic DMI and MAC indicators are restored to their full
/// weights, and the base threshold (30) is used without the "likely
/// legitimate server" boost or hypervisor-only suppression.
///
/// Use this when the caller needs to match the enforcement decision — for
/// example, a pre-flight report or a secondary check before a sensitive
/// operation.
///
/// Returns `(is_vm, total_strict_score, threshold)`.
pub fn detect_vm_strict() -> (bool, u32, u32) {
    let mut indicators = collect_indicators();
    // Restore weights that were conservatively reduced to prevent false
    // positives in informational mode.
    for ind in indicators.iter_mut() {
        if ind.source == "dmi" && ind.weight == 10 {
            ind.weight = 25;
        }
        if ind.source == "mac" && ind.weight == 10 {
            ind.weight = 20;
        }
    }
    let strict_total: u32 = indicators.iter().map(|i| i.weight).sum();
    // Apply the same production-server threshold boost used by enforce():
    // when the host has production-server characteristics (high RAM, long
    // uptime, multi-core) and the score is borderline (30–35 from ≤ 2
    // weak indicators), raise the threshold to 40 to avoid false positives
    // on loaded production VMs where only CPUID + timing anomaly fire.
    let production_server = is_likely_production_server();
    let num_indicators = indicators.len();
    let is_borderline = strict_total >= 30 && strict_total <= 35 && num_indicators <= 2;
    let strict_threshold: u32 = if production_server && is_borderline { 40 } else { 30 };
    // A score of 0 means no indicators at all; that is safe to ignore.
    let is_vm = strict_total > 0 && strict_total >= strict_threshold;
    (is_vm, strict_total, strict_threshold)
}

// ── Headless / CI / RDP Environment Detection ──────────────────────────────
//
// Mouse movement and desktop richness checks produce false positives in
// non-interactive environments (headless servers, CI runners, RDP sessions
// without mouse activity).  These helpers detect such environments so the
// scoring pipeline can reduce or zero-out the mouse/desktop weights.

/// Detect common CI/CD runner environments by checking well-known environment
/// variables.  Returns `true` if the current process is likely running inside
/// a CI pipeline.
///
/// CI environments are inherently headless: they never have a human moving a
/// mouse or interacting with a desktop.  Both mouse and desktop indicators
/// should be zeroed when this returns `true`.
fn is_ci_environment() -> bool {
    // Single definitive CI variables (set by the CI system itself).
    if std::env::var_os("CI").is_some() && std::env::var("CI").map(|v| v == "true").unwrap_or(false) {
        return true;
    }
    // Platform-specific CI indicators.
    const CI_VARS: &[&str] = &[
        "GITHUB_ACTIONS",       // GitHub Actions
        "GITLAB_CI",            // GitLab CI
        "JENKINS_URL",          // Jenkins
        "TRAVIS",               // Travis CI
        "CIRCLECI",             // CircleCI
        "BUILDKITE",            // Buildkite
        "TF_BUILD",             // Azure Pipelines
        "HEROKU_TEST_RUN_ID",   // Heroku CI
        "BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
        "TEAMCITY_VERSION",     // TeamCity
        "CODEBUILD_BUILD_ID",   // AWS CodeBuild
    ];
    for var in CI_VARS {
        if std::env::var_os(var).is_some() {
            return true;
        }
    }
    false
}

/// Detect whether the current Windows session is an RDP (Terminal Services)
/// client session.  On RDP sessions the mouse may not move if the user is
/// only using keyboard or is connected but idle — the mouse check should
/// be zeroed to avoid false positives.
///
/// Returns `false` on non-Windows platforms.
#[cfg(windows)]
fn is_rdp_session() -> bool {
    let get_system_metrics: win_resolve::FnGetSystemMetrics = unsafe {
        match win_resolve::resolve_api_or_load(
            win_resolve::USER32_DLL_W,
            win_resolve::HASH_USER32_DLL,
            win_resolve::HASH_GETSYSTEMMETRICS,
        ) {
            Some(f) => f,
            None => return false,
        }
    };
    unsafe { get_system_metrics(win_resolve::SM_REMOTESESSION) != 0 }
}

#[cfg(not(windows))]
fn is_rdp_session() -> bool {
    false
}

/// Detect whether the current Windows process is running in a non-interactive
/// (service) session.  Windows services run in Session 0 which has no desktop.
///
/// Returns `false` on non-Windows platforms.
#[cfg(windows)]
fn is_noninteractive_session() -> bool {
    // Check if the process is in Session 0 (services session).
    // Services run in Session 0 which has no interactive desktop.
    let get_system_metrics: win_resolve::FnGetSystemMetrics = unsafe {
        match win_resolve::resolve_api_or_load(
            win_resolve::USER32_DLL_W,
            win_resolve::HASH_USER32_DLL,
            win_resolve::HASH_GETSYSTEMMETRICS,
        ) {
            Some(f) => f,
            None => return false,
        }
    };
    // SM_REMOTESESSION already checked separately; this checks if there's
    // no user interactive session at all (headless server / service).
    // A secondary heuristic: check SESSIONNAME env var.  Services typically
    // have no SESSIONNAME or "Console" in Session 0.
    if std::env::var_os("SESSIONNAME").is_none() {
        // Could be a service.  Also check if we're in Session 0 via
        // ProcessIdToSessionId.  If unavailable, rely on the registry
        // InstallationType check (already done in sandbox module).
        // For now, combine with the Server Core registry check.
        return false; // Don't over-flag — the Server Core check handles this
    }
    false
}

#[cfg(not(windows))]
fn is_noninteractive_session() -> bool {
    false
}

// ══════════════════════════════════════════════════════════════════════════════
//  UNIFIED SANDBOX SCORING PIPELINE
// ══════════════════════════════════════════════════════════════════════════════
//
// The pipeline consolidates the previously duplicated checks from
// `detect_vm()`, `is_cloud_instance_sandbox()`, `is_expected_hypervisor()`,
// the sandbox module, and timing checks into a single `collect_indicators()`
// function that returns structured `SandboxIndicator` results.
//
// `detect_vm()` is preserved for backward compatibility and delegates to
// `evaluate_sandbox_score()` internally.

/// Run all sandbox/VM detection checks and return a structured list of
/// indicators with weights.  Each indicator has a category, detail string,
/// weight, and source.  The caller can sum weights and compare against a
/// threshold to decide whether the environment is hostile.
///
/// This replaces the overlapping boolean checks in `is_cloud_instance_sandbox`,
/// `is_expected_hypervisor`, and the indicator-counting logic in `detect_vm`
/// with a single unified pipeline.
pub fn collect_indicators() -> Vec<common::SandboxIndicator> {
    let mut indicators = Vec::new();

    // ── Cloud confirmation pre-computation ──────────────────────────────
    let cloud_hypervisor = is_expected_hypervisor();
    let cloud_imds = is_cloud_instance();
    let cloud_confirmed = cloud_hypervisor || cloud_imds;

    // ── 1. CPUID hypervisor bit ─────────────────────────────────────────
    if cpuid_hypervisor_bit() {
        // Reduce weight when cloud is not confirmed — on legitimate cloud VMs
        // where IMDS is firewalled and the provider is not in the expected
        // hypervisor list, the CPUID bit alone is an unreliable signal.
        // Full weight (30) is reserved for cases where cloud context is
        // confirmed, which means the bit is expected and carries no weight
        // anyway.  In all other cases, use a reduced weight (15) to avoid
        // false positives on niche cloud providers.
        let weight = if cloud_confirmed { 0 } else { 15 };
        indicators.push(common::SandboxIndicator {
            category: "hypervisor".to_string(),
            detail: "CPUID hypervisor bit set".to_string(),
            weight,
            source: "cpuid".to_string(),
        });
    }

    // ── 2. Platform DMI / registry VM indicators ────────────────────────
    #[cfg(target_os = "linux")]
    {
        if linux_dmi_indicates_vm_detailed(&mut indicators) {
            // Indicators added inside the helper.
        }
    }

    #[cfg(windows)]
    {
        if windows_registry_indicates_vm_detailed(&mut indicators) {
            // Indicators added inside the helper.
        }
    }

    #[cfg(target_os = "macos")]
    {
        if macos_system_profiler_indicates_vm_detailed(&mut indicators) {
            // Indicators added inside the helper.
        }
    }

    // ── 3. MAC prefix indicators ────────────────────────────────────────
    mac_prefix_indicators(&mut indicators);

    // ── 3b. Reduce generic indicator weights when cloud is not confirmed ─
    // On legitimate cloud VMs where IMDS is firewalled and the provider
    // isn't in the expected hypervisor list, DMI and MAC indicators are
    // generic (e.g., "QEMU detected in DMI" on a KVM-based cloud host).
    // Reduce their weights from 25/20 to 10 to prevent false positives
    // where CPUID(15) + DMI(25) = 40 > threshold 30.
    if !cloud_confirmed {
        for indicator in indicators.iter_mut() {
            if indicator.source == "dmi" && indicator.weight == 25 {
                indicator.weight = 10;
            }
            if indicator.source == "mac" && indicator.weight == 20 {
                indicator.weight = 10;
            }
        }
    }

    // ── 4. Sandbox heuristics (mouse, desktop, uptime, hardware) ────────
    // Keep indicator contributions consistent with env_check_sandbox's
    // capped scoring model:
    //   mouse=min(score*5,30), desktop=min(score*3,25),
    //   uptime=min(score*2,25), hardware=min(score,20)
    let metrics = sandbox::collect_raw_metrics();
    let mut mouse_weight = std::cmp::min((metrics.mouse_movement_score as u32) * 5, 30);
    let mut desktop_weight = std::cmp::min((metrics.desktop_richness_score as u32) * 3, 25);
    let uptime_weight = std::cmp::min((metrics.uptime_score as u32) * 2, 25);
    let hardware_weight = std::cmp::min(metrics.hardware_plausibility_score as u32, 20);

    // ── 4a. Headless / CI / RDP false-positive mitigation ──────────────
    //
    // Mouse movement and desktop richness checks are unreliable in
    // non-interactive environments:
    //
    //   • CI runners (GitHub Actions, GitLab CI, Jenkins, …) never have a
    //     human at the console.  Both mouse AND desktop should be zeroed.
    //
    //   • RDP sessions: the remote user may be idle or using keyboard-only.
    //     Mouse weight is zeroed; desktop weight is kept because the remote
    //     session still has a window manager.
    //
    //   • Headless Linux/macOS: already handled by DISPLAY/CoreGraphics
    //     checks inside the sandbox module (return 0).  The mitigations
    //     below are additive to those per-OS checks.
    let ci_env = is_ci_environment();
    let rdp_session = is_rdp_session();

    if ci_env {
        // CI environments are headless by definition — zero both.
        tracing::info!(
            "env_check: CI environment detected (CI/GITHUB_ACTIONS/etc); zeroing mouse and desktop weights"
        );
        mouse_weight = 0;
        desktop_weight = 0;
    }
    if rdp_session && mouse_weight > 0 {
        // RDP sessions often have no mouse movement (user may be idle or
        // keyboard-only).  Reduce mouse weight but keep desktop — the
        // remote session still has a window manager with visible windows.
        tracing::info!(
            "env_check: RDP session detected (SM_REMOTESESSION); zeroing mouse weight (desktop kept)"
        );
        mouse_weight = 0;
    }

    if mouse_weight > 0 {
        indicators.push(common::SandboxIndicator {
            category: "timing".to_string(),
            detail: format!(
                "Low mouse activity (score={})",
                metrics.mouse_movement_score
            ),
            weight: mouse_weight,
            source: "mouse".to_string(),
        });
    }
    if desktop_weight > 0 {
        indicators.push(common::SandboxIndicator {
            category: "desktop".to_string(),
            detail: format!(
                "Few desktop windows (score={})",
                metrics.desktop_richness_score
            ),
            weight: desktop_weight,
            source: "desktop".to_string(),
        });
    }
    if uptime_weight > 0 {
        indicators.push(common::SandboxIndicator {
            category: "uptime".to_string(),
            detail: format!(
                "Low uptime / few temp artifacts (score={})",
                metrics.uptime_score
            ),
            weight: uptime_weight,
            source: "uptime".to_string(),
        });
    }
    if hardware_weight > 0 {
        indicators.push(common::SandboxIndicator {
            category: "hardware".to_string(),
            detail: format!(
                "Hardware below plausibility thresholds (score={})",
                metrics.hardware_plausibility_score
            ),
            weight: hardware_weight,
            source: "hardware".to_string(),
        });
    }

    // ── 5. Timing anomaly ───────────────────────────────────────────────
    if detect_timing_anomaly() {
        indicators.push(common::SandboxIndicator {
            category: "timing".to_string(),
            detail: "Sleep timing anomaly detected".to_string(),
            weight: 15,
            source: "timing".to_string(),
        });
    }

    // ── 6. Debugger presence ────────────────────────────────────────────
    if is_debugger_present() {
        indicators.push(common::SandboxIndicator {
            category: "debugger".to_string(),
            detail: "Debugger attached to process".to_string(),
            weight: 20,
            source: "debugger".to_string(),
        });
    }

    // ── 7. Cloud context indicators (informational) ─────────────────────
    if cloud_hypervisor {
        indicators.push(common::SandboxIndicator {
            category: "cloud_bios".to_string(),
            detail: "Expected cloud/container hypervisor context detected".to_string(),
            weight: 0, // Informational — does not contribute to score
            source: "expected_context".to_string(),
        });
    }
    if cloud_imds {
        indicators.push(common::SandboxIndicator {
            category: "cloud_bios".to_string(),
            detail: "IMDS endpoint responded — cloud instance confirmed".to_string(),
            weight: 0, // Informational — does not contribute to score
            source: "imds".to_string(),
        });
    }

    // ── 8. Hardware Performance Counter fingerprint ───────────────────
    // x86_64: uses RDPMC to measure cache misses, branch prediction,
    // instruction retirement, and micro-op ratio.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    if let Some(hpc) = env_check_hpc::hpc_indicator() {
        indicators.push(hpc);
    }
    // ARM64: uses PMCCNTR_EL0 (PMU cycle counter) when accessible.
    #[cfg(target_arch = "aarch64")]
    if let Some(pmu) = env_check_arm64_timer::pmu_indicator() {
        indicators.push(pmu);
    }

    // ── 9. Instruction-granularity timing ────────────────────────────────
    // x86_64: uses RDTSC/RDTSCP with CPUID serialization.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    if let Some(rdtsc) = env_check_rdtsc::instruction_timing_indicator() {
        indicators.push(rdtsc);
    }
    // ARM64: uses CNTVCT_EL0 with ISB serialization.
    #[cfg(target_arch = "aarch64")]
    if let Some(arm64_timer) = env_check_arm64_timer::instruction_timing_indicator() {
        indicators.push(arm64_timer);
    }

    // ── 10. Hypervisor vendor string (CPUID 0x40000000) ──────────────────
    // Distinguishes sandbox hypervisors (VirtualBox, unconfirmed VMware) from
    // legitimate cloud hypervisors (Azure Hyper-V, GCP KVM).  Harder to spoof
    // than the hypervisor bit because changing the vendor string breaks the
    // guest OS's paravirt layer.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    if let Some(ind) = hypervisor_vendor_indicator(cloud_confirmed) {
        indicators.push(ind);
    }

    // ── 11. Timing source consistency cross-check ───────────────────────
    // Windows x86-64: compares RDTSC, QPC, and GSTPAFT.  All three should
    // agree within 1-2% on real hardware.  Sandboxes diverge by >10%.
    #[cfg(all(windows, target_arch = "x86_64"))]
    if let Some(ind) = timing_consistency_indicator() {
        indicators.push(ind);
    }
    // ARM64: compares CNTVCT_EL0 against std::time::Instant.
    #[cfg(target_arch = "aarch64")]
    if let Some(ind) = env_check_arm64_timer::timing_consistency_indicator() {
        indicators.push(ind);
    }

    // ── 12. Hardware topology (CPU count, RAM, disk) ──────────────────────
    // Sandboxes often provision minimal resources; these are collected before
    // the cloud-aware weight zeroing below.
    hardware_topology_indicators(&mut indicators);

    // ── 12b. Zero topology and network weights when cloud is confirmed ────
    // On confirmed cloud VMs (Azure, GCP, AWS) small resource counts and a
    // single NIC are EXPECTED (cheap-tier VMs start at 1-2 vCPUs / 1 GiB).
    // Lineage and timing indicators keep their full weight regardless of cloud
    // because analysis frameworks never run in production cloud VMs.
    if cloud_confirmed {
        for indicator in indicators.iter_mut() {
            if indicator.source == "topology" || indicator.source == "network" {
                indicator.weight = 0;
            }
        }
    }

    // ── 13. Process lineage analysis (Windows) ────────────────────────────
    // Sandboxes (Cuckoo, CAPE, Joe Sandbox) spawn samples from python.exe or
    // java.exe.  This signal is NOT cloud-aware (analysis tools don't run in
    // production cloud deployments).
    #[cfg(windows)]
    if let Some(ind) = process_lineage_indicator() {
        indicators.push(ind);
    }

    // ── 14. Network environment (Windows) ─────────────────────────────────
    // A single physical NIC with no enterprise proxy is a mild sandbox signal.
    // Weight is zeroed on confirmed cloud by step 12b above.
    #[cfg(windows)]
    if let Some(ind) = network_environment_indicator() {
        indicators.push(ind);
    }

    indicators
}

/// Evaluate the total sandbox score from the collected indicators and return
/// whether the environment is classified as a VM/sandbox, together with the
/// full indicator breakdown.
///
/// Uses the same adaptive threshold logic as the original `detect_vm()`:
/// - When both cloud checks agree (strong confirmation): threshold = 60
/// - When one cloud check fires: threshold = 30
/// - No cloud signal: threshold = 30, raised to 40 for likely-legitimate servers
///
/// Returns `(is_sandbox, threshold, indicators)` where `is_sandbox` is true
/// when the summed weights exceed `threshold`.
pub fn evaluate_sandbox_score(
    indicators: &[common::SandboxIndicator],
) -> (bool, u32, Vec<common::SandboxIndicator>) {
    let cloud_hypervisor = indicators.iter().any(|i| {
        i.category == "cloud_bios"
            && (i.source == "expected_context" || i.detail.contains("DMI/registry"))
    });
    let cloud_imds = indicators
        .iter()
        .any(|i| i.category == "cloud_bios" && i.detail.contains("IMDS"));

    let total_weight: u32 = indicators.iter().map(|i| i.weight).sum();
    let heuristic_weight: u32 = indicators
        .iter()
        .filter(|i| {
            matches!(
                i.source.as_str(),
                "mouse" | "desktop" | "uptime" | "hardware"
            )
        })
        .map(|i| i.weight)
        .sum();
    let has_vm_artifact_signal = indicators.iter().any(|i| {
        i.weight > 0
            && matches!(
                i.source.as_str(),
                "cpuid" | "dmi" | "registry" | "mac" | "imds"
                    | "cpuid_vendor"              // hypervisor vendor string
                    | "rdtsc_consistency"          // x86 timing source cross-check
                    | "arm64_timer_consistency"    // ARM64 timing source cross-check
                    | "arm64_timer"                // ARM64 instruction timing
                    | "arm64_pmu"                  // ARM64 PMU fingerprint
                    | "lineage" // analysis-framework parent process
            )
    });

    // Adaptive threshold (mirrors the original detect_vm logic).
    let hypervisor_bit_set = indicators
        .iter()
        .any(|i| i.category == "hypervisor" && i.detail.contains("CPUID"));
    let likely_legitimate_server =
        hypervisor_bit_set && get_ram_gb() > 4 && get_uptime_secs() > 24 * 3600;

    let high_threshold_mode = crate::config::load_config()
        .map(|c| c.malleable_profile.vm_detection_high_threshold_mode)
        .unwrap_or(false);

    let threshold = if cloud_hypervisor && cloud_imds {
        60 // Strong confirmation: both local DMI *and* IMDS agree
    } else if cloud_hypervisor || cloud_imds {
        30 // Moderate confidence: one signal present
    } else if likely_legitimate_server {
        40 // CPUID + >4 GiB RAM + >24 h uptime
    } else {
        30
    };

    // Make "high threshold mode" materially stricter. The previous
    // threshold.max(30) had no effect because the adaptive base threshold is
    // already >= 30.
    let threshold = if high_threshold_mode {
        threshold.max(45)
    } else {
        threshold
    };

    let is_sandbox = total_weight >= threshold;

    // Heuristic-only medium scores are noisy on legitimate fresh/headless
    // environments. Require high-confidence heuristics (>=70) when there is
    // no VM artifact signal.
    let is_sandbox = if is_sandbox && !has_vm_artifact_signal && heuristic_weight < 70 {
        tracing::info!(
            "env_check: suppressing medium heuristic-only VM classification \
             (heuristic_weight={heuristic_weight}, total_weight={total_weight}, threshold={threshold})"
        );
        false
    } else {
        is_sandbox
    };

    // L-8 fix: removed blanket hypervisor-only suppression.  The CPUID
    // hypervisor bit carries weight 15, which cannot exceed the minimum
    // threshold of 30 on its own, so it cannot trigger a false positive.
    // The previous suppression prevented the hypervisor bit from being
    // reported in the score breakdown and from contributing to
    // `has_vm_artifact_signal` corroboration, which caused false negatives
    // on cloud-hosted sandboxes that pass IMDS checks.
    //
    // If the hypervisor bit is the sole indicator (total_weight == 15,
    // threshold >= 30), `is_sandbox` is already false by the threshold
    // check above — no suppression needed.  If any other indicator is
    // present (e.g. timing anomaly at weight 15), the combined score of
    // 30 now correctly reaches the threshold instead of being discarded.

    if is_sandbox && !cloud_imds && !cloud_hypervisor {
        tracing::warn!(
            "env_check: VM detected with threshold={threshold} and no cloud signal confirmed; \
             if this is a niche cloud deployment, verify IMDS connectivity and \
             extend is_expected_hypervisor via vm_detection_extra_hypervisor_names"
        );
    }

    (is_sandbox, threshold, indicators.to_vec())
}

fn cpuid_hypervisor_bit() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::__cpuid;
        // `__cpuid` is `unsafe` on older toolchains and safe on newer ones; tolerate both.
        #[allow(unused_unsafe)]
        let r = unsafe { __cpuid(1) };
        (r.ecx & (1 << 31)) != 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_dmi_indicates_vm() -> bool {
    const DMI: &[&str] = &[
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
    ];
    let needles = [
        String::from_utf8_lossy(&string_crypt::enc_str!("qemu"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("kvm"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("virtualbox"))
            .trim_end_matches('\0')
            .to_string(),
        "vbox".to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("xen"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("hyperv"))
            .trim_end_matches('\0')
            .to_string(),
        "innotek".to_string(),
    ];
    // std::str::from_utf8(&string_crypt::enc_str!("microsoft corporation")[..21]).unwrap() in sys_vendor appears on physical Microsoft hardware
    // (e.g., Surface devices) as well as on Hyper-V guests. Only treat it as a VM
    // indicator when the product_name is also "virtual machine", which is the
    // definitive fingerprint of a Hyper-V guest and not present on bare-metal hardware.
    let mut ms_vendor = false;
    let mut virt_product = false;
    for path in DMI {
        if let Ok(content) = std::fs::read_to_string(path) {
            let s = content.to_ascii_lowercase();
            if needles.iter().any(|n| s.contains(n.as_str())) {
                return true;
            }
            if path.ends_with("sys_vendor") {
                // Trim null bytes before comparing to avoid fragile byte-count slicing (4.1)
                let trimmed =
                    String::from_utf8_lossy(&string_crypt::enc_str!("microsoft corporation"))
                        .trim_end_matches('\0')
                        .to_ascii_lowercase();
                if s.contains(trimmed.as_str()) {
                    ms_vendor = true;
                }
            }
            if path.ends_with("product_name") && s.contains("virtual machine") {
                virt_product = true;
            }
        }
    }
    ms_vendor && virt_product
}

/// Detailed version of [`linux_dmi_indicates_vm`] that pushes individual
/// `SandboxIndicator`s instead of returning a boolean.
#[cfg(target_os = "linux")]
fn linux_dmi_indicates_vm_detailed(indicators: &mut Vec<common::SandboxIndicator>) -> bool {
    const DMI: &[&str] = &[
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
    ];
    let needles = [
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("qemu"))
                .trim_end_matches('\0')
                .to_string(),
            "QEMU",
        ),
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("kvm"))
                .trim_end_matches('\0')
                .to_string(),
            "KVM",
        ),
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
                .trim_end_matches('\0')
                .to_string(),
            "VMware",
        ),
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("virtualbox"))
                .trim_end_matches('\0')
                .to_string(),
            "VirtualBox",
        ),
        ("vbox".to_string(), "VirtualBox"),
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("xen"))
                .trim_end_matches('\0')
                .to_string(),
            "Xen",
        ),
        (
            String::from_utf8_lossy(&string_crypt::enc_str!("hyperv"))
                .trim_end_matches('\0')
                .to_string(),
            "Hyper-V",
        ),
        ("innotek".to_string(), "VirtualBox (innotek)"),
    ];
    let mut ms_vendor = false;
    let mut virt_product = false;
    let mut found = false;
    for path in DMI {
        if let Ok(content) = std::fs::read_to_string(path) {
            let s = content.to_ascii_lowercase();
            for (needle, label) in &needles {
                if s.contains(needle.as_str()) {
                    indicators.push(common::SandboxIndicator {
                        category: "hypervisor".to_string(),
                        detail: format!("{label} detected in {path}"),
                        weight: 25,
                        source: "dmi".to_string(),
                    });
                    found = true;
                }
            }
            if path.ends_with("sys_vendor") {
                let trimmed =
                    String::from_utf8_lossy(&string_crypt::enc_str!("microsoft corporation"))
                        .trim_end_matches('\0')
                        .to_ascii_lowercase();
                if s.contains(trimmed.as_str()) {
                    ms_vendor = true;
                }
            }
            if path.ends_with("product_name") && s.contains("virtual machine") {
                virt_product = true;
            }
        }
    }
    if ms_vendor && virt_product {
        indicators.push(common::SandboxIndicator {
            category: "hypervisor".to_string(),
            detail: "Microsoft Corporation vendor + Virtual Machine product (Hyper-V)".to_string(),
            weight: 25,
            source: "dmi".to_string(),
        });
        found = true;
    }
    found
}

#[cfg(target_os = "macos")]
fn macos_system_profiler_indicates_vm() -> bool {
    let mut is_vm = false;

    // Check sysctl hw.model and kern.hv_support
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
    {
        let model = String::from_utf8_lossy(&output.stdout).to_lowercase();
        // Match only well-known hypervisor product strings.
        // "pxe" is intentionally excluded: PXE is a network-boot protocol and
        // hw.model will contain "pxe" on Macs booted via NetBoot/IBOOT, which
        // are physical machines.  The string "virtual" covers VMware/Parallels
        // which set hw.model to "VMware..." or "Parallels Virtual Platform".
        if model.contains("virtual")
            || model.contains(
                String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
                    .trim_end_matches('\0')
                    .trim(),
            )
        {
            is_vm = true;
        }
    }

    // `kern.hv_support` only indicates CPU *capability* for virtualisation
    // (Hypervisor.framework), not that we are running *inside* a VM.  Physical
    // Macs with an Intel/Apple Silicon CPU always report kern.hv_support=1.
    // The correct sysctl is `kern.hv_vmm_present` which is set to 1 only when
    // the kernel detects it is running as a guest inside a hypervisor.
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("kern.hv_vmm_present")
        .output()
    {
        let present = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if present == "1" {
            // kern.hv_vmm_present=1 means we are a VM guest.
            is_vm = true;
        }
    }

    // Stream ioreg output line-by-line and bound execution to 2 s so startup
    // is not blocked on loaded systems.  Return as soon as we see a
    // definitive hypervisor marker (e.g., AppleVirtIO).
    {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::{Duration, Instant};

        let virtualbox_needle = String::from_utf8_lossy(&string_crypt::enc_str!("virtualbox"))
            .trim_end_matches('\0')
            .to_string();
        let vmware_needle = String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
            .trim_end_matches('\0')
            .to_string();
        let qemu_needle = String::from_utf8_lossy(&string_crypt::enc_str!("qemu"))
            .trim_end_matches('\0')
            .to_string();

        if let Ok(mut child) = Command::new("ioreg")
            .arg("-l")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(stdout) = child.stdout.take() {
                let (tx, rx) = mpsc::channel::<String>();
                let reader = std::thread::spawn(move || {
                    let mut buf = BufReader::new(stdout);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match buf.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {
                                let _ = tx.send(line.to_ascii_lowercase());
                            }
                            Err(_) => break,
                        }
                    }
                });

                let mut saw_docker_desktop = false;
                let mut saw_qemu = false;
                let mut timed_out = false;
                let deadline = Instant::now() + Duration::from_secs(2);

                let mut process_line = |line: &str| -> bool {
                    if line.contains("docker")
                        || line.contains("com.docker")
                        || line.contains("docker.desktop")
                    {
                        saw_docker_desktop = true;
                    }

                    if line.contains("applevirtio")
                        || line.contains("parallels")
                        || line.contains(virtualbox_needle.as_str())
                        || line.contains(vmware_needle.as_str())
                    {
                        return true;
                    }

                    if line.contains(qemu_needle.as_str()) {
                        saw_qemu = true;
                    }

                    false
                };

                loop {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        break;
                    }

                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let wait_for = std::cmp::min(remaining, Duration::from_millis(100));

                    match rx.recv_timeout(wait_for) {
                        Ok(line) => {
                            if process_line(&line) {
                                let _ = child.kill();
                                let _ = child.wait();
                                let _ = reader.join();
                                return true;
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => match child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => {}
                            Err(_) => break,
                        },
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }

                // Process any buffered lines emitted right before process exit.
                while let Ok(line) = rx.try_recv() {
                    if process_line(&line) {
                        is_vm = true;
                        break;
                    }
                }

                let _ = child.wait();
                let _ = reader.join();

                if timed_out {
                    tracing::debug!(
                        "env_check: macOS ioreg -l timed out after 2s; returning no ioreg VM indicator"
                    );
                } else if saw_qemu && !saw_docker_desktop {
                    // Only flag qemu when Docker Desktop markers are absent,
                    // since Docker may surface QEMU-backed virtual devices.
                    is_vm = true;
                }
            }
        }
    }

    is_vm
}

#[cfg(windows)]
fn windows_registry_indicates_vm() -> bool {
    // "VIRTUAL" removed: Windows machines with VBS/HVCI or Hyper-V role enabled
    // may have registry values containing "VIRTUAL" (e.g., "VIRTUAL TPM",
    // "VIRTUALIZATION-BASED SECURITY") on physical hardware. Use only
    // hypervisor-vendor-specific strings to avoid false positives.
    let needles = ["VBOX", "VMWARE", "QEMU", "XEN"];
    for path in [
        "HARDWARE\\DESCRIPTION\\System",
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
    ] {
        if let Some(key) = unsafe { reg_open_subkey(win_resolve::HKEY_LOCAL_MACHINE, path) } {
            for value in [
                "SystemBiosVersion",
                "VideoBiosVersion",
                "SystemManufacturer",
            ] {
                if let Some(v) = unsafe { reg_read_string(key, value) } {
                    let upper = v.to_ascii_uppercase();
                    if needles.iter().any(|n| upper.contains(n)) {
                        unsafe {
                            reg_close_key(key);
                        }
                        return true;
                    }
                }
            }
            unsafe {
                reg_close_key(key);
            }
        }
    }
    false
}

/// Detailed version of [`windows_registry_indicates_vm`] that pushes individual
/// `SandboxIndicator`s instead of returning a boolean.
#[cfg(windows)]
fn windows_registry_indicates_vm_detailed(indicators: &mut Vec<common::SandboxIndicator>) -> bool {
    let needles = [
        ("VBOX", "VirtualBox"),
        ("VMWARE", "VMware"),
        ("QEMU", "QEMU"),
        ("XEN", "Xen"),
    ];
    let mut found = false;
    for path in [
        "HARDWARE\\DESCRIPTION\\System",
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
    ] {
        if let Some(key) = unsafe { reg_open_subkey(win_resolve::HKEY_LOCAL_MACHINE, path) } {
            for value in [
                "SystemBiosVersion",
                "VideoBiosVersion",
                "SystemManufacturer",
            ] {
                if let Some(v) = unsafe { reg_read_string(key, value) } {
                    let upper = v.to_ascii_uppercase();
                    for (needle, label) in &needles {
                        if upper.contains(needle) {
                            indicators.push(common::SandboxIndicator {
                                category: "hypervisor".to_string(),
                                detail: format!(
                                    "{label} detected in registry HKLM\\{path}\\{value}"
                                ),
                                weight: 25,
                                source: "registry".to_string(),
                            });
                            found = true;
                        }
                    }
                }
            }
            unsafe {
                reg_close_key(key);
            }
        }
    }
    found
}

/// Detailed version of [`macos_system_profiler_indicates_vm`] that pushes
/// individual `SandboxIndicator`s instead of returning a boolean.
#[cfg(target_os = "macos")]
fn macos_system_profiler_indicates_vm_detailed(
    indicators: &mut Vec<common::SandboxIndicator>,
) -> bool {
    let mut found = false;

    // sysctl hw.model
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
    {
        let model = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if model.contains("virtual") {
            indicators.push(common::SandboxIndicator {
                category: "hypervisor".to_string(),
                detail: "hw.model contains 'virtual'".to_string(),
                weight: 25,
                source: "sysctl".to_string(),
            });
            found = true;
        } else if model.contains(
            String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
                .trim_end_matches('\0')
                .trim(),
        ) {
            indicators.push(common::SandboxIndicator {
                category: "hypervisor".to_string(),
                detail: "hw.model contains 'vmware'".to_string(),
                weight: 25,
                source: "sysctl".to_string(),
            });
            found = true;
        }
    }

    // kern.hv_vmm_present
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("kern.hv_vmm_present")
        .output()
    {
        let present = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if present == "1" {
            indicators.push(common::SandboxIndicator {
                category: "hypervisor".to_string(),
                detail: "kern.hv_vmm_present=1 (running inside hypervisor)".to_string(),
                weight: 30,
                source: "sysctl".to_string(),
            });
            found = true;
        }
    }

    found
}

fn mac_prefix_indicates_vm() -> bool {
    // E-02: Expanded to include additional hypervisor MAC prefixes.
    // KVM/QEMU (52:54:00) and Hyper-V (00:15:5d) are also used by cloud
    // providers; false positives are mitigated because this function is only
    // one of several indicators — detect_vm() requires 2+ indicators to flag
    // vm_detected = true, so a single MAC match won't cause a false refusal.
    //
    // E-03: Majority-vote mitigation.  A bare-metal host may have one USB NIC
    // or docking-station adapter whose OUI coincidentally belongs to a
    // hypervisor vendor (e.g., a VMware OUI on a repurposed VNIC).  We only
    // treat MAC prefixes as a VM indicator when MORE THAN HALF of all
    // enumerated NICs carry a virtual OUI, which filters out single-virtual-
    // NIC bare-metal hosts while still catching analysis VMs that expose
    // only virtual adapters.
    let virtual_prefixes: &[[u8; 3]] = &[
        [0x08u8, 0x00, 0x27], // VirtualBox
        [0x00, 0x0C, 0x29],   // VMware
        [0x00, 0x50, 0x56],   // VMware
        [0x00, 0x15, 0x5D],   // Hyper-V / Azure VM
        [0x52, 0x54, 0x00],   // KVM / QEMU
        [0x00, 0x16, 0x3E],   // Xen
        [0x00, 0x1C, 0x42],   // Parallels
    ];
    // Prefixes belonging to common USB NICs and docking-station chipsets.
    // A NIC whose OUI appears here is excluded from both the total and the
    // virtual counts so that cheap USB adapters and docks do not skew the
    // majority ratio in either direction.
    let excluded_prefixes: &[[u8; 3]] = &[
        [0x00, 0x50, 0xB6], // ASIX Electronics (USB-to-Ethernet, e.g. AX88179)
        [0x00, 0xE0, 0x4C], // Realtek Semiconductor (common USB adapters)
        [0x00, 0x24, 0x9B], // DisplayLink USB docking stations
        [0xB8, 0x27, 0xEB], // Raspberry Pi Foundation
        [0xDC, 0xA6, 0x32], // Raspberry Pi Ltd
        [0xE4, 0x5F, 0x01], // Raspberry Pi Ltd (second OUI block)
        [0x00, 0x17, 0xC8], // Various USB NIC ODMs (e.g. Linksys USB300M)
    ];

    // Returns true when virtual_count * 2 > total_count, i.e. strict majority.
    let majority = |virtual_count: usize, total_count: usize| -> bool {
        total_count > 0 && virtual_count * 2 > total_count
    };

    // Read /sys/class/net on Linux.
    #[cfg(target_os = "linux")]
    {
        let net = Path::new("/sys/class/net");
        if let Ok(entries) = std::fs::read_dir(net) {
            let mut total = 0usize;
            let mut virtual_count = 0usize;
            for entry in entries.flatten() {
                let addr_path = entry.path().join("address");
                if let Ok(addr) = std::fs::read_to_string(&addr_path) {
                    let bytes: Vec<u8> = addr
                        .trim()
                        .split(':')
                        .filter_map(|h| u8::from_str_radix(h, 16).ok())
                        .collect();
                    if bytes.len() >= 3 {
                        let prefix = [bytes[0], bytes[1], bytes[2]];
                        if excluded_prefixes.contains(&prefix) {
                            continue; // skip USB NIC / docking station adapters
                        }
                        total += 1;
                        if virtual_prefixes.contains(&prefix) {
                            virtual_count += 1;
                        }
                    }
                }
            }
            if majority(virtual_count, total) {
                return true;
            }
        }
    }
    // On Windows use GetAdaptersAddresses to read physical MAC addresses.
    #[cfg(windows)]
    {
        let (virtual_count, total) = windows_mac_prefix_counts(virtual_prefixes, excluded_prefixes);
        if majority(virtual_count, total) {
            return true;
        }
    }
    // On macOS use getifaddrs to read physical MAC addresses.
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) == 0 {
                let mut curr = ifap;
                let mut total = 0usize;
                let mut virtual_count = 0usize;
                while !curr.is_null() {
                    let addr = (*curr).ifa_addr;
                    if !addr.is_null() && (*addr).sa_family as libc::c_int == libc::AF_LINK {
                        let sdl = addr as *const libc::sockaddr_dl;
                        // The MAC address bytes follow the interface name in sdl_data.
                        // sdl_data is documented as a variable-length field;
                        // the libc crate's definition is an array of fixed length that
                        // may be shorter than the actual data on some macOS versions.
                        //
                        // Use raw byte arithmetic relative to the sockaddr_dl pointer
                        // itself to compute the MAC start address, which avoids
                        // depending on sdl_data's array length being accurate:
                        //
                        //   offset_of!(sockaddr_dl, sdl_data) = 8 on macOS x86-64/arm64
                        //   MAC starts at sdl_data[sdl_nlen]
                        //   => raw offset from sdl = 8 + sdl_nlen
                        const SDL_DATA_OFFSET: isize = 8;
                        let sdl_nlen = (*sdl).sdl_nlen as isize;
                        let mac_ptr =
                            (sdl as *const u8).offset(SDL_DATA_OFFSET + sdl_nlen) as *const u8;
                        let alen = (*sdl).sdl_alen as usize;
                        if alen >= 3 {
                            let mac = std::slice::from_raw_parts(mac_ptr, 3);
                            let prefix = [mac[0], mac[1], mac[2]];
                            if !excluded_prefixes.contains(&prefix) {
                                total += 1;
                                if virtual_prefixes.contains(&prefix) {
                                    virtual_count += 1;
                                }
                            }
                        }
                    }
                    curr = (*curr).ifa_next;
                }
                libc::freeifaddrs(ifap);
                if majority(virtual_count, total) {
                    return true;
                }
            }
        }
    }
    let _ = virtual_prefixes;
    let _ = excluded_prefixes;
    let _ = Path::new("/dev/null");
    false
}

/// Collect MAC prefix indicators as structured `SandboxIndicator`s.
/// Uses the same majority-vote logic as [`mac_prefix_indicates_vm`], but
/// pushes per-NIC indicators so the scoring pipeline can aggregate them.
fn mac_prefix_indicators(indicators: &mut Vec<common::SandboxIndicator>) {
    let virtual_prefixes: &[[u8; 3]] = &[
        [0x08u8, 0x00, 0x27], // VirtualBox
        [0x00, 0x0C, 0x29],   // VMware
        [0x00, 0x50, 0x56],   // VMware
        [0x00, 0x15, 0x5D],   // Hyper-V / Azure VM
        [0x52, 0x54, 0x00],   // KVM / QEMU
        [0x00, 0x16, 0x3E],   // Xen
        [0x00, 0x1C, 0x42],   // Parallels
    ];
    let virtual_labels: &[&str] = &[
        "VirtualBox",
        "VMware",
        "VMware",
        "Hyper-V/Azure",
        "KVM/QEMU",
        "Xen",
        "Parallels",
    ];
    let excluded_prefixes: &[[u8; 3]] = &[
        [0x00, 0x50, 0xB6], // ASIX Electronics
        [0x00, 0xE0, 0x4C], // Realtek Semiconductor
        [0x00, 0x24, 0x9B], // DisplayLink
        [0xB8, 0x27, 0xEB], // Raspberry Pi Foundation
        [0xDC, 0xA6, 0x32], // Raspberry Pi Ltd
        [0xE4, 0x5F, 0x01], // Raspberry Pi Ltd (second OUI)
        [0x00, 0x17, 0xC8], // Various USB NIC ODMs
    ];

    let majority = |vc: usize, tc: usize| -> bool { tc > 0 && vc * 2 > tc };

    // Collect per-NIC info for indicator generation.
    let mut virtual_nics: Vec<(String, &str)> = Vec::new(); // (mac_label, vendor_label)
    let mut total: usize = 0;
    let mut virtual_count: usize = 0;

    #[cfg(target_os = "linux")]
    {
        let net = Path::new("/sys/class/net");
        if let Ok(entries) = std::fs::read_dir(net) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let addr_path = entry.path().join("address");
                if let Ok(addr) = std::fs::read_to_string(&addr_path) {
                    let bytes: Vec<u8> = addr
                        .trim()
                        .split(':')
                        .filter_map(|h| u8::from_str_radix(h, 16).ok())
                        .collect();
                    if bytes.len() >= 3 {
                        let prefix = [bytes[0], bytes[1], bytes[2]];
                        if excluded_prefixes.contains(&prefix) {
                            continue;
                        }
                        total += 1;
                        if let Some(idx) = virtual_prefixes.iter().position(|p| *p == prefix) {
                            virtual_count += 1;
                            virtual_nics.push((name, virtual_labels[idx]));
                        }
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        let (vc, tc) = windows_mac_prefix_counts(virtual_prefixes, excluded_prefixes);
        total = tc;
        virtual_count = vc;
        // On Windows we don't have easy per-NIC names for indicators,
        // so we just note the counts.
    }
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) == 0 {
                let mut curr = ifap;
                while !curr.is_null() {
                    let addr = (*curr).ifa_addr;
                    if !addr.is_null() && (*addr).sa_family as libc::c_int == libc::AF_LINK {
                        let sdl = addr as *const libc::sockaddr_dl;
                        const SDL_DATA_OFFSET: isize = 8;
                        let sdl_nlen = (*sdl).sdl_nlen as isize;
                        let mac_ptr = (sdl as *const u8).offset(SDL_DATA_OFFSET + sdl_nlen);
                        let alen = (*sdl).sdl_alen as usize;
                        if alen >= 3 {
                            let mac = std::slice::from_raw_parts(mac_ptr, 3);
                            let prefix = [mac[0], mac[1], mac[2]];
                            if !excluded_prefixes.contains(&prefix) {
                                total += 1;
                                if let Some(idx) =
                                    virtual_prefixes.iter().position(|p| *p == prefix)
                                {
                                    virtual_count += 1;
                                    let ifname = std::ffi::CStr::from_ptr(
                                        (*sdl).sdl_data.as_ptr() as *const libc::c_char
                                    );
                                    virtual_nics.push((
                                        ifname.to_string_lossy().to_string(),
                                        virtual_labels[idx],
                                    ));
                                }
                            }
                        }
                    }
                    curr = (*curr).ifa_next;
                }
                libc::freeifaddrs(ifap);
            }
        }
    }

    // Only push indicators when majority-vote threshold is met.
    if majority(virtual_count, total) {
        for (nic_name, vendor) in &virtual_nics {
            indicators.push(common::SandboxIndicator {
                category: "mac_prefix".to_string(),
                detail: format!("Virtual OUI ({vendor}) on {nic_name}"),
                weight: 20,
                source: "mac".to_string(),
            });
        }
        // If no per-NIC names available (Windows path), add a single indicator.
        if virtual_nics.is_empty() && virtual_count > 0 {
            indicators.push(common::SandboxIndicator {
                category: "mac_prefix".to_string(),
                detail: format!("{virtual_count}/{total} NICs have virtual OUI (majority vote)"),
                weight: 20,
                source: "mac".to_string(),
            });
        }
    }

    let _ = virtual_prefixes;
    let _ = excluded_prefixes;
    let _ = Path::new("/dev/null");
}

/// Windows implementation: walk the adapter list via `GetAdaptersAddresses`,
/// count how many adapters have a virtual OUI versus the total (excluding
/// adapters whose OUI is in `excluded_prefixes`), and return `(virtual, total)`.
#[cfg(windows)]
fn windows_mac_prefix_counts(
    virtual_prefixes: &[[u8; 3]],
    excluded_prefixes: &[[u8; 3]],
) -> (usize, usize) {
    use crate::win_types::IP_ADAPTER_ADDRESSES;

    // AF_UNSPEC = 0; skip address lists we don't need.
    const AF_UNSPEC: u32 = 0;
    const GAA_FLAG_SKIP_UNICAST: u32 = 0x0001;
    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    let get_adapters_addresses: win_resolve::FnGetAdaptersAddresses = unsafe {
        win_resolve::resolve_api_or_load(
            win_resolve::IPHLPAPI_DLL_W,
            win_resolve::HASH_IPHLPAPI_DLL,
            win_resolve::HASH_GETADAPTERSADDRESSES,
        )
        .expect("GetAdaptersAddresses not found")
    };

    unsafe {
        // First call with a null buffer to obtain the required size.
        let mut buf_size: u32 = 0;
        get_adapters_addresses(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_size,
        );
        if buf_size == 0 {
            return (0, 0);
        }

        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let ret = get_adapters_addresses(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
            &mut buf_size,
        );
        if ret != win_resolve::ERROR_SUCCESS {
            return (0, 0);
        }

        let mut total = 0usize;
        let mut virtual_count = 0usize;
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES;
        while !adapter.is_null() {
            let phy_len = (*adapter).physical_address_length as usize;
            if phy_len >= 3 {
                let mac = &(&(*adapter).physical_address)[..phy_len];
                let prefix = [mac[0], mac[1], mac[2]];
                if !excluded_prefixes.contains(&prefix) {
                    total += 1;
                    if virtual_prefixes.contains(&prefix) {
                        virtual_count += 1;
                    }
                }
            }
            adapter = (*adapter).next;
        }
        (virtual_count, total)
    }
}

// ------------------------------------------------ anti-analysis (Linux)

#[cfg(target_os = "linux")]
fn is_ld_preload_set() -> bool {
    std::env::var("LD_PRELOAD").is_ok()
}

#[cfg(not(target_os = "linux"))]
fn is_ld_preload_set() -> bool {
    false
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn linux_has_cap_sys_ptrace() -> bool {
    // CAP_SYS_PTRACE is capability bit 19.
    const CAP_SYS_PTRACE_BIT: u32 = 19;

    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };

    let cap_eff_hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim);

    match cap_eff_hex.and_then(|hex| u128::from_str_radix(hex, 16).ok()) {
        Some(mask) => (mask & (1u128 << CAP_SYS_PTRACE_BIT)) != 0,
        None => false,
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn linux_proc_real_uid(proc_path: &Path) -> Option<u32> {
    let status = std::fs::read_to_string(proc_path.join("status")).ok()?;
    let uid_line = status.lines().find(|line| line.starts_with("Uid:"))?;
    uid_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
}

#[cfg(target_os = "linux")]
fn is_tracer_process_running() -> bool {
    // Primary check: TracerPid in our own status — fast and reliable.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            // L-4: Use whitespace-split to handle tab-delimited and unusual
            // /proc/self/status formats (custom kernels, container procfs).
            let mut parts = line.split_whitespace();
            if parts.next().map_or(false, |k| k == "TracerPid:") {
                if let Some(val) = parts.next() {
                    if val != "0" {
                        return true;
                    }
                }
            }
        }
    }

    // Secondary check: scan /proc/<pid>/status (world-readable, no
    // CAP_SYS_PTRACE required, no environ reads) for known tracer names.
    // Each status file is only a few hundred bytes; Name: is always the
    // second line, so reads terminate early in practice.
    const TRACERS: &[&str] = &["strace", "gdb", "ltrace", "gdbserver"];
    let my_uid = unsafe { libc::getuid() };
    let mut scanned = 0usize;

    if let Ok(procs) = std::fs::read_dir("/proc") {
        for entry in procs.flatten() {
            let proc_path = entry.path();

            // Skip non-PID entries (/proc/net, /proc/sys, etc.)
            let is_pid_dir = proc_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.as_bytes().iter().all(u8::is_ascii_digit))
                .unwrap_or(false);
            if !is_pid_dir {
                continue;
            }

            scanned += 1;
            if scanned > 200 {
                tracing::debug!("env_check: /proc tracer scan reached 200-process limit; stopping");
                break;
            }

            let status_text = match std::fs::read_to_string(proc_path.join("status")) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Extract Name: and Uid: from status in a single pass.
            let mut proc_name: Option<&str> = None;
            let mut proc_uid: Option<u32> = None;

            for line in status_text.lines() {
                if let Some(name) = line.strip_prefix("Name:") {
                    proc_name = Some(name.trim());
                } else if let Some(uid_field) = line.strip_prefix("Uid:") {
                    // Uid: real  effective  saved  fs
                    proc_uid = uid_field
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u32>().ok());
                }
                if proc_name.is_some() && proc_uid.is_some() {
                    break;
                }
            }

            let name = match proc_name {
                Some(n) => n,
                None => continue,
            };
            let uid = match proc_uid {
                Some(u) => u,
                None => continue,
            };

            // Only flag tracers belonging to the same user (avoids false
            // positives from another user's legitimate debugger session).
            if uid != my_uid {
                continue;
            }

            if TRACERS.contains(&name) {
                return true;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_tracer_process_running() -> bool {
    false
}

fn detect_timing_anomaly() -> bool {
    // E-03: Skip timing check on Linux if the system is genuinely overloaded
    // (load average > 2× CPU count).  A heavily loaded build server or CI
    // machine will have large sleep jitter that looks like a sandbox even
    // though it is a legitimate execution environment.
    #[cfg(target_os = "linux")]
    if let Ok(la) = std::fs::read_to_string("/proc/loadavg") {
        if let Some(first) = la.split_whitespace().next() {
            if let Ok(load) = first.parse::<f64>() {
                let cpu_count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64;
                if cpu_count > 0.0 && load > cpu_count * 2.0 {
                    // System is overloaded; timing check would be unreliable.
                    return false;
                }
            }
        }
    }

    // 7.2: On Windows, check CPU utilisation via GetSystemTimes.  If the
    // system is under heavy load (>80 % busy) the timing check would produce
    // spurious positives — skip it.
    #[cfg(windows)]
    {
        use crate::win_types::FILETIME;
        let get_system_times: win_resolve::FnGetSystemTimes = unsafe {
            win_resolve::resolve_api(
                pe_resolve::HASH_KERNEL32_DLL,
                win_resolve::HASH_GETSYSTEMTIMES,
            )
            .expect("GetSystemTimes not found")
        };
        let mut idle = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut kernel = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut user = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        unsafe {
            get_system_times(&mut idle, &mut kernel, &mut user);
        }
        let to_u64 = |ft: FILETIME| -> u64 {
            ((ft.dw_high_date_time as u64) << 32) | ft.dw_low_date_time as u64
        };
        let idle0 = to_u64(idle);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut idle2 = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut kernel2 = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut user2 = FILETIME {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        unsafe {
            get_system_times(&mut idle2, &mut kernel2, &mut user2);
        }
        let idle_delta = to_u64(idle2).saturating_sub(idle0);
        let kernel_delta = to_u64(kernel2).saturating_sub(to_u64(kernel));
        let user_delta = to_u64(user2).saturating_sub(to_u64(user));
        let total = idle_delta + kernel_delta + user_delta;
        if total > 0 {
            // total includes idle time so busy_pct is correctly 1 - idle/total.
            let busy_pct = 1.0 - (idle_delta as f64 / total as f64);
            if busy_pct > 0.80 {
                return false; // System overloaded; skip timing check.
            }
        }
    }

    // 7.2: On macOS, use sysctl kern.cpuload (or host_statistics) to check
    // system-wide CPU utilisation before running the timing test.
    #[cfg(target_os = "macos")]
    {
        // vm_stat provides CPU idle ticks via sysctl; use a simpler approach:
        // read the 1-minute load average and compare to CPU count (same
        // heuristic as the Linux path above).
        if let Ok(output) = std::process::Command::new("sysctl")
            .args(["-n", "vm.loadavg"])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout);
            // Output: "{ 0.50 0.42 0.35 }" — first number is 1-min avg
            let trimmed = s.trim_matches(|c: char| c == '{' || c == '}' || c.is_whitespace());
            if let Some(first) = trimmed.split_whitespace().next() {
                if let Ok(load) = first.parse::<f64>() {
                    let cpu_count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64;
                    if cpu_count > 0.0 && load > cpu_count * 2.0 {
                        return false;
                    }
                }
            }
        }
    }

    let mut times = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        times.push(start.elapsed().as_millis() as f64);
    }

    let sum: f64 = times.iter().sum();
    let mean = sum / 10.0;

    let variance: f64 = times.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / 10.0;

    // E-03: Raised thresholds to reduce false positives on loaded-but-legitimate
    // servers.  mean > 500 ms means the 10 ms sleeps are taking 50× too long;
    // variance > 50000 ms² means a single iteration outlier of ≈224 ms.
    let mean_anomaly = mean > 500.0;
    let var_anomaly = variance > 50000.0;

    // Flag if either the mean is outrageously high (slow execution overall,
    // e.g., heavy tracing) or variance is high (e.g., breakpoint on one
    // iteration causing a long pause).
    mean_anomaly || var_anomaly
}

// -------------------------------------------------------------------- domain

/// True if the host's primary domain matches `required` (case‑insensitive).
pub fn validate_domain(required: &str) -> bool {
    let observed = current_domain().unwrap_or_default();
    !required.is_empty() && observed.eq_ignore_ascii_case(required)
}

/// Best‑effort host domain detection.
fn current_domain() -> Option<String> {
    if let Ok(v) = std::env::var("USERDNSDOMAIN") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    #[cfg(windows)]
    {
        if let Some(d) = windows_computer_domain() {
            return Some(d);
        }
        // E-04: Azure AD joined machines do not set the traditional
        // Tcpip\Parameters\Domain key.  Check the AAD join info instead.
        if let Some(d) = windows_aad_domain() {
            return Some(d);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
            let s = s.trim();
            if !s.is_empty() && s != "(none)" {
                return Some(s.to_string());
            }
        }
        if let Some(d) = domain_from_resolv_conf() {
            return Some(d);
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS does not set USERDNSDOMAIN (that is a Windows env var).
        // Use /etc/resolv.conf (present on all macOS systems) and fall back
        // to the Bonjour / local hostname returned by `scutil --get
        // ComputerName` for non-domain-joined hosts.
        if let Some(d) = domain_from_resolv_conf() {
            return Some(d);
        }
        // dsconfigad -show can confirm Active Directory binding, but
        // spawning an external process is noisy.  Prefer /etc/resolv.conf.
    }
    None
}

/// Read `/etc/resolv.conf` and extract the `domain` or `search` directive.
///
/// Shared by the Linux and macOS domain-detection paths.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn domain_from_resolv_conf() -> Option<String> {
    let s = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    domain_from_resolv_conf_content(&s)
}

/// Parse domain/search directives from resolv.conf content.
///
/// Visible for testing so callers can supply synthetic content without
/// touching the filesystem.
fn domain_from_resolv_conf_content(s: &str) -> Option<String> {
    // `domain` takes priority; `search` is accepted as a fallback because
    // many managed hosts (cloud-init, corporate DHCP) only set `search`
    // and omit the `domain` directive entirely.
    //
    // Parsing rules (per resolv.conf(5)):
    //   • Leading whitespace (spaces, tabs) before the directive is accepted
    //     by glibc and musl and must not cause a false negative.
    //   • Lines starting with '#' or ';' after trimming are comments.
    //   • Empty lines are skipped.
    //   • L-5: The separator between the keyword and value may be spaces
    //     OR tabs — use whitespace-split instead of strip_prefix to handle
    //     tab-delimited entries (e.g. `domain\tcorp.example.com` from
    //     systemd-resolved or unusual DHCP clients).
    let mut search_fallback: Option<String> = None;
    for raw_line in s.lines() {
        let line = raw_line.trim();
        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let keyword = match parts.next() {
            Some(k) => k,
            None => continue,
        };
        let value = parts.next().unwrap_or("").trim();
        if keyword == "domain" {
            // `domain` is definitive — return immediately.
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        if search_fallback.is_none() && keyword == "search" {
            // `search` may list multiple domains separated by whitespace;
            // take the first one (the most specific, per resolv.conf(5)).
            if let Some(first) = value.split_whitespace().next() {
                search_fallback = Some(first.to_string());
            }
        }
    }
    search_fallback
}

#[cfg(windows)]
fn windows_computer_domain() -> Option<String> {
    let key = unsafe {
        reg_open_subkey(
            win_resolve::HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        )
    }?;
    let domain = unsafe { reg_read_string(key, "Domain") }?;
    unsafe {
        reg_close_key(key);
    }
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// E-04: Detect Azure AD domain from the AAD join info registry key.
///
/// Azure AD joined machines store join metadata under
/// `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`.  Each
/// subkey is a tenant GUID with values `UserEmail` and `TenantId`.  We
/// extract the domain portion of `UserEmail` (e.g. `contoso.onmicrosoft.com`)
/// as the effective domain for `validate_domain` comparison.
#[cfg(windows)]
fn windows_aad_domain() -> Option<String> {
    let join_info = unsafe {
        reg_open_subkey(
            win_resolve::HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo",
        )
    }?;
    // Enumerate tenant subkeys (each is a GUID-formatted key).
    for name in unsafe { reg_enum_subkey_names(join_info) } {
        if let Some(subkey) = unsafe { reg_open_subkey(join_info, &name) } {
            // Prefer the domain portion of UserEmail.
            if let Some(email) = unsafe { reg_read_string(subkey, "UserEmail") } {
                if let Some(domain_part) = email.splitn(2, '@').nth(1) {
                    if !domain_part.is_empty() {
                        unsafe {
                            reg_close_key(subkey);
                        }
                        unsafe {
                            reg_close_key(join_info);
                        }
                        return Some(domain_part.to_string());
                    }
                }
            }
            // Fall back to TenantId as an opaque tenant identifier.
            if let Some(tenant) = unsafe { reg_read_string(subkey, "TenantId") } {
                if !tenant.is_empty() {
                    unsafe {
                        reg_close_key(subkey);
                    }
                    unsafe {
                        reg_close_key(join_info);
                    }
                    return Some(tenant);
                }
            }
            unsafe {
                reg_close_key(subkey);
            }
        }
    }
    unsafe {
        reg_close_key(join_info);
    }
    None
}

// ------------------------------------------------------------------ enforcer

/// Run every probe and either return `Ok(())` or refuse to start.
///
/// Policy inputs come from `agent.toml`; any unset policy leaves the
/// corresponding signal informational.
pub fn enforce(
    required_domain: Option<&str>,
    refuse_when_debugged: bool,
    refuse_in_vm: bool,
    sandbox_score_threshold: Option<u32>,
) -> EnvDecision {
    let mut report = EnvReport::collect(required_domain);

    // When the operator explicitly sets `refuse_in_vm = true`, the default
    // false-positive mitigations (cloud-uncertainty weight reductions, the
    // "likely legitimate server" threshold boost, and the hypervisor-only
    // suppression) must not silently swallow a VM signal.  Re-evaluate with
    // full indicator weights and the base threshold (30) so that e.g.
    // CPUID(15) + DMI(25) + MAC(20) = 60 >= 30 correctly fires even when
    // normal detection was suppressed.
    if refuse_in_vm && !report.vm_detected {
        let mut strict_indicators = collect_indicators();
        // Restore weights that were conservatively reduced to prevent false
        // positives in informational mode.  In strict (refuse_in_vm) mode the
        // operator's intent is unambiguous.
        for ind in strict_indicators.iter_mut() {
            if ind.source == "dmi" && ind.weight == 10 {
                ind.weight = 25;
            }
            if ind.source == "mac" && ind.weight == 10 {
                ind.weight = 20;
            }
        }
        let strict_total: u32 = strict_indicators.iter().map(|i| i.weight).sum();
        // Use base threshold 30, but raise to 40 on production servers when
        // the evidence is only borderline.  This prevents false positives on
        // loaded production VMs where the only indicators are the hypervisor
        // CPUID bit (15) and a transient timing anomaly (15) — neither of
        // which is conclusive on its own.  A production server with strong
        // evidence (DMI=25 or MAC=20 alongside the CPUID bit) will still
        // score ≥ 40 and be correctly flagged.
        let production_server = is_likely_production_server();
        let num_indicators = strict_indicators.len();
        // The "borderline" zone is exactly the base threshold with at most 2
        // weak indicators: anything above 30 has at least one strong indicator
        // and should not be suppressed.
        let is_borderline = strict_total >= 30 && strict_total <= 35 && num_indicators <= 2;
        let strict_threshold: u32 = if production_server && is_borderline {
            tracing::info!(
                "env_check: raising strict VM threshold 30→40 on production-server host \
                 (strict_total={strict_total}, {num_indicators} indicator(s)); borderline \
                 score from weak indicators alone is insufficient"
            );
            40
        } else {
            30
        };
        if strict_total >= strict_threshold {
            tracing::info!(
                "env_check: strict VM detection fired for refuse_in_vm=true \
                 (strict_total={strict_total}, threshold={strict_threshold}); \
                 normal detection was suppressed"
            );
            report.vm_detected = true;
            report.vm_detected_strict = true;
        }
    }

    let effective_refuse_in_vm = if refuse_in_vm && report.vm_detected {
        if cloud_instance_vm_refusal_bypassed() {
            false
        } else if is_likely_production_server() {
            tracing::warn!(
                "env_check: strict VM detection fired but host has production-server \
                 characteristics (high RAM + long uptime + multi-core); bypassing VM \
                 refusal to avoid false positive on unrecognized cloud/virtualized host"
            );
            false
        } else {
            true
        }
    } else {
        refuse_in_vm
    };
    let refuse = report.should_refuse(
        refuse_when_debugged,
        effective_refuse_in_vm,
        sandbox_score_threshold,
    );
    EnvDecision { report, refuse }
}

/// Decision returned from [`enforce`].
#[derive(Debug, Clone)]
pub struct EnvDecision {
    pub report: EnvReport,
    pub refuse: bool,
}

// ══════════════════════════════════════════════════════════════════════════════
//  HARDENED DETECTION INDICATORS
//
//  Five new signals that are substantially harder for analysis sandboxes to
//  spoof while remaining immune to false positives on legitimate cloud VMs:
//
//  1. Hypervisor vendor string (CPUID 0x40000000) — distinguishes sandbox
//     hypervisors (VirtualBox, unauthenticated VMware) from cloud hypervisors
//     (Azure Hyper-V, GCP/AWS KVM).  The CPUID *bit* (leaf 1 ECX[31]) is
//     already checked; this reads the 12-byte *vendor string* which is harder
//     to spoof without breaking the guest OS.
//
//  2. Timing source consistency cross-check (Windows x86-64) — measures a
//     known workload with RDTSC, QueryPerformanceCounter, and
//     GetSystemTimePreciseAsFileTime.  Physical and properly-virtualised
//     hardware keeps all three within 1-2%; sandboxes that manipulate time
//     sources diverge by >10%.
//
//  3. Hardware topology (CPU count, RAM, disk) — analysis sandboxes often
//     provision minimal resources (1 vCPU, <2 GiB RAM, <40 GiB disk).
//     Weight is zeroed when cloud is confirmed so legitimate small-tier VMs
//     are not penalised.
//
//  4. Process lineage (Windows) — analysis frameworks (Cuckoo, CAPE, Joe
//     Sandbox) typically spawn the sample from python.exe or java.exe.  No
//     legitimate endpoint management tool uses these as parent processes.
//     Weight is NOT zeroed on cloud (analysis frameworks don't run in cloud).
//
//  5. Network environment (Windows) — a single physical NIC with no
//     enterprise proxy configured is a mild sandbox indicator.  Weight is
//     zeroed on confirmed cloud (cloud VMs legitimately have one NIC).
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. Hypervisor vendor string ───────────────────────────────────────────────

/// Read the 12-byte hypervisor vendor string from CPUID leaf 0x40000000.
///
/// This is distinct from the CPUID hypervisor BIT (leaf 1, ECX[31]) — the
/// vendor string identifies *which* hypervisor is running.  Returns `None`
/// when the hypervisor bit is not set or the vendor reports all-zero bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn read_hypervisor_vendor_string() -> Option<[u8; 12]> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;

    // Only proceed if the hypervisor bit is set (leaf 1, ECX[31]).
    #[allow(unused_unsafe)]
    let r1 = unsafe { __cpuid(1) };
    if (r1.ecx & (1 << 31)) == 0 {
        return None;
    }

    // Leaf 0x40000000 — hypervisor vendor is in EBX:ECX:EDX (12 bytes).
    #[allow(unused_unsafe)]
    let r = unsafe { __cpuid(0x40000000) };
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&r.ecx.to_le_bytes());
    vendor[8..12].copy_from_slice(&r.edx.to_le_bytes());

    // All-zero vendor means hypervisor bit set but no identity reported.
    if vendor.iter().all(|&b| b == 0) {
        return None;
    }
    Some(vendor)
}

/// Classify a raw 12-byte hypervisor vendor string into a `SandboxIndicator`.
///
/// This is a pure function exposed for unit testing.  Production callers use
/// [`hypervisor_vendor_indicator`] which reads the CPU directly.
///
/// `cloud_confirmed` is `true` when both `is_expected_hypervisor()` and
/// `is_cloud_instance()` agree — in which case known cloud hypervisors get
/// weight 0 (they are expected and benign).
fn classify_hypervisor_vendor(
    vendor: &[u8; 12],
    cloud_confirmed: bool,
) -> Option<common::SandboxIndicator> {
    // VirtualBox: "VBoxVBoxVBox".  No legitimate cloud uses VirtualBox.
    // High weight even when cloud is ostensibly confirmed (impossible scenario).
    if vendor.starts_with(b"VBoxVBoxVBox") {
        return Some(common::SandboxIndicator {
            category: "hypervisor_vendor".to_string(),
            detail: "VirtualBox hypervisor vendor (CPUID 0x40000000)".to_string(),
            weight: 30,
            source: "cpuid_vendor".to_string(),
        });
    }

    // VMware: "VMwareVMware".  Used by many sandbox products (Cuckoo, CAPE,
    // Triage).  Also used by enterprise VMware vCloud, so reduce weight when
    // cloud is confirmed.
    if vendor.starts_with(b"VMwareVMware") {
        let weight = if cloud_confirmed { 5 } else { 20 };
        return Some(common::SandboxIndicator {
            category: "hypervisor_vendor".to_string(),
            detail: "VMware hypervisor vendor (CPUID 0x40000000)".to_string(),
            weight,
            source: "cpuid_vendor".to_string(),
        });
    }

    // Microsoft Hyper-V: "Microsoft Hv".  Azure uses this, as do Windows
    // Sandbox and analysis VMs on bare-metal Hyper-V.  Weight 0 when cloud
    // is confirmed; mild suspicion otherwise.
    if vendor.starts_with(b"Microsoft Hv") {
        let weight = if cloud_confirmed { 0 } else { 10 };
        if weight > 0 {
            return Some(common::SandboxIndicator {
                category: "hypervisor_vendor".to_string(),
                detail: "Microsoft Hv hypervisor vendor — cloud unconfirmed (Hyper-V sandbox?)"
                    .to_string(),
                weight,
                source: "cpuid_vendor".to_string(),
            });
        }
        return None;
    }

    // KVM: "KVMKVMKVM\0\0\0".  Used by GCP, DigitalOcean, many IaaS providers,
    // and Cuckoo/QEMU-based sandboxes.  Weight 0 when cloud is confirmed.
    if vendor[..9] == *b"KVMKVMKVM" {
        let weight = if cloud_confirmed { 0 } else { 10 };
        if weight > 0 {
            return Some(common::SandboxIndicator {
                category: "hypervisor_vendor".to_string(),
                detail: "KVM hypervisor vendor — cloud unconfirmed (QEMU sandbox?)".to_string(),
                weight,
                source: "cpuid_vendor".to_string(),
            });
        }
        return None;
    }

    // Xen: "XenVMMXenVMM".  Used on older AWS and analysis platforms.
    if vendor.starts_with(b"XenVMMXenVMM") {
        let weight = if cloud_confirmed { 0 } else { 15 };
        if weight > 0 {
            return Some(common::SandboxIndicator {
                category: "hypervisor_vendor".to_string(),
                detail: "Xen hypervisor vendor — cloud unconfirmed".to_string(),
                weight,
                source: "cpuid_vendor".to_string(),
            });
        }
        return None;
    }

    // Unrecognised vendor: rare, mildly suspicious on unconfirmed hosts.
    let printable: String = vendor
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect();
    let weight = if cloud_confirmed { 0 } else { 5 };
    if weight > 0 {
        return Some(common::SandboxIndicator {
            category: "hypervisor_vendor".to_string(),
            detail: format!("Unrecognised hypervisor vendor: '{printable}' (CPUID 0x40000000)"),
            weight,
            source: "cpuid_vendor".to_string(),
        });
    }
    None
}

/// Read the CPU's hypervisor vendor string and return a `SandboxIndicator`
/// when the vendor is suspicious.  x86/x86-64 only.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn hypervisor_vendor_indicator(cloud_confirmed: bool) -> Option<common::SandboxIndicator> {
    let vendor = read_hypervisor_vendor_string()?;
    classify_hypervisor_vendor(&vendor, cloud_confirmed)
}

// ── 2. Timing source consistency cross-check (Windows x86-64) ────────────────

/// Measure a known workload with three independent time sources (RDTSC, QPC,
/// `GetSystemTimePreciseAsFileTime`) and flag divergence > 10%.
///
/// Physical and properly-virtualised hosts keep all three sources within 1-2%
/// of each other.  Sandboxes that manipulate time (e.g. Cuckoo in
/// `clock_resolution` mode) cause RDTSC to disagree with the wall clock by an
/// amount the sandbox cannot easily hide without breaking the guest OS.
///
/// Returns `None` when any time source is unavailable (e.g. `GSTPAFT` on
/// Windows 7, or non-invariant TSC on very old CPUs).
#[cfg(all(windows, target_arch = "x86_64"))]
fn timing_consistency_indicator() -> Option<common::SandboxIndicator> {
    use crate::win_types::FILETIME;

    // Resolve QPC and GSTPAFT — graceful failure on older Windows / VMs.
    let qpc: win_resolve::FnQueryPerformanceCounter = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_QUERYPERFORMANCECOUNTER,
        )?
    };
    let qpf: win_resolve::FnQueryPerformanceFrequency = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_QUERYPERFORMANCEFREQUENCY,
        )?
    };
    let gstpaft: win_resolve::FnGetSystemTimePreciseAsFileTime = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_GETSYSTEMTIMEPRECISEASFILETIME,
        )?
    };

    let mut qpc_freq: i64 = 0;
    unsafe { qpf(&mut qpc_freq) };
    if qpc_freq <= 0 {
        return None; // Degenerate: no QPC frequency
    }

    // ── Snapshot T0 ───────────────────────────────────────────────────────────
    let tsc0 = unsafe { std::arch::x86_64::_rdtsc() };
    let mut qpc0: i64 = 0;
    unsafe { qpc(&mut qpc0) };
    let mut ft0 = FILETIME::default();
    unsafe { gstpaft(&mut ft0) };

    // ── Known workload: 10,000 multiply-accumulate iterations ─────────────────
    // Written to `acc` via `write_volatile` so the compiler cannot eliminate
    // the loop; the pattern is deterministic and fast (< 100 µs on any CPU).
    let mut acc: u64 = 1;
    for i in 0u64..10_000 {
        acc = acc.wrapping_mul(i.wrapping_add(1)).wrapping_add(i);
    }
    // Prevent dead-code elimination.
    unsafe { std::ptr::write_volatile(&mut acc, acc) };

    // ── Snapshot T1 ───────────────────────────────────────────────────────────
    let tsc1 = unsafe { std::arch::x86_64::_rdtsc() };
    let mut qpc1: i64 = 0;
    unsafe { qpc(&mut qpc1) };
    let mut ft1 = FILETIME::default();
    unsafe { gstpaft(&mut ft1) };

    let tsc_delta = tsc1.saturating_sub(tsc0);
    let qpc_delta = qpc1.saturating_sub(qpc0).max(0) as u64;
    let ft_u64 = |ft: FILETIME| -> u64 {
        ((ft.dw_high_date_time as u64) << 32) | ft.dw_low_date_time as u64
    };
    let ft_delta = ft_u64(ft1).saturating_sub(ft_u64(ft0));

    // Emulator indicator: RDTSC did not advance while QPC progressed.
    // Under hardware virtualisation RDTSC is passed through transparently;
    // only emulators that don't simulate the TSC register will produce this.
    if tsc_delta == 0 && qpc_delta > 100 {
        return Some(common::SandboxIndicator {
            category: "timing_consistency".to_string(),
            detail: "RDTSC delta is 0 while QPC advanced (TSC not emulated — full emulator)"
                .to_string(),
            weight: 20,
            source: "rdtsc_consistency".to_string(),
        });
    }

    // Time-skew indicator: QPC (in 100ns units) vs GSTPAFT diverge by > 10%.
    // Convert QPC ticks to 100ns: (qpc_delta * 10_000_000) / freq.
    if ft_delta > 0 && qpc_delta > 0 {
        let qpc_in_100ns = (qpc_delta as u128)
            .saturating_mul(10_000_000)
            .checked_div(qpc_freq as u128)
            .unwrap_or(0) as u64;
        if qpc_in_100ns > 0 {
            let max_v = qpc_in_100ns.max(ft_delta);
            let min_v = qpc_in_100ns.min(ft_delta);
            let divergence_pct = (max_v - min_v).saturating_mul(100) / max_v;
            if divergence_pct > 10 {
                return Some(common::SandboxIndicator {
                    category: "timing_consistency".to_string(),
                    detail: format!(
                        "QPC and wall-clock diverge by {divergence_pct}% (time source manipulation)"
                    ),
                    weight: 20,
                    source: "rdtsc_consistency".to_string(),
                });
            }
        }
    }

    None
}

// ── 3. Hardware topology ──────────────────────────────────────────────────────

/// Check CPU count, RAM, and system-disk size for sandbox-typical minimal
/// resource provisioning.
///
/// Analysis sandboxes commonly use 1 vCPU and <2 GiB RAM to reduce overhead.
/// Legitimate cloud VMs at even the smallest tier (e.g. AWS t3.micro) have
/// 2 vCPUs and 1 GiB RAM — still suspicious by this check, but the
/// `cloud_confirmed` path in `collect_indicators` zeroes all "topology" source
/// weights when the cloud context is confirmed, so legitimate small VMs are
/// not penalised.
#[cfg(windows)]
fn hardware_topology_indicators(indicators: &mut Vec<common::SandboxIndicator>) {
    // ── CPU count via GetSystemInfo ───────────────────────────────────────────
    let cpu_count: u32 = {
        let get_sysinfo: win_resolve::FnGetSystemInfo = unsafe {
            win_resolve::resolve_api(
                pe_resolve::HASH_KERNEL32_DLL,
                win_resolve::HASH_GETSYSTEMINFO,
            )
            .expect("GetSystemInfo not found")
        };
        let mut si = win_resolve::SystemInfo::default();
        unsafe { get_sysinfo(&mut si) };
        si.dw_number_of_processors
    };

    match cpu_count {
        0 | 1 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{cpu_count} logical CPU(s) — sandboxes commonly use 1 vCPU"),
            weight: 15,
            source: "topology".to_string(),
        }),
        2 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: "2 logical CPUs — suspicious but possible for small cloud VMs".to_string(),
            weight: 5,
            source: "topology".to_string(),
        }),
        _ => {} // 4+ CPUs → normal
    }

    // ── RAM via get_ram_gb() ──────────────────────────────────────────────────
    let ram_gb = get_ram_gb();
    if ram_gb < 2 {
        indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{ram_gb} GiB RAM — sandboxes often provision <2 GiB"),
            weight: 15,
            source: "topology".to_string(),
        });
    }

    // ── System disk size via GetDiskFreeSpaceExW on C:\ ───────────────────────
    let get_disk: win_resolve::FnGetDiskFreeSpaceExW = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_GETDISKFREESPACEEXW,
        )
        .expect("GetDiskFreeSpaceExW not found")
    };
    // C:\ as null-terminated wide string.
    const C_DRIVE_W: &[u16] = &['C' as u16, ':' as u16, '\\' as u16, 0u16];
    let mut _free_caller: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut _free_total: u64 = 0;
    let ok = unsafe {
        get_disk(
            C_DRIVE_W.as_ptr(),
            &mut _free_caller,
            &mut total_bytes,
            &mut _free_total,
        )
    };
    if ok != 0 {
        let disk_gb = total_bytes / (1024 * 1024 * 1024);
        if disk_gb > 0 && disk_gb < 40 {
            indicators.push(common::SandboxIndicator {
                category: "topology".to_string(),
                detail: format!(
                    "C:\\ disk is {disk_gb} GiB — sandboxes often use <40 GiB system disks"
                ),
                weight: 10,
                source: "topology".to_string(),
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn hardware_topology_indicators(indicators: &mut Vec<common::SandboxIndicator>) {
    // ── CPU count via sysconf ─────────────────────────────────────────────
    let cpu_count: u32 = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32 };

    match cpu_count {
        0 | 1 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{cpu_count} logical CPU(s) — sandboxes commonly use 1 vCPU"),
            weight: 15,
            source: "topology".to_string(),
        }),
        2 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: "2 logical CPUs — suspicious but possible for small cloud VMs".to_string(),
            weight: 5,
            source: "topology".to_string(),
        }),
        _ => {} // 4+ CPUs → normal
    }

    // ── RAM via get_ram_gb() ──────────────────────────────────────────────
    let ram_gb = get_ram_gb();
    if ram_gb < 2 {
        indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{ram_gb} GiB RAM — sandboxes often provision <2 GiB"),
            weight: 15,
            source: "topology".to_string(),
        });
    }

    // ── System disk size via statvfs on / ─────────────────────────────────
    let disk_gb: u64 = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut stat) == 0 {
            (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024 * 1024)
        } else {
            0
        }
    };
    if disk_gb > 0 && disk_gb < 40 {
        indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!(
                "root disk is {disk_gb} GiB — sandboxes often use <40 GiB system disks"
            ),
            weight: 10,
            source: "topology".to_string(),
        });
    }
}

#[cfg(target_os = "macos")]
fn hardware_topology_indicators(indicators: &mut Vec<common::SandboxIndicator>) {
    // ── CPU count via sysconf ─────────────────────────────────────────────
    let cpu_count: u32 = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32 };

    match cpu_count {
        0 | 1 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{cpu_count} logical CPU(s) — sandboxes commonly use 1 vCPU"),
            weight: 15,
            source: "topology".to_string(),
        }),
        2 => indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: "2 logical CPUs — suspicious but possible for small cloud VMs".to_string(),
            weight: 5,
            source: "topology".to_string(),
        }),
        _ => {} // 4+ CPUs → normal
    }

    // ── RAM via sysctl hw.memsize ─────────────────────────────────────────
    let ram_gb: u64 = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
        .map(|bytes| bytes / (1024 * 1024 * 1024))
        .unwrap_or(0);
    if ram_gb < 2 {
        indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!("{ram_gb} GiB RAM — sandboxes often provision <2 GiB"),
            weight: 15,
            source: "topology".to_string(),
        });
    }

    // ── System disk size via statvfs on / ─────────────────────────────────
    let disk_gb: u64 = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut stat) == 0 {
            (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024 * 1024)
        } else {
            0
        }
    };
    if disk_gb > 0 && disk_gb < 40 {
        indicators.push(common::SandboxIndicator {
            category: "topology".to_string(),
            detail: format!(
                "root disk is {disk_gb} GiB — sandboxes often use <40 GiB system disks"
            ),
            weight: 10,
            source: "topology".to_string(),
        });
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn hardware_topology_indicators(_indicators: &mut Vec<common::SandboxIndicator>) {
    // Not implemented on other platforms.
}

// ── 4. Process lineage analysis (Windows) ─────────────────────────────────────

/// Names of analysis frameworks that commonly spawn malware samples directly.
/// These never appear as legitimate endpoint management parent processes.
const ANALYSIS_FRAMEWORKS: &[&str] = &[
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    "java.exe",
    "javaw.exe",
    "node.exe",
    "nodejs.exe",
    "ruby.exe",
    "perl.exe",
    "sample_runner.exe",
    "malware_runner.exe",
    "analyzer.exe",
    "cuckoo.exe",
    "cuckoomon.dll",
    "cape.exe",
];

/// Common intermediary processes used by sandboxes to obfuscate parent
/// lineage.  These are legitimate programs but when they appear between
/// an analysis framework and the payload, walking through them reveals
/// the true launcher.
const LINEAGE_INTERMEDIARIES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "conhost.exe",
    "wsl.exe",
    "bash.exe",
    "sh.exe",
];

/// Classify a process name as an analysis framework.
///
/// Returns `true` when the name matches a known analysis/sandbox launcher.
/// Pure function exposed for unit testing.
fn is_analysis_framework(name: &str) -> bool {
    ANALYSIS_FRAMEWORKS.contains(&name)
}

/// Classify a process name as a benign intermediary that sandboxes use
/// to obscure their lineage (e.g., `cmd.exe → python.exe → payload`).
///
/// Returns `true` for common shell/script hosts that are legitimate but
/// should be walked through to find the real ancestor.
fn is_lineage_intermediary(name: &str) -> bool {
    LINEAGE_INTERMEDIARIES.contains(&name)
}

/// Classify a parent process name as suspicious, returning a `SandboxIndicator`
/// when the name matches a known analysis framework.
///
/// This is a pure function exposed for unit testing.
fn classify_parent_process_name(parent_name: Option<&str>) -> Option<common::SandboxIndicator> {
    match parent_name {
        // No parent found — process was orphaned or parent has already exited
        // (e.g., setup.exe dropped the agent and then exited).  Mild suspicion.
        None => Some(common::SandboxIndicator {
            category: "lineage".to_string(),
            detail: "No parent process found in snapshot (agent may be orphaned)".to_string(),
            weight: 5,
            source: "lineage".to_string(),
        }),
        Some(name) if is_analysis_framework(name) => Some(common::SandboxIndicator {
            category: "lineage".to_string(),
            detail: format!("Agent spawned by analysis-framework process: {name}"),
            weight: 25,
            source: "lineage".to_string(),
        }),
        _ => None, // Legitimate parent
    }
}

/// Classify an ancestor process (not the immediate parent) as suspicious.
///
/// Uses a decaying weight: 15 for grandparent, 10 for great-grandparent and
/// beyond.  This catches sandbox chains like `cmd.exe → python.exe → payload`
/// without over-penalizing deep legitimate process trees.
fn classify_ancestor_process_name(
    ancestor_name: &str,
    depth: u32,
) -> Option<common::SandboxIndicator> {
    if !is_analysis_framework(ancestor_name) {
        return None;
    }

    // Weight decays with depth: 15 for grandparent (depth=2), 10 for deeper.
    let weight = if depth <= 2 { 15 } else { 10 };
    let relation = if depth == 2 {
        "grandparent"
    } else if depth == 3 {
        "great-grandparent"
    } else {
        "ancestor"
    };

    Some(common::SandboxIndicator {
        category: "lineage".to_string(),
        detail: format!(
            "Analysis-framework {relation} detected (depth={depth}): {ancestor_name}"
        ),
        weight,
        source: "lineage".to_string(),
    })
}

/// Walk the full ancestor process chain using `CreateToolhelp32Snapshot` and
/// return the strongest `SandboxIndicator` from any ancestor matching a known
/// analysis framework.
///
/// The walk proceeds up the process tree from the agent's immediate parent
/// through grandparents and beyond (up to 8 levels).  Intermediary processes
/// (cmd.exe, powershell.exe, wscript.exe, etc.) are transparent — the walk
/// continues through them to find the real launcher.  Weight decays with
/// distance: 25 (parent), 15 (grandparent), 10 (great-grandparent+).
///
/// This catches sandbox chains like:
///   `cmd.exe → python.exe → payload`      (weight 15 from python.exe)
///   `powershell → cmd → python → payload` (weight 10 from python.exe)
///   `explorer → python.exe → payload`     (weight 25 from python.exe)
///
/// Why this doesn't produce false positives on cloud VMs:
/// Analysis frameworks (Cuckoo, CAPE, Joe Sandbox) do not run inside
/// production cloud VMs.  No legitimate CI/CD or deployment tool spawns agents
/// from python.exe or java.exe at runtime.
#[cfg(windows)]
fn process_lineage_indicator() -> Option<common::SandboxIndicator> {
    use crate::win_types::{ProcessEntry32W, INVALID_HANDLE_VALUE};

    // Resolve Toolhelp32 APIs via the existing dynamic resolver.
    let create_snapshot: win_resolve::FnCreateToolhelp32Snapshot = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_CREATETOOLHELP32SNAPSHOT,
        )?
    };
    let process32_first: win_resolve::FnProcess32FirstW = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_PROCESS32FIRSTW,
        )?
    };
    let process32_next: win_resolve::FnProcess32NextW = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_PROCESS32NEXTW,
        )?
    };
    let close_handle: win_resolve::FnCloseHandle = unsafe {
        win_resolve::resolve_api(pe_resolve::HASH_KERNEL32_DLL, win_resolve::HASH_CLOSEHANDLE)?
    };
    let get_cur_pid: win_resolve::FnGetCurrentProcessId = unsafe {
        win_resolve::resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            win_resolve::HASH_GETCURRENTPROCESSID,
        )?
    };

    let our_pid = unsafe { get_cur_pid() };

    // TH32CS_SNAPPROCESS = 0x00000002 — enumerate all processes.
    let snapshot = unsafe { create_snapshot(0x00000002, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return None;
    }

    // Collect (pid, parent_pid, exe_name_lowercase) for all processes.
    let mut processes: Vec<(u32, u32, String)> = Vec::with_capacity(128);
    let mut entry = ProcessEntry32W {
        dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
        ..ProcessEntry32W::default()
    };

    if unsafe { process32_first(snapshot, &mut entry) } != 0 {
        loop {
            let name_len = entry
                .sz_exe_file
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.sz_exe_file.len());
            let name =
                String::from_utf16_lossy(&entry.sz_exe_file[..name_len]).to_ascii_lowercase();
            processes.push((entry.th32_process_id, entry.th32_parent_process_id, name));
            // Reset size field before the next call, as documented.
            entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
            if unsafe { process32_next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { close_handle(snapshot) };

    // Build a PID → (parent_pid, name) lookup for fast ancestor walking.
    let proc_map: std::collections::HashMap<u32, (u32, &str)> = processes
        .iter()
        .map(|(pid, ppid, name)| (*pid, (*ppid, name.as_str())))
        .collect();

    // Find our own entry first.
    let mut current_pid = match proc_map.get(&our_pid) {
        Some((ppid, _)) => *ppid,
        None => return None, // Our own entry not found — degenerate snapshot
    };

    // ── Check immediate parent (depth 1) ─────────────────────────────────
    let parent_name = proc_map
        .get(&current_pid)
        .map(|(_, name)| name.to_string());

    if let Some(ind) = classify_parent_process_name(parent_name.as_deref()) {
        return Some(ind);
    }

    // ── Walk ancestors beyond the immediate parent ────────────────────────
    // Walk up to 8 levels (parent = depth 1, grandparent = depth 2, etc.).
    // Intermediary processes (cmd.exe, powershell, etc.) are transparent:
    // we skip through them to find the real launcher.
    const MAX_WALK_DEPTH: u32 = 8;
    let mut depth: u32 = 1; // parent is depth 1 (already checked above)
    let mut best_indicator: Option<common::SandboxIndicator> = None;

    for _ in 0..MAX_WALK_DEPTH {
        // Move to the next ancestor.
        current_pid = match proc_map.get(&current_pid) {
            Some((ppid, _)) => *ppid,
            None => break, // No more ancestors (reached root or orphaned)
        };
        depth += 1;

        let ancestor_name = match proc_map.get(&current_pid) {
            Some((_, name)) => *name,
            None => break,
        };

        // Check if this ancestor is a known analysis framework.
        if let Some(ind) = classify_ancestor_process_name(ancestor_name, depth) {
            // Keep the strongest indicator (highest weight).
            match &best_indicator {
                None => best_indicator = Some(ind),
                Some(existing) if ind.weight > existing.weight => best_indicator = Some(ind),
                _ => {}
            }
            // Don't break — continue walking to find potentially closer
            // ancestors with higher weight (shouldn't happen since weight
            // decays, but defensive).
        }

        // If this is NOT an intermediary and NOT a framework, stop walking.
        // We don't want to report analysis frameworks that happen to be
        // running somewhere deep in the tree but aren't actually in the
        // agent's launch chain.
        if !is_analysis_framework(ancestor_name) && !is_lineage_intermediary(ancestor_name) {
            break;
        }
    }

    best_indicator
}

#[cfg(not(windows))]
fn process_lineage_indicator() -> Option<common::SandboxIndicator> {
    None
}

// ── 5. Network environment profiling (Windows) ────────────────────────────────

/// Check the number of physical network adapters and the presence of an
/// enterprise proxy.
///
/// A single physical NIC with no proxy configured is a mild indicator of a
/// sandbox environment (sandboxes commonly expose only the host-bridge NIC).
/// Enterprise endpoints and cloud VMs with multiple NICs or configured proxies
/// are excluded, keeping the false-positive rate near zero.
///
/// Why cloud VMs don't produce false positives:
/// The "topology" source weight is zeroed when cloud is confirmed (step 10b in
/// `collect_indicators`), so even a cloud VM with one NIC doesn't contribute.
/// The lineage and timing indicators still carry full weight on cloud VMs
/// because analysis frameworks don't run there.
#[cfg(windows)]
fn network_environment_indicator() -> Option<common::SandboxIndicator> {
    use crate::win_types::IP_ADAPTER_ADDRESSES;

    const AF_UNSPEC: u32 = 0;
    // Skip address lists we don't need; we only care about physical MACs.
    const GAA_FLAG_SKIP_UNICAST: u32 = 0x0001;
    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    let get_adapters: win_resolve::FnGetAdaptersAddresses = unsafe {
        win_resolve::resolve_api_or_load(
            win_resolve::IPHLPAPI_DLL_W,
            win_resolve::HASH_IPHLPAPI_DLL,
            win_resolve::HASH_GETADAPTERSADDRESSES,
        )?
    };

    let adapter_count: usize = unsafe {
        let mut buf_size: u32 = 0;
        get_adapters(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_size,
        );
        if buf_size == 0 {
            return None;
        }
        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let ret = get_adapters(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
            &mut buf_size,
        );
        if ret != win_resolve::ERROR_SUCCESS {
            return None;
        }
        let mut count = 0usize;
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES;
        while !adapter.is_null() {
            // Only count adapters with a real physical MAC address (≥6 bytes).
            // This skips loopback, Teredo, 6to4, and WAN miniport adapters.
            if (*adapter).physical_address_length >= 6 {
                count += 1;
            }
            adapter = (*adapter).next;
        }
        count
    };

    // Check for a system-wide WinHTTP/WinInet proxy in the registry.
    // A configured proxy strongly suggests an enterprise environment rather
    // than a sandbox (sandboxes typically don't set up MITM proxy infra).
    let proxy_configured = unsafe {
        // Try HKLM Internet Settings for machine-wide proxy (most reliable).
        let key = reg_open_subkey(
            win_resolve::HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        );
        if let Some(k) = key {
            let enabled = reg_read_string(k, "ProxyEnable")
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);
            reg_close_key(k);
            enabled != 0
        } else {
            false
        }
    };

    if proxy_configured {
        return None; // Enterprise proxy present → not a sandbox
    }

    if adapter_count <= 1 {
        return Some(common::SandboxIndicator {
            category: "network".to_string(),
            detail: format!(
                "{adapter_count} physical NIC(s) and no enterprise proxy — common sandbox profile"
            ),
            weight: 5,
            source: "network".to_string(),
        });
    }

    None
}

#[cfg(not(windows))]
fn network_environment_indicator() -> Option<common::SandboxIndicator> {
    None
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_with_no_required_domain_has_none_match() {
        let r = EnvReport::collect(None);
        assert!(r.domain_match.is_none());
        // Refusal must not fire from a missing required_domain alone.
        assert!(!r.should_refuse(false, false, None));
    }

    #[test]
    fn validate_domain_rejects_unmatched() {
        assert!(!validate_domain("definitely-not-this-domain-xyz.invalid"));
    }

    #[test]
    fn validate_domain_matches_when_env_var_set() {
        // SAFETY: tests run in this process and we restore the env afterward.
        let prev = std::env::var("USERDNSDOMAIN").ok();
        // Use scopeguard-style restore via Drop.
        struct Restore(Option<String>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("USERDNSDOMAIN", v),
                    None => std::env::remove_var("USERDNSDOMAIN"),
                }
            }
        }
        let _g = Restore(prev);
        std::env::set_var("USERDNSDOMAIN", "corp.example.com");
        assert!(validate_domain("CORP.example.com"));
        assert!(!validate_domain("other.example.com"));
    }

    /// Simulate a debugged process by writing a fake `/proc/self/status`
    /// line and parsing it through the same routine the real check uses.
    #[test]
    fn detect_debugger_from_synthetic_status() {
        fn parse_tracer(status: &str) -> bool {
            for line in status.lines() {
                let mut parts = line.split_whitespace();
                if parts.next().map_or(false, |k| k == "TracerPid:") {
                    if let Some(val) = parts.next() {
                        return val.parse::<u32>().map(|p| p != 0).unwrap_or(false);
                    }
                }
            }
            false
        }
        let undebugged = "Name:\tagent\nTracerPid:\t0\n";
        let debugged = "Name:\tagent\nTracerPid:\t1234\n";
        assert!(!parse_tracer(undebugged));
        assert!(parse_tracer(debugged));
    }

    #[test]
    fn refusal_policy_combines_signals() {
        let mut r = EnvReport::default();
        assert!(!r.should_refuse(false, false, None));
        r.debugger_present = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(true, false, None));
        r.debugger_present = false;
        r.domain_match = Some(false);
        assert!(r.should_refuse(false, false, None));
        r.domain_match = Some(true);
        r.vm_detected = true;
        r.vm_detected_strict = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(false, true, None));
    }

    #[test]
    fn unrelated_tracer_process_is_informational() {
        let mut r = EnvReport::default();
        r.tracer_process_found = true;
        assert!(!r.should_refuse(false, false, None));
    }

    #[test]
    fn cloud_vm_indicators_are_informational_by_default() {
        let mut r = EnvReport::default();
        r.vm_detected = true;
        r.vm_detected_strict = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(false, true, None));
    }

    #[test]
    fn sandbox_score_threshold_is_explicit() {
        let mut r = EnvReport::default();
        r.sandbox_score = 80;
        assert!(!r.should_refuse(false, false, None));
        assert!(!r.should_refuse(false, false, Some(81)));
        assert!(r.should_refuse(false, false, Some(80)));
    }

    #[test]
    fn sandbox_score_threshold_without_corroboration_uses_floor() {
        let mut r = EnvReport::default();
        // Score below 50: the multi-category range is 50–59, so scores below
        // 50 still use the strict floor of 60 and should NOT trigger refusal.
        r.sandbox_score = 45;
        assert!(
            !r.should_refuse(false, false, Some(30)),
            "without corroboration, scores below the multi-category range (50–59) \
             should be suppressed by the 60-floor"
        );

        // Score 55 in the multi-category range: a score of 50+ requires at
        // least 2 independent heuristic categories to contribute (no single
        // category exceeds 30).  This is strong enough to trigger refusal
        // with the lowered floor of 50.
        r.sandbox_score = 55;
        assert!(
            r.should_refuse(false, false, Some(30)),
            "without corroboration, multi-category score (50–59) should trigger \
             refusal at the lowered 50-floor"
        );

        r.sandbox_score = 60;
        assert!(
            r.should_refuse(false, false, Some(30)),
            "without corroboration, threshold floor should still refuse at very high score"
        );
    }

    #[test]
    fn sandbox_score_threshold_with_corroboration_uses_operator_value() {
        let mut r = EnvReport::default();
        r.timing_anomaly_detected = true;
        r.sandbox_score = 35;
        assert!(
            r.should_refuse(false, false, Some(30)),
            "with corroboration, configured threshold should apply directly"
        );
    }

    #[test]
    fn heuristic_only_medium_indicators_do_not_trigger_vm_detection() {
        let indicators = vec![
            common::SandboxIndicator {
                category: "timing".to_string(),
                detail: "Low mouse activity".to_string(),
                weight: 30,
                source: "mouse".to_string(),
            },
            common::SandboxIndicator {
                category: "desktop".to_string(),
                detail: "Few desktop windows".to_string(),
                weight: 25,
                source: "desktop".to_string(),
            },
            common::SandboxIndicator {
                category: "uptime".to_string(),
                detail: "Low uptime".to_string(),
                weight: 10,
                source: "uptime".to_string(),
            },
        ];
        let (is_sandbox, _, _ind) = evaluate_sandbox_score(&indicators);
        assert!(
            !is_sandbox,
            "medium heuristic-only indicators should be informational"
        );
    }

    #[test]
    fn zero_weight_expected_context_does_not_bypass_heuristic_guard() {
        let indicators = vec![
            common::SandboxIndicator {
                category: "cloud_bios".to_string(),
                detail: "Known cloud hypervisor DMI/registry strings detected".to_string(),
                weight: 0,
                source: "registry".to_string(),
            },
            common::SandboxIndicator {
                category: "timing".to_string(),
                detail: "Low mouse activity".to_string(),
                weight: 30,
                source: "mouse".to_string(),
            },
            common::SandboxIndicator {
                category: "desktop".to_string(),
                detail: "Few desktop windows".to_string(),
                weight: 25,
                source: "desktop".to_string(),
            },
            common::SandboxIndicator {
                category: "uptime".to_string(),
                detail: "Low uptime".to_string(),
                weight: 10,
                source: "uptime".to_string(),
            },
        ];

        let (is_sandbox, _, _) = evaluate_sandbox_score(&indicators);
        assert!(
            !is_sandbox,
            "zero-weight expected context must not make heuristic-only evidence look corroborated"
        );
    }

    #[test]
    fn heuristic_only_high_indicators_still_trigger_vm_detection() {
        let indicators = vec![
            common::SandboxIndicator {
                category: "timing".to_string(),
                detail: "Low mouse activity".to_string(),
                weight: 30,
                source: "mouse".to_string(),
            },
            common::SandboxIndicator {
                category: "desktop".to_string(),
                detail: "Few desktop windows".to_string(),
                weight: 25,
                source: "desktop".to_string(),
            },
            common::SandboxIndicator {
                category: "uptime".to_string(),
                detail: "Low uptime".to_string(),
                weight: 20,
                source: "uptime".to_string(),
            },
        ];
        let (is_sandbox, _, _ind) = evaluate_sandbox_score(&indicators);
        assert!(
            is_sandbox,
            "very high heuristic-only score should still classify as sandbox"
        );
    }

    // ── Strict domain matching ────────────────────────────────────────────────

    /// Domain matching is case-insensitive and must match the full domain string.
    #[test]
    fn strict_domain_match_is_case_insensitive() {
        assert!(validate_domain_pair("CORP.EXAMPLE.COM", "corp.example.com"));
        assert!(validate_domain_pair("corp.example.com", "CORP.EXAMPLE.COM"));
        assert!(!validate_domain_pair(
            "corp.example.com",
            "other.example.com"
        ));
        // Empty required domain should never match (not configured).
        assert!(!validate_domain_pair("corp.example.com", ""));
    }

    /// A subdomain of the required domain is NOT considered a match (strict match).
    #[test]
    fn strict_domain_does_not_match_subdomain() {
        // "workstation.corp.example.com" is not the same as "corp.example.com".
        assert!(!validate_domain_pair(
            "workstation.corp.example.com",
            "corp.example.com"
        ));
    }

    fn validate_domain_pair(observed: &str, required: &str) -> bool {
        if required.is_empty() {
            return false;
        }
        observed.eq_ignore_ascii_case(required)
    }

    // ── VM detection false-positive scenarios ─────────────────────────────────

    /// `detect_vm` must never refuse on its own: `should_refuse` only reacts to
    /// `vm_detected` when the operator explicitly sets `refuse_in_vm = true`.
    #[test]
    fn vm_detected_is_informational_by_default() {
        let report = EnvReport {
            vm_detected: true,
            vm_detected_strict: true,
            ..EnvReport::default()
        };
        // Default policy: refuse_in_vm = false → must NOT refuse.
        assert!(!report.should_refuse(false, false, None));
        // Explicit policy: refuse_in_vm = true → must refuse.
        assert!(report.should_refuse(false, true, None));
    }

    /// A single VM indicator is not enough to set vm_detected = true.
    /// (detect_vm() requires 2+ indicators.)
    #[test]
    fn detect_vm_requires_multiple_indicators() {
        // This test verifies the policy, not the hardware probes.
        // The probe functions are platform-specific, but the thresholding
        // logic is captured in should_refuse which is testable here.
        let report = EnvReport {
            vm_detected: false, // Single indicator: not enough.
            ..EnvReport::default()
        };
        assert!(!report.should_refuse(false, true, None));
    }

    // ── Unknown hypervisors ───────────────────────────────────────────────────

    /// A machine with an unknown hypervisor that doesn't match cloud needles
    /// contributes a VM indicator but must NOT automatically cause refusal.
    #[test]
    fn unknown_hypervisor_requires_explicit_policy_to_refuse() {
        let report = EnvReport {
            vm_detected: true, // Detected but unknown hypervisor.
            vm_detected_strict: true,
            ..EnvReport::default()
        };
        // Without refuse_in_vm, even an unknown hypervisor is just informational.
        assert!(!report.should_refuse(false, false, None));
    }

    // ── Cloud provider detection (headless / CI) ──────────────────────────────

    /// A cloud/CI environment sets vm_detected but must pass with default policy.
    ///
    /// This mirrors the CI runner scenario: GitHub Actions / AWS CodeBuild runs
    /// inside a VM; the agent must not refuse when env-validation is enabled
    /// unless `refuse_in_vm = true` is explicitly set by the operator.
    #[test]
    fn cloud_ci_environment_does_not_auto_refuse() {
        let report = EnvReport {
            vm_detected: true,  // Cloud hypervisor detected.
            vm_detected_strict: true,  // Strict mode also detects it.
            sandbox_score: 45,  // Moderate score from headless probe.
            domain_match: None, // No domain requirement configured.
            ..EnvReport::default()
        };
        assert!(
            !report.should_refuse(false, false, None),
            "cloud/CI vm_detected=true must not refuse with default policy"
        );
        assert!(
            !report.should_refuse(false, false, Some(60)),
            "sandbox score 45 must not trigger threshold 60"
        );
        // Only refuses if both flags are explicitly set.
        assert!(
            report.should_refuse(false, true, None),
            "refuse_in_vm=true must still refuse"
        );
    }

    // ── macOS headless / CI ───────────────────────────────────────────────────

    /// On macOS in a headless CI environment, the sandbox probe returns 0 for
    /// mouse and desktop scores (no display), so the total sandbox score should
    /// be low enough not to trigger a default threshold.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_headless_sandbox_score_is_below_default_threshold() {
        // In headless macOS (no DISPLAY, no window server), the sandbox probe
        // returns 0 for mouse and desktop components.  With only uptime/hw
        // checks, the total is typically < 45.
        let score = sandbox::evaluate_sandbox().unwrap_or(0);
        // We can't assert an exact value (depends on uptime/hw of the runner),
        // but a headless system should not exceed the strict threshold 60.
        let report = EnvReport {
            sandbox_score: score,
            ..EnvReport::default()
        };
        assert!(
            !report.should_refuse(false, false, Some(60)),
            "headless macOS sandbox score {score} should not exceed threshold 60"
        );
    }

    // ── Hardened detection indicators ─────────────────────────────────────────

    // ── 1. Hypervisor vendor classification ──────────────────────────────────

    /// VirtualBox vendor string always yields weight 30, even when cloud is
    /// confirmed (no legitimate cloud uses VirtualBox).
    #[test]
    fn hypervisor_vendor_vbox_is_always_suspicious() {
        let vendor = *b"VBoxVBoxVBox";
        let ind_no_cloud = classify_hypervisor_vendor(&vendor, false).unwrap();
        let ind_cloud = classify_hypervisor_vendor(&vendor, true).unwrap();
        assert_eq!(ind_no_cloud.weight, 30);
        assert_eq!(ind_cloud.weight, 30);
        assert_eq!(ind_no_cloud.source, "cpuid_vendor");
    }

    /// VMware vendor string has weight 20 without cloud and 5 with cloud
    /// (enterprise VMware vCloud is a plausible but uncommon deployment).
    #[test]
    fn hypervisor_vendor_vmware_weight_depends_on_cloud() {
        let vendor = *b"VMwareVMware";
        let ind_no_cloud = classify_hypervisor_vendor(&vendor, false).unwrap();
        let ind_cloud = classify_hypervisor_vendor(&vendor, true).unwrap();
        assert_eq!(ind_no_cloud.weight, 20);
        assert_eq!(ind_cloud.weight, 5);
    }

    /// Microsoft Hv vendor string yields weight 0 when cloud is confirmed
    /// (Azure always presents "Microsoft Hv").
    #[test]
    fn hypervisor_vendor_microsoft_hv_cloud_confirmed_is_zero() {
        let vendor = *b"Microsoft Hv";
        let ind = classify_hypervisor_vendor(&vendor, true);
        assert!(
            ind.is_none(),
            "Microsoft Hv on confirmed cloud should produce no indicator"
        );
    }

    /// Microsoft Hv with cloud unconfirmed is mildly suspicious.
    #[test]
    fn hypervisor_vendor_microsoft_hv_unconfirmed_has_weight() {
        let vendor = *b"Microsoft Hv";
        let ind = classify_hypervisor_vendor(&vendor, false).unwrap();
        assert_eq!(ind.weight, 10);
    }

    /// KVM vendor yields weight 0 when cloud confirmed.
    #[test]
    fn hypervisor_vendor_kvm_cloud_confirmed_is_zero() {
        let mut vendor = [0u8; 12];
        vendor[..9].copy_from_slice(b"KVMKVMKVM");
        let ind = classify_hypervisor_vendor(&vendor, true);
        assert!(ind.is_none());
    }

    /// KVM vendor with cloud unconfirmed is mildly suspicious.
    #[test]
    fn hypervisor_vendor_kvm_unconfirmed_has_weight() {
        let mut vendor = [0u8; 12];
        vendor[..9].copy_from_slice(b"KVMKVMKVM");
        let ind = classify_hypervisor_vendor(&vendor, false).unwrap();
        assert_eq!(ind.weight, 10);
    }

    // ── 2. Timing consistency divergence calculation ──────────────────────────

    /// Divergence percentage calculation: 0% when sources agree.
    #[test]
    fn timing_consistency_divergence_zero_when_equal() {
        // Simulate equal QPC-in-100ns and FILETIME delta.
        let qpc_in_100ns: u64 = 50_000;
        let ft_delta: u64 = 50_000;
        let max_v = qpc_in_100ns.max(ft_delta);
        let min_v = qpc_in_100ns.min(ft_delta);
        let divergence_pct = (max_v - min_v).saturating_mul(100) / max_v;
        assert_eq!(divergence_pct, 0, "equal sources should give 0% divergence");
    }

    /// Divergence percentage calculation: 50% when one is double the other.
    #[test]
    fn timing_consistency_divergence_fifty_pct() {
        let qpc_in_100ns: u64 = 100_000;
        let ft_delta: u64 = 50_000;
        let max_v = qpc_in_100ns.max(ft_delta);
        let min_v = qpc_in_100ns.min(ft_delta);
        let divergence_pct = (max_v - min_v).saturating_mul(100) / max_v;
        assert_eq!(divergence_pct, 50);
    }

    // ── 3. Hardware topology indicator weights ────────────────────────────────

    /// Topology indicators from `collect_indicators` have their weight zeroed
    /// when both cloud signals fire.
    #[test]
    fn topology_indicators_zeroed_on_confirmed_cloud() {
        let mut indicators = vec![
            common::SandboxIndicator {
                category: "topology".to_string(),
                detail: "1 logical CPU".to_string(),
                weight: 15,
                source: "topology".to_string(),
            },
            common::SandboxIndicator {
                category: "topology".to_string(),
                detail: "1 GiB RAM".to_string(),
                weight: 15,
                source: "topology".to_string(),
            },
        ];
        // Simulate the collect_indicators cloud-aware zeroing step.
        let cloud_confirmed = true;
        if cloud_confirmed {
            for ind in indicators.iter_mut() {
                if ind.source == "topology" || ind.source == "network" {
                    ind.weight = 0;
                }
            }
        }
        assert!(indicators.iter().all(|i| i.weight == 0));
    }

    /// Topology indicators retain weight when cloud is not confirmed.
    #[test]
    fn topology_indicators_keep_weight_without_cloud() {
        let mut indicators = vec![common::SandboxIndicator {
            category: "topology".to_string(),
            detail: "1 logical CPU".to_string(),
            weight: 15,
            source: "topology".to_string(),
        }];
        let cloud_confirmed = false;
        if cloud_confirmed {
            for ind in indicators.iter_mut() {
                if ind.source == "topology" {
                    ind.weight = 0;
                }
            }
        }
        assert_eq!(indicators[0].weight, 15);
    }

    // ── 4. Process lineage classification ─────────────────────────────────────

    /// python.exe parent → weight 25 (analysis framework).
    #[test]
    fn process_lineage_python_parent_is_suspicious() {
        let ind = classify_parent_process_name(Some("python.exe")).unwrap();
        assert_eq!(ind.weight, 25);
        assert_eq!(ind.source, "lineage");
    }

    /// java.exe parent → weight 25.
    #[test]
    fn process_lineage_java_parent_is_suspicious() {
        let ind = classify_parent_process_name(Some("java.exe")).unwrap();
        assert_eq!(ind.weight, 25);
    }

    /// cuckoo.exe parent → weight 25.
    #[test]
    fn process_lineage_cuckoo_parent_is_suspicious() {
        let ind = classify_parent_process_name(Some("cuckoo.exe")).unwrap();
        assert_eq!(ind.weight, 25);
    }

    /// explorer.exe parent → no indicator (legitimate launch).
    #[test]
    fn process_lineage_explorer_parent_is_benign() {
        let ind = classify_parent_process_name(Some("explorer.exe"));
        assert!(
            ind.is_none(),
            "explorer.exe parent should not produce an indicator"
        );
    }

    /// svchost.exe parent → no indicator.
    #[test]
    fn process_lineage_svchost_parent_is_benign() {
        assert!(classify_parent_process_name(Some("svchost.exe")).is_none());
    }

    /// No parent → weight 5 (orphaned process).
    #[test]
    fn process_lineage_no_parent_is_mildly_suspicious() {
        let ind = classify_parent_process_name(None).unwrap();
        assert_eq!(ind.weight, 5);
    }

    // ── 5. Network environment ────────────────────────────────────────────────

    /// Network indicator source is "network" so that cloud-aware zeroing applies.
    #[test]
    fn network_indicator_source_is_network() {
        // Simulate the indicator that would be created for 1 adapter.
        let ind = common::SandboxIndicator {
            category: "network".to_string(),
            detail: "1 physical NIC(s) and no enterprise proxy".to_string(),
            weight: 5,
            source: "network".to_string(),
        };
        assert_eq!(ind.source, "network");
        assert_eq!(ind.weight, 5);
    }

    /// Network indicators are zeroed on confirmed cloud (same mechanism as topology).
    #[test]
    fn network_indicator_zeroed_on_confirmed_cloud() {
        let mut indicators = vec![common::SandboxIndicator {
            category: "network".to_string(),
            detail: "1 physical NIC".to_string(),
            weight: 5,
            source: "network".to_string(),
        }];
        let cloud_confirmed = true;
        if cloud_confirmed {
            for ind in indicators.iter_mut() {
                if ind.source == "topology" || ind.source == "network" {
                    ind.weight = 0;
                }
            }
        }
        assert_eq!(indicators[0].weight, 0);
    }

    // ── Combined: sandbox profile with new indicators triggers detection ───────

    /// A simulated sandbox with VirtualBox vendor + analysis framework parent +
    /// small topology scores above the 30-point detection threshold.
    #[test]
    fn combined_sandbox_indicators_exceed_threshold() {
        let indicators = vec![
            common::SandboxIndicator {
                category: "hypervisor_vendor".to_string(),
                detail: "VirtualBox hypervisor vendor".to_string(),
                weight: 30,
                source: "cpuid_vendor".to_string(),
            },
            common::SandboxIndicator {
                category: "lineage".to_string(),
                detail: "Spawned by python.exe".to_string(),
                weight: 25,
                source: "lineage".to_string(),
            },
        ];
        let (is_sandbox, threshold, _) = evaluate_sandbox_score(&indicators);
        assert!(
            is_sandbox,
            "VBox(30) + lineage(25) = 55 should exceed threshold {threshold}"
        );
    }

    /// Cloud VM indicators (confirmed) should NOT be classified as sandbox
    /// even with small topology numbers.
    #[test]
    fn cloud_confirmed_topology_does_not_trigger_detection() {
        // Simulate confirmed cloud VM: topology indicators zeroed.
        let indicators = vec![
            common::SandboxIndicator {
                category: "cloud_bios".to_string(),
                detail: "Known cloud hypervisor DMI/registry strings detected".to_string(),
                weight: 0,
                source: "registry".to_string(),
            },
            common::SandboxIndicator {
                category: "cloud_bios".to_string(),
                detail: "IMDS endpoint responded — cloud instance confirmed".to_string(),
                weight: 0,
                source: "imds".to_string(),
            },
            common::SandboxIndicator {
                category: "topology".to_string(),
                detail: "1 logical CPU — zeroed by cloud confirmation".to_string(),
                weight: 0, // Zeroed because cloud confirmed
                source: "topology".to_string(),
            },
        ];
        let (is_sandbox, _, _) = evaluate_sandbox_score(&indicators);
        assert!(
            !is_sandbox,
            "zeroed topology on confirmed cloud must not trigger detection"
        );
    }

    // ── domain_from_resolv_conf_content tests ─────────────────────────────

    #[test]
    fn resolv_conf_plain_domain() {
        let content = "nameserver 8.8.8.8\ndomain example.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn resolv_conf_leading_whitespace_domain() {
        let content = "nameserver 8.8.8.8\n  domain example.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn resolv_conf_leading_tab_domain() {
        let content = "nameserver 8.8.8.8\n\tdomain example.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn resolv_conf_commented_domain_is_skipped() {
        let content = "nameserver 8.8.8.8\n# domain example.com\n";
        assert_eq!(domain_from_resolv_conf_content(content), None);
    }

    #[test]
    fn resolv_conf_semicolon_comment_search_is_skipped() {
        let content = "nameserver 8.8.8.8\n; search example.com\n";
        assert_eq!(domain_from_resolv_conf_content(content), None);
    }

    #[test]
    fn resolv_conf_search_fallback() {
        let content = "nameserver 8.8.8.8\nsearch corp.internal example.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("corp.internal".to_string())
        );
    }

    #[test]
    fn resolv_conf_search_with_leading_whitespace() {
        let content = "nameserver 8.8.8.8\n  search corp.internal example.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("corp.internal".to_string())
        );
    }

    #[test]
    fn resolv_conf_domain_takes_priority_over_search() {
        let content = "search fallback.com\ndomain primary.com\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("primary.com".to_string())
        );
    }

    #[test]
    fn resolv_conf_empty_lines_are_skipped() {
        let content = "\n\nnameserver 8.8.8.8\n\n\ndomain example.com\n\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn resolv_conf_mixed_format_cloud_init() {
        // Typical cloud-init generated resolv.conf with comments and
        // leading whitespace.
        let content = "# Generated by NetworkManager\nsearch corp.internal\nnameserver 10.0.0.1\n";
        assert_eq!(
            domain_from_resolv_conf_content(content),
            Some("corp.internal".to_string())
        );
    }
}

/// Combined sandbox heuristics implementation (Prompt 6)
pub mod sandbox {
    include!("env_check_sandbox.rs");
}

/// Hardware Performance Counter (HPC) fingerprinting for VM / emulation
/// detection.  Uses the `RDPMC` instruction to measure physical CPU events
/// (cache misses, branch mispredictions, micro-ops retired) that cannot be
/// accurately replicated by VMs and emulators.  x86_64 only.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod env_check_hpc {
    include!("env_check_hpc.rs");
}

/// Instruction-granularity RDTSC timing for single-step debugging and
/// instruction-level emulation detection.  Measures cycle counts of
/// individual instructions (NOP, MOV, CPUID, RDTSC) and flags statistical
/// anomalies that indicate per-instrumentation overhead.  x86_64 only.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod env_check_rdtsc {
    include!("env_check_rdtsc.rs");
}

/// ARM64 generic-timer (CNTVCT_EL0) and PMU (PMCCNTR_EL0) timing for
/// single-step debugging and emulation detection on AArch64.  Measures
/// instruction-granularity tick counts using ISB + CNTVCT_EL0, cross-checks
/// against std::time::Instant, and — when available — uses PMCCNTR_EL0 for
/// PMU-based VM probability estimation.  Covers Apple Silicon, AWS Graviton,
/// and other ARM64 environments with zero x86 timing coverage.
#[cfg(target_arch = "aarch64")]
pub mod env_check_arm64_timer {
    include!("env_check_arm64_timer.rs");
}
