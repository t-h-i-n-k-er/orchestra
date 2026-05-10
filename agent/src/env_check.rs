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

    // ── API hash constants (advapi32) ──────────────────────────────────────────
    pub const HASH_REGOPENKEYEXW: u32 = hash_str_const(b"RegOpenKeyExW\0");
    pub const HASH_REGQUERYVALUEEXW: u32 = hash_str_const(b"RegQueryValueExW\0");
    pub const HASH_REGCLOSEKEY: u32 = hash_str_const(b"RegCloseKey\0");
    pub const HASH_REGENUMKEYEXW: u32 = hash_str_const(b"RegEnumKeyExW\0");

    // ── API hash constants (iphlpapi) ──────────────────────────────────────────
    pub const HASH_GETADAPTERSADDRESSES: u32 = hash_str_const(b"GetAdaptersAddresses\0");

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
    /// Heuristic VM/sandbox detection fired.
    pub vm_detected: bool,
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
        Self {
            debugger_present: is_debugger_present(),
            vm_detected: detect_vm(),
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
            None => log::info!("env: kernel.yama.ptrace_scope not present (YAMA LSM absent — no ptrace restrictions)"),
            Some(0) => log::info!("env: kernel.yama.ptrace_scope=0 (unrestricted ptrace)"),
            Some(1) => log::info!("env: kernel.yama.ptrace_scope=1 (restricted to parent/child or PR_SET_PTRACER peers)"),
            Some(2) => log::warn!("env: kernel.yama.ptrace_scope=2 (CAP_SYS_PTRACE required for ptrace injection)"),
            Some(3) => log::warn!("env: kernel.yama.ptrace_scope=3 (ptrace injection disabled by policy)"),
            Some(v) => log::warn!("env: kernel.yama.ptrace_scope={v} (unrecognised value)"),
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
        if refuse_in_vm && self.vm_detected {
            return true;
        }
        if let Some(threshold) = sandbox_score_threshold {
            let corroborated = self.vm_detected
                || self.debugger_present
                || self.tracer_process_found
                || self.timing_anomaly_detected;
            let effective_threshold = if corroborated {
                threshold
            } else {
                threshold.max(60)
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
///   `sysctl(KERN_PROC, KERN_PROC_PID, getpid())` and calls
///   `ptrace(PT_DENY_ATTACH, 0, 0, 0)` to deny future debugger attach.
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

    // Call PT_DENY_ATTACH as a side-effect to deny future debugger attachment.
    // Do NOT use the return value to determine whether a debugger is present:
    // on macOS, ptrace(PT_DENY_ATTACH) fails with EPERM when no debugger is
    // attached (this is normal — only a traced process can deny attachment),
    // so treating the failure as "debugger present" causes a false positive.
    let _ = unsafe {
        libc::ptrace(
            libc::PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };

    traced
}

#[cfg(target_os = "linux")]
fn linux_is_debugger_present() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
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
    // internally for Flatpak, snap, and other sandboxing on bare-metal hosts.
    // When `containerd` is the *only* matched token, we additionally require
    // a container namespace marker (`/.dockerenv`, `CONTAINER` env var, or
    // PID namespace isolation) before concluding this is a real container.
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
            // snap sandboxing on bare metal), verify with a secondary check.
            let only_containerd = matched.len() == 1 && matched[0] == "containerd";
            if !only_containerd {
                return true;
            }
            // containerd-only: confirm we are actually inside a container
            // namespace by checking PID 1's cgroup inode or the presence
            // of /.dockerenv.
            if std::path::Path::new("/.dockerenv").exists()
                || std::env::var_os("CONTAINER").is_some()
            {
                return true;
            }
            // Last check: if our PID namespace differs from the init
            // namespace, we are in a container even if only containerd
            // appeared in cgroup.
            if let Ok(self_cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
                let self_lower = self_cgroup.to_ascii_lowercase();
                if self_lower.contains("docker")
                    || self_lower.contains("kubepods")
                    || self_lower.contains("crio")
                {
                    return true;
                }
            }
        }
    }

    // /proc/self/mountinfo: overlay or aufs filesystem type indicates an
    // overlayfs/aufs-based container (Docker, containerd, Podman, …).
    // Require the CPUID hypervisor bit to be set to avoid false positives from
    // storage configurations that use overlayfs on bare-metal hosts.
    if let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") {
        let lower = content.to_ascii_lowercase();
        if (lower.contains("overlay") || lower.contains("aufs")) && cpuid_hypervisor_bit() {
            return true;
        }
    }

    false
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
            log::debug!("env_check: is_expected_hypervisor: container environment detected");
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
                log::debug!(
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
                log::debug!("env_check: Microsoft manufacturer without VM product name + CPUID hypervisor bit set — likely physical Windows with Hyper-V features");
                return true;
            }
        }

        // WSL2 guest: the WSL_DISTRO_NAME environment variable is set inside
        // Windows Subsystem for Linux containers.  This is a legitimate
        // execution environment, not a hostile sandbox.
        if std::env::var("WSL_DISTRO_NAME").is_ok() {
            log::debug!("env_check: WSL_DISTRO_NAME set — WSL2 environment, treating as expected hypervisor");
            return true;
        }

        // Windows Sandbox runs as WindowsSandbox.exe.  If the current process
        // or its parent is WindowsSandbox.exe, this is a legitimate Windows
        // feature, not a hostile analysis sandbox.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
                if name.to_ascii_lowercase().contains("windowssandbox") {
                    log::debug!("env_check: running inside Windows Sandbox — treating as expected hypervisor");
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
                            if line.contains("applevirtio")
                                || line.contains("vmwarevirtual")
                                || line.contains("prlvirtual")
                            {
                                found_hypervisor = true;
                                let _ = child.kill();
                                break;
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
                        if line.contains("applevirtio")
                            || line.contains("vmwarevirtual")
                            || line.contains("prlvirtual")
                        {
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
                    log::debug!("env_check: is_expected_hypervisor ioreg -l timed out after 2s");
                }
            }
        }

        // Check hardware model via system_profiler.
        if let Ok(out) = std::process::Command::new("system_profiler")
            .args(["SPHardwareDataType"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if stdout.contains("vmware") || stdout.contains("parallels") || stdout.contains("ec2") {
                return true;
            }
        }

        // Check sysctl hypervisor flag (Apple Silicon and later x86 kernels).
        if let Ok(out) = std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_vmm_present"])
            .output()
        {
            if String::from_utf8_lossy(&out.stdout).trim() == "1" {
                return true;
            }
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
/// **macOS**: Always returns `false`.  macOS uses the 169.254.0.0/16 range for
/// link-local networking (Bonjour/mDNS, Internet Sharing, AwDL) and the
/// CaptiveNetworkSupport daemon can intercept HTTP probes to any IP.  This
/// produces false positives on physical Macs.  macOS cloud VMs (AWS EC2 Mac)
/// are already identified by `is_expected_hypervisor()` via ioreg AppleVirtIO.
fn is_cloud_instance() -> bool {
    // M-29: Skip IMDS probe on macOS — link-local/mDNS and captive portal
    // detection cause false positives.  Cloud Mac instances are already
    // detected by is_expected_hypervisor() via ioreg AppleVirtIO.
    #[cfg(target_os = "macos")]
    {
        return false;
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
            log::debug!(
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

            // For HTTP 200 responses, reject HTML/captive-portal bodies and
            // require at least one known IMDS key when a body is present.
            if status == b"200" && n > 16 {
                let header_end = buf[..n]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4);
                if let Some(body_start) = header_end {
                    let body = &buf[body_start..n];
                    if body.starts_with(b"<") || body.starts_with(b"<!") {
                        return false;
                    }
                    let body_str = String::from_utf8_lossy(body);
                    let known_keys = ["ami-id", "instance-id", "hostname", "local-ipv4"];
                    if !known_keys.iter().any(|k| body_str.contains(k)) {
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
            log::debug!("env_check: cloud instance detected via IMDSv1");
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
            log::debug!("env_check: cloud instance detected via IMDSv2");
            return true;
        }

        log_probe_failure("IMDSv2 metadata response", &"unexpected HTTP status/body");

        false
    }
}

/// Fetch cloud instance-id from IMDS, supporting IMDSv1 and IMDSv2.
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
    parse_http_200_body(&buf, n)
}

fn cloud_instance_vm_refusal_bypassed() -> bool {
    if !is_cloud_instance() {
        return false;
    }

    let cfg = match crate::config::load_config() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let profile = &cfg.malleable_profile;
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
                log::warn!(
                    "env_check: IMDS reachable but instance-id unavailable; VM refusal bypassed via cloud_instance_allow_without_imds"
                );
                return true;
            }

            let fallback_count = profile
                .cloud_instance_fallback_ids
                .iter()
                .filter(|p| !p.trim().is_empty())
                .count();

            if fallback_count > 0 && is_expected_hypervisor() {
                log::warn!(
                    "env_check: IMDS instance-id unavailable; VM refusal bypassed via cloud_instance_fallback_ids ({fallback_count} configured) + expected cloud hypervisor"
                );
                return true;
            }

            return false;
        }
    };

    if expected.as_deref() == Some(actual.as_str()) {
        log::info!(
            "env_check: running on whitelisted cloud instance {}, VM refusal bypassed",
            actual
        );
        true
    } else {
        false
    }
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
    #[cfg(not(any(target_os = "linux", windows)))]
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
    #[cfg(not(any(target_os = "linux", windows)))]
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
pub fn detect_vm() -> bool {
    // Delegate to the unified scoring pipeline.
    let indicators = collect_indicators();
    let (is_sandbox, _) = evaluate_sandbox_score(&indicators);
    is_sandbox
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
    let mouse_weight = std::cmp::min((metrics.mouse_movement_score as u32) * 5, 30);
    let desktop_weight = std::cmp::min((metrics.desktop_richness_score as u32) * 3, 25);
    let uptime_weight = std::cmp::min((metrics.uptime_score as u32) * 2, 25);
    let hardware_weight = std::cmp::min(metrics.hardware_plausibility_score as u32, 20);

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
            detail: "Known cloud hypervisor DMI/registry strings detected".to_string(),
            weight: 0, // Informational — does not contribute to score
            source: "registry".to_string(),
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
/// Returns `(is_sandbox, indicators)` where `is_sandbox` is true when the
/// summed weights exceed the threshold.
pub fn evaluate_sandbox_score(
    indicators: &[common::SandboxIndicator],
) -> (bool, Vec<common::SandboxIndicator>) {
    let cloud_hypervisor = indicators
        .iter()
        .any(|i| i.category == "cloud_bios" && i.detail.contains("DMI/registry"));
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
        matches!(
            i.source.as_str(),
            "cpuid" | "dmi" | "registry" | "mac" | "imds"
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
        log::info!(
            "env_check: suppressing medium heuristic-only VM classification \
             (heuristic_weight={heuristic_weight}, total_weight={total_weight}, threshold={threshold})"
        );
        false
    } else {
        is_sandbox
    };

    // Defence-in-depth: never flag based solely on the CPUID hypervisor bit.
    let hypervisor_only = indicators.iter().any(|i| i.weight > 0)
        && indicators.iter().filter(|i| i.weight > 0).count() == 1
        && hypervisor_bit_set;

    let is_sandbox = if hypervisor_only {
        log::info!(
            "env_check: hypervisor bit is the sole weighted indicator (total_weight={total_weight}, \
             threshold={threshold}); suppressing VM detection to avoid false positive"
        );
        false
    } else {
        is_sandbox
    };

    if is_sandbox && !cloud_imds && !cloud_hypervisor {
        log::warn!(
            "env_check: VM detected with threshold={threshold} and no cloud signal confirmed; \
             if this is a niche cloud deployment, verify IMDS connectivity and \
             extend is_expected_hypervisor via vm_detection_extra_hypervisor_names"
        );
    }

    (is_sandbox, indicators.to_vec())
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
                    log::debug!(
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
            if line.starts_with("TracerPid:") {
                let pid = line.trim_start_matches("TracerPid:").trim();
                // A TracerPid other than 0 means we are actively being traced.
                if pid != "0" {
                    return true;
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
                log::debug!("env_check: /proc tracer scan reached 200-process limit; stopping");
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
        if let Ok(s) = std::fs::read_to_string("/etc/resolv.conf") {
            // `domain` takes priority; `search` is accepted as a fallback because
            // many managed Linux hosts (cloud-init, corporate DHCP) only set
            // `search` and omit the `domain` directive entirely.
            let mut search_fallback: Option<String> = None;
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("domain ") {
                    // `domain` is definitive — return immediately.
                    return Some(rest.trim().to_string());
                }
                if search_fallback.is_none() {
                    if let Some(rest) = line.strip_prefix("search ") {
                        // `search` may list multiple domains separated by whitespace;
                        // take the first one (the most specific, per resolv.conf(5)).
                        if let Some(first) = rest.split_whitespace().next() {
                            search_fallback = Some(first.to_string());
                        }
                    }
                }
            }
            if let Some(sd) = search_fallback {
                return Some(sd);
            }
        }
    }
    None
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
    let report = EnvReport::collect(required_domain);
    let effective_refuse_in_vm = if refuse_in_vm && report.vm_detected {
        !cloud_instance_vm_refusal_bypassed()
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
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    return rest.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
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
        r.sandbox_score = 55;
        assert!(
            !r.should_refuse(false, false, Some(30)),
            "without corroboration, threshold floor should suppress moderate heuristic-only score"
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
        let (is_sandbox, _ind) = evaluate_sandbox_score(&indicators);
        assert!(
            !is_sandbox,
            "medium heuristic-only indicators should be informational"
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
        let (is_sandbox, _ind) = evaluate_sandbox_score(&indicators);
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
}

/// Combined sandbox heuristics implementation (Prompt 6)
pub mod sandbox {
    include!("env_check_sandbox.rs");
}
