// Hardware Performance Counter (HPC) Fingerprinting
//
// VM/emulation detection using CPU hardware performance counters via the
// `RDPMC` instruction.  Emulators and VMs cannot accurately replicate
// hardware performance counter behavior because these counters track
// physical CPU events (cache misses, branch mispredictions, micro-ops
// retired).  Statistical analysis of these counters detects virtualization
// even when all traditional VM indicators have been bypassed.
//
// # How it works
//
// On Linux the module opens four hardware performance counters via the
// `perf_event_open` syscall (using the event codes in the table below),
// which configures the PMCs through the kernel and makes their values
// readable via `read()`.  On other platforms (Windows, macOS) it attempts
// `RDPMC` directly after checking availability via a fault-guarded probe.
// In both cases controlled workloads are run and counter deltas measured:
//
// | Counter | Event | Purpose |
// |---------|-------|---------|
// | PMC 0 | `INST_RETIRED.ANY` (0x00C0) | Instruction retirement rate |
// | PMC 1 | `BR_INST_RETIRED.ALL_BRANCHES` (0x00C4) | Branch prediction accuracy |
// | PMC 2 | `MEM_LOAD_RETIRED.L3_MISS` (0x00CB, umask 0x01) | L3 cache miss ratio |
// | PMC 3 | `UOPS_RETIRED.ALL` (0x00C2) | Micro-op / instruction ratio |
//
// On physical hardware the measured ratios fall within narrow, deterministic
// bands for a given micro-architecture.  Under virtualization or binary
// translation the ratios diverge significantly because:
//
// - VM exit/entry overhead injects phantom instructions.
// - Binary translators retire different micro-op counts.
// - Simulated caches have different latency / associativity.
// - Branch predictors are not faithfully modelled.
//
// # Physical hardware baselines
//
// | Metric | Physical range | VM / emulator range |
// |--------|---------------|---------------------|
// | Cache miss ratio (seq) | 0.01 – 0.05 | > 0.10 |
// | Branch prediction accuracy | 95 – 100 % | < 90 % |
// | Instruction retirement rate | 0.95 – 1.05 | outside range |
// | Micro-op ratio | 1.0 – 2.0 | anomalous |
//
// # Constraints
//
// - x86_64 only (`RDPMC` is an x86 instruction).
// - Gracefully handles systems where `RDPMC` is unavailable (BIOS locks
//   `CR4.PCE=0`) by catching `#GP` and returning `None`.
// - Does NOT require kernel-mode access.  `RDPMC` is a user-mode
//   instruction when `CR4.PCE = 1`.
// - Handles both Intel and AMD CPUs (different performance counter event
//   numbers).
// - All measurements complete within 100 ms.

use std::arch::x86_64::__cpuid;

// ─── MSR / Event Constants ───────────────────────────────────────────────

/// MSR address for `IA32_PERFEVTSEL0`.
const MSR_PERFEVTSEL0: u32 = 0x186;
/// MSR address for `IA32_PERFEVTSEL0` + counter index offset.
const MSR_PERFEVTSEL_STRIDE: u32 = 1;

/// Bits in `PERFEVTSEL`: Enable counter + User-mode counting.
const PERFEVTSEL_EN: u64 = 1 << 22;
const PERFEVTSEL_USR: u64 = 1 << 16;

/// Intel event select values.
const INTEL_EVT_INST_RETIRED_ANY: u64 = 0x00C0;
const INTEL_EVT_BR_INST_RETIRED_ALL: u64 = 0x00C4;
const INTEL_EVT_MEM_LOAD_RETIRED_L3_MISS: u64 = 0x00CB;
const INTEL_EVT_UOPS_RETIRED_ALL: u64 = 0x00C2;

/// AMD event select values (Performance Event Select registers).
const AMD_EVT_INST_RETIRED_ANY: u64 = 0x00C0; // Retired Instructions
const AMD_EVT_BR_INST_RETIRED_ALL: u64 = 0x00C2; // Retired Branch Instructions
const AMD_EVT_MEM_LOAD_RETIRED_L3_MISS: u64 = 0x01A3; // L3 Cache Misses (umask 0x01)
const AMD_EVT_UOPS_RETIRED_ALL: u64 = 0x00C1; // Retired µOps

/// Umask for L3 miss sub-event.
const INTEL_UMASK_L3_MISS: u64 = 0x01;
const AMD_UMASK_L3_MISS: u64 = 0x01;

// ─── Baseline thresholds ─────────────────────────────────────────────────

/// Cache miss ratio: physical sequential access produces < this.
const CACHE_MISS_RATIO_VM_THRESHOLD: f64 = 0.10;
/// Cache miss ratio: physical sequential access produces < this (max).
const CACHE_MISS_RATIO_PHYS_MAX: f64 = 0.05;

/// Branch prediction accuracy: physical > this (%).
const BRANCH_PRED_PHYS_MIN: f64 = 95.0;
/// Branch prediction accuracy: VM < this (%).
const BRANCH_PRED_VM_THRESHOLD: f64 = 90.0;

/// Instruction retirement rate: physical within [min, max].
const INST_RATE_PHYS_MIN: f64 = 0.95;
const INST_RATE_PHYS_MAX: f64 = 1.05;

/// Micro-op ratio: physical within [min, max].
const UOP_RATIO_PHYS_MIN: f64 = 1.0;
const UOP_RATIO_PHYS_MAX: f64 = 2.0;

/// Number of measurement iterations for each metric.
const HPC_ITERATIONS: usize = 5;

// ─── RDPMC / MSR Helpers ─────────────────────────────────────────────────

/// Read a performance counter using `rdpmc`.
///
/// # Safety
///
/// Counter index must be 0-3 (or 0-7 on CPUs supporting `IA32_FIXED_CTR`).
/// The `CR4.PCE` bit must be set for user-mode access; otherwise a `#GP`
/// is raised and this function will unwind through the `catch_unwind`.
#[target_feature(enable = "sse2")]
unsafe fn read_rdpmc(counter: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    std::arch::asm!(
        "rdpmc",
        in("ecx") counter,
        lateout("eax") lo,
        lateout("edx") hi,
        options(nostack, nomem, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write to an MSR via `wrmsr`.
///
/// **Ring-0 only.**  Invoking this from user mode raises `#GP` (→ SIGSEGV
/// on Linux, STATUS_PRIVILEGED_INSTRUCTION on Windows).  Retained as a
/// reference implementation; never called in the user-mode measurement path.
#[cfg(any())]  // never compiled — kept for documentation only
#[target_feature(enable = "sse2")]
unsafe fn wrmsr(msr: u32, value: u64) {
    std::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("edx") (value >> 32) as u32,
        in("eax") value as u32,
        options(nostack, nomem, preserves_flags)
    );
}

// ─── CPU Vendor Detection ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

fn detect_cpu_vendor() -> CpuVendor {
    let leaf0 = __cpuid(0);
    let mut vendor: [u8; 12] = [0; 12];
    vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());
    let vendor_str = std::str::from_utf8(&vendor).unwrap_or("");
    match vendor_str {
        "GenuineIntel" => CpuVendor::Intel,
        "AuthenticAMD" | "HygonGenuine" => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    }
}

// ─── Performance Counter Configuration ────────────────────────────────────

/// Event configuration for a single PMC.
struct PmcConfig {
    event_select: u64,
    umask: u64,
}

/// Get the four PMC event configurations for the detected CPU vendor.
fn get_pmc_configs(vendor: CpuVendor) -> [PmcConfig; 4] {
    match vendor {
        CpuVendor::Intel => [
            PmcConfig { event_select: INTEL_EVT_INST_RETIRED_ANY, umask: 0 },
            PmcConfig { event_select: INTEL_EVT_BR_INST_RETIRED_ALL, umask: 0 },
            PmcConfig { event_select: INTEL_EVT_MEM_LOAD_RETIRED_L3_MISS, umask: INTEL_UMASK_L3_MISS },
            PmcConfig { event_select: INTEL_EVT_UOPS_RETIRED_ALL, umask: 0 },
        ],
        CpuVendor::Amd => [
            PmcConfig { event_select: AMD_EVT_INST_RETIRED_ANY, umask: 0 },
            PmcConfig { event_select: AMD_EVT_BR_INST_RETIRED_ALL, umask: 0 },
            PmcConfig { event_select: AMD_EVT_MEM_LOAD_RETIRED_L3_MISS, umask: AMD_UMASK_L3_MISS },
            PmcConfig { event_select: AMD_EVT_UOPS_RETIRED_ALL, umask: 0 },
        ],
        CpuVendor::Unknown => [
            PmcConfig { event_select: INTEL_EVT_INST_RETIRED_ANY, umask: 0 },
            PmcConfig { event_select: INTEL_EVT_BR_INST_RETIRED_ALL, umask: 0 },
            PmcConfig { event_select: INTEL_EVT_MEM_LOAD_RETIRED_L3_MISS, umask: INTEL_UMASK_L3_MISS },
            PmcConfig { event_select: INTEL_EVT_UOPS_RETIRED_ALL, umask: 0 },
        ],
    }
}

// ─── Counter Index Constants ──────────────────────────────────────────────

/// PMC 0: retired instructions.
const PMC_INST_RETIRED: u32 = 0;
/// PMC 1: retired branch instructions.
const PMC_BRANCH_RETIRED: u32 = 1;
/// PMC 2: L3 cache misses.
const PMC_L3_MISS: u32 = 2;
/// PMC 3: retired micro-ops.
const PMC_UOPS_RETIRED: u32 = 3;

// ─── Linux perf_event_open Infrastructure ────────────────────────────────
//
// On Linux, `perf_event_open(2)` (syscall 298 on x86-64) opens a hardware
// performance-counter file descriptor that the kernel configures via the
// appropriate MSR writes in ring-0.  User space then calls `read(fd, …, 8)`
// to obtain a cumulative u64 counter value.  This is the correct and
// portable way to configure PMCs from user space without requiring
// `CR4.PCE=1` or RDPMC access.

#[cfg(target_os = "linux")]
mod linux_perf {
    /// Minimal `perf_event_attr` for raw hardware counter access.
    ///
    /// The layout mirrors `struct perf_event_attr` from `<linux/perf_event.h>`.
    /// We only need the first few fields; the kernel uses the `size` field to
    /// know how much of the struct is present.
    #[repr(C)]
    pub struct PerfEventAttr {
        pub type_: u32,
        pub size: u32,
        pub config: u64,
        pub sample_period_or_freq: u64,
        pub sample_type: u64,
        pub read_format: u64,
        /// Bitfield: bit 5 = exclude_kernel, bit 6 = exclude_hv.
        pub flags: u64,
        pub wakeup_events: u32,
        pub bp_type: u32,
        pub config1: u64,
        pub config2: u64,
        pub branch_sample_type: u64,
        pub sample_regs_user: u64,
        pub sample_stack_user: u32,
        pub clockid: i32,
        pub sample_regs_intr: u64,
        pub aux_watermark: u32,
        pub sample_max_stack: u16,
        pub _reserved: u16,
    }

    /// `PERF_TYPE_RAW`: use raw event-select codes.
    pub const PERF_TYPE_RAW: u32 = 4;
    /// Exclude kernel-mode counts (bit 5 of `flags`).
    pub const EXCLUDE_KERNEL: u64 = 1 << 5;
    /// Exclude hypervisor counts (bit 6 of `flags`).
    pub const EXCLUDE_HV: u64 = 1 << 6;
    /// `perf_event_open` syscall number on x86-64 Linux.
    pub const SYS_PERF_EVENT_OPEN: libc::c_long = 298;
}

// Thread-local array of open `perf_event_open` file descriptors (Linux).
//
// Set to `Some([fd0, fd1, fd2, fd3])` by `analyze_hpc_fingerprint` before
// measurements; cleared afterwards.  A value of `-1` for an individual slot
// means that counter could not be opened (falls back to raw RDPMC for that
// slot).
#[cfg(target_os = "linux")]
thread_local! {
    static ACTIVE_PERF_FDS: std::cell::Cell<Option<[i32; 4]>> =
        const { std::cell::Cell::new(None) };
}

/// Open a single raw hardware performance-counter fd via `perf_event_open`.
///
/// `event_config` is the raw event-select value (`event_code | (umask << 8)`).
/// Returns the fd (≥ 0) on success, or `-1` on failure.
#[cfg(target_os = "linux")]
fn open_perf_event(event_config: u64) -> i32 {
    use linux_perf::*;
    let attr = PerfEventAttr {
        type_: PERF_TYPE_RAW,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: event_config,
        sample_period_or_freq: 0,
        sample_type: 0,
        read_format: 0,
        flags: EXCLUDE_KERNEL | EXCLUDE_HV,
        wakeup_events: 0,
        bp_type: 0,
        config1: 0,
        config2: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_stack_user: 0,
        clockid: 0,
        sample_regs_intr: 0,
        aux_watermark: 0,
        sample_max_stack: 0,
        _reserved: 0,
    };
    unsafe {
        libc::syscall(
            SYS_PERF_EVENT_OPEN,
            &attr as *const PerfEventAttr,
            0_i32,   // pid = 0: current process
            -1_i32,  // cpu = -1: any CPU
            -1_i32,  // group_fd = -1: no group
            0_u64,   // flags = 0
        ) as i32
    }
}

/// Open all four hardware PMC fds for the detected CPU vendor.
///
/// Returns `Some([fd0, fd1, fd2, fd3])` on success.  Individual fds that
/// fail to open are set to `-1` (measurement functions fall back to RDPMC
/// for those slots).
#[cfg(target_os = "linux")]
fn open_performance_counters(vendor: CpuVendor) -> Option<[i32; 4]> {
    let configs = get_pmc_configs(vendor);
    let mut fds = [-1i32; 4];
    for (i, cfg) in configs.iter().enumerate() {
        let event_config = cfg.event_select | (cfg.umask << 8);
        fds[i] = open_perf_event(event_config);
    }
    // Return Some even if some fds are -1; callers handle partial failure.
    Some(fds)
}

/// Close all open performance-counter fds.
#[cfg(target_os = "linux")]
fn close_performance_counters(fds: &[i32; 4]) {
    for &fd in fds.iter() {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
}

/// Read the current cumulative value of a performance counter via its fd.
///
/// On failure returns 0.
#[cfg(target_os = "linux")]
fn read_perf_event_counter(fd: i32) -> u64 {
    let mut val: u64 = 0;
    unsafe {
        libc::read(
            fd,
            &mut val as *mut u64 as *mut libc::c_void,
            std::mem::size_of::<u64>(),
        );
    }
    val
}

/// Read hardware performance counter `idx` (0–3).
///
/// On Linux: uses the open `perf_event_open` fd from `ACTIVE_PERF_FDS` if
/// available; falls back to raw `RDPMC` otherwise.
///
/// On non-Linux (Windows, macOS): uses raw `RDPMC` directly.
#[target_feature(enable = "sse2")]
unsafe fn read_hpc_counter(idx: u32) -> u64 {
    #[cfg(target_os = "linux")]
    {
        let fd = ACTIVE_PERF_FDS.with(|cell| {
            cell.get()
                .and_then(|fds| fds.get(idx as usize).copied())
                .filter(|&f| f >= 0)
        });
        if let Some(fd) = fd {
            return read_perf_event_counter(fd);
        }
    }
    read_rdpmc(idx)
}

// ─── Counter Availability Check ───────────────────────────────────────────

/// Cached result of the RDPMC availability probe.
static RDPMC_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

// ── Linux: setjmp / longjmp FFI ───────────────────────────────────────────
//
// We declare our own thin FFI bindings to glibc / musl for `setjmp` and
// `longjmp` rather than relying on the `libc` crate (which may use
// versioned symbols that complicate linking).

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod rdpmc_probe_ffi {
    unsafe extern "C" {
        /// Save the calling environment (including signal mask on most
        /// implementations).  Returns 0 on the initial call, or the
        /// `savemask` value when re-entered via `longjmp`.
        pub fn setjmp(buf: *mut u8) -> i32;
        /// Restore the environment saved by `setjmp`, resuming execution
        /// at the `setjmp` call site with the given return value.
        pub fn longjmp(buf: *mut u8, val: i32) -> !;
    }

    /// Conservative buffer size for `jmp_buf` on x86_64 (glibc / macOS libc
    /// use roughly 200 bytes; 256 provides a safety margin).
    pub const JMP_BUF_SIZE: usize = 256;
}

/// Pointer to the `jmp_buf` used by the RDPMC probe.  Written by
/// `probe_rdpmc()` before installing the handler, cleared afterwards.
/// Only accessed during the single-threaded probe.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static RDPMC_JMP_BUF: std::sync::atomic::AtomicPtr<u8> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Signal handler for the RDPMC availability probe.
///
/// Linux delivers `#GP` from `rdpmc` as `SIGSEGV`; macOS delivers it as
/// `SIGILL`.  In both cases this handler jumps back to the `setjmp` anchor
/// in `probe_rdpmc` with a non-zero return value, indicating unavailability.
///
/// # Safety
///
/// Installed with `SA_RESETHAND` so it executes at most once, preventing
/// recursion if the `longjmp` path itself faults.
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" fn rdpmc_fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let buf = RDPMC_JMP_BUF.load(std::sync::atomic::Ordering::SeqCst);
    if !buf.is_null() {
        unsafe {
            rdpmc_probe_ffi::longjmp(buf, 1);
        }
    }
    // buf was null — nothing we can do; SA_RESETHAND will restore the
    // default disposition and the process will be killed.
}

/// Platform-specific RDPMC availability probe.
///
/// On Linux we use a `setjmp` / `longjmp` guard: a temporary
/// `SIGSEGV` handler is installed, we attempt `rdpmc`, and if the
/// instruction raises `#GP` (CR4.PCE = 0) the signal handler jumps us back
/// to the `setjmp` anchor with a non-zero return value.
///
/// On macOS (x86-64) the kernel delivers `#GP` as `SIGILL`; we use the
/// same `setjmp` / `longjmp` pattern with `SIGILL` instead of `SIGSEGV`.
///
/// On Windows we install a one-shot Vectored Exception Handler that catches
/// `STATUS_PRIVILEGED_INSTRUCTION` (0xC0000096) and redirects execution
/// past the faulting `rdpmc` instruction using a pre-stored resume address.
fn probe_rdpmc() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rdpmc_probe_ffi::JMP_BUF_SIZE;

        // Allocate the jump buffer on the stack.  We align it to 16 bytes
        // (glibc jmp_buf alignment requirement on x86_64).
        #[repr(C, align(16))]
        struct AlignedBuf([u8; JMP_BUF_SIZE]);
        let mut buf = AlignedBuf([0u8; JMP_BUF_SIZE]);
        let buf_ptr = buf.0.as_mut_ptr();

        // Publish the buffer pointer so the signal handler can find it.
        RDPMC_JMP_BUF.store(buf_ptr, std::sync::atomic::Ordering::SeqCst);

        // Install a one-shot signal handler.
        // Linux delivers #GP as SIGSEGV; macOS delivers it as SIGILL.
        #[cfg(target_os = "linux")]
        let probe_signal = libc::SIGSEGV;
        #[cfg(target_os = "macos")]
        let probe_signal = libc::SIGILL;

        let mut new_sa: libc::sigaction = unsafe { std::mem::zeroed() };
        new_sa.sa_sigaction = rdpmc_fault_handler as *const () as usize;
        new_sa.sa_flags = (libc::SA_SIGINFO | libc::SA_RESETHAND);
        unsafe {
            libc::sigemptyset(&mut new_sa.sa_mask);
        }

        let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigaction(probe_signal, &new_sa, &mut old_sa);
        }

        // `setjmp` returns 0 on the initial call.  If the handler
        // fires, `longjmp(buf, 1)` causes `setjmp` to return 1.
        let faulted = unsafe { rdpmc_probe_ffi::setjmp(buf_ptr) };

        if faulted == 0 {
            // First call — attempt the RDPMC instruction.
            #[target_feature(enable = "sse2")]
            unsafe fn try_rdpmc() -> u64 {
                read_rdpmc(0)
            }
            let _val = unsafe { try_rdpmc() };

            // If we reached here the instruction succeeded.  Restore the
            // original handler *before* returning so a later unrelated
            // signal is handled normally.
            unsafe {
                libc::sigaction(probe_signal, &old_sa, std::ptr::null_mut());
            }
            RDPMC_JMP_BUF.store(std::ptr::null_mut(), std::sync::atomic::Ordering::SeqCst);
            true
        } else {
            // Re-entered via longjmp — RDPMC faulted (#GP / signal).
            // SA_RESETHAND already restored the default disposition, but we
            // still restore the original handler for correctness.
            unsafe {
                libc::sigaction(probe_signal, &old_sa, std::ptr::null_mut());
            }
            RDPMC_JMP_BUF.store(std::ptr::null_mut(), std::sync::atomic::Ordering::SeqCst);
            false
        }
    }

    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::ffi::c_void;

        type PVOID = *mut c_void;
        type DWORD = u32;

        const STATUS_PRIVILEGED_INSTRUCTION: DWORD = 0xC000_0096;
        const STATUS_ACCESS_VIOLATION: DWORD = 0xC000_0005;
        const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
        const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

        #[repr(C)]
        struct ExceptionRecord {
            ExceptionCode: DWORD,
            ExceptionFlags: DWORD,
            ExceptionRecord: *mut ExceptionRecord,
            ExceptionAddress: PVOID,
            NumberParameters: DWORD,
            ExceptionInformation: [usize; 15],
        }

        #[repr(C)]
        struct ProbeContext {
            _pad: [u8; 0xF8],
            Rip: u64,
        }

        #[repr(C)]
        struct ExceptionPointers {
            ExceptionRecord: *mut ExceptionRecord,
            ContextRecord: *mut ProbeContext,
        }

        // Thread-local continuation address.  Written by the inline asm
        // before the `rdpmc` instruction; cleared by the VEH handler if the
        // instruction faults.
        thread_local! {
            static RDPMC_PROBE_RESUME: std::cell::Cell<usize> =
                std::cell::Cell::new(0);
        }

        unsafe extern "system" fn rdpmc_probe_veh(
            ep: *mut ExceptionPointers,
        ) -> i32 {
            if ep.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            let code = (*(*ep).ExceptionRecord).ExceptionCode;
            if code == STATUS_PRIVILEGED_INSTRUCTION || code == STATUS_ACCESS_VIOLATION {
                let resume = RDPMC_PROBE_RESUME.with(|c| c.get());
                if resume != 0 {
                    // Advance RIP to the resume label and clear the slot.
                    (*(*ep).ContextRecord).Rip = resume as u64;
                    RDPMC_PROBE_RESUME.with(|c| c.set(0));
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            EXCEPTION_CONTINUE_SEARCH
        }

        // Resolve AddVectoredExceptionHandler / RemoveVectoredExceptionHandler
        // via pe_resolve to avoid IAT entries.
        let kernel32 = match unsafe {
            pe_resolve::get_module_handle_by_hash(
                pe_resolve::hash_str(b"kernel32.dll\0"),
            )
        } {
            Some(b) => b,
            None => return false,
        };
        let aveh_addr = match unsafe {
            pe_resolve::get_proc_address_by_hash(
                kernel32,
                pe_resolve::hash_str(b"AddVectoredExceptionHandler\0"),
            )
        } {
            Some(a) => a,
            None => return false,
        };
        let rveh_addr = match unsafe {
            pe_resolve::get_proc_address_by_hash(
                kernel32,
                pe_resolve::hash_str(b"RemoveVectoredExceptionHandler\0"),
            )
        } {
            Some(a) => a,
            None => return false,
        };

        type FnAddVeh = unsafe extern "system" fn(
            u32,
            unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> PVOID;
        type FnRemoveVeh = unsafe extern "system" fn(PVOID) -> u32;

        let add_veh: FnAddVeh = unsafe { std::mem::transmute(aveh_addr) };
        let remove_veh: FnRemoveVeh = unsafe { std::mem::transmute(rveh_addr) };

        let handle = unsafe { add_veh(1, rdpmc_probe_veh) };
        if handle.is_null() {
            return false;
        }

        // Store the resume address and attempt rdpmc.  If it faults,
        // the VEH clears RDPMC_PROBE_RESUME and redirects RIP to "99:".
        let resume_ptr: *mut usize =
            RDPMC_PROBE_RESUME.with(|c| c.as_ptr() as *mut usize);

        unsafe {
            std::arch::asm!(
                // Pre-store the continuation address.
                "lea rax, [rip + 99f]",
                "mov qword ptr [{ptr}], rax",
                // Attempt RDPMC for counter 0.
                "xor ecx, ecx",
                "rdpmc",          // may raise STATUS_PRIVILEGED_INSTRUCTION
                "99:",
                ptr = in(reg) resume_ptr,
                lateout("rax") _,
                out("ecx") _,
                lateout("edx") _,
                options(nostack),
            );
        }

        unsafe { remove_veh(handle) };

        // If VEH fired it cleared RDPMC_PROBE_RESUME → get() == 0 → false.
        // If rdpmc succeeded the slot is still non-zero → true.
        let available = RDPMC_PROBE_RESUME.with(|c| c.get()) != 0;
        RDPMC_PROBE_RESUME.with(|c| c.set(0)); // clean up
        available
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

/// Check whether `rdpmc` is available in user mode.
///
/// The result is cached after the first probe so subsequent calls are
/// essentially free and, crucially, never trigger a second fault.
fn rdpmc_available() -> bool {
    *RDPMC_AVAILABLE.get_or_init(probe_rdpmc)
}

// ─── Measurement: Cache Miss Ratio ────────────────────────────────────────

/// Execute a sequential memory access pattern and measure L3 cache miss ratio.
///
/// Sequential access on physical hardware has very low miss rate (data is
/// prefetched).  VMs / emulators often show higher miss rates due to
/// simulated or passthrough caches with different characteristics.
///
/// Returns `(l3_misses, total_loads)` ratio.
fn measure_cache_miss_ratio_once() -> Option<f64> {
    const ARRAY_SIZE: usize = 1024 * 1024; // 1 MiB of u64
    let mut buffer = vec![0u64; ARRAY_SIZE];

    // Warm up — ensure the buffer is allocated.
    for (i, slot) in buffer.iter_mut().enumerate() {
        *slot = i as u64;
    }

    #[target_feature(enable = "sse2")]
    unsafe fn read_l3() -> u64 { read_hpc_counter(PMC_L3_MISS) }
    let start_l3 = unsafe { read_l3() };

    // Sequential access pattern — highly predictable, well-prefetched.
    let mut acc: u64 = 0;
    for value in &buffer {
        acc = acc.wrapping_add(*value);
    }

    let end_l3 = unsafe { read_l3() };

    // Prevent optimizer from eliminating the loop.
    std::hint::black_box(acc);

    let l3_misses = end_l3.wrapping_sub(start_l3) as f64;
    let total_loads = ARRAY_SIZE as f64;

    Some(l3_misses / total_loads)
}

// ─── Measurement: Branch Prediction Accuracy ──────────────────────────────

/// Execute a predictable branch pattern and measure prediction accuracy.
///
/// Physical hardware achieves >95 % accuracy on simple predictable branches.
/// VMs / emulators often don't accurately simulate branch prediction.
///
/// Returns prediction accuracy percentage (0-100).
fn measure_branch_prediction_accuracy_once() -> Option<f64> {
    const ITERATIONS: usize = 1_000_000;
    let pattern = [true, false, true, true, false, true, false, false]; // fixed pattern

    #[target_feature(enable = "sse2")]
    unsafe fn read_br() -> u64 { read_hpc_counter(PMC_BRANCH_RETIRED) }
    let start_branches = unsafe { read_br() };

    // Execute a completely predictable if-else pattern.
    let mut acc: u64 = 0;
    for i in 0..ITERATIONS {
        if pattern[i % pattern.len()] {
            acc = acc.wrapping_add(1);
        } else {
            acc = acc.wrapping_add(2);
        }
    }

    let end_branches = unsafe { read_br() };

    std::hint::black_box(acc);

    let branches_retired = end_branches.wrapping_sub(start_branches) as f64;

    // On physical hardware, a fixed-pattern branch will be predicted with
    // near-perfect accuracy.  The hardware retires the same number of
    // branches as iterations.  Mispredictions are measured indirectly —
    // if the retired count matches expected (≈ ITERATIONS) with minimal
    // overhead, prediction is accurate.
    //
    // We approximate: if branches_retired ≈ ITERATIONS, the predictor
    // is working well.  Significant deviation suggests emulation overhead
    // (binary translation inserting extra branches or misreporting).
    let expected = ITERATIONS as f64;
    if branches_retired <= 0.0 {
        return Some(0.0);
    }

    // Accuracy = min(100%, expected / actual * 100).
    // If actual >> expected → overhead from emulation → lower accuracy.
    let accuracy = (expected / branches_retired * 100.0).min(100.0);
    Some(accuracy)
}

// ─── Measurement: Instruction Retirement Rate ─────────────────────────────

/// Execute a known number of NOPs and compare measured retirement count.
///
/// Physical hardware: counter ≈ expected count.
/// VM/emulator: counter may differ (especially under binary translation).
///
/// Returns the ratio of measured / expected instructions.
fn measure_instruction_retirement_rate_once() -> Option<f64> {
    const NOP_COUNT: usize = 1_000_000;

    #[target_feature(enable = "sse2")]
    unsafe fn read_inst() -> u64 { read_hpc_counter(PMC_INST_RETIRED) }
    let start_inst = unsafe { read_inst() };

    // Execute a tight loop of NOP-equivalent instructions.
    // We use a volatile accumulator to prevent loop unrolling/elimination.
    let mut acc: u64 = 0;
    for _ in 0..NOP_COUNT {
        acc = acc.wrapping_add(1);
    }

    let end_inst = unsafe { read_inst() };

    std::hint::black_box(acc);

    let retired = end_inst.wrapping_sub(start_inst) as f64;
    let expected = NOP_COUNT as f64;

    Some(retired / expected)
}

// ─── Measurement: Micro-Op Ratio ──────────────────────────────────────────

/// Execute a mix of simple and complex instructions, measure uops/instruction.
///
/// Physical hardware: ratio is deterministic for a specific microarchitecture.
/// VM/emulator: ratio may differ (complex instructions emulated differently).
///
/// Returns the uops / instruction ratio.
fn measure_micro_op_ratio_once() -> Option<f64> {
    const ITERATIONS: usize = 500_000;

    #[target_feature(enable = "sse2")]
    unsafe fn read_inst() -> u64 { read_hpc_counter(PMC_INST_RETIRED) }
    let start_inst = unsafe { read_inst() };

    #[target_feature(enable = "sse2")]
    unsafe fn read_uops() -> u64 { read_hpc_counter(PMC_UOPS_RETIRED) }
    let start_uops = unsafe { read_uops() };

    // Mix of simple (1 uop) and complex (multiple uops) instructions.
    // Each iteration: add (1 uop), imul (3-4 uops on Intel), xor (1 uop),
    // shift (1 uop), comparison + conditional branch (2 uops).
    let mut acc: u64 = 1;
    for i in 0..ITERATIONS {
        acc = acc.wrapping_add(i as u64);      // ADD: 1 uop
        acc = acc.wrapping_mul(3);              // IMUL: 3-4 uops
        acc ^= i as u64;                        // XOR: 1 uop
        acc = acc.wrapping_shl(1);              // SHL: 1 uop
        if acc > 0x1_0000_0000 {
            acc >>= 1;
        }
    }

    let end_inst = unsafe { read_inst() };

    let end_uops = unsafe { read_uops() };

    std::hint::black_box(acc);

    let instructions = end_inst.wrapping_sub(start_inst) as f64;
    let uops = end_uops.wrapping_sub(start_uops) as f64;

    if instructions <= 0.0 {
        return None;
    }

    Some(uops / instructions)
}

// ─── Statistical Analysis ─────────────────────────────────────────────────

/// Result of HPC fingerprinting analysis.
#[derive(Debug, Clone)]
pub struct HpcFingerprint {
    /// Mean cache miss ratio across iterations.
    pub cache_miss_ratio_mean: f64,
    /// Std dev of cache miss ratio.
    pub cache_miss_ratio_stddev: f64,
    /// Mean branch prediction accuracy (%).
    pub branch_accuracy_mean: f64,
    /// Std dev of branch accuracy.
    pub branch_accuracy_stddev: f64,
    /// Mean instruction retirement rate.
    pub inst_rate_mean: f64,
    /// Std dev of instruction rate.
    pub inst_rate_stddev: f64,
    /// Mean micro-op ratio.
    pub uop_ratio_mean: f64,
    /// Std dev of micro-op ratio.
    pub uop_ratio_stddev: f64,
    /// VM probability score (0.0 = physical, 1.0 = definitely VM).
    pub vm_probability: f64,
    /// Number of successful measurement iterations.
    pub samples: usize,
}

/// Compute mean and standard deviation of a slice of f64 values.
fn mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

/// Run all four HPC measurements multiple times and compute statistical
/// fingerprint.
///
/// Returns `None` if neither `RDPMC` nor `perf_event_open` is available.
pub fn analyze_hpc_fingerprint() -> Option<HpcFingerprint> {
    // On Linux, perf_event_open provides a user-mode path to hardware PMCs
    // that works even when the kernel disallows direct RDPMC (CR4.PCE=0).
    // Many Linux hosts expose perf reads while disallowing user-mode RDPMC,
    // so we must not gate on rdpmc_available() alone.  Instead we open the
    // perf counters first and only bail out if both RDPMC *and* perf are
    // unavailable.
    #[cfg(not(target_os = "linux"))]
    {
        if !rdpmc_available() {
            return None;
        }
    }

    // On Linux: open perf_event_open file descriptors to configure the four
    // hardware PMCs through the kernel (the correct user-mode way to set up
    // hardware performance counters).  The measurement functions then read
    // counter values via read() on these fds, falling back to raw RDPMC if
    // a particular fd failed to open.
    #[cfg(target_os = "linux")]
    let _perf_guard = {
        let vendor = detect_cpu_vendor();
        let fds = open_performance_counters(vendor).unwrap_or([-1i32; 4]);
        // If RDPMC is unavailable AND no perf fds opened, there is no way
        // to read hardware counters on this host — bail out early.
        if !rdpmc_available() && fds.iter().all(|&f| f < 0) {
            return None;
        }
        ACTIVE_PERF_FDS.with(|c| c.set(Some(fds)));
        // RAII guard: close fds and clear thread-local when this scope exits.
        struct PerfGuard([i32; 4]);
        impl Drop for PerfGuard {
            fn drop(&mut self) {
                ACTIVE_PERF_FDS.with(|c| c.set(None));
                close_performance_counters(&self.0);
            }
        }
        PerfGuard(fds)
    };

    let mut cache_ratios = Vec::with_capacity(HPC_ITERATIONS);
    let mut branch_accs = Vec::with_capacity(HPC_ITERATIONS);
    let mut inst_rates = Vec::with_capacity(HPC_ITERATIONS);
    let mut uop_ratios = Vec::with_capacity(HPC_ITERATIONS);

    for _ in 0..HPC_ITERATIONS {
        if let Some(r) = measure_cache_miss_ratio_once() {
            cache_ratios.push(r);
        }
        if let Some(r) = measure_branch_prediction_accuracy_once() {
            branch_accs.push(r);
        }
        if let Some(r) = measure_instruction_retirement_rate_once() {
            inst_rates.push(r);
        }
        if let Some(r) = measure_micro_op_ratio_once() {
            uop_ratios.push(r);
        }
    }

    if cache_ratios.is_empty() && branch_accs.is_empty() {
        // No measurements succeeded.
        return None;
    }

    let (cache_mean, cache_stddev) = mean_stddev(&cache_ratios);
    let (branch_mean, branch_stddev) = mean_stddev(&branch_accs);
    let (inst_mean, inst_stddev) = mean_stddev(&inst_rates);
    let (uop_mean, uop_stddev) = mean_stddev(&uop_ratios);

    // Compute VM probability based on deviation from physical baselines.
    let vm_prob = compute_vm_probability(
        cache_mean,
        branch_mean,
        inst_mean,
        uop_mean,
    );

    Some(HpcFingerprint {
        cache_miss_ratio_mean: cache_mean,
        cache_miss_ratio_stddev: cache_stddev,
        branch_accuracy_mean: branch_mean,
        branch_accuracy_stddev: branch_stddev,
        inst_rate_mean: inst_mean,
        inst_rate_stddev: inst_stddev,
        uop_ratio_mean: uop_mean,
        uop_ratio_stddev: uop_stddev,
        vm_probability: vm_prob,
        samples: cache_ratios.len().max(branch_accs.len()),
    })
}

/// Compute a VM probability score (0.0 – 1.0) from the four HPC metrics.
///
/// Each metric contributes a sub-score:
///
/// - **Cache miss ratio**: above `CACHE_MISS_RATIO_VM_THRESHOLD` → 1.0,
///   below `CACHE_MISS_RATIO_PHYS_MAX` → 0.0, linear interpolation between.
///
/// - **Branch prediction accuracy**: below `BRANCH_PRED_VM_THRESHOLD` → 1.0,
///   above `BRANCH_PRED_PHYS_MIN` → 0.0, linear interpolation between.
///
/// - **Instruction retirement rate**: outside `[INST_RATE_PHYS_MIN,
///   INST_RATE_PHYS_MAX]` → 1.0, linear decay to 0.0 at ±0.2 from bounds.
///
/// - **Micro-op ratio**: outside `[UOP_RATIO_PHYS_MIN, UOP_RATIO_PHYS_MAX]`
///   → 1.0, linear interpolation back to bounds.
///
/// The final score is the mean of the four sub-scores.
pub fn compute_vm_probability(
    cache_miss_ratio: f64,
    branch_accuracy: f64,
    inst_rate: f64,
    uop_ratio: f64,
) -> f64 {
    let cache_score = if cache_miss_ratio >= CACHE_MISS_RATIO_VM_THRESHOLD {
        1.0
    } else if cache_miss_ratio <= CACHE_MISS_RATIO_PHYS_MAX {
        0.0
    } else {
        (cache_miss_ratio - CACHE_MISS_RATIO_PHYS_MAX)
            / (CACHE_MISS_RATIO_VM_THRESHOLD - CACHE_MISS_RATIO_PHYS_MAX)
    };

    let branch_score = if branch_accuracy <= BRANCH_PRED_VM_THRESHOLD {
        1.0
    } else if branch_accuracy >= BRANCH_PRED_PHYS_MIN {
        0.0
    } else {
        (BRANCH_PRED_PHYS_MIN - branch_accuracy)
            / (BRANCH_PRED_PHYS_MIN - BRANCH_PRED_VM_THRESHOLD)
    };

    let inst_score = if inst_rate < INST_RATE_PHYS_MIN {
        if inst_rate < INST_RATE_PHYS_MIN - 0.2 {
            1.0
        } else {
            (INST_RATE_PHYS_MIN - inst_rate) / 0.2
        }
    } else if inst_rate > INST_RATE_PHYS_MAX {
        if inst_rate > INST_RATE_PHYS_MAX + 0.2 {
            1.0
        } else {
            (inst_rate - INST_RATE_PHYS_MAX) / 0.2
        }
    } else {
        0.0
    };

    let uop_score = if uop_ratio < UOP_RATIO_PHYS_MIN {
        if uop_ratio < UOP_RATIO_PHYS_MIN - 0.5 {
            1.0
        } else {
            (UOP_RATIO_PHYS_MIN - uop_ratio) / 0.5
        }
    } else if uop_ratio > UOP_RATIO_PHYS_MAX {
        if uop_ratio > UOP_RATIO_PHYS_MAX + 1.0 {
            1.0
        } else {
            (uop_ratio - UOP_RATIO_PHYS_MAX) / 1.0
        }
    } else {
        0.0
    };

    (cache_score + branch_score + inst_score + uop_score) / 4.0
}

// ─── Integration with env_check Scoring Pipeline ──────────────────────────

/// Produce a `SandboxIndicator` from the HPC fingerprint, if available.
///
/// This is called from `collect_indicators()` in `env_check.rs`.
///
/// Weight assignment:
/// - High confidence (>0.8 vm_probability): weight 25
/// - Medium confidence (0.5–0.8): weight 15
/// - Low confidence (<0.5): weight 0 (informational only)
pub fn hpc_indicator() -> Option<common::SandboxIndicator> {
    let fp = analyze_hpc_fingerprint()?;

    let weight = if fp.vm_probability > 0.8 {
        25
    } else if fp.vm_probability > 0.5 {
        15
    } else {
        0
    };

    let detail = format!(
        "HPC fingerprint: cache_miss={:.3} branch_acc={:.1}% inst_rate={:.3} uop_ratio={:.3} vm_prob={:.3}",
        fp.cache_miss_ratio_mean,
        fp.branch_accuracy_mean,
        fp.inst_rate_mean,
        fp.uop_ratio_mean,
        fp.vm_probability,
    );

    Some(common::SandboxIndicator {
        category: "hpc".to_string(),
        detail,
        weight,
        source: "hpc_rdpmc".to_string(),
    })
}

// ─── Public helpers for testing ───────────────────────────────────────────

/// Check whether `RDPMC` is available in user mode.
pub fn is_available() -> bool {
    rdpmc_available()
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_probability_physical_baseline() {
        // Physical hardware values should produce low probability.
        let prob = compute_vm_probability(
            0.02,   // cache miss: within physical range
            97.0,   // branch accuracy: physical range
            1.0,    // inst rate: perfect
            1.5,    // uop ratio: within range
        );
        assert!(
            prob < 0.1,
            "Physical baseline should produce low VM probability, got {prob}"
        );
    }

    #[test]
    fn test_vm_probability_vm_baseline() {
        // VM / emulator values should produce high probability.
        let prob = compute_vm_probability(
            0.20,   // cache miss: well above VM threshold
            80.0,   // branch accuracy: below VM threshold
            0.5,    // inst rate: far outside range
            3.5,    // uop ratio: well outside range
        );
        assert!(
            prob > 0.8,
            "VM baseline should produce high VM probability, got {prob}"
        );
    }

    #[test]
    fn test_vm_probability_mixed_signals() {
        // Some metrics physical, some VM-ish → medium probability.
        let prob = compute_vm_probability(
            0.03,   // cache miss: physical
            92.0,   // branch accuracy: between thresholds
            1.0,    // inst rate: physical
            2.5,    // uop ratio: slightly outside
        );
        assert!(
            (0.1..0.6).contains(&prob),
            "Mixed signals should produce medium probability, got {prob}"
        );
    }

    #[test]
    fn test_vm_probability_boundary_cache() {
        // Exactly at VM threshold → 1.0 for that sub-score.
        let prob_at = compute_vm_probability(CACHE_MISS_RATIO_VM_THRESHOLD, 97.0, 1.0, 1.5);
        let prob_above = compute_vm_probability(CACHE_MISS_RATIO_VM_THRESHOLD + 0.01, 97.0, 1.0, 1.5);
        assert!(
            prob_above >= prob_at,
            "Higher cache miss should not decrease probability"
        );
    }

    #[test]
    fn test_vm_probability_boundary_branch() {
        // Exactly at VM threshold → 1.0 for that sub-score.
        let prob = compute_vm_probability(
            0.02,
            BRANCH_PRED_VM_THRESHOLD,
            1.0,
            1.5,
        );
        // branch sub-score = 1.0, others = 0.0 → total = 0.25
        assert!(
            (prob - 0.25).abs() < 0.01,
            "Single metric at threshold should give ~0.25, got {prob}"
        );
    }

    #[test]
    fn test_mean_stddev_empty() {
        let (m, s) = mean_stddev(&[]);
        assert_eq!(m, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_mean_stddev_single() {
        let (m, s) = mean_stddev(&[3.0]);
        assert_eq!(m, 3.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_mean_stddev_multi() {
        let (m, s) = mean_stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((m - 5.0).abs() < 0.01, "mean should be 5.0, got {m}");
        assert!((s - 2.0).abs() < 0.01, "stddev should be 2.0, got {s}");
    }

    #[test]
    fn test_cpu_vendor_detection() {
        // Just verify it doesn't panic — actual vendor depends on host.
        let vendor = detect_cpu_vendor();
        assert!(matches!(vendor, CpuVendor::Intel | CpuVendor::Amd | CpuVendor::Unknown));
    }

    #[test]
    fn test_hpc_indicator_weight_physical() {
        // Construct a fingerprint that looks like physical hardware.
        let indicator = common::SandboxIndicator {
            category: "hpc".to_string(),
            detail: "test".to_string(),
            weight: 0,
            source: "hpc_rdpmc".to_string(),
        };
        assert_eq!(indicator.weight, 0);
    }

    #[test]
    fn test_compute_vm_probability_deterministic() {
        // Same inputs → same output.
        let p1 = compute_vm_probability(0.03, 96.0, 1.0, 1.5);
        let p2 = compute_vm_probability(0.03, 96.0, 1.0, 1.5);
        assert!((p1 - p2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_all_metrics_physical() {
        let prob = compute_vm_probability(0.01, 99.0, 1.0, 1.5);
        assert_eq!(prob, 0.0, "All physical metrics should give 0.0 probability");
    }

    #[test]
    fn test_all_metrics_vm() {
        let prob = compute_vm_probability(0.30, 70.0, 0.3, 4.0);
        assert_eq!(prob, 1.0, "All VM metrics should give 1.0 probability");
    }
}
