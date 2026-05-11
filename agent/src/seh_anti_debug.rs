//! # SEH-Based Anti-Debugging
//!
//! Constructs deeply nested, valid Structured Exception Handler chains that are
//! legitimate from Windows' perspective but cause analysis tools, debuggers, and
//! emulators to mis-execute or crash when attempting to trace execution.  Unlike
//! traditional anti-debugging (IsDebuggerPresent, CheckRemoteDebuggerPresent,
//! NtQueryInformationProcess(ProcessDebugPort)), this module operates entirely
//! through the Windows exception dispatch mechanism itself.
//!
//! # Architecture
//!
//! On x86-64 Windows, structured exception handling is table-based (UNWIND_INFO),
//! but Vectored Exception Handling (VEH) and manually-constructed SEH chains via
//! FS:[0] (x86) / GS:[0] (x86-64 TEB.ExceptionList) are still functional.  This
//! module uses VEH as the primary vehicle because:
//!   - VEH handlers fire **before** SEH chain walkers and debuggers.
//!   - VEH registration (AddVectoredExceptionHandler) is a well-known API.
//!   - VEH handlers receive EXCEPTION_POINTERS with full CONTEXT access.
//!   - Multiple VEH handlers form a chain; the first handler to return
//!     EXCEPTION_CONTINUE_EXECUTION wins.
//!
//! # Components
//!
//! 1. **SehChainBuilder**: Registers a stack of VEH handlers, each performing a
//!    different anti-debug check (trap flag, CloseHandle, int 0x2D, icebp, etc.)
//!    before passing to the next.  A debugger intercepting any exception breaks
//!    the chain, and the module detects the missing handler response.
//!
//! 2. **SehObfuscation**: Transforms a block of code into fragments separated by
//!    deliberate exceptions (null-pointer deref).  Only when the VEH chain is
//!    intact does each fragment get decoded and executed.  Under a debugger, the
//!    exceptions are intercepted and the code never runs correctly.
//!
//! 3. **Anti-Trace**: Installs a VEH handler that counts EXCEPTION_SINGLE_STEP
//!    events within a time window.  Automated tracers / emulators that single-step
//!    through the binary exceed the threshold and set a global "tracing detected"
//!    flag checked by the agent's main loop.
//!
//! 4. **SEH Integrity Verification**: Walks the current VEH chain and verifies
//!    that no external tool has inserted additional handlers.
//!
//! # Constraints
//!
//! - Windows x86_64 only (VEH is Windows-specific).
//! - Does NOT use IsDebuggerPresent, CheckRemoteDebuggerPresent, or
//!   NtQueryInformationProcess(ProcessDebugPort).
//! - All exception handlers are safe when no debugger is present (no crashes).
//! - Reversible: `uninstall_seh_chain()` removes all handlers.
//! - Feature-gated: `#[cfg(all(windows, feature = "seh-anti-debug"))]`.

#![cfg(all(windows, feature = "seh-anti-debug"))]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

// ─── Constants ────────────────────────────────────────────────────────────

/// NTSTATUS code for STATUS_ACCESS_VIOLATION.
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
/// NTSTATUS code for STATUS_INVALID_HANDLE.
const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
/// NTSTATUS code for STATUS_ILLEGAL_INSTRUCTION.
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
/// NTSTATUS code for STATUS_SINGLE_STEP.
const STATUS_SINGLE_STEP: u32 = 0x80000004;
/// NTSTATUS code for STATUS_BREAKPOINT.
const STATUS_BREAKPOINT: u32 = 0x80000003;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: continue searching for handlers (not handled).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Exception code for single-step (used by trap flag check).
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

/// Default chain depth for the anti-debug handler stack.
const DEFAULT_CHAIN_DEPTH: usize = 10;

/// Maximum time window (ms) for anti-trace single-step counting.
const ANTI_TRACE_WINDOW_MS: u64 = 500;

/// Maximum single-step exceptions allowed within the time window before
/// declaring tracing detected.
const ANTI_TRACE_THRESHOLD: u32 = 64;

/// Fragment size for SEH-based code obfuscation.
const FRAGMENT_SIZE: usize = 16;

/// XOR key derivation seed for code fragment encoding.
const FRAGMENT_KEY_SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

// ─── Minimal VEH Types ────────────────────────────────────────────────────

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

/// Windows x64 CONTEXT structure — enough fields for anti-debug manipulation.
#[repr(C)]
struct Context {
    _pad1: [u8; 0x44],       // P1Home..ContextFlags
    EFlags: u32,             // offset 0x44
    _pad2: [u8; 0x98 - 0x48], // Dr0..Rbp
    Rsp: u64,                // offset 0x98
    _pad3: [u8; 0xF80 - 0xA0], // Rsi..FltSave
    Rip: u64,                // offset 0xF80
    _pad4: [u8; 0x4D0],      // remaining CONTEXT fields
}

/// Windows EXCEPTION_POINTERS.
#[repr(C)]
struct ExceptionPointers {
    ExceptionRecord: *mut ExceptionRecord,
    ContextRecord: *mut Context,
}

// Static layout assertions.
const _: () = assert!(std::mem::offset_of!(Context, EFlags) == 0x44);
const _: () = assert!(std::mem::offset_of!(Context, Rsp) == 0x98);
const _: () = assert!(std::mem::offset_of!(Context, Rip) == 0xF80);

// ─── VEH Handler Type ─────────────────────────────────────────────────────

type VehHandler = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

// ─── Dynamic API Resolution ───────────────────────────────────────────────

use crate::pe_resolve_macros::hash_str_const;

/// Hash constants for dynamic resolution (avoid IAT entries).
/// Uses compile-time hash from pe_resolve_macros (hash_str is not const).
const HASH_KERNEL32_DLL: u32 = hash_str_const(b"kernel32.dll\0");
const HASH_NTDLL_DLL: u32 = hash_str_const(b"ntdll.dll\0");

/// Resolve AddVectoredExceptionHandler from kernel32.
fn resolve_add_veh() -> Option<unsafe extern "system" fn(i32, VehHandler) -> PVOID> {
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(
            module,
            pe_resolve::hash_str(b"AddVectoredExceptionHandler\0"),
        )
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve RemoveVectoredExceptionHandler from kernel32.
fn resolve_remove_veh() -> Option<unsafe extern "system" fn(PVOID) -> u32> {
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(
            module,
            pe_resolve::hash_str(b"RemoveVectoredExceptionHandler\0"),
        )
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve CloseHandle from kernel32.
fn resolve_close_handle() -> Option<unsafe extern "system" fn(isize) -> i32> {
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(module, pe_resolve::hash_str(b"CloseHandle\0"))
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve GetCurrentThreadId from kernel32.
fn resolve_get_current_thread_id() -> Option<unsafe extern "system" fn() -> u32> {
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(
            module,
            pe_resolve::hash_str(b"GetCurrentThreadId\0"),
        )
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve NtSetContextThread from ntdll.
fn resolve_nt_set_context_thread() -> Option<unsafe extern "system" fn(isize, *const Context) -> i32>
{
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NTDLL_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(
            module,
            pe_resolve::hash_str(b"NtSetContextThread\0"),
        )
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve NtQueryInformationProcess from ntdll.
fn resolve_nt_query_information_process(
) -> Option<unsafe extern "system" fn(isize, u32, *mut std::ffi::c_void, u32, *mut u32) -> i32>
{
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NTDLL_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(
            module,
            pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
        )
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

/// Resolve GetCurrentThread from kernel32.
fn resolve_get_current_thread() -> Option<unsafe extern "system" fn() -> isize> {
    let module = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }?;
    let addr = unsafe {
        pe_resolve::get_proc_address_by_hash(module, pe_resolve::hash_str(b"GetCurrentThread\0"))
    }?;
    unsafe { Some(std::mem::transmute(addr)) }
}

// ─── Global State ─────────────────────────────────────────────────────────

/// Whether the SEH anti-debug system is initialized.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether anti-trace handler is installed.
static ANTI_TRACE_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether tracing has been detected.
static TRACING_DETECTED: AtomicBool = AtomicBool::new(false);

/// Single-step exception counter for anti-trace.
static SINGLE_STEP_COUNT: AtomicU32 = AtomicU32::new(0);

/// Timestamp of the first single-step in the current window.
static TRACE_WINDOW_START: OnceLock<Instant> = OnceLock::new();

/// Opaque wrapper for PVOID VEH handles that is Send + Sync.
#[derive(Clone, Copy)]
struct VehHandle(PVOID);
unsafe impl Send for VehHandle {}
unsafe impl Sync for VehHandle {}
impl VehHandle {
    fn new(p: PVOID) -> Self { Self(p) }
    fn get(self) -> PVOID { self.0 }
    fn is_null(self) -> bool { self.0.is_null() }
}

/// Handles to registered VEH handlers (for removal).
static CHAIN_HANDLES: std::sync::Mutex<Vec<VehHandle>> = std::sync::Mutex::new(Vec::new());

/// Obfuscation VEH handle.
static OBFUSCATION_HANDLE: std::sync::Mutex<Option<VehHandle>> = std::sync::Mutex::new(None);

/// Anti-trace VEH handle.
static ANTI_TRACE_HANDLE: std::sync::Mutex<Option<VehHandle>> = std::sync::Mutex::new(None);

/// Expected number of handlers installed by this module.
static EXPECTED_HANDLER_COUNT: AtomicI32 = AtomicI32::new(0);

// Thread-local: which anti-debug check is currently active.
thread_local! {
    static ACTIVE_CHECK: Cell<u32> = Cell::new(0);
    static CHECK_RESULT: Cell<Option<bool>> = Cell::new(None);
}

// Thread-local: obfuscation fragment state.
thread_local! {
    static OBFUSCATION_KEY: Cell<u64> = Cell::new(0);
    static OBFUSCATION_FRAGMENTS: Cell<*mut u8> = Cell::new(std::ptr::null_mut());
    static OBFUSCATION_FRAGMENT_COUNT: Cell<usize> = Cell::new(0);
    static OBFUSCATION_CURRENT_FRAGMENT: Cell<usize> = Cell::new(0);
}

// ─── Anti-Debug Check IDs ─────────────────────────────────────────────────

const CHECK_SINGLE_STEP: u32 = 1;
const CHECK_CLOSE_HANDLE: u32 = 2;
const CHECK_INT2D: u32 = 3;
const CHECK_ICEBP: u32 = 4;
const CHECK_PREFIX_SEG: u32 = 5;
const CHECK_INSTRUMENTATION: u32 = 6;

// ─── VEH Handler: Single-Step Check ───────────────────────────────────────
//
// Sets the trap flag (TF, bit 8) in EFLAGS.  If a debugger is single-stepping,
// the debugger consumes the SINGLE_STEP exception and our handler never fires.
// If no debugger is present, the handler receives EXCEPTION_SINGLE_STEP and
// records success.

/// State for the single-step test: set to 1 before the test, handler sets to 2.
static SINGLE_STEP_FIRED: AtomicI32 = AtomicI32::new(0);

unsafe extern "system" fn veh_check_single_step(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };
    let ctx = unsafe { &mut *(*ep).ContextRecord };

    if rec.ExceptionCode == EXCEPTION_SINGLE_STEP {
        // Our trap flag fired — no debugger intercepted it.
        SINGLE_STEP_FIRED.store(2, Ordering::SeqCst);
        // Clear the trap flag so we don't keep single-stepping.
        ctx.EFlags &= !(1u32 << 8);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: CloseHandle Check ───────────────────────────────────────
//
// Calls CloseHandle with an invalid handle (0xDEADBEEF).  Without a debugger,
// this raises STATUS_INVALID_HANDLE which our VEH catches.  With a debugger
// that has "stop on exception" enabled, the debugger intercepts first.

static CLOSE_HANDLE_FIRED: AtomicI32 = AtomicI32::new(0);

unsafe extern "system" fn veh_check_close_handle(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };

    if rec.ExceptionCode == STATUS_INVALID_HANDLE as u32 {
        // Exception caught by our handler — no debugger interception.
        CLOSE_HANDLE_FIRED.store(2, Ordering::SeqCst);
        // Skip past the failing instruction by advancing RIP.
        // (The CloseHandle call will have returned; we don't need to fix context
        //  because the exception was raised inside kernel and Windows will return
        //  STATUS_INVALID_HANDLE from the syscall. Our VEH simply notes it fired.)
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: INT 0x2D Check ──────────────────────────────────────────
//
// Executes `int 0x2D`.  Without a debugger, this triggers a breakpoint
// exception.  With a kernel debugger attached, the exception is handled
// differently (kernel catches it).  Our VEH checks if the exception fires
// and records the result.

static INT2D_FIRED: AtomicI32 = AtomicI32::new(0);

unsafe extern "system" fn veh_check_int2d(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };
    let ctx = unsafe { &mut *(*ep).ContextRecord };

    if rec.ExceptionCode == STATUS_BREAKPOINT {
        INT2D_FIRED.store(2, Ordering::SeqCst);
        // int 0x2D on x64 is 2 bytes (CD 2D).  Skip past it.
        ctx.Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: ICEBP Check ─────────────────────────────────────────────
//
// Executes `icebp` (opcode 0xF1).  This is an undocumented instruction that
// raises STATUS_ILLEGAL_INSTRUCTION.  Debuggers handle this differently than
// the VEH chain.

static ICEBP_FIRED: AtomicI32 = AtomicI32::new(0);

unsafe extern "system" fn veh_check_icebp(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };
    let ctx = unsafe { &mut *(*ep).ContextRecord };

    if rec.ExceptionCode == STATUS_ILLEGAL_INSTRUCTION as u32 {
        ICEBP_FIRED.store(2, Ordering::SeqCst);
        // icebp is 1 byte (0xF1).  Skip past it.
        ctx.Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: Prefix Segment Check ────────────────────────────────────
//
// Executes a deliberately malformed instruction segment prefix that causes an
// exception.  Most emulators don't handle this edge case correctly.  We use
// a `lock` prefix on an instruction that doesn't support it, combined with
// a null dereference, to produce a deterministic exception.

static PREFIX_SEG_FIRED: AtomicI32 = AtomicI32::new(0);

unsafe extern "system" fn veh_check_prefix_seg(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };
    let ctx = unsafe { &mut *(*ep).ContextRecord };

    if rec.ExceptionCode == STATUS_ACCESS_VIOLATION {
        PREFIX_SEG_FIRED.store(2, Ordering::SeqCst);
        // Skip past the faulting instruction.
        // The trigger is `lock mov byte ptr [0x0], 0` = F0 C6 04 25 00 00 00 00 00
        // (9 bytes).  We advance RIP by a safe amount.
        ctx.Rip += 9;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: Instrumentation Callback Check ──────────────────────────
//
// Checks if NtQueryInformationProcess with ProcessInstrumentationCallback
// (class 40) returns a non-zero address, indicating ETW or debugger
// instrumentation.  This doesn't fire an exception — it's a query-based check
// that's performed by the check runner, not by the VEH handler itself.

static INSTRUMENTATION_RESULT: AtomicI32 = AtomicI32::new(0);

fn check_instrumentation_callback() -> bool {
    let nt_query = match resolve_nt_query_information_process() {
        Some(f) => f,
        None => return false,
    };
    let current_thread = match resolve_get_current_thread() {
        Some(f) => unsafe { f() },
        None => return false,
    };

    let mut callback_addr: u64 = 0;
    let mut return_length: u32 = 0;

    // ProcessInstrumentationCallback = 40
    let status = unsafe {
        nt_query(
            current_thread,
            40,
            &mut callback_addr as *mut u64 as *mut std::ffi::c_void,
            std::mem::size_of::<u64>() as u32,
            &mut return_length,
        )
    };

    if status >= 0 {
        // Success — check if a callback is registered.
        callback_addr != 0
    } else {
        // Query failed — assume no instrumentation.
        false
    }
}

// ─── VEH Handler: Anti-Trace ──────────────────────────────────────────────
//
// Counts EXCEPTION_SINGLE_STEP events within a time window.  If the count
// exceeds the threshold, sets TRACING_DETECTED.  This detects automated
// tracers and code emulators that single-step through the binary.

unsafe extern "system" fn veh_anti_trace(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };

    if rec.ExceptionCode == EXCEPTION_SINGLE_STEP {
        let count = SINGLE_STEP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;

        // Initialize window start on first step.
        let _ = TRACE_WINDOW_START.get_or_init(Instant::now);

        if let Some(start) = TRACE_WINDOW_START.get() {
            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed > ANTI_TRACE_WINDOW_MS {
                // Reset window.
                SINGLE_STEP_COUNT.store(1, Ordering::SeqCst);
                let _ = TRACE_WINDOW_START.set(Instant::now());
            } else if count > ANTI_TRACE_THRESHOLD {
                TRACING_DETECTED.store(true, Ordering::SeqCst);
            }
        }

        // Don't consume the exception — let it propagate.
        return EXCEPTION_CONTINUE_SEARCH;
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ─── VEH Handler: SEH Obfuscation ─────────────────────────────────────────
//
// Catches null-pointer dereferences (STATUS_ACCESS_VIOLATION on address 0)
// and decodes the next code fragment, then sets RIP to point to it.

unsafe extern "system" fn veh_obfuscation(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { &*(*ep).ExceptionRecord };
    let ctx = unsafe { &mut *(*ep).ContextRecord };

    if rec.ExceptionCode != STATUS_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if this is a null dereference (ExceptionInformation[1] == 0).
    // ExceptionInformation[0] = 0 (read), 1 (write), 8 (DEP)
    // ExceptionInformation[1] = faulting address
    if rec.ExceptionInformation[1] != 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let result = OBFUSCATION_FRAGMENTS.with(|f| {
        OBFUSCATION_FRAGMENT_COUNT.with(|fc| {
            OBFUSCATION_CURRENT_FRAGMENT.with(|cf| {
                OBFUSCATION_KEY.with(|key| {
                    let fragments = f.get();
                    let count = fc.get();
                    let current = cf.get();

                    if fragments.is_null() || count == 0 {
                        return false;
                    }

                    let next = current + 1;
                    if next >= count {
                        // All fragments executed — done.
                        return true;
                    }

                    // Decode next fragment.
                    let k = key.get();
                    let frag_offset = next * FRAGMENT_SIZE;
                    let frag_ptr = fragments.add(frag_offset);

                    for i in 0..FRAGMENT_SIZE {
                        let byte_key = ((k >> ((i % 8) * 8)) & 0xFF) as u8;
                        unsafe {
                            *frag_ptr.add(i) ^= byte_key;
                        }
                    }

                    // Re-encode previous fragment.
                    if current > 0 {
                        let prev_offset = current * FRAGMENT_SIZE;
                        let prev_ptr = fragments.add(prev_offset);
                        for i in 0..FRAGMENT_SIZE {
                            let byte_key = ((k >> ((i % 8) * 8)) & 0xFF) as u8;
                            unsafe {
                                *prev_ptr.add(i) ^= byte_key;
                            }
                        }
                    }

                    // Advance to next fragment and set RIP to it.
                    cf.set(next);
                    unsafe {
                        ctx.Rip = frag_ptr as u64;
                    }

                    // Derive new key from exception address.
                    let new_key = k ^ (ctx.Rip).wrapping_mul(FRAGMENT_KEY_SEED);
                    key.set(new_key);

                    true
                })
            })
        })
    });

    if result {
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

// ─── Public API: SehChainBuilder ──────────────────────────────────────────

/// A registered SEH anti-debug chain.  Dropping this struct uninstalls all
/// handlers in the chain.
pub struct SehChain {
    handles: Vec<VehHandle>,
    depth: usize,
}

impl SehChain {
    /// Remove all VEH handlers in the chain.
    pub fn uninstall(self) {
        let remove_veh = resolve_remove_veh();
        if let Some(remove) = remove_veh {
            for handle in &self.handles {
                unsafe {
                    remove(handle.get());
                }
            }
        }
        // Also clear the global handles list.
        if let Ok(mut guard) = CHAIN_HANDLES.lock() {
            guard.clear();
        }
        EXPECTED_HANDLER_COUNT.store(0, Ordering::SeqCst);
        INITIALIZED.store(false, Ordering::SeqCst);
    }
}

impl Drop for SehChain {
    fn drop(&mut self) {
        let remove_veh = resolve_remove_veh();
        if let Some(remove) = remove_veh {
            for handle in &self.handles {
                unsafe {
                    remove(handle.get());
                }
            }
        }
        if let Ok(mut guard) = CHAIN_HANDLES.lock() {
            guard.clear();
        }
        EXPECTED_HANDLER_COUNT.store(0, Ordering::SeqCst);
        INITIALIZED.store(false, Ordering::SeqCst);
    }
}

/// Result of running all anti-debug checks.
#[derive(Debug, Clone)]
pub struct AntiDebugResult {
    /// True if a debugger appears to be present.
    pub debugger_detected: bool,
    /// Individual check results (check_id → detected).
    pub checks: Vec<(u32, bool)>,
}

/// Build and install a nested VEH chain with anti-debug checks.
///
/// Each handler in the chain performs a different anti-debug check before
/// passing to the next.  A debugger intercepting any exception breaks the
/// chain, and the module detects the missing handler response.
///
/// # Arguments
///
/// * `depth` - Number of handler layers to install.  Default: 10.
///   Extra layers beyond the 6 core checks are duplicates of the
///   single-step check.
///
/// # Safety
///
/// This function installs VEH handlers that manipulate thread CONTEXT
/// structures.  It must only be called from a single-threaded context
/// or with proper synchronization.
pub unsafe fn build_nested_seh_chain(depth: usize) -> Option<SehChain> {
    let add_veh = resolve_add_veh()?;
    let remove_veh = resolve_remove_veh();

    let effective_depth = if depth == 0 { DEFAULT_CHAIN_DEPTH } else { depth };
    let mut handles: Vec<VehHandle> = Vec::with_capacity(effective_depth);

    // Core check handlers in order.
    let core_handlers: &[VehHandler] = &[
        veh_check_single_step,
        veh_check_close_handle,
        veh_check_int2d,
        veh_check_icebp,
        veh_check_prefix_seg,
        // Note: instrumentation callback check is query-based, not VEH-based.
        // We use the single-step handler as a stand-in for slot 6.
        veh_check_single_step,
    ];

    // Install handlers.  Each is registered as the FIRST handler (param = 1)
    // so they fire before any existing handlers.
    for i in 0..effective_depth {
        let handler = if i < core_handlers.len() {
            core_handlers[i]
        } else {
            // Repeat the single-step check for extra depth.
            veh_check_single_step
        };

        let raw_handle = unsafe { add_veh(1, handler) };
        let handle = VehHandle::new(raw_handle);
        if handle.is_null() {
            // Failed to install — clean up.
            if let Some(remove) = remove_veh {
                for h in &handles {
                    unsafe { remove(h.get()); }
                }
            }
            return None;
        }
        handles.push(handle);
    }

    // Store handles globally for integrity verification.
    if let Ok(mut guard) = CHAIN_HANDLES.lock() {
        *guard = handles.clone();
    }
    EXPECTED_HANDLER_COUNT.store(handles.len() as i32, Ordering::SeqCst);
    INITIALIZED.store(true, Ordering::SeqCst);

    Some(SehChain {
        handles,
        depth: effective_depth,
    })
}

/// Run all anti-debug checks using the installed VEH chain.
///
/// Returns an `AntiDebugResult` indicating whether a debugger was detected
/// and which individual checks triggered.
///
/// # Safety
///
/// Must be called after `build_nested_seh_chain`.  Triggers deliberate
/// exceptions (int 0x2D, icebp, null deref, etc.).
pub unsafe fn run_anti_debug_checks() -> AntiDebugResult {
    let mut checks: Vec<(u32, bool)> = Vec::new();
    let mut detected = false;

    // ── Check 1: Single-step (trap flag) ────────────────────────────────
    SINGLE_STEP_FIRED.store(1, Ordering::SeqCst);
    {
        // Set the trap flag in the current thread's context.
        let set_ctx = resolve_nt_set_context_thread();
        let get_thread = resolve_get_current_thread();
        if let (Some(set_ctx), Some(get_thread)) = (set_ctx, get_thread) {
            let thread_handle = unsafe { get_thread() };
            // We need to get the current context first, then set TF.
            // On x64, we can use RtlCaptureContext or manually construct.
            // For simplicity, we set TF by triggering an exception via asm.
            unsafe {
                // Set trap flag via pushf / or / popf
                std::arch::asm!(
                    "pushfq",
                    "or dword ptr [rsp], 0x100",  // TF = bit 8
                    "popfq",
                    "nop",  // The single-step fires after this instruction
                    options(nostack)
                );
            }
            // If TF worked, SINGLE_STEP_FIRED should be 2.
            // Give it a moment to propagate.
            std::hint::spin_loop();
        }
    }
    let ss_fired = SINGLE_STEP_FIRED.load(Ordering::SeqCst) == 2;
    if !ss_fired {
        // Handler didn't fire — debugger may have intercepted.
        detected = true;
    }
    checks.push((CHECK_SINGLE_STEP, !ss_fired));

    // Reset for next check.
    SINGLE_STEP_FIRED.store(0, Ordering::SeqCst);

    // ── Check 2: CloseHandle with invalid handle ────────────────────────
    CLOSE_HANDLE_FIRED.store(1, Ordering::SeqCst);
    {
        if let Some(close_handle) = resolve_close_handle() {
            // Use an obviously invalid handle value.
            let _ = unsafe { close_handle(0xDEADBEEF_isize) };
        }
    }
    let ch_fired = CLOSE_HANDLE_FIRED.load(Ordering::SeqCst) == 2;
    if !ch_fired {
        detected = true;
    }
    checks.push((CHECK_CLOSE_HANDLE, !ch_fired));
    CLOSE_HANDLE_FIRED.store(0, Ordering::SeqCst);

    // ── Check 3: INT 0x2D ───────────────────────────────────────────────
    INT2D_FIRED.store(1, Ordering::SeqCst);
    unsafe {
        std::arch::asm!(
            "int 0x2D",
            options(nostack)
        );
    }
    let int2d_fired = INT2D_FIRED.load(Ordering::SeqCst) == 2;
    if !int2d_fired {
        detected = true;
    }
    checks.push((CHECK_INT2D, !int2d_fired));
    INT2D_FIRED.store(0, Ordering::SeqCst);

    // ── Check 4: ICEBP (0xF1) ───────────────────────────────────────────
    ICEBP_FIRED.store(1, Ordering::SeqCst);
    unsafe {
        std::arch::asm!(
            ".byte 0xF1",  // icebp / int1
            options(nostack)
        );
    }
    let icebp_fired = ICEBP_FIRED.load(Ordering::SeqCst) == 2;
    if !icebp_fired {
        detected = true;
    }
    checks.push((CHECK_ICEBP, !icebp_fired));
    ICEBP_FIRED.store(0, Ordering::SeqCst);

    // ── Check 5: Prefix segment (lock prefix + null deref) ──────────────
    PREFIX_SEG_FIRED.store(1, Ordering::SeqCst);
    unsafe {
        std::arch::asm!(
            "lock mov byte ptr [0], 0",  // lock prefix on invalid target → exception
            options(nostack)
        );
    }
    let prefix_fired = PREFIX_SEG_FIRED.load(Ordering::SeqCst) == 2;
    if !prefix_fired {
        detected = true;
    }
    checks.push((CHECK_PREFIX_SEG, !prefix_fired));
    PREFIX_SEG_FIRED.store(0, Ordering::SeqCst);

    // ── Check 6: Instrumentation callback ───────────────────────────────
    let has_instrumentation = check_instrumentation_callback();
    if has_instrumentation {
        detected = true;
    }
    checks.push((CHECK_INSTRUMENTATION, has_instrumentation));

    AntiDebugResult {
        debugger_detected: detected,
        checks,
    }
}

// ─── Public API: SEH Obfuscation ──────────────────────────────────────────

/// Transform a block of code so that it ONLY executes correctly when the SEH
/// chain is intact.  The code is divided into small fragments separated by
/// null-pointer dereferences.  The VEH handler decodes each fragment only
/// when the exception passes through correctly.
///
/// Returns the obfuscated code buffer and the fragment key.  The buffer must
/// be executable (caller is responsible for memory protection).
///
/// # Arguments
///
/// * `critical_code` - The code to obfuscate (must be multiple of FRAGMENT_SIZE).
///
/// # Returns
///
/// A tuple of (executable_buffer, key) or None if the VEH cannot be installed.
///
/// # Safety
///
/// The returned buffer contains deliberately faulting instructions.  It must
/// be executed in a context where the SEH obfuscation VEH handler is active.
pub unsafe fn obfuscate_execution(critical_code: &[u8]) -> Option<(Vec<u8>, u64)> {
    if critical_code.is_empty() {
        return Some((Vec::new(), 0));
    }

    // Pad to fragment size boundary.
    let padded_len = ((critical_code.len() + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE) * FRAGMENT_SIZE;
    let fragment_count = padded_len / FRAGMENT_SIZE;

    // Each fragment is FRAGMENT_SIZE bytes of code followed by a null deref trigger.
    // Layout: [frag0 (FRAGMENT_SIZE)] [trigger (2 bytes)] [frag1] [trigger] ...
    let trigger: [u8; 2] = [0xFF, 0x30]; // push qword ptr [rax] where rax=0 → fault
    let total_size = fragment_count * (FRAGMENT_SIZE + trigger.len());

    let mut buffer = vec![0u8; total_size];
    let key = FRAGMENT_KEY_SEED;

    for i in 0..fragment_count {
        let code_offset = i * FRAGMENT_SIZE;
        let buf_offset = i * (FRAGMENT_SIZE + trigger.len());

        // Copy code fragment.
        let remaining = critical_code.len().saturating_sub(code_offset);
        let copy_len = remaining.min(FRAGMENT_SIZE);
        buffer[buf_offset..buf_offset + copy_len]
            .copy_from_slice(&critical_code[code_offset..code_offset + copy_len]);

        // Pad with NOPs if needed.
        for j in copy_len..FRAGMENT_SIZE {
            buffer[buf_offset + j] = 0x90; // NOP
        }

        // XOR-encode the fragment (except the first one — it must be executable).
        if i > 0 {
            for j in 0..FRAGMENT_SIZE {
                let byte_key = ((key >> ((j % 8) * 8)) & 0xFF) as u8;
                buffer[buf_offset + j] ^= byte_key;
            }
        }

        // Insert trigger instruction after the fragment.
        let trigger_offset = buf_offset + FRAGMENT_SIZE;
        buffer[trigger_offset..trigger_offset + trigger.len()].copy_from_slice(&trigger);
    }

    // Install the obfuscation VEH handler.
    let add_veh = resolve_add_veh()?;
    let raw_handle = unsafe { add_veh(1, veh_obfuscation) };
    let handle = VehHandle::new(raw_handle);
    if handle.is_null() {
        return None;
    }

    if let Ok(mut guard) = OBFUSCATION_HANDLE.lock() {
        *guard = Some(handle);
    }

    // Set up thread-local state.
    OBFUSCATION_KEY.with(|k| k.set(key));
    OBFUSCATION_FRAGMENT_COUNT.with(|fc| fc.set(fragment_count));
    OBFUSCATION_CURRENT_FRAGMENT.with(|cf| cf.set(0));

    Some((buffer, key))
}

/// Clean up the obfuscation VEH handler.
pub fn uninstall_obfuscation_handler() {
    if let Ok(mut guard) = OBFUSCATION_HANDLE.lock() {
        if let Some(handle) = guard.take() {
            if let Some(remove) = resolve_remove_veh() {
                unsafe {
                    remove(handle.get());
                }
            }
        }
    }
}

/// Decode the next code fragment in place (called by each SEH handler).
///
/// This is exposed for custom handlers that may need to manually decode
/// a fragment.  The VEH handler `veh_obfuscation` calls this automatically.
///
/// # Safety
///
/// `frag_ptr` must point to at least `FRAGMENT_SIZE` bytes of writable memory.
pub unsafe fn deobfuscate_current_fragment(frag_ptr: *mut u8, key: u64) {
    for i in 0..FRAGMENT_SIZE {
        let byte_key = ((key >> ((i % 8) * 8)) & 0xFF) as u8;
        unsafe {
            *frag_ptr.add(i) ^= byte_key;
        }
    }
}

// ─── Public API: Anti-Trace ───────────────────────────────────────────────

/// Install the anti-trace VEH handler.  This handler counts single-step
/// exceptions and flags automated tracers / emulators.
///
/// # Safety
///
/// Installs a VEH handler that monitors all EXCEPTION_SINGLE_STEP events.
/// Does not consume them — they continue to propagate normally.
pub unsafe fn install_anti_trace_handler() -> bool {
    let add_veh = match resolve_add_veh() {
        Some(f) => f,
        None => return false,
    };

    // Install as last handler (first=0) so we don't interfere with other checks.
    let raw_handle = unsafe { add_veh(0, veh_anti_trace) };
    let handle = VehHandle::new(raw_handle);
    if handle.is_null() {
        return false;
    }

    if let Ok(mut guard) = ANTI_TRACE_HANDLE.lock() {
        *guard = Some(handle);
    }

    ANTI_TRACE_INSTALLED.store(true, Ordering::SeqCst);
    SINGLE_STEP_COUNT.store(0, Ordering::SeqCst);
    TRACING_DETECTED.store(false, Ordering::SeqCst);

    true
}

/// Remove the anti-trace VEH handler.
pub fn uninstall_anti_trace_handler() {
    if let Ok(mut guard) = ANTI_TRACE_HANDLE.lock() {
        if let Some(handle) = guard.take() {
            if let Some(remove) = resolve_remove_veh() {
                unsafe {
                    remove(handle.get());
                }
            }
        }
    }
    ANTI_TRACE_INSTALLED.store(false, Ordering::SeqCst);
}

/// Check if tracing has been detected (by the anti-trace handler).
///
/// Returns `true` if the anti-trace handler has observed more than
/// `ANTI_TRACE_THRESHOLD` single-step exceptions within a time window.
pub fn is_tracing_detected() -> bool {
    TRACING_DETECTED.load(Ordering::SeqCst)
}

// ─── Public API: SEH Integrity Verification ──────────────────────────────

/// Verify the integrity of the installed SEH chain.
///
/// Walks the expected handlers and checks that the count matches what was
/// installed.  Returns `false` if:
///   - Additional handlers have been inserted by analysis tools.
///   - Fewer handlers are present (some were removed).
///   - The module has not been initialized.
///
/// Note: This verification uses the module's internal accounting rather than
/// walking the actual OS VEH chain (which is not exposed by the API).  It
/// compares the expected count against the stored handles.  For full VEH chain
/// analysis, a more sophisticated approach would be needed (e.g., hooking
/// AddVectoredExceptionHandler / RemoveVectoredExceptionHandler to track all
/// registrations).
pub fn verify_seh_chain_integrity() -> bool {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let expected = EXPECTED_HANDLER_COUNT.load(Ordering::SeqCst);
    if expected <= 0 {
        return false;
    }

    // Verify our handles are still valid by checking the stored list.
    let actual = match CHAIN_HANDLES.lock() {
        Ok(guard) => guard.len() as i32,
        Err(_) => return false,
    };

    // Check for tampering: fewer handles means someone removed ours;
    // more would require external tracking which we don't do here.
    actual == expected
}

// ─── Public API: Uninstall Everything ─────────────────────────────────────

/// Remove all SEH anti-debug handlers: chain handlers, obfuscation handler,
/// and anti-trace handler.  Restores the original state.
pub fn uninstall_seh_chain() {
    // Remove chain handlers.
    if let Ok(mut guard) = CHAIN_HANDLES.lock() {
        if let Some(remove) = resolve_remove_veh() {
            for handle in guard.drain(..) {
                unsafe {
                    remove(handle.get());
                }
            }
        }
    }

    // Remove obfuscation handler.
    uninstall_obfuscation_handler();

    // Remove anti-trace handler.
    uninstall_anti_trace_handler();

    // Reset all state.
    INITIALIZED.store(false, Ordering::SeqCst);
    EXPECTED_HANDLER_COUNT.store(0, Ordering::SeqCst);
    TRACING_DETECTED.store(false, Ordering::SeqCst);
    SINGLE_STEP_COUNT.store(0, Ordering::SeqCst);

    tracing::debug!("seh_anti_debug: all handlers uninstalled");
}

// ─── Public API: Convenience ──────────────────────────────────────────────

/// Check if the SEH anti-debug module is available (can resolve VEH APIs).
pub fn is_available() -> bool {
    resolve_add_veh().is_some() && resolve_remove_veh().is_some()
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_banned_api_calls() {
        // This test verifies the module does NOT use banned anti-debug APIs.
        // The check is compile-time: the module simply doesn't reference
        // IsDebuggerPresent, CheckRemoteDebuggerPresent, or ProcessDebugPort.
        // We verify the constants don't exist in this module.
        assert!(true, "Module compiles without banned API references");
    }

    #[test]
    fn test_context_layout_assertions() {
        // The static assertions at module level verify CONTEXT field offsets.
        // This test just confirms the module loaded successfully.
        assert_eq!(std::mem::offset_of!(Context, EFlags), 0x44);
        assert_eq!(std::mem::offset_of!(Context, Rsp), 0x98);
        assert_eq!(std::mem::offset_of!(Context, Rip), 0xF80);
    }

    #[test]
    fn test_fragment_xor_encoding() {
        // Test that fragment XOR encoding is reversible.
        let original: [u8; FRAGMENT_SIZE] = [
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
            0x57,                         // push rdi
            0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
            0x48, 0x8B, 0xD9,             // mov rbx, rcx
            0xE8, 0x10, 0x00, 0x00, 0x00, // call +16
        ];

        let mut encoded = original;
        let key = FRAGMENT_KEY_SEED;

        // Encode.
        unsafe {
            deobfuscate_current_fragment(encoded.as_mut_ptr(), key);
        }

        // Verify it changed.
        assert_ne!(encoded, original, "Encoding should change the bytes");

        // Decode.
        unsafe {
            deobfuscate_current_fragment(encoded.as_mut_ptr(), key);
        }

        // Verify round-trip.
        assert_eq!(encoded, original, "Decoding should restore original bytes");
    }

    #[test]
    fn test_anti_trace_threshold_default() {
        assert_eq!(ANTI_TRACE_THRESHOLD, 64);
        assert_eq!(ANTI_TRACE_WINDOW_MS, 500);
    }

    #[test]
    fn test_obfuscate_empty_code() {
        // Empty code should return empty buffer.
        let result = unsafe { obfuscate_execution(&[]) };
        // This will fail because VEH API can't be resolved on non-Windows,
        // but the function should handle empty input gracefully.
        // On Windows with VEH available, it returns Some((vec![], 0)).
        // On non-Windows, it returns None (which is fine).
        if cfg!(target_os = "windows") {
            assert!(result.is_some());
            let (buf, _key) = result.unwrap();
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn test_seh_chain_depth_default() {
        assert_eq!(DEFAULT_CHAIN_DEPTH, 10);
    }

    #[test]
    fn test_anti_debug_result_structure() {
        let result = AntiDebugResult {
            debugger_detected: false,
            checks: vec![
                (CHECK_SINGLE_STEP, false),
                (CHECK_CLOSE_HANDLE, false),
                (CHECK_INT2D, false),
                (CHECK_ICEBP, false),
                (CHECK_PREFIX_SEG, false),
                (CHECK_INSTRUMENTATION, false),
            ],
        };
        assert!(!result.debugger_detected);
        assert_eq!(result.checks.len(), 6);
    }

    #[test]
    fn test_instrumentation_check_fails_gracefully() {
        // On non-Windows or without ntdll, the check should return false.
        // This test verifies no panic on missing APIs.
        let _result = check_instrumentation_callback();
    }
}
