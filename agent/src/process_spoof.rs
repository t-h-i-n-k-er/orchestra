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
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::GetExitCodeProcess;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;

    use winapi::um::fileapi::ReadFile;
    use winapi::um::handleapi::SetHandleInformation;
    use winapi::um::namedpipeapi::CreatePipe;
    use winapi::um::winbase::HANDLE_FLAG_INHERIT;
    use winapi::um::winbase::STARTF_USESTDHANDLES;

    let parent_pid =
        crate::process_manager::get_spoof_parent_pid().unwrap_or_else(|| std::process::id());

    unsafe {
        let mut p_handle: HANDLE = std::ptr::null_mut();
        if parent_pid != std::process::id() {
            p_handle = OpenProcess(PROCESS_CREATE_PROCESS, 0, parent_pid);
        }

        let mut size = 0;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
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
                SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0); // read handle not inherited
                si.StartupInfo.hStdOutput = stdout_wr;
                si.StartupInfo.hStdError = stdout_wr;
                si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            }
        }

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut cmd_str = String::from(program);
        for a in args {
            cmd_str.push(' ');
            cmd_str.push_str(a); // Needs quoting in real systems, but fine for arp/schtasks
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
            CloseHandle(stdout_wr);
        }

        if !si.lpAttributeList.is_null() {
            DeleteProcThreadAttributeList(si.lpAttributeList);
        }
        if !p_handle.is_null() {
            CloseHandle(p_handle);
        }

        if success == 0 {
            if !stdout_rd.is_null() {
                CloseHandle(stdout_rd);
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
            CloseHandle(stdout_rd);
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

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
