import sys
import re

content = open('agent/src/syscalls.rs', 'r').read()

part1 = """        let sys_ntcreatesection = get_syscall_id("NtCreateSection")?;
        let sys_ntmapview = get_syscall_id("NtMapViewOfSection")?;

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| rr"C:\\Windows".to_string());
        
        let path_str = if dll_lower.contains("\\") {
            dll_lower.clone()
        } else {
            format!(r"{}\\System32\\{}", sysroot, dll_name)
        };
        let c_path = std::ffi::CString::new(path_str).unwrap();
        
        // Use CreateFile for non-ntdll clean maps. NtOpenFile can also be used if preferred, but for now we follow the script
        let h_file = CreateFileA(
            c_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to open {} from system directory. Refusing to initialize.", dll_name));
        }"""

# Actually, my previous attempt at regex or string replace might fail because of exactly how strings are escaped. Let's read lines and slice.
