with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

import re

old_func = """fn map_clean_ntdll() -> Result<usize> {
    use winapi::um::memoryapi::MapViewOfFile;
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SEC_IMAGE};
    use winapi::um::winbase::CreateFileMappingA;
    use winapi::um::handleapi::CloseHandle;

    unsafe {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\\\\\\\Windows".to_string());
        let ntdll_path = std::ffi::CString::new(format!("{}\\\\\\\\System32\\\\\\\\ntdll.dll", sysroot)).unwrap();
        
        let h_file = CreateFileA(
            ntdll_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to open ntdll.dll"));
        }
        
        let h_map = CreateFileMappingA(
            h_file,
            std::ptr::null_mut(),
            PAGE_EXECUTE_READ | SEC_IMAGE,
            0,
            0,
            std::ptr::null_mut(),
        );
        CloseHandle(h_file);
        
        if h_map.is_null() {
            return Err(anyhow!("Failed to CreateFileMapping"));
        }
        
        let base = MapViewOfFile(
            h_map,
            winapi::um::memoryapi::FILE_MAP_READ | winapi::um::memoryapi::FILE_MAP_EXECUTE,
            0,
            0,
            0,
        );
        CloseHandle(h_map);
        
        if base.is_null() {
            return Err(anyhow!("Failed to MapViewOfFile"));
        }
        Ok(base as usize)
    }
}"""

new_func = """type NtCreateSectionFn = unsafe extern "system" fn(
    SectionHandle: *mut winapi::shared::ntdef::HANDLE,
    DesiredAccess: winapi::um::winnt::ACCESS_MASK,
    ObjectAttributes: winapi::shared::ntdef::POBJECT_ATTRIBUTES,
    MaximumSize: winapi::shared::ntdef::PLARGE_INTEGER,
    SectionPageProtection: winapi::shared::ntdef::ULONG,
    AllocationAttributes: winapi::shared::ntdef::ULONG,
    FileHandle: winapi::shared::ntdef::HANDLE,
) -> winapi::shared::ntdef::NTSTATUS;

#[cfg(windows)]
type NtMapViewOfSectionFn = unsafe extern "system" fn(
    SectionHandle: winapi::shared::ntdef::HANDLE,
    ProcessHandle: winapi::shared::ntdef::HANDLE,
    BaseAddress: *mut winapi::shared::ntdef::PVOID,
    ZeroBits: winapi::shared::basetsd::ULONG_PTR,
    CommitSize: winapi::shared::basetsd::SIZE_T,
    SectionOffset: winapi::shared::ntdef::PLARGE_INTEGER,
    ViewSize: *mut winapi::shared::basetsd::SIZE_T,
    InheritDisposition: u32,
    AllocationType: winapi::shared::ntdef::ULONG,
    Win32Protect: winapi::shared::ntdef::ULONG,
) -> winapi::shared::ntdef::NTSTATUS;

#[cfg(windows)]
fn map_clean_ntdll() -> Result<usize> {
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SEC_IMAGE, SECTION_MAP_READ, SECTION_MAP_EXECUTE};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let ntdll_mod = GetModuleHandleA(b"ntdll.dll\\0".as_ptr() as *const i8);
        if ntdll_mod.is_null() {
            return Err(anyhow!("Failed to get ntdll.dll module handle for NtCreateSection"));
        }
        
        let nt_create_section_ptr = GetProcAddress(ntdll_mod, b"NtCreateSection\\0".as_ptr() as *const i8);
        let nt_map_view_ptr = GetProcAddress(ntdll_mod, b"NtMapViewOfSection\\0".as_ptr() as *const i8);
        
        if nt_create_section_ptr.is_null() || nt_map_view_ptr.is_null() {
            return Err(anyhow!("Failed to resolve NtCreateSection or NtMapViewOfSection"));
        }
        
        let nt_create_section: NtCreateSectionFn = std::mem::transmute(nt_create_section_ptr);
        let nt_map_view_of_section: NtMapViewOfSectionFn = std::mem::transmute(nt_map_view_ptr);

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\\\Windows".to_string());
        let ntdll_path = std::ffi::CString::new(format!("{}\\\\System32\\\\ntdll.dll", sysroot)).unwrap();
        
        let h_file = CreateFileA(
            ntdll_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to open native ntdll.dll from system directory. Refusing to initialize."));
        }
        
        let mut h_section: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let status = nt_create_section(
            &mut h_section,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            PAGE_EXECUTE_READ,
            SEC_IMAGE,
            h_file
        );
        CloseHandle(h_file);
        
        if status != 0 || h_section.is_null() {
            return Err(anyhow!("NtCreateSection failed with status {:x}. Refusing to initialize.", status));
        }
        
        let mut base_addr: winapi::shared::ntdef::PVOID = std::ptr::null_mut();
        let mut view_size: winapi::shared::basetsd::SIZE_T = 0;
        
        let status = nt_map_view_of_section(
            h_section,
            -1isize as winapi::shared::ntdef::HANDLE, // CurrentProcess
            &mut base_addr,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            1, // ViewShare
            0,
            PAGE_EXECUTE_READ,
        );
        CloseHandle(h_section);
        
        if status != 0 || base_addr.is_null() {
            return Err(anyhow!("NtMapViewOfSection failed with status {:x}. Refusing to initialize.", status));
        }
        
        Ok(base_addr as usize)
    }
}"""

if old_func in text:
    text = text.replace(old_func, new_func)
else:
    print("Could not find old map_clean_ntdll function to replace. Trying regex...")
    text = re.sub(r'fn map_clean_ntdll\(\) -> Result<usize> \{.*?\n}\n', new_func + '\n', text, flags=re.DOTALL)

with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)

