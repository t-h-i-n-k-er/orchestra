use winapi::um::memoryapi::MapViewOfFile;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SEC_IMAGE};
use winapi::um::winbase::CreateFileMappingA;
use winapi::um::handleapi::CloseHandle;
use std::ptr::null_mut;

#[cfg(windows)]
pub fn map_clean_ntdll() -> anyhow::Result<usize> {
    unsafe {
        let path = std::ffi::CString::new("C:\\Windows\\System32\\ntdll.dll").unwrap();
        let h_file = CreateFileA(
            path.as_ptr(),
            GENERIC_READ, // We only need read access to map as SEC_IMAGE|PAGE_EXECUTE_READ?
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("Failed to open ntdll.dll"));
        }
        
        let h_map = CreateFileMappingA(
            h_file,
            null_mut(),
            PAGE_EXECUTE_READ | SEC_IMAGE,
            0,
            0,
            null_mut(),
        );
        CloseHandle(h_file);
        
        if h_map.is_null() {
            return Err(anyhow::anyhow!("Failed to CreateFileMapping"));
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
            return Err(anyhow::anyhow!("Failed to MapViewOfFile"));
        }
        Ok(base as usize)
    }
}
