use winapi::um::memoryapi::MapViewOfFile;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SEC_IMAGE};
use winapi::um::winbase::CreateFileMappingA;
use winapi::um::handleapi::CloseHandle;

fn map_clean_ntdll() -> anyhow::Result<usize> {
    unsafe {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let ntdll_path = format!("{}\\System32\\ntdll.dll\0", sysroot);
        let h_file = CreateFileA(
            ntdll_path.as_ptr() as *const i8,
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("Failed to open ntdll.dll"));
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
