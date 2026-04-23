//! Manual map PE loader for Windows.
#![cfg(windows)]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::collections::HashMap;
use std::ffi::{c_void, CString};
use winapi::shared::ntdef::{LIST_ENTRY, UNICODE_STRING};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, MEM_RELEASE, PAGE_READWRITE,
};

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

unsafe fn get_proc_address_manual(module: *mut c_void, proc_name: &str) -> *mut c_void {
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
        if let Ok(cname) = CString::new(proc_name) {
            return GetProcAddress(module as _, cname.as_ptr() as _) as *mut c_void;
        }
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
                                // Try PEB walk first, then LoadLibrary.
                                let mut mod_handle = get_module_handle_peb(target_mod);
                                if mod_handle.is_null() {
                                    let mod_name = format!("{}\0", target_mod);
                                    mod_handle =
                                        LoadLibraryA(mod_name.as_ptr() as _) as *mut c_void;
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

    if let Ok(cname) = CString::new(proc_name) {
        return GetProcAddress(module as _, cname.as_ptr() as _) as *mut c_void;
    }
    std::ptr::null_mut()
}

pub unsafe fn load_dll_in_memory(dll_bytes: &[u8]) -> Result<*mut c_void> {
    let pe = PE::parse(dll_bytes)?;
    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    // 1. Allocate memory for the DLL
    let image_base = VirtualAlloc(
        std::ptr::null_mut(),
        optional_header.windows_fields.size_of_image as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if image_base.is_null() {
        return Err(anyhow!("VirtualAlloc failed"));
    }

    struct AllocGuard {
        ptr: *mut c_void,
        success: bool,
    }
    impl Drop for AllocGuard {
        fn drop(&mut self) {
            if !self.success {
                unsafe { VirtualFree(self.ptr, 0, MEM_RELEASE); }
            }
        }
    }
    let mut _guard = AllocGuard { ptr: image_base, success: false };

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
                if let Ok(cname) = CString::new(dll_name) {
                    handle = LoadLibraryA(cname.as_ptr()) as *mut c_void;
                }
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
        let thunk_ref = image_base.add(import.rva);
        *(thunk_ref as *mut usize) = proc_addr as usize;
    }

    // 4. Apply base relocations
    let preferred_base = optional_header.windows_fields.image_base as isize;
    let base_delta = image_base as isize - preferred_base;
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
                    std::slice::from_raw_parts(image_base.add(block_rva), reloc_size).to_vec();

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
                            // IMAGE_REL_BASED_DIR64
                            let addr = image_base.add(page_rva + reloc_offset) as *mut isize;
                            *addr += base_delta;
                        } else if reloc_type == 3 {
                            // IMAGE_REL_BASED_HIGHLOW
                            let addr = image_base.add(page_rva + reloc_offset) as *mut i32;
                            *addr = (*addr as isize + base_delta) as i32;
                        }
                    }
                    offset += block_size;
                }
            }
        }
    }

    // 4b. Invoke TLS callbacks (if any) before calling DllMain.
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
            //   AddressOfCallBacks     : usize  ← VA of null-terminated callback array
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
                let mut cb_ptr = tls_dir.address_of_callbacks as *const usize;
                loop {
                    let cb_va = *cb_ptr;
                    if cb_va == 0 {
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

    // 5. Set memory protections
    for section in &pe.sections {
        // PAGE_* constants are mutually exclusive — never OR them together.
        // Map (exec, read, write) characteristic flags to the single PAGE_*
        // value that best approximates the requested protection.
        let exec = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = section.characteristics & IMAGE_SCN_MEM_READ != 0;
        let write = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let prot: u32 = match (exec, read, write) {
            (true, _, true) => PAGE_EXECUTE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };
        let mut old_prot = 0;
        VirtualProtect(
            image_base.add(section.virtual_address as usize),
            section.virtual_size as usize,
            prot,
            &mut old_prot,
        );
    }

    // 5b. Register the .pdata section (exception handling directory) so the OS
    //     can correctly unwind the stack for exceptions thrown inside the DLL.
    //     Without this, any C++ try/catch or SEH block in the DLL terminates
    //     the process instead of propagating to a handler.
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
