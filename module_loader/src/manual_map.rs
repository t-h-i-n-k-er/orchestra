//! Manual map PE loader for Windows.
#![cfg(windows)]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::ffi::{c_void, CStr, CString};
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
};
use winapi::shared::ntdef::{LIST_ENTRY, UNICODE_STRING};

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
    
    #[cfg(target_arch = "x86_64")]
    use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86")]
    use winapi::um::winnt::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;

    let nt_headers = &*(base.add(e_lfanew) as *const IMAGE_NT_HEADERS);
    if nt_headers.Signature != 0x4550 {
        return std::ptr::null_mut();
    }

    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    let export_dir_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
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
                        // Forwarded export, fallback to native GetProcAddress
                        if let Ok(cname) = CString::new(proc_name) {
                            return GetProcAddress(module as _, cname.as_ptr() as _) as *mut c_void;
                        }
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

    // 2. Copy sections
    for section in &pe.sections {
        let dest = image_base.add(section.virtual_address as usize);
        let src = dll_bytes.as_ptr().add(section.pointer_to_raw_data as usize);
        std::ptr::copy_nonoverlapping(src, dest as *mut u8, section.size_of_raw_data as usize);
    }

    // 3. Process imports
    if let Some(import_dir) = pe.directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT as usize) {
        let import_desc = pe.import_data.as_ref().unwrap();
        for import in import_desc {
            let module_name = CStr::from_ptr(import.name.as_ptr() as *const i8);
            let module_name_str = module_name.to_str()?;
            
            // Try PEB first, then fallback to LoadLibraryA
            let mut module_handle = get_module_handle_peb(module_name_str);
            if module_handle.is_null() {
                module_handle = LoadLibraryA(module_name.as_ptr()) as *mut c_void;
                if module_handle.is_null() {
                    return Err(anyhow!("Failed to load dependent module {}", module_name_str));
                }
            }

            for (i, func_name) in import.import_by_name.iter().enumerate() {
                let proc_addr = get_proc_address_manual(module_handle, &func_name.name);
                if proc_addr.is_null() {
                    return Err(anyhow!("Failed to resolve function {}", func_name.name));
                }
                let thunk_ref =
                    image_base.add(import.first_thunk as usize + i * std::mem::size_of::<usize>());
                *(thunk_ref as *mut usize) = proc_addr as usize;
            }
        }
    }

    // 4. Apply base relocations
    let base_delta = image_base as isize - optional_header.windows_fields.image_base as isize;
    if base_delta != 0 {
        if let Some(reloc_dir) = pe.directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC as usize) {
            if let Some(ref relocs) = pe.relocations {
                for reloc in relocs {
                    let page_va = image_base.add(reloc.virtual_address as usize);
                    for &entry in &reloc.entries {
                        let offset = entry.data;
                        let reloc_type = entry.kind;
                        if reloc_type == 10 {
                            // IMAGE_REL_BASED_DIR64
                            let reloc_addr = page_va.add(offset as usize);
                            let original_addr = *(reloc_addr as *mut isize);
                            *(reloc_addr as *mut isize) = original_addr + base_delta;
                        }
                    }
                }
            }
        }
    }

    // 5. Set memory protections
    for section in &pe.sections {
        let mut prot = 0;
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            prot |= PAGE_EXECUTE_READ;
        }
        if section.characteristics & IMAGE_SCN_MEM_READ != 0 {
            prot |= PAGE_READWRITE; // Simplified
        }
        if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            prot |= PAGE_READWRITE;
        }
        let mut old_prot = 0;
        VirtualProtect(
            image_base.add(section.virtual_address as usize),
            section.virtual_size as usize,
            prot,
            &mut old_prot,
        );
    }

    // 6. Call entry point
    let entry_point_addr =
        image_base.add(optional_header.windows_fields.address_of_entry_point as usize);
    let entry_point: extern "system" fn(*mut c_void, u32, *mut c_void) -> bool =
        std::mem::transmute(entry_point_addr);
    if !entry_point(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut()) {
        return Err(anyhow!("DLL entry point failed"));
    }

    Ok(image_base)
}
