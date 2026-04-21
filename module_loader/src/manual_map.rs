//! Manual map PE loader for Windows.
#![cfg(all(windows, feature = "manual-map"))]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::ffi::{c_void, CStr};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};

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
    if let Some(import_dir) = pe.directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        let import_desc = pe.import_data.as_ref().unwrap();
        for import in import_desc {
            let module_name = CStr::from_ptr(import.name.as_ptr() as *const i8);
            let module_handle = GetModuleHandleA(module_name.as_ptr());
            if module_handle.is_null() {
                return Err(anyhow!(
                    "GetModuleHandleA failed for {}",
                    module_name.to_str()?
                ));
            }

            for (i, func_name) in import.import_by_name.iter().enumerate() {
                let proc_addr = GetProcAddress(module_handle, func_name.name.as_ptr() as *const i8);
                if proc_addr.is_null() {
                    return Err(anyhow!("GetProcAddress failed for {}", func_name.name));
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
        if let Some(reloc_dir) = pe.directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
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
