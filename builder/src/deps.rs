//! Dependency / toolchain detection for the Builder.
//!
//! We only ever *check* and *report* — automatic installs are gated behind an
//! explicit `--auto-install` flag (handled in `main.rs`) so that running the
//! builder never silently escalates privileges.

use anyhow::{anyhow, Context, Result};
use std::process::Command;
use tracing::{info, warn};

/// Required system packages, keyed by current OS.
fn required_system_packages() -> &'static [(&'static str, &'static str)] {
    // (binary_to_check, install_hint)
    #[cfg(target_os = "linux")]
    {
        &[
            ("cc", "sudo apt-get install -y build-essential"),
            ("pkg-config", "sudo apt-get install -y pkg-config"),
            (
                "x86_64-w64-mingw32-gcc",
                "sudo apt-get install -y mingw-w64  # for cross-compiling to Windows",
            ),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            ("cc", "xcode-select --install"),
            ("pkg-config", "brew install pkg-config"),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        &[(
            "cl.exe",
            "Install Visual Studio Build Tools (https://aka.ms/vs/17/release/vs_BuildTools.exe)",
        )]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        &[]
    }
}

/// Rust targets the builder will need to be able to cross-compile for the full
/// matrix.
const RUST_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-gnu",
    "x86_64-apple-darwin",
];

/// Entry point for `builder setup` command.
pub fn cmd_setup(auto_install: bool) -> Result<()> {
    let missing = ensure_dependencies(false)?;
    if missing.is_empty() {
        return Ok(());
    }

    if auto_install {
        info!("Attempting to install missing dependencies...");
        install_missing_dependencies(&missing)?;
        info!("Re-running dependency check...");
        ensure_dependencies(true)?;
    } else {
        anyhow::bail!("Dependencies missing. Re-run with `--auto-install` to attempt installation.");
    }
    Ok(())
}

/// Inspect the host environment and report what's missing. Returns a list of
/// missing dependency descriptions. If `fatal` is true, returns an error on
/// the first missing dependency.
fn ensure_dependencies(fatal: bool) -> Result<Vec<String>> {
    let mut missing: Vec<String> = Vec::new();

    if which::which("cargo").is_err() {
        let msg = "cargo (install via https://rustup.rs/ — `curl https://sh.rustup.rs -sSf | sh`)";
        if fatal {
            return Err(anyhow!(msg.to_string()));
        }
        missing.push(msg.into());
    } else {
        info!("✓ cargo present");
    }

    if which::which("rustup").is_err() {
        let msg = "rustup (https://rustup.rs/)";
        if fatal {
            return Err(anyhow!(msg.to_string()));
        }
        missing.push(msg.into());
    } else {
        info!("✓ rustup present");
    }

    for (bin, hint) in required_system_packages() {
        if which::which(bin).is_err() {
            let msg = format!("{bin} — install with: {hint}");
            if fatal {
                return Err(anyhow!(msg));
            }
            missing.push(msg);
        } else {
            info!("✓ {bin} present");
        }
    }

    // Verify rust targets.
    if which::which("rustup").is_ok() {
        let installed = installed_rust_targets()?;
        for t in RUST_TARGETS {
            if installed.iter().any(|i| i == t) {
                info!("✓ rust target {t} installed");
            } else {
                let msg = format!("rust target {t} — install with: rustup target add {t}");
                if fatal {
                    return Err(anyhow!(msg));
                }
                missing.push(msg);
            }
        }
    }

    if missing.is_empty() {
        info!("All build dependencies satisfied.");
    } else if !fatal {
        eprintln!("\nMissing dependencies:");
        for m in &missing {
            eprintln!("  - {m}");
        }
    }

    Ok(missing)
}

fn install_missing_dependencies(missing: &[String]) -> Result<()> {
    for m in missing {
        if m.contains("rust target") {
            let target = m.split(' ').nth(2).unwrap();
            info!("Installing rust target {}...", target);
            let status = Command::new("rustup")
                .args(["target", "add", target])
                .status()
                .context("Failed to run `rustup target add`")?;
            if !status.success() {
                return Err(anyhow!("`rustup target add {}` failed", target));
            }
        } else {
            warn!("Cannot auto-install: {}", m);
        }
    }
    Ok(())
}

/// Query `rustup` for a list of installed targets.
fn installed_rust_targets() -> Result<Vec<String>> {
    let output = Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
        .context("Failed to query installed rust targets")?;
    if !output.status.success() {
        return Err(anyhow!(
            "rustup target list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}
