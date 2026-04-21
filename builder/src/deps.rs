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

/// Inspect the host environment and report what's missing. Returns `Ok(())`
/// only if every required tool is present.
pub fn ensure_dependencies() -> Result<()> {
    let mut missing: Vec<String> = Vec::new();

    if which::which("cargo").is_err() {
        missing.push(
            "cargo (install via https://rustup.rs/ — `curl https://sh.rustup.rs -sSf | sh`)".into(),
        );
    } else {
        info!("✓ cargo present");
    }

    if which::which("rustup").is_err() {
        missing.push("rustup (https://rustup.rs/)".into());
    } else {
        info!("✓ rustup present");
    }

    for (bin, hint) in required_system_packages() {
        if which::which(bin).is_err() {
            missing.push(format!("{bin} — install with: {hint}"));
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
                missing.push(format!(
                    "rust target {t} — install with: rustup target add {t}"
                ));
            }
        }
    }

    if missing.is_empty() {
        info!("All build dependencies satisfied.");
        Ok(())
    } else {
        eprintln!("\nMissing dependencies:");
        for m in &missing {
            eprintln!("  - {m}");
        }
        Err(anyhow!(
            "{} dependency item(s) missing — see instructions above",
            missing.len()
        ))
    }
}

/// Try to add any missing rust targets via `rustup target add`. Requires
/// network access; user must have already approved this action.
pub fn auto_install_rust_targets() -> Result<()> {
    let installed = installed_rust_targets().unwrap_or_default();
    for t in RUST_TARGETS {
        if installed.iter().any(|i| i == t) {
            continue;
        }
        info!("Adding rust target {t} ...");
        let status = Command::new("rustup")
            .args(["target", "add", t])
            .status()
            .with_context(|| format!("Failed to invoke rustup target add {t}"))?;
        if !status.success() {
            warn!("rustup target add {t} exited with {status}");
        }
    }
    Ok(())
}

fn installed_rust_targets() -> Result<Vec<String>> {
    let out = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("Failed to run `rustup target list --installed`")?;
    if !out.status.success() {
        return Err(anyhow!("rustup target list exited with {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}
