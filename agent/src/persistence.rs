//! Opt-in persistence for enterprise maintenance.
//!
//! When `persistence_enabled = true` in `agent.toml`, the agent installs a
//! per-user systemd unit (Linux) or a scheduled task (Windows) that re-launches
//! the agent at the next user login. This is an *opt-in* convenience for
//! environments where an administrator wants the agent to survive reboots
//! without manually redeploying the launcher each time.
//!
//! All entry points return a `Result` and never panic. Test runs use the
//! `ORCHESTRA_PERSISTENCE_ROOT` environment variable to redirect filesystem
//! writes into a temporary directory.

#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::Context;
use anyhow::Result;
use std::path::PathBuf;

/// Determine where the persistence-related files should live. In production
/// this is `$XDG_CONFIG_HOME/systemd/user` on Linux. In tests, the root can be
/// overridden via `ORCHESTRA_PERSISTENCE_ROOT`.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn config_root() -> PathBuf {
    if let Ok(p) = std::env::var("ORCHESTRA_PERSISTENCE_ROOT") {
        return PathBuf::from(p);
    }
    if let Some(dir) = directories::BaseDirs::new() {
        dir.config_dir().to_path_buf()
    } else {
        PathBuf::from(".")
    }
}

#[cfg(target_os = "linux")]
fn unit_path() -> PathBuf {
    config_root().join("systemd/user/orchestra-agent.service")
}

#[cfg(target_os = "windows")]
fn task_marker_path() -> PathBuf {
    config_root().join("Orchestra/persistence-task.installed")
}

/// Install the persistence entry. Returns the absolute path that was created
/// (useful for tests).
pub fn install_persistence() -> Result<PathBuf> {
    install_persistence_inner()
}

/// Remove the persistence entry installed by [`install_persistence`].
pub fn uninstall_persistence() -> Result<()> {
    uninstall_persistence_inner()
}

#[cfg(target_os = "linux")]
fn install_persistence_inner() -> Result<PathBuf> {
    let path = unit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create unit directory {}", parent.display()))?;
    }

    let unit = "[Unit]\n\
                Description=Orchestra remote-management agent\n\
                After=network-online.target\n\n\
                [Service]\n\
                Type=simple\n\
                ExecStart=/usr/local/bin/orchestra-launcher\n\
                Restart=on-failure\n\n\
                [Install]\n\
                WantedBy=default.target\n";

    std::fs::write(&path, unit)
        .with_context(|| format!("Failed to write unit file {}", path.display()))?;

    // Best-effort enable; silently tolerate missing systemctl in tests.
    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "orchestra-agent.service"])
            .status();
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn uninstall_persistence_inner() -> Result<()> {
    let path = unit_path();
    if path.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", "orchestra-agent.service"])
                .status();
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_persistence_inner() -> Result<PathBuf> {
    let marker = task_marker_path();
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let status = std::process::Command::new("schtasks")
            .args([
                "/Create",
                "/F",
                "/SC",
                "ONLOGON",
                "/TN",
                "OrchestraAgent",
                "/TR",
                "C:\\Program Files\\Orchestra\\launcher.exe",
            ])
            .status()
            .context("Failed to invoke schtasks")?;
        if !status.success() {
            anyhow::bail!("schtasks /Create exited with {status}");
        }
    }
    std::fs::write(&marker, b"installed")?;
    Ok(marker)
}

#[cfg(target_os = "windows")]
fn uninstall_persistence_inner() -> Result<()> {
    let marker = task_marker_path();
    if marker.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let _ = std::process::Command::new("schtasks")
                .args(["/Delete", "/F", "/TN", "OrchestraAgent"])
                .status();
        }
        std::fs::remove_file(&marker)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn install_persistence_inner() -> Result<PathBuf> {
    anyhow::bail!("Persistence is not implemented on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn uninstall_persistence_inner() -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn install_then_uninstall_in_sandbox() {
        let dir = tempdir().unwrap();
        std::env::set_var("ORCHESTRA_PERSISTENCE_ROOT", dir.path());

        let path = install_persistence().expect("install");
        assert!(path.exists(), "unit/marker file was not created");

        uninstall_persistence().expect("uninstall");
        assert!(!path.exists(), "uninstall did not remove the file");

        std::env::remove_var("ORCHESTRA_PERSISTENCE_ROOT");
    }
}
