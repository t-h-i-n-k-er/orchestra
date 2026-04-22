import re

with open("agent/src/persistence.rs", "r") as f:
    code = f.read()

code = code.replace(
    '#[cfg(any(target_os = "linux", target_os = "windows"))]',
    '#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]'
)
code = code.replace(
    '#[cfg(not(any(target_os = "linux", target_os = "windows")))]',
    '#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]'
)

macos_impl = '''
#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    if let Ok(p) = std::env::var("ORCHESTRA_PERSISTENCE_ROOT") {
        return PathBuf::from(p).join(format!("{}.plist", get_service_name()));
    }
    if let Some(dir) = directories::BaseDirs::new() {
        dir.home_dir().join("Library").join("LaunchAgents").join(format!("{}.plist", get_service_name()))
    } else {
        PathBuf::from(format!("{}.plist", get_service_name()))
    }
}

#[cfg(target_os = "macos")]
fn install_persistence_inner() -> Result<PathBuf> {
    let path = plist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create LaunchAgents directory {}", parent.display()))?;
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
    <true/>
</dict>
</plist>
"#,
        service_name, exe_path
    );

    std::fs::write(&path, plist)
        .with_context(|| format!("Failed to write plist file {}", path.display()))?;

    if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
        let status = std::process::Command::new("launchctl")
            .args(["load", &path.to_string_lossy().to_string()])
            .status()?;
        if !status.success() {
            anyhow::bail!("launchctl load failed with status: {status}");
        }
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn uninstall_persistence_inner() -> Result<()> {
    let path = plist_path();
    if path.exists() {
        if std::env::var("ORCHESTRA_PERSISTENCE_ROOT").is_err() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &path.to_string_lossy().to_string()])
                .status();
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove {}", path.display()))?;
    }
    Ok(())
}
'''

# Find the end of windows uninstall_persistence_inner
insert_pos = code.find('#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]')
code = code[:insert_pos] + macos_impl + code[insert_pos:]

with open("agent/src/persistence.rs", "w") as f:
    f.write(code)

