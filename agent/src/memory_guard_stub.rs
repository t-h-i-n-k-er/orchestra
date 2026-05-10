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
use std::sync::Mutex;

// ── Statics ──────────────────────────────────────────────────────────────────

/// Registered regions: (pointer, length, label).
///
/// Raw pointers are safe to send across threads because the regions are
/// `'static` and we only access them inside `unsafe` blocks with the
/// caller's responsibility to ensure validity.
static REGISTERED_REGIONS: Mutex<Vec<(usize, usize, &'static str)>> = Mutex::new(Vec::new());

/// Per-cycle XOR key: generated fresh on every `lock()` call.
/// A new key per cycle prevents trivial recovery via plaintext/ciphertext
/// XOR comparison across multiple sleep windows.
static CURRENT_KEY: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);

/// Per-cycle integrity checksums: one per registered region.
/// Stores a 32-byte hash of each region's plaintext content before
/// encryption so that `unlock()` can detect tampering while encrypted.
static INTEGRITY_HASHES: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

// ── Opaque handle ────────────────────────────────────────────────────────────

/// Opaque handle returned by [`lock`].  Carries the per-cycle key and a
/// copy of the integrity hashes so `unlock` can verify without relying on
/// global mutable state that may have been corrupted.
pub struct KeyHandle {
    key: [u8; 32],
    hashes: Vec<[u8; 32]>,
}

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
    REGISTERED_REGIONS
        .lock()
        .unwrap()
        .push((buf.as_mut_ptr() as usize, buf.len(), label));
    log::debug!(
        "memory_guard_stub: registered region '{}' ({} bytes)",
        label,
        buf.len()
    );
}

/// Lock (XOR-encrypt) all registered regions.
///
/// Generates a **fresh random key** for this cycle, computes integrity
/// hashes of each region's plaintext, then XOR-encrypts.  The key and
/// hashes are returned in a [`KeyHandle`] that must be passed to [`unlock`].
///
/// # Errors
///
/// Returns an error if random key generation fails.
#[inline]
pub fn lock() -> Result<KeyHandle> {
    log::debug!(
        "memory-guard: feature disabled; using XOR-based stub encryption \
         (NOT as strong as XChaCha20-Poly1305; enable memory-guard feature for full protection)"
    );
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    if key.iter().all(|&b| b == 0) {
        anyhow::bail!("memory_guard_stub::lock: key generation produced all-zeros key");
    }

    let regions = REGISTERED_REGIONS.lock().unwrap();

    // Compute integrity hashes of plaintext before encryption.
    let mut hashes = Vec::with_capacity(regions.len());
    for &(ptr_addr, len, _label) in regions.iter() {
        let hash = if ptr_addr == 0 || len == 0 {
            [0u8; 32]
        } else {
            unsafe { simple_hash(ptr_addr as *mut u8, len) }
        };
        hashes.push(hash);
    }

    xor_regions(&regions, &key);

    // Store the key globally for guarded_sleep() compatibility.
    *CURRENT_KEY.lock().unwrap() = key;
    *INTEGRITY_HASHES.lock().unwrap() = hashes.clone();

    Ok(KeyHandle { key, hashes })
}

/// Unlock (XOR-decrypt) all registered regions.
///
/// XOR is symmetric — applying the same operation with the same key
/// restores the original plaintext.  After decryption, integrity hashes
/// are verified to detect tampering while the memory was encrypted.
///
/// # Errors
///
/// Returns an error if integrity verification fails (data was modified
/// while encrypted) or if the handle is invalid.
#[inline]
pub fn unlock(handle: KeyHandle) -> Result<()> {
    let regions = REGISTERED_REGIONS.lock().unwrap();
    xor_regions(&regions, &handle.key);

    // Verify integrity: compare post-decryption hashes with pre-encryption hashes.
    for (i, &(ptr_addr, len, label)) in regions.iter().enumerate() {
        if ptr_addr == 0 || len == 0 {
            continue;
        }
        let expected = handle.hashes.get(i).copied().unwrap_or([0u8; 32]);
        if expected == [0u8; 32] {
            continue; // region was empty/null at lock time
        }
        let actual = unsafe { simple_hash(ptr_addr as *mut u8, len) };
        if actual != expected {
            log::error!(
                "memory_guard_stub: INTEGRITY CHECK FAILED for region '{}' — \
                 data was modified while encrypted! Expected hash {:02x?}, got {:02x?}",
                label,
                &expected[..8],
                &actual[..8]
            );
            anyhow::bail!(
                "memory_guard_stub: integrity check failed for region '{}'",
                label
            );
        }
    }

    // Clear the per-cycle key from global state.
    *CURRENT_KEY.lock().unwrap() = [0u8; 32];
    INTEGRITY_HASHES.lock().unwrap().clear();

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
/// regions.  Verifies integrity hashes to detect tampering.
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
/// signal), then decrypts regions on wake.  A fresh key is generated for
/// each sleep cycle.
///
/// The `mask_rotation_interval` parameter is ignored in the stub — there is
/// no scheme rotation for the XOR cipher.
#[inline]
pub async fn guarded_sleep(
    duration: std::time::Duration,
    wake_rx: Option<tokio::sync::watch::Receiver<bool>>,
    _mask_rotation_interval: u64,
) -> Result<()> {
    let handle = lock()?;
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
    unlock(handle)?;
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
pub fn init_schemes(_schemes: Vec<common::config::SleepScheme>, _rotation_interval: u32) {
    // No-op in the stub.
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Simple hash for integrity verification.
///
/// Uses a FNV-1a-inspired hash stretched to 32 bytes.  This is NOT
/// cryptographically strong but is sufficient to detect accidental or
/// naive tampering with encrypted memory during sleep cycles.
///
/// # Safety
///
/// `ptr` must point to at least `len` readable bytes.
unsafe fn simple_hash(ptr: *mut u8, len: usize) -> [u8; 32] {
    // FNV-1a offset basis and prime for 64-bit.
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut state: [u64; 4] = [
        FNV_OFFSET.wrapping_add(1),
        FNV_OFFSET.wrapping_add(2),
        FNV_OFFSET.wrapping_add(3),
        FNV_OFFSET.wrapping_add(4),
    ];

    let slice = std::slice::from_raw_parts(ptr, len);
    for (i, &byte) in slice.iter().enumerate() {
        let lane = &mut state[i % 4];
        *lane ^= byte as u64;
        *lane = lane.wrapping_mul(FNV_PRIME);
    }

    let mut result = [0u8; 32];
    for (i, &s) in state.iter().enumerate() {
        result[i * 8..(i + 1) * 8].copy_from_slice(&s.to_le_bytes());
    }
    result
}

/// Apply the XOR cipher to every registered region.
fn xor_regions(regions: &[(usize, usize, &'static str)], key: &[u8; 32]) {
    for &(ptr_addr, len, label) in regions {
        if ptr_addr == 0 || len == 0 {
            continue;
        }
        unsafe {
            let ptr = ptr_addr as *mut u8;
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
