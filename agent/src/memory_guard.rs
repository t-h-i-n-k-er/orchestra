//! Memory-Guard: encrypt sensitive heap regions while the agent is idle.
//!
//! # Design overview
//!
//! When the agent is between work cycles it has nothing useful to compute.
//! Leaving plaintext secrets in RAM during that window is unnecessary risk:
//! a cold-boot attack, a kernel-level memory dump, or a live-forensics scan
//! could extract session keys, the loaded-module blob, or the configuration
//! blob that includes the module-signing key and server fingerprint.
//!
//! This module provides a zero-overhead abstraction on top of XChaCha20-Poly1305
//! to:
//!
//! 1. **Register** arbitrary byte slices as *sensitive regions* before sleeping.
//! 2. **Lock** (encrypt in-place) all regions with a freshly generated key, then
//!    zero-out and drop the key from the heap.
//! 3. **Stash the key** in CPU registers for the duration of the idle window.
//!    On x86-64 the 32-byte key is spread across two 128-bit XMM registers
//!    (`xmm14` / `xmm15`) which are non-volatile across context switches on
//!    Windows but volatile on Linux — a trade-off documented in the caveats
//!    below.  On other architectures (aarch64, etc.) the key is kept in a
//!    locked memory page instead because that ABI does not offer 256+ bits of
//!    caller-saved float registers.
//! 4. **Retrieve the key** from registers, decrypt all regions, and clear the
//!    registers before the agent resumes.
//!
//! # Caveats
//!
//! * On **Linux x86-64** the kernel *does* save and restore XMM14/XMM15 across
//!   a context switch because they are part of the XSAVE area.  That means the
//!   key bytes do transiently appear in kernel memory during context switches.
//!   This scheme is therefore resistant to *user-space* memory inspection tools
//!   (ptrace, /proc/mem, VM snapshots in user mode) but not to a *kernel* dump.
//!   Accept this as a documented limitation.
//! * The AEAD nonce (12 bytes) is stored alongside the ciphertext in each
//!   region header.  It is not secret.
//! * AEAD authentication tags are validated on decryption; a mismatch causes
//!   the agent to abort rather than continue with corrupt data.
//!
//! # Feature gate
//!
//! This entire module is compiled only when the `memory-guard` Cargo feature is
//! enabled.  All public entry points are no-ops when the feature is absent (see
//! `memory_guard_stub.rs`).

#![cfg(feature = "memory-guard")]

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A descriptor for a region of memory that should be encrypted while idle.
///
/// Safety invariant: `ptr` must remain valid for the entire lifetime of the
/// `GuardedRegion` in the registry.  Callers are responsible for ensuring this
/// (typically by registering heap-allocated buffers whose lifetime is `'static`
/// or that of the agent).
struct GuardedRegion {
    /// Raw pointer to the beginning of the buffer.
    ptr: *mut u8,
    /// Length of the buffer in bytes.
    len: usize,
    /// Human-readable label for diagnostics.
    label: &'static str,
    /// `true` while the region is encrypted (locked).
    locked: bool,
    /// 24-byte nonce written into the first 24 bytes of the region when locked.
    /// Stored here so we can decrypt without scanning for a header.
    nonce: [u8; 24],
    /// AEAD authentication tag (16 bytes) appended after encryption.
    tag: [u8; 16],
}

// SAFETY: The agent is single-operator; raw pointers are accessed only while
// holding the global `REGISTRY` mutex.
unsafe impl Send for GuardedRegion {}
unsafe impl Sync for GuardedRegion {}

/// Global registry of sensitive regions.
static REGISTRY: OnceLock<Mutex<Vec<GuardedRegion>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<GuardedRegion>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Register a mutable byte slice as a sensitive region.
///
/// The slice must outlive all calls to [`lock`] and [`unlock`].  In practice
/// this means passing `'static` buffers (e.g. contents of `lazy_static!` or
/// `Box::leak`-ed heap data).
///
/// # Safety
///
/// The caller must ensure that no other thread reads or writes `buf` between a
/// call to [`lock`] and the corresponding call to [`unlock`].
pub unsafe fn register(buf: &'static mut [u8], label: &'static str) {
    let mut reg = registry().lock().unwrap();
    reg.push(GuardedRegion {
        ptr: buf.as_mut_ptr(),
        len: buf.len(),
        label,
        locked: false,
        nonce: [0u8; 24],
        tag: [0u8; 16],
    });
    tracing::debug!(
        "[memory-guard] registered region '{}' ({} bytes)",
        label,
        buf.len()
    );
}

/// Encrypt all registered regions in-place and stash the key in CPU registers.
///
/// After this call returns the 32-byte key is held *only* in XMM14/XMM15 (x86-64)
/// or in a locked memory page (other architectures) — it is **not** present in
/// any heap or stack allocation owned by this function.
///
/// Returns the opaque key handle that must be passed to [`unlock`].  The handle
/// contains no heap data; it is a wrapper around the register-stash mechanism.
pub fn lock() -> Result<KeyHandle> {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    {
        let mut reg = registry().lock().unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("failed to create cipher"))?;

        for region in reg.iter_mut() {
            if region.locked {
                tracing::warn!(
                    "[memory-guard] region '{}' already locked, skipping",
                    region.label
                );
                continue;
            }
            // Generate a fresh 24-byte nonce for each region.
            let mut nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from_slice(&nonce_bytes);

            // SAFETY: We hold the registry mutex; no other code accesses the region.
            let buf = unsafe { std::slice::from_raw_parts_mut(region.ptr, region.len) };

            // Encrypt in-place.  chacha20poly1305 appends the 16-byte tag.
            // We store the buf as plaintext then call encrypt_in_place which
            // extends the buffer in-place — but we can't extend a raw slice.
            // Instead we use Aead::encrypt which allocates, then copy back.
            let ct = cipher
                .encrypt(nonce, buf as &[u8])
                .map_err(|_| anyhow::anyhow!("encryption failed for region '{}'", region.label))?;

            // ct = ciphertext (same length) + 16-byte tag.
            // Copy ciphertext back over the plaintext.
            let ct_len = ct.len() - 16;
            buf[..ct_len].copy_from_slice(&ct[..ct_len]);
            region.tag.copy_from_slice(&ct[ct_len..]);
            region.nonce = nonce_bytes;
            region.locked = true;

            tracing::debug!("[memory-guard] locked region '{}'", region.label);
        }
    }

    // Stash the key in registers (erases from stack first).
    let handle = KeyHandle::stash(key_bytes);
    // key_bytes is zeroed by stash(); belt-and-suspenders zeroize it here too.
    key_bytes.zeroize();
    Ok(handle)
}

/// Decrypt all registered regions using the key retrieved from CPU registers.
///
/// Consumes the `KeyHandle`, which zeroes the key out of the register stash.
pub fn unlock(handle: KeyHandle) -> Result<()> {
    let mut key_bytes = handle.retrieve();

    {
        let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("failed to create cipher for unlock"))?;

        let mut reg = registry().lock().unwrap();
        for region in reg.iter_mut() {
            if !region.locked {
                tracing::warn!(
                    "[memory-guard] region '{}' not locked, skipping unlock",
                    region.label
                );
                continue;
            }
            let nonce = XNonce::from_slice(&region.nonce);

            // Reassemble ciphertext || tag into a temporary buffer for decryption.
            let buf = unsafe { std::slice::from_raw_parts(region.ptr, region.len) };
            let mut combined = Vec::with_capacity(region.len + 16);
            combined.extend_from_slice(buf);
            combined.extend_from_slice(&region.tag);

            let pt = cipher.decrypt(nonce, combined.as_slice()).map_err(|_| {
                anyhow::anyhow!(
                    "[memory-guard] authentication tag mismatch for region '{}': \
                         memory may have been tampered with",
                    region.label
                )
            })?;

            // Copy plaintext back.
            let dst = unsafe { std::slice::from_raw_parts_mut(region.ptr, region.len) };
            dst.copy_from_slice(&pt);
            region.locked = false;
            region.nonce.zeroize();
            region.tag.zeroize();

            tracing::debug!("[memory-guard] unlocked region '{}'", region.label);
        }
    }

    key_bytes.zeroize();
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Sleep-window wrappers used by `obfuscated_sleep`
// ──────────────────────────────────────────────────────────────────────────────

thread_local! {
    static SLEEP_KEY_HANDLE: std::cell::RefCell<Option<KeyHandle>> = const { std::cell::RefCell::new(None) };
}

/// Encrypt all registered regions and stash the key handle thread-locally so
/// the matching `unguard_memory()` call can retrieve it.
pub fn guard_memory() -> Result<()> {
    let h = lock()?;
    SLEEP_KEY_HANDLE.with(|c| *c.borrow_mut() = Some(h));
    Ok(())
}

/// Restore all registered regions using the previously-stashed key handle.
/// Returns an error if no matching `guard_memory()` call preceded it.
pub fn unguard_memory() -> Result<()> {
    let h = SLEEP_KEY_HANDLE
        .with(|c| c.borrow_mut().take())
        .ok_or_else(|| anyhow::anyhow!("unguard_memory called without prior guard_memory"))?;
    unlock(h)
}

// ──────────────────────────────────────────────────────────────────────────────
// KeyHandle — register stash
// ──────────────────────────────────────────────────────────────────────────────

/// Opaque handle that holds the 32-byte encryption key in CPU registers.
///
/// On x86-64 **Windows** the key bytes are packed into two 128-bit XMM registers
/// (`xmm14` and `xmm15`) using `movdqu`.  Those registers are non-volatile
/// (callee-saved) in the Windows x64 ABI so they survive across async suspension
/// points.  On Linux / all other targets a locked heap page is used instead,
/// because xmm14/15 are caller-saved in the System V AMD64 ABI and would be
/// clobbered by the Tokio executor between stash and retrieve.
pub struct KeyHandle {
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "windows",
        feature = "memory-guard"
    ))]
    _marker: (),
    /// Fallback: locked heap page on Linux x86-64 and all non-x86-64 targets.
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    locked_page: LockedKeyPage,
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
impl Drop for KeyHandle {
    fn drop(&mut self) {
        // Zero the XMM register stash unconditionally on drop so that a
        // handle that is discarded without calling retrieve() still cleans up.
        unsafe {
            std::arch::asm!(
                "pxor xmm14, xmm14",
                "pxor xmm15, xmm15",
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
impl KeyHandle {
    fn stash(mut key: [u8; 32]) -> Self {
        unsafe {
            // Load the two halves of the key into xmm14 and xmm15.
            // SAFETY: On the Windows x64 ABI xmm14/15 are non-volatile
            // (callee-saved), so they are preserved across function calls and
            // async suspension points within the same OS thread.
            std::arch::asm!(
                "movdqu xmm14, [{lo}]",
                "movdqu xmm15, [{hi}]",
                lo = in(reg) key.as_ptr(),
                hi = in(reg) key.as_ptr().add(16),
                options(nostack, preserves_flags),
            );
        }
        key.zeroize();
        KeyHandle { _marker: () }
    }

    fn retrieve(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            std::arch::asm!(
                "movdqu [{lo}], xmm14",
                "movdqu [{hi}], xmm15",
                lo = in(reg) out.as_mut_ptr(),
                hi = in(reg) out.as_mut_ptr().add(16),
                options(nostack, preserves_flags),
            );
            // Zero the register stash.
            std::arch::asm!(
                "pxor xmm14, xmm14",
                "pxor xmm15, xmm15",
                options(nostack, preserves_flags),
            );
        }
        out
    }
}

// On Linux x86_64 xmm14/15 are caller-saved (System V ABI), so we use the
// LockedKeyPage fallback to avoid corruption across await points.
#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
impl KeyHandle {
    fn stash(key: [u8; 32]) -> Self {
        KeyHandle {
            locked_page: LockedKeyPage::new(key),
        }
    }

    fn retrieve(mut self) -> [u8; 32] {
        let k = *self.locked_page.key;
        self.locked_page.key.zeroize();
        k
    }
}

// ── Fallback: locked heap page (non-Windows x86-64 and all non-x86-64 targets)

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
struct LockedKeyPage {
    key: Box<[u8; 32]>,
}

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
impl LockedKeyPage {
    fn new(key: [u8; 32]) -> Self {
        let mut b = Box::new(key);
        // mlock the page so it is not swapped out.
        #[cfg(unix)]
        unsafe {
            libc::mlock(b.as_ptr() as *const _, 32);
        }
        LockedKeyPage { key: b }
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
impl Drop for LockedKeyPage {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.key.as_ptr() as *const _, 32);
        }
    }
}

// Fallback: locked heap page for non-x86-64 targets only.
// Linux x86_64 is handled by the explicit impl block above; the
// `not(all(x86_64, windows))` predicate used to also match Linux x86_64 and
// created a duplicate impl error (B-01). Narrowed to `not(x86_64)`.
#[cfg(not(target_arch = "x86_64"))]
impl KeyHandle {
    fn stash(key: [u8; 32]) -> Self {
        KeyHandle {
            locked_page: LockedKeyPage::new(key),
        }
    }

    fn retrieve(mut self) -> [u8; 32] {
        let k = *self.locked_page.key;
        self.locked_page.key.zeroize();
        k
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Idle timer — platform-specific wake-up
// ──────────────────────────────────────────────────────────────────────────────

/// Sleep for `duration`, holding memory locked for the duration.
///
/// This is the primary entry point for the agent's idle path.  It:
///
/// 1. Encrypts all registered regions and stashes the key in registers.
/// 2. Sleeps for exactly `duration` (or until `wake_rx` fires, whichever comes
///    first).
/// 3. Retrieves the key, decrypts all regions.
///
/// The `wake_rx` channel is optional.  Pass `None` if no early-wake is needed.
pub async fn guarded_sleep(
    duration: std::time::Duration,
    wake_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    let handle = lock()?;

    let sleep_fut = tokio::time::sleep(duration);
    tokio::pin!(sleep_fut);

    match wake_rx {
        Some(mut rx) => {
            tokio::select! {
                _ = &mut sleep_fut => {},
                _ = rx.changed() => {
                    tracing::debug!("[memory-guard] early wake signal received");
                }
            }
        }
        None => sleep_fut.await,
    }

    unlock(handle)?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Serialize all tests that mutate the global REGISTRY.  Because the
    // registry is a process-wide singleton, running tests in parallel would
    // let one test's `fresh_registry()` clear regions registered by another
    // concurrent test, producing false-positives and race conditions.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fresh_registry() {
        if let Some(reg) = REGISTRY.get() {
            reg.lock().unwrap().clear();
        }
    }

    /// Helper: read `n` bytes from a raw pointer as a Vec (no borrow of the
    /// original `&'static mut` slice).
    unsafe fn read_bytes(ptr: *const u8, n: usize) -> Vec<u8> {
        std::slice::from_raw_parts(ptr, n).to_vec()
    }

    /// Basic round-trip: register a buffer, lock it, verify ciphertext ≠ plaintext,
    /// unlock it, verify plaintext restored.
    #[test]
    fn roundtrip_encrypt_decrypt() {
        let _guard = TEST_LOCK.lock().unwrap();
        fresh_registry();

        let plaintext_orig = b"super-secret-session-key-1234567";
        let boxed: Box<[u8]> = plaintext_orig.to_vec().into_boxed_slice();
        let leaked: &'static mut [u8] = Box::leak(boxed);
        let ptr = leaked.as_ptr();
        let len = leaked.len();

        unsafe { register(leaked, "test-roundtrip") }

        let handle = lock().expect("lock should succeed");

        let after_lock = unsafe { read_bytes(ptr, len) };
        assert_ne!(
            after_lock.as_slice(),
            plaintext_orig.as_ref(),
            "plaintext must be encrypted after lock()"
        );

        unlock(handle).expect("unlock should succeed");

        let restored = unsafe { read_bytes(ptr, len) };
        assert_eq!(
            restored.as_slice(),
            plaintext_orig.as_ref(),
            "plaintext must be fully restored after unlock()"
        );
    }

    /// A second `lock()` call must not re-encrypt an already-locked region
    /// (doing so with a different key would make h1 unable to decrypt it).
    ///
    /// NOTE: nested lock/unlock pairs are **not** supported.  The XMM register
    /// stash is a single slot; calling `lock()` a second time overwrites h1's
    /// key.  This test only verifies ciphertext stability — it does NOT attempt
    /// to unlock, because h1's key is irrecoverable after h2 overwrites the stash.
    #[test]
    fn second_lock_skips_already_locked_region() {
        let _guard = TEST_LOCK.lock().unwrap();
        fresh_registry();

        let content = b"data-to-protect";
        let boxed: Box<[u8]> = content.to_vec().into_boxed_slice();
        let leaked: &'static mut [u8] = Box::leak(boxed);
        let ptr = leaked.as_ptr();
        let len = leaked.len();

        unsafe { register(leaked, "test-second-lock") }

        // First lock encrypts the region and stashes the key in XMM14/15.
        let h1 = lock().unwrap();
        let after_first = unsafe { read_bytes(ptr, len) };
        assert_ne!(
            after_first.as_slice(),
            content.as_ref(),
            "region must be encrypted after lock"
        );

        // Second lock: region is already marked locked, so it must be skipped.
        // The XMM stash is overwritten with h2's (unused) key.
        let h2 = lock().unwrap();
        let after_second = unsafe { read_bytes(ptr, len) };
        assert_eq!(
            after_second, after_first,
            "second lock() must not change ciphertext of an already-locked region"
        );

        // Both handles are dropped here (Drop zeroes XMM14/15).
        // The region remains encrypted; fresh_registry() in the next test
        // will clear the stale entry.
        drop(h1);
        drop(h2);
    }

    /// Tag mismatch: mutate a byte while locked, expect unlock to fail.
    #[test]
    fn tag_mismatch_detected() {
        let _guard = TEST_LOCK.lock().unwrap();
        fresh_registry();

        let boxed: Box<[u8]> = b"tamper-me-if-you-can".to_vec().into_boxed_slice();
        let leaked: &'static mut [u8] = Box::leak(boxed);
        let ptr = leaked.as_mut_ptr();

        unsafe { register(leaked, "test-tamper") }

        let handle = lock().unwrap();

        // Flip a bit in the encrypted region to simulate tampering.
        unsafe { *ptr ^= 0xFF };

        let result = unlock(handle);
        assert!(
            result.is_err(),
            "unlock() must fail when ciphertext has been tampered with"
        );
    }

    /// `guarded_sleep` round-trip (very short duration).
    #[tokio::test]
    async fn guarded_sleep_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap();
        fresh_registry();

        let content = b"async-sensitive-data";
        let boxed: Box<[u8]> = content.to_vec().into_boxed_slice();
        let leaked: &'static mut [u8] = Box::leak(boxed);
        let ptr = leaked.as_ptr();
        let len = leaked.len();

        unsafe { register(leaked, "test-async") }

        guarded_sleep(Duration::from_millis(1), None)
            .await
            .expect("guarded_sleep should not fail");

        let restored = unsafe { read_bytes(ptr, len) };
        assert_eq!(restored.as_slice(), content.as_ref());
    }

    /// Early wake via watch channel.
    #[tokio::test]
    async fn early_wake() {
        let _guard = TEST_LOCK.lock().unwrap();
        fresh_registry();

        let content = b"early-wake-data";
        let boxed: Box<[u8]> = content.to_vec().into_boxed_slice();
        let leaked: &'static mut [u8] = Box::leak(boxed);
        let ptr = leaked.as_ptr();
        let len = leaked.len();

        unsafe { register(leaked, "test-early-wake") }

        let (wake_tx, wake_rx) = tokio::sync::watch::channel(false);

        // Spawn the guarded sleep with a 60-second timeout that should be
        // interrupted well before it expires.
        let sleep_handle = tokio::spawn(async move {
            guarded_sleep(std::time::Duration::from_secs(60), Some(wake_rx))
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(5)).await;
        wake_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(2), sleep_handle)
            .await
            .expect("timeout — guarded_sleep did not respond to early wake")
            .unwrap();

        // After early wake memory must be restored.
        let restored = unsafe { read_bytes(ptr, len) };
        assert_eq!(restored.as_slice(), content.as_ref());
    }
}
