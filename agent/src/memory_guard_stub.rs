//! Placeholder stub for builds where the `memory-guard` feature is disabled.
//!
//! This module intentionally provides **no-op implementations** of the same
//! public API exposed by `memory_guard.rs` so call sites can remain unchanged
//! regardless of feature selection.
//!
//! ## What the full implementation provides
//!
//! With `memory-guard` enabled, the real module adds guarded sleep and memory
//! protection helpers that:
//! - register sensitive regions,
//! - encrypt those regions during idle/sleep windows,
//! - decrypt them on wake,
//! - and manage the session key lifecycle for protected regions.
//!
//! ## Upgrade path
//!
//! Rebuild the agent with the `memory-guard` feature to switch from these
//! stubs to the active implementation in `memory_guard.rs`:
//!
//! `cargo build -p agent --features memory-guard`

#![cfg(not(feature = "memory-guard"))]

use anyhow::Result;
use std::sync::Once;

// One-time notice emitted when the stub path is used.
static STUB_NOTICE_ONCE: Once = Once::new();

#[inline(always)]
fn log_stub_inactive_once() {
    STUB_NOTICE_ONCE.call_once(|| {
        log::warn!(
            "memory-guard: feature disabled; using memory_guard_stub no-op implementation (runtime memory encryption is not active)"
        );
    });
}

/// Register a sensitive region.
///
/// In the full implementation, this records the region so it can be encrypted
/// during guarded sleep and restored on wake.
///
/// # Safety
///
/// No-op when `memory-guard` is disabled. The pointer is never dereferenced.
#[inline(always)]
pub unsafe fn register(_buf: &'static mut [u8], _label: &'static str) {
    log_stub_inactive_once();
}

/// Lock (encrypt) all registered regions.
///
/// In the full implementation, this encrypts each registered region and
/// stashes a key handle needed for a subsequent [`unlock`] call.
///
/// Stub behavior: no-op — returns a zero-size handle.
#[inline(always)]
pub fn lock() -> Result<KeyHandle> {
    log_stub_inactive_once();
    Ok(KeyHandle)
}

/// Unlock (decrypt) all registered regions.
///
/// In the full implementation, this restores plaintext for previously locked
/// regions using the provided key handle.
///
/// Stub behavior: no-op.
#[inline(always)]
pub fn unlock(_handle: KeyHandle) -> Result<()> {
    log_stub_inactive_once();
    Ok(())
}

/// Opaque handle returned by [`lock`].  Zero-size when the feature is off.
pub struct KeyHandle;

/// Guard memory for the current sleep window.
///
/// In the full implementation, this encrypts registered regions and stores the
/// lock handle thread-locally until [`unguard_memory`] is called.
///
/// Stub behavior: no-op.
#[inline(always)]
pub fn guard_memory() -> Result<()> {
    log_stub_inactive_once();
    Ok(())
}

/// Undo a prior [`guard_memory`] call.
///
/// In the full implementation, this retrieves the previously stashed lock
/// handle and decrypts all guarded regions.
///
/// Stub behavior: no-op.
#[inline(always)]
pub fn unguard_memory() -> Result<()> {
    log_stub_inactive_once();
    Ok(())
}

/// Sleep while memory guard would normally be active.
///
/// In the full implementation, this encrypts sensitive regions before sleep,
/// sleeps (or wakes early on a signal), then decrypts regions on wake.
///
/// Stub behavior: sleeps only; no memory encryption is performed.
#[inline(always)]
pub async fn guarded_sleep(
    duration: std::time::Duration,
    wake_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    log_stub_inactive_once();
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
    Ok(())
}

/// Register the active transport/session key for guard coverage.
///
/// In the full implementation, this key material is tracked as a protected
/// region so idle-time locking encrypts it in place.
///
/// Stub behavior: no-op when `memory-guard` is disabled.
#[inline(always)]
pub fn register_session_key(_session: &common::CryptoSession) {
    log_stub_inactive_once();
}
