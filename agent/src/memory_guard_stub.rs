//! No-op stubs for the `memory-guard` feature when it is disabled.
//!
//! All public symbols are present so callers can reference them unconditionally;
//! everything compiles to nothing when `memory-guard` is absent.

#![cfg(not(feature = "memory-guard"))]

use anyhow::Result;

/// Register a sensitive region.
///
/// # Safety
///
/// No-op when `memory-guard` is disabled. The pointer is never dereferenced.
#[inline(always)]
pub unsafe fn register(_buf: &'static mut [u8], _label: &'static str) {}

/// Lock (encrypt) all regions.  No-op — returns a zero-size handle.
#[inline(always)]
pub fn lock() -> Result<KeyHandle> {
    Ok(KeyHandle)
}

/// Unlock (decrypt) all regions.  No-op.
#[inline(always)]
pub fn unlock(_handle: KeyHandle) -> Result<()> {
    Ok(())
}

/// Opaque handle returned by [`lock`].  Zero-size when the feature is off.
pub struct KeyHandle;

/// Sleep without memory protection.  Delegates directly to `tokio::time::sleep`.
#[inline(always)]
pub async fn guarded_sleep(
    duration: std::time::Duration,
    wake_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
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

/// Register the session key for memory protection.  No-op when `memory-guard` is disabled.
#[inline(always)]
pub fn register_session_key(_session: &common::CryptoSession) {}
