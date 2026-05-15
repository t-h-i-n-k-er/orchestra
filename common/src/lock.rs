//! Poison-resilient lock helpers.
//!
//! The standard library's [`Mutex::lock`] and [`RwLock::read`] / [`RwLock::write`]
//! return a [`LockResult`] that propagates **poison** when a thread panicked while
//! holding the lock.  The agent uses dozens of global `Mutex` / `RwLock` instances
//! across 15+ files, and calling `.unwrap()` on the lock result means that a
//! single panic anywhere cascades into an unrecoverable agent crash.
//!
//! This module provides two small extension traits — [`MutexExt`] and
//! [`RwLockExt`] — that recover from poison by calling
//! `.unwrap_or_else(|e| e.into_inner())`, i.e. they always yield the inner
//! guard even if a previous holder panicked.  This is safe for the agent's
//! use case because the data protected by the lock is always recoverable
//! (e.g. a cache, a config struct, a buffer) and the alternative — an
//! irrecoverable panic — is strictly worse.
//!
//! # Usage
//!
//! ```ignore
//! use common::lock::MutexExt;
//!
//! let mut guard = MY_GLOBAL_MUTEX.lock_recover();
//! // … instead of MY_GLOBAL_MUTEX.lock().unwrap()
//! ```
//!
//! The traits are implemented for all `Mutex<T>` and `RwLock<T>` regardless
//! of the inner type.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ── Mutex helper ──────────────────────────────────────────────────────────

/// Extension trait that adds poison-recovering lock acquisition to [`Mutex`].
pub trait MutexExt<T> {
    /// Acquire the lock, recovering from poison.
    ///
    /// If a previous holder panicked while holding the lock, the lock is
    /// considered *poisoned*.  This method recovers the guard anyway by
    /// extracting the inner value from the [`PoisonError`].
    ///
    /// This is equivalent to `.lock().unwrap_or_else(|e| e.into_inner())`
    /// but more readable and intent-signalling.
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> MutexExt<T> for Mutex<T> {
    #[inline]
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ── RwLock helpers ────────────────────────────────────────────────────────

/// Extension trait that adds poison-recovering read/write acquisition to [`RwLock`].
pub trait RwLockExt<T> {
    /// Acquire a read lock, recovering from poison.
    ///
    /// Equivalent to `.read().unwrap_or_else(|e| e.into_inner())`.
    fn read_recover(&self) -> RwLockReadGuard<'_, T>;

    /// Acquire a write lock, recovering from poison.
    ///
    /// Equivalent to `.write().unwrap_or_else(|e| e.into_inner())`.
    fn write_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    #[inline]
    fn read_recover(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }

    #[inline]
    fn write_recover(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}

// ── Free-function shorthand for one-shot lock+access ──────────────────────

/// Acquire a `Mutex` lock with poison recovery, useful for one-liner access.
///
/// ```ignore
/// *SOME_STATIC.lock_recover() = new_value;
/// // equivalent to:
/// recover_lock(&SOME_STATIC);
/// ```
///
/// This function exists mainly so call-sites that do `X.lock().unwrap()`
/// can be replaced with a single `recover_lock(&X)` expression when the
/// result is immediately destructured or method-called.
#[inline]
pub fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock_recover()
}

/// Acquire an `RwLock` read lock with poison recovery.
#[inline]
pub fn recover_read<T>(rwlock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    rwlock.read_recover()
}

/// Acquire an `RwLock` write lock with poison recovery.
#[inline]
pub fn recover_write<T>(rwlock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    rwlock.write_recover()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn mutex_recover_from_poison() {
        let m = Arc::new(Mutex::new(42usize));
        let m2 = m.clone();

        // Poison the mutex by panicking while holding it.
        let h = thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("intentional poison");
        });
        let _ = h.join();

        // Standard .lock().unwrap() would panic here.
        // lock_recover() should succeed.
        let guard = m.lock_recover();
        assert_eq!(*guard, 42);
    }

    #[test]
    fn rwlock_read_recover_from_poison() {
        let rw = Arc::new(RwLock::new(100usize));
        let rw2 = rw.clone();

        let h = thread::spawn(move || {
            let _guard = rw2.write().unwrap();
            panic!("intentional poison");
        });
        let _ = h.join();

        let guard = rw.read_recover();
        assert_eq!(*guard, 100);
    }

    #[test]
    fn rwlock_write_recover_from_poison() {
        let rw = Arc::new(RwLock::new(String::from("hello")));
        let rw2 = rw.clone();

        let h = thread::spawn(move || {
            let _guard = rw2.write().unwrap();
            panic!("intentional poison");
        });
        let _ = h.join();

        let mut guard = rw.write_recover();
        guard.push_str(" world");
        assert_eq!(&*guard, "hello world");
    }
}
