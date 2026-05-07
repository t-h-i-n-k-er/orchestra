/// RAII wrapper around an NT kernel handle (`HANDLE`).
///
/// Automatically calls `NtClose` via indirect syscall when dropped,
/// ensuring handles are never leaked even across early returns or
/// `?` error propagation paths.
///
/// # Safety
///
/// The inner value is a raw `usize` representing a kernel handle.
/// Constructing an `NtHandle` from an invalid value will produce a
/// no-op drop (the `!is_valid()` check prevents closing an invalid
/// handle).  The caller is responsible for ensuring the handle was
/// obtained from a legitimate NT API call.
///
/// # Example
///
/// ```ignore
/// let raw = some_nt_api_that_returns_a_handle();
/// let handle = NtHandle::new(raw);
/// // use handle.raw() for subsequent API calls
/// do_something_with(handle.raw());
/// // NtClose called automatically when `handle` goes out of scope
/// ```
#[cfg(windows)]
pub struct NtHandle(pub usize);

#[cfg(windows)]
impl NtHandle {
    /// Wrap a raw handle value.
    ///
    /// Does **not** take ownership of the underlying kernel object —
    /// it merely records the value so `Drop` can close it later.
    /// Passing `0` (the conventional null-handle value) is safe and
    /// will produce an `is_valid() == false` wrapper whose drop is a
    /// no-op.
    #[inline]
    pub fn new(handle: usize) -> Self {
        Self(handle)
    }

    /// Return the raw handle value for passing to NT API calls.
    #[inline]
    pub fn raw(&self) -> usize {
        self.0
    }

    /// Returns `true` if the handle is non-zero.
    ///
    /// A zero handle is the NT null-handle sentinel; closing it is
    /// undefined behaviour, so the `Drop` impl skips `NtClose` for
    /// invalid handles.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

#[cfg(windows)]
impl Drop for NtHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            let status =
                unsafe { crate::syscalls::syscall_NtClose(self.0 as u64) };
            if status != 0 {
                log::warn!(
                    "NtHandle::drop: NtClose({:#x}) returned status {:#x}",
                    self.0,
                    status
                );
            }
        }
    }
}
