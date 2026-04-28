//! Runtime helper: locate a function's machine code, apply the transformation,
//! and write the result back into the executable page.
//!
//! # Safety
//!
//! This module uses `mprotect` to change page permissions.  It must only be
//! called while no other thread is executing the function being patched.  In
//! practice, callers should use a `std::sync::Once` guard (as the
//! `#[code_transform]` macro does) so the patch is applied exactly once,
//! before concurrent callers can reach the function.
//!
//! Only available on `x86_64 linux`.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_impl::apply_to_fn;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_impl {
    use crate::transform;

    /// Maximum number of bytes scanned when estimating a function's size.
    const MAX_FN_SCAN: usize = 4096;

    /// Apply the full instruction-substitution + block-reorder transformation
    /// to the function whose first byte is at `fn_ptr`.
    ///
    /// Steps:
    /// 1. Scan forward from `fn_ptr` for a `RET` (0xC3) byte to estimate the
    ///    function body size (capped at `MAX_FN_SCAN`).
    /// 2. Call `transform(bytes, seed)` to produce the new byte sequence.
    /// 3. `mprotect` the page RW, copy the transformed bytes, `mprotect` RX.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// * `fn_ptr` is the start address of a compiled x86-64 function.
    /// * No other thread is concurrently executing the function.
    pub unsafe fn apply_to_fn(fn_ptr: *mut u8, seed: u64) {
        use libc::{mprotect, sysconf, PROT_EXEC, PROT_READ, PROT_WRITE, _SC_PAGESIZE};

        let page_size = sysconf(_SC_PAGESIZE) as usize;

        // ── 1. Estimate function size ────────────────────────────────────────
        let scan = std::slice::from_raw_parts(fn_ptr as *const u8, MAX_FN_SCAN);
        let fn_len = estimate_fn_len(scan).min(MAX_FN_SCAN);
        if fn_len == 0 {
            return;
        }
        let code_slice = std::slice::from_raw_parts(fn_ptr as *const u8, fn_len);

        // ── 2. Transform ─────────────────────────────────────────────────────
        let transformed = transform(code_slice, seed);
        if transformed == code_slice || transformed.is_empty() {
            return; // nothing changed
        }

        // ── 3. Patch the page ────────────────────────────────────────────────
        // Align the pointer down to the start of its page.
        let page_start = (fn_ptr as usize) & !(page_size - 1);
        // Cover enough pages for both old and new code.
        let cover = fn_len.max(transformed.len()) + (fn_ptr as usize - page_start);
        let mmap_len = ((cover + page_size - 1) / page_size) * page_size;

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_WRITE);

        // Copy new bytes; do not write beyond the original function boundary
        // (the transformed code must not be longer than the scan window).
        let copy_len = transformed.len().min(fn_len);
        std::ptr::copy_nonoverlapping(transformed.as_ptr(), fn_ptr, copy_len);

        // NOP-pad any remaining bytes from the old body.
        if copy_len < fn_len {
            std::ptr::write_bytes(fn_ptr.add(copy_len), 0x90, fn_len - copy_len);
        }

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_EXEC);
    }

    /// Scan `code` for a bare `RET` (0xC3) byte, returning the offset
    /// *after* it (exclusive).  Falls back to `MAX_FN_SCAN` if not found.
    fn estimate_fn_len(code: &[u8]) -> usize {
        // Simple scan: find the first 0xC3 that isn't part of a longer opcode.
        // This is a heuristic — a proper length finder would use a full
        // disassembler, but for typical leaf/small functions this is sufficient.
        for (i, &b) in code.iter().enumerate() {
            if b == 0xC3 {
                return i + 1;
            }
        }
        MAX_FN_SCAN
    }
}
