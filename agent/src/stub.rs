#![allow(dead_code)]

#[cfg(windows)]
use winapi::um::memoryapi::VirtualProtect;
#[cfg(windows)]
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

/// In-memory .data section decryptor using ChaCha20.
/// The key is derived at compile time; there is no hardcoded seed string.
/// # Safety
///
/// Performs raw pointer arithmetic and inline assembly on x86_64 Windows.
/// On other platforms this is a no-op and always safe.
#[link_section = ".text"]
pub unsafe fn decrypt_payload() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        use core::arch::asm;

        // gs:[0x60] is the PEB pointer on x86_64 Windows
        let peb: usize;
        asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));
        if peb == 0 {
            return;
        }

        // PEB layout (x86_64): +0x10 = ImageBaseAddress
        let image_base = *(peb as *const usize).add(2); // offset 0x10 = index 2 for usize
        if image_base == 0 {
            return;
        }

        let dos_magic = *(image_base as *const u16);
        if dos_magic != 0x5A4D {
            return;
        } // 'MZ'

        let e_lfanew = *((image_base + 0x3C) as *const u32) as usize;
        let nt_headers = image_base + e_lfanew;

        // Verify PE signature
        let pe_sig = *(nt_headers as *const u32);
        if pe_sig != 0x00004550 {
            return;
        } // 'PE\0\0'

        let num_sections = *((nt_headers + 0x06) as *const u16) as usize;
        let size_of_opt_header = *((nt_headers + 0x14) as *const u16) as usize;
        let section_headers_base = nt_headers + 0x18 + size_of_opt_header;

        // Key: derived from ORCHESTRA_KEY env var at build time (2.12)
        let key: [u8; 32] = build_key();
        // Nonce: derived from package metadata so it is non-zero (2.13)
        let nonce: [u8; 12] = build_nonce();

        for i in 0..num_sections {
            let section = section_headers_base + (i * 0x28);
            let name = core::slice::from_raw_parts(section as *const u8, 5);
            if name != b".data" {
                continue;
            }

            let virtual_addr = *((section + 0x0C) as *const u32) as usize;
            let virtual_size = *((section + 0x08) as *const u32) as usize;
            if virtual_size == 0 {
                break;
            }

            let section_ptr = (image_base + virtual_addr) as *mut u8;
            let mut old_protect: u32 = 0;
            VirtualProtect(
                section_ptr as _,
                virtual_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            // Apply ChaCha20 keystream in-place
            chacha20_xor(section_ptr, virtual_size, &key, &nonce);

            // Restore .data to PAGE_READWRITE so the loaded process can write
            // global variables at runtime; making it PAGE_EXECUTE_READ would
            // crash on the first write to a static (H-8).
            VirtualProtect(
                section_ptr as _,
                virtual_size,
                PAGE_READWRITE,
                &mut old_protect,
            );
            break;
        }
    }
}

/// Build the decryption key. Uses a compile-time env var ORCHESTRA_KEY if set
/// (must be 64 hex characters = 32 bytes).  Falls back to a deterministic
/// placeholder derived from package metadata so the crate still compiles in
/// development environments that do not set ORCHESTRA_KEY.
///
/// **Security note**: Production builds MUST set ORCHESTRA_KEY to a unique
/// 64-character hex string.  A build.rs warning is emitted when the variable
/// is absent.  The placeholder key has no security value and must never be
/// shipped in a production artifact.
#[inline(always)]
const fn build_key() -> [u8; 32] {
    // option_env! returns None at compile time if the variable is not set,
    // instead of aborting compilation.  This makes development builds possible
    // without the env var while still enforcing it for release (via build.rs).
    match option_env!("ORCHESTRA_KEY") {
        Some(hex) => parse_hex_key(hex),
        None => {
            // Derive a placeholder key from package metadata so each package
            // at least gets a distinct non-zero key even without the env var.
            let ver = env!("CARGO_PKG_VERSION").as_bytes();
            let name = env!("CARGO_PKG_NAME").as_bytes();
            let mut k = [0u8; 32];
            let mut i = 0usize;
            while i < 32 {
                let v = if i < ver.len() { ver[i] } else { 0xA5u8 };
                let n = if i < name.len() { name[i] } else { 0x5Au8 };
                k[i] = v ^ n ^ (i as u8).wrapping_mul(0x37).wrapping_add(0x1B);
                i += 1;
            }
            k
        }
    }
}

/// Decode a 64-character ASCII hex string into a 32-byte key at compile time.
#[inline(always)]
const fn parse_hex_key(hex: &str) -> [u8; 32] {
    let b = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_nibble(b[i * 2]);
        let lo = hex_nibble(b[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

#[inline(always)]
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Build a non-zero nonce derived from compile-time package metadata (2.13).
/// This gives each build a distinct nonce without requiring runtime entropy.
#[inline(always)]
const fn build_nonce() -> [u8; 12] {
    let ver = env!("CARGO_PKG_VERSION").as_bytes();
    let name = env!("CARGO_PKG_NAME").as_bytes();
    // Mix version and name bytes into a 12-byte nonce deterministically.
    let mut n = [0u8; 12];
    let mut i = 0usize;
    while i < 12 {
        let v = if i < ver.len() { ver[i] } else { 0x5A };
        let nm = if i < name.len() { name[i] } else { 0xA5 };
        n[i] = v ^ nm ^ (i as u8).wrapping_mul(0x1B).wrapping_add(0x37);
        i += 1;
    }
    n
}

/// Minimal ChaCha20 stream cipher applied in-place.
/// This is a self-contained implementation that does not depend on external crates.
unsafe fn chacha20_xor(data: *mut u8, len: usize, key: &[u8; 32], nonce: &[u8; 12]) {
    let mut state = chacha20_init(key, nonce, 0);
    let mut block = [0u32; 16];
    let mut keystream = [0u8; 64];
    let mut offset = 0usize;

    while offset < len {
        chacha20_block(&state, &mut block);
        // Serialise block to bytes (little-endian)
        for (i, word) in block.iter().enumerate() {
            let bytes = word.to_le_bytes();
            keystream[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        // Increment counter (word 12)
        state[12] = state[12].wrapping_add(1);

        let chunk = (len - offset).min(64);
        for (j, k) in keystream[..chunk].iter().enumerate() {
            *data.add(offset + j) ^= k;
        }
        offset += chunk;
    }
}

#[inline(always)]
fn chacha20_init(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574, // "expa nd 3 2-by te k"
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ]
}

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn chacha20_block(state: &[u32; 16], out: &mut [u32; 16]) {
    *out = *state;
    for _ in 0..10 {
        // Column rounds
        quarter_round(out, 0, 4, 8, 12);
        quarter_round(out, 1, 5, 9, 13);
        quarter_round(out, 2, 6, 10, 14);
        quarter_round(out, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(out, 0, 5, 10, 15);
        quarter_round(out, 1, 6, 11, 12);
        quarter_round(out, 2, 7, 8, 13);
        quarter_round(out, 3, 4, 9, 14);
    }
    for i in 0..16 {
        out[i] = out[i].wrapping_add(state[i]);
    }
}
