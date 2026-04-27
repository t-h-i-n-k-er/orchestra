#![allow(dead_code)]

#[cfg(windows)]
use winapi::um::memoryapi::VirtualProtect;
#[cfg(windows)]
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

/// In-memory .data section decryptor using ChaCha20-Poly1305.
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
        asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
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
            let raw_size = *((section + 0x10) as *const u32) as usize;
            if virtual_size == 0 {
                break;
            }

            // M-41 wire format in .data:
            //   [ciphertext: virtual_size bytes][tag: 16 bytes]
            // Ensure the appended tag fits inside section-backed data.
            let tagged_span = match virtual_size.checked_add(16) {
                Some(v) => v,
                None => return,
            };
            if tagged_span > raw_size {
                return;
            }

            let section_ptr = (image_base + virtual_addr) as *mut u8;
            let mut old_protect: u32 = 0;
            VirtualProtect(
                section_ptr as _,
                tagged_span,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            let ciphertext = core::slice::from_raw_parts(section_ptr as *const u8, virtual_size);
            let mut supplied_tag = [0u8; 16];
            core::ptr::copy_nonoverlapping(
                section_ptr.add(virtual_size) as *const u8,
                supplied_tag.as_mut_ptr(),
                16,
            );

            // Bind nonce as AAD and verify ciphertext integrity before decrypting.
            let expected_tag = chacha20poly1305_tag(&key, &nonce, &nonce, ciphertext);
            if !ct_eq_16(&supplied_tag, &expected_tag) {
                // Fail-safe on tamper: wipe .data and stop.
                core::ptr::write_bytes(section_ptr, 0, virtual_size);
                VirtualProtect(
                    section_ptr as _,
                    tagged_span,
                    PAGE_READWRITE,
                    &mut old_protect,
                );
                return;
            }

            // MAC verified: decrypt ciphertext in-place with ChaCha20 counter = 1
            // (counter 0 is reserved for Poly1305 one-time key derivation).
            chacha20_xor(section_ptr, virtual_size, &key, &nonce, 1);

            // Restore .data to PAGE_READWRITE so the loaded process can write
            // global variables at runtime; making it PAGE_EXECUTE_READ would
            // crash on the first write to a static (H-8).
            VirtualProtect(
                section_ptr as _,
                tagged_span,
                PAGE_READWRITE,
                &mut old_protect,
            );
            break;
        }
    }
}

/// Build the decryption key from the ORCHESTRA_KEY compile-time env var.
///
/// ORCHESTRA_KEY is always set by build.rs — either by the operator or
/// auto-generated as a per-build random 32-byte value.  The CARGO metadata
/// fallback has been removed because those values are publicly known and
/// produce deterministic (insecure) keys (C-6 fix).
#[inline(always)]
const fn build_key() -> [u8; 32] {
    match option_env!("ORCHESTRA_KEY") {
        Some(hex) => parse_hex_key(hex),
        None => {
            // Unreachable in practice — build.rs always sets ORCHESTRA_KEY.
            // All-zero key will fail to decrypt rather than silently using a
            // guessable placeholder derived from public CARGO metadata.
            [0u8; 32]
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

/// Decode a 24-character ASCII hex string into a 12-byte nonce at compile time.
#[inline(always)]
const fn parse_hex_nonce(hex: &str) -> [u8; 12] {
    let b = hex.as_bytes();
    let mut out = [0u8; 12];
    let mut i = 0usize;
    while i < 12 {
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

/// Build the decryption nonce from the ORCHESTRA_NONCE compile-time env var.
///
/// ORCHESTRA_NONCE is always set by build.rs — auto-generated as a per-build
/// random 12-byte value.  This ensures every build uses a unique nonce even
/// when ORCHESTRA_KEY is pinned, preventing ChaCha20 nonce reuse (C-6 fix).
///
/// Previously derived from CARGO_PKG_VERSION + CARGO_PKG_NAME, which are
/// public and fixed — same key + same nonce = same keystream every build.
#[inline(always)]
const fn build_nonce() -> [u8; 12] {
    match option_env!("ORCHESTRA_NONCE") {
        Some(hex) => parse_hex_nonce(hex),
        None => {
            // Unreachable in practice — build.rs always sets ORCHESTRA_NONCE.
            // All-zero nonce will fail to decrypt (fail-safe over guessable).
            [0u8; 12]
        }
    }
}

#[inline(always)]
fn load_u32_le(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

struct Poly1305 {
    r: [u64; 5],
    r5: [u64; 4],
    h: [u64; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let t0 = load_u32_le(&key[0..4]) as u64;
        let t1 = load_u32_le(&key[4..8]) as u64;
        let t2 = load_u32_le(&key[8..12]) as u64;
        let t3 = load_u32_le(&key[12..16]) as u64;

        let r0 = t0 & 0x3ffffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
        let r4 = (t3 >> 8) & 0x00fffff;

        Self {
            r: [r0, r1, r2, r3, r4],
            r5: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
            h: [0; 5],
            pad: [
                load_u32_le(&key[16..20]),
                load_u32_le(&key[20..24]),
                load_u32_le(&key[24..28]),
                load_u32_le(&key[28..32]),
            ],
        }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            self.process_block(&block);
        }
    }

    fn process_block(&mut self, block: &[u8; 17]) {
        let t0 = load_u32_le(&block[0..4]) as u64;
        let t1 = load_u32_le(&block[3..7]) as u64;
        let t2 = load_u32_le(&block[6..10]) as u64;
        let t3 = load_u32_le(&block[9..13]) as u64;
        let t4 = load_u32_le(&block[12..16]) as u64;

        let mut h0 = self.h[0] + (t0 & 0x3ffffff);
        let mut h1 = self.h[1] + ((t1 >> 2) & 0x3ffffff);
        let mut h2 = self.h[2] + ((t2 >> 4) & 0x3ffffff);
        let mut h3 = self.h[3] + ((t3 >> 6) & 0x3ffffff);
        let mut h4 = self.h[4] + ((t4 >> 8) | ((block[16] as u64) << 24));

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];
        let s1 = self.r5[0];
        let s2 = self.r5[1];
        let s3 = self.r5[2];
        let s4 = self.r5[3];

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ffffff;
        d1 += c;
        c = d1 >> 26;
        h1 = d1 & 0x3ffffff;
        d2 += c;
        c = d2 >> 26;
        h2 = d2 & 0x3ffffff;
        d3 += c;
        c = d3 >> 26;
        h3 = d3 & 0x3ffffff;
        d4 += c;
        c = d4 >> 26;
        h4 = d4 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        self.h = [h0, h1, h2, h3, h4];
    }

    fn finalize(self) -> [u8; 16] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let mut g4 = h4 + c;
        g4 = g4.wrapping_sub(1 << 26);

        let mask = (g4 >> 63).wrapping_sub(1);
        let nmask = !mask;
        h0 = (h0 & nmask) | (g0 & mask);
        h1 = (h1 & nmask) | (g1 & mask);
        h2 = (h2 & nmask) | (g2 & mask);
        h3 = (h3 & nmask) | (g3 & mask);
        h4 = (h4 & nmask) | (g4 & mask);

        let f0 = (h0 | (h1 << 26)).wrapping_add(self.pad[0] as u64);
        let mut f1 = ((h1 >> 6) | (h2 << 20)).wrapping_add(self.pad[1] as u64);
        f1 = f1.wrapping_add(f0 >> 32);
        let mut f2 = ((h2 >> 12) | (h3 << 14)).wrapping_add(self.pad[2] as u64);
        f2 = f2.wrapping_add(f1 >> 32);
        let mut f3 = ((h3 >> 18) | (h4 << 8)).wrapping_add(self.pad[3] as u64);
        f3 = f3.wrapping_add(f2 >> 32);

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        out
    }
}

#[inline(always)]
fn poly1305_tag(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(poly_key);
    let zero_pad = [0u8; 16];

    // RFC 8439 AEAD input: aad || pad16(aad) || ciphertext || pad16(ciphertext)
    // || aad_len(8) || ciphertext_len(8)
    poly.update(aad);
    let aad_rem = aad.len() % 16;
    if aad_rem != 0 {
        poly.update(&zero_pad[..16 - aad_rem]);
    }

    poly.update(ciphertext);
    let ct_rem = ciphertext.len() % 16;
    if ct_rem != 0 {
        poly.update(&zero_pad[..16 - ct_rem]);
    }

    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&lens);

    poly.finalize()
}

#[inline(always)]
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < 16 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

#[inline(always)]
fn chacha20_block_bytes(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let state = chacha20_init(key, nonce, counter);
    let mut block_words = [0u32; 16];
    chacha20_block(&state, &mut block_words);

    let mut out = [0u8; 64];
    for (i, word) in block_words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[inline(always)]
fn chacha20poly1305_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut poly_key = [0u8; 32];
    let block0 = chacha20_block_bytes(key, nonce, 0);
    poly_key.copy_from_slice(&block0[..32]);
    poly1305_tag(&poly_key, aad, ciphertext)
}

/// Minimal ChaCha20 stream cipher applied in-place.
/// This is a self-contained implementation that does not depend on external crates.
unsafe fn chacha20_xor(
    data: *mut u8,
    len: usize,
    key: &[u8; 32],
    nonce: &[u8; 12],
    initial_counter: u32,
) {
    let mut state = chacha20_init(key, nonce, initial_counter);
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
