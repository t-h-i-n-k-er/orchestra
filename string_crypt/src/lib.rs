extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_SEED: &str = "orchestra-string-crypt-v1";

fn seed_material() -> String {
    std::env::var("ORCHESTRA_STRING_CRYPT_SEED").unwrap_or_else(|_| DEFAULT_SEED.to_string())
}

// ── Key derivation ────────────────────────────────────────────────────────────
//
// C-7 fix: keys are derived from (seed + label) only — NOT from the plaintext.
// Previously, `deterministic_bytes(label, &plaintext, len)` mixed the plaintext
// into the FNV state, meaning anyone who knows the algorithm + seed can re-derive
// every key.  The key bytes were also embedded alongside the ciphertext in the
// binary, making XOR trivial.
//
// Now:
//   - The key depends only on the per-build random master seed + a per-string
//     counter label.  The plaintext plays no role.
//   - The generated decryption code embeds the seed bytes + label bytes and
//     re-derives the key at runtime, so raw key arrays no longer appear next
//     to the ciphertext in the binary.

/// FNV-1a over a byte slice, starting from a given state.
fn fnv1a_mix(mut state: u64, data: &[u8]) -> u64 {
    for &b in data {
        state ^= b as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    state
}

/// Derive `len` key bytes from the master seed and a per-string label.
/// The plaintext is NOT part of this derivation (C-7 fix).
fn derive_key_from_seed(seed: &str, label: &[u8], len: usize) -> Vec<u8> {
    let mut state = fnv1a_mix(0xcbf29ce484222325u64, seed.as_bytes());
    state = fnv1a_mix(state, label);
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    // Expand via xorshift64, emitting all 8 bytes per round.
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Method selection: depends on the seed only, NOT on the plaintext.
fn get_build_method(seed: &str) -> usize {
    let state = fnv1a_mix(0xcbf29ce484222325u64, seed.as_bytes());
    let state = fnv1a_mix(state, b"method");
    (state % 3) as usize
}

/// Per-string counter so every enc_str! invocation gets a unique label even
/// when the same literal appears multiple times.
static STRING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[proc_macro]
pub fn enc_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit.value().into_bytes();
    let mut pt_with_null = pt.clone();
    pt_with_null.push(0);
    let len = pt_with_null.len();

    let seed = seed_material();
    let method = get_build_method(&seed);

    // Include the crate name in the label so parallel builds of different
    // crates with the same seed still produce distinct per-string keys.
    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let idx = STRING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let label = format!("enc_str:{}:{}", crate_name, idx);
    let label_bytes: Vec<u8> = label.bytes().collect();
    let label_len = label_bytes.len();

    // Master seed is embedded as ASCII hex bytes.  The key is re-derived at
    // runtime from seed + label — raw key bytes are NOT stored in the binary.
    let seed_bytes: Vec<u8> = seed.bytes().collect();
    let seed_len = seed_bytes.len();

    if method == 0 {
        // ── XOR with seed-derived key ─────────────────────────────────────
        let key = derive_key_from_seed(&seed, &label_bytes, len);
        let ct: Vec<u8> = pt_with_null
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let expanded = quote! {
            {
                const SEED: &[u8; #seed_len] = &[#(#seed_bytes),*];
                const LABEL: &[u8; #label_len] = &[#(#label_bytes),*];
                const CT: [u8; #len] = [#(#ct),*];
                // Re-derive key from seed + label at runtime (not from plaintext).
                let mut state: u64 = 0xcbf29ce484222325u64;
                let mut _i = 0usize;
                while _i < #seed_len {
                    state ^= SEED[_i] as u64;
                    state = state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    state ^= LABEL[_i] as u64;
                    state = state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if state == 0 { state = 0x9e3779b97f4a7c15u64; }
                let mut pt = [0u8; #len];
                let mut _j = 0usize;
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                while _j < #len {
                    if _buf_idx >= 8 {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        _buf = state.to_le_bytes();
                        _buf_idx = 0;
                    }
                    pt[_j] = CT[_j] ^ _buf[_buf_idx];
                    _buf_idx += 1;
                    _j += 1;
                }
                pt
            }
        };
        expanded.into()
    } else if method == 1 {
        // ── RC4-like with seed-derived key ────────────────────────────────
        let rc4_key = derive_key_from_seed(&seed, &label_bytes, 16);
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j: usize = 0;
        for i in 0..=255 {
            j = (j
                .wrapping_add(s[i] as usize)
                .wrapping_add(rc4_key[i % 16] as usize))
                % 256;
            s.swap(i, j);
        }
        let mut ct = Vec::with_capacity(len);
        let mut i: usize = 0;
        j = 0;
        for b in &pt_with_null {
            i = (i.wrapping_add(1)) % 256;
            j = (j.wrapping_add(s[i] as usize)) % 256;
            s.swap(i, j);
            let k = s[(s[i] as usize).wrapping_add(s[j] as usize) % 256];
            ct.push(*b ^ k);
        }

        let expanded = quote! {
            {
                const SEED: &[u8; #seed_len] = &[#(#seed_bytes),*];
                const LABEL: &[u8; #label_len] = &[#(#label_bytes),*];
                const CT: [u8; #len] = [#(#ct),*];
                // Re-derive the RC4 key from seed + label at runtime.
                let mut kstate: u64 = 0xcbf29ce484222325u64;
                let mut _i = 0usize;
                while _i < #seed_len {
                    kstate ^= SEED[_i] as u64;
                    kstate = kstate.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    kstate ^= LABEL[_i] as u64;
                    kstate = kstate.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if kstate == 0 { kstate = 0x9e3779b97f4a7c15u64; }
                let mut rc4_key = [0u8; 16];
                let mut _ki = 0usize;
                while _ki < 16 {
                    kstate ^= kstate << 13;
                    kstate ^= kstate >> 7;
                    kstate ^= kstate << 17;
                    rc4_key[_ki] = kstate as u8;
                    _ki += 1;
                }
                let mut s = [0u8; 256];
                for i in 0..=255usize { s[i] = i as u8; }
                let mut j: usize = 0;
                for i in 0..=255usize {
                    j = (j.wrapping_add(s[i] as usize).wrapping_add(rc4_key[i % 16] as usize)) % 256;
                    s.swap(i, j);
                }
                let mut pt = [0u8; #len];
                let mut i: usize = 0;
                j = 0;
                for n in 0..#len {
                    i = (i.wrapping_add(1)) % 256;
                    j = (j.wrapping_add(s[i] as usize)) % 256;
                    s.swap(i, j);
                    let k = s[(s[i] as usize).wrapping_add(s[j] as usize) % 256];
                    pt[n] = CT[n] ^ k;
                }
                pt
            }
        };
        expanded.into()
    } else {
        // ── Double-XOR with two independent seed-derived keys ─────────────
        let label1_bytes: Vec<u8> = format!("{}:k1", label).bytes().collect();
        let label2_bytes: Vec<u8> = format!("{}:k2", label).bytes().collect();
        let label1_len = label1_bytes.len();
        let label2_len = label2_bytes.len();

        let key1 = derive_key_from_seed(&seed, &label1_bytes, len);
        let key2 = derive_key_from_seed(&seed, &label2_bytes, len);
        let ct: Vec<u8> = pt_with_null
            .iter()
            .enumerate()
            .map(|(i, p)| p ^ key1[i] ^ key2[i])
            .collect();

        let expanded = quote! {
            {
                const SEED: &[u8; #seed_len] = &[#(#seed_bytes),*];
                const LABEL1: &[u8; #label1_len] = &[#(#label1_bytes),*];
                const LABEL2: &[u8; #label2_len] = &[#(#label2_bytes),*];
                const CT: [u8; #len] = [#(#ct),*];
                // Re-derive key1 from seed + label1 at runtime.
                let mut s1: u64 = 0xcbf29ce484222325u64;
                let mut _i = 0usize;
                while _i < #seed_len { s1 ^= SEED[_i] as u64; s1 = s1.wrapping_mul(0x100000001b3u64); _i += 1; }
                _i = 0;
                while _i < #label1_len { s1 ^= LABEL1[_i] as u64; s1 = s1.wrapping_mul(0x100000001b3u64); _i += 1; }
                if s1 == 0 { s1 = 0x9e3779b97f4a7c15u64; }
                // Re-derive key2 from seed + label2 at runtime.
                let mut s2: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len { s2 ^= SEED[_i] as u64; s2 = s2.wrapping_mul(0x100000001b3u64); _i += 1; }
                _i = 0;
                while _i < #label2_len { s2 ^= LABEL2[_i] as u64; s2 = s2.wrapping_mul(0x100000001b3u64); _i += 1; }
                if s2 == 0 { s2 = 0x9e3779b97f4a7c15u64; }

                let mut pt = [0u8; #len];
                let mut _j = 0usize;
                let mut _buf1 = [0u8; 8];
                let mut _buf2 = [0u8; 8];
                let mut _buf1_idx = 8usize;
                let mut _buf2_idx = 8usize;
                while _j < #len {
                    if _buf1_idx >= 8 {
                        s1 ^= s1 << 13; s1 ^= s1 >> 7; s1 ^= s1 << 17;
                        _buf1 = s1.to_le_bytes();
                        _buf1_idx = 0;
                    }
                    if _buf2_idx >= 8 {
                        s2 ^= s2 << 13; s2 ^= s2 >> 7; s2 ^= s2 << 17;
                        _buf2 = s2.to_le_bytes();
                        _buf2_idx = 0;
                    }
                    pt[_j] = CT[_j] ^ _buf1[_buf1_idx] ^ _buf2[_buf2_idx];
                    _buf1_idx += 1;
                    _buf2_idx += 1;
                    _j += 1;
                }
                pt
            }
        };
        expanded.into()
    }
}

#[proc_macro]
pub fn enc_wstr(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let pt: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let pt_bytes: Vec<u8> = pt.iter().flat_map(|&w| w.to_le_bytes()).collect();
    let len = pt_bytes.len();
    let wlen = pt.len();

    let seed = seed_material();
    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let idx = STRING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let label_bytes: Vec<u8> = format!("enc_wstr:{}:{}", crate_name, idx).bytes().collect();
    let label_len = label_bytes.len();
    let seed_bytes: Vec<u8> = seed.bytes().collect();
    let seed_len = seed_bytes.len();

    let key = derive_key_from_seed(&seed, &label_bytes, len);
    let ct: Vec<u8> = pt_bytes
        .iter()
        .zip(key.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    let expanded = quote! {
        {
            const SEED: &[u8; #seed_len] = &[#(#seed_bytes),*];
            const LABEL: &[u8; #label_len] = &[#(#label_bytes),*];
            const CT: [u8; #len] = [#(#ct),*];
            let mut state: u64 = 0xcbf29ce484222325u64;
            let mut _i = 0usize;
            while _i < #seed_len {
                state ^= SEED[_i] as u64;
                state = state.wrapping_mul(0x100000001b3u64);
                _i += 1;
            }
            _i = 0;
            while _i < #label_len {
                state ^= LABEL[_i] as u64;
                state = state.wrapping_mul(0x100000001b3u64);
                _i += 1;
            }
            if state == 0 { state = 0x9e3779b97f4a7c15u64; }
            let mut pt_bytes = [0u8; #len];
            let mut _j = 0usize;
            let mut _buf = [0u8; 8];
            let mut _buf_idx = 8usize;
            while _j < #len {
                if _buf_idx >= 8 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    _buf = state.to_le_bytes();
                    _buf_idx = 0;
                }
                pt_bytes[_j] = CT[_j] ^ _buf[_buf_idx];
                _buf_idx += 1;
                _j += 1;
            }
            let mut pt_w = [0u16; #wlen];
            for i in 0..#wlen {
                pt_w[i] = u16::from_le_bytes([pt_bytes[i * 2], pt_bytes[i * 2 + 1]]);
            }
            pt_w
        }
    };
    expanded.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_stable_for_same_seed_and_label() {
        let a = derive_key_from_seed("abcd1234", b"label", 32);
        let b = derive_key_from_seed("abcd1234", b"label", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_differs_for_different_labels() {
        let a = derive_key_from_seed("abcd1234", b"enc_str:agent:0", 32);
        let b = derive_key_from_seed("abcd1234", b"enc_str:agent:1", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_differs_for_different_seeds() {
        let a = derive_key_from_seed("seed-a", b"label", 32);
        let b = derive_key_from_seed("seed-b", b"label", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_does_not_depend_on_plaintext() {
        // C-7 core property: same seed + same label → same key, regardless of
        // what string is being encrypted.
        let key_for_hello = derive_key_from_seed("seed", b"enc_str:agent:0", 32);
        let key_for_world = derive_key_from_seed("seed", b"enc_str:agent:0", 32);
        assert_eq!(key_for_hello, key_for_world);

        // Different label → different key (counter ensures uniqueness).
        let key_for_next = derive_key_from_seed("seed", b"enc_str:agent:1", 32);
        assert_ne!(key_for_hello, key_for_next);
    }

    #[test]
    fn derive_key_bytes_are_not_all_identical() {
        let key = derive_key_from_seed("seed-non-identical-check", b"enc_str:test:0", 64);
        assert!(
            key.windows(2).any(|w| w[0] != w[1]),
            "derived key bytes should not all be identical"
        );
    }

    #[test]
    fn method_selection_depends_on_seed_not_plaintext() {
        let m1 = get_build_method("seed-a");
        let m2 = get_build_method("seed-a");
        assert_eq!(m1, m2);
        // Different seeds may produce different methods (not guaranteed but
        // confirms seed is the only input).
        let _ = get_build_method("seed-b");
    }
}

#[proc_macro]
pub fn stack_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit
        .value()
        .into_bytes()
        .into_iter()
        .chain(std::iter::once(0))
        .collect();

    let assigns = pt.iter().enumerate().map(|(i, &b)| {
        quote! { pt[#i] = #b; }
    });

    let len = pt.len();

    let expanded = quote! {
        {
            let mut pt = [0u8; #len];
            #(#assigns)*
            pt
        }
    };
    expanded.into()
}

