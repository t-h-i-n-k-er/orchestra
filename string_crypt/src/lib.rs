extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

const DEFAULT_SEED: &str = "orchestra-string-crypt-v1";

fn seed_material() -> String {
    std::env::var("ORCHESTRA_STRING_CRYPT_SEED").unwrap_or_else(|_| DEFAULT_SEED.to_string())
}

fn deterministic_seed(label: &[u8], input: &[u8], seed: &str) -> u64 {
    // FNV-1a over explicit seed material and macro input. This is not a
    // cryptographic PRNG; it is only used to keep proc-macro expansion stable
    // across reproducible builds unless ORCHESTRA_STRING_CRYPT_SEED is changed.
    let mut hash = 0xcbf29ce484222325u64;
    for b in seed
        .as_bytes()
        .iter()
        .chain(label.iter())
        .chain(input.iter())
    {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 {
        0x9e3779b97f4a7c15
    } else {
        hash
    }
}

fn deterministic_bytes_with_seed(label: &[u8], input: &[u8], seed: &str, len: usize) -> Vec<u8> {
    let mut state = deterministic_seed(label, input, seed);
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

fn deterministic_bytes(label: &[u8], input: &[u8], len: usize) -> Vec<u8> {
    let seed = seed_material();
    deterministic_bytes_with_seed(label, input, &seed, len)
}

fn get_build_rotation(input: &[u8]) -> usize {
    let seed = seed_material();
    (deterministic_seed(b"method", input, &seed) % 3) as usize
}

#[proc_macro]
pub fn enc_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit.value().into_bytes();
    let mut pt_with_null = pt.clone();
    pt_with_null.push(0); // Null-terminate for C APIs
    let len = pt_with_null.len();

    let method = get_build_rotation(&pt_with_null);

    if method == 0 {
        // XOR
        let key = deterministic_bytes(b"enc_str:xor", &pt_with_null, len);
        let ct: Vec<u8> = pt_with_null
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        let expanded = quote! {
            {
                let ct = [#(#ct),*];
                let key = [#(#key),*];
                let mut pt = [0u8; #len];
                for i in 0..#len {
                    pt[i] = ct[i] ^ key[i];
                }
                pt
            }
        };
        expanded.into()
    } else if method == 1 {
        // RC4-like
        let key = deterministic_bytes(b"enc_str:rc4", &pt_with_null, 16);
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j: usize = 0;
        for i in 0..=255 {
            j = (j
                .wrapping_add(s[i] as usize)
                .wrapping_add(key[i % 16] as usize))
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
                let ct = [#(#ct),*];
                let key = [#(#key),*];
                let mut s = [0u8; 256];
                let mut pt = [0u8; #len];
                for i in 0..=255 { s[i] = i as u8; }
                let mut j: usize = 0;
                for i in 0..=255 {
                    j = (j.wrapping_add(s[i] as usize).wrapping_add(key[i % 16] as usize)) % 256;
                    s.swap(i, j);
                }
                let mut i: usize = 0;
                j = 0;
                for n in 0..#len {
                    i = (i.wrapping_add(1)) % 256;
                    j = (j.wrapping_add(s[i] as usize)) % 256;
                    s.swap(i, j);
                    let k = s[(s[i] as usize).wrapping_add(s[j] as usize) % 256];
                    pt[n] = ct[n] ^ k;
                }
                pt
            }
        };
        expanded.into()
    } else {
        // AES-CTR conceptually, or a fallback to multi-key XOR for simplicity
        let key1 = deterministic_bytes(b"enc_str:mkxor:key1", &pt_with_null, len);
        let key2 = deterministic_bytes(b"enc_str:mkxor:key2", &pt_with_null, len);
        let ct: Vec<u8> = pt_with_null
            .iter()
            .enumerate()
            .map(|(i, p)| p ^ key1[i] ^ key2[i])
            .collect();

        let expanded = quote! {
            {
                let ct = [#(#ct),*];
                let key1 = [#(#key1),*];
                let key2 = [#(#key2),*];
                let mut pt = [0u8; #len];
                for i in 0..#len {
                    pt[i] = ct[i] ^ key1[i] ^ key2[i];
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

    let key = deterministic_bytes(b"enc_wstr:xor", &pt_bytes, len);
    let ct: Vec<u8> = pt_bytes
        .iter()
        .zip(key.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    let expanded = quote! {
        {
            let ct = [#(#ct),*];
            let key = [#(#key),*];
            let mut pt_bytes = [0u8; #len];
            for i in 0..#len {
                pt_bytes[i] = ct[i] ^ key[i];
            }

            // Reconstruct the u16 array
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
    fn deterministic_bytes_are_stable_for_same_seed() {
        let a = deterministic_bytes_with_seed(b"label", b"input", "seed", 32);
        let b = deterministic_bytes_with_seed(b"label", b"input", "seed", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_bytes_change_with_seed() {
        let a = deterministic_bytes_with_seed(b"label", b"input", "seed-a", 32);
        let b = deterministic_bytes_with_seed(b"label", b"input", "seed-b", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn build_rotation_is_derived_from_input_and_seed() {
        let first = deterministic_seed(b"method", b"hello\0", DEFAULT_SEED) % 3;
        let second = deterministic_seed(b"method", b"hello\0", DEFAULT_SEED) % 3;
        assert_eq!(first, second);
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

    // Use assignments to defeat basic string extraction of static data
    let expanded = quote! {
        {
            let mut pt = [0u8; #len];
            #(#assigns)*
            pt
        }
    };
    expanded.into()
}
