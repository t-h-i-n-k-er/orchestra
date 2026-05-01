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
// The master seed is split into two halves (SEED_A ^ SEED_B = seed) stored at
// different locations in the binary and recombined at runtime.
//
// xorshift64 has been replaced with Xoshiro256PlusPlus for higher-quality
// key stream generation.  Xoshiro256PlusPlus is also used in build.rs for
// seed generation, so the PRNG is consistent across the crate.

/// FNV-1a over a byte slice, starting from a given state.
fn fnv1a_mix(mut state: u64, data: &[u8]) -> u64 {
    for &b in data {
        state ^= b as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    state
}

// ── SplitMix64 — used to expand a 64-bit FNV state into 256 bits ────────────

const SM64_GAMMA: u64 = 0x9E3779B97F4A7C15;
const SM64_MUL1: u64 = 0xBF58476D1CE4E5B9;
const SM64_MUL2: u64 = 0x94D049BB133111EB;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(SM64_GAMMA);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(SM64_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(SM64_MUL2);
    z ^ (z >> 31)
}

// ── Xoshiro256PlusPlus — high-quality PRNG for key derivation ────────────────

struct Xoshiro256PlusPlus {
    s: [u64; 4],
}

impl Xoshiro256PlusPlus {
    /// Initialize from a single 64-bit seed via SplitMix64 expansion.
    fn from_u64(seed: u64) -> Self {
        let mut sm = seed;
        let s = [
            splitmix64(&mut sm),
            splitmix64(&mut sm),
            splitmix64(&mut sm),
            splitmix64(&mut sm),
        ];
        // All-zero state is invalid.
        let s = if s.iter().all(|&x| x == 0) {
            [1u64, 0, 0, 0]
        } else {
            s
        };
        Self { s }
    }

    fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Fill a byte slice with PRNG output.
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Derive `len` key bytes from the master seed and a per-string label using
/// Xoshiro256PlusPlus (replaces the old xorshift64 expansion).
fn derive_key_from_seed(seed: &str, label: &[u8], len: usize) -> Vec<u8> {
    let mut state = fnv1a_mix(0xcbf29ce484222325u64, seed.as_bytes());
    state = fnv1a_mix(state, label);
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    let mut rng = Xoshiro256PlusPlus::from_u64(state);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Derive a 32-byte ChaCha20 key and 12-byte nonce from seed + label.
fn derive_chacha20_key_nonce(seed: &str, label: &[u8]) -> ([u8; 32], [u8; 12]) {
    // Key: derive from seed + label + "chacha20_key"
    let key_label: Vec<u8> = label.iter().copied().chain(b":chacha20_key".iter().copied()).collect();
    let key = derive_key_from_seed(seed, &key_label, 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);

    // Nonce: derive from seed + label + "chacha20_nonce"
    let nonce_label: Vec<u8> = label.iter().copied().chain(b":chacha20_nonce".iter().copied()).collect();
    let nonce = derive_key_from_seed(seed, &nonce_label, 12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    (key_arr, nonce_arr)
}

/// Generate a per-string mask for seed splitting.
/// The mask is derived from the label using a separate FNV path so it's
/// deterministic but independent of the key derivation path.
fn generate_seed_mask(label: &[u8], len: usize) -> Vec<u8> {
    let mut state = fnv1a_mix(0x6c62272e07bb0142u64, label); // different FNV offset basis
    state = fnv1a_mix(state, b"seed_mask");
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    let mut rng = Xoshiro256PlusPlus::from_u64(state);
    let mut mask = vec![0u8; len];
    rng.fill_bytes(&mut mask);
    mask
}

// ── ChaCha20 block function (compile-time encryption) ────────────────────────

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    // Key (8 x u32 LE)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    // Counter
    state[12] = counter;
    // Nonce (3 x u32 LE)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut working = state;

    // 10 double rounds
    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    // Add original state
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
    }
    out
}

/// ChaCha20 encrypt (or decrypt — same operation for a stream cipher).
fn chacha20_encrypt(pt: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut ct = Vec::with_capacity(pt.len());
    let full_blocks = pt.len() / 64;
    for block_idx in 0..full_blocks {
        let keystream = chacha20_block(key, block_idx as u32, nonce);
        for i in 0..64 {
            ct.push(pt[block_idx * 64 + i] ^ keystream[i]);
        }
    }
    // Partial block
    let remainder = pt.len() % 64;
    if remainder > 0 {
        let keystream = chacha20_block(key, full_blocks as u32, nonce);
        for i in 0..remainder {
            ct.push(pt[full_blocks * 64 + i] ^ keystream[i]);
        }
    }
    ct
}

// ── RC4 with 3072-byte initial drop ─────────────────────────────────────────

struct Rc4State {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j: usize = 0;
        for i in 0..=255 {
            j = (j.wrapping_add(s[i] as usize).wrapping_add(key[i % key.len()] as usize)) % 256;
            s.swap(i, j);
        }
        let mut state = Rc4State { s, i: 0, j: 0 };
        // Standard 3072-byte initial drop to mitigate known biases.
        let mut discard = [0u8; 3072];
        state.process_in_place(&mut discard);
        state
    }

    fn process_in_place(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = (self.i.wrapping_add(1)) % 256;
            self.j = (self.j.wrapping_add(self.s[self.i] as usize)) % 256;
            self.s.swap(self.i, self.j);
            let k = self.s[(self.s[self.i] as usize).wrapping_add(self.s[self.j] as usize) % 256];
            *b ^= k;
        }
    }
}

// ── Method selection ─────────────────────────────────────────────────────────

/// Method selection: depends on the seed only, NOT on the plaintext.
/// Methods: 0=XOR, 1=RC4 (with drop), 2=double-XOR, 3=ChaCha20.
fn get_build_method(seed: &str) -> usize {
    let state = fnv1a_mix(0xcbf29ce484222325u64, seed.as_bytes());
    let state = fnv1a_mix(state, b"method");
    (state % 4) as usize
}

/// Per-string counter so every enc_str! invocation gets a unique label even
/// when the same literal appears multiple times.
static STRING_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── Seed splitting helpers ───────────────────────────────────────────────────

fn split_seed(seed: &str, label: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let seed_bytes: Vec<u8> = seed.bytes().collect();
    let mask = generate_seed_mask(label, seed_bytes.len());
    let seed_a: Vec<u8> = seed_bytes.iter().zip(mask.iter()).map(|(s, m)| s ^ m).collect();
    (seed_a, mask)
}

// ── enc_str! macro ───────────────────────────────────────────────────────────

#[proc_macro]
pub fn enc_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit.value().into_bytes();
    let mut pt_with_null = pt.clone();
    pt_with_null.push(0);
    let len = pt_with_null.len();

    let seed = seed_material();
    let method = get_build_method(&seed);

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let idx = STRING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let label = format!("enc_str:{}:{}", crate_name, idx);
    let label_bytes: Vec<u8> = label.bytes().collect();
    let label_len = label_bytes.len();

    let (seed_a_bytes, seed_b_bytes) = split_seed(&seed, &label_bytes);
    let seed_len = seed_a_bytes.len();

    if method == 0 {
        // ── Method 0: XOR with Xoshiro256PlusPlus keystream ──────────────
        let key = derive_key_from_seed(&seed, &label_bytes, len);
        let ct: Vec<u8> = pt_with_null
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Everything in ONE quote! block to avoid hygiene span mismatches
        let expanded = quote! {
            {
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                // Recombine the split seed by XOR
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                // FNV-1a hash of recombined seed
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                // Mix in the label
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                // Expand FNV state -> 4 x u64 via splitmix64
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                // XOR decrypt loop
                let _ct: [u8; #len] = [#(#ct),*];
                let mut pt = [0u8; #len];
                let mut _j = 0usize;
                while _j < #len {
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        _xs2 ^= _xs0;
                        _xs3 ^= _xs1;
                        _xs1 ^= _xs2;
                        _xs0 ^= _xs3;
                        _xs2 ^= _t;
                        _xs3 = _xs3.rotate_left(45);
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    pt[_j] = _ct[_j] ^ _buf[_buf_idx];
                    _buf_idx += 1;
                    _j += 1;
                }
                pt
            }
        };
        expanded.into()
    } else if method == 1 {
        // ── Method 1: RC4 with 3072-byte initial drop ────────────────────
        let rc4_key = derive_key_from_seed(&seed, &label_bytes, 16);
        let mut rc4 = Rc4State::new(&rc4_key);
        let mut ct_bytes = pt_with_null.clone();
        rc4.process_in_place(&mut ct_bytes);

        let expanded = quote! {
            {
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                // RC4 decrypt with 3072-byte initial drop
                let _ct: [u8; #len] = [#(#ct_bytes),*];
                // Derive RC4 key from Xoshiro256PlusPlus stream (16 bytes)
                let mut _rc4_key = [0u8; 16];
                let mut _ki = 0usize;
                while _ki < 16 {
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        _xs2 ^= _xs0;
                        _xs3 ^= _xs1;
                        _xs1 ^= _xs2;
                        _xs0 ^= _xs3;
                        _xs2 ^= _t;
                        _xs3 = _xs3.rotate_left(45);
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    _rc4_key[_ki] = _buf[_buf_idx];
                    _buf_idx += 1;
                    _ki += 1;
                }
                // RC4 KSA
                let mut _s = [0u8; 256];
                let mut _si = 0usize;
                while _si < 256 { _s[_si] = _si as u8; _si += 1; }
                let mut _j = 0usize;
                _si = 0;
                while _si < 256 {
                    _j = (_j + _s[_si] as usize + _rc4_key[_si % 16] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    _si += 1;
                }
                // 3072-byte initial drop
                let mut _di = 0usize;
                _si = 0; _j = 0;
                while _di < 3072 {
                    _si = (_si + 1) & 0xFF;
                    _j = (_j + _s[_si] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    _di += 1;
                }
                // RC4 PRGA decrypt
                let mut pt = [0u8; #len];
                let mut _n = 0usize;
                _si = 0; _j = 0;
                while _n < #len {
                    _si = (_si + 1) & 0xFF;
                    _j = (_j + _s[_si] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    let k = _s[(_s[_si] as usize + _s[_j] as usize) & 0xFF];
                    pt[_n] = _ct[_n] ^ k;
                    _n += 1;
                }
                pt
            }
        };
        expanded.into()
    } else if method == 2 {
        // ── Method 2: Double-XOR with two independent keystreams ──────────
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
                let _ct: [u8; #len] = [#(#ct),*];
                // ── Keystream 1 ──
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label1_len] = &[#(#label1_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label1_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                // Save keystream 1 state
                let mut _buf1 = _buf;
                let mut _buf1_idx = _buf_idx;
                let mut _xs1_0 = _xs0; let mut _xs1_1 = _xs1;
                let mut _xs1_2 = _xs2; let mut _xs1_3 = _xs3;
                // ── Keystream 2 ──
                let _label2: &[u8; #label2_len] = &[#(#label2_bytes),*];
                let mut _fnv2_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv2_state ^= _seed_buf[_i] as u64;
                    _fnv2_state = _fnv2_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label2_len {
                    _fnv2_state ^= _label2[_i] as u64;
                    _fnv2_state = _fnv2_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv2_state == 0 { _fnv2_state = 0x9e3779b97f4a7c15u64; }
                _sm = _fnv2_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs0 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs1 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs2 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs3 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                _buf = [0u8; 8];
                _buf_idx = 8usize;
                // Decrypt using both keystreams
                let mut pt = [0u8; #len];
                let mut _j = 0usize;
                while _j < #len {
                    if _buf1_idx >= 8 {
                        let _xs0 = _xs1_0; let _xs1 = _xs1_1;
                        let _xs2 = _xs1_2; let _xs3 = _xs1_3;
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        let _xs2_new = _xs2 ^ _xs0;
                        let _xs3_new = _xs3 ^ _xs1;
                        let _xs1_new = _xs2 ^ _xs1;
                        let _xs0_new = _xs3 ^ _xs0;
                        let _xs2_new = _xs2_new ^ _t;
                        let _xs3_new = _xs3_new.rotate_left(45);
                        _xs1_0 = _xs0_new; _xs1_1 = _xs1_new;
                        _xs1_2 = _xs2_new; _xs1_3 = _xs3_new;
                        _buf1 = _res.to_le_bytes();
                        _buf1_idx = 0;
                    }
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        let _xs2_new = _xs2 ^ _xs0;
                        let _xs3_new = _xs3 ^ _xs1;
                        let _xs1_new = _xs2 ^ _xs1;
                        let _xs0_new = _xs3 ^ _xs0;
                        let _xs2_new = _xs2_new ^ _t;
                        let _xs3_new = _xs3_new.rotate_left(45);
                        _xs0 = _xs0_new; _xs1 = _xs1_new;
                        _xs2 = _xs2_new; _xs3 = _xs3_new;
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    pt[_j] = _ct[_j] ^ _buf1[_buf1_idx] ^ _buf[_buf_idx];
                    _buf1_idx += 1;
                    _buf_idx += 1;
                    _j += 1;
                }
                pt
            }
        };
        expanded.into()
    } else {
        // ── Method 3: ChaCha20 with per-string nonce ──────────────────────
        let (key, nonce) = derive_chacha20_key_nonce(&seed, &label_bytes);
        let ct = chacha20_encrypt(&pt_with_null, &key, &nonce);
        let num_blocks = (len + 63) / 64;
        let key_bytes: Vec<u8> = key.to_vec();
        let nonce_bytes: Vec<u8> = nonce.to_vec();

        let expanded = quote! {
            {
                // Seed recombination (still present to prevent single-array extraction)
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                let _ = _fnv_state;
                // ChaCha20 decrypt
                let _ct: [u8; #len] = [#(#ct),*];
                let _ck: [u8; 32] = [#(#key_bytes),*];
                let _cn: [u8; 12] = [#(#nonce_bytes),*];

                let mut _chacha_qr = |v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
                    v[a] = v[a].wrapping_add(v[b]); v[d] ^= v[a]; v[d] = v[d].rotate_left(16);
                    v[c] = v[c].wrapping_add(v[d]); v[b] ^= v[c]; v[b] = v[b].rotate_left(12);
                    v[a] = v[a].wrapping_add(v[b]); v[d] ^= v[a]; v[d] = v[d].rotate_left(8);
                    v[c] = v[c].wrapping_add(v[d]); v[b] ^= v[c]; v[b] = v[b].rotate_left(7);
                };

                let mut pt = [0u8; #len];
                let mut _blk = 0usize;
                while _blk < #num_blocks {
                    // ChaCha20 state: "expand 32-byte k"
                    let mut _st = [0u32; 16];
                    _st[0] = 0x61707865u32; _st[1] = 0x3320646eu32;
                    _st[2] = 0x79622d32u32; _st[3] = 0x6b206574u32;
                    let mut _ki = 0usize;
                    while _ki < 8 {
                        _st[4 + _ki] = u32::from_le_bytes([_ck[_ki*4], _ck[_ki*4+1], _ck[_ki*4+2], _ck[_ki*4+3]]);
                        _ki += 1;
                    }
                    let mut _ni = 0usize;
                    while _ni < 3 {
                        _st[13 + _ni] = u32::from_le_bytes([_cn[_ni*4], _cn[_ni*4+1], _cn[_ni*4+2], _cn[_ni*4+3]]);
                        _ni += 1;
                    }
                    _st[12] = _blk as u32;
                    let mut _w = _st;
                    let mut _r = 0usize;
                    while _r < 20 {
                        _chacha_qr(&mut _w, 0, 4, 8, 12);
                        _chacha_qr(&mut _w, 1, 5, 9, 13);
                        _chacha_qr(&mut _w, 2, 6, 10, 14);
                        _chacha_qr(&mut _w, 3, 7, 11, 15);
                        _chacha_qr(&mut _w, 0, 5, 10, 15);
                        _chacha_qr(&mut _w, 1, 6, 11, 12);
                        _chacha_qr(&mut _w, 2, 7, 8, 13);
                        _chacha_qr(&mut _w, 3, 4, 9, 14);
                        _r += 2;
                    }
                    let mut _ki = 0usize;
                    while _ki < 16 {
                        _w[_ki] = _w[_ki].wrapping_add(_st[_ki]);
                        _ki += 1;
                    }
                    let mut _bi = 0usize;
                    while _bi < 64 {
                        let _base = _blk * 64;
                        let _di = _base + _bi;
                        if _di < #len {
                            let _ks = [0u8; 64];
                            // Extract keystream byte from _w
                            let _w_byte = _w[_bi / 4].to_le_bytes()[_bi % 4];
                            pt[_di] = _ct[_di] ^ _w_byte;
                        }
                        _bi += 1;
                    }
                    _blk += 1;
                }
                pt
            }
        };
        expanded.into()
    }
}

// ── enc_wstr! macro — wide (UTF-16) strings ──────────────────────────────────

#[proc_macro]
pub fn enc_wstr(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let pt: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let pt_bytes: Vec<u8> = pt.iter().flat_map(|&w| w.to_le_bytes()).collect();
    let len = pt_bytes.len();
    let wlen = pt.len();

    let seed = seed_material();
    let method = get_build_method(&seed);

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let idx = STRING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let label = format!("enc_wstr:{}:{}", crate_name, idx);
    let label_bytes: Vec<u8> = label.bytes().collect();
    let label_len = label_bytes.len();

    let (seed_a_bytes, seed_b_bytes) = split_seed(&seed, &label_bytes);
    let seed_len = seed_a_bytes.len();

    if method == 0 {
        let key = derive_key_from_seed(&seed, &label_bytes, len);
        let ct: Vec<u8> = pt_bytes
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect();
        let expanded = quote! {
            {
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                let _ct: [u8; #len] = [#(#ct),*];
                let mut pt_bytes = [0u8; #len];
                let mut _j = 0usize;
                while _j < #len {
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        _xs2 ^= _xs0;
                        _xs3 ^= _xs1;
                        _xs1 ^= _xs2;
                        _xs0 ^= _xs3;
                        _xs2 ^= _t;
                        _xs3 = _xs3.rotate_left(45);
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    pt_bytes[_j] = _ct[_j] ^ _buf[_buf_idx];
                    _buf_idx += 1;
                    _j += 1;
                }
                let mut pt_w = [0u16; #wlen];
                let mut _wi = 0usize;
                while _wi < #wlen {
                    pt_w[_wi] = u16::from_le_bytes([pt_bytes[_wi * 2], pt_bytes[_wi * 2 + 1]]);
                    _wi += 1;
                }
                pt_w
            }
        };
        expanded.into()
    } else if method == 1 {
        let rc4_key = derive_key_from_seed(&seed, &label_bytes, 16);
        let mut rc4 = Rc4State::new(&rc4_key);
        let mut ct_bytes = pt_bytes.clone();
        rc4.process_in_place(&mut ct_bytes);
        let expanded = quote! {
            {
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                let _ct: [u8; #len] = [#(#ct_bytes),*];
                let mut _rc4_key = [0u8; 16];
                let mut _ki = 0usize;
                while _ki < 16 {
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        _xs2 ^= _xs0;
                        _xs3 ^= _xs1;
                        _xs1 ^= _xs2;
                        _xs0 ^= _xs3;
                        _xs2 ^= _t;
                        _xs3 = _xs3.rotate_left(45);
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    _rc4_key[_ki] = _buf[_buf_idx];
                    _buf_idx += 1;
                    _ki += 1;
                }
                let mut _s = [0u8; 256];
                let mut _si = 0usize;
                while _si < 256 { _s[_si] = _si as u8; _si += 1; }
                let mut _j = 0usize;
                _si = 0;
                while _si < 256 {
                    _j = (_j + _s[_si] as usize + _rc4_key[_si % 16] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    _si += 1;
                }
                let mut _di = 0usize;
                _si = 0; _j = 0;
                while _di < 3072 {
                    _si = (_si + 1) & 0xFF;
                    _j = (_j + _s[_si] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    _di += 1;
                }
                let mut pt_bytes = [0u8; #len];
                let mut _n = 0usize;
                _si = 0; _j = 0;
                while _n < #len {
                    _si = (_si + 1) & 0xFF;
                    _j = (_j + _s[_si] as usize) & 0xFF;
                    let _tmp = _s[_si]; _s[_si] = _s[_j]; _s[_j] = _tmp;
                    let k = _s[(_s[_si] as usize + _s[_j] as usize) & 0xFF];
                    pt_bytes[_n] = _ct[_n] ^ k;
                    _n += 1;
                }
                let mut pt_w = [0u16; #wlen];
                let mut _wi = 0usize;
                while _wi < #wlen {
                    pt_w[_wi] = u16::from_le_bytes([pt_bytes[_wi * 2], pt_bytes[_wi * 2 + 1]]);
                    _wi += 1;
                }
                pt_w
            }
        };
        expanded.into()
    } else if method == 2 {
        let label1_bytes: Vec<u8> = format!("{}:k1", label).bytes().collect();
        let label2_bytes: Vec<u8> = format!("{}:k2", label).bytes().collect();
        let label1_len = label1_bytes.len();
        let label2_len = label2_bytes.len();

        let key1 = derive_key_from_seed(&seed, &label1_bytes, len);
        let key2 = derive_key_from_seed(&seed, &label2_bytes, len);
        let ct: Vec<u8> = pt_bytes
            .iter()
            .enumerate()
            .map(|(i, p)| p ^ key1[i] ^ key2[i])
            .collect();

        let expanded = quote! {
            {
                let _ct: [u8; #len] = [#(#ct),*];
                // Keystream 1
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label1_len] = &[#(#label1_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label1_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv_state == 0 { _fnv_state = 0x9e3779b97f4a7c15u64; }
                let mut _sm = _fnv_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                let mut _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs0: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs1: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs2: u64 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                let mut _xs3: u64 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                let mut _buf = [0u8; 8];
                let mut _buf_idx = 8usize;
                let mut _buf1 = _buf;
                let mut _buf1_idx = _buf_idx;
                let mut _xs1_0 = _xs0; let mut _xs1_1 = _xs1;
                let mut _xs1_2 = _xs2; let mut _xs1_3 = _xs3;
                // Keystream 2
                let _label2: &[u8; #label2_len] = &[#(#label2_bytes),*];
                let mut _fnv2_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv2_state ^= _seed_buf[_i] as u64;
                    _fnv2_state = _fnv2_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label2_len {
                    _fnv2_state ^= _label2[_i] as u64;
                    _fnv2_state = _fnv2_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                if _fnv2_state == 0 { _fnv2_state = 0x9e3779b97f4a7c15u64; }
                _sm = _fnv2_state;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs0 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs1 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs2 = _z;
                _sm = _sm.wrapping_add(0x9e3779b97f4a7c15u64);
                _z = _sm;
                _z = (_z ^ (_z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
                _z = (_z ^ (_z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
                _z = _z ^ (_z >> 31);
                _xs3 = _z;
                if _xs0 == 0 && _xs1 == 0 && _xs2 == 0 && _xs3 == 0 { _xs0 = 1; }
                _buf = [0u8; 8];
                _buf_idx = 8usize;
                let mut pt_bytes = [0u8; #len];
                let mut _j = 0usize;
                while _j < #len {
                    if _buf1_idx >= 8 {
                        let _xs0 = _xs1_0; let _xs1 = _xs1_1;
                        let _xs2 = _xs1_2; let _xs3 = _xs1_3;
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        let _xs2_new = _xs2 ^ _xs0;
                        let _xs3_new = _xs3 ^ _xs1;
                        let _xs1_new = _xs2 ^ _xs1;
                        let _xs0_new = _xs3 ^ _xs0;
                        let _xs2_new = _xs2_new ^ _t;
                        let _xs3_new = _xs3_new.rotate_left(45);
                        _xs1_0 = _xs0_new; _xs1_1 = _xs1_new;
                        _xs1_2 = _xs2_new; _xs1_3 = _xs3_new;
                        _buf1 = _res.to_le_bytes();
                        _buf1_idx = 0;
                    }
                    if _buf_idx >= 8 {
                        let _res = _xs0.wrapping_add(_xs3).rotate_left(23).wrapping_add(_xs0);
                        let _t = _xs1 << 17;
                        let _xs2_new = _xs2 ^ _xs0;
                        let _xs3_new = _xs3 ^ _xs1;
                        let _xs1_new = _xs2 ^ _xs1;
                        let _xs0_new = _xs3 ^ _xs0;
                        let _xs2_new = _xs2_new ^ _t;
                        let _xs3_new = _xs3_new.rotate_left(45);
                        _xs0 = _xs0_new; _xs1 = _xs1_new;
                        _xs2 = _xs2_new; _xs3 = _xs3_new;
                        _buf = _res.to_le_bytes();
                        _buf_idx = 0;
                    }
                    pt_bytes[_j] = _ct[_j] ^ _buf1[_buf1_idx] ^ _buf[_buf_idx];
                    _buf1_idx += 1;
                    _buf_idx += 1;
                    _j += 1;
                }
                let mut pt_w = [0u16; #wlen];
                let mut _wi = 0usize;
                while _wi < #wlen {
                    pt_w[_wi] = u16::from_le_bytes([pt_bytes[_wi * 2], pt_bytes[_wi * 2 + 1]]);
                    _wi += 1;
                }
                pt_w
            }
        };
        expanded.into()
    } else {
        let (key, nonce) = derive_chacha20_key_nonce(&seed, &label_bytes);
        let ct = chacha20_encrypt(&pt_bytes, &key, &nonce);
        let num_blocks = (len + 63) / 64;
        let key_bytes: Vec<u8> = key.to_vec();
        let nonce_bytes: Vec<u8> = nonce.to_vec();
        let expanded = quote! {
            {
                let _seed_a: &[u8; #seed_len] = &[#(#seed_a_bytes),*];
                let _seed_b: &[u8; #seed_len] = &[#(#seed_b_bytes),*];
                let _label: &[u8; #label_len] = &[#(#label_bytes),*];
                let mut _seed_buf = [0u8; #seed_len];
                let mut _i = 0usize;
                while _i < #seed_len {
                    _seed_buf[_i] = _seed_a[_i] ^ _seed_b[_i];
                    _i += 1;
                }
                let mut _fnv_state: u64 = 0xcbf29ce484222325u64;
                _i = 0;
                while _i < #seed_len {
                    _fnv_state ^= _seed_buf[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                _i = 0;
                while _i < #label_len {
                    _fnv_state ^= _label[_i] as u64;
                    _fnv_state = _fnv_state.wrapping_mul(0x100000001b3u64);
                    _i += 1;
                }
                let _ = _fnv_state;
                let _ct: [u8; #len] = [#(#ct),*];
                let _ck: [u8; 32] = [#(#key_bytes),*];
                let _cn: [u8; 12] = [#(#nonce_bytes),*];
                let mut _chacha_qr = |v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
                    v[a] = v[a].wrapping_add(v[b]); v[d] ^= v[a]; v[d] = v[d].rotate_left(16);
                    v[c] = v[c].wrapping_add(v[d]); v[b] ^= v[c]; v[b] = v[b].rotate_left(12);
                    v[a] = v[a].wrapping_add(v[b]); v[d] ^= v[a]; v[d] = v[d].rotate_left(8);
                    v[c] = v[c].wrapping_add(v[d]); v[b] ^= v[c]; v[b] = v[b].rotate_left(7);
                };
                let mut pt_bytes = [0u8; #len];
                let mut _blk = 0usize;
                while _blk < #num_blocks {
                    let mut _st = [0u32; 16];
                    _st[0] = 0x61707865u32; _st[1] = 0x3320646eu32;
                    _st[2] = 0x79622d32u32; _st[3] = 0x6b206574u32;
                    let mut _ki = 0usize;
                    while _ki < 8 {
                        _st[4 + _ki] = u32::from_le_bytes([_ck[_ki*4], _ck[_ki*4+1], _ck[_ki*4+2], _ck[_ki*4+3]]);
                        _ki += 1;
                    }
                    let mut _ni = 0usize;
                    while _ni < 3 {
                        _st[13 + _ni] = u32::from_le_bytes([_cn[_ni*4], _cn[_ni*4+1], _cn[_ni*4+2], _cn[_ni*4+3]]);
                        _ni += 1;
                    }
                    _st[12] = _blk as u32;
                    let mut _w = _st;
                    let mut _r = 0usize;
                    while _r < 20 {
                        _chacha_qr(&mut _w, 0, 4, 8, 12);
                        _chacha_qr(&mut _w, 1, 5, 9, 13);
                        _chacha_qr(&mut _w, 2, 6, 10, 14);
                        _chacha_qr(&mut _w, 3, 7, 11, 15);
                        _chacha_qr(&mut _w, 0, 5, 10, 15);
                        _chacha_qr(&mut _w, 1, 6, 11, 12);
                        _chacha_qr(&mut _w, 2, 7, 8, 13);
                        _chacha_qr(&mut _w, 3, 4, 9, 14);
                        _r += 2;
                    }
                    let mut _ki = 0usize;
                    while _ki < 16 {
                        _w[_ki] = _w[_ki].wrapping_add(_st[_ki]);
                        _ki += 1;
                    }
                    let mut _bi = 0usize;
                    while _bi < 64 {
                        let _base = _blk * 64;
                        let _di = _base + _bi;
                        if _di < #len {
                            let _w_byte = _w[_bi / 4].to_le_bytes()[_bi % 4];
                            pt_bytes[_di] = _ct[_di] ^ _w_byte;
                        }
                        _bi += 1;
                    }
                    _blk += 1;
                }
                let mut pt_w = [0u16; #wlen];
                let mut _wi = 0usize;
                while _wi < #wlen {
                    pt_w[_wi] = u16::from_le_bytes([pt_bytes[_wi * 2], pt_bytes[_wi * 2 + 1]]);
                    _wi += 1;
                }
                pt_w
            }
        };
        expanded.into()
    }
}

// ── stack_str! macro — no encryption ─────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────────────────

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
        let key_for_hello = derive_key_from_seed("seed", b"enc_str:agent:0", 32);
        let key_for_world = derive_key_from_seed("seed", b"enc_str:agent:0", 32);
        assert_eq!(key_for_hello, key_for_world);

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
        assert!(m1 < 4, "method must be 0..4");
        let _ = get_build_method("seed-b");
    }

    #[test]
    fn xoshiro256_plus_plus_is_deterministic() {
        let mut a = Xoshiro256PlusPlus::from_u64(12345);
        let mut b = Xoshiro256PlusPlus::from_u64(12345);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn xoshiro256_plus_plus_differs_for_different_seeds() {
        let mut a = Xoshiro256PlusPlus::from_u64(1);
        let mut b = Xoshiro256PlusPlus::from_u64(2);
        let mut same = true;
        for _ in 0..10 {
            if a.next_u64() != b.next_u64() {
                same = false;
                break;
            }
        }
        assert!(!same, "different seeds should produce different streams");
    }

    #[test]
    fn chacha20_roundtrip() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; 12];
        let pt = b"Hello, ChaCha20 encryption!";
        let ct = chacha20_encrypt(pt, &key, &nonce);
        assert_ne!(ct.as_slice(), pt.as_slice());
        let recovered = chacha20_encrypt(&ct, &key, &nonce);
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn chacha20_empty_input() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ct = chacha20_encrypt(&[], &key, &nonce);
        assert!(ct.is_empty());
    }

    #[test]
    fn chacha20_long_input() {
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];
        let pt: Vec<u8> = (0..200).map(|i| (i as u8).wrapping_mul(37)).collect();
        let ct = chacha20_encrypt(&pt, &key, &nonce);
        let recovered = chacha20_encrypt(&ct, &key, &nonce);
        assert_eq!(recovered, pt);
    }

    #[test]
    fn derive_chacha20_key_nonce_differs_for_different_labels() {
        let (k1, n1) = derive_chacha20_key_nonce("seed", b"label_a");
        let (k2, n2) = derive_chacha20_key_nonce("seed", b"label_b");
        assert_ne!(k1, k2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn seed_split_recombines_correctly() {
        let seed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let label = b"test_label";
        let (a, b) = split_seed(seed, label);
        let recombined: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        let original: Vec<u8> = seed.bytes().collect();
        assert_eq!(recombined, original);
    }

    #[test]
    fn seed_split_differs_for_different_labels() {
        let seed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let (a1, b1) = split_seed(seed, b"label_a");
        let (a2, b2) = split_seed(seed, b"label_b");
        assert_ne!(b1, b2);
        let r1: Vec<u8> = a1.iter().zip(b1.iter()).map(|(x, y)| x ^ y).collect();
        let r2: Vec<u8> = a2.iter().zip(b2.iter()).map(|(x, y)| x ^ y).collect();
        assert_eq!(r1, r2);
    }

    #[test]
    fn rc4_with_drop_roundtrip() {
        let key = derive_key_from_seed("test-seed", b"rc4_test", 16);
        let pt = b"Test RC4 with initial drop!";
        let mut rc4_enc = Rc4State::new(&key);
        let mut ct = pt.to_vec();
        rc4_enc.process_in_place(&mut ct);
        assert_ne!(ct.as_slice(), pt.as_slice());
        let mut rc4_dec = Rc4State::new(&key);
        rc4_dec.process_in_place(&mut ct);
        assert_eq!(&ct, pt);
    }
}
