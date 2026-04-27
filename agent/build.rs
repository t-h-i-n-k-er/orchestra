//! Build script: generates per-build ORCHESTRA_KEY and ORCHESTRA_NONCE.
//!
//! If the operator has set ORCHESTRA_KEY in the environment, that value is
//! used and re-exported.  Otherwise, a fresh random 32-byte key is generated
//! per build.  ORCHESTRA_NONCE is always auto-generated (12 bytes) unless
//! explicitly set — the nonce must never repeat for the same key, so it must
//! be different per build even when the key is pinned for reproducibility.
//!
//! Both values are emitted as `cargo:rustc-env=...` so stub.rs can read them
//! at compile time via `option_env!()`.

use std::time::{SystemTime, UNIX_EPOCH};

/// SplitMix64-based PRNG seeded from time + PID.
struct Sm64 {
    state: u128,
}

impl Sm64 {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        Self {
            state: nanos ^ (pid.wrapping_mul(0x9E3779B97F4A7C15)),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        z as u64
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=ORCHESTRA_KEY");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_NONCE");

    // ── ORCHESTRA_KEY (32 bytes = 64 hex chars) ────────────────────────────
    if std::env::var("ORCHESTRA_KEY").is_err() {
        let mut rng = Sm64::new();
        let mut key = [0u8; 32];
        rng.next_bytes(&mut key);
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        println!("cargo:rustc-env=ORCHESTRA_KEY={}", hex);
    }

    // ── ORCHESTRA_NONCE (12 bytes = 24 hex chars) ──────────────────────────
    // Always auto-generate unless explicitly set.  Even when the operator
    // pins ORCHESTRA_KEY for reproducibility, the nonce MUST change per
    // build — ChaCha20 with the same key+nonce pair leaks the keystream.
    // Operators who need bit-for-bit reproducible builds should set both
    // env vars explicitly (C-6 fix).
    if std::env::var("ORCHESTRA_NONCE").is_err() {
        let mut rng = Sm64::new();
        // Advance state past the key bytes to avoid correlation.
        let mut _discard = [0u8; 32];
        rng.next_bytes(&mut _discard);
        let mut nonce = [0u8; 12];
        rng.next_bytes(&mut nonce);
        let hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
        println!("cargo:rustc-env=ORCHESTRA_NONCE={}", hex);
    }
}
