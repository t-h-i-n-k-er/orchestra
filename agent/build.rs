//! Build script: ensures ORCHESTRA_KEY is always available at compile time.
//!
//! If the operator has set ORCHESTRA_KEY in the environment, that value is
//! used and re-exported.  Otherwise, a fresh random 32-byte key is generated
//! per build and exposed via `cargo:rustc-env=ORCHESTRA_KEY=<hex>`.  This
//! removes the previously hardcoded fallback (audit issue 33) while still
//! allowing operators to pin a key for reproducible builds.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=ORCHESTRA_KEY");

    if std::env::var("ORCHESTRA_KEY").is_ok() {
        // Operator-supplied key — leave it alone, it's already in env.
        return;
    }

    // Generate a 32-byte random key from a mix of time and process metadata.
    // Not cryptographically random, but unique per build invocation, which
    // is what we need: every build gets a different key, with no extractable
    // constant in source.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut state = nanos ^ (pid.wrapping_mul(0x9E3779B97F4A7C15));
    let mut key = [0u8; 32];
    for byte in key.iter_mut() {
        // SplitMix64-ish mixer
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }

    let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
    println!("cargo:rustc-env=ORCHESTRA_KEY={}", hex);
}
