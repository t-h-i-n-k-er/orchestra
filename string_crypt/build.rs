use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_STRING_CRYPT_SEED");

    // ── Per-build random master seed ──────────────────────────────────────
    // If the operator supplies ORCHESTRA_STRING_CRYPT_SEED, use it for
    // reproducible builds (must be exactly 64 hex characters = 32 bytes).
    // Otherwise generate a fresh random seed each build so keys are NOT
    // derivable from public constants (C-7 fix).
    if std::env::var("ORCHESTRA_STRING_CRYPT_SEED").is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let mut state = nanos ^ (pid.wrapping_mul(0x9E3779B97F4A7C15));

        let mut seed = [0u8; 32];
        for byte in seed.iter_mut() {
            state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            *byte = (z & 0xFF) as u8;
        }
        let hex: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
        // Emit as an env var so the proc-macro reads the same value via
        // std::env::var("ORCHESTRA_STRING_CRYPT_SEED") at expansion time.
        println!("cargo:rustc-env=ORCHESTRA_STRING_CRYPT_SEED={}", hex);
    } else {
        let seed = std::env::var("ORCHESTRA_STRING_CRYPT_SEED").unwrap();
        if seed.len() != 64 || !seed.chars().all(|c| c.is_ascii_hexdigit()) {
            panic!(
                "ORCHESTRA_STRING_CRYPT_SEED must be 64 hex characters (32 bytes), got {}",
                seed.len()
            );
        }
    }
}
