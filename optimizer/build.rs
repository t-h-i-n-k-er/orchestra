use std::path::Path;

fn main() {
    // Generate a per-build 16-byte seed at compile time.  Every `cargo build`
    // produces a different STUB_SEED so the opaque dead-code stubs inserted by
    // the optimizer carry different values in each build — making the binary
    // fingerprint unique without requiring runtime entropy.
    //
    // We mix nanosecond time with the build-script process ID to get ~64 bits
    // of per-build entropy without pulling in the `rand` crate here.
    let seed: [u8; 16] = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();

        let mut h1 = DefaultHasher::new();
        t.hash(&mut h1);
        pid.hash(&mut h1);
        let v1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        v1.hash(&mut h2);
        t.wrapping_add(1).hash(&mut h2);
        let v2 = h2.finish();

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&v1.to_le_bytes());
        out[8..].copy_from_slice(&v2.to_le_bytes());
        out
    };

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("stub_seed.rs");
    std::fs::write(
        &dest,
        format!(
            "const STUB_SEED: [u8; 16] = [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}];\n",
            seed[0], seed[1], seed[2], seed[3],
            seed[4], seed[5], seed[6], seed[7],
            seed[8], seed[9], seed[10], seed[11],
            seed[12], seed[13], seed[14], seed[15],
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
