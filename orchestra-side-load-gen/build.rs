use std::path::Path;

fn main() {
    // Generate a random 4-byte XOR key at build time so every build produces
    // a different encrypted payload without requiring a runtime secret.
    let key: [u8; 4] = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Use a mix of time and process ID to get per-build randomness without
        // pulling the `rand` crate into build-script dependencies.
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();

        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        pid.hash(&mut h);
        let v = h.finish();
        let bytes = v.to_le_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    };

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("side_key.rs");
    std::fs::write(
        &dest,
        format!(
            "const SIDE_XOR_KEY: [u8; 4] = [0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}];\n",
            key[0], key[1], key[2], key[3]
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
