use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("cipher_config.rs");

    let seed = env::var("ORCHESTRA_STRING_CRYPT_SEED")
        .unwrap_or_else(|_| "orchestra-string-crypt-v1".to_string());
    let mut hash = 0xcbf29ce484222325u64;
    for b in seed.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let method: u8 = (hash % 3) as u8;

    let content = format!("pub const CIPHER_METHOD: u8 = {};\n", method);
    fs::write(&dest_path, content).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_STRING_CRYPT_SEED");
}
