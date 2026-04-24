use std::env;
use std::fs;
use std::path::Path;
use rand::Rng;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("cipher_config.rs");
    
    let mut rng = rand::thread_rng();
    let method: u8 = rng.gen_range(0..3);
    
    let content = format!("pub const CIPHER_METHOD: u8 = {};\n", method);
    fs::write(&dest_path, content).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
