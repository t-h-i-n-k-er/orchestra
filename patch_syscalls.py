import sys
content = open('agent/src/syscalls.rs', 'r').read()

content = content.replace('format!("{}\System32\ntdll.dll", sysroot)', 'format!(r"{}\System32\ntdll.dll", sysroot)')
content = content.replace('format!("\??\{}\System32\ntdll.dll", sysroot)', 'format!(r"\??\{}\System32\ntdll.dll", sysroot)')
content = content.replace('dll_lower.contains("\")', 'dll_lower.contains(r"\")')
content = content.replace('format!("{}\System32\{}", sysroot, dll_name)', 'format!(r"{}\System32\{}", sysroot, dll_name)')
content = content.replace('"C:\Windows"', 'r"C:\Windows"')

open('agent/src/syscalls.rs', 'w').write(content)
