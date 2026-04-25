import re

with open('src/amsi_defense.rs', 'r') as f:
    text = f.read()

text = re.sub(r'crate::syscall!\("NtProtectVirtualMemory", [^,]+, &mut ([^ ]+) as \*mut _ as usize as u64, &mut ([^ ]+) as \*mut _ as usize as u64, ([^,]+) as u64, &mut ([^ ]+) as \*mut _ as usize as u64\)', r'winapi::um::memoryapi::VirtualProtect(\1 as *mut winapi::ctypes::c_void, \2 as usize, \3 as u32, &mut \4)', text)

with open('src/amsi_defense.rs', 'w') as f:
    f.write(text)

with open('src/obfuscated_sleep.rs', 'r') as f:
    text = f.read()

text = re.sub(r'crate::syscalls::syscall_NtProtectVirtualMemory\([^,]+, &mut ([^ ]+) as \*mut _ as usize as u64, &mut ([^ ]+) as \*mut _ as usize as u64, ([^,]+) as u64, &mut ([^ ]+) as \*mut _ as usize as u64\)', r'winapi::um::memoryapi::VirtualProtect(\1 as *mut winapi::ctypes::c_void, \2 as usize, \3 as u32, &mut \4)', text)

with open('src/obfuscated_sleep.rs', 'w') as f:
    f.write(text)
