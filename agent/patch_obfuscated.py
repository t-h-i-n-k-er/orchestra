import re

with open('src/obfuscated_sleep.rs', 'r') as f:
    text = f.read()

# Fix pe_resolve::hash_wstr_str to map to string wstr slices
text = text.replace('pe_resolve::hash_wstr_str("ntdll.dll", 0)', 'pe_resolve::hash_wstr(&"ntdll.dll\\0".encode_utf16().collect::<Vec<u16>>())')
text = text.replace('pe_resolve::hash_wstr_str("kernel32.dll", 0)', 'pe_resolve::hash_wstr(&"kernel32.dll\\0".encode_utf16().collect::<Vec<u16>>())')
text = text.replace('pe_resolve::hash_str("NtDelayExecution", 0)', 'pe_resolve::hash_str(b"NtDelayExecution\\0")')

# Fix get_proc_address_by_hash to unwrap the ntdll module handle correctly
text = text.replace('pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtDelayExecution\\0")) as usize', 'pe_resolve::get_proc_address_by_hash(ntdll.unwrap_or(0), pe_resolve::hash_str(b"NtDelayExecution\\0")).unwrap_or(0)')

with open('src/obfuscated_sleep.rs', 'w') as f:
    f.write(text)
