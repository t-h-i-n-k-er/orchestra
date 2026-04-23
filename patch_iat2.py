import sys
content = open('builder/patch_agent.py', 'r').read()
content = content.replace('while (*temp_thunk).u1.AddressOfData() != &0 {',
                          'while !(*temp_thunk).u1.AddressOfData().is_null() {')
content = content.replace('while (*original_thunk).u1.AddressOfData() != &0 {',
                          'while !(*original_thunk).u1.AddressOfData().is_null() {')
ordinal_to_replace = """let proc_addr = if (addr_of_data & winapi::um::winnt::IMAGE_ORDINAL_FLAG64) != 0 {
                    0 // Ordinal imports bypass not implemented here seamlessly in pure manual lookup, fallback removed
                } else {"""
ordinal_replacement = """let proc_addr = if (addr_of_data & winapi::um::winnt::IMAGE_ORDINAL_FLAG64) != 0 {
                    let ordinal = (addr_of_data & 0xFFFF) as u16;
                    winapi::um::libloaderapi::GetProcAddress(dep_handle as *mut _, ordinal as winapi::um::winnt::LPCSTR) as usize
                } else {"""
content = content.replace(ordinal_to_replace, ordinal_replacement)
content = content.replace('let addr_of_data = *(*original_thunk).u1.AddressOfData();',
                          'let addr_of_data = *(*original_thunk).u1.AddressOfData() as u64;')
with open('builder/patch_agent.py', 'w') as f:
    f.write(content)
