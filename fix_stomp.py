import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix target_dll string array handling
# Instead of iterating over &[u8] correctly, we need strings or we need to decode them
text = text.replace('let mut target_dll_w: Vec<u16> = target_dll.encode_utf16().chain(std::iter::once(0)).collect();', '''
let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");
let mut target_dll_w: Vec<u16> = target_dll_str.encode_utf16().chain(std::iter::once(0)).collect();
''')

text = text.replace('if name_str.contains(&target_dll.to_lowercase()) {', 'if name_str.contains(&target_dll_str.to_lowercase()) {')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

