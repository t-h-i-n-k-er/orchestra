import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error 
text = text.replace('''            let mut candidates: Vec<Vec<u8>> = vec![
                enc_str!("msfte.dll").to_vec(),
                enc_str!("msratelc.dll").to_vec(),
                enc_str!("scrobj.dll").to_vec(),
                enc_str!("amstream.dll").to_vec()
            ];
''', '''
            let mut candidates: Vec<Vec<u8>> = Vec::new();
            candidates.push(enc_str!("msfte.dll").to_vec());
            candidates.push(enc_str!("msratelc.dll").to_vec());
            candidates.push(enc_str!("scrobj.dll").to_vec());
            candidates.push(enc_str!("amstream.dll").to_vec());
''')
text = text.replace('''            let target_dll = candidates[0].as_slice();''', '''            let target_dll = &candidates[0];''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

