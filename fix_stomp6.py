import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by making it not borrow
text = text.replace('''            let mut candidates: Vec<&[u8]> = Vec::new();
            let mut c1 = enc_str!("msfte.dll");
            let mut c2 = enc_str!("msratelc.dll");
            let mut c3 = enc_str!("scrobj.dll");
            let mut c4 = enc_str!("amstream.dll");
            candidates.push(&c1);
            candidates.push(&c2);
            candidates.push(&c3);
            candidates.push(&c4);
''', '''
            let c1 = enc_str!("msfte.dll").to_vec();
            let c2 = enc_str!("msratelc.dll").to_vec();
            let c3 = enc_str!("scrobj.dll").to_vec();
            let c4 = enc_str!("amstream.dll").to_vec();
            
            let candidates: Vec<&[u8]> = vec![
                c1.as_slice(),
                c2.as_slice(),
                c3.as_slice(),
                c4.as_slice()
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

