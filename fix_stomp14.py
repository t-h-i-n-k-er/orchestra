import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Put it back to how we had it when there were no compiler errors on that line
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
            // Hardcode strings to avoid borrow checker
            let candidates: Vec<&[u8]> = vec![
                b"msfte.dll\\0",
                b"msratelc.dll\\0",
                b"scrobj.dll\\0",
                b"amstream.dll\\0"
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

