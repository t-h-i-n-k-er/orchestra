import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by keeping the objects alive
text = text.replace('''let candidates = vec![
                enc_str!("msfte.dll").as_ref(),
                enc_str!("msratelc.dll").as_ref(),
                enc_str!("scrobj.dll").as_ref(),
                enc_str!("amstream.dll").as_ref()

            ];''', '''
            let c1 = enc_str!("msfte.dll");
            let c2 = enc_str!("msratelc.dll");
            let c3 = enc_str!("scrobj.dll");
            let c4 = enc_str!("amstream.dll");
            let candidates = vec![
                c1.as_ref(),
                c2.as_ref(),
                c3.as_ref(),
                c4.as_ref()
            ];
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

