import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            let mut target_dll: &[u8] = &[];''', '''            let mut target_dll = "";''')
text = text.replace('''            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
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
            
            // It's possible we didn't find *any* target dlls
            if target_dll.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }
            let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");''', '''            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
                h_proc = h; target_base = b; target_dll = std::str::from_utf8(dll1.as_ref()).unwrap_or("");
            } else if let Ok((h, b)) = target_dll_search(&[dll2.as_ref()]) {
                h_proc = h; target_base = b; target_dll = std::str::from_utf8(dll2.as_ref()).unwrap_or("");
            } else if let Ok((h, b)) = target_dll_search(&[dll3.as_ref()]) {
                h_proc = h; target_base = b; target_dll = std::str::from_utf8(dll3.as_ref()).unwrap_or("");
            } else if let Ok((h, b)) = target_dll_search(&[dll4.as_ref()]) {
                h_proc = h; target_base = b; target_dll = std::str::from_utf8(dll4.as_ref()).unwrap_or("");
            } else {
                return Err(anyhow::anyhow!("No target dll found"));
            }
            
            let target_dll_str = target_dll;
            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }
''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

