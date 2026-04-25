import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

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

            let dos_header = std::ptr::read(target_base as *const ImageDosHeader);''', '''            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
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
            
            // To satisfy borrow checker, just do the string copy here if needed
            let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");
            
            let dos_header = std::ptr::read(target_base as *const ImageDosHeader);''')

text = text.replace('std::str::from_utf8(target_dll).unwrap_or("")', 'target_dll_str')
text = text.replace('let target_dll_str = target_dll_str;', 'let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

