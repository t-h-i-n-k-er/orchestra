import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            let mut target_dll = "";
            let mut target_dll_str = "";
            
            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
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
            
            target_dll_str = target_dll;
            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }''', '''            let mut target_dll_str_val = String::new();
            
            if let Ok((h, b)) = target_dll_search(&[dll1.as_ref()]) {
                h_proc = h; target_base = b; target_dll_str_val = std::str::from_utf8(dll1.as_ref()).unwrap_or("").to_string();
            } else if let Ok((h, b)) = target_dll_search(&[dll2.as_ref()]) {
                h_proc = h; target_base = b; target_dll_str_val = std::str::from_utf8(dll2.as_ref()).unwrap_or("").to_string();
            } else if let Ok((h, b)) = target_dll_search(&[dll3.as_ref()]) {
                h_proc = h; target_base = b; target_dll_str_val = std::str::from_utf8(dll3.as_ref()).unwrap_or("").to_string();
            } else if let Ok((h, b)) = target_dll_search(&[dll4.as_ref()]) {
                h_proc = h; target_base = b; target_dll_str_val = std::str::from_utf8(dll4.as_ref()).unwrap_or("").to_string();
            } else {
                return Err(anyhow::anyhow!("No target dll found"));
            }
            
            let target_dll_str = target_dll_str_val.as_str();
            
            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

