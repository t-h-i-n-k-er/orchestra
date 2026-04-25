import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");''', '''            // It's possible we didn't find *any* target dlls
            if target_dll.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }
            let target_dll_str = std::str::from_utf8(target_dll).unwrap_or("");''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

