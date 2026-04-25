import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            // It's possible we didn't find *any* target dlls
            ''', '''            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {
                return Err(anyhow::anyhow!("No target dll found"));
            }
            ''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

