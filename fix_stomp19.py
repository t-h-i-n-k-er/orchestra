import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            let mut target_dll = "";''', '''            let mut target_dll = "";
            let mut target_dll_str = "";''')
text = text.replace('''            let target_dll_str = target_dll;
            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {''', '''            target_dll_str = target_dll;
            // It's possible we didn't find *any* target dlls
            if target_dll_str.is_empty() {''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

