import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            if target_dll.is_empty() {''', '')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

