import re

with open('hollowing/src/windows_impl.rs', 'r') as f:
    text = f.read()

text = text.replace("let pi = &guard.pi;", "let pi = guard.pi;")

with open('hollowing/src/windows_impl.rs', 'w') as f:
    f.write(text)
