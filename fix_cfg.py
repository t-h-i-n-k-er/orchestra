import re
with open("agent/src/obfuscated_sleep.rs", "r") as f: c = f.read()
c = c.replace('#[cfg(windows)]\n    use winapi::um', '#[cfg(windows)] use winapi::um')

with open("agent/src/obfuscated_sleep.rs", "w") as f: f.write(c)
