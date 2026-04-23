import re

# Update build_handler.rs API Request struct
with open("orchestra-server/src/build_handler.rs", "r") as f:
    content = f.read()

old_s = """pub struct BuildFeatures {
    pub persistence: bool,
    pub syscalls: bool,
    pub screencap: bool,
    pub keylog: bool,
}"""

new_s = """pub struct BuildFeatures {
    pub persistence: bool,
    pub syscalls: bool,
    pub screencap: bool,
    pub keylog: bool,
    pub stealth: bool,
}"""
content = content.replace(old_s, new_s)

old_b = """if req.features.keylog { features.push("keylog".to_string()); }"""
new_b = """if req.features.keylog { features.push("keylog".to_string()); }
    if req.features.stealth { features.push("stealth".to_string()); }"""
content = content.replace(old_b, new_b)

with open("orchestra-server/src/build_handler.rs", "w") as f:
    f.write(content)
