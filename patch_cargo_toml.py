import sys

with open("agent/Cargo.toml", "r") as f:
    text = f.read()

# I need to add "tlhelp32" to winapi features. Also need "minwindef"? EXCEPTION_SINGLE_STEP is in winbase I think.
import re
match = re.search(r'winapi\s*=\s*\{.*features\s*=\s*\[(.*?)\]', text)
if match:
    features = match.group(1)
    if '"tlhelp32"' not in features:
        new_features = features + ', "tlhelp32"'
        text = text[:match.start(1)] + new_features + text[match.end(1):]

with open("agent/Cargo.toml", "w") as f:
    f.write(text)
print("Updated Cargo.toml")

