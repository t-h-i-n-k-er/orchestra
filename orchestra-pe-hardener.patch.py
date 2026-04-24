import os
import glob
for f in glob.glob("**/*.rs", recursive=True):
    with open(f, 'r') as file:
        content = file.read()
    if 'zero out dos header' in content.lower() or 'zeroing header bytes' in content.lower() or 'pe-hardener' in f.lower():
        content = content.replace("memset(dos_header", "// Patched to maintain PE validity\n// memset(dos_header")
        with open(f, 'w') as file:
            file.write(content)
