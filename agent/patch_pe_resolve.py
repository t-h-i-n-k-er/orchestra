import os

path = '/home/replicant/la/pe_resolve/build.rs'
with open(path, 'r') as f:
    data = f.read()

# Add NtCreateThreadEx and AmsiScanBuffer if not present
if 'NtCreateThreadEx' not in data:
    data = data.replace('let funcs = vec![', 'let funcs = vec![\n        "NtCreateThreadEx",\n        "AmsiScanBuffer",\n        "AmsiInitialize",')

with open(path, 'w') as f:
    f.write(data)

