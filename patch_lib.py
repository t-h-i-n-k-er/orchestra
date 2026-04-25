import re
path = '/home/replicant/la/agent/src/lib.rs'
with open(path, 'r') as f:
    data = f.read()

data = data.replace('crate::evasion::patch_amsi();', 'unsafe { crate::evasion::patch_amsi(); }')

with open(path, 'w') as f:
    f.write(data)
