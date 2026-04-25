import re
cb = '/home/replicant/la/agent/src/callback_exec.rs'
with open(cb, 'r') as f:
    text = f.read()

text = text.replace('use winapi::um::winnls::{EnumSystemLocalesA, LCID};', 'use winapi::um::winnls::EnumSystemLocalesA;\nuse winapi::shared::ntdef::LCID;')
text = text.replace('use winapi::shared::ntdef::LCID;', 'use winapi::um::winnt::LCID;')
with open(cb, 'w') as f:
    f.write(text)

