import re
with open("agent/src/obfuscated_sleep.rs", "r") as f:
    c = f.read()

# Replace the missing chrono import. If chrono isn't in Cargo.toml, we can just use std::time or a hack
c = c.replace('chrono::Local::now().hour()', '(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 3600 % 24) as u32')

# wrap `get_text_section` and `encrypt_sections` entirely in #[cfg(windows)] since they use windows PE structures
if '#[cfg(windows)]\n    unsafe fn get_text_section' not in c:
    c = c.replace('unsafe fn get_text_section', '#[cfg(windows)]\n    unsafe fn get_text_section')

if '#[cfg(windows)]\npub unsafe fn encrypt_sections' not in c:
    c = c.replace('pub unsafe fn encrypt_sections', '#[cfg(windows)]\npub unsafe fn encrypt_sections')

# Wait, `get_text_section` was defined without pub, let's just make sure.
# We also need a dummy encrypt_sections for linux
if '#[cfg(not(windows))]\npub unsafe fn encrypt_sections() {}' not in c:
    c += '\n#[cfg(not(windows))]\npub unsafe fn encrypt_sections() {}\n'

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(c)

