import re

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    text = f.read()

# E0433: cannot find `syscalls` in `crate`
# The problem is that obfuscated_sleep does not have a #[cfg(feature = "direct-syscalls")] gate inside it, or something.
# It's only conditionally compiled. The sleep function uses do_syscall.
# If direct-syscalls feature isn't active, `crate::syscalls` is not found.
# For now, let's just cfg gate the calls to crate::syscalls.

text = text.replace("let _ = crate::syscalls::do_syscall(", '''#[cfg(all(windows, target_arch = "x86_64", feature = "direct-syscalls"))]
                let _ = crate::syscalls::do_syscall(''')
                
with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(text)

