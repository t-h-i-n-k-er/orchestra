import re

with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

# Specifically target the Windows do_syscall block
pattern = re.compile(
    r'(#\[doc\(hidden\)\]\n#\[inline\(never\)\]\n)(pub unsafe fn do_syscall\(ssn: u32, args: &\[u64\]\) -> i32 \{)\n(.*?)(    if status > 0xfffffffffffff000 \{\n        Err\(\(!status \+ 1\) as i32\)\n    \} else \{\n        Ok\(status\)\n    \}\n\})',
    re.DOTALL
)

def repl(m):
    return m.group(1) + m.group(2) + """
    #[cfg(target_arch = "x86_64")]
    {
""" + m.group(3) + """    status
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Direct syscalls currently unsupported on Windows ARM64
        tracing::error!("Direct syscalls not yet implemented for aarch64 Windows");
        -1
    }
}"""

new_text = pattern.sub(repl, text)

with open("agent/src/syscalls.rs", "w") as f:
    f.write(new_text)

