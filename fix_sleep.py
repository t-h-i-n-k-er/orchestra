import re

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    content = f.read()

# fix `do_syscall(50, &[(-1isize]) as usize as u64,` to `do_syscall(50, &[(-1isize as usize as u64),`
# but also we need to close the array at the end: `]);` instead of `);`

content = content.replace("do_syscall(50, &[(-1isize]) as usize as u64,", "do_syscall(50, &[(-1isize as usize as u64),")
content = content.replace("&mut old_protect as *mut _ as usize as u64\n                );", "&mut old_protect as *mut _ as usize as u64\n                ]);")
content = content.replace("&mut temp as *mut _ as usize as u64\n                );", "&mut temp as *mut _ as usize as u64\n                ]);")


with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(content)

