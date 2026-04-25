import re
p = 'agent/src/obfuscated_sleep.rs'
with open(p, 'r') as f:
    t = f.read()

# Instead of blindly doing an exact rewrite, let's just make it look like a valid do_syscall call.
# The original was crate::syscalls::syscall_NtProtectVirtualMemory(-1, base_addr, size, PAGE_READWRITE, &mut temp);
# I changed it to crate::syscalls::do_syscall(-1, base_addr, size, PAGE_READWRITE, &mut temp);
# Then it failed because do_syscall signature is do_syscall(ssn: u32, args: &[u64])
# So we need to rewrite to crate::syscalls::do_syscall(50, &[...])

t = re.sub(
    r'crate::syscalls::do_syscall\(\s*([\s\S]*?)\s*\)',
    r'crate::syscalls::do_syscall(50, &[\1])',
    t
)

# wait I already replaced syscall_NtProtectVirtualMemory with do_syscall in a previous prompt
# I checked out the original file so it has syscall_NtProtectVirtualMemory right now!
t = re.sub(
    r'crate::syscalls::syscall_NtProtectVirtualMemory\(\s*([\s\S]*?)\s*\)',
    r'crate::syscalls::do_syscall(50, &[\1])',
    t
)

with open(p, 'w') as f:
    f.write(t)

