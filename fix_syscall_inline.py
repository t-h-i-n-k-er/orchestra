import re

with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

# Let's replace the do_syscall asm section
asm_search = r'''        asm!\(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call r11",
            ssn = in\(reg\) ssn,
            in\("r11"\) gadget_addr,
'''
asm_replace = r'''        asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "test r11, r11",
            "jz 1f",
            "call r11",
            "jmp 2f",
            "1:",
            "syscall",
            "2:",
            ssn = in(reg) ssn,
            in("r11") gadget_addr,
'''
if 'call r11' in text and 'test r11, r11' not in text:
    text = text.replace('            "call r11",\n            ssn = in(reg) ssn,\n            in("r11") gadget_addr,', '''            "test r11, r11",
            "jz 1f",
            "call r11",
            "jmp 2f",
            "1:",
            "syscall",
            "2:",
            ssn = in(reg) ssn,
            in("r11") gadget_addr,''')

with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)

