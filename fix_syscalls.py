import re

with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

# Fix TEB/PEB imports: winapi::um::winnt doesn't have them
text = text.replace("use winapi::um::winnt::{TEB, PEB};", "use winapi::um::winnt::NT_TIB;\n            // TEB/PEB are in winapi::um::winternl\n            use winapi::um::winternl::{TEB, PEB};")

# HMODULE__ -> HINSTANCE__ (HMODULE is just an alias, but minwindef::HMODULE is HINSTANCE)
text = text.replace("winapi::shared::minwindef::HMODULE__", "winapi::shared::minwindef::HINSTANCE__")

# ntdef::c_void is private -> std::os::raw::c_void
text = text.replace("winapi::shared::ntdef::c_void", "std::os::raw::c_void")

# *section.Misc.VirtualSize() 
text = text.replace("let size = section.Misc.VirtualSize() as usize;", "let size = *section.Misc.VirtualSize() as usize;")

# OriginalFirstThunk -> u.OriginalFirstThunk()
text = text.replace("(*import_desc).OriginalFirstThunk", "(*import_desc).u.OriginalFirstThunk()")

# (*temp_thunk).u1.AddressOfData().is_null() 
# .AddressOfData() returns a *mut or reference? Actually u1 is an union, .AddressOfData() returns a pointer. 
text = text.replace("!(*temp_thunk).u1.AddressOfData().is_null()", "(*temp_thunk).u1.AddressOfData() != &0")
text = text.replace("!(*original_thunk).u1.AddressOfData().is_null()", "(*original_thunk).u1.AddressOfData() != &0")
# Wait, u1.AddressOfData() returns `&u64` or `*mut u64` in winapi? It's `&u64` in the getter. Let's just do `*(*temp_thunk).u1.Function() != 0`
text = re.sub(r'!\(\*temp_thunk\)\.u1\.AddressOfData\(\)\.is_null\(\)', r'*(*temp_thunk).u1.Function() != 0', text)
text = re.sub(r'!\(\*original_thunk\)\.u1\.AddressOfData\(\)\.is_null\(\)', r'*(*original_thunk).u1.Function() != 0', text)

# pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL).unwrap_or(0) as *mut _
text = text.replace("unwrap_or(0) as *mut _", "unwrap_or(0) as *mut std::os::raw::c_void")

with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)

