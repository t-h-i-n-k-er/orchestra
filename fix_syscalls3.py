import re

with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

# remove the structs from where they are (first 34 lines)
peb_structs = """#[repr(C)]
struct PEB {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitFields: u8,
    Mutant: *mut std::os::raw::c_void,
    ImageBaseAddress: *mut std::os::raw::c_void,
    Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut std::os::raw::c_void,
    InLoadOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
    InMemoryOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
    InInitializationOrderModuleList: winapi::shared::ntdef::LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    InMemoryOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    InInitializationOrderLinks: winapi::shared::ntdef::LIST_ENTRY,
    DllBase: *mut std::os::raw::c_void,
    EntryPoint: *mut std::os::raw::c_void,
    SizeOfImage: u32,
    FullDllName: winapi::shared::ntdef::UNICODE_STRING,
    BaseDllName: winapi::shared::ntdef::UNICODE_STRING,
}
"""

text = text.replace(peb_structs, "")

# Insert just before first `use`
text = text.replace("use anyhow::{anyhow, Result};", peb_structs + "\nuse anyhow::{anyhow, Result};")

text = text.replace("let head = &(*ldr).InMemoryOrderModuleList as *const winapi::shared::ntdef::LIST_ENTRY;", "let head = &(*ldr).InMemoryOrderModuleList as *const _ as *mut winapi::shared::ntdef::LIST_ENTRY;")

with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)

