import re

with open('hollowing/src/windows_impl.rs', 'r') as f:
    text = f.read()

text = text.replace("use std::ffi::{c_void, CStr, OsStr};", "use std::ffi::{CStr, OsStr};\nuse winapi::ctypes::c_void;")

with open('hollowing/src/windows_impl.rs', 'w') as f:
    f.write(text)
