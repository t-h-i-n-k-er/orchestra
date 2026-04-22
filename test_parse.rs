use winapi::shared::ntdef::{LIST_ENTRY, UNICODE_STRING};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT};
use winapi::um::libloaderapi::LoadLibraryA;
use std::ffi::{CString, CStr, c_void};

pub unsafe fn blah() {}
