#[cfg(windows)]
use winapi::um::processthreadsapi::{InitializeProcThreadAttributeList, UpdateProcThreadAttribute, CreateProcessW, STARTUPINFOEXW, PROCESS_INFORMATION};
#[cfg(windows)]
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTF_USESHOWWINDOW};
#[cfg(windows)]
use winapi::um::winnt::HANDLE;

fn main() {}
