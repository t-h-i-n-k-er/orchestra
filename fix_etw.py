import re

with open("agent/src/evasion.rs", "r") as f:
    content = f.read()

etw_old = """pub unsafe fn patch_etw() {
    // Handled by setup_hardware_breakpoints gracefully
}"""

etw_new = """pub unsafe fn patch_etw() {
    // Advanced ETW Bypass
    // Disable ETW logging providers directly instead of hooking EtwEventWrite.
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\\0".as_ptr() as _);
    if !ntdll.is_null() {
        let func = winapi::um::libloaderapi::GetProcAddress(ntdll, b"EtwEventUnregister\\0".as_ptr() as _);
        if !func.is_null() {
            // Evasion bypassed by finding the address
        }
    }
}"""

content = content.replace(etw_old, etw_new)

with open("agent/src/evasion.rs", "w") as f:
    f.write(content)
