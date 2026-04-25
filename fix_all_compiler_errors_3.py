import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the macro strings bug (again since it didn't match the last replace properly)
text = text.replace('''            let candidates = vec![
                
                enc_str!("msfte.dll").as_ref(),
                enc_str!("msratelc.dll").as_ref(),
                enc_str!("scrobj.dll").as_ref(),
                enc_str!("amstream.dll").as_ref()

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
    
with open("agent/src/process_manager.rs", "r") as f:
    text = f.read()

# Let's see what is passing to inject_into_process
text = text.replace("let result = hollowing::inject_into_process(process, &payload);",
                    "let result = hollowing::inject_into_process(pid, &payload);")
text = text.replace("let result = hollowing::windows_impl::inject_into_process(process, &payload);",
                    "let result = hollowing::windows_impl::inject_into_process(pid, &payload);")

with open("agent/src/process_manager.rs", "w") as f:
    f.write(text)
    
with open("agent/src/lib.rs", "r") as f:
    text = f.read()

# Fix the syscall missing module 
if "pub mod syscalls;" not in text and "mod syscalls;" not in text:
    text = text.replace('pub mod process_manager;', 'pub mod process_manager;\npub mod syscalls;')
elif "cfg(all(windows, target_arch = \"x86_64\", feature = \"direct-syscalls\"))]" in text:
    text = text.replace('#[cfg(all(windows, target_arch = "x86_64", feature = "direct-syscalls"))]\npub mod syscalls;', 'pub mod syscalls;')

with open("agent/src/lib.rs", "w") as f:
    f.write(text)

