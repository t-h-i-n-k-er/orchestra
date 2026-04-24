with open("agent/src/injection/module_stomp.rs", "r") as f:
    c = f.read()

c = c.replace("nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const _;", "nt_headers.FileHeader.SizeOfOptionalHeader as usize);")

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(c)

