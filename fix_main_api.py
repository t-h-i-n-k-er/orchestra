import re

def fix_file(path):
    with open(path, "r") as f:
        content = f.read()
    
    # regex to find struct initialization and inject field
    content = re.sub(
        r'c_server_secret(: [^,]+)?,',
        r'c_server_secret\g<1>,\n            server_cert_fingerprint: None,',
        content
    )
    
    with open(path, "w") as f:
        f.write(content)

fix_file("builder/src/main.rs")
fix_file("orchestra-server/src/build_handler.rs")
fix_file("orchestra-server/src/api.rs")
