import re

for filename in ["agent/src/c2_http.rs", "agent/src/c2_doh.rs"]:
    with open(filename, "r") as f:
        text = f.read()
    
    text = text.replace("use async_trait::async_trait;\n", "")
    text = text.replace("#[async_trait]\n", "")

    with open(filename, "w") as f:
        f.write(text)

