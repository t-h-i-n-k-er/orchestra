with open("agent/src/lib.rs", "r") as f:
    text = f.read()

if "pub mod c2_http;" not in text:
    text += "\npub mod c2_http;\npub mod c2_doh;\n"

with open("agent/src/lib.rs", "w") as f:
    f.write(text)
