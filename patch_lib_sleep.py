with open("agent/src/lib.rs", "r") as f:
    text = f.read()

if "pub mod obfuscated_sleep;" not in text:
    text += "\npub mod obfuscated_sleep;\n"

with open("agent/src/lib.rs", "w") as f:
    f.write(text)
