with open("agent/Cargo.toml", "r") as f:
    content = f.read()

# Add stealth feature
content = content.replace("ppid-spoofing = []", "ppid-spoofing = []\nstealth = [\"direct-syscalls\", \"unsafe-runtime-rewrite\", \"memory-guard\", \"ppid-spoofing\"]")

with open("agent/Cargo.toml", "w") as f:
    f.write(content)
