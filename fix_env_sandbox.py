with open("agent/src/env_check.rs", "r") as f:
    text = f.read()

# I accidentally double appended due to re-running the script
import re
text = re.sub(r'/// Combined sandbox heuristics implementation \(Prompt 6\)\npub mod sandbox \{\n    include\!\("env_check_sandbox\.rs"\);\n\}\n', '', text)
text += "\n/// Combined sandbox heuristics implementation (Prompt 6)\n"
text += "pub mod sandbox {\n"
text += "    include!(\"env_check_sandbox.rs\");\n"
text += "}\n"

with open("agent/src/env_check.rs", "w") as f:
    f.write(text)

