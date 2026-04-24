with open("agent/src/env_check.rs", "r") as f:
    text = f.read()

if "sandbox_probability_score" not in text:
    text += "\n/// Combined sandbox heuristics implementation (Prompt 6)\n"
    text += "pub mod sandbox {\n"
    text += "    include!(\"env_check_sandbox.rs\");\n"
    text += "}\n"

with open("agent/src/env_check.rs", "w") as f:
    f.write(text)
