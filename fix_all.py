import os
import re

# 1. Fix lib.rs to call orchestrate_layers
with open("agent/src/lib.rs", "r") as f:
    lib_rs = f.read()
if "amsi_defense::orchestrate_layers();" not in lib_rs:
    lib_rs = lib_rs.replace(
        "evasion::patch_amsi();",
        "evasion::patch_amsi();\n            amsi_defense::orchestrate_layers();"
    )
    with open("agent/src/lib.rs", "w") as f:
        f.write(lib_rs)

