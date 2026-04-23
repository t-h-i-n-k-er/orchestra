import re

with open('agent/src/syscalls.rs', 'r') as f:
    orig = f.read()

print("Original size:", len(orig))
