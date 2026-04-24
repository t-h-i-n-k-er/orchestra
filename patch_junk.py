import os
import glob
import re

def patch_files():
    rs_files = ["agent/src/main.rs", "agent/src/lib.rs", "agent/src/evasion.rs", "agent/src/shell.rs", "launcher/src/main.rs"]
    
    for f in rs_files:
        if not os.path.exists(f): continue
        with open(f, 'r') as fp:
            content = fp.read()
            
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            # Only inside main or specific functions safely
            if (line.startswith('fn main(') or line.startswith('pub fn patch_') or line.startswith('pub fn execute_')) and '{' in line:
                new_lines.append("    junk_macro::insert_junk!();")
        
        with open(f, 'w') as fp:
            fp.write('\n'.join(new_lines))

if __name__ == '__main__':
    patch_files()
