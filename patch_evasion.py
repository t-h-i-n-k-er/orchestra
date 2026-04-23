import sys

content = open('agent/src/evasion.rs', 'r').read()

old_code = """use std::sync::atomic::{AtomicUsize, Ordering};

static AMSI_ADDR: AtomicUsize = AtomicUsize::new(0);
static ETW_ADDR: AtomicUsize = AtomicUsize::new(0);"""

new_code = """#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
static AMSI_ADDR: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static ETW_ADDR: AtomicUsize = AtomicUsize::new(0);"""

content = content.replace(old_code, new_code)
with open('agent/src/evasion.rs', 'w') as f:
    f.write(content)
