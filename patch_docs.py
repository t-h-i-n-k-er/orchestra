import os

def insert_doc(filepath, docstring):
    if not os.path.exists(filepath): return
    with open(filepath, "r") as f:
        content = f.read()
    if "//! " not in content[:50]:
        with open(filepath, "w") as f:
            f.write(docstring + "\n" + content)

evasion_doc = """//! Evasion mechanisms including HWBP-based AMSI/ETW bypass, PPID spoofing, argument spoofing, and callback execution.
//! 
//! # Operation
//! - HWBP AMSI/ETW Bypass: Uses thread context hardware debug registers (Dr0-Dr3) to intercept execution at AMSI/ETW boundaries.
//! - PPID Spoofing: Manipulates thread attributes during process creation to masquerade the parent process.
//! - Argument Spoofing: Modifies the PEB command line at runtime.
//! 
//! # Required Privileges
//! Standard user privileges are generally sufficient, though certain target processes for PPID spoofing may require SeDebugPrivilege.
//! 
//! # Compatibility
//! Windows 10+ only (relies on specific offsets and newer thread context manipulation APIs).
"""
insert_doc("agent/src/evasion.rs", evasion_doc)

syscall_doc = """//! Indirect syscalls and clean NTDLL mapping.
//! 
//! # Operation
//! Maps a fresh copy of `ntdll.dll` from disk to bypass user-land hooks placed by EDRs in the naturally loaded `ntdll.dll`.
//! Syscalls are made indirectly using JMP gadgets to spoof the call stack.
//! 
//! # Required Privileges
//! Standard user privileges.
//! 
//! # Compatibility
//! Windows 8+ (relies on structure of NTDLL on modern Windows).
"""
insert_doc("agent/src/syscalls.rs", syscall_doc)

mg_doc = """//! Sleep encryption and memory guarding.
//! 
//! # Operation
//! Encrypts the agent's heap and readable memory segments during idle sleep periods.
//! The key is temporarily held in CPU registers (e.g., XMM) or managed via ROP chains to prevent memory scanners from finding the plaintext agent.
//! 
//! # Required Privileges
//! Standard user privileges.
//! 
//! # Compatibility
//! Cross-platform (Linux/Windows), though exact memory protection APIs (mprotect vs VirtualProtect) differ.
"""
insert_doc("agent/src/memory_guard.rs", mg_doc)

