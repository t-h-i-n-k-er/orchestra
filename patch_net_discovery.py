import sys

with open('agent/src/net_discovery.rs', 'r') as f:
    orig = f.read()

orig = orig.replace("""    let output = crate::process_spoof::execute_command("arp", &["-a"], true)
        .args(["-a"])
        .output()
        .map_err(|e| format!("failed to run arp -a: {e}"))?;""",
"""    let output = crate::process_spoof::execute_command("arp", &["-a"], true)
        .map_err(|e| format!("failed to run arp -a: {e}"))?;""")

with open('agent/src/net_discovery.rs', 'w') as f:
    f.write(orig)
