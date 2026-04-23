with open("builder/src/build.rs", "r") as f:
    content = f.read()

env_old = """    if effective_features.iter().any(|f| f == "outbound-c") {
        extra_env.push(("ORCHESTRA_C_ADDR".into(), cfg.c2_address.clone()));
        if let Some(ref secret) = cfg.c_server_secret {
            extra_env.push(("ORCHESTRA_C_SECRET".into(), secret.clone()));
        } else {"""

env_new = """    if effective_features.iter().any(|f| f == "outbound-c") {
        extra_env.push(("ORCHESTRA_C_ADDR".into(), cfg.c2_address.clone()));
        if let Some(ref fp) = cfg.server_cert_fingerprint {
            extra_env.push(("ORCHESTRA_C_CERT_FP".into(), fp.clone()));
        }
        if let Some(ref secret) = cfg.c_server_secret {
            extra_env.push(("ORCHESTRA_C_SECRET".into(), secret.clone()));
        } else {"""

content = content.replace(env_old, env_new)

with open("builder/src/build.rs", "w") as f:
    f.write(content)

with open("builder/src/config.rs", "r") as f:
    content2 = f.read()
    
# check if server_cert_fingerprint is in config
if "server_cert_fingerprint" not in content2:
    config_old = """    /// Required for outbound-c: the Orchestrator's Pre-Shared Key.
    pub c_server_secret: Option<String>,"""
    
    config_new = """    /// Required for outbound-c: the Orchestrator's Pre-Shared Key.
    pub c_server_secret: Option<String>,
    /// Optional fingerprint to compile into the agent for TLS pinning.
    pub server_cert_fingerprint: Option<String>,"""
    
    content2 = content2.replace(config_old, config_new)
    with open("builder/src/config.rs", "w") as f:
        f.write(content2)

