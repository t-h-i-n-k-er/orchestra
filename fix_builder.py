with open("builder/src/config.rs", "r") as f:
    content = f.read()

config_old = """    let profile = PayloadConfig {
        target_os,
        target_arch,
        c2_address,
        encryption_key,
        hmac_key: hmac_key_b64,
        c_server_secret,
        features,
        output_name: None,
        package: "launcher".to_string(),
        bin_name: None,
    };"""

config_new = """    let profile = PayloadConfig {
        target_os,
        target_arch,
        c2_address,
        encryption_key,
        hmac_key: hmac_key_b64,
        c_server_secret,
        server_cert_fingerprint: None,
        features,
        output_name: None,
        package: "launcher".to_string(),
        bin_name: None,
    };"""

content = content.replace(config_old, config_new)

test_old = """        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "file:key.bin".to_string(),
            hmac_key: "file:hmac.bin".to_string(),
            c_server_secret: Some("secret".to_string()),
            features: vec!["persistence".to_string()],
            output_name: Some("test_agent".to_string()),
            package: "agent-standalone".to_string(),
            bin_name: Some("agent-standalone".to_string()),
        };"""

test_new = """        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "file:key.bin".to_string(),
            hmac_key: "file:hmac.bin".to_string(),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: None,
            features: vec!["persistence".to_string()],
            output_name: Some("test_agent".to_string()),
            package: "agent-standalone".to_string(),
            bin_name: Some("agent-standalone".to_string()),
        };"""

content = content.replace(test_old, test_new)

test2_old = """        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "short".to_string(),
            hmac_key: "also short".to_string(),
            c_server_secret: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };"""

test2_new = """        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "short".to_string(),
            hmac_key: "also short".to_string(),
            c_server_secret: None,
            server_cert_fingerprint: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };"""

content = content.replace(test2_old, test2_new)

test3_old = """        let profile = PayloadConfig {
            target_os: "amiga".to_string(),
            target_arch: "m68k".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "a".repeat(44), // 32 bytes b64
            hmac_key: "b".repeat(44),
            c_server_secret: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };"""

test3_new = """        let profile = PayloadConfig {
            target_os: "amiga".to_string(),
            target_arch: "m68k".to_string(),
            c2_address: "127.0.0.1:8443".to_string(),
            encryption_key: "a".repeat(44), // 32 bytes b64
            hmac_key: "b".repeat(44),
            c_server_secret: None,
            server_cert_fingerprint: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };"""
content = content.replace(test3_old, test3_new)

with open("builder/src/config.rs", "w") as f:
    f.write(content)
