use anyhow::Result;
use common::config::Config;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("orchestra")
        .join("agent.toml")
}

/// Load agent configuration from `~/.config/orchestra/agent.toml`.
/// Returns a default [`Config`] when the file does not exist yet.
/// If a `.sha256` companion file exists, its contents are checked against the
/// SHA-256 digest of the config file and loading is aborted on mismatch (M-37).
pub fn load_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(&path)?;

    // Integrity check: if agent.toml.sha256 is present, verify before parsing.
    let sha_path = {
        let mut p = path.clone();
        let fname = p
            .file_name()
            .map(|n| format!("{}.sha256", n.to_string_lossy()))
            .unwrap_or_else(|| "agent.toml.sha256".to_string());
        p.set_file_name(fname);
        p
    };
    if sha_path.exists() {
        let expected = std::fs::read_to_string(&sha_path)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let actual = format!("{:x}", Sha256::digest(content.as_bytes()));
        if actual != expected {
            anyhow::bail!(
                "Config integrity check failed: SHA-256 mismatch for {}",
                path.display()
            );
        }
    }

    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_allowed_paths() {
        let cfg = Config::default();
        assert!(!cfg.allowed_paths.is_empty());
    }

    #[test]
    fn default_config_disables_persistence() {
        assert!(!Config::default().persistence_enabled);
    }

    #[test]
    fn toml_round_trip() {
        let original = Config {
            port_scan_timeout_ms: 1000,
            port_scan_concurrency: 10,
            allowed_paths: vec!["/tmp".into(), "/var/log".into()],
            heartbeat_interval_secs: 60,
            persistence_enabled: false,
            module_repo_url: "https://example.com".into(),
            module_aes_key: None,
            module_verify_key: None,
            module_cache_dir: common::config::default_module_cache_dir(),
            traffic_profile: Default::default(),
            required_domain: None,
            refuse_in_vm: false,
            server_cert_fingerprint: None,
            ..Default::default()
        };
        let serialized = toml::to_string(&original).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.allowed_paths, original.allowed_paths);
        assert_eq!(deserialized.heartbeat_interval_secs, 60);
    }

    /// Verify that path validation logic respects the allowed-paths list.
    #[test]
    fn path_validation_respects_allowed_list() {
        let cfg = Config {
            allowed_paths: vec!["/var/log".into()],
            ..Config::default()
        };
        let allowed = |p: &str| cfg.allowed_paths.iter().any(|a| p.starts_with(a.as_str()));
        assert!(allowed("/var/log/syslog"));
        assert!(!allowed("/etc/shadow"));
        assert!(!allowed("/home/user/secret"));
    }
}
