use anyhow::Result;
use common::config::Config;
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
pub fn load_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(&path)?;
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
            module_signing_key: None,
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
