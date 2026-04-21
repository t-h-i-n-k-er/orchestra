use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub persistence_enabled: bool,
    #[serde(default = "default_module_repo")]
    pub module_repo_url: String,
    /// Base64-encoded AES-256 key used to decrypt signed capability modules.
    pub module_signing_key: Option<String>,
}

fn default_allowed_paths() -> Vec<String> {
    vec!["/var/log".into(), "/home".into(), "/tmp".into()]
}

fn default_heartbeat() -> u64 { 30 }

fn default_module_repo() -> String {
    "https://updates.example.com/modules".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_paths: default_allowed_paths(),
            heartbeat_interval_secs: default_heartbeat(),
            persistence_enabled: false,
            module_repo_url: default_module_repo(),
            module_signing_key: None,
        }
    }
}
