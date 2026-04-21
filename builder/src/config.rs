//! Configuration profiles for the Orchestra Builder.
//!
//! A `PayloadConfig` describes everything the builder needs to know to produce
//! a single agent payload: where it should run, what features it should ship
//! with, and which AES-256 key should encrypt the resulting binary. Profiles
//! are persisted to `profiles/<name>.toml` so that operators can keep a small
//! library of reproducible build recipes (one per deployment target).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Directory (relative to the workspace root) where profiles live.
pub const PROFILES_DIR: &str = "profiles";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConfig {
    /// `"linux"`, `"windows"`, or `"macos"`.
    pub target_os: String,
    /// `"x86_64"` or `"aarch64"`.
    pub target_arch: String,
    /// Address of the Control Center / management endpoint, e.g. `"10.0.0.5:8444"`.
    pub c2_address: String,
    /// Either a base64-encoded 32-byte AES key, or `file:/path/to/key.bin`
    /// (the file is read at build time). Used to encrypt the payload binary.
    pub encryption_key: String,
    /// Pre-shared secret the agent uses for its AES-TCP connection to the
    /// Control Center. Must match `agent_shared_secret` in `orchestra-server.toml`.
    /// Required when `outbound-c` is in `features`. If absent the agent will
    /// look for the `ORCHESTRA_SECRET` runtime environment variable.
    #[serde(default)]
    pub c_server_secret: Option<String>,
    /// Cargo feature flags to enable on the agent crate.
    #[serde(default)]
    pub features: Vec<String>,
    /// Optional override for the encrypted output filename (without
    /// extension). Defaults to the profile name.
    #[serde(default)]
    pub output_name: Option<String>,
    /// Cargo package to build as the payload. Defaults to `launcher`.
    #[serde(default = "default_package")]
    pub package: String,
    /// Name of the binary target within `package`. Defaults to `package`.
    /// Set to `"agent-standalone"` when building with `outbound-c`.
    #[serde(default)]
    pub bin_name: Option<String>,
}

fn default_package() -> String {
    "launcher".to_string()
}

impl PayloadConfig {
    /// Cargo target triple derived from `target_os` and `target_arch`.
    pub fn target_triple(&self) -> Result<String> {
        let triple = match (self.target_os.as_str(), self.target_arch.as_str()) {
            ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
            ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
            ("windows", "x86_64") => "x86_64-pc-windows-gnu",
            ("windows", "aarch64") => "aarch64-pc-windows-msvc",
            ("macos", "x86_64") => "x86_64-apple-darwin",
            ("macos", "aarch64") => "aarch64-apple-darwin",
            (os, arch) => return Err(anyhow!("Unsupported target combination: {os}/{arch}")),
        };
        Ok(triple.to_string())
    }

    /// Resolve the encryption key into raw 32 bytes.
    pub fn resolve_key(&self) -> Result<Vec<u8>> {
        use base64::Engine;

        let raw = if let Some(path) = self.encryption_key.strip_prefix("file:") {
            std::fs::read(path).with_context(|| format!("Failed to read key file {path}"))?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(self.encryption_key.trim())
                .context("encryption_key is not valid base64 (or `file:<path>`)")?
        };

        if raw.len() != 32 {
            return Err(anyhow!(
                "AES-256 key must be exactly 32 bytes (got {})",
                raw.len()
            ));
        }
        Ok(raw)
    }
}

/// Path to the profile file for a given name.
pub fn profile_path(name: &str) -> PathBuf {
    Path::new(PROFILES_DIR).join(format!("{name}.toml"))
}

/// Load a profile by name (no `.toml` suffix) or by direct path.
pub fn load_profile(name_or_path: &str) -> Result<PayloadConfig> {
    let path = if Path::new(name_or_path).is_file() {
        PathBuf::from(name_or_path)
    } else {
        profile_path(name_or_path)
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read profile {}", path.display()))?;
    let cfg: PayloadConfig =
        toml::from_str(&text).with_context(|| format!("Invalid TOML in {}", path.display()))?;
    Ok(cfg)
}

/// Persist a profile to `profiles/<name>.toml`.
pub fn save_profile(name: &str, cfg: &PayloadConfig) -> Result<PathBuf> {
    std::fs::create_dir_all(PROFILES_DIR)
        .with_context(|| format!("Failed to create {PROFILES_DIR}/"))?;
    let path = profile_path(name);
    let text = toml::to_string_pretty(cfg).context("Failed to serialize profile")?;
    std::fs::write(&path, text).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(path)
}

/// List every `*.toml` file in `profiles/`.
pub fn list_profiles() -> Result<Vec<String>> {
    let dir = Path::new(PROFILES_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn round_trip_profile() {
        let cfg = PayloadConfig {
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            c2_address: "127.0.0.1:8444".into(),
            encryption_key: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            c_server_secret: Some("my-secret".into()),
            features: vec!["persistence".into()],
            output_name: None,
            package: "launcher".into(),
            bin_name: None,
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: PayloadConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.target_triple().unwrap(), "x86_64-unknown-linux-gnu");
        assert_eq!(parsed.resolve_key().unwrap().len(), 32);
    }

    #[test]
    fn rejects_short_key() {
        let cfg = PayloadConfig {
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            c2_address: "x".into(),
            encryption_key: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
            c_server_secret: None,
            features: vec![],
            output_name: None,
            package: "launcher".into(),
            bin_name: None,
        };
        assert!(cfg.resolve_key().is_err());
    }

    #[test]
    fn rejects_unknown_triple() {
        let cfg = PayloadConfig {
            target_os: "plan9".into(),
            target_arch: "x86_64".into(),
            c2_address: String::new(),
            encryption_key: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            c_server_secret: None,
            features: vec![],
            output_name: None,
            package: "launcher".into(),
            bin_name: None,
        };
        assert!(cfg.target_triple().is_err());
    }
}
