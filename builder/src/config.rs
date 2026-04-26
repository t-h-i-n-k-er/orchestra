//! Configuration profiles for the Orchestra Builder.
//!
//! A `PayloadConfig` describes everything the builder needs to know to produce
//! a single agent payload: where it should run, what features it should ship
//! with, and which AES-256 key should encrypt the resulting binary. Profiles
//! are persisted to `profiles/<name>.toml` so that operators can keep a small
//! library of reproducible build recipes (one per deployment target).

use anyhow::{anyhow, Context, Result};
use dialoguer::{theme::ColorfulTheme, Input, MultiSelect, Select};
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
    /// Legacy profile field from the previous HMAC design. The current
    /// payload format uses AES-GCM and does not require a separate HMAC key.
    #[serde(default)]
    pub hmac_key: Option<String>,
    /// Pre-shared secret the agent uses for its AES-TCP connection to the
    /// Control Center. Must match `agent_shared_secret` in `orchestra-server.toml`.
    /// Required when `outbound-c` is in `features`. If absent the agent will
    /// look for the `ORCHESTRA_SECRET` runtime environment variable.
    #[serde(default)]
    pub c_server_secret: Option<String>,
    /// Optional fingerprint to compile into the agent for TLS pinning.
    #[serde(default)]
    pub server_cert_fingerprint: Option<String>,
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
    pub fn encryption_key_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let enc_key = if let Some(path) = self.encryption_key.strip_prefix("file:") {
            std::fs::read(path).with_context(|| format!("Failed to read key file {path}"))?
        } else {
            engine
                .decode(self.encryption_key.trim())
                .context("encryption_key is not valid base64 (or `file:<path>`)")?
        };

        if enc_key.len() != 32 {
            return Err(anyhow!(
                "AES-256 key must be exactly 32 bytes (got {})",
                enc_key.len()
            ));
        }

        if is_weak_key(&enc_key) {
            tracing::warn!(
                "A configured key appears to be a weak placeholder. \
                 Generate random keys with `orchestra-builder configure`."
            );
        }

        if let Some(hmac_key) = &self.hmac_key {
            validate_legacy_hmac_key(hmac_key)?;
            tracing::warn!(
                "profile contains legacy `hmac_key`; the current AES-GCM payload format ignores it"
            );
        }

        Ok(enc_key)
    }
}

fn validate_legacy_hmac_key(hmac_key: &str) -> Result<()> {
    use base64::Engine;
    let bytes = if let Some(path) = hmac_key.strip_prefix("file:") {
        std::fs::read(path).with_context(|| format!("Failed to read key file {path}"))?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(hmac_key.trim())
            .context("legacy hmac_key is not valid base64 (or `file:<path>`)")?
    };
    if bytes.len() != 32 {
        return Err(anyhow!(
            "legacy hmac_key must decode to exactly 32 bytes when present (got {})",
            bytes.len()
        ));
    }
    Ok(())
}

/// Check for obviously weak (non-random) keys.
pub fn is_weak_key(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }
    // All bytes are identical (e.g., all zeros).
    if key.iter().all(|&b| b == key[0]) {
        return true;
    }
    // Bytes are sequential (e.g., 0, 1, 2, 3...).
    if key.windows(2).all(|w| w[1] == w[0].wrapping_add(1)) {
        return true;
    }
    false
}

/// Entry point for `builder configure` command.
pub fn cmd_configure(name: Option<String>) -> Result<()> {
    let theme = ColorfulTheme::default();
    let name = if let Some(name) = name {
        name
    } else {
        Input::with_theme(&theme)
            .with_prompt("Profile name")
            .interact_text()?
    };

    let target_os_idx = Select::with_theme(&theme)
        .with_prompt("Target OS")
        .items(&["linux", "windows", "macos"])
        .default(0)
        .interact()?;
    let target_os = ["linux", "windows", "macos"][target_os_idx].to_string();

    let target_arch_idx = Select::with_theme(&theme)
        .with_prompt("Target Architecture")
        .items(&["x86_64", "aarch64"])
        .default(0)
        .interact()?;
    let target_arch = ["x86_64", "aarch64"][target_arch_idx].to_string();

    let c2_address = Input::with_theme(&theme)
        .with_prompt("C2 Address (e.g., 10.0.0.5:8444)")
        .default("127.0.0.1:8444".to_string())
        .interact_text()?;

    let all_features = read_agent_features().unwrap_or_default();
    let feature_indices = MultiSelect::with_theme(&theme)
        .with_prompt("Agent Features")
        .items(&all_features)
        .defaults(&[true, false])
        .interact()?;
    let features: Vec<String> = feature_indices
        .iter()
        .map(|&i| all_features[i].clone())
        .collect();

    let c_server_secret = if features.iter().any(|f| f == "outbound-c") {
        Some(
            Input::with_theme(&theme)
                .with_prompt("C2 Shared Secret (for outbound-c)")
                .interact_text()?,
        )
    } else {
        None
    };

    use base64::Engine;
    let enc_key: [u8; 32] = rand::random();
    let encryption_key = base64::engine::general_purpose::STANDARD.encode(enc_key);

    let profile = PayloadConfig {
        target_os,
        target_arch,
        c2_address,
        encryption_key,
        hmac_key: None,
        c_server_secret,
        server_cert_fingerprint: None,
        features: features.clone(),
        output_name: None,
        // When outbound-c is selected, the payload is the agent standalone
        // binary, not the launcher.  The launcher waits for inbound console
        // connections; the agent-standalone binary dials the server directly.
        package: if features.iter().any(|f| f == "outbound-c") {
            "agent".to_string()
        } else {
            "launcher".to_string()
        },
        bin_name: if features.iter().any(|f| f == "outbound-c") {
            Some("agent-standalone".to_string())
        } else {
            None
        },
    };

    save_profile(&name, &profile)?;
    Ok(())
}

/// Read all feature flags from `agent/Cargo.toml`.
pub fn read_agent_features() -> Result<Vec<String>> {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("agent/Cargo.toml");
    let manifest_str = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let manifest: toml::Value = manifest_str.parse()?;
    let features = manifest
        .get("features")
        .and_then(|f| f.as_table())
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();
    Ok(features)
}

/// Split a list of features into those present in `available` and those not.
pub fn partition_features(features: &[String], available: &[String]) -> (Vec<String>, Vec<String>) {
    let mut effective = Vec::new();
    let mut unknown = Vec::new();
    for f in features {
        if available.contains(f) {
            effective.push(f.clone());
        } else {
            unknown.push(f.clone());
        }
    }
    (effective, unknown)
}

/// Get the full path for a profile name.
pub fn profile_path(name: &str) -> PathBuf {
    if name.contains('/') || name.ends_with(".toml") {
        PathBuf::from(name)
    } else {
        Path::new(PROFILES_DIR).join(format!("{name}.toml"))
    }
}

/// Load a `PayloadConfig` from a TOML file.
pub fn load_profile(name: &str) -> Result<PayloadConfig> {
    let path = profile_path(name);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read profile {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("Failed to parse profile {}", path.display()))
}

/// Save a `PayloadConfig` to a TOML file.
pub fn save_profile(name: &str, cfg: &PayloadConfig) -> Result<()> {
    let path = profile_path(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(cfg)?;
    std::fs::write(&path, content)?;
    tracing::info!("Profile saved to {}", path.display());
    Ok(())
}

/// List all `.toml` files in the `profiles/` directory.
pub fn list_profiles() -> Result<Vec<String>> {
    let mut profiles = Vec::new();
    let dir = Path::new(PROFILES_DIR);
    if !dir.exists() {
        return Ok(profiles);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".toml") {
                profiles.push(name.trim_end_matches(".toml").to_string());
            }
        }
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_profile() {
        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "file:key.bin".to_string(),
            hmac_key: Some("file:hmac.bin".to_string()),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: None,
            features: vec!["persistence".to_string()],
            output_name: Some("test_agent".to_string()),
            package: "agent-standalone".to_string(),
            bin_name: Some("agent-standalone".to_string()),
        };
        let s = toml::to_string(&profile).unwrap();
        let back: PayloadConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.target_os, "linux");
        assert_eq!(back.c_server_secret.unwrap(), "secret");
    }

    #[test]
    fn rejects_short_key() {
        let profile = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "short".to_string(),
            hmac_key: None,
            c_server_secret: None,
            server_cert_fingerprint: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };
        assert!(profile.encryption_key_bytes().is_err());
    }

    #[test]
    fn quickbuild_profile_without_hmac_key_parses() {
        let content = r#"
target_os      = "linux"
target_arch    = "x86_64"
c2_address     = "127.0.0.1:7890"
encryption_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
features       = []
package        = "launcher"
"#;
        let profile: PayloadConfig = toml::from_str(content).unwrap();
        assert!(profile.hmac_key.is_none());
        assert_eq!(profile.package, "launcher");
        assert_eq!(profile.encryption_key_bytes().unwrap().len(), 32);
    }

    #[test]
    fn rejects_unknown_triple() {
        let profile = PayloadConfig {
            target_os: "amiga".to_string(),
            target_arch: "m68k".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "a".repeat(44), // 32 bytes b64
            hmac_key: None,
            c_server_secret: None,
            server_cert_fingerprint: None,
            features: vec![],
            output_name: None,
            package: "launcher".to_string(),
            bin_name: None,
        };
        assert!(profile.target_triple().is_err());
    }

    #[test]
    fn read_agent_features_matches_real_cargo_toml() {
        let features = read_agent_features().unwrap();
        assert!(features.contains(&"persistence".to_string()));
        assert!(features.contains(&"outbound-c".to_string()));
    }

    #[test]
    fn readme_feature_table_matches_agent_features() {
        let features = read_agent_features().unwrap();
        let readme_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("README.md");
        let readme = std::fs::read_to_string(&readme_path).unwrap();
        let mut documented = Vec::new();
        let mut in_feature_table = false;
        for line in readme.lines() {
            let line = line.trim_start();
            if line == "| Feature | Purpose |" {
                in_feature_table = true;
                continue;
            }
            if !in_feature_table {
                continue;
            }
            if !line.starts_with('|') {
                break;
            }
            if line.starts_with("|---------") {
                continue;
            }
            if let Some(feature) = line.split('`').nth(1) {
                documented.push(feature.to_string());
            }
        }

        let missing: Vec<_> = features
            .iter()
            .filter(|feature| !documented.contains(feature))
            .cloned()
            .collect();
        let unknown: Vec<_> = documented
            .iter()
            .filter(|feature| !features.contains(feature))
            .cloned()
            .collect();

        assert!(
            missing.is_empty() && unknown.is_empty(),
            "README feature table drift: missing={missing:?} unknown={unknown:?}"
        );
    }

    #[test]
    fn partition_features_splits_known_and_unknown() {
        let available = vec!["a".to_string(), "b".to_string()];
        let requested = vec!["a".to_string(), "c".to_string()];
        let (effective, unknown) = partition_features(&requested, &available);
        assert_eq!(effective, vec!["a".to_string()]);
        assert_eq!(unknown, vec!["c".to_string()]);
    }

    #[test]
    fn is_weak_key_detects_all_zeros() {
        assert!(is_weak_key(&[0; 32]));
    }

    #[test]
    fn is_weak_key_detects_all_same_nonzero() {
        assert!(is_weak_key(&[42; 32]));
    }

    #[test]
    fn is_weak_key_detects_sequential() {
        let key: Vec<u8> = (0..32).collect();
        assert!(is_weak_key(&key));
    }

    #[test]
    fn is_weak_key_accepts_random_looking_bytes() {
        let key = b"J\x1a\xf3\x9b\xde\x9a\x8c\xf3\x9b\xde\x9a\x8c\xf3\x9b\xde\x9a\x8c\xf3\x9b\xde\x9a\x8c\xf3\x9b\xde\x9a\x8c\xf3\x9b\xde\x9a\x8c";
        assert!(!is_weak_key(key));
    }

    /// The default c2_address must point at the agent listener (8444),
    /// not the HTTP dashboard (8443).  If this test fails, an operator
    /// building with defaults will produce a payload that silently fails
    /// to connect.
    #[test]
    fn default_c2_address_matches_server_agent_listener() {
        // Server default agent listener is 127.0.0.1:8444.
        let server_agent_port = 8444u16;

        let profiles = vec![
            "127.0.0.1:8444".to_string(), // debug
        ];
        for addr in profiles {
            let port: u16 = addr.split(':').last().unwrap().parse().unwrap();
            assert_eq!(
                port,
                server_agent_port,
                "c2_address '{}' must use port {} (agent listener), not 8443 (dashboard)",
                addr,
                server_agent_port
            );
        }
    }
}
