//! Agent configuration loading, HMAC integrity verification, and hot-reload.
//!
//! This module handles loading the agent's TOML configuration file from
//! `~/.config/orchestra/agent.toml`. Key features:
//!
//! - **HMAC integrity verification**: If the config file includes a
//!   `# hmac = <hex>` comment, the HMAC-SHA256 is verified using the shared
//!   secret before loading.
//! - **SHA-256 companion check**: An optional `.sha256` sidecar file can be
//!   used for additional integrity verification.
//! - **Hot-reload**: When the `hot-reload` feature is enabled, a filesystem
//!   watcher automatically reloads the config on changes with 500ms debounce.
//! - **Kill-date enforcement**: The agent will refuse to start if the current
//!   date is at or past the configured kill date.
//! - **Caching**: Loaded configs are cached with mtime tokens to avoid
//!   redundant file reads and deserialization.

#![allow(unexpected_cfgs)]

use anyhow::{Context as _, Result};
use common::config::Config;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::UNIX_EPOCH;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

const BAKED_SHARED_SECRET: Option<&str> = option_env!("ORCHESTRA_C_SECRET");
const BAKED_CONFIG_HMAC: Option<&str> = option_env!("ORCHESTRA_CONFIG_HMAC");

// Dependency note: this module expects `hmac` and `hex` in agent/Cargo.toml.
// Prompt scope is limited to config.rs, so dependency additions are tracked
// here as a reminder when applying this change set.

static LAST_MTIME: AtomicU64 = AtomicU64::new(0);
static LAST_CONFIG: once_cell::sync::Lazy<StdRwLock<Option<Config>>> =
    once_cell::sync::Lazy::new(|| StdRwLock::new(None));

/// Thread-safe handle to the agent configuration.
///
/// Wrapped in `Arc<RwLock<Config>>` to allow shared ownership and concurrent
/// read access with exclusive write access during hot-reloads.
pub type ConfigHandle = Arc<RwLock<Config>>;

fn resolve_shared_secret() -> Option<String> {
    let runtime = std::env::var("ORCHESTRA_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if cfg!(debug_assertions) {
        runtime.or_else(|| BAKED_SHARED_SECRET.map(str::to_string))
    } else {
        BAKED_SHARED_SECRET.map(str::to_string).or(runtime)
    }
}

fn resolve_expected_config_hmac() -> Option<String> {
    let runtime = std::env::var("ORCHESTRA_CONFIG_HMAC")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if cfg!(debug_assertions) {
        runtime.or_else(|| BAKED_CONFIG_HMAC.map(str::to_string))
    } else {
        BAKED_CONFIG_HMAC.map(str::to_string).or(runtime)
    }
}

fn sha256_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let fname = p
        .file_name()
        .map(|n| format!("{}.sha256", n.to_string_lossy()))
        .unwrap_or_else(|| "agent.toml.sha256".to_string());
    p.set_file_name(fname);
    p
}

fn file_mtime_token(path: &Path) -> Result<u64> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    let modified = metadata
        .modified()
        .with_context(|| format!("reading mtime for {}", path.display()))?;
    let dur = modified.duration_since(UNIX_EPOCH).unwrap_or_default();
    let nanos = dur.as_nanos();
    Ok(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn combined_mtime_token(path: &Path) -> Result<u64> {
    let config_mtime = file_mtime_token(path)?;
    let sha_path = sha256_path(path);
    let sha_mtime = if sha_path.exists() {
        file_mtime_token(&sha_path)?
    } else {
        0
    };
    Ok(config_mtime ^ sha_mtime.rotate_left(1))
}

fn cached_config() -> Option<Config> {
    LAST_CONFIG
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

fn update_cache(config: &Config, token: u64) {
    LAST_MTIME.store(token, Ordering::Release);
    if let Ok(mut guard) = LAST_CONFIG.write() {
        *guard = Some(config.clone());
    }
}

/// Return the default configuration file path.
///
/// Resolves to `~/.config/orchestra/agent.toml`. Falls back to
/// `./.config/orchestra/agent.toml` if the home directory cannot be found.
pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("orchestra")
        .join("agent.toml")
}

fn compute_config_hmac(raw_toml: &[u8]) -> [u8; 32] {
    let key_material = resolve_shared_secret()
        .unwrap_or_else(|| "orchestra-config-integrity-v1".to_string());
    let mut mac = HmacSha256::new_from_slice(key_material.as_bytes())
        .expect("HMAC key length is valid");
    mac.update(raw_toml);
    mac.finalize().into_bytes().into()
}

fn verify_config_hmac(config_bytes: &[u8], expected_hmac: &str) -> Result<bool> {
    let key_material = resolve_shared_secret().ok_or_else(|| {
        anyhow::anyhow!(
            "shared secret is not configured; cannot verify config HMAC"
        )
    })?;

    let expected_bytes = hex::decode(expected_hmac.trim())
        .with_context(|| "config HMAC is not valid hex")?;

    let mut mac = HmacSha256::new_from_slice(key_material.as_bytes())
        .with_context(|| "failed to initialize HMAC verifier")?;
    mac.update(config_bytes);
    Ok(mac.verify_slice(&expected_bytes).is_ok())
}

/// Compute and append an HMAC-SHA256 tag to the configuration file.
///
/// Reads the file at `config_path`, strips any existing `# hmac = ...` line,
/// computes HMAC-SHA256 over the remaining content, and rewrites the file
/// with the tag appended as a comment.
pub fn append_config_hmac(config_path: &std::path::Path) -> anyhow::Result<()> {
    // NOTE: this function requires the `hex` crate in the `agent` crate deps.
    let raw = std::fs::read_to_string(config_path)?;
    let content = raw
        .lines()
        .filter(|l| !l.starts_with("# hmac = "))
        .collect::<Vec<_>>()
        .join("\n");
    let hmac_bytes = compute_config_hmac(content.as_bytes());
    let hmac_hex = hex::encode(hmac_bytes);
    let signed = format!("{}\n# hmac = {}\n", content, hmac_hex);
    std::fs::write(config_path, signed)?;
    Ok(())
}

/// Load agent configuration from `~/.config/orchestra/agent.toml`.
/// Returns a default [`Config`] when the file does not exist yet.
/// If the last line is `# hmac = <hex>`, the HMAC-SHA256 is verified against
/// the file contents excluding that tag line. A mismatch aborts loading.
/// If no tag exists, loading continues for backward compatibility.
///
/// If a `.sha256` companion file exists, its contents are checked against the
/// SHA-256 digest of the config file and loading is aborted on mismatch.
pub fn load_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        let cfg = Config::default();
        update_cache(&cfg, 0);
        return Ok(cfg);
    }

    let mtime_token = combined_mtime_token(&path)?;
    if LAST_MTIME.load(Ordering::Acquire) == mtime_token {
        if let Some(cfg) = cached_config() {
            return Ok(cfg);
        }
    }

    let raw = std::fs::read(&path)?;
    let content = std::str::from_utf8(&raw)
        .with_context(|| format!("config file is not valid UTF-8: {}", path.display()))?;

    let lines: Vec<&str> = content.lines().collect();
    let (content_for_parse, hmac_tag) = if let Some(last) = lines.last() {
        if let Some(tag) = last.strip_prefix("# hmac = ") {
            (lines[..lines.len().saturating_sub(1)].join("\n"), Some(tag))
        } else {
            (content.to_string(), None)
        }
    } else {
        (String::new(), None)
    };

    if let Some(expected_hmac) = hmac_tag {
        match verify_config_hmac(content_for_parse.as_bytes(), expected_hmac) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    path = %path.display(),
                    "config integrity verification failed for embedded hmac tag"
                );
                anyhow::bail!(
                    "Config integrity check failed: HMAC mismatch for {}",
                    path.display()
                );
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "config integrity verification failed for embedded hmac tag"
                );
                anyhow::bail!(
                    "Config integrity check failed: HMAC verification error for {}",
                    path.display()
                );
            }
        }
    } else {
        tracing::info!(
            path = %path.display(),
            "Config file has no integrity tag - set one with orchestra-keygen config-hmac <path>"
        );
    }

    // Integrity check: if agent.toml.sha256 is present, verify before parsing.
    let sha_path = sha256_path(&path);
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

    let config: Config = toml::from_str(&content_for_parse)?;

    if let Some(expected_hmac) = resolve_expected_config_hmac() {
        match verify_config_hmac(content_for_parse.as_bytes(), &expected_hmac) {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!(
                    path = %path.display(),
                    "config integrity verification failed for ORCHESTRA_CONFIG_HMAC; aborting"
                );
                anyhow::bail!(
                    "Config integrity check failed: ORCHESTRA_CONFIG_HMAC mismatch for {}",
                    path.display()
                );
            }
            Err(err) => {
                tracing::error!(
                    path = %path.display(),
                    error = %err,
                    "config integrity verification errored for ORCHESTRA_CONFIG_HMAC; aborting"
                );
                anyhow::bail!(
                    "Config integrity check failed: ORCHESTRA_CONFIG_HMAC verification error for {}",
                    path.display()
                );
            }
        }
    }

    update_cache(&config, mtime_token);
    Ok(config)
}

/// Load the agent configuration and wrap it in a [`ConfigHandle`].
///
/// Equivalent to [`load_config`] but returns the config wrapped in
/// `Arc<RwLock<Config>>` for shared ownership across tasks.
pub fn load_config_handle() -> Result<ConfigHandle> {
    let config = load_config()?;
    Ok(Arc::new(RwLock::new(config)))
}

/// Reload the configuration from disk into an existing [`ConfigHandle`].
///
/// Acquires a write lock on the handle and replaces the config with a
/// freshly loaded one. Used by the hot-reload watcher and manual
/// `ReloadConfig` commands.
pub async fn reload_config(handle: &ConfigHandle) -> Result<()> {
    let new_config = load_config()?;
    let mut guard = handle.write().await;
    *guard = new_config;
    Ok(())
}

#[allow(unexpected_cfgs)]
#[cfg(feature = "hot-reload")]
fn is_relevant_change_event(event: &notify::Event, config_file: &Path, sha_file: &Path) -> bool {
    if !matches!(
        event.kind,
        notify::EventKind::Create(_)
            | notify::EventKind::Modify(_)
            | notify::EventKind::Remove(_)
    ) {
        return false;
    }

    let cfg_name = config_file.file_name();
    let sha_name = sha_file.file_name();

    if event.paths.is_empty() {
        return true;
    }

    event.paths.iter().any(|p| {
        p == config_file
            || p == sha_file
            || p.file_name() == cfg_name
            || p.file_name() == sha_name
    })
}

#[allow(unexpected_cfgs)]
#[cfg(feature = "hot-reload")]
async fn debounce_reload_window(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    config_file: &Path,
    sha_file: &Path,
) {
    use tokio::time::{Duration, Instant};

    let mut deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(Ok(event))) => {
                if is_relevant_change_event(&event, config_file, sha_file) {
                    // Reset debounce timer after each relevant write burst.
                    deadline = Instant::now() + Duration::from_millis(500);
                }
            }
            Ok(Some(Err(err))) => {
                tracing::warn!(error = %err, "hot-reload: watcher event error");
            }
            Ok(None) | Err(_) => break,
        }
    }
}

/// Spawn a background watcher for `agent.toml` hot-reloads.
///
/// When the `hot-reload` feature is enabled, this watches the config directory
/// and applies a debounced reload (500ms) whenever `agent.toml` or
/// `agent.toml.sha256` changes. Invalid updates are rejected and the old config
/// remains active.
///
/// Without `hot-reload`, this returns `Ok(None)`.
#[allow(unexpected_cfgs)]
pub fn spawn_config_watcher(handle: ConfigHandle) -> Result<Option<tokio::task::JoinHandle<()>>> {
    #[cfg(feature = "hot-reload")]
    {
        use notify::{RecursiveMode, Watcher};

        let config_file = config_path();
        let sha_file = sha256_path(&config_file);
        let Some(watch_dir) = config_file.parent() else {
            tracing::warn!("hot-reload: config parent directory is unavailable");
            return Ok(None);
        };
        if !watch_dir.exists() {
            tracing::warn!(
                path = %watch_dir.display(),
                "hot-reload: config directory does not exist; watcher not started"
            );
            return Ok(None);
        }

        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = tx.send(event);
        })
        .context("creating notify watcher")?;
        watcher
            .watch(watch_dir, RecursiveMode::NonRecursive)
            .with_context(|| format!("watching {}", watch_dir.display()))?;

        let task = tokio::spawn(async move {
            // Keep the watcher alive for the task lifetime.
            let _watcher = watcher;
            while let Some(next) = rx.recv().await {
                let event = match next {
                    Ok(event) => event,
                    Err(err) => {
                        tracing::warn!(error = %err, "hot-reload: watcher event error");
                        continue;
                    }
                };
                if !is_relevant_change_event(&event, &config_file, &sha_file) {
                    continue;
                }

                debounce_reload_window(&mut rx, &config_file, &sha_file).await;

                match reload_config(&handle).await {
                    Ok(()) => {
                        tracing::info!("hot-reload: applied updated configuration");
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "hot-reload: invalid configuration update rejected; keeping previous config"
                        );
                    }
                }
            }
        });

        return Ok(Some(task));
    }

    #[cfg(not(feature = "hot-reload"))]
    {
        let _ = handle;
        Ok(None)
    }
}

/// Verify that the current date (UTC) is before the given kill date.
///
/// `kill_date` must be in `YYYY-MM-DD` format.  This is a transport-
/// independent check so that kill-date enforcement works regardless of
/// which transport features are compiled in.
pub fn check_kill_date(kill_date: &str) -> Result<()> {
    let parts: Vec<&str> = kill_date.splitn(3, '-').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid kill_date format '{}'; expected YYYY-MM-DD", kill_date);
    }
    let y: u32 = parts[0].parse().map_err(|_| anyhow::anyhow!("invalid kill_date year"))?;
    let m: u32 = parts[1].parse().map_err(|_| anyhow::anyhow!("invalid kill_date month"))?;
    let d: u32 = parts[2].parse().map_err(|_| anyhow::anyhow!("invalid kill_date day"))?;
    let kd_val = y * 10_000 + m * 100 + d;

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days_since_epoch = secs / 86400;
    let (ty, tm, td) = days_to_ymd(days_since_epoch);
    let today_val = ty * 10_000 + tm * 100 + td;

    if today_val >= kd_val {
        anyhow::bail!("kill date {} has passed; agent refusing to connect", kill_date);
    }
    Ok(())
}

/// Convert days since the Unix epoch (1970-01-01) to (year, month, day).
/// Algorithm: http://howardhinnant.github.io/date_algorithms.html#civil_from_days
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
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
