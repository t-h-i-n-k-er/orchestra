#![allow(unexpected_cfgs)]

use anyhow::{Context as _, Result};
use common::config::Config;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::UNIX_EPOCH;
use tokio::sync::RwLock;

static LAST_MTIME: AtomicU64 = AtomicU64::new(0);
static LAST_CONFIG: once_cell::sync::Lazy<StdRwLock<Option<Config>>> =
    once_cell::sync::Lazy::new(|| StdRwLock::new(None));

pub type ConfigHandle = Arc<RwLock<Config>>;

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

    let content = std::fs::read_to_string(&path)?;

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

    let config: Config = toml::from_str(&content)?;
    update_cache(&config, mtime_token);
    Ok(config)
}

pub fn load_config_handle() -> Result<ConfigHandle> {
    let config = load_config()?;
    Ok(Arc::new(RwLock::new(config)))
}

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
