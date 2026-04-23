//! Orchestra Control Center entry point.

use anyhow::Result;
use clap::Parser;
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, state::AppState, tls,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    // rustls 0.23 with the `ring` backend requires a process-wide default
    // CryptoProvider. Install it before any TLS code paths run.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
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

    if cfg.admin_token == "change-me-admin-token" {
        tracing::warn!(
            "admin_token is the default placeholder; set a strong value in your config or via --admin-token"
        );
    }

    let audit = Arc::new(AuditLog::open(cfg.audit_log_path.clone())?);
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

    // Operator HTTPS server.
    let app = api::router(state.clone(), cfg.static_dir.clone());
    tracing::info!(addr = %cfg.http_addr, "operator HTTPS listening");
    axum_server::bind_rustls(cfg.http_addr, tls_cfg)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
