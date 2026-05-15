//! Tiny static-file HTTP server for local Orchestra QA.
//!
//! Use during development to host an encrypted payload produced by
//! `payload-packager` so the `launcher` can fetch it from
//! `http://localhost:<port>/<file>`. **Not** intended for production: there is
//! no TLS, no auth, no rate limiting.

use anyhow::Result;
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

#[derive(Parser, Debug)]
#[command(author, version, about = "Serve a directory over HTTP for local QA.")]
struct Cli {
    /// TCP port to bind on `127.0.0.1`.
    #[arg(long, default_value_t = 8000)]
    port: u16,

    /// Directory to serve.
    #[arg(long, default_value = ".")]
    directory: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();
    let dir = cli
        .directory
        .canonicalize()
        .unwrap_or(cli.directory.clone());
    let addr: SocketAddr = ([127, 0, 0, 1], cli.port).into();

    tracing::info!(directory = %dir.display(), %addr, "starting dev-server");

    let app = Router::new()
        .fallback_service(ServeDir::new(dir))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
