//! Tiny static-file HTTP server for local Orchestra QA.
//!
//! Use during development to host an encrypted payload produced by
//! `payload-packager` so the `launcher` can fetch it from
//! `http://localhost:<port>/<file>`. **Not** intended for production: there is
//! no TLS, no auth, no rate limiting.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use warp::Filter;

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
    let dir = cli.directory.canonicalize().unwrap_or(cli.directory.clone());
    let addr: SocketAddr = ([127, 0, 0, 1], cli.port).into();

    tracing::info!(directory = %dir.display(), %addr, "starting dev-server");

    let routes = warp::fs::dir(dir.clone()).with(warp::log::custom(|info| {
        tracing::info!(
            method = %info.method(),
            path = info.path(),
            status = info.status().as_u16(),
            "request"
        );
    }));

    let (_addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received");
        });
    server.await;
    Ok(())
}
