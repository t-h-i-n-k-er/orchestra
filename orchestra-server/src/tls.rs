//! TLS configuration for the operator-facing HTTPS listener.
//!
//! If both a cert and key path are configured, those PEM files are loaded.
//! Otherwise a self-signed certificate is generated in-memory at startup
//! (suitable for development / single-tenant deployments behind a real
//! reverse proxy).

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::path::Path;

pub async fn build(cert: Option<&Path>, key: Option<&Path>) -> Result<RustlsConfig> {
    match (cert, key) {
        (Some(c), Some(k)) => RustlsConfig::from_pem_file(c, k)
            .await
            .with_context(|| format!("loading TLS material from {} / {}", c.display(), k.display())),
        _ => {
            tracing::warn!(
                "No TLS cert configured; generating an in-memory self-signed certificate. \
                 For production, terminate TLS at a reverse proxy or supply tls_cert_path/tls_key_path."
            );
            let cert = rcgen::generate_simple_self_signed(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ])?;
            let pem_cert = cert.cert.pem();
            let pem_key = cert.key_pair.serialize_pem();
            RustlsConfig::from_pem(pem_cert.into_bytes(), pem_key.into_bytes())
                .await
                .context("self-signed RustlsConfig")
        }
    }
}
