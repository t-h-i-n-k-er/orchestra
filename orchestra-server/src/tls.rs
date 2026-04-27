//! TLS configuration for the operator-facing HTTPS listener.
//!
//! If both a cert and key path are configured, those PEM files are loaded.
//! Otherwise a self-signed certificate is generated in-memory at startup
//! (suitable for development / single-tenant deployments behind a real
//! reverse proxy).
//!
//! ## Certificate pinning
//!
//! When an operator-supplied certificate is loaded, this module logs the
//! SHA-256 DER fingerprint at startup.  Use that value as
//! `server_cert_fingerprint` in your agent `agent.toml` to enable TLS
//! certificate pinning on the agent side:
//!
//! ```text
//! # In agent.toml:
//! server_cert_fingerprint = "<hex fingerprint printed at server startup>"
//! ```
//!
//! To compute the fingerprint offline:
//! ```sh
//! openssl x509 -in server.crt -outform DER | sha256sum
//! ```

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Compute the SHA-256 fingerprint of the first PEM certificate in `pem_bytes`
/// and return it as a lowercase colon-separated hex string.
fn cert_fingerprint(pem_bytes: &[u8]) -> Option<String> {
    // Find the first base64 body between -----BEGIN CERTIFICATE----- markers.
    let text = std::str::from_utf8(pem_bytes).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")?;
    let rest = &text[start + 27..];
    let end = rest.find("-----END CERTIFICATE-----")?;
    let b64: String = rest[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD.decode(&b64).ok()?;
    let digest = Sha256::digest(&der);
    Some(digest.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""))
}

pub async fn build(cert: Option<&Path>, key: Option<&Path>) -> Result<RustlsConfig> {
    match (cert, key) {
        (Some(c), Some(k)) => {
            let pem_bytes = std::fs::read(c)
                .with_context(|| format!("reading TLS cert from {}", c.display()))?;
            if let Some(fp) = cert_fingerprint(&pem_bytes) {
                tracing::info!(
                    cert = %c.display(),
                    fingerprint = %fp,
                    "TLS certificate loaded — use this fingerprint as \
                     `server_cert_fingerprint` in agent.toml for pinning"
                );
            }
            RustlsConfig::from_pem_file(c, k).await.with_context(|| {
                format!(
                    "loading TLS material from {} / {}",
                    c.display(),
                    k.display()
                )
            })
        }
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
            if let Some(fp) = cert_fingerprint(pem_cert.as_bytes()) {
                tracing::info!(
                    fingerprint = %fp,
                    "Self-signed TLS certificate generated — \
                     use this fingerprint as `server_cert_fingerprint` in agent.toml for pinning"
                );
            }
            let pem_key = cert.key_pair.serialize_pem();
            RustlsConfig::from_pem(pem_cert.into_bytes(), pem_key.into_bytes())
                .await
                .context("self-signed RustlsConfig")
        }
    }
}
