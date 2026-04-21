//! Orchestra payload packaging utility.
//!
//! Produces an AES-256-GCM encrypted payload from a plaintext agent binary so
//! that it can be served to managed endpoints over HTTPS and consumed by the
//! `launcher` component. The output format is a single binary file:
//!
//! ```text
//! [12-byte random nonce][AES-256-GCM ciphertext (includes auth tag)]
//! ```
//!
//! This format is identical to what `common::CryptoSession::encrypt` already
//! produces, which guarantees that any agent capable of constructing a
//! `CryptoSession` from the same shared key can decrypt the payload.
//!
//! # Why this exists
//!
//! Secure software distribution: encryption protects the **confidentiality**
//! of agent updates in transit, while AES-GCM's authentication tag protects
//! their **integrity**. The packager is a stand-alone CLI so that build
//! pipelines or release engineers can produce reproducible artefacts without
//! linking the encryption code into every consumer.

use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use common::CryptoSession;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Encrypt an Orchestra agent binary into a deployable payload."
)]
struct Cli {
    /// Plaintext agent binary to encrypt.
    #[arg(long)]
    input: PathBuf,

    /// Destination path for the encrypted payload.
    #[arg(long)]
    output: PathBuf,

    /// Base64-encoded 32-byte AES-256 key.
    #[arg(long)]
    key: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cli.key)
        .context("--key is not valid Base64")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "--key must decode to exactly 32 bytes (got {})",
            key_bytes.len()
        );
    }

    let plaintext = std::fs::read(&cli.input)
        .with_context(|| format!("Failed to read input file {}", cli.input.display()))?;

    let plaintext_hash = {
        let mut h = Sha256::new();
        h.update(&plaintext);
        h.finalize()
    };

    let session = CryptoSession::from_shared_secret(&key_bytes);
    let payload = session.encrypt(&plaintext);

    std::fs::write(&cli.output, &payload)
        .with_context(|| format!("Failed to write output file {}", cli.output.display()))?;

    tracing::info!(
        input = %cli.input.display(),
        output = %cli.output.display(),
        plaintext_bytes = plaintext.len(),
        payload_bytes = payload.len(),
        plaintext_sha256 = %hex(&plaintext_hash),
        "payload packaged successfully"
    );

    println!("plaintext sha256: {}", hex(&plaintext_hash));
    println!("payload size: {} bytes", payload.len());

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
