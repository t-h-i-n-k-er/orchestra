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
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

mod poly;
mod stub_emitter;

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

    /// Base64-encoded 32-byte AES-256 key (required for standard mode; omit with --poly).
    #[arg(long)]
    key: Option<String>,

    /// Path to a file containing a 32-byte Ed25519 private key for signing.
    #[arg(long)]
    signing_key: Option<PathBuf>,

    /// Polymorphic mode: randomly select an encryption scheme and key each run.
    ///
    /// Produces a POLY-format blob (see payload-packager/src/poly.rs for the
    /// wire format).  The --key argument is ignored in this mode.
    #[arg(long, conflicts_with = "key")]
    poly: bool,

    /// Write the generated Rust decryption stub to this file (only with --poly).
    ///
    /// The emitted source defines `pub fn poly_decrypt(ciphertext: &[u8]) -> Vec<u8>`
    /// with the scheme and key hardcoded; the code structure varies per build.
    #[arg(long, requires = "poly")]
    stub_out: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    let mut plaintext = std::fs::read(&cli.input)
        .with_context(|| format!("Failed to read input file {}", cli.input.display()))?;

    if let Some(signing_key_path) = cli.signing_key {
        let signing_key_bytes = std::fs::read(signing_key_path)?;
        let signing_key = SigningKey::from_bytes(signing_key_bytes.as_slice().try_into()?);
        let signature = signing_key.sign(&plaintext);
        let mut signed_payload = Vec::with_capacity(64 + plaintext.len());
        signed_payload.extend_from_slice(signature.to_bytes().as_ref());
        signed_payload.append(&mut plaintext);
        plaintext = signed_payload;
    }

    if cli.poly {
        // ── Polymorphic mode ────────────────────────────────────────────────
        let blob = poly::poly_wrap(&plaintext);
        let serialized = poly::poly_serialize(&blob, rand::thread_rng().gen::<u64>());

        std::fs::write(&cli.output, &serialized)
            .with_context(|| format!("Failed to write poly output {}", cli.output.display()))?;

        tracing::info!(
            input  = %cli.input.display(),
            output = %cli.output.display(),
            scheme = ?blob.scheme,
            key_bytes = blob.key.len(),
            payload_bytes = serialized.len(),
            "polymorphic payload packaged"
        );
        println!("poly scheme: {:?}", blob.scheme);
        println!("key length:  {} bytes", blob.key.len());
        println!("output size: {} bytes", serialized.len());

        if let Some(stub_path) = cli.stub_out {
            let stub_source = poly::poly_emit_stub(&blob);
            std::fs::write(&stub_path, &stub_source)
                .with_context(|| format!("Failed to write stub to {}", stub_path.display()))?;
            tracing::info!(stub = %stub_path.display(), "decryption stub written");
            println!("stub written: {}", stub_path.display());
        }

        return Ok(());
    }

    // ── Standard AES-256-GCM mode ───────────────────────────────────────────
    let key_str = cli
        .key
        .ok_or_else(|| anyhow::anyhow!("--key is required in standard mode"))?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&key_str)
        .context("--key is not valid Base64")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "--key must decode to exactly 32 bytes (got {})",
            key_bytes.len()
        );
    }

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
