use anyhow::Result;
use base64::Engine;
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate keypairs for Orchestra.")]
struct Cli {
    /// Generate an AES-256-GCM module decryption key (set as `module_aes_key` in agent.toml).
    #[arg(long)]
    module_aes_key: bool,

    /// Generate an Ed25519 keypair for module signature verification
    /// (set `module_verify_key` to the public key in agent.toml).
    #[arg(long)]
    module_signing_key: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.module_aes_key {
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);
        println!("// AES-256-GCM module decryption key");
        println!("// Set as `module_aes_key` in agent.toml");
        println!(
            "module_aes_key = \"{}\"",
            base64::engine::general_purpose::STANDARD.encode(key)
        );
    }

    if cli.module_signing_key {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        println!("// Ed25519 keypair for module signing");
        println!("// Signing key (32 bytes, hex) — keep this SECRET:");
        println!("{}", hex::encode(signing_key.to_bytes()));
        println!("// Verifying (public) key (32 bytes, hex):");
        println!("{}", hex::encode(verifying_key.to_bytes()));

        println!("\n// Signing key (Base64) — keep this SECRET:");
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes())
        );
        println!("// Set as `module_verify_key` in agent.toml:");
        println!(
            "module_verify_key = \"{}\"",
            base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes())
        );
    }

    Ok(())
}
