use anyhow::Result;
use base64::Engine;
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate keypairs for Orchestra.")]
struct Cli {
    /// Generate a keypair for module signing.
    #[arg(long)]
    module_signing_key: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.module_signing_key {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        println!("// Ed25519 keypair for module signing");
        println!("// Private key (32 bytes, hex):");
        println!("{}", hex::encode(signing_key.to_bytes()));
        println!("// Public key (32 bytes, hex):");
        println!("{}", hex::encode(verifying_key.to_bytes()));

        println!("\n// Private key (Base64):");
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes())
        );
        println!("// Public key (Base64):");
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes())
        );
    }

    Ok(())
}
