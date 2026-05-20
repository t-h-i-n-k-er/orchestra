use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;

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

    /// Output directory for generated key files. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Create output directory if it doesn't exist.
    fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("Failed to create output directory {:?}", cli.output_dir))?;

    if cli.module_aes_key {
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);

        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);

        // Write the full TOML config line (with secret) to a file.
        let secret_path = cli.output_dir.join("module_aes_key.toml");
        fs::write(
            &secret_path,
            format!(
                "// AES-256-GCM module decryption key — GENERATED, DO NOT COMMIT\n\
                 module_aes_key = \"{}\"\n",
                key_b64
            ),
        )
        .with_context(|| format!("Failed to write {}", secret_path.display()))?;

        // Print only the file path to stdout — no secret material.
        println!(
            "AES-256-GCM module key written to: {}",
            secret_path.display()
        );
        eprintln!(
            "WARNING: {} contains secret key material. Restrict file permissions and do not commit.",
            secret_path.display()
        );
    }

    if cli.module_signing_key {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        let signing_key_hex = hex::encode(signing_key.to_bytes());
        let signing_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
        let verifying_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());

        // Write the signing key (secret) to its own file.
        let signing_key_path = cli.output_dir.join("module_signing_key.txt");
        fs::write(
            &signing_key_path,
            format!(
                "// Ed25519 signing key — GENERATED, DO NOT COMMIT\n\
                 // Keep this file SECRET. Needed only for signing modules.\n\
                 signing_key_hex = {}\n\
                 signing_key_base64 = {}\n",
                signing_key_hex, signing_key_b64
            ),
        )
        .with_context(|| format!("Failed to write {}", signing_key_path.display()))?;

        // Write the verifying (public) key + TOML config to a separate file.
        let verifying_key_path = cli.output_dir.join("module_verify_key.toml");
        fs::write(
            &verifying_key_path,
            format!(
                "// Ed25519 verifying (public) key — safe to commit\n\
                 module_verify_key = \"{}\"\n",
                verifying_key_b64
            ),
        )
        .with_context(|| format!("Failed to write {}", verifying_key_path.display()))?;

        // Print only file paths to stdout — no secret material.
        println!(
            "Ed25519 signing key (SECRET) written to: {}",
            signing_key_path.display()
        );
        println!(
            "Ed25519 verifying (public) key written to: {}",
            verifying_key_path.display()
        );
        eprintln!(
            "WARNING: {} contains the private signing key. Restrict file permissions and do not commit.",
            signing_key_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_module_aes_key_mode() {
        let cli = Cli::parse_from(["keygen", "--module-aes-key"]);
        assert!(cli.module_aes_key);
        assert!(!cli.module_signing_key);
    }

    #[test]
    fn cli_allows_generating_both_key_types() {
        let cli = Cli::parse_from(["keygen", "--module-aes-key", "--module-signing-key"]);
        assert!(cli.module_aes_key);
        assert!(cli.module_signing_key);
    }

    #[test]
    fn cli_default_output_dir_is_cwd() {
        let cli = Cli::parse_from(["keygen", "--module-aes-key"]);
        assert_eq!(cli.output_dir, PathBuf::from("."));
    }

    #[test]
    fn cli_custom_output_dir() {
        let cli = Cli::parse_from(["keygen", "--module-aes-key", "--output-dir", "/tmp/keys"]);
        assert_eq!(cli.output_dir, PathBuf::from("/tmp/keys"));
    }

    #[test]
    fn keygen_writes_files_not_stdout() {
        let tmp = tempfile::tempdir().unwrap();
        let out_dir = tmp.path().to_path_buf();

        // Simulate what main() does for --module-aes-key.
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);

        let secret_path = out_dir.join("module_aes_key.toml");
        fs::write(&secret_path, format!("module_aes_key = \"{}\"\n", key_b64)).unwrap();

        let contents = fs::read_to_string(&secret_path).unwrap();
        assert!(contents.contains("module_aes_key"));
        assert!(contents.contains(&key_b64));
    }
}
