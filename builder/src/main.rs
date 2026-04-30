//! Orchestra Builder — unified CLI for producing deployable agent payloads.

mod build;
mod config;
mod deps;
mod pe_artifact_kit;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::config::{list_profiles, load_profile};

#[derive(Parser, Debug)]
#[command(
    name = "orchestra-builder",
    version,
    about = "Build, configure, and package Orchestra agent payloads."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Verify host has all required toolchains/packages.
    Setup {
        /// Attempt to install missing rust targets via `rustup target add`.
        #[arg(long)]
        auto_install: bool,
    },
    /// Interactively create a new profile and save it under `profiles/`.
    Configure {
        /// Profile name (file will be `profiles/<name>.toml`).
        #[arg(long)]
        name: Option<String>,
    },
    /// List all `profiles/*.toml` entries.
    ListProfiles,
    /// Print a single profile's contents.
    ShowProfile {
        /// Profile name (without `.toml`) or full path to a TOML file.
        name: String,
    },
    /// Build the agent for a profile and emit `dist/<name>.enc`.
    Build {
        /// Profile name (without `.toml`).
        name: String,
        /// Reserved for build-time code diversification; currently disabled.
        #[arg(long)]
        diversify: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Setup { auto_install } => deps::cmd_setup(auto_install),
        Cmd::Configure { name } => config::cmd_configure(name),
        Cmd::ListProfiles => {
            for profile in list_profiles()? {
                println!("{}", profile);
            }
            Ok(())
        }
        Cmd::ShowProfile { name } => {
            let profile = load_profile(&name)?;
            println!("{}", toml::to_string_pretty(&profile)?);
            Ok(())
        }
        Cmd::Build { name, diversify } => {
            let profile = load_profile(&name)?;
            let enc_key = profile.encryption_key_bytes()?;

            let agent_bytes =
                build::build_agent_for_profile(&profile).context("Failed to build agent")?;

            let final_agent_bytes = if diversify {
                info!("Applying code diversification passes...");
                #[cfg(feature = "diversification")]
                {
                    optimizer::apply_passes_to_binary(&agent_bytes)
                        .map_err(|e| anyhow::anyhow!("diversification failed: {e}"))?
                }
                #[cfg(not(feature = "diversification"))]
                {
                    anyhow::bail!(
                        "code diversification is not compiled in; rebuild the builder with \
                         `cargo build --features diversification` to enable this feature"
                    );
                }
            } else {
                agent_bytes
            };

            let encrypted_bytes =
                common::CryptoSession::from_shared_secret(&enc_key).encrypt(&final_agent_bytes);

            let dist_dir = std::path::PathBuf::from("dist");
            if !dist_dir.exists() {
                std::fs::create_dir(&dist_dir)?;
            }
            let output_name = profile.output_name.as_deref().unwrap_or(&name);
            let out_path = dist_dir.join(format!("{}.enc", output_name));
            std::fs::write(&out_path, encrypted_bytes)?;
            info!("Encrypted payload written to {}", out_path.display());
            Ok(())
        }
    }
}
