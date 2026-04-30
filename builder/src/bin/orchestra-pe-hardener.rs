//! Orchestra PE Hardener — standalone CLI front-end.
//!
//! Wraps the `pe_artifact_kit` library module from the `builder` crate.
//! The core four hardening operations are always applied.  Additional
//! operations can be requested with optional flags.
//!
//! Usage:
//!   orchestra-pe-hardener <input> <output> [options]
//!
//! Options:
//!   --strip-signature        Remove any existing digital signature
//!   --strip-debug            Remove the debug directory (PDB path)
//!   --manifest <preset>      Inject RT_MANIFEST; preset: asInvoker,
//!                            requireAdministrator, highestAvailable
//!   --icon <path>            Inject RT_ICON/RT_GROUP_ICON from a .ico file
//!   --version-info <json>    Inject VS_VERSIONINFO from a JSON object
//!                            (keys: file_version, product_version, company_name,
//!                             file_description, product_name, original_filename,
//!                             legal_copyright, comments, file_version_name,
//!                             clone_from)

use builder::pe_artifact_kit;
use builder::config::VersionInfoConfig;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <input_pe> <output_pe> [--strip-signature] [--strip-debug] \
                  [--manifest <preset>] [--icon <path>] [--version-info <json>]",
                  args[0]);
        std::process::exit(1);
    }

    let input_path  = &args[1];
    let output_path = &args[2];

    // Parse optional flags.
    let mut strip_signature = false;
    let mut strip_debug = false;
    let mut manifest: Option<String> = None;
    let mut icon_path: Option<String> = None;
    let mut version_info: Option<VersionInfoConfig> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--strip-signature" => { strip_signature = true; }
            "--strip-debug"     => { strip_debug = true; }
            "--manifest" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--manifest requires an argument");
                    std::process::exit(1);
                }
                manifest = Some(args[i].clone());
            }
            "--icon" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--icon requires a path argument");
                    std::process::exit(1);
                }
                icon_path = Some(args[i].clone());
            }
            "--version-info" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--version-info requires a JSON argument");
                    std::process::exit(1);
                }
                version_info = Some(
                    serde_json::from_str(&args[i])
                        .map_err(|e| format!("Invalid --version-info JSON: {e}"))?
                );
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let mut buffer = fs::read(input_path)?;

    // Always apply the four core hardening operations.
    pe_artifact_kit::apply_hardening_only(&mut buffer);

    // Optional operations.
    if strip_signature {
        pe_artifact_kit::strip_signature(&mut buffer);
    }
    if strip_debug {
        pe_artifact_kit::strip_debug_directory(&mut buffer);
    }
    if let Some(ref vi) = version_info {
        pe_artifact_kit::inject_version_info(&mut buffer, vi)?;
    }
    if let Some(ref ico) = icon_path {
        pe_artifact_kit::inject_icon(&mut buffer, ico)?;
    }
    if let Some(ref m) = manifest {
        pe_artifact_kit::inject_manifest(&mut buffer, m)?;
    }

    // Always recalculate the PE checksum after any modifications.
    pe_artifact_kit::recalculate_checksum(&mut buffer);

    fs::write(output_path, &buffer)?;
    println!("PE hardened successfully.");
    Ok(())
}
