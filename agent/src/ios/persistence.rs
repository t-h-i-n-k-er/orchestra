//! iOS persistence mechanisms.
//!
//! Implements persistence installation, removal, checking, and repair
//! for the iOS platform.
//!
//! Stub implementation — returns errors until full iOS persistence
//! is implemented (Prompt 8).

use anyhow::Result;

/// Install iOS persistence.
///
/// Full implementation will support:
/// - Jailbroken: LaunchDaemon PLIST, LaunchAgent PLIST, Cydia Substrate tweak
/// - Non-jailbroken: Background fetch, BGProcessingTask, silent push,
///   significant location changes, VoIP push, audio background mode
pub fn install_persistence() -> Result<()> {
    Err(anyhow::anyhow!("iOS persistence not yet implemented"))
}

/// Remove previously installed persistence.
pub fn remove_persistence() -> Result<()> {
    Err(anyhow::anyhow!(
        "iOS persistence removal not yet implemented"
    ))
}

/// Check if persistence is currently active.
pub fn check_persistence() -> Result<bool> {
    Ok(false)
}

/// Repair broken persistence.
pub fn repair_persistence() -> Result<()> {
    Err(anyhow::anyhow!(
        "iOS persistence repair not yet implemented"
    ))
}

/// List all active persistence mechanisms.
pub fn list_persistence() -> Result<Vec<String>> {
    Ok(Vec::new())
}
