import re

with open('common/src/config.rs', 'r') as f:
    text = f.read()

sleep_config = """
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
"""

if "pub struct SleepConfig" not in text:
    # Insert before Config struct
    text = text.replace("#[derive(Serialize, Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {", sleep_config + "\n#[derive(Serialize, Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {\n    #[serde(default)]\n    pub sleep: SleepConfig,")

    text = text.replace("port_scan_timeout_ms: default_port_scan_timeout(),", "port_scan_timeout_ms: default_port_scan_timeout(),\n            sleep: SleepConfig::default(),")

with open('common/src/config.rs', 'w') as f:
    f.write(text)

