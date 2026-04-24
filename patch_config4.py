with open("common/src/config.rs", "r") as f:
    text = f.read()

malleable_config = """
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
    text = text.replace("pub struct Config {", malleable_config + "\n#[derive(Serialize, Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {\n    #[serde(default)]\n    pub malleable_profile: MalleableProfile,")

with open("common/src/config.rs", "w") as f:
    f.write(text)

