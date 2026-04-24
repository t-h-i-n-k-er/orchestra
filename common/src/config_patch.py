import re
with open('common/src/config.rs', 'r') as f:
    text = f.read()

enum_text = """
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecStrategy {
    #[default]
    Indirect,
    Direct,
    Fallback,
}

"""
text = text.replace("#[derive(Serialize, Deserialize, Debug, Clone)]\npub struct Config {", enum_text + "#[derive(Serialize, Deserialize, Debug, Clone)]\npub struct Config {\n    #[serde(default)]\n    pub exec_strategy: ExecStrategy,")

with open('common/src/config.rs', 'w') as f:
    f.write(text)
