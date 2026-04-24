with open("common/src/config.rs", "r") as f:
    t = f.read()

enum_def = """
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecStrategy {
    #[default]
    Indirect,
    Direct,
    Fallback,
}

"""

t = t.replace("#[derive(Serialize, Deserialize, Debug, Clone)]\npub struct Config {", enum_def + "#[derive(Serialize, Deserialize, Debug, Clone)]\n#[serde(rename_all = \"kebab-case\")]\npub struct Config {\n    #[serde(default)]\n    pub exec_strategy: ExecStrategy,")
with open("common/src/config.rs", "w") as f:
    f.write(t)
