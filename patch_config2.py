with open("common/src/config.rs", "r") as f:
    text = f.read()
    
# Wait, let's just use `Default::default()` in the `Default` block.
text = text.replace("pub struct Config {", """#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecStrategy {
    #[default]
    Indirect,
    Direct,
    Fallback,
}

pub struct Config {""").replace(
    "pub allowed_paths: Vec<String>,",
    "pub allowed_paths: Vec<String>,\n    #[serde(default)]\n    pub exec_strategy: ExecStrategy,"
).replace(
    "..Default::default()",
    "exec_strategy: ExecStrategy::Default,\n            ..Default::default()"
)

with open("common/src/config.rs", "w") as f:
    f.write(text)
