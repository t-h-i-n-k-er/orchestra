use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub agent_id: String,
    pub user: String,
    pub action: String,
    pub details: String,
    pub outcome: Outcome,
}

impl AuditEvent {
    pub fn new(agent_id: &str, user: &str, action: &str, details: &str, outcome: Outcome) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            agent_id: agent_id.to_string(),
            user: user.to_string(),
            action: action.to_string(),
            details: details.to_string(),
            outcome,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Outcome {
    Success,
    Failure,
}
