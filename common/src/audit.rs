use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub agent_id: String,
    pub user: String,
    pub action: String,
    pub details: String,
    pub outcome: Outcome,
    /// P2-10: `true` if the HMAC verification of this entry failed when
    /// read back from the audit log, indicating the persisted line was
    /// tampered with after it was written.  Fresh events always have
    /// `tampered: false`.
    #[serde(default)]
    pub tampered: bool,
}

impl AuditEvent {
    pub fn new(agent_id: &str, user: &str, action: &str, details: &str, outcome: Outcome) -> Self {
        Self {
            // P2-15: use unwrap_or(0) for timestamp — practically infallible
            // but avoids a panic if system clock is misconfigured.
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs(),
            agent_id: agent_id.to_string(),
            user: user.to_string(),
            action: action.to_string(),
            details: details.to_string(),
            outcome,
            tampered: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Outcome {
    Success,
    Failure,
}
