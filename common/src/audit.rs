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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_populates_fields() {
        let evt = AuditEvent::new("agent-1", "admin", "login", "via ssh", Outcome::Success);
        assert_eq!(evt.agent_id, "agent-1");
        assert_eq!(evt.user, "admin");
        assert_eq!(evt.action, "login");
        assert_eq!(evt.details, "via ssh");
        assert!(matches!(evt.outcome, Outcome::Success));
        assert!(!evt.tampered);
        // Timestamp should be a reasonable Unix epoch value (> year 2020).
        assert!(evt.timestamp > 1577836800);
    }

    #[test]
    fn outcome_failure() {
        let evt = AuditEvent::new("a", "u", "act", "det", Outcome::Failure);
        assert!(matches!(evt.outcome, Outcome::Failure));
    }

    #[test]
    fn tampered_default_is_false() {
        let evt = AuditEvent::new("a", "u", "act", "det", Outcome::Success);
        assert!(!evt.tampered);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let evt = AuditEvent::new("agent-42", "root", "exec", "ls -la", Outcome::Success);
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, evt.agent_id);
        assert_eq!(parsed.user, evt.user);
        assert_eq!(parsed.action, evt.action);
        assert_eq!(parsed.details, evt.details);
        assert_eq!(parsed.timestamp, evt.timestamp);
        assert!(!parsed.tampered);
    }

    #[test]
    fn deserialize_missing_tampered_defaults_false() {
        // JSON without the `tampered` field should deserialize with tampered = false.
        let json = r#"{
            "timestamp": 1700000000,
            "agent_id": "a",
            "user": "u",
            "action": "act",
            "details": "d",
            "outcome": "Success"
        }"#;
        let parsed: AuditEvent = serde_json::from_str(json).unwrap();
        assert!(!parsed.tampered);
    }

    #[test]
    fn outcome_serialization() {
        assert_eq!(
            serde_json::to_string(&Outcome::Success).unwrap(),
            "\"Success\""
        );
        assert_eq!(
            serde_json::to_string(&Outcome::Failure).unwrap(),
            "\"Failure\""
        );
    }

    #[test]
    fn timestamp_is_reasonable() {
        let evt1 = AuditEvent::new("a", "u", "act", "det", Outcome::Success);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let evt2 = AuditEvent::new("a", "u", "act", "det", Outcome::Success);
        // Second event should have a >= timestamp.
        assert!(evt2.timestamp >= evt1.timestamp);
    }
}
