//! Append-only JSON-Lines audit log + in-process broadcast channel.
//! Each event is written as two lines: the JSON payload, then an HMAC-SHA256
//! hex digest computed over that exact JSON line.  On read, every pair is
//! verified and tampered entries are flagged.

use common::{AuditEvent, Outcome};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use rand::RngCore;
use base64::Engine as _;
use tokio::sync::broadcast;

type HmacSha256 = Hmac<Sha256>;

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    tx: broadcast::Sender<AuditEvent>,
    /// P1-07: HMAC key locked in RAM via `mlock`/`VirtualLock`, zeroized on
    /// drop.  Prevents the key from being written to swap or core dumps.
    hmac_key: common::LockedSecret,
}

impl AuditLog {
    pub fn open(path: PathBuf, hmac_key: &[u8]) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let (tx, _rx) = broadcast::channel(256);
        Ok(Self {
            path,
            file: Mutex::new(file),
            tx,
            hmac_key: common::LockedSecret::new(hmac_key),
        })
    }

    /// Load or generate the audit HMAC key.
    ///
    /// Priority:
    /// 1. If `configured_key_b64` is `Some`, decode and use it directly.
    /// 2. If a key file exists at `key_path`, load and use it.
    /// 3. Otherwise generate a fresh random 32-byte key and persist it to
    ///    `key_path` so the same key is used across restarts.
    ///
    /// The key file is `<audit_log_path>.key` (e.g. `audit.jsonl.key`).
    pub fn load_or_generate_hmac_key(
        configured_key_b64: Option<&str>,
        key_path: &std::path::Path,
    ) -> anyhow::Result<Vec<u8>> {
        // 1. Explicit config takes precedence.
        if let Some(b64) = configured_key_b64 {
            let key = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| anyhow::anyhow!("invalid base64 in audit_hmac_key: {e}"))?;
            if key.len() != 32 {
                anyhow::bail!("audit_hmac_key must be exactly 32 bytes (got {})", key.len());
            }
            return Ok(key);
        }

        // 2. Try loading from the persisted key file.
        if key_path.exists() {
            let b64 = std::fs::read_to_string(key_path)?;
            let key = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| anyhow::anyhow!("corrupt audit key file {}: {e}", key_path.display()))?;
            if key.len() != 32 {
                anyhow::bail!(
                    "audit key file must contain exactly 32 bytes (got {})",
                    key.len()
                );
            }
            return Ok(key);
        }

        // 3. Generate a new random key and persist it.
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        if let Some(parent) = key_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&key);
        std::fs::write(key_path, format!("{b64}\n"))?;
        tracing::info!(
            path = %key_path.display(),
            "generated new audit HMAC key and persisted to file"
        );
        Ok(key)
    }

    pub fn record(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit serialize error: {e}");
                return;
            }
        };

        // Compute HMAC-SHA256 over the JSON line.
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_bytes())
            .expect("HMAC key length is always valid");
        mac.update(line.as_bytes());
        let tag = mac.finalize();
        let hex_tag = hex::encode(tag.into_bytes());

        match self.file.lock() {
            Ok(mut f) => {
                // Write JSON line then HMAC line.
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::error!("audit write error: {e}");
                } else if let Err(e) = writeln!(f, "{hex_tag}") {
                    tracing::error!("audit hmac write error: {e}");
                } else {
                    let _ = f.flush();
                }
            }
            Err(poisoned) => {
                // P2-11: Poisoned mutex recovery — write a marker line before
                // the recovered event so the gap is visible during audit review.
                // The marker makes it clear that an entry may have been lost or
                // partially written when the previous holder panicked.
                let mut f = poisoned.into_inner();

                // Write a gap marker entry.
                let gap_marker = serde_json::json!({
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(std::time::Duration::from_secs(0))
                        .as_secs(),
                    "agent_id": "",
                    "user": "",
                    "action": "AuditGapMarker",
                    "details": "mutex was poisoned — one or more preceding entries may be lost or incomplete",
                    "outcome": "Failure",
                    "tampered": false,
                });
                let gap_line = serde_json::to_string(&gap_marker).unwrap_or_default();
                let mut gap_mac = HmacSha256::new_from_slice(self.hmac_key.as_bytes())
                    .expect("HMAC key length is always valid");
                gap_mac.update(gap_line.as_bytes());
                let gap_hex = hex::encode(gap_mac.finalize().into_bytes());
                let _ = writeln!(f, "{gap_line}");
                let _ = writeln!(f, "{gap_hex}");
                let _ = f.flush();

                if let Err(e) = writeln!(f, "{line}") {
                    tracing::error!("audit write error: {e}");
                } else if let Err(e) = writeln!(f, "{hex_tag}") {
                    tracing::error!("audit hmac write error: {e}");
                } else {
                    let _ = f.flush();
                }
            }
        }
        let _ = self.tx.send(event);
    }

    pub fn record_simple(
        &self,
        agent_id: &str,
        user: &str,
        action: &str,
        details: &str,
        outcome: Outcome,
    ) {
        self.record(AuditEvent::new(agent_id, user, action, details, outcome));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.tx.subscribe()
    }

    /// Returns up to `limit` most recent audit events by re-reading the log.
    /// Each event in the log is stored as two lines: JSON then HMAC hex digest.
    ///
    /// P2-10: Tampered entries (HMAC mismatch) are now **included** in the
    /// result with their `tampered` flag set to `true` and `[TAMPERED]` prefixed
    /// to the details field, rather than being silently dropped.  A server-wide
    /// alert is also broadcast on the existing `broadcast::Sender` so that
    /// connected dashboard clients are notified immediately.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let body = match std::fs::read_to_string(&self.path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let lines: Vec<&str> = body.lines().collect();
        let mut out: Vec<AuditEvent> = Vec::new();

        // Process pairs: JSON line + HMAC line.
        let mut i = 0;
        while i + 1 < lines.len() {
            let json_line = lines[i];
            let stored_hmac = lines[i + 1];
            i += 2;

            let event: AuditEvent = match serde_json::from_str(json_line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Verify HMAC.
            let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_bytes())
                .expect("HMAC key length is always valid");
            mac.update(json_line.as_bytes());
            match mac.verify_slice(&hex::decode(stored_hmac).unwrap_or_default()) {
                Ok(()) => {}
                Err(_) => {
                    // P2-10: Return tampered entries with a flag instead of
                    // silently dropping them.
                    tracing::error!(
                        "[audit] TAMPERED ENTRY DETECTED: agent_id={}, user={}, details={}",
                        event.agent_id, event.user, event.details
                    );
                    let mut tampered_event = event;
                    tampered_event.details = format!("[TAMPERED] {}", tampered_event.details);
                    tampered_event.tampered = true;
                    // Broadcast a server-wide alert so dashboard clients
                    // are notified immediately.
                    let alert = AuditEvent {
                        // P2-15: unwrap_or(0) for timestamp
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or(std::time::Duration::from_secs(0))
                            .as_secs(),
                        agent_id: String::new(),
                        user: String::new(),
                        action: "AuditTamperDetected".into(),
                        details: format!(
                            "HMAC mismatch for entry: agent_id={}, user={}, action={}",
                            tampered_event.agent_id,
                            tampered_event.user,
                            tampered_event.action
                        ),
                        outcome: Outcome::Failure,
                        tampered: false,
                    };
                    let _ = self.tx.send(alert);
                    out.push(tampered_event);
                    continue;
                }
            }

            out.push(event);
        }

        if out.len() > limit {
            let drop = out.len() - limit;
            out.drain(0..drop);
        }
        out
    }
}
