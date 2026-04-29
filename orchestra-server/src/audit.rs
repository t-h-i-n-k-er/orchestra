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
use tokio::sync::broadcast;

type HmacSha256 = Hmac<Sha256>;

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    tx: broadcast::Sender<AuditEvent>,
    hmac_key: Vec<u8>,
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
            hmac_key: hmac_key.to_vec(),
        })
    }

    /// Convenience: derive the HMAC key from a shared secret string using
    /// a simple SHA-256 hash of the secret bytes.  This is deterministic
    /// so the same secret always yields the same key.
    pub fn derive_hmac_key(secret: &str) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.finalize().to_vec()
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
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
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
                let mut f = poisoned.into_inner();
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
    /// Tampered entries (HMAC mismatch) are flagged with `[TAMPERED]` in the
    /// details field.
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

            let mut event: AuditEvent = match serde_json::from_str(json_line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Verify HMAC.
            let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
                .expect("HMAC key length is always valid");
            mac.update(json_line.as_bytes());
            match mac.verify_slice(&hex::decode(stored_hmac).unwrap_or_default()) {
                Ok(()) => {}
                Err(_) => {
                    // Flag tampered entry.
                    event.details = format!("[TAMPERED] {}", event.details);
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
