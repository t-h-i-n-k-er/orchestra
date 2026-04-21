//! Append-only JSON-Lines audit log + in-process broadcast channel.

use common::{AuditEvent, Outcome};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::broadcast;

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    tx: broadcast::Sender<AuditEvent>,
}

impl AuditLog {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
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
        })
    }

    pub fn record(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit serialize error: {e}");
                return;
            }
        };
        if let Ok(mut f) = self.file.lock() {
            if let Err(e) = writeln!(f, "{line}") {
                tracing::error!("audit write error: {e}");
            } else {
                let _ = f.flush();
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
    /// Used by the dashboard's history endpoint; not on the hot path.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let body = match std::fs::read_to_string(&self.path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<AuditEvent> = body
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if out.len() > limit {
            let drop = out.len() - limit;
            out.drain(0..drop);
        }
        out
    }
}
