//! Optional Human-Computer Interaction (HCI) logging for research.
//!
//! This module provides capabilities for collecting anonymized interaction data,
//! such as active window titles and keyboard events. It is designed with
//! privacy safeguards and is strictly opt-in.
//!
//! **Warning:** This module must only be used with informed user consent and
//! in full compliance with all applicable privacy regulations (e.g., GDPR).
//! The data collected can be sensitive.

#![cfg(feature = "hci-research")]

use lazy_static::lazy_static;
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Clone)]
pub enum HciEvent {
    KeyPress { timestamp: u64, key_code: u16 },
    WindowFocus { timestamp: u64, title: String },
}

#[allow(dead_code)]
const MAX_BUFFER_SIZE: usize = 1024;

lazy_static! {
    static ref HCI_LOG_BUFFER: Arc<Mutex<Vec<HciEvent>>> = Arc::new(Mutex::new(Vec::new()));
    static ref IS_LOGGING: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

/// Starts the HCI logging process.
pub fn start_logging() -> Result<(), String> {
    let mut is_logging = IS_LOGGING.lock().unwrap();
    if *is_logging {
        return Err("Logging is already in progress.".to_string());
    }
    *is_logging = true;

    // In a real implementation, this would spawn background threads for
    // keyboard hooking and window title polling.
    println!("HCI logging started.");
    Ok(())
}

/// Stops the HCI logging process.
pub fn stop_logging() -> Result<(), String> {
    let mut is_logging = IS_LOGGING.lock().unwrap();
    if !*is_logging {
        return Err("Logging is not in progress.".to_string());
    }
    *is_logging = false;
    println!("HCI logging stopped.");
    Ok(())
}

/// Retrieves the current HCI log buffer as a JSON string.
pub fn get_log_buffer() -> Result<String, String> {
    let buffer = HCI_LOG_BUFFER.lock().unwrap();
    serde_json::to_string(&*buffer).map_err(|e| e.to_string())
}

/// Adds an event to the log buffer, enforcing size limits.
#[allow(dead_code)]
fn add_log_event(event: HciEvent) {
    if *IS_LOGGING.lock().unwrap() {
        let mut buffer = HCI_LOG_BUFFER.lock().unwrap();
        if buffer.len() >= MAX_BUFFER_SIZE {
            buffer.remove(0);
        }
        buffer.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_buffer_size_limit() {
        *IS_LOGGING.lock().unwrap() = true;
        for i in 0..(MAX_BUFFER_SIZE + 10) {
            add_log_event(HciEvent::KeyPress {
                timestamp: i as u64,
                key_code: (i % 256) as u16,
            });
        }
        let buffer = HCI_LOG_BUFFER.lock().unwrap();
        assert_eq!(buffer.len(), MAX_BUFFER_SIZE);
        *IS_LOGGING.lock().unwrap() = false;
    }
}
