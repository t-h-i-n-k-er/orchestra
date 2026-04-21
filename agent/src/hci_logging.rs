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

use chrono::Utc;
use lazy_static::lazy_static;
use rdev::{listen, Event, EventType};
use serde::Serialize;
use std::collections::VecDeque;
use std::fs;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use twox_hash::XxHash64;

const MAX_BUFFER_SIZE: usize = 10_000;

#[derive(Serialize, Clone, Debug)]
pub struct KeyEvent {
    timestamp: u64,
    pressed: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct WindowEvent {
    timestamp: u64,
    title_hash: u64,
}

#[derive(Serialize, Clone, Debug)]
pub enum HciEvent {
    Keyboard(KeyEvent),
    Window(WindowEvent),
}

lazy_static! {
    static ref CONSENT_FILE_PATH: Mutex<String> =
        Mutex::new("/var/run/orchestra-consent".to_string());
    static ref HCI_LOG_BUFFER: Arc<Mutex<VecDeque<HciEvent>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BUFFER_SIZE)));
    static ref IS_LOGGING: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

fn check_consent() -> bool {
    let path = CONSENT_FILE_PATH.lock().unwrap();
    fs::metadata(path.as_str()).is_ok()
}

/// Starts the HCI logging process.
pub fn start_logging() -> Result<(), String> {
    if !check_consent() {
        return Err("HCI research consent not found. Aborting.".to_string());
    }

    let mut is_logging = IS_LOGGING.lock().unwrap();
    if *is_logging {
        return Err("Logging is already in progress.".to_string());
    }
    *is_logging = true;

    let logging_handle = Arc::clone(&IS_LOGGING);
    let buffer_handle = Arc::clone(&HCI_LOG_BUFFER);

    thread::spawn(move || {
        let callback = move |event: Event| {
            if !*logging_handle.lock().unwrap() {
                return;
            }
            let timestamp = Utc::now().timestamp_micros() as u64;
            match event.event_type {
                EventType::KeyPress(_) => {
                    add_log_event(
                        &buffer_handle,
                        HciEvent::Keyboard(KeyEvent {
                            timestamp,
                            pressed: true,
                        }),
                    );
                }
                EventType::KeyRelease(_) => {
                    add_log_event(
                        &buffer_handle,
                        HciEvent::Keyboard(KeyEvent {
                            timestamp,
                            pressed: false,
                        }),
                    );
                }
                _ => {}
            }
        };

        if let Err(error) = listen(callback) {
            eprintln!("Error while listening for HCI events: {:?}", error);
        }
    });

    let logging_handle_win = Arc::clone(&IS_LOGGING);
    let buffer_handle_win = Arc::clone(&HCI_LOG_BUFFER);
    tokio::spawn(async move {
        while *logging_handle_win.lock().unwrap() {
            if let Ok(title) = get_active_window_title() {
                let timestamp = Utc::now().timestamp_micros() as u64;
                let mut hasher = XxHash64::default();
                title.hash(&mut hasher);
                let title_hash = hasher.finish();
                add_log_event(
                    &buffer_handle_win,
                    HciEvent::Window(WindowEvent {
                        timestamp,
                        title_hash,
                    }),
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

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

/// Retrieves the current HCI log buffer.
pub fn get_log_buffer() -> Result<Vec<HciEvent>, String> {
    let buffer = HCI_LOG_BUFFER.lock().unwrap();
    Ok(buffer.iter().cloned().collect())
}

/// Adds an event to the log buffer, enforcing size limits.
fn add_log_event(buffer_handle: &Arc<Mutex<VecDeque<HciEvent>>>, event: HciEvent) {
    let mut buffer = buffer_handle.lock().unwrap();
    if buffer.len() == MAX_BUFFER_SIZE {
        buffer.pop_front();
    }
    buffer.push_back(event);
}

#[cfg(target_os = "linux")]
fn get_active_window_title() -> Result<String, String> {
    use std::process::Command;
    let output = Command::new("xdotool")
        .arg("getactivewindow")
        .arg("getwindowname")
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_active_window_title() -> Result<String, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use winapi::um::winuser::{GetForegroundWindow, GetWindowTextW};

    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_null() {
        return Err("No foreground window found".to_string());
    }

    let mut buffer: [u16; 256] = [0; 256];
    let len = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };

    if len > 0 {
        Ok(OsString::from_wide(&buffer[..len as usize])
            .to_string_lossy()
            .into_owned())
    } else {
        Err("Could not get window title".to_string())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_active_window_title() -> Result<String, String> {
    Err("Active window title not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdev::{simulate, Key};
    use std::path::Path;
    use tempfile::tempdir;

    // Helper to create the consent file for testing
    fn create_consent_file(path: &Path) {
        fs::write(path, "consent").unwrap();
    }

    // Helper to remove the consent file after testing
    fn remove_consent_file(path: &Path) {
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_start_stop_logging() {
        let dir = tempdir().unwrap();
        let consent_file = dir.path().join("orchestra-consent");
        let original_path = {
            let mut path_guard = CONSENT_FILE_PATH.lock().unwrap();
            let original = path_guard.clone();
            *path_guard = consent_file.to_str().unwrap().to_string();
            original
        };

        create_consent_file(&consent_file);
        if let Err(e) = start_logging() {
            println!("Could not start logging, skipping test: {}", e);
            // Restore original path
            *CONSENT_FILE_PATH.lock().unwrap() = original_path;
            return;
        }
        assert!(start_logging().is_err()); // Already running
        assert!(stop_logging().is_ok());
        assert!(stop_logging().is_err()); // Already stopped
        remove_consent_file(&consent_file);
        assert!(start_logging().is_err()); // No consent

        // Restore original path
        *CONSENT_FILE_PATH.lock().unwrap() = original_path;
    }

    #[tokio::test]
    async fn test_event_collection() {
        let dir = tempdir().unwrap();
        let consent_file = dir.path().join("orchestra-consent");
        let original_path = {
            let mut path_guard = CONSENT_FILE_PATH.lock().unwrap();
            let original = path_guard.clone();
            *path_guard = consent_file.to_str().unwrap().to_string();
            original
        };

        create_consent_file(&consent_file);
        // Clear buffer from previous runs
        HCI_LOG_BUFFER.lock().unwrap().clear();

        if let Err(e) = start_logging() {
            println!("Could not start logging, skipping test: {}", e);
            // Restore original path
            *CONSENT_FILE_PATH.lock().unwrap() = original_path;
            return;
        }

        // Allow some time for the logger to initialize
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Simulate a key press and release
        if simulate(&EventType::KeyPress(Key::KeyA)).is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if simulate(&EventType::KeyRelease(Key::KeyA)).is_err() {
                println!("Could not simulate key release.");
            }
        } else {
            println!("Could not simulate key press. Input simulation may not be available in this environment.");
        }

        // Allow time for window title polling
        tokio::time::sleep(Duration::from_secs(2)).await;

        stop_logging().unwrap();

        let buffer = get_log_buffer().unwrap();

        // We expect at least 1 window event if xdotool is available.
        let xdotool_available = std::process::Command::new("xdotool")
            .arg("--version")
            .output()
            .is_ok();
        if xdotool_available {
            let window_events_found = buffer
                .iter()
                .filter(|e| matches!(e, HciEvent::Window(_)))
                .count();
            assert!(
                window_events_found >= 1,
                "No window events found, but xdotool seems to be available."
            );
        } else {
            println!("xdotool not found, skipping window event check.");
        }

        // Restore original path
        *CONSENT_FILE_PATH.lock().unwrap() = original_path;
    }

    #[test]
    fn test_log_buffer_size_limit() {
        let buffer_handle = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BUFFER_SIZE)));
        for i in 0..(MAX_BUFFER_SIZE + 10) {
            add_log_event(
                &buffer_handle,
                HciEvent::Keyboard(KeyEvent {
                    timestamp: i as u64,
                    pressed: true,
                }),
            );
        }
        let buffer = buffer_handle.lock().unwrap();
        assert_eq!(buffer.len(), MAX_BUFFER_SIZE);
    }
}
