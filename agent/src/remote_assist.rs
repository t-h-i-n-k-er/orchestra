//! Optional remote assistance module for screen capture and input simulation.
//!
//! This module provides capabilities similar to VNC or remote desktop tools,
//! intended for remote support scenarios with explicit user consent.
//!
//! **Warning:** These features can be intrusive. They are disabled by default
//! and require the `remote-assist` feature flag. Input simulation also
//! requires a consent flag on the target machine.

#![cfg(feature = "remote-assist")]

use anyhow::{anyhow, Result};
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use enigo::{Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use std::cell::RefCell;
#[cfg(windows)]
use windows_capture::{
    capture::GraphicsCaptureApi,
    monitor::Monitor,
    settings::{Color, CursorCaptureSettings, DrawBorderSettings, Settings as CaptureSettings},
};
#[cfg(target_os = "linux")]
use x11cap::{Capturer, Screen};

/// Thread-local `Enigo` instance shared across input-simulation calls.
/// Avoids the overhead of re-initialising the platform input backend on every
/// call; `Enigo` is not `Send` so a thread-local is the right storage class.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
thread_local! {
    static ENIGO_INSTANCE: RefCell<Option<Enigo>> = const { RefCell::new(None) };
}

/// Obtain a mutable reference to the thread-local `Enigo`, initialising it
/// on first use, and call `f` with it.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn with_enigo<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut Enigo) -> Result<R>,
{
    ENIGO_INSTANCE.with(|cell| -> Result<R> {
        let mut borrow = cell.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(
                Enigo::new(&Settings::default()).map_err(|e| anyhow!("enigo init failed: {e}"))?,
            );
        }
        f(borrow.as_mut().unwrap())
    })
}

/// Checks for the existence of a consent flag.
#[cfg(target_os = "linux")]
fn check_consent() -> Result<()> {
    if std::path::Path::new("/var/run/orchestra-consent").exists() {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted on target machine. Missing /var/run/orchestra-consent."
        ))
    }
}

#[cfg(target_os = "macos")]
fn check_consent() -> Result<()> {
    // macOS requires root to write to /var/run by default.
    // Instead use the system user's temporary consent file or preferences flag.
    let consent_path = std::env::var("HOME")
        .map(|h| format!("{}/.orchestra-consent", h))
        .unwrap_or_else(|_| "/tmp/orchestra-consent".to_string());
    if std::path::Path::new(&consent_path).exists() {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted on target machine. Missing macOS consent flag."
        ))
    }
}

/// On Windows, this checks for a registry key.
/// `HKLM\Software\Orchestra\Consent` (DWORD) must be `1`.
#[cfg(windows)]
fn check_consent() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let orchestra_key = hklm.open_subkey("Software\\Orchestra")?;
    let consent: u32 = orchestra_key.get_value("Consent")?;
    if consent == 1 {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted via registry key."
        ))
    }
}

/// Captures the primary monitor's screen and returns it as a PNG image.
pub fn capture_screen() -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        check_consent()?;
        // On Wayland without an X11 socket, x11cap will fail silently.
        // Detect and report this explicitly so callers receive a useful error.
        if std::env::var_os("WAYLAND_DISPLAY").is_some() && std::env::var_os("DISPLAY").is_none() {
            return Err(anyhow!(
                "Screen capture is not supported on a pure Wayland session. \
                 Enable XWayland (set DISPLAY) or use an XDG Desktop Portal-compatible tool."
            ));
        }
        use image::{ImageBuffer, Rgb};
        let mut capturer =
            Capturer::new(Screen::Default).map_err(|_| anyhow!("failed to open X11 display"))?;
        let (pixels, (width, height)) = capturer
            .capture_frame()
            .map_err(|e| anyhow!("capture failed: {:?}", e))?;
        let raw: Vec<u8> = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
        let img = ImageBuffer::<Rgb<u8>, _>::from_raw(width, height, raw)
            .ok_or_else(|| anyhow!("failed to create image buffer"))?;
        let mut buffer = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut buffer),
            image::ImageFormat::Png,
        )?;
        Ok(buffer)
    }
    #[cfg(windows)]
    {
        check_consent()?;
        let primary_monitor = Monitor::primary()?;
        let settings = CaptureSettings::new(
            primary_monitor,
            CursorCaptureSettings::Default,
            DrawBorderSettings::Default,
            Color::default(),
            false,
        )?;
        let mut capturer = GraphicsCaptureApi::new(settings)?;
        let frame = capturer.next_frame()?;
        let mut buffer = Vec::new();
        image::save_buffer_with_format(
            &mut std::io::Cursor::new(&mut buffer),
            &frame.buffer(),
            frame.width(),
            frame.height(),
            image::ColorType::Rgba8,
            image::ImageFormat::Png,
        )?;
        Ok(buffer)
    }
    #[cfg(target_os = "macos")]
    {
        check_consent()?;
        // Use the bundled `screencapture` CLI to grab a PNG screenshot.
        // Pipe to stdout using `-` avoiding temporary files
        let output = std::process::Command::new("screencapture")
            .args(["-x", "-t", "png", "-"])
            .output()
            .map_err(|e| anyhow!("screencapture invocation failed: {e}"))?;

        if !output.status.success() {
            return Err(anyhow!("screencapture exited with non-zero status"));
        }

        Ok(output.stdout)
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Err(anyhow!("Screen capture not implemented for this platform."))
    }
}

/// Map a string key name to an enigo `Key` variant.
///
/// Returns `None` for single characters (caller should use `enigo.text()`) and
/// unknown names.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn map_key_name(name: &str) -> Option<enigo::Key> {
    match name {
        "Return" | "Enter" => Some(enigo::Key::Return),
        "Tab" => Some(enigo::Key::Tab),
        "Escape" | "Esc" => Some(enigo::Key::Escape),
        "Backspace" | "BackSpace" => Some(enigo::Key::Backspace),
        "Delete" | "Del" => Some(enigo::Key::Delete),
        "Home" => Some(enigo::Key::Home),
        "End" => Some(enigo::Key::End),
        "PageUp" => Some(enigo::Key::PageUp),
        "PageDown" => Some(enigo::Key::PageDown),
        "Up" | "UpArrow" => Some(enigo::Key::UpArrow),
        "Down" | "DownArrow" => Some(enigo::Key::DownArrow),
        "Left" | "LeftArrow" => Some(enigo::Key::LeftArrow),
        "Right" | "RightArrow" => Some(enigo::Key::RightArrow),
        "F1" => Some(enigo::Key::F1),
        "F2" => Some(enigo::Key::F2),
        "F3" => Some(enigo::Key::F3),
        "F4" => Some(enigo::Key::F4),
        "F5" => Some(enigo::Key::F5),
        "F6" => Some(enigo::Key::F6),
        "F7" => Some(enigo::Key::F7),
        "F8" => Some(enigo::Key::F8),
        "F9" => Some(enigo::Key::F9),
        "F10" => Some(enigo::Key::F10),
        "F11" => Some(enigo::Key::F11),
        "F12" => Some(enigo::Key::F12),
        "Space" => Some(enigo::Key::Space),
        "CapsLock" => Some(enigo::Key::CapsLock),
        "Shift" => Some(enigo::Key::Shift),
        "Control" | "Ctrl" => Some(enigo::Key::Control),
        "Alt" => Some(enigo::Key::Alt),
        "Meta" | "Super" | "Win" | "Command" => Some(enigo::Key::Meta),
        _ => None,
    }
}

/// Simulates a key press / key sequence.
pub fn simulate_key(key: &str) -> Result<()> {
    check_consent()?;
    with_enigo(|enigo| {
        if let Some(k) = map_key_name(key) {
            enigo
                .key(k, Direction::Click)
                .map_err(|e| anyhow!("key simulation failed: {e}"))
        } else if key.chars().count() == 1 {
            // Single character — type it as text.
            enigo
                .text(key)
                .map_err(|e| anyhow!("key simulation failed: {e}"))
        } else {
            Err(anyhow!(
                "Unknown key name '{}'. Expected a named key (e.g. 'Enter', 'Tab', 'F1') \
                 or a single character.",
                key
            ))
        }
    })
}

/// Simulates mouse movement to a given (x, y) coordinate.
pub fn simulate_mouse_move(x: i32, y: i32) -> Result<()> {
    check_consent()?;
    with_enigo(|enigo| {
        enigo
            .move_mouse(x, y, Coordinate::Abs)
            .map_err(|e| anyhow!("mouse move failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_consent_check_fails_by_default() {
        // This test assumes the consent file does not exist.
        assert!(check_consent().is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_consent_check_fails_by_default_win() {
        // This test assumes the consent registry key is not set.
        assert!(check_consent().is_err());
    }
}
