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
#[cfg(target_os = "linux")]
use enigo::{Coordinate, Enigo, Keyboard, Mouse, Settings};
#[cfg(windows)]
use enigo::{Coordinate, Enigo, Keyboard, Mouse, Settings};
#[cfg(windows)]
use windows_capture::{
    capture::GraphicsCaptureApi,
    monitor::Monitor,
    settings::{Color, CursorCaptureSettings, DrawBorderSettings, Settings as CaptureSettings},
};
#[cfg(target_os = "linux")]
use x11cap::{Capturer, Screen};

/// Checks for the existence of a consent flag.
#[cfg(unix)]
fn check_consent() -> Result<()> {
    if std::path::Path::new("/var/run/orchestra-consent").exists() {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted on target machine. Missing /var/run/orchestra-consent."
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
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(anyhow!("Screen capture not implemented for this platform."))
    }
}

/// Simulates a key press / key sequence.
pub fn simulate_key(key: &str) -> Result<()> {
    check_consent()?;
    let mut enigo =
        Enigo::new(&Settings::default()).map_err(|e| anyhow!("enigo init failed: {e}"))?;
    enigo
        .text(key)
        .map_err(|e| anyhow!("key simulation failed: {e}"))?;
    Ok(())
}

/// Simulates mouse movement to a given (x, y) coordinate.
pub fn simulate_mouse_move(x: i32, y: i32) -> Result<()> {
    check_consent()?;
    let mut enigo =
        Enigo::new(&Settings::default()).map_err(|e| anyhow!("enigo init failed: {e}"))?;
    enigo
        .move_mouse(x, y, Coordinate::Abs)
        .map_err(|e| anyhow!("mouse move failed: {e}"))?;
    Ok(())
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
