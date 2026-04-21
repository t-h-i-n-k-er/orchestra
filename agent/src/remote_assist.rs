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
use enigo::{Enigo, Keyboard, Mouse, Settings};
#[cfg(target_os = "linux")]
use x11cap::X11Capture;

/// Checks for the existence of a consent flag.
/// On Linux/macOS, this is the file `/var/run/orchestra-consent`.
/// On Windows, this would be a registry key.
fn check_consent() -> Result<()> {
    if std::path::Path::new("/var/run/orchestra-consent").exists() {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted on target machine."
        ))
    }
}

/// Captures the primary monitor's screen and returns it as a PNG image.
pub fn capture_screen() -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        let capturer = X11Capture::new(true)?;
        let (w, h) = capturer.get_resolution();
        let image = capturer.capture_image(0, 0, w, h)?;
        let mut buffer = Vec::new();
        image.write_to(
            &mut std::io::Cursor::new(&mut buffer),
            image::ImageOutputFormat::Png,
        )?;
        Ok(buffer)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(anyhow!("Screen capture not implemented for this platform."))
    }
}

/// Simulates a key press.
pub fn simulate_key(key: &str) -> Result<()> {
    check_consent()?;
    #[cfg(target_os = "linux")]
    {
        let mut enigo = Enigo::new(&Settings::default())?;
        enigo.key(key, enigo::Direction::Click)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("Simulating key press: {}", key);
        Ok(())
    }
}

/// Simulates mouse movement to a given (x, y) coordinate.
pub fn simulate_mouse_move(x: i32, y: i32) -> Result<()> {
    check_consent()?;
    #[cfg(target_os = "linux")]
    {
        let mut enigo = Enigo::new(&Settings::default())?;
        enigo.mouse(enigo::Button::Left, enigo::Direction::Click)?;
        enigo.mouse(enigo::Axis::X, x)?;
        enigo.mouse(enigo::Axis::Y, y)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("Simulating mouse move to ({}, {})", x, y);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_check_fails_by_default() {
        // This test assumes the consent file does not exist.
        assert!(check_consent().is_err());
    }
}
