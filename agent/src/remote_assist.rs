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
#[cfg(target_os = "macos")]
use std::ffi::c_void;
#[cfg(target_os = "linux")]
use x11cap::{Capturer, Screen};

#[cfg(target_os = "macos")]
type CFTypeRef = *const c_void;
#[cfg(target_os = "macos")]
type CFDataRef = *const c_void;
#[cfg(target_os = "macos")]
type CGImageRef = *mut c_void;
#[cfg(target_os = "macos")]
type CGDataProviderRef = *mut c_void;

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Copy, Clone)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Copy, Clone)]
struct CGSize {
    width: f64,
    height: f64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Copy, Clone)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

#[cfg(target_os = "macos")]
const KCG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1;
#[cfg(target_os = "macos")]
const KCG_NULL_WINDOW_ID: u32 = 0;
#[cfg(target_os = "macos")]
const KCG_WINDOW_IMAGE_DEFAULT: u32 = 0;

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGMainDisplayID() -> u32;
    fn CGDisplayBounds(display: u32) -> CGRect;
    fn CGWindowListCreateImage(
        screenBounds: CGRect,
        listOption: u32,
        windowID: u32,
        imageOption: u32,
    ) -> CGImageRef;
    fn CGImageGetWidth(image: CGImageRef) -> usize;
    fn CGImageGetHeight(image: CGImageRef) -> usize;
    fn CGImageGetBytesPerRow(image: CGImageRef) -> usize;
    fn CGImageGetBitsPerPixel(image: CGImageRef) -> usize;
    fn CGImageGetDataProvider(image: CGImageRef) -> CGDataProviderRef;
    fn CGDataProviderCopyData(provider: CGDataProviderRef) -> CFDataRef;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataGetLength(theData: CFDataRef) -> isize;
    fn CFDataGetBytePtr(theData: CFDataRef) -> *const u8;
    fn CFRelease(cf: CFTypeRef);
}

// Thread-local `Enigo` instance shared across input-simulation calls.
// Avoids the overhead of re-initialising the platform input backend on every
// call; `Enigo` is not `Send` so a thread-local is the right storage class.
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
///
/// Consent storage is intentionally user-level on all platforms so that no
/// elevated privileges are required to grant or revoke consent:
///
/// * Linux/macOS: `$HOME/.orchestra-consent` (falls back to
///   `$XDG_RUNTIME_DIR/orchestra-consent` on Linux if HOME is unavailable).
/// * Windows: `HKCU\Software\Orchestra\Consent` (DWORD == 1) — current user
///   only; does not require administrator rights.

/// Returns the platform-specific consent file path.
#[cfg(not(windows))]
fn consent_path() -> Option<std::path::PathBuf> {
    // Prefer $HOME for a portable, user-level location.
    if let Some(home) = std::env::var_os("HOME") {
        return Some(std::path::PathBuf::from(home).join(".orchestra-consent"));
    }
    // Fallback: XDG_RUNTIME_DIR (Linux) or /tmp (macOS).
    #[cfg(target_os = "linux")]
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(std::path::PathBuf::from(xdg).join("orchestra-consent"));
    }
    Some(std::path::PathBuf::from("/tmp/orchestra-consent"))
}

#[cfg(not(windows))]
fn check_consent() -> Result<()> {
    match consent_path() {
        Some(p) if p.exists() => Ok(()),
        Some(p) => Err(anyhow!(
            "Remote assistance consent not granted. \
             Create {:?} to enable remote assistance.",
            p
        )),
        None => Err(anyhow!(
            "Remote assistance consent not granted: could not determine consent file path"
        )),
    }
}

/// On Windows, consent is stored in the current user's registry hive
/// (`HKCU`) so that no administrator privileges are needed.
/// `HKCU\Software\Orchestra\Consent` (DWORD) must be `1`.
#[cfg(windows)]
fn check_consent() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let orchestra_key = hkcu.open_subkey("Software\\Orchestra")?;
    let consent: u32 = orchestra_key.get_value("Consent")?;
    if consent == 1 {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted. \
             Set HKCU\\Software\\Orchestra\\Consent (DWORD) = 1 to enable remote assistance."
        ))
    }
}

/// Captures the primary monitor's screen and returns it as PNG bytes.
pub fn take_screenshot() -> Result<Vec<u8>> {
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
        use std::io::Cursor;
        use winapi::shared::windef::HBITMAP;
        use winapi::um::wingdi::{
            BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
            SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
        };
        use winapi::um::winuser::{GetDC, GetSystemMetrics, ReleaseDC, SM_CXSCREEN, SM_CYSCREEN};

        // SAFETY: All Win32 handles are checked for null before use and are
        // released in reverse-acquisition order even on early returns.
        let png_bytes = unsafe {
            let width = GetSystemMetrics(SM_CXSCREEN);
            let height = GetSystemMetrics(SM_CYSCREEN);
            if width <= 0 || height <= 0 {
                return Err(anyhow!(
                    "GetSystemMetrics returned invalid screen dimensions: {}x{}",
                    width,
                    height
                ));
            }

            let hdc_screen = GetDC(std::ptr::null_mut());
            if hdc_screen.is_null() {
                return Err(anyhow!("GetDC failed — no desktop DC available"));
            }

            let hdc_mem = CreateCompatibleDC(hdc_screen);
            if hdc_mem.is_null() {
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                return Err(anyhow!("CreateCompatibleDC failed"));
            }

            let hbm: HBITMAP = CreateCompatibleBitmap(hdc_screen, width, height);
            if hbm.is_null() {
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                return Err(anyhow!("CreateCompatibleBitmap failed"));
            }

            let old_obj = SelectObject(hdc_mem, hbm as _);
            let blt_ok = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

            if blt_ok == 0 {
                SelectObject(hdc_mem, old_obj);
                DeleteObject(hbm as _);
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                return Err(anyhow!("BitBlt failed — screen capture blocked"));
            }

            // Request 32-bit top-down BGRA pixels (BI_RGB with biBitCount=32).
            let bmi_header = BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height, // negative → top-down row order
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            };
            let mut bmi = BITMAPINFO {
                bmiHeader: bmi_header,
                bmiColors: [std::mem::zeroed(); 1],
            };

            let pixel_count = (width as usize) * (height as usize);
            // Each pixel is 4 bytes (BGRA).
            let mut pixels: Vec<u8> = vec![0u8; pixel_count * 4];

            let scan_lines = GetDIBits(
                hdc_mem,
                hbm,
                0,
                height as u32,
                pixels.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            );

            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbm as _);
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);

            if scan_lines == 0 {
                return Err(anyhow!("GetDIBits failed — could not read screen pixels"));
            }

            // GDI returns BGRA; the `image` crate RGBA buffer expects R at index 0.
            // Swap B (index 0) and R (index 2) in every 4-byte pixel.
            for chunk in pixels.chunks_exact_mut(4) {
                chunk.swap(0, 2);
            }

            let img =
                image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width as u32, height as u32, pixels)
                    .ok_or_else(|| anyhow!("failed to construct RGBA image buffer from GDI pixels"))?;

            let mut png_buf: Vec<u8> = Vec::new();
            img.write_to(
                &mut Cursor::new(&mut png_buf),
                image::ImageFormat::Png,
            )?;
            png_buf
        };
        Ok(png_bytes)
    }
    #[cfg(target_os = "macos")]
    {
        check_consent()?;
        use image::{ImageBuffer, Rgba};
        use std::io::Cursor;

        // SAFETY: CoreGraphics/CoreFoundation objects are released exactly
        // once after use. Raw pointers from CFData are only read for the
        // reported length and converted into owned Rust buffers.
        let png_bytes = unsafe {
            let bounds = CGDisplayBounds(CGMainDisplayID());
            let image = CGWindowListCreateImage(
                bounds,
                KCG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY,
                KCG_NULL_WINDOW_ID,
                KCG_WINDOW_IMAGE_DEFAULT,
            );
            if image.is_null() {
                return Err(anyhow!(
                    "CGWindowListCreateImage failed; ensure Screen Recording permission is granted"
                ));
            }

            let result = (|| -> Result<Vec<u8>> {
                let width = CGImageGetWidth(image);
                let height = CGImageGetHeight(image);
                if width == 0 || height == 0 {
                    return Err(anyhow!(
                        "CoreGraphics returned invalid screenshot size: {}x{}",
                        width,
                        height
                    ));
                }
                if width > u32::MAX as usize || height > u32::MAX as usize {
                    return Err(anyhow!(
                        "screenshot dimensions exceed PNG encoder limits: {}x{}",
                        width,
                        height
                    ));
                }

                let bits_per_pixel = CGImageGetBitsPerPixel(image);
                if bits_per_pixel < 32 {
                    return Err(anyhow!(
                        "unsupported CoreGraphics pixel format ({} bits per pixel)",
                        bits_per_pixel
                    ));
                }

                let bytes_per_row = CGImageGetBytesPerRow(image);
                let min_row_bytes = width
                    .checked_mul(4)
                    .ok_or_else(|| anyhow!("screenshot row size overflow"))?;
                if bytes_per_row < min_row_bytes {
                    return Err(anyhow!(
                        "invalid CoreGraphics row stride {} for width {}",
                        bytes_per_row,
                        width
                    ));
                }

                let provider = CGImageGetDataProvider(image);
                if provider.is_null() {
                    return Err(anyhow!("CGImageGetDataProvider returned null"));
                }

                let cf_data = CGDataProviderCopyData(provider);
                if cf_data.is_null() {
                    return Err(anyhow!("CGDataProviderCopyData failed"));
                }

                let data_result = (|| -> Result<Vec<u8>> {
                    let data_len = CFDataGetLength(cf_data);
                    if data_len <= 0 {
                        return Err(anyhow!("CoreGraphics returned empty pixel data"));
                    }
                    let data_ptr = CFDataGetBytePtr(cf_data);
                    if data_ptr.is_null() {
                        return Err(anyhow!("CoreGraphics returned null pixel pointer"));
                    }

                    let src = std::slice::from_raw_parts(data_ptr, data_len as usize);
                    let mut rgba = vec![0u8; width * height * 4];

                    for y in 0..height {
                        let row_offset = y * bytes_per_row;
                        let row_end = row_offset
                            .checked_add(min_row_bytes)
                            .ok_or_else(|| anyhow!("screenshot row bounds overflow"))?;
                        if row_end > src.len() {
                            return Err(anyhow!("CoreGraphics pixel buffer shorter than expected"));
                        }
                        let row = &src[row_offset..row_end];

                        for x in 0..width {
                            let src_idx = x * 4;
                            let dst_idx = (y * width + x) * 4;
                            // CoreGraphics window images are typically BGRA.
                            rgba[dst_idx] = row[src_idx + 2];
                            rgba[dst_idx + 1] = row[src_idx + 1];
                            rgba[dst_idx + 2] = row[src_idx];
                            rgba[dst_idx + 3] = row[src_idx + 3];
                        }
                    }

                    let img = ImageBuffer::<Rgba<u8>, _>::from_raw(width as u32, height as u32, rgba)
                        .ok_or_else(|| anyhow!("failed to create image buffer from CoreGraphics data"))?;

                    let mut out = Vec::new();
                    img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)?;
                    Ok(out)
                })();

                CFRelease(cf_data as CFTypeRef);
                data_result
            })();

            CFRelease(image as CFTypeRef);
            result
        }?;

        Ok(png_bytes)
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Err(anyhow!("Screen capture not implemented for this platform."))
    }
}

/// Backward-compatible screenshot entrypoint used by existing command dispatch.
pub fn capture_screen() -> Result<Vec<u8>> {
    take_screenshot()
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
        // This test assumes the consent file does not exist at the user-level path.
        // It should fail because the consent file is absent.
        assert!(check_consent().is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_consent_check_fails_by_default_win() {
        // This test assumes the consent registry key is not set under HKCU.
        assert!(check_consent().is_err());
    }
}
