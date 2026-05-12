//! Optional remote assistance module for screen capture and input simulation.
//!
//! This module provides capabilities similar to VNC or remote desktop tools,
//! intended for remote support scenarios with explicit user consent.
//!
//! **Warning:** These features can be intrusive. They are disabled by default
//! and require the `remote-assist` feature flag. Input simulation also
//! requires a consent flag on the target machine.

#![cfg(feature = "remote-assist")]

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};
use anyhow::{anyhow, Result};
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use enigo::{Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use std::cell::RefCell;
#[cfg(target_os = "macos")]
use std::ffi::c_void;

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

// ─────────────────────────── Linux screen-capture helpers ───────────────────

/// Capture via the X11 root window using the pure-Rust `x11rb` backend.
#[cfg(target_os = "linux")]
fn capture_x11() -> Result<Vec<u8>> {
    use image::{ImageBuffer, Rgba};
    use x11rb::connection::Connection;
    use x11rb::image::{BitsPerPixel, Image};

    let (conn, screen_num) =
        x11rb::connect(None).map_err(|e| anyhow!("X11 connect failed: {e}"))?;
    let setup = conn.setup();
    let screen = setup
        .roots
        .get(screen_num)
        .ok_or_else(|| anyhow!("X11 screen index {} is out of range", screen_num))?;
    let width = screen.width_in_pixels;
    let height = screen.height_in_pixels;
    if width == 0 || height == 0 {
        return Err(anyhow!(
            "X11 root window has invalid size {}x{}",
            width,
            height
        ));
    }

    let (ximage, visual_id) = Image::get(&conn, screen.root, 0, 0, width, height)
        .map_err(|e| anyhow!("X11 GetImage failed: {e}"))?;
    let visual = screen
        .allowed_depths
        .iter()
        .flat_map(|depth| depth.visuals.iter())
        .find(|visual| visual.visual_id == visual_id)
        .ok_or_else(|| anyhow!("X11 visual {visual_id} not found in screen visual list"))?;

    let bytes_per_pixel = match ximage.bits_per_pixel() {
        BitsPerPixel::B32 => 4,
        BitsPerPixel::B24 => 3,
        BitsPerPixel::B16 => 2,
        other => {
            return Err(anyhow!(
                "unsupported X11 screenshot pixel format: {:?} bits per pixel",
                other
            ))
        }
    };
    let row_bits = (width as usize)
        .checked_mul(usize::from(ximage.bits_per_pixel()))
        .ok_or_else(|| anyhow!("X11 row size overflow"))?;
    let scanline_pad = usize::from(ximage.scanline_pad());
    let stride_bits = ((row_bits + scanline_pad - 1) / scanline_pad) * scanline_pad;
    let stride = stride_bits / 8;
    let expected = (height as usize)
        .checked_mul(stride)
        .ok_or_else(|| anyhow!("X11 image size overflow"))?;
    if ximage.data().len() < expected {
        return Err(anyhow!(
            "X11 image data is shorter than expected: {} < {}",
            ximage.data().len(),
            expected
        ));
    }

    let mut rgba = vec![0u8; width as usize * height as usize * 4];
    for y in 0..height as usize {
        let row = &ximage.data()[y * stride..y * stride + stride];
        for x in 0..width as usize {
            let src = x * bytes_per_pixel;
            let pixel = read_x11_pixel(&row[src..src + bytes_per_pixel], ximage.byte_order());
            let dst = (y * width as usize + x) * 4;
            rgba[dst] = x11_channel_to_u8(pixel, visual.red_mask);
            rgba[dst + 1] = x11_channel_to_u8(pixel, visual.green_mask);
            rgba[dst + 2] = x11_channel_to_u8(pixel, visual.blue_mask);
            rgba[dst + 3] = 0xff;
        }
    }

    let img = ImageBuffer::<Rgba<u8>, _>::from_raw(width as u32, height as u32, rgba)
        .ok_or_else(|| anyhow!("failed to create image buffer from X11 pixels"))?;
    let mut buffer = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut buffer),
        image::ImageFormat::Png,
    )?;
    Ok(buffer)
}

#[cfg(target_os = "linux")]
fn read_x11_pixel(bytes: &[u8], byte_order: x11rb::image::ImageOrder) -> u32 {
    match byte_order {
        x11rb::image::ImageOrder::LsbFirst => bytes
            .iter()
            .enumerate()
            .fold(0u32, |acc, (idx, byte)| acc | ((*byte as u32) << (idx * 8))),
        x11rb::image::ImageOrder::MsbFirst => bytes
            .iter()
            .fold(0u32, |acc, byte| (acc << 8) | (*byte as u32)),
    }
}

#[cfg(target_os = "linux")]
fn x11_channel_to_u8(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let bits = 32 - mask.leading_zeros() - shift;
    let value = (pixel & mask) >> shift;
    if bits >= 8 {
        (value >> (bits - 8)) as u8
    } else {
        let max = (1u32 << bits) - 1;
        ((value * 255 + max / 2) / max) as u8
    }
}

/// Capture the primary framebuffer via `/dev/fb0` (headless/VT fallback).
///
/// Reads display geometry from `/sys/class/graphics/fb0/virtual_size` and
/// bits-per-pixel from `/sys/class/graphics/fb0/bits_per_pixel`.
/// Only 32 bpp (BGRA) framebuffers are supported; other formats return an
/// error rather than producing corrupt output.
#[cfg(target_os = "linux")]
fn capture_fb0() -> Result<Vec<u8>> {
    use std::io::Read;

    let virt_size =
        std::fs::read_to_string("/sys/class/graphics/fb0/virtual_size").map_err(|e| {
            anyhow!("/dev/fb0 not available: /sys/class/graphics/fb0/virtual_size: {e}")
        })?;
    let mut parts = virt_size.trim().split(',');
    let width: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("invalid fb0 virtual_size (width)"))?;
    let height: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("invalid fb0 virtual_size (height)"))?;

    let bpp: u32 = std::fs::read_to_string("/sys/class/graphics/fb0/bits_per_pixel")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32);

    if bpp != 32 {
        return Err(anyhow!(
            "/dev/fb0 bits_per_pixel={bpp}; only 32 bpp (BGRA) is supported"
        ));
    }

    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| anyhow!("fb0 dimensions overflow"))?;

    let mut fb_data = vec![0u8; expected];
    let mut fb =
        std::fs::File::open("/dev/fb0").map_err(|e| anyhow!("/dev/fb0 open failed: {e}"))?;
    fb.read_exact(&mut fb_data)
        .map_err(|e| anyhow!("/dev/fb0 read failed: {e}"))?;

    // Framebuffers typically store BGRA; swap B (index 0) and R (index 2) for RGBA.
    for chunk in fb_data.chunks_exact_mut(4) {
        chunk.swap(0, 2);
    }

    let img = image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width, height, fb_data)
        .ok_or_else(|| anyhow!("failed to construct RGBA image from fb0 data"))?;
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)?;
    Ok(out)
}

/// Capture via the XDG Desktop Portal Screenshot interface over D-Bus
/// (Wayland sessions).
///
/// Spawns a dedicated OS thread with its own Tokio runtime to drive the
/// async D-Bus exchange, avoiding nesting issues with the agent's main
/// runtime.  Times out after 35 seconds.
#[cfg(target_os = "linux")]
fn capture_wayland_portal() -> Result<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Vec<u8>>>(1);
    std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime init failed: {e}"))
            .and_then(|rt| rt.block_on(capture_wayland_portal_async()));
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(35))
        .map_err(|_| anyhow!("xdg-desktop-portal timed out (35 s)"))?
}

/// Async core of the XDG Portal screenshot request.
///
/// Flow:
/// 1. Open the D-Bus session bus.
/// 2. Subscribe to `org.freedesktop.portal.Request.Response` on the
///    expected handle path *before* calling `Screenshot`, to avoid a
///    TOCTOU race if the portal responds immediately.
/// 3. Call `org.freedesktop.portal.Screenshot.Screenshot` with
///    `interactive = false`.
/// 4. Wait up to 30 s for the `Response` signal.
/// 5. Extract the `file://` URI, read the PNG, and return the bytes.
#[cfg(target_os = "linux")]
async fn capture_wayland_portal_async() -> Result<Vec<u8>> {
    use futures_util::StreamExt;
    use std::collections::HashMap;
    use zbus::zvariant::Value;

    let conn = zbus::Connection::session()
        .await
        .map_err(|e| anyhow!("D-Bus session connection failed: {e}"))?;

    // Build the expected request-handle path from the caller's unique bus name
    // and the handle token.  The portal constructs the same path.
    let token = format!("rs{}", std::process::id());
    let unique_name = conn
        .unique_name()
        .ok_or_else(|| anyhow!("no D-Bus unique name assigned"))?
        .to_string();
    // ":1.23" → "1_23"
    let sender_id = unique_name.trim_start_matches(':').replace('.', "_");
    let handle_path = format!(
        "/org/freedesktop/portal/desktop/request/{}/{}",
        sender_id, token
    );

    // Subscribe to the Response signal *before* making the call to avoid
    // missing an immediate response.
    let match_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.portal.Request")
        .map_err(|e| anyhow!("invalid interface name: {e}"))?
        .member("Response")
        .map_err(|e| anyhow!("invalid member name: {e}"))?
        .path(handle_path.as_str())
        .map_err(|e| anyhow!("invalid path: {e}"))?
        .build();

    let mut signal_stream = zbus::MessageStream::for_match_rule(match_rule, &conn, Some(1))
        .await
        .map_err(|e| anyhow!("failed to subscribe to portal response signal: {e}"))?;

    // Build the options dictionary for the Screenshot portal call.
    let mut opts: HashMap<&str, Value<'_>> = HashMap::new();
    opts.insert("interactive", false.into());
    opts.insert("handle_token", Value::Str(token.as_str().into()));

    conn.call_method(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        Some("org.freedesktop.portal.Screenshot"),
        "Screenshot",
        &("", &opts),
    )
    .await
    .map_err(|e| anyhow!("Screenshot portal call failed: {e}"))?;

    // Wait for the response signal, with a 30-second timeout.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(30), signal_stream.next())
        .await
        .map_err(|_| anyhow!("xdg-desktop-portal did not respond within 30 seconds"))?
        .ok_or_else(|| anyhow!("portal signal stream ended without a Response"))?
        .map_err(|e| anyhow!("portal D-Bus message error: {e}"))?;

    // Parse the body: (response_code: u32, results: a{sv})
    let (response, results): (u32, HashMap<String, zbus::zvariant::OwnedValue>) = msg
        .body()
        .deserialize()
        .map_err(|e| anyhow!("failed to deserialize portal Response body: {e}"))?;

    if response != 0 {
        return Err(anyhow!(
            "xdg-desktop-portal screenshot request rejected (response code {}; \
             0=success, 1=cancelled, 2=other error)",
            response
        ));
    }

    // Extract the file URI from the results dictionary.
    let uri_value = results
        .get("uri")
        .ok_or_else(|| anyhow!("portal Response missing 'uri' field"))?;

    // OwnedValue derefs to Value; use downcast_ref::<String>() to extract
    // the URI (the unsized `str` type is not accepted by downcast_ref).
    let uri_str = uri_value
        .downcast_ref::<String>()
        .map_err(|_| anyhow!("portal 'uri' value is not a string"))?
        .clone();

    let file_path = uri_str
        .strip_prefix("file://")
        .ok_or_else(|| anyhow!("portal returned non-file URI: {uri_str}"))?;

    // The portal saves a PNG; read it directly.
    let png_bytes = std::fs::read(file_path)
        .map_err(|e| anyhow!("failed to read portal screenshot file '{file_path}': {e}"))?;

    // Clean up the temporary file (best-effort; ignore errors).
    let _ = std::fs::remove_file(file_path);

    Ok(png_bytes)
}

// ────────────────────────────────────────────────────────────────────────────

/// Checks for the existence of a consent flag.
///
/// Consent storage is intentionally user-level on all platforms so that no
/// elevated privileges are required to grant or revoke consent:
///
/// * Linux/macOS: `$HOME/.sysd-notify` (falls back to
///   `$XDG_RUNTIME_DIR/sysd-notify` on Linux if HOME is unavailable).
/// * Windows: `HKCU\Software\SysNotify\Consent` (DWORD == 1) — current user
///   only; does not require administrator rights.

/// Returns the platform-specific consent file path.
#[cfg(not(windows))]
fn consent_path() -> Option<std::path::PathBuf> {
    // Prefer $HOME for a portable, user-level location.
    if let Some(home) = std::env::var_os("HOME") {
        return Some(std::path::PathBuf::from(home).join(".sysd-notify"));
    }
    // Fallback: XDG_RUNTIME_DIR (Linux) or /tmp (macOS).
    #[cfg(target_os = "linux")]
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(std::path::PathBuf::from(xdg).join("sysd-notify"));
    }
    Some(std::path::PathBuf::from("/tmp/.sysd-notify"))
}

// ── pe_resolve helpers ──────────────────────────────────────────────────────

/// Resolve a function pointer from a DLL that is already loaded in the PEB.
#[cfg(windows)]
unsafe fn resolve_api<T>(dll_hash: u32, fn_hash: u32) -> Result<T> {
    let module = pe_resolve::get_module_handle_by_hash(dll_hash)
        .ok_or_else(|| anyhow!("DLL not found (hash 0x{:08X})", dll_hash))?;
    let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
        .ok_or_else(|| anyhow!("API not found (hash 0x{:08X})", fn_hash))?;
    Ok(std::mem::transmute_copy(&addr))
}

/// Resolve a function pointer from a DLL, loading it if not already present.
#[cfg(windows)]
unsafe fn resolve_api_or_load<T>(dll_wide: &[u16], dll_hash: u32, fn_hash: u32) -> Result<T> {
    let module = match pe_resolve::get_module_handle_by_hash(dll_hash) {
        Some(m) => m,
        None => {
            let load_library_w: unsafe extern "system" fn(*const u16) -> *mut std::ffi::c_void =
                resolve_api(
                    pe_resolve::HASH_KERNEL32_DLL,
                    pe_resolve::hash_str(b"LoadLibraryW\0"),
                )?;
            let m = load_library_w(dll_wide.as_ptr());
            if m.is_null() {
                return Err(anyhow!(
                    "LoadLibraryW failed for DLL (hash 0x{:08X})",
                    dll_hash
                ));
            }
            m as usize
        }
    };
    let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
        .ok_or_else(|| anyhow!("API not found (hash 0x{:08X})", fn_hash))?;
    Ok(std::mem::transmute_copy(&addr))
}

// ── user32.dll wide string & hash ────────────────────────────────────────────
#[cfg(windows)]
const USER32_DLL_W: &[u16] = &[
    'u' as u16, 's' as u16, 'e' as u16, 'r' as u16, '3' as u16, '2' as u16, '.' as u16, 'd' as u16,
    'l' as u16, 'l' as u16, 0,
];
#[cfg(windows)]
const HASH_USER32_DLL: u32 = hash_wstr_const(USER32_DLL_W);

// ── gdi32.dll wide string & hash ─────────────────────────────────────────────
#[cfg(windows)]
const GDI32_DLL_W: &[u16] = &[
    'g' as u16, 'd' as u16, 'i' as u16, '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16,
    'l' as u16, 0,
];
#[cfg(windows)]
const HASH_GDI32_DLL: u32 = hash_wstr_const(GDI32_DLL_W);

// ── API hash constants (user32) ──────────────────────────────────────────────
#[cfg(windows)]
const HASH_GETDC: u32 = hash_str_const(b"GetDC\0");
#[cfg(windows)]
const HASH_RELEASEDC: u32 = hash_str_const(b"ReleaseDC\0");
#[cfg(windows)]
const HASH_GETSYSTEMMETRICS: u32 = hash_str_const(b"GetSystemMetrics\0");

// ── API hash constants (gdi32) ───────────────────────────────────────────────
#[cfg(windows)]
const HASH_BITBLT: u32 = hash_str_const(b"BitBlt\0");
#[cfg(windows)]
const HASH_CREATECOMPATIBLEBITMAP: u32 = hash_str_const(b"CreateCompatibleBitmap\0");
#[cfg(windows)]
const HASH_CREATECOMPATIBLEDC: u32 = hash_str_const(b"CreateCompatibleDC\0");
#[cfg(windows)]
const HASH_DELETEDC: u32 = hash_str_const(b"DeleteDC\0");
#[cfg(windows)]
const HASH_DELETEOBJECT: u32 = hash_str_const(b"DeleteObject\0");
#[cfg(windows)]
const HASH_GETDIBITS: u32 = hash_str_const(b"GetDIBits\0");
#[cfg(windows)]
const HASH_SELECTOBJECT: u32 = hash_str_const(b"SelectObject\0");

// ── Function pointer types (user32) ──────────────────────────────────────────
#[cfg(windows)]
type FnGetDC = unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void;
#[cfg(windows)]
type FnReleaseDC = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;
#[cfg(windows)]
type FnGetSystemMetrics = unsafe extern "system" fn(i32) -> i32;

// ── Function pointer types (gdi32) ───────────────────────────────────────────
#[cfg(windows)]
type FnBitBlt = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    i32,
    i32,
    i32,
    i32,
    *mut std::ffi::c_void,
    i32,
    i32,
    u32,
) -> i32;
#[cfg(windows)]
type FnCreateCompatibleBitmap =
    unsafe extern "system" fn(*mut std::ffi::c_void, i32, i32) -> *mut std::ffi::c_void;
#[cfg(windows)]
type FnCreateCompatibleDC =
    unsafe extern "system" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void;
#[cfg(windows)]
type FnDeleteDC = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
#[cfg(windows)]
type FnDeleteObject = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
#[cfg(windows)]
type FnGetDIBits = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    u32,
    u32,
    *mut std::ffi::c_void,
    *mut winapi::um::wingdi::BITMAPINFO,
    u32,
) -> i32;
#[cfg(windows)]
type FnSelectObject = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
) -> *mut std::ffi::c_void;

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
/// `HKCU\Software\SysNotify\Consent` (DWORD) must be `1`.
#[cfg(windows)]
fn check_consent() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let sys_key = hkcu.open_subkey("Software\\SysNotify")?;
    let consent: u32 = sys_key.get_value("Consent")?;
    if consent == 1 {
        Ok(())
    } else {
        Err(anyhow!(
            "Remote assistance consent not granted. \
             Set HKCU\\Software\\SysNotify\\Consent (DWORD) = 1 to enable remote assistance."
        ))
    }
}

/// Captures the primary monitor's screen and returns it as PNG bytes.
pub fn take_screenshot() -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        check_consent()?;
        // Priority 1: Wayland session → xdg-desktop-portal Screenshot portal.
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            match capture_wayland_portal() {
                Ok(bytes) => return Ok(bytes),
                Err(e) => log::warn!(
                    "xdg-desktop-portal screenshot failed ({}); falling back to X11/fb0",
                    e
                ),
            }
        }
        // Priority 2: X11 via x11rb.
        if std::env::var_os("DISPLAY").is_some() {
            match capture_x11() {
                Ok(bytes) => return Ok(bytes),
                Err(e) => log::warn!(
                    "X11 screen capture failed ({}); falling back to /dev/fb0",
                    e
                ),
            }
        }
        // Priority 3: raw framebuffer (headless servers, VTs).
        capture_fb0()
    }
    #[cfg(windows)]
    {
        check_consent()?;
        use std::io::Cursor;
        use winapi::um::wingdi::{BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY};
        use winapi::um::winuser::{SM_CXSCREEN, SM_CYSCREEN};

        // SAFETY: All Win32 handles are checked for null before use and are
        // released in reverse-acquisition order even on early returns.
        let png_bytes = unsafe {
            // Resolve user32 functions at runtime (no IAT entries).
            let get_system_metrics: FnGetSystemMetrics =
                resolve_api_or_load(USER32_DLL_W, HASH_USER32_DLL, HASH_GETSYSTEMMETRICS)?;
            let get_dc: FnGetDC = resolve_api_or_load(USER32_DLL_W, HASH_USER32_DLL, HASH_GETDC)?;
            let release_dc: FnReleaseDC =
                resolve_api_or_load(USER32_DLL_W, HASH_USER32_DLL, HASH_RELEASEDC)?;

            // Resolve gdi32 functions at runtime (no IAT entries).
            let create_compatible_dc: FnCreateCompatibleDC =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_CREATECOMPATIBLEDC)?;
            let create_compatible_bitmap: FnCreateCompatibleBitmap =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_CREATECOMPATIBLEBITMAP)?;
            let select_object: FnSelectObject =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_SELECTOBJECT)?;
            let bit_blt: FnBitBlt = resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_BITBLT)?;
            let get_di_bits: FnGetDIBits =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_GETDIBITS)?;
            let delete_object: FnDeleteObject =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_DELETEOBJECT)?;
            let delete_dc: FnDeleteDC =
                resolve_api_or_load(GDI32_DLL_W, HASH_GDI32_DLL, HASH_DELETEDC)?;

            let width = get_system_metrics(SM_CXSCREEN);
            let height = get_system_metrics(SM_CYSCREEN);
            if width <= 0 || height <= 0 {
                return Err(anyhow!(
                    "GetSystemMetrics returned invalid screen dimensions: {}x{}",
                    width,
                    height
                ));
            }

            let hdc_screen = get_dc(std::ptr::null_mut());
            if hdc_screen.is_null() {
                return Err(anyhow!("GetDC failed — no desktop DC available"));
            }

            let hdc_mem = create_compatible_dc(hdc_screen);
            if hdc_mem.is_null() {
                release_dc(std::ptr::null_mut(), hdc_screen);
                return Err(anyhow!("CreateCompatibleDC failed"));
            }

            let hbm: *mut std::ffi::c_void = create_compatible_bitmap(hdc_screen, width, height);
            if hbm.is_null() {
                delete_dc(hdc_mem);
                release_dc(std::ptr::null_mut(), hdc_screen);
                return Err(anyhow!("CreateCompatibleBitmap failed"));
            }

            let old_obj = select_object(hdc_mem, hbm);
            let blt_ok = bit_blt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

            if blt_ok == 0 {
                select_object(hdc_mem, old_obj);
                delete_object(hbm);
                delete_dc(hdc_mem);
                release_dc(std::ptr::null_mut(), hdc_screen);
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

            let scan_lines = get_di_bits(
                hdc_mem,
                hbm,
                0,
                height as u32,
                pixels.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            );

            select_object(hdc_mem, old_obj);
            delete_object(hbm);
            delete_dc(hdc_mem);
            release_dc(std::ptr::null_mut(), hdc_screen);

            if scan_lines == 0 {
                return Err(anyhow!("GetDIBits failed — could not read screen pixels"));
            }

            // GDI returns BGRA; the `image` crate RGBA buffer expects R at index 0.
            // Swap B (index 0) and R (index 2) in every 4-byte pixel.
            for chunk in pixels.chunks_exact_mut(4) {
                chunk.swap(0, 2);
            }

            let img = image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(
                width as u32,
                height as u32,
                pixels,
            )
            .ok_or_else(|| anyhow!("failed to construct RGBA image buffer from GDI pixels"))?;

            let mut png_buf: Vec<u8> = Vec::new();
            img.write_to(&mut Cursor::new(&mut png_buf), image::ImageFormat::Png)?;
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
                        "CoreGraphics returned invalid screenshot size: {}x{} — \
                         Screen Recording permission may not be granted",
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

                    // ── Screen Recording permission check ─────────────────
                    // On macOS 10.15+, CGWindowListCreateImage returns a valid
                    // but *blank* image (typically all black or all zeros) when
                    // the Screen Recording permission has not been granted to
                    // the calling process.  Detect this by sampling pixels
                    // across the image — if all sampled pixels are identical
                    // (R==G==B==0, fully opaque), the capture is blank.
                    {
                        let pixel_count = width * height;
                        // Sample up to 256 evenly-spaced pixels.
                        let step = (pixel_count / 256).max(1);
                        let mut all_blank = true;
                        let first_r = rgba[0];
                        let first_g = rgba[1];
                        let first_b = rgba[2];
                        for i in (0..pixel_count).step_by(step) {
                            let idx = i * 4;
                            if rgba[idx] != first_r
                                || rgba[idx + 1] != first_g
                                || rgba[idx + 2] != first_b
                            {
                                all_blank = false;
                                break;
                            }
                        }
                        if all_blank && first_r == 0 && first_g == 0 && first_b == 0 {
                            return Err(anyhow!(
                                "Screen capture produced a blank image — \
                                 Screen Recording permission is required. \
                                 Grant it in System Settings → Privacy & Security → Screen Recording"
                            ));
                        }
                    }

                    let img =
                        ImageBuffer::<Rgba<u8>, _>::from_raw(width as u32, height as u32, rgba)
                            .ok_or_else(|| {
                                anyhow!("failed to create image buffer from CoreGraphics data")
                            })?;

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
