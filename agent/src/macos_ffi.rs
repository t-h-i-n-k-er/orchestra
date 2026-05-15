//! Shared macOS FFI type definitions and bindings.
//!
//! This module centralises CoreGraphics, CoreFoundation, and Security
//! framework types and `extern "C"` declarations that are used by multiple
//! crates/modules (`remote_assist`, `macos_postexp`, `env_check_sandbox`).
//!
//! **Why not a crate dependency?** All consumers are inside the same `agent`
//! crate and the types are trivial FFI wrappers — a separate crate would add
//! compilation overhead for no benefit.

// ═══════════════════════════════════════════════════════════════════════════
// CoreFoundation types
// ═══════════════════════════════════════════════════════════════════════════

pub type CFAllocatorRef = *const std::ffi::c_void;
pub type CFTypeRef = *const std::ffi::c_void;
pub type CFDataRef = *const std::ffi::c_void;
pub type CFStringRef = *const std::ffi::c_void;
pub type CFDictionaryRef = *const std::ffi::c_void;
pub type CFArrayRef = *const std::ffi::c_void;
pub type CFBooleanRef = *const std::ffi::c_void;
pub type CFNumberRef = *const std::ffi::c_void;

pub const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = std::ptr::null();
pub const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// Resolve `kCFBooleanTrue` at runtime by linking the well-known CoreFoundation
/// global symbol.
pub fn kcf_boolean_true() -> CFBooleanRef {
    extern "C" {
        static kCFBooleanTrue: CFBooleanRef;
    }
    unsafe { kCFBooleanTrue }
}

// ═══════════════════════════════════════════════════════════════════════════
// CoreGraphics types
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGPoint {
    pub x: f64,
    pub y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

pub type CGEventRef = *const std::ffi::c_void;
pub type CGEventSourceRef = *const std::ffi::c_void;
pub type CGImageRef = *mut std::ffi::c_void;
pub type CGDataProviderRef = *mut std::ffi::c_void;

// ═══════════════════════════════════════════════════════════════════════════
// CoreGraphics constants
// ═══════════════════════════════════════════════════════════════════════════

pub const KCG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1;
pub const KCG_NULL_WINDOW_ID: u32 = 0;
pub const KCG_WINDOW_IMAGE_DEFAULT: u32 = 0;

pub const K_CGEVENT_MOUSE_DOWN: u32 = 1;
pub const K_CGEVENT_MOUSE_UP: u32 = 2;
pub const K_CGEVENT_LEFT_BUTTON: u32 = 0;
pub const _K_CGEVENT_SOURCE_STATE_HID_SYSTEM: u32 = 1;

// ═══════════════════════════════════════════════════════════════════════════
// CoreFoundation extern bindings
// ═══════════════════════════════════════════════════════════════════════════

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    pub fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const i8,
        encoding: u32,
    ) -> CFStringRef;
    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFDataGetLength(data: CFDataRef) -> isize;
    pub fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    pub fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const std::ffi::c_void)
        -> *const std::ffi::c_void;
    pub fn CFDictionaryCreate(
        alloc: CFAllocatorRef,
        keys: *const *const std::ffi::c_void,
        values: *const *const std::ffi::c_void,
        num_values: isize,
        key_callbacks: *const std::ffi::c_void,
        value_callbacks: *const std::ffi::c_void,
    ) -> CFDictionaryRef;
    pub fn CFArrayGetCount(array: CFArrayRef) -> isize;
    pub fn CFArrayGetValueAtIndex(array: CFArrayRef, idx: isize) -> *const std::ffi::c_void;
    pub fn CFBooleanGetValue(boolean: CFBooleanRef) -> u8;
    pub fn CFNumberCreate(
        alloc: CFAllocatorRef,
        the_type: i32,
        value_ptr: *const std::ffi::c_void,
    ) -> CFNumberRef;
    pub fn CFNumberGetValue(
        number: CFNumberRef,
        the_type: i32,
        value_ptr: *mut std::ffi::c_void,
    ) -> u8;
    pub fn CFGetTypeID(cf: CFTypeRef) -> usize;
    pub fn CFStringGetLength(the_string: CFStringRef) -> isize;
    pub fn CFStringGetCString(
        the_string: CFStringRef,
        buffer: *mut i8,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
}

// CoreFoundation exported globals for dictionary callbacks.
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    pub static kCFTypeDictionaryKeyCallBacks: *const std::ffi::c_void;
    pub static kCFTypeDictionaryValueCallBacks: *const std::ffi::c_void;
}

// ═══════════════════════════════════════════════════════════════════════════
// CoreGraphics extern bindings (screenshot / display)
// ═══════════════════════════════════════════════════════════════════════════

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    pub fn CGMainDisplayID() -> u32;
    pub fn CGDisplayBounds(display: u32) -> CGRect;
    pub fn CGWindowListCreateImage(
        screen_bounds: CGRect,
        list_option: u32,
        window_id: u32,
        image_option: u32,
    ) -> CGImageRef;
    pub fn CGImageGetWidth(image: CGImageRef) -> usize;
    pub fn CGImageGetHeight(image: CGImageRef) -> usize;
    pub fn CGImageGetBytesPerRow(image: CGImageRef) -> usize;
    pub fn CGImageGetBitsPerPixel(image: CGImageRef) -> usize;
    pub fn CGImageGetDataProvider(image: CGImageRef) -> CGDataProviderRef;
    pub fn CGDataProviderCopyData(provider: CGDataProviderRef) -> CFDataRef;
}

// ═══════════════════════════════════════════════════════════════════════════
// CoreGraphics extern bindings (event / input)
// ═══════════════════════════════════════════════════════════════════════════

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    pub fn CGEventCreateMouseEvent(
        source: CGEventSourceRef,
        mouse_type: u32,
        mouse_location: CGPoint,
        mouse_button: u32,
    ) -> CGEventRef;
    pub fn CGEventPost(tap_location: u32, event: CGEventRef);
    pub fn CGEventCreate(source: *const std::ffi::c_void) -> CGEventRef;
    pub fn CGEventGetLocation(event: CGEventRef) -> CGPoint;
}
