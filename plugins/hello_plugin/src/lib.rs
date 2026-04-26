use module_loader::{PluginObject, PluginVTable};

// ─────────────────────────────────────────────────────────────────────────────
// Concrete plugin type
// ─────────────────────────────────────────────────────────────────────────────

/// The plugin's private data.  `hdr` MUST be the first field so that a
/// `*mut HelloPluginObj` can be safely cast to `*mut PluginObject` and back.
#[repr(C)]
struct HelloPluginObj {
    hdr: PluginObject,
}

// ─────────────────────────────────────────────────────────────────────────────
// C-ABI vtable implementation
// ─────────────────────────────────────────────────────────────────────────────

unsafe extern "C" fn plugin_init(_this: *mut PluginObject) -> i32 {
    0 // Nothing to initialise.
}

unsafe extern "C" fn plugin_execute(
    _this: *mut PluginObject,
    args_ptr: *const u8,
    args_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let args = std::str::from_utf8(std::slice::from_raw_parts(args_ptr, args_len))
        .unwrap_or("");
    let result = format!("Hello, {}", args);
    let bytes = result.into_bytes();
    *out_len = bytes.len();
    // Transfer ownership to the caller; they must call free_result() when done.
    let ptr = bytes.as_ptr() as *mut u8;
    std::mem::forget(bytes);
    *out_ptr = ptr;
    0
}

unsafe extern "C" fn plugin_free_result(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // Re-construct the Vec so its allocator can free it correctly.
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

unsafe extern "C" fn plugin_destroy(this: *mut PluginObject) {
    drop(Box::from_raw(this as *mut HelloPluginObj));
}

static HELLO_VTABLE: PluginVTable = PluginVTable {
    init: plugin_init,
    execute: plugin_execute,
    free_result: plugin_free_result,
    destroy: plugin_destroy,
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Stable C-ABI entry point required by the module loader.
///
/// Returns a heap-allocated `HelloPluginObj` whose first field is a
/// `PluginObject` header.  The caller takes ownership and must eventually
/// invoke `vtable.destroy()` to release the allocation.
#[no_mangle]
pub extern "C" fn _create_plugin() -> *mut PluginObject {
    let obj = Box::new(HelloPluginObj {
        hdr: PluginObject { vtable: &HELLO_VTABLE },
    });
    // Cast to *mut PluginObject — safe because `hdr` is the first field and
    // HelloPluginObj is #[repr(C)].
    Box::into_raw(obj) as *mut PluginObject
}
