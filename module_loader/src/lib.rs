//! Capability plugin loading for dynamically-deployed Orchestra modules.
//!
//! This module handles fetching, decrypting, verifying, and loading shared
//! libraries (`.so`, `.dll`) into the agent process.  The loading strategy
//! varies by platform and build configuration:
//!
//! * **Linux**: Uses `memfd_create(2)` + `/proc/self/fd/<fd>` — the plugin
//!   bytes are never written to any mounted filesystem.  This is the only
//!   truly in-memory path.
//!
//! * **Windows (with `manual-map` feature)**: Performs a reflective PE load
//!   via `manual_map::load_dll_in_memory`.  The DLL image lives in a private
//!   heap allocation; no filesystem write occurs.  Requires the `manual-map`
//!   feature to be enabled at build time.
//!
//! * **Windows (without `manual-map`) / macOS / other**: Falls back to a
//!   temporary file with the shortest possible lifetime (`FILE_FLAG_DELETE_ON_CLOSE`
//!   on Windows; `tempfile` on UNIX).  The file is visible on-disk during
//!   load and is **not** an in-memory operation.
//!
//! ## Plugin ABI
//!
//! Plugins export a single C-ABI symbol `_create_plugin` whose signature is:
//! ```c
//! PluginObject* _create_plugin(void);
//! ```
//! `PluginObject` contains a pointer to a `PluginVTable` — a `#[repr(C)]`
//! struct of function pointers — so the ABI is fully defined at the C level
//! and does not depend on Rust fat-pointer or vtable layout stability.
//!
//! `load_plugin` calls `Plugin::init` exactly once before returning the boxed
//! plugin, so callers can register or execute the returned plugin immediately.

use anyhow::{anyhow, Result};
use common::CryptoSession;
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(not(windows))]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};
use tracing::info;

/// Manual PE-map loader (Windows only, requires the `manual-map` feature).
#[cfg(all(windows, feature = "manual-map"))]
pub mod manual_map;

#[cfg(feature = "module-signatures")]
use ed25519_dalek::{Signature, VerifyingKey};

#[cfg(feature = "module-signatures")]
#[allow(dead_code)]
const MODULE_SIGNING_PUBKEY: [u8; 32] = [
    0xc4, 0x5a, 0x22, 0x2a, 0x6a, 0x94, 0x86, 0xa5, 0xef, 0x72, 0xa7, 0xee, 0x2e, 0xb2, 0x4d, 0xf3,
    0x2e, 0xe5, 0x8c, 0x14, 0x0a, 0xe4, 0x09, 0x7f, 0x2e, 0x56, 0x96, 0xf9, 0x46, 0x7b, 0x26, 0x79,
];

// Signing seed whose verifying key equals MODULE_SIGNING_PUBKEY (test use only).
#[cfg(all(test, feature = "module-signatures"))]
const MODULE_TEST_SIGNING_SEED: [u8; 32] = [
    0x3, 0x6a, 0x2e, 0x3c, 0x3a, 0x3e, 0x5c, 0x1d, 0x5a, 0x4, 0x1b, 0x2, 0x1d, 0x5e, 0x4, 0x4, 0x4,
    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
];

// ──────────────────────────────────────────────────────────────────────────────
// Stable plugin ABI
//
// `*mut dyn Plugin` is a Rust fat pointer whose vtable layout is an
// implementation detail of rustc — it is not stable across compiler versions,
// optimisation settings, or separately-compiled crates.  We replace it with an
// explicit `#[repr(C)]` vtable struct so that the calling convention is
// well-defined at the C level and therefore safe across build environments.
// ──────────────────────────────────────────────────────────────────────────────

/// Function-pointer table that each plugin must populate.
///
/// All fields use `extern "C"` so the layout and calling convention are stable.
///
/// # ABI Stability
///
/// These four entries are guaranteed to remain at these offsets.  Extended
/// capabilities (metadata, binary execution) are exposed via a separate
/// [`PluginVTableExt`] table that plugins can optionally export.
#[repr(C)]
pub struct PluginVTable {
    /// One-time initialisation.  Returns 0 on success, non-zero on failure.
    pub init: unsafe extern "C" fn(this: *mut PluginObject) -> i32,

    /// Execute the plugin.  On success returns 0 and writes a heap-allocated
    /// UTF-8 byte buffer into `*out_ptr` / `*out_len`; the caller must release
    /// it via `free_result`.  On error returns non-zero.
    pub execute: unsafe extern "C" fn(
        this: *mut PluginObject,
        args_ptr: *const u8,
        args_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,

    /// Free a result buffer previously written by `execute`.  Must use the
    /// allocator of the *plugin* library (not the loader's allocator).
    pub free_result: unsafe extern "C" fn(ptr: *mut u8, len: usize),

    /// Destroy the plugin instance and release all associated resources.
    pub destroy: unsafe extern "C" fn(this: *mut PluginObject),
}

/// **Extended** vtable for plugins that support metadata and binary I/O.
///
/// Plugins that want to participate in the extended framework export a
/// `_get_plugin_vtable_ext() -> *const PluginVTableExt` symbol in addition
/// to the mandatory `_create_plugin()` entry point.  The loader queries
/// this symbol after loading the library; if it is absent, all extended
/// features fall back to sensible defaults and the plugin still works.
#[repr(C)]
pub struct PluginVTableExt {
    /// Size-of-self for forward-compatible versioning.  Must be set to
    /// `std::mem::size_of::<PluginVTableExt>()`.
    pub size: usize,

    /// Return a JSON-encoded [`PluginMetadata`] string.  The returned buffer
    /// is owned by the plugin and must be freed with `free_metadata`.
    /// On success returns 0 and writes a heap-allocated buffer.
    /// On error returns non-zero.
    pub get_metadata: Option<unsafe extern "C" fn(this: *mut PluginObject, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32>,

    /// Free a metadata string previously returned by `get_metadata`.
    pub free_metadata: Option<unsafe extern "C" fn(ptr: *mut u8, len: usize)>,

    /// Binary execution path.  Takes arbitrary bytes as input and returns
    /// arbitrary bytes as output.  On success returns 0 and writes a
    /// heap-allocated buffer into `*out_ptr` / `*out_len`.  The caller must
    /// free it via `free_binary_result`.  On error returns non-zero.
    pub execute_binary: Option<unsafe extern "C" fn(
        this: *mut PluginObject,
        in_ptr: *const u8,
        in_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32>,

    /// Free a binary result buffer previously written by `execute_binary`.
    pub free_binary_result: Option<unsafe extern "C" fn(ptr: *mut u8, len: usize)>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Plugin metadata and registry types
// ──────────────────────────────────────────────────────────────────────────────

/// Metadata describing a loaded plugin's capabilities and requirements.
///
/// Populated via the `get_metadata` vtable entry when available, or
/// constructed with default/unknown values for legacy plugins.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginMetadata {
    /// Human-readable plugin name.
    pub name: String,
    /// Semantic version string (e.g. "1.0.0").
    pub version: String,
    /// One-line description of the plugin's purpose.
    pub description: String,
    /// Optional author attribution.
    #[serde(default)]
    pub author: Option<String>,
    /// Capability identifiers (e.g. "credential-harvesting",
    /// "process-inspection", "network-discovery").
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Minimum agent version required, if applicable.
    #[serde(default)]
    pub min_agent_version: Option<String>,
    /// Privilege level required: "user", "elevated", or "system".
    #[serde(default)]
    pub privilege_required: Option<String>,
}

impl PluginMetadata {
    /// Construct a default metadata object for a legacy plugin that does not
    /// implement `get_metadata`.
    pub fn default_for(plugin_id: &str) -> Self {
        Self {
            name: plugin_id.to_string(),
            version: "unknown".to_string(),
            description: "(no metadata available)".to_string(),
            author: None,
            capabilities: Vec::new(),
            min_agent_version: None,
            privilege_required: None,
        }
    }
}

/// A loaded plugin together with its metadata and load timestamp.
///
/// This is the value type stored in the agent's `LOADED_PLUGINS` registry.
pub struct LoadedPlugin {
    /// The loaded plugin instance.
    pub plugin: Arc<Box<dyn Plugin + Send + Sync>>,
    /// Metadata extracted from the plugin (or default values).
    pub metadata: PluginMetadata,
    /// Unix epoch seconds when the plugin was loaded.
    pub load_timestamp: u64,
}

/// Header that every plugin instance must start with (first field, `#[repr(C)]`).
///
/// This allows a `*mut ConcretePlugin` to be safely cast to `*mut PluginObject`
/// and back.
#[repr(C)]
pub struct PluginObject {
    /// Pointer to the plugin's static vtable.  Valid for the lifetime of the object.
    pub vtable: *const PluginVTable,
}

// ──────────────────────────────────────────────────────────────────────────────
// Host-side `Plugin` trait and FFI adapter
// ──────────────────────────────────────────────────────────────────────────────

/// The trait that all Orchestra plugins must implement on the host side.
///
/// Plugin libraries do **not** implement this trait directly — they export
/// `_create_plugin() -> *mut PluginObject`.  The loader wraps the returned
/// object in the private [`FfiPlugin`] adapter which then implements this trait.
pub trait Plugin: Send + Sync {
    /// Called once after the plugin is loaded.
    fn init(&self) -> Result<()>;
    /// The main entry point for executing the plugin's logic.
    fn execute(&self, args: &str) -> Result<String>;
    /// Optional binary execution path for plugins that accept/return raw bytes.
    /// The default implementation returns `Err` so that existing plugins are
    /// not required to implement it.  When the vtable's `execute_binary` entry
    /// is available, [`FfiPlugin`] overrides this with a real implementation.
    fn execute_binary(&self, _input: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("plugin does not support binary execution"))
    }
    /// Return plugin metadata, if the vtable provides `get_metadata`.
    /// The default implementation returns `None`.
    fn get_metadata(&self) -> Option<PluginMetadata> {
        None
    }
}

/// Adapter that wraps a raw [`PluginObject`] and exposes it as `dyn Plugin`.
///
/// This is an implementation detail of the loader and is not part of the public API.
struct FfiPlugin {
    obj: *mut PluginObject,
    /// Optional extended vtable, resolved via `_get_plugin_vtable_ext`.
    ext: Option<*const PluginVTableExt>,
}

// SAFETY: We are the sole owner after creation; the underlying plugin is
// required to be Send+Sync by construction.
unsafe impl Send for FfiPlugin {}
unsafe impl Sync for FfiPlugin {}

impl Plugin for FfiPlugin {
    fn init(&self) -> Result<()> {
        let rc = unsafe { ((*(*self.obj).vtable).init)(self.obj) };
        if rc != 0 {
            Err(anyhow!("plugin init() returned error code {}", rc))
        } else {
            Ok(())
        }
    }

    fn execute(&self, args: &str) -> Result<String> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            ((*(*self.obj).vtable).execute)(
                self.obj,
                args.as_ptr(),
                args.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(anyhow!("plugin execute() returned error code {}", rc));
        }
        if out_ptr.is_null() {
            return Err(anyhow!("plugin execute() returned a null output buffer"));
        }
        // Copy bytes out before we release the plugin-owned allocation.
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len).to_vec() };
        unsafe { ((*(*self.obj).vtable).free_result)(out_ptr, out_len) };
        String::from_utf8(bytes)
            .map_err(|e| anyhow!("plugin execute() returned non-UTF-8 output: {}", e))
    }

    fn execute_binary(&self, input: &[u8]) -> Result<Vec<u8>> {
        let ext = self
            .ext
            .ok_or_else(|| anyhow!("plugin does not support binary execution"))?;
        let vtable = unsafe { &*ext };
        let execute_fn = vtable
            .execute_binary
            .ok_or_else(|| anyhow!("plugin does not support binary execution"))?;
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            execute_fn(self.obj, input.as_ptr(), input.len(), &mut out_ptr, &mut out_len)
        };
        if rc != 0 {
            return Err(anyhow!("plugin execute_binary() returned error code {}", rc));
        }
        if out_ptr.is_null() {
            return Err(anyhow!("plugin execute_binary() returned a null output buffer"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len).to_vec() };
        if let Some(free_fn) = vtable.free_binary_result {
            unsafe { free_fn(out_ptr, out_len) };
        }
        Ok(bytes)
    }

    fn get_metadata(&self) -> Option<PluginMetadata> {
        let ext_ptr = self.ext?;
        let vtable = unsafe { &*ext_ptr };
        let get_fn = vtable.get_metadata?;
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe { get_fn(self.obj, &mut out_ptr, &mut out_len) };
        if rc != 0 || out_ptr.is_null() {
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len).to_vec() };
        if let Some(free_fn) = vtable.free_metadata {
            unsafe { free_fn(out_ptr, out_len) };
        }
        serde_json::from_slice(&bytes).ok()
    }
}

impl Drop for FfiPlugin {
    fn drop(&mut self) {
        // SAFETY: We own the object; destroy() frees it using the plugin's allocator.
        unsafe { ((*(*self.obj).vtable).destroy)(self.obj) };
    }
}

fn initialized_plugin(plugin_ptr: *mut PluginObject, ext: Option<*const PluginVTableExt>) -> Result<Box<dyn Plugin>> {
    if plugin_ptr.is_null() {
        return Err(anyhow!("_create_plugin() returned a null pointer"));
    }
    let plugin = Box::new(FfiPlugin { obj: plugin_ptr, ext }) as Box<dyn Plugin>;
    plugin.init()?;
    Ok(plugin)
}

/// Convenience wrapper: load a plugin and return it as a [`LoadedPlugin`] with
/// metadata and timestamp.
fn loaded_plugin_with_metadata(
    plugin_ptr: *mut PluginObject,
    ext: Option<*const PluginVTableExt>,
    plugin_id: &str,
) -> Result<LoadedPlugin> {
    let plugin = initialized_plugin(plugin_ptr, ext)?;
    let metadata = plugin
        .get_metadata()
        .unwrap_or_else(|| PluginMetadata::default_for(plugin_id));
    let load_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(LoadedPlugin {
        plugin: Arc::new(plugin),
        metadata,
        load_timestamp,
    })
}

/// Loads a decrypted, signed plugin from a byte slice into a `Box<dyn Plugin>`.
///
/// * `encrypted_blob`: The raw bytes of the plugin, encrypted with AES-256-GCM.
/// * `session`: The `CryptoSession` to use for decryption.
/// * `verify_key`: Optional base64-encoded Ed25519 verifying key.
///   - When `Some(b64)`, the blob signature is verified against the decoded key.
///   - When `None` and the `strict-module-key` feature is **disabled**, the
///     compile-time constant `MODULE_SIGNING_PUBKEY` is used as a fallback.
///     This is convenient for tests and development builds.
///   - When `None` and the `strict-module-key` feature is **enabled**, this
///     function returns `Err` immediately.  Production builds should enable
///     `strict-module-key` to prevent silent fallback to the embedded key.
///
/// # Safety
///
/// This function loads a native shared library. The library must be compiled
/// from trusted source and must export `_create_plugin() -> *mut PluginObject`
/// using the stable C ABI defined by [`PluginVTable`] and [`PluginObject`].
/// The loaded code executes with the same privileges as the host process.
pub fn load_plugin(
    encrypted_blob: &[u8],
    session: &CryptoSession,
    verify_key: Option<&str>,
) -> Result<Box<dyn Plugin>> {
    // 1. Decrypt the blob. The GCM tag provides authentication.
    let decrypted_blob = session
        .decrypt(encrypted_blob)
        .map_err(|e| anyhow!("Plugin decryption failed: {}", e))?;
    info!(
        "Plugin decrypted successfully ({} bytes)",
        decrypted_blob.len()
    );

    #[cfg(feature = "module-signatures")]
    let module_data = {
        if decrypted_blob.len() < 64 {
            return Err(anyhow!("Module is too small to contain a signature."));
        }
        let (signature_bytes, module_bytes) = decrypted_blob.split_at(64);
        let signature = Signature::from_bytes(signature_bytes.try_into()?);
        let pub_key_bytes: [u8; 32] = if let Some(b64) = verify_key {
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b64.trim(),
            )
            .map_err(|e| anyhow!("module_verify_key is not valid base64: {e}"))?;
            raw.try_into()
                .map_err(|_| anyhow!("module_verify_key must be exactly 32 bytes"))?
        } else {
            // When the `strict-module-key` feature is enabled, a missing
            // runtime key is a hard error.  This prevents an attacker who can
            // modify the binary from substituting a different embedded key
            // while silently accepting modules signed with the new key.
            //
            // The compile-time fallback is only available without
            // `strict-module-key` — useful for the test suite and development
            // builds where a full key-management setup is not yet in place.
            #[cfg(feature = "strict-module-key")]
            {
                return Err(anyhow!(
                    "module_verify_key must be supplied at runtime when `strict-module-key` \
                     is enabled.  Pass a base64-encoded Ed25519 public key to `load_plugin`."
                ));
            }
            #[cfg(not(feature = "strict-module-key"))]
            MODULE_SIGNING_PUBKEY
        };
        let public_key = VerifyingKey::from_bytes(&pub_key_bytes)?;
        public_key.verify_strict(module_bytes, &signature)?;
        info!("Module signature verified successfully.");
        module_bytes
    };

    #[cfg(not(feature = "module-signatures"))]
    let module_data = decrypted_blob.as_slice();

    // 2. Load the library from memory.
    #[cfg(target_os = "linux")]
    let library = {
        // On Linux, we use `memfd_create` to get an in-memory file descriptor.
        // This is ideal because the file doesn't exist on any mounted filesystem.
        let name = std::ffi::CString::new("orchestra_plugin").unwrap();
        // SAFETY: `name` is a valid nul-terminated C string and `MFD_CLOEXEC`
        // is a documented flag value.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd == -1 {
            return Err(anyhow!(
                "Failed to create memfd: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(module_data)?;

        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        info!("Loading plugin from in-memory path: {}", path);
        // The library is dropped when `file` is dropped, closing the fd.
        // SAFETY: The path is valid and we trust the decrypted blob.
        unsafe { Library::new(path)? }
    };

    #[cfg(not(target_os = "linux"))]
    let library = {
        #[cfg(all(windows, feature = "manual-map"))]
        {
            info!("Attempting to load plugin using manual map loader.");
            if let Ok(image_base) = unsafe { manual_map::load_dll_in_memory(module_data) } {
                // Resolve the _create_plugin export RVA from the original flat
                // file (goblin parses the on-disk layout, not the mapped image).
                let mut rva = 0usize;
                if let Some(pe) = goblin::pe::PE::parse(module_data).ok() {
                    for export in &pe.exports {
                        if export.name == Some("_create_plugin") {
                            rva = export.rva;
                            break;
                        }
                    }
                }
                if rva != 0 {
                    // Use the stable C ABI: _create_plugin returns *mut PluginObject.
                    let plugin_ptr = unsafe {
                        let create_func: unsafe extern "C" fn() -> *mut PluginObject =
                            std::mem::transmute(image_base.add(rva));
                        create_func()
                    };
                    // Library memory is leaked intentionally (plugin lifetime = process lifetime).
                    return initialized_plugin(plugin_ptr, None);
                }
                // Export not found — free the mapped image rather than falling
                // through to the temp-file path with a partially-initialised DLL.
                // Use NtFreeVirtualMemory via nt_syscall to avoid IAT-visible
                // VirtualFree hooks.
                unsafe {
                    let mut base = image_base;
                    let mut size: usize = 0;
                    let _ = nt_syscall::syscall!(
                        "NtFreeVirtualMemory",
                        (-1isize) as u64, // current process
                        &mut base as *mut _ as u64,
                        &mut size as *mut _ as u64,
                        winapi::um::winnt::MEM_RELEASE as u64,
                    );
                }
                return Err(anyhow!(
                    "DLL mapped successfully but the required '_create_plugin' export is missing"
                ));
            }
            info!("Manual map failed, falling back to temp file.");
        }
        // Temp-file fallback for non-Linux platforms (or Windows without `manual-map`).
        // The file is written to disk for the duration of the dlopen() call.
        // On Windows we use FILE_FLAG_DELETE_ON_CLOSE to minimise on-disk lifetime.
        #[cfg(windows)]
        let lib = {
            use std::os::windows::fs::OpenOptionsExt;
            let temp_dir = std::env::temp_dir();
            let file_name = format!(
                "plugin-{}.{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                std::env::consts::DLL_EXTENSION
            );
            let tp = temp_dir.join(file_name);
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .share_mode(0x00000001 | 0x00000004) // FILE_SHARE_READ | FILE_SHARE_DELETE
                .custom_flags(0x04000000) // FILE_FLAG_DELETE_ON_CLOSE
                .open(&tp)?;
            std::io::Write::write_all(&mut file, module_data)?;
            // We must leak the file handle. It stays active inside the OS, keeping the file valid.
            // When the process terminates or the library unmaps, the OS deletes it.
            Box::leak(Box::new(file));
            info!("Loading plugin from temporary file: {:?}", &tp);
            unsafe { Library::new(&tp)? }
        };

        #[cfg(not(target_os = "windows"))]
        let lib = {
            let mut temp_file = tempfile::Builder::new()
                .prefix("plugin-")
                .suffix(std::env::consts::DLL_SUFFIX)
                .tempfile()?;
            temp_file.write_all(module_data)?;
            let temp_path = temp_file.path().to_path_buf();
            info!(
                "Loading plugin from temporary file that will be unlinked after dlopen: {:?}",
                &temp_path
            );
            // POSIX `dlopen` keeps the mapped image alive after the pathname is
            // unlinked, so dropping `temp_file` after `Library::new` restores
            // temporary-file semantics.
            let lib = unsafe { Library::new(&temp_path)? };
            drop(temp_file);
            lib
        };
        lib
    };

    // 3. Load `_create_plugin` using the stable C ABI and wrap in FfiPlugin.
    //    The symbol must return *mut PluginObject (not *mut dyn Plugin).
    let create_func: Symbol<unsafe extern "C" fn() -> *mut PluginObject> =
        unsafe { library.get(b"_create_plugin")? };

    // 4. Try to resolve optional extended vtable symbol.
    let ext: Option<*const PluginVTableExt> = unsafe {
        library
            .get::<unsafe extern "C" fn() -> *const PluginVTableExt>(
                b"_get_plugin_vtable_ext\0",
            )
            .ok()
            .map(|sym| sym())
    };

    let plugin_ptr = unsafe { create_func() };

    // Leak the library so the plugin's code remains mapped for the process lifetime.
    std::mem::forget(library);

    initialized_plugin(plugin_ptr, ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    // This test requires the `hello_plugin` to be built first.
    // A `build.rs` script could automate this, but for now, we run it manually.
    fn build_test_plugin() -> PathBuf {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut plugin_dir = PathBuf::from(manifest_dir);
        plugin_dir.pop();
        plugin_dir.push("plugins/hello_plugin");

        let mut cmd = Command::new("cargo");
        cmd.arg("build").current_dir(&plugin_dir);
        // This is needed to find the rust toolchain
        if let Some(path) = std::env::var_os("PATH") {
            let mut paths = std::env::split_paths(&path).collect::<Vec<_>>();
            if let Some(home) = std::env::var_os("HOME") {
                let mut cargo_path = PathBuf::from(home);
                cargo_path.push(".cargo/bin");
                paths.push(cargo_path);
            }
            let new_path = std::env::join_paths(paths).unwrap();
            cmd.env("PATH", new_path);
        }
        let status = cmd.status().expect("Failed to build hello_plugin");
        assert!(status.success(), "hello_plugin build failed");

        let path = PathBuf::from("../target/debug/");
        // The exact filename depends on the OS and cargo's mangling.
        // We find the file with the right extension.
        let lib_file = fs::read_dir(&path)
            .unwrap_or_else(|e| panic!("Failed to read plugin directory: {:?}, error: {}", path, e))
            .find_map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path();
                let file_name = path.file_name().unwrap().to_str().unwrap();
                let expected_prefix = format!("{}hello_plugin", std::env::consts::DLL_PREFIX);
                if file_name.starts_with(&expected_prefix)
                    && file_name.ends_with(std::env::consts::DLL_EXTENSION)
                {
                    Some(path)
                } else {
                    None
                }
            })
            .expect("Could not find compiled plugin library");

        lib_file
    }

    #[tokio::test]
    async fn test_load_and_execute_plugin() {
        // 1. Build the plugin shared library.
        let plugin_path = build_test_plugin();
        let plugin_bytes = fs::read(plugin_path).unwrap();

        // 2. Sign + encrypt (or just encrypt when signatures are not enabled).
        let session = CryptoSession::from_shared_secret(b"test-key");
        #[cfg(feature = "module-signatures")]
        let payload = {
            use ed25519_dalek::Signer;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&MODULE_TEST_SIGNING_SEED);
            let sig = signing_key.sign(&plugin_bytes);
            let mut signed = Vec::with_capacity(64 + plugin_bytes.len());
            signed.extend_from_slice(sig.to_bytes().as_ref());
            signed.extend_from_slice(&plugin_bytes);
            signed
        };
        #[cfg(not(feature = "module-signatures"))]
        let payload = plugin_bytes;
        let encrypted_blob = session.encrypt(&payload);

        // 3. Load it using the module_loader.
        let plugin = load_plugin(&encrypted_blob, &session, None).expect("Failed to load plugin");

        // 4. Loading initializes the plugin; execute verifies it is usable.
        let result = plugin.execute("World").expect("Plugin execution failed");

        assert_eq!(result, "Hello, World");
    }

    #[cfg(all(windows, feature = "manual-map"))]
    #[tokio::test]
    async fn test_manual_map_load() {
        let plugin_path = build_test_plugin();
        let plugin_bytes = fs::read(plugin_path).unwrap();
        let session = CryptoSession::from_shared_secret(b"test-key");
        let encrypted_blob = session.encrypt(&plugin_bytes);
        let plugin =
            load_plugin(&encrypted_blob, &session, None).expect("Failed to load plugin with manual map");
        let result = plugin
            .execute("ManualMap")
            .expect("Plugin execution failed");
        assert_eq!(result, "Hello, ManualMap");
    }

    #[cfg(feature = "module-signatures")]
    #[tokio::test]
    async fn test_tampered_module_fails_verification() {
        // 1. Build the plugin shared library.
        let plugin_path = build_test_plugin();
        let mut plugin_bytes = fs::read(plugin_path).unwrap();

        // 2. Sign it
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&MODULE_TEST_SIGNING_SEED);
        let signature = signing_key.sign(&plugin_bytes);
        let mut signed_payload = Vec::with_capacity(64 + plugin_bytes.len());
        signed_payload.extend_from_slice(signature.to_bytes().as_ref());
        signed_payload.append(&mut plugin_bytes);

        // 3. Encrypt it.
        let session = CryptoSession::from_shared_secret(b"test-key");
        let mut encrypted_blob = session.encrypt(&signed_payload);

        // 4. Tamper with the encrypted blob
        let last_byte_index = encrypted_blob.len() - 1;
        encrypted_blob[last_byte_index] ^= 0x01;

        // 5. Try to load it. It should fail decryption or signature verification.
        let result = load_plugin(&encrypted_blob, &session, None);
        assert!(result.is_err());
    }

    /// When `strict-module-key` is enabled, passing `verify_key = None` must
    /// return an error immediately — it must not silently fall back to the
    /// compile-time `MODULE_SIGNING_PUBKEY`.
    ///
    /// This test is gated on `strict-module-key` and verifies the policy
    /// defined in §11 of `docs/SECURITY_AUDIT.md`.
    #[cfg(feature = "strict-module-key")]
    #[test]
    fn strict_module_key_rejects_none_verify_key() {
        // We do not need a valid blob — the key check happens before any
        // decryption, so an empty blob is sufficient to trigger the error.
        let session = CryptoSession::from_shared_secret(b"test-key");
        // Provide a minimal 64-byte "blob" so we get past the size check and
        // reach the key-selection code.
        let dummy_blob = session.encrypt(&[0u8; 128]);
        let result = load_plugin(&dummy_blob, &session, None);
        assert!(
            result.is_err(),
            "strict-module-key must reject verify_key = None"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("module_verify_key must be supplied"),
            "error message should explain the strict-module-key requirement, got: {msg}"
        );
    }

    /// When `module-signatures` is enabled but `strict-module-key` is NOT,
    /// passing `verify_key = None` must fall back to the compile-time key
    /// rather than returning an error.  The load will still fail (the dummy
    /// data is not a real module) but the failure must NOT be the
    /// "must be supplied" error from strict-module-key.
    #[cfg(all(feature = "module-signatures", not(feature = "strict-module-key")))]
    #[test]
    fn non_strict_mode_allows_none_verify_key() {
        let session = CryptoSession::from_shared_secret(b"test-key");
        let dummy_blob = session.encrypt(&[0u8; 128]);
        let result = load_plugin(&dummy_blob, &session, None);
        // The load will fail (invalid module), but not with the strict-key message.
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("module_verify_key must be supplied"),
                "non-strict mode must not produce strict-key error, got: {e}"
            );
        }
    }
}
