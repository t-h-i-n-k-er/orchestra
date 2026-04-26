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
}

/// Adapter that wraps a raw [`PluginObject`] and exposes it as `dyn Plugin`.
///
/// This is an implementation detail of the loader and is not part of the public API.
struct FfiPlugin(*mut PluginObject);

// SAFETY: We are the sole owner after creation; the underlying plugin is
// required to be Send+Sync by construction.
unsafe impl Send for FfiPlugin {}
unsafe impl Sync for FfiPlugin {}

impl Plugin for FfiPlugin {
    fn init(&self) -> Result<()> {
        let rc = unsafe { ((*(*self.0).vtable).init)(self.0) };
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
            ((*(*self.0).vtable).execute)(
                self.0,
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
        unsafe { ((*(*self.0).vtable).free_result)(out_ptr, out_len) };
        String::from_utf8(bytes)
            .map_err(|e| anyhow!("plugin execute() returned non-UTF-8 output: {}", e))
    }
}

impl Drop for FfiPlugin {
    fn drop(&mut self) {
        // SAFETY: We own the object; destroy() frees it using the plugin's allocator.
        unsafe { ((*(*self.0).vtable).destroy)(self.0) };
    }
}

fn initialized_plugin(plugin_ptr: *mut PluginObject) -> Result<Box<dyn Plugin>> {
    if plugin_ptr.is_null() {
        return Err(anyhow!("_create_plugin() returned a null pointer"));
    }
    let plugin = Box::new(FfiPlugin(plugin_ptr)) as Box<dyn Plugin>;
    plugin.init()?;
    Ok(plugin)
}

/// Loads a decrypted, signed plugin from a byte slice into a `Box<dyn Plugin>`.
///
/// * `encrypted_blob`: The raw bytes of the plugin, encrypted with AES-256-GCM.
/// * `session`: The `CryptoSession` to use for decryption.
/// * `verify_key`: Optional base64-encoded Ed25519 verifying key.  When `None`
///   the compile-time constant `MODULE_SIGNING_PUBKEY` is used.
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
                    return initialized_plugin(plugin_ptr);
                }
                // Export not found — free the mapped image rather than falling
                // through to the temp-file path with a partially-initialised DLL.
                unsafe {
                    winapi::um::memoryapi::VirtualFree(
                        image_base,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
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

    let plugin_ptr = unsafe { create_func() };

    // Leak the library so the plugin's code remains mapped for the process lifetime.
    std::mem::forget(library);

    initialized_plugin(plugin_ptr)
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
}
