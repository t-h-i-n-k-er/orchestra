//! Secure, in-memory loading for dynamically deployed capability plugins.
//
//! This module handles fetching, decrypting, verifying, and loading shared
//! libraries (`.so`, `.dll`) entirely in memory, without writing the plugin to
//! the filesystem. This is a security and hygiene feature, preventing disk
//! clutter and reducing the attack surface.

use anyhow::{anyhow, Result};
use common::CryptoSession;
use libloading::{Library, Symbol};
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};
use tracing::info;

#[cfg(windows)]
mod manual_map;

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

/// The trait that all Orchestra plugins must implement.
pub trait Plugin: Send + Sync {
    /// Called once after the plugin is loaded. Use for initialization.
    fn init(&self) -> Result<()>;
    /// The main entry point for executing the plugin's logic.
    fn execute(&self, args: &str) -> Result<String>;
}

/// Loads a decrypted, signed plugin from a byte slice into a `Box<dyn Plugin>`.
///
/// * `encrypted_blob`: The raw bytes of the plugin, encrypted with AES-256-GCM.
/// * `session`: The `CryptoSession` to use for decryption.
///
/// # Safety
///
/// This function uses `libloading` to load a native shared library. The library
/// must be compiled from trusted source and expose a `_create_plugin` function
/// that returns a `*mut dyn Plugin`. The loaded code will execute with the same
/// permissions as the host process.
pub fn load_plugin(encrypted_blob: &[u8], session: &CryptoSession) -> Result<Box<dyn Plugin>> {
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
        let public_key = VerifyingKey::from_bytes(&MODULE_SIGNING_PUBKEY)?;
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
        #[cfg(target_os = "windows")]
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
                    unsafe {
                        let create_func: unsafe extern "C" fn() -> *mut dyn Plugin =
                            std::mem::transmute(image_base.add(rva));
                        let plugin_ptr = create_func();
                        let plugin = Box::from_raw(plugin_ptr);
                        return Ok(plugin);
                    }
                }
                // The export was not found. Free the mapped image (best-effort)
                // and return an error rather than falling back to the temp-file
                // path with an already-initialised DLL in memory.
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
        // Fallback for non-Linux OSs (e.g., macOS, Windows).
        // For Windows, a more advanced technique involves CreateFileMapping/MapViewOfFile
        // with SEC_IMAGE, but for simplicity, we'll use a temporary file.
        // This is less secure than memfd but functional.
        //
        // On Windows we MUST close the file handle before calling LoadLibrary,
        // otherwise the loader fails with "file is being used by another process"
        // (os error 32). We persist the temp file and clean it up after loading.
        let temp_file = tempfile::Builder::new()
            .prefix("plugin-")
            .suffix(std::env::consts::DLL_SUFFIX)
            .tempfile()?;
        let temp_path = temp_file.into_temp_path();
        std::fs::write(&temp_path, module_data)?;
        info!("Loading plugin from temporary file: {:?}", &*temp_path);
        // SAFETY: We trust the decrypted blob.
        let lib = unsafe { Library::new(&*temp_path)? };
        // Persist the file for the lifetime of the loaded library; the OS
        // will release the file once the process exits. On Windows we cannot
        // delete a loaded DLL while it is mapped.
        let _ = temp_path.keep();
        lib
    };

    // 3. Find the `_create_plugin` symbol, call it, and return the Plugin trait object.
    // SAFETY: The loaded library must have this exact symbol.
    let create_func: Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> =
        unsafe { library.get(b"_create_plugin")? };

    // SAFETY: The function returns a valid pointer to a Box'd Plugin.
    let plugin_ptr = unsafe { create_func() };
    // SAFETY: We are converting the raw pointer back into a Box, taking ownership.
    let plugin = unsafe { Box::from_raw(plugin_ptr) };

    // The library must be kept alive for the plugin to be valid.
    // We leak it here, which is acceptable as plugins are loaded for the
    // lifetime of the agent process.
    std::mem::forget(library);

    Ok(plugin)
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
        let plugin = load_plugin(&encrypted_blob, &session).expect("Failed to load plugin");

        // 4. Initialize and execute.
        plugin.init().expect("Plugin init failed");
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
            load_plugin(&encrypted_blob, &session).expect("Failed to load plugin with manual map");
        plugin.init().expect("Plugin init failed");
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
        let result = load_plugin(&encrypted_blob, &session);
        assert!(result.is_err());
    }
}
