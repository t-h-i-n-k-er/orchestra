//! Secure, in-memory loading for dynamically deployed capability plugins.
//
//! This module handles fetching, decrypting, verifying, and loading shared
//! libraries (`.so`, `.dll`) entirely in memory, without writing the plugin to
//! the filesystem. This is a security and hygiene feature, preventing disk
//! clutter and reducing the attack surface.

use anyhow::{anyhow, Result};
use common::CryptoSession;
use libloading::{Library, Symbol};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};
use tracing::info;

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
        file.write_all(&decrypted_blob)?;

        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        info!("Loading plugin from in-memory path: {}", path);
        // The library is dropped when `file` is dropped, closing the fd.
        // SAFETY: The path is valid and we trust the decrypted blob.
        unsafe { Library::new(path)? }
    };

    #[cfg(not(target_os = "linux"))]
    let library = {
        // Fallback for non-Linux OSs (e.g., macOS, Windows).
        // For Windows, a more advanced technique involves CreateFileMapping/MapViewOfFile
        // with SEC_IMAGE, but for simplicity, we'll use a temporary file.
        // This is less secure than memfd but functional.
        let mut temp_file = tempfile::Builder::new()
            .prefix("plugin-")
            .suffix(libloading::consts::EXT)
            .tempfile()?;
        temp_file.write_all(&decrypted_blob)?;
        info!("Loading plugin from temporary file: {:?}", temp_file.path());
        // SAFETY: We trust the decrypted blob.
        unsafe { Library::new(temp_file.path())? }
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

        let mut path = PathBuf::from(format!("../target/debug/",));
        // The exact filename depends on the OS and cargo's mangling.
        // We find the file with the right extension.
        let lib_file = fs::read_dir(&path)
            .unwrap_or_else(|e| panic!("Failed to read plugin directory: {:?}, error: {}", path, e))
            .find_map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path();
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.starts_with("libhello_plugin")
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

        // 2. Encrypt it.
        let session = CryptoSession::from_shared_secret(b"test-key");
        let encrypted_blob = session.encrypt(&plugin_bytes);

        // 3. Load it using the module_loader.
        let plugin = load_plugin(&encrypted_blob, &session).expect("Failed to load plugin");

        // 4. Initialize and execute.
        plugin.init().expect("Plugin init failed");
        let result = plugin.execute("World").expect("Plugin execution failed");

        assert_eq!(result, "Hello, World");
    }
}
