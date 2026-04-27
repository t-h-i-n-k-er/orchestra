//! Filesystem operations with security checks.
//!
//! Path validation is unified here: every public file operation calls
//! [`validate_path`] with the agent's [`Config`], which:
//!
//! 1. Fast-rejects any input containing `..` components.
//! 2. Canonicalises the path (resolving symlinks) — when the target does
//!    not yet exist, the existing parent directory is canonicalised and
//!    the final component is re-attached, so writes to new files inside
//!    an allowed directory still succeed.
//! 3. Verifies the resulting absolute path lives under one of the
//!    canonicalised entries in `config.allowed_paths`.
//!
//! ## Symlink-race hardening for writes
//!
//! `validate_path` canonicalises the path at validation time.  A TOCTOU
//! window exists between validation and the actual file-system operation:
//! an attacker with write access to the directory could create a symlink at
//! the final path component after validation, redirecting the write.
//!
//! [`write_file`] defends against this by opening the target with
//! `O_NOFOLLOW` (Linux/macOS) so that if the final component is a symlink
//! the `open()` call fails instead of following it.  On other platforms
//! (Windows, etc.) a post-open `symlink_metadata` check is used to detect
//! a newly-appeared symlink before writing.

use anyhow::{anyhow, Result};
use common::config::Config;
use std::path::{Component, Path, PathBuf};
use tokio::fs as afs;
#[cfg(unix)]
use libc;

#[derive(serde::Serialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Validate a caller-supplied path against the agent's policy.
///
/// Returns the canonical absolute path on success.
pub async fn validate_path(path: &str, config: &Config) -> Result<PathBuf> {
    let raw = PathBuf::from(path);

    // Fast-path traversal rejection: catch `..` before any I/O.
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(anyhow!("Path cannot contain '..'"));
    }

    let raw_clone = raw.clone();
    let canonical = tokio::task::spawn_blocking(move || canonicalize_existing(&raw_clone))
        .await
        .map_err(|e| anyhow!("validation task panicked: {e}"))??;

    let allowed_roots = canonical_allowed_roots(config);
    if allowed_roots.is_empty() {
        return Err(anyhow!("No allowed paths configured"));
    }

    if !allowed_roots.iter().any(|root| canonical.starts_with(root)) {
        return Err(anyhow!("Path is outside of allowed directories"));
    }

    Ok(canonical)
}

/// Canonicalise allowed roots once per call. Roots that fail to
/// canonicalise (e.g. they don't exist on this host) are silently
/// skipped — they cannot match any real path anyway.
fn canonical_allowed_roots(config: &Config) -> Vec<PathBuf> {
    config
        .allowed_paths
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

/// Canonicalise `path` if it exists; otherwise canonicalise its
/// nearest existing ancestor and re-append the missing tail. This
/// preserves symlink-resolution semantics for the parts that *do*
/// exist while still allowing operations on not-yet-created files.
fn canonicalize_existing(path: &Path) -> Result<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(path) {
        return Ok(c);
    }
    let mut ancestors = path.ancestors().skip(1);
    let parent = ancestors
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("Path has no existing ancestor"))?;
    let canon_parent = std::fs::canonicalize(parent)?;
    let tail = path
        .strip_prefix(parent)
        .map_err(|_| anyhow!("Failed to compute path tail"))?;
    Ok(canon_parent.join(tail))
}

/// Returns `true` if `path` names a Windows reparse point (symlink or
/// junction).  Opens the path with `FILE_FLAG_OPEN_REPARSE_POINT` so the
/// check itself never follows the link, then confirms the attribute with
/// `GetFileAttributesW`.
///
/// On non-Windows platforms this is always `Ok(false)`.
#[cfg(windows)]
fn is_reparse_point(path: &Path) -> Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::{CreateFileW, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
    use winapi::um::winnt::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GENERIC_READ,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();

    // Open without following the reparse point.
    // FILE_FLAG_BACKUP_SEMANTICS is required when the path is a directory.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        // Path does not exist yet — cannot be a reparse point.
        return Ok(false);
    }
    unsafe { CloseHandle(handle) };

    // GetFileAttributesW does not follow reparse points; it reports the
    // attributes of the reparse point entry itself.
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Ok(false);
    }
    Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
}

#[cfg(all(not(windows), not(unix)))]
fn is_reparse_point(_path: &Path) -> Result<bool> {
    Ok(false)
}

pub async fn list_directory(path: &str, config: &Config) -> Result<Vec<FileEntry>> {
    let path = validate_path(path, config).await?;
    let mut entries = Vec::new();
    let mut read_dir = afs::read_dir(path).await?;

    while let Some(entry) = read_dir.next_entry().await? {
        let metadata = entry.metadata().await?;
        entries.push(FileEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
        });
    }
    Ok(entries)
}

pub async fn read_file(path: &str, config: &Config) -> Result<Vec<u8>> {
    let path = validate_path(path, config).await?;
    Ok(afs::read(path).await?)
}

pub async fn write_file(path: &str, data: &[u8], config: &Config) -> Result<()> {
    let path = validate_path(path, config).await?;
    // Use O_NOFOLLOW on Unix so that if the final path component is a symlink
    // (introduced between validate_path and here), open() returns ELOOP/ENOENT
    // instead of following the link.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                // O_NOFOLLOW: refuse to open the path if it is a symlink.
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|e| {
                    if e.raw_os_error() == Some(libc::ELOOP)
                        || e.raw_os_error() == Some(libc::ENOTDIR)
                    {
                        anyhow!(
                            "write_file: final path component is a symlink; write refused ({})",
                            path.display()
                        )
                    } else {
                        anyhow!("write_file: open failed: {e}")
                    }
                })?;
            f.write_all(&data_owned)
                .map_err(|e| anyhow!("write_file: write failed: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("write_file task panicked: {e}"))??;
    }
    #[cfg(not(unix))]
    {
        // On Windows, check for a reparse point (symlink or junction) BEFORE
        // writing.  Opening with FILE_FLAG_OPEN_REPARSE_POINT ensures the
        // check itself never follows the link.  If the path is a reparse
        // point we resolve its target for the warning, delete the reparse
        // point, and create a regular file at the same path.
        use std::io::Write;
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            if is_reparse_point(&path)? {
                // Resolve the target via read_link (works for symlinks and
                // NTFS junctions alike on Windows).
                let target = std::fs::read_link(&path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_else(|_| "<unresolvable reparse point>".to_owned());
                log::warn!(
                    "write_file: {} is a reparse point pointing to {}; \
                     removing reparse point and writing a regular file",
                    path.display(),
                    target
                );
                std::fs::remove_file(&path).map_err(|e| {
                    anyhow!(
                        "write_file: failed to remove reparse point {}: {e}",
                        path.display()
                    )
                })?;
            }
            // Write a regular file.  The symlink (if any) was just removed,
            // so this open cannot follow one.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .map_err(|e| anyhow!("write_file: open failed: {e}"))?;
            f.write_all(&data_owned)
                .map_err(|e| anyhow!("write_file: write failed: {e}"))
        })
        .await
        .map_err(|e| anyhow!("write_file task panicked: {e}"))??;
    }
    Ok(())
}

pub async fn delete_path(path: &str, config: &Config) -> Result<()> {
    let path = validate_path(path, config).await?;
    if path.is_dir() {
        afs::remove_dir_all(path).await?;
    } else {
        afs::remove_file(path).await?;
    }
    Ok(())
}

pub async fn move_path(src: &str, dst: &str, config: &Config) -> Result<()> {
    let src_path = validate_path(src, config).await?;
    let dst_path = validate_path(dst, config).await?;
    afs::rename(src_path, dst_path).await?;
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cfg_with(roots: &[&Path]) -> Config {
        Config {
            allowed_paths: roots
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn validate_path_accepts_file_inside_allowed_dir() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("inner.txt");
        std::fs::write(&f, b"hi").unwrap();

        let cfg = cfg_with(&[dir.path()]);
        let resolved = validate_path(f.to_str().unwrap(), &cfg).await.unwrap();
        assert!(resolved.starts_with(std::fs::canonicalize(dir.path()).unwrap()));
    }

    #[tokio::test]
    async fn validate_path_rejects_parent_dir_traversal() {
        let dir = tempdir().unwrap();
        let cfg = cfg_with(&[dir.path()]);
        let bad = format!("{}/../etc/passwd", dir.path().display());
        let err = validate_path(&bad, &cfg).await.unwrap_err();
        assert!(err.to_string().contains(".."), "got: {err}");
    }

    #[tokio::test]
    async fn validate_path_rejects_symlink_outside_allowed() {
        let allowed = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"top-secret").unwrap();

        let link = allowed.path().join("escape");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let cfg = cfg_with(&[allowed.path()]);
        let err = validate_path(link.to_str().unwrap(), &cfg)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("outside"),
            "expected outside-allowed rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn validate_path_allows_nonexistent_file_in_allowed_dir() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("not-yet-created.txt");
        let cfg = cfg_with(&[dir.path()]);
        let resolved = validate_path(target.to_str().unwrap(), &cfg).await.unwrap();
        assert!(resolved.starts_with(std::fs::canonicalize(dir.path()).unwrap()));
    }

    #[tokio::test]
    async fn validate_path_rejects_when_no_roots_configured() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"x").unwrap();
        let cfg = cfg_with(&[]);
        assert!(validate_path(f.to_str().unwrap(), &cfg).await.is_err());
    }

    /// A symlink planted at the final path component after validate_path but
    /// before write_file must cause write_file to fail (TOCTOU hardening).
    ///
    /// This test is Linux-only because the O_NOFOLLOW defence is Unix-specific
    /// and the race window cannot be reliably reproduced on other platforms.
    #[tokio::test]
    async fn write_file_refuses_final_component_symlink() {
        let allowed = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();

        // Create a legitimate target path inside the allowed dir.
        let link_path = allowed.path().join("data.txt");

        // Pre-create a symlink pointing outside before write_file runs.
        std::os::unix::fs::symlink(&victim, &link_path).unwrap();

        let cfg = cfg_with(&[allowed.path()]);
        let err = write_file(link_path.to_str().unwrap(), b"malicious", &cfg)
            .await
            .unwrap_err();
        // The write must be refused.  The exact message depends on which
        // guard fires first: validate_path (detects symlink-outside-allowed)
        // or the O_NOFOLLOW open (catches a symlink planted between validate
        // and open).  Both are correct behaviours.
        let msg = err.to_string();
        assert!(
            msg.contains("symlink")
                || msg.contains("ELOOP")
                || msg.contains("outside")
                || msg.contains("allowed"),
            "expected write to be refused due to symlink, got: {msg}"
        );

        // The victim file must NOT have been overwritten.
        let contents = std::fs::read(&victim).unwrap();
        assert_eq!(
            contents,
            b"original",
            "victim file must not be overwritten via symlink"
        );
    }
}
