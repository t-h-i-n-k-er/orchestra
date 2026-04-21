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

use anyhow::{anyhow, Result};
use common::config::Config;
use std::path::{Component, Path, PathBuf};
use tokio::fs as afs;

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
    afs::write(path, data).await?;
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
}
