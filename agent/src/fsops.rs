//! Filesystem operations with security checks.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use tokio::fs as afs;

#[derive(serde::Serialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

fn get_allowed_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![PathBuf::from("C:\\ProgramData\\Orchestra")]
    } else {
        vec![
            PathBuf::from("/var/log"),
            dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home")),
        ]
    }
}

fn validate_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(anyhow!("Path cannot contain '..'"));
    }

    let canonical_path = path.canonicalize()?;
    let allowed_roots = get_allowed_roots();

    if !allowed_roots
        .iter()
        .any(|root| canonical_path.starts_with(root))
    {
        return Err(anyhow!("Path is outside of allowed directories"));
    }

    Ok(canonical_path)
}

pub async fn list_directory(path: &str) -> Result<Vec<FileEntry>> {
    let path = validate_path(path)?;
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

pub async fn read_file(path: &str) -> Result<Vec<u8>> {
    let path = validate_path(path)?;
    Ok(afs::read(path).await?)
}

pub async fn write_file(path: &str, data: &[u8]) -> Result<()> {
    let path = validate_path(path)?;
    afs::write(path, data).await?;
    Ok(())
}

pub async fn delete_path(path: &str) -> Result<()> {
    let path = validate_path(path)?;
    if path.is_dir() {
        afs::remove_dir_all(path).await?;
    } else {
        afs::remove_file(path).await?;
    }
    Ok(())
}

pub async fn move_path(src: &str, dst: &str) -> Result<()> {
    let src_path = validate_path(src)?;
    let dst_path = validate_path(dst)?;
    afs::rename(src_path, dst_path).await?;
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validate_path() {
        // This test needs to run in a context where it can create files and directories.
        let dir = tempdir().unwrap();
        let allowed_dir = dir.path().join("allowed");
        std::fs::create_dir(&allowed_dir).unwrap();

        // Mock get_allowed_roots to use our temp dir
        let _original_roots_fn = super::get_allowed_roots;
        // This is a bit of a hack, but for a test it's ok.
        // In a real scenario, we would inject the roots.
        // For now, we can't easily override the function, so we test against the real roots.
        // This test will likely fail if not run with appropriate permissions.

        // Allowed
        assert!(validate_path("/var/log").is_ok());

        // Disallowed
        assert!(validate_path("/etc/passwd").is_err());
        assert!(validate_path("../../../etc/passwd").is_err());
    }
}
