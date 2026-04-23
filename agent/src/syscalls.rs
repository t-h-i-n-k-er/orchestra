//! Direct syscalls for Windows.
#![cfg(all(windows, target_arch = "x86_64", feature = "direct-syscalls"))]

use anyhow::{anyhow, Result};
use std::arch::asm;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

/// Retrieves the syscall number (SSN) for a given NT function.
///
/// **Disk-first strategy**: reads `ntdll.dll` from the `System32` directory on
/// disk and resolves the SSN from that clean copy.  This avoids the common EDR
/// hook pattern where the in-memory NTDLL prologue is patched with a `jmp`
/// trampoline that redirects execution to a monitoring DLL—if the patch
/// replaces the `mov eax, <ssn>` instruction, the in-memory scan would return
/// the wrong number or fail entirely.
///
/// Falls back to the in-memory scan if the file cannot be read or parsed, so
/// that the function continues to work in environments where disk access is
/// restricted.
#[doc(hidden)]
pub fn get_syscall_id(func_name: &str) -> Result<u32> {
    // Try the clean disk copy first.
    if let Ok(ssn) = get_syscall_id_from_disk(func_name) {
        return Ok(ssn);
    }
    // Fall back to scanning the in-memory (possibly hooked) copy.
    get_syscall_id_from_memory(func_name)
}

/// Read the SSN from a freshly mapped (un-hooked) copy of ntdll.dll on disk.
fn get_syscall_id_from_disk(func_name: &str) -> Result<u32> {
    // Build the path to System32\ntdll.dll from the SystemRoot environment
    // variable so we respect non-standard Windows installations.
    let sysroot =
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let ntdll_path = format!("{}\\System32\\ntdll.dll", sysroot);

    let bytes = std::fs::read(&ntdll_path)
        .map_err(|e| anyhow!("failed to read {ntdll_path} from disk: {e}"))?;

    // Minimal PE parsing — no external crate needed.
    if bytes.len() < 0x40 {
        anyhow::bail!("ntdll.dll on disk is too small");
    }
    let e_magic = u16::from_le_bytes(bytes[0..2].try_into()?);
    if e_magic != 0x5A4D {
        anyhow::bail!("ntdll.dll on disk has wrong DOS magic");
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into()?) as usize;
    if bytes.len() < e_lfanew + 0x18 + 2 {
        anyhow::bail!("ntdll.dll truncated before optional header magic");
    }
    let nt_sig = u32::from_le_bytes(bytes[e_lfanew..e_lfanew + 4].try_into()?);
    if nt_sig != 0x4550 {
        anyhow::bail!("ntdll.dll on disk has wrong PE signature");
    }

    // FileHeader is at e_lfanew+4 (20 bytes); OptionalHeader starts at e_lfanew+24.
    let num_sections =
        u16::from_le_bytes(bytes[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_header_size =
        u16::from_le_bytes(bytes[e_lfanew + 0x14..e_lfanew + 0x16].try_into()?) as usize;
    let opt_hdr_start = e_lfanew + 24;
    let magic = u16::from_le_bytes(bytes[opt_hdr_start..opt_hdr_start + 2].try_into()?);

    // Offset of DataDirectory[0] (export RVA + size) within the optional header.
    // PE32 (x86): 0x60; PE32+ (x64): 0x70.
    let dd_rel = match magic {
        0x020b => 0x70usize, // PE32+
        0x010b => 0x60usize, // PE32
        _ => anyhow::bail!("unknown PE optional-header magic {magic:#x}"),
    };
    let dd_off = opt_hdr_start + dd_rel;
    if bytes.len() < dd_off + 8 {
        anyhow::bail!("ntdll.dll truncated before export data-directory entry");
    }
    let export_rva = u32::from_le_bytes(bytes[dd_off..dd_off + 4].try_into()?) as usize;
    if export_rva == 0 {
        anyhow::bail!("ntdll.dll has no export directory");
    }

    // Section headers start immediately after the optional header.
    let sections_off = opt_hdr_start + opt_header_size;

    // Translate an RVA to a flat file offset using the section table.
    // IMAGE_SECTION_HEADER is 40 bytes:
    //   +0  Name[8]
    //   +8  Misc.VirtualSize
    //   +12 VirtualAddress
    //   +16 SizeOfRawData
    //   +20 PointerToRawData
    let rva_to_off = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let base = sections_off + i * 40;
            if base + 40 > bytes.len() {
                return None;
            }
            let virt_addr =
                u32::from_le_bytes(bytes[base + 12..base + 16].try_into().ok()?) as usize;
            let virt_size =
                u32::from_le_bytes(bytes[base + 8..base + 12].try_into().ok()?) as usize;
            let raw_size =
                u32::from_le_bytes(bytes[base + 16..base + 20].try_into().ok()?) as usize;
            let raw_off =
                u32::from_le_bytes(bytes[base + 20..base + 24].try_into().ok()?) as usize;
            let extent = if virt_size == 0 { raw_size } else { virt_size };
            if rva >= virt_addr && rva < virt_addr + extent {
                return Some(raw_off + (rva - virt_addr));
            }
        }
        None
    };

    let export_off = rva_to_off(export_rva)
        .ok_or_else(|| anyhow!("export directory RVA not in any section"))?;

    // IMAGE_EXPORT_DIRECTORY (40 bytes):
    //  +24 NumberOfNames
    //  +28 AddressOfFunctions (RVA)
    //  +32 AddressOfNames     (RVA)
    //  +36 AddressOfNameOrdinals (RVA)
    if export_off + 40 > bytes.len() {
        anyhow::bail!("export directory overruns ntdll.dll bytes");
    }
    let num_names =
        u32::from_le_bytes(bytes[export_off + 24..export_off + 28].try_into()?) as usize;
    let funcs_rva =
        u32::from_le_bytes(bytes[export_off + 28..export_off + 32].try_into()?) as usize;
    let names_rva =
        u32::from_le_bytes(bytes[export_off + 32..export_off + 36].try_into()?) as usize;
    let ords_rva =
        u32::from_le_bytes(bytes[export_off + 36..export_off + 40].try_into()?) as usize;

    let funcs_off = rva_to_off(funcs_rva)
        .ok_or_else(|| anyhow!("AddressOfFunctions RVA not in any section"))?;
    let names_off = rva_to_off(names_rva)
        .ok_or_else(|| anyhow!("AddressOfNames RVA not in any section"))?;
    let ords_off = rva_to_off(ords_rva)
        .ok_or_else(|| anyhow!("AddressOfNameOrdinals RVA not in any section"))?;

    for i in 0..num_names {
        let name_rva_off = names_off + i * 4;
        if name_rva_off + 4 > bytes.len() {
            break;
        }
        let name_rva =
            u32::from_le_bytes(bytes[name_rva_off..name_rva_off + 4].try_into()?) as usize;
        let name_off = match rva_to_off(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let name_end = bytes[name_off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let name = match std::str::from_utf8(&bytes[name_off..name_off + name_end]) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name != func_name {
            continue;
        }

        // Found the name — resolve ordinal → function RVA.
        let ord_off = ords_off + i * 2;
        if ord_off + 2 > bytes.len() {
            anyhow::bail!("ordinal array overruns ntdll.dll");
        }
        let ordinal = u16::from_le_bytes(bytes[ord_off..ord_off + 2].try_into()?) as usize;
        let func_rva_off = funcs_off + ordinal * 4;
        if func_rva_off + 4 > bytes.len() {
            anyhow::bail!("function RVA array overruns ntdll.dll");
        }
        let func_rva =
            u32::from_le_bytes(bytes[func_rva_off..func_rva_off + 4].try_into()?) as usize;
        let func_off = rva_to_off(func_rva)
            .ok_or_else(|| anyhow!("function RVA not in any section for {func_name}"))?;

        // Scan up to 32 bytes of the function body for the SSN.
        let scan_end = (func_off + 32).min(bytes.len());
        let func_bytes = &bytes[func_off..scan_end];
        for j in 0..func_bytes.len().saturating_sub(1) {
            if func_bytes[j] == 0x0f && func_bytes[j + 1] == 0x05 {
                for k in (0..j).rev() {
                    if func_bytes[k] == 0xb8 && k + 5 <= func_bytes.len() {
                        let ssn = u32::from_le_bytes(
                            func_bytes[k + 1..k + 5].try_into()?,
                        );
                        return Ok(ssn);
                    }
                }
            }
        }
        anyhow::bail!("could not find syscall ID for {func_name} in disk image");
    }
    anyhow::bail!("function {func_name} not found in ntdll.dll export table")
}

/// Original in-memory scan — used as fallback when the disk read fails.
fn get_syscall_id_from_memory(func_name: &str) -> Result<u32> {
    unsafe {
        let name_c = std::ffi::CString::new("ntdll.dll")
            .expect("static literal is valid C string");
        let ntdll = GetModuleHandleA(name_c.as_ptr());
        if ntdll.is_null() {
            return Err(anyhow!("GetModuleHandleA(ntdll) failed"));
        }
        let func_c = std::ffi::CString::new(func_name)
            .map_err(|e| anyhow!("invalid syscall name {func_name}: {e}"))?;
        let func_addr = GetProcAddress(ntdll, func_c.as_ptr());
        if func_addr.is_null() {
            return Err(anyhow!("Could not find function {}", func_name));
        }

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        // Scan for `syscall` instruction (0x0f, 0x05)
        for i in 0..bytes.len() - 1 {
            if bytes[i] == 0x0f && bytes[i + 1] == 0x05 {
                // Found syscall, now search backwards for `mov eax, <ssn>` (0xb8, ....)
                for j in (0..i).rev() {
                    if bytes[j] == 0xb8 && j + 5 <= bytes.len() {
                        let ssn_bytes: [u8; 4] =
                            bytes[j + 1..j + 5].try_into().map_err(|_| {
                                anyhow!("Failed to read SSN bytes for {}", func_name)
                            })?;
                        return Ok(u32::from_le_bytes(ssn_bytes));
                    }
                }
            }
        }
    }
    Err(anyhow!("Could not find syscall ID for {}", func_name))
}

/// Invokes a Windows NT syscall with a variable number of arguments.
///
/// The first four arguments go in `rcx`, `rdx`, `r8`, `r9` per the Windows x64
/// calling convention. Any additional arguments are copied onto the stack at
/// `[rsp+0x28]` (immediately above the 0x20-byte shadow space and the 8-byte
/// slot that `syscall` treats as the "return address" area). RSP is saved,
/// re-aligned to 16 bytes, and restored around the `syscall` instruction so
/// this works for any number of arguments, not just <= 4.
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let ssn: u32 = $crate::syscalls::get_syscall_id($func_name)?;
        let args: &[u64] = &[$($args as u64),*];
        $crate::syscalls::do_syscall(ssn, args)
    }};
}

/// Internal helper: invoke `syscall` with `ssn` as the syscall number and
/// `args` laid out per the Windows x64 ABI.
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> i32 {
    let a1 = args.get(0).copied().unwrap_or(0);
    let a2 = args.get(1).copied().unwrap_or(0);
    let a3 = args.get(2).copied().unwrap_or(0);
    let a4 = args.get(3).copied().unwrap_or(0);
    let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
    let nstack: usize = stack_args.len();
    let stack_ptr: *const u64 = stack_args.as_ptr();
    let status: i32;

    asm!(
        // Stash caller-provided register args that our stack-copy code will
        // clobber (rcx/rdx are used by `rep movsq`).
        "mov r12, rcx",
        "mov r13, rdx",
        // Save original rsp so we can restore it regardless of alignment.
        "mov r14, rsp",
        // Compute bytes to reserve: 0x28 (shadow + fake-ret slot) + 8*nstack,
        // rounded up to 16 for ABI alignment.
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        // Copy stack args to [rsp + 0x28 ..] if any.
        "test {nstack}, {nstack}",
        "jz 2f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        "2:",
        // Restore register args (r8/r9 were never touched).
        "mov rcx, r12",
        "mov rdx, r13",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        // Restore rsp.
        "mov rsp, r14",
        ssn        = in(reg) ssn,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        in("rcx") a1,
        in("rdx") a2,
        in("r8")  a3,
        in("r9")  a4,
        lateout("rax") status,
        // Clobbers:
        out("r10") _, out("r11") _,
        out("r12") _, out("r13") _, out("r14") _,
        out("rsi") _, out("rdi") _,
    );

    status
}




