//! Runtime helper: locate a function's machine code, apply the transformation,
//! and write the result back into the executable page.
//!
//! # Safety
//!
//! This module uses `mprotect` to change page permissions.  It must only be
//! called while no other thread is executing the function being patched.  In
//! practice, callers should use a `std::sync::Once` guard (as the
//! `#[code_transform]` macro does) so the patch is applied exactly once,
//! before concurrent callers can reach the function.
//!
//! Only available on `x86_64 linux`.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_impl::apply_to_fn;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_impl {
    use crate::transform;
    use iced_x86::{Code, Decoder, DecoderOptions, Instruction};

    /// Maximum number of bytes scanned when estimating a function's size.
    const MAX_FN_SCAN: usize = 4096;

    /// x86-64 `JMP rel32` opcode.
    const JMP_REL32: u8 = 0xE9;
    /// Size of a `JMP rel32` instruction.
    const JMP_REL32_SIZE: usize = 5;

    /// Apply the full instruction-substitution + block-reorder transformation
    /// to the function whose first byte is at `fn_ptr`.
    ///
    /// Steps:
    /// 1. Decode forward from `fn_ptr` with iced-x86 to find the actual last
    ///    instruction (stopping at an unconditional return / unreachable).
    /// 2. Call `transform(bytes, seed)` to produce the new byte sequence.
    /// 3. If the transformed code fits within the original function boundary,
    ///    patch in-place.  Otherwise, allocate a fresh executable page, copy
    ///    the transformed code there, and overwrite the original entry with a
    ///    `JMP rel32` trampoline.
    /// 4. Flush the instruction cache via a serializing `CPUID` instruction.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// * `fn_ptr` is the start address of a compiled x86-64 function.
    /// * No other thread is concurrently executing the function.
    pub unsafe fn apply_to_fn(fn_ptr: *mut u8, seed: u64) {
        use libc::sysconf;

        let page_size = sysconf(libc::_SC_PAGESIZE) as usize;

        // ── 1. Estimate function size via iced-x86 decoder ──────────────────
        let scan = std::slice::from_raw_parts(fn_ptr as *const u8, MAX_FN_SCAN);
        let fn_len = estimate_fn_len(scan);
        if fn_len == 0 {
            return;
        }
        let code_slice = std::slice::from_raw_parts(fn_ptr as *const u8, fn_len);

        // ── 2. Transform ─────────────────────────────────────────────────────
        let transformed = transform(code_slice, seed);
        if transformed == code_slice || transformed.is_empty() {
            return; // nothing changed
        }

        // ── 3. Patch ─────────────────────────────────────────────────────────
        if transformed.len() <= fn_len {
            // Transformed code fits in-place.
            patch_in_place(fn_ptr, fn_len, &transformed, page_size);
        } else {
            // Transformed code is larger — allocate a new executable region
            // and write a JMP trampoline at the original entry.
            patch_with_trampoline(fn_ptr, fn_len, &transformed, page_size);
        }

        // ── 4. Cache coherency — serialize ───────────────────────────────────
        // Execute a serializing instruction so the pipeline fetches the
        // freshly-written code.  `CPUID` is a serializing instruction on every
        // Intel/AMD x86-64 implementation.
        serialize_cpu();
    }

    /// Patch the function in-place: make the page RW, copy the new bytes,
    /// NOP-pad the tail, and restore RX.
    ///
    /// # Safety
    /// Caller must ensure `fn_ptr` points to a valid function and no thread
    /// is executing it concurrently.
    unsafe fn patch_in_place(
        fn_ptr: *mut u8,
        fn_len: usize,
        transformed: &[u8],
        page_size: usize,
    ) {
        use libc::{mprotect, PROT_EXEC, PROT_READ, PROT_WRITE};

        let page_start = (fn_ptr as usize) & !(page_size - 1);
        let cover = fn_len + (fn_ptr as usize - page_start);
        let mmap_len = ((cover + page_size - 1) / page_size) * page_size;

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_WRITE);

        std::ptr::copy_nonoverlapping(transformed.as_ptr(), fn_ptr, transformed.len());

        // NOP-pad any remaining bytes from the old body.
        if transformed.len() < fn_len {
            std::ptr::write_bytes(fn_ptr.add(transformed.len()), 0x90, fn_len - transformed.len());
        }

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_EXEC);
    }

    /// Allocate a fresh executable region, copy the transformed code there,
    /// and overwrite the original function entry with a `JMP rel32` trampoline.
    ///
    /// # Safety
    /// Caller must ensure `fn_ptr` points to a valid function and no thread
    /// is executing it concurrently.
    unsafe fn patch_with_trampoline(
        fn_ptr: *mut u8,
        fn_len: usize,
        transformed: &[u8],
        page_size: usize,
    ) {
        use libc::{mmap, mprotect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};

        // Allocate a fresh page for the transformed code.
        let new_page = mmap(
            std::ptr::null_mut(),
            page_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if new_page == libc::MAP_FAILED {
            log::error!("code_transform: mmap for trampoline target failed");
            return;
        }

        // Copy transformed code into the new region.
        std::ptr::copy_nonoverlapping(transformed.as_ptr(), new_page as *mut u8, transformed.len());

        // Make the new region executable.
        mprotect(new_page, page_size, PROT_READ | PROT_EXEC);

        // Build a JMP rel32 trampoline at the original entry.
        // We need at least 5 bytes (E9 rel32).  The original function is
        // guaranteed to be at least that long because estimate_fn_len stops
        // at a full instruction boundary.
        let target = new_page as usize;
        let source = fn_ptr as usize + JMP_REL32_SIZE; // PC after the JMP
        let rel32 = (target as i64 - source as i64) as i32;

        let page_start = (fn_ptr as usize) & !(page_size - 1);
        let cover = fn_len + (fn_ptr as usize - page_start);
        let mmap_len = ((cover + page_size - 1) / page_size) * page_size;

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_WRITE);

        // Write JMP rel32.
        fn_ptr.write(JMP_REL32);
        let rel_ptr = fn_ptr.add(1) as *mut i32;
        rel_ptr.write(rel32);

        // NOP out remaining bytes in the original function that are no
        // longer reachable (keeps disassembly tidy).
        if JMP_REL32_SIZE < fn_len {
            std::ptr::write_bytes(fn_ptr.add(JMP_REL32_SIZE), 0x90, fn_len - JMP_REL32_SIZE);
        }

        mprotect(page_start as *mut _, mmap_len, PROT_READ | PROT_EXEC);
    }

    /// Decode instructions sequentially with iced-x86 to find the actual
    /// end of the function.  Returns the byte offset *after* the last
    /// instruction that terminates the function (e.g. `RET`, `INT3`-sentinel,
    /// or `UD2`).  Falls back to `MAX_FN_SCAN` if no terminating instruction
    /// is found within the scan window.
    fn estimate_fn_len(code: &[u8]) -> usize {
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instr: Instruction = decoder.decode();

            match instr.code() {
                // Unconditional near return.
                Code::Retnq
                | Code::Retfq
                // `UD2` — intentional undefined (unreachable after optimization).
                | Code::Ud2
                // `INT3` used as a sentinel / padding after the function body.
                | Code::Int3 => {
                    return (instr.ip() as usize) + instr.len();
                }
                _ => {}
            }
        }

        // No clear terminator found — use the whole scan window.
        MAX_FN_SCAN
    }

    /// Issue a serializing instruction to ensure the CPU pipeline fetches
    /// freshly-written code after the `mprotect` + copy.
    ///
    /// `CPUID` is serializing on every x86-64 implementation (Intel SDM
    /// Vol. 2A "CPUID", AMD APM Vol. 3 "CPUID").
    fn serialize_cpu() {
        // SAFETY: CPUID is a non-trapping, side-effect-free user-mode
        // instruction (leaf 0 is always supported).  We save RBX around
        // the call because LLVM reserves RBX and does not allow it as an
        // inline-asm output operand.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "xor eax, eax",
                "cpuid",
                "pop rbx",
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
            );
        }
    }
}
