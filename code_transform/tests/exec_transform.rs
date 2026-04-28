//! Integration test: execute a transformed function and verify its output
//! matches the original.
//!
//! The test allocates an executable memory page, copies machine code into it,
//! and calls the function through a raw function pointer.  The test is
//! `#[cfg(target_os = "linux")]` because the `mmap`/`mprotect` calls are
//! Linux-specific.

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod exec_tests {
    use code_transform::transform;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Allocate a page of RWX memory, copy `code` into it, and return a
    /// pointer to the start of that page.  The caller is responsible for
    /// munmap-ing the returned pointer when done.
    unsafe fn alloc_exec_page(code: &[u8]) -> *mut u8 {
        use libc::{
            mmap, mprotect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
        };
        let page_size: usize = 4096;
        let len = ((code.len() + page_size - 1) / page_size) * page_size;

        let ptr = mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut u8;

        assert!(!ptr.is_null(), "mmap failed");

        std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());

        mprotect(ptr as *mut _, len, PROT_READ | PROT_EXEC);

        ptr
    }

    unsafe fn free_exec_page(ptr: *mut u8, len: usize) {
        libc::munmap(ptr as *mut _, len);
    }

    /// Execute the machine-code function at `ptr` with `arg` in RDI (System
    /// V AMD64 ABI) and return the value in RAX.
    unsafe fn call_fn(ptr: *const u8, arg: i64) -> i64 {
        let f: extern "C" fn(i64) -> i64 = std::mem::transmute(ptr);
        f(arg)
    }

    // ── Test ──────────────────────────────────────────────────────────────────

    /// Hand-crafted x86_64 machine code for:
    /// ```c
    /// int64_t test_fn(int64_t x) {
    ///     int64_t r = 0;          // 48 C7 C0 00 00 00 00  — Rule 1 candidate
    ///     r = r + x;              // 48 03 C7              — ADD rax, rdi
    ///     r = r + x;              // 48 03 C7              — ADD rax, rdi
    ///     return r;               // C3
    /// }
    /// ```
    /// Returns `2 * x`.  Uses `MOV rax, 0` so Rule 1 fires; two ADDs so
    /// Rule 2 may fire; no branches so the function is one basic block.
    const ORIG_CODE: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // MOV rax, 0
        0x48, 0x03, 0xC7, // ADD rax, rdi
        0x48, 0x03, 0xC7, // ADD rax, rdi
        0xC3,             // RET
    ];

    /// Machine code with a conditional branch (two basic blocks), for testing
    /// the reorder pass:
    /// ```c
    /// int64_t branch_fn(int64_t x) {
    ///     if (x == 0) return 99;
    ///     return x + 1;
    /// }
    /// ```
    ///
    /// Assembled by hand:
    ///   48 85 FF                 TEST   rdi, rdi
    ///   74 0A                    JZ     .zero  (offset +0x0A from end of JZ = +10)
    ///   48 8D 47 01              LEA    rax, [rdi+1]
    ///   C3                       RET
    ///   48 C7 C0 63 00 00 00     MOV    rax, 99
    ///   C3                       RET
    const BRANCH_CODE: &[u8] = &[
        0x48, 0x85, 0xFF, // TEST rdi, rdi
        0x74, 0x05,       // JZ +5 (→ byte 10 = start of MOV rax, 99)
        0x48, 0x8D, 0x47, 0x01, // LEA rax, [rdi+1]
        0xC3,             // RET
        0x48, 0xC7, 0xC0, 0x63, 0x00, 0x00, 0x00, // MOV rax, 99
        0xC3,             // RET
    ];

    /// Verify that the byte sequence in BRANCH_CODE is well-formed by
    /// computing expected outputs before transformation.
    #[test]
    fn orig_branch_fn_sane() {
        unsafe {
            let page_size = 4096;
            let ptr = alloc_exec_page(BRANCH_CODE);
            assert_eq!(call_fn(ptr, 0), 99, "branch_fn(0) should be 99");
            assert_eq!(call_fn(ptr, 5), 6, "branch_fn(5) should be 6");
            assert_eq!(call_fn(ptr, -1), 0, "branch_fn(-1) should be 0");
            free_exec_page(ptr, page_size);
        }
    }

    /// The transformed version of `test_fn` (single block) must produce the
    /// same output as the original for a range of inputs.
    #[test]
    fn transformed_single_block_matches_original() {
        const SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let transformed = transform(ORIG_CODE, SEED);

        unsafe {
            let page_size = 4096;
            let orig_ptr = alloc_exec_page(ORIG_CODE);
            let xfrm_ptr = alloc_exec_page(&transformed);

            for x in [-10i64, -1, 0, 1, 7, 42, 1000] {
                let expected = call_fn(orig_ptr, x);
                let got = call_fn(xfrm_ptr, x);
                assert_eq!(
                    got, expected,
                    "transformed(x={x}) = {got} but original = {expected}"
                );
            }

            free_exec_page(orig_ptr, page_size);
            free_exec_page(xfrm_ptr, page_size);
        }
    }

    /// The transformed version of `branch_fn` (two basic blocks) must
    /// produce the same output as the original for a range of inputs.
    #[test]
    fn transformed_branch_fn_matches_original() {
        const SEED: u64 = 0x0102_0304_0506_0708;
        let transformed = transform(BRANCH_CODE, SEED);

        unsafe {
            let page_size = 4096;
            let orig_ptr = alloc_exec_page(BRANCH_CODE);
            let xfrm_ptr = alloc_exec_page(&transformed);

            for x in [-5i64, -1, 0, 1, 2, 99] {
                let expected = call_fn(orig_ptr, x);
                let got = call_fn(xfrm_ptr, x);
                assert_eq!(
                    got, expected,
                    "transformed branch_fn(x={x}) = {got} but original = {expected}"
                );
            }

            free_exec_page(orig_ptr, page_size);
            free_exec_page(xfrm_ptr, page_size);
        }
    }
}
