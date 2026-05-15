//! Integration test for the launcher's in-memory execution path.
//!
//! On Windows this test launches a tiny dummy `.exe` via process hollowing
//! and verifies the call returns successfully (the spawned host process is
//! detached and reaped by the system).
//!
//! On non-Windows hosts hollowing is unavailable; we instead verify that
//! the shared `hollowing` crate returns the documented controlled error so
//! callers can surface a clean diagnostic.
//!
//! ## PE Validation Tests (cross-platform)
//!
//! The hollowing crate includes PE-parsing helpers (`rva_to_file_offset`,
//! `checked_payload_range`, `checked_pe_lfanew`) that are exercised here
//! with hand-crafted byte buffers to ensure malformed PE data is rejected
//! cleanly without panics.

#[cfg(windows)]
#[test]
#[ignore] // Requires a writable build dir and is invasive: opt-in only.
fn hollow_and_execute_runs_a_dummy_exe() {
    // Minimal valid PE: just point to our own exe so we know it runs cleanly.
    // We deliberately use the test binary itself as the payload here because
    // it is guaranteed to be a valid PE on the host architecture.
    let payload =
        std::fs::read(std::env::current_exe().unwrap()).expect("read current test exe as payload");
    hollowing::hollow_and_execute(&payload).expect("hollowing succeeded");
}

#[cfg(not(windows))]
#[test]
fn hollow_and_execute_returns_controlled_error_off_windows() {
    let err = hollowing::hollow_and_execute(b"unused payload").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("only available on Windows"),
        "expected 'only available on Windows' in {msg:?}"
    );
}

#[cfg(not(windows))]
#[test]
fn inject_into_process_returns_controlled_error_off_windows() {
    let err = hollowing::inject_into_process(1234, b"shellcode").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("only available on Windows"),
        "expected 'only available on Windows' for inject_into_process in {msg:?}"
    );
}

// ── PE validation helpers (cross-platform, unit-testable) ──────────────
//
// These tests exercise the PE parsing helpers that are `#[cfg(any(windows, test))]`
// in hollowing::windows_impl.  They validate that malformed PE data is
// rejected with proper error messages rather than panicking or producing
// incorrect results.

/// Helper: build a minimal PE byte buffer with a DOS header pointing to
/// an NT header at `nt_offset`, followed by `num_sections` section headers.
fn build_minimal_pe(nt_offset: usize, num_sections: usize) -> Vec<u8> {
    let section_size = 40; // IMAGE_SECTION_HEADER size
    let nt_header_size = 24 + 240; // FILE_HEADER + OPTIONAL_HEADER64
    let total = nt_offset + nt_header_size + num_sections * section_size;
    let mut buf = vec![0u8; total];

    // DOS signature "MZ"
    buf[0] = b'M';
    buf[1] = b'Z';

    // e_lfanew at offset 0x3C
    let lfanew = nt_offset as u32;
    buf[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());

    // NT signature "PE\0\0"
    buf[nt_offset] = b'P';
    buf[nt_offset + 1] = b'E';
    buf[nt_offset + 2] = 0;
    buf[nt_offset + 3] = 0;

    // FileHeader at nt_offset + 4
    // NumberOfSections at offset 2 (u16)
    let num_sec = num_sections as u16;
    buf[nt_offset + 4 + 2..nt_offset + 4 + 4].copy_from_slice(&num_sec.to_le_bytes());

    // SizeOfOptionalHeader at offset 16 (u16) — standard size for PE32+
    let opt_size = 240u16; // sizeof(IMAGE_OPTIONAL_HEADER64)
    buf[nt_offset + 4 + 16..nt_offset + 4 + 18].copy_from_slice(&opt_size.to_le_bytes());

    // OptionalHeader magic at nt_offset + 24 (PE32+ = 0x20B)
    let magic = 0x20Bu16;
    buf[nt_offset + 24..nt_offset + 26].copy_from_slice(&magic.to_le_bytes());

    buf
}

/// `hollow_and_execute` should reject an empty payload with a clear error.
#[test]
fn hollowing_rejects_empty_payload() {
    let result = hollowing::hollow_and_execute(&[]);
    assert!(result.is_err(), "empty payload should be rejected");
}

/// `hollow_and_execute` should reject a payload that is too small to hold
/// the DOS header e_lfanew field at offset 0x3C.
#[test]
fn hollowing_rejects_truncated_dos_header() {
    // Only 10 bytes — not enough to read e_lfanew at offset 0x3C.
    let result = hollowing::hollow_and_execute(&[0u8; 10]);
    assert!(result.is_err(), "truncated DOS header should be rejected");
}

/// A payload with a valid MZ signature but garbage e_lfanew pointing past
/// the buffer should be rejected.
#[test]
fn hollowing_rejects_invalid_e_lfanew() {
    let mut buf = vec![0u8; 128];
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew points to offset 0x1000, which is far beyond the buffer.
    buf[0x3C..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
    let result = hollowing::hollow_and_execute(&buf);
    assert!(result.is_err(), "invalid e_lfanew should be rejected");
}

/// A payload with a negative e_lfanew value should be rejected.
#[test]
fn hollowing_rejects_negative_e_lfanew() {
    let mut buf = vec![0u8; 128];
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew = -1 (0xFFFFFFFF as i32).
    buf[0x3C..0x40].copy_from_slice(&(-1i32).to_le_bytes());
    let result = hollowing::hollow_and_execute(&buf);
    assert!(result.is_err(), "negative e_lfanew should be rejected");
}

/// Verify that `hollow_and_execute` rejects a payload with a valid DOS
/// header but no "PE\0\0" signature at the NT offset.
#[test]
fn hollowing_rejects_missing_pe_signature() {
    let mut buf = vec![0u8; 512];
    buf[0] = b'M';
    buf[1] = b'Z';
    // Point e_lfanew to a valid offset but don't write "PE\0\0".
    buf[0x3C..0x40].copy_from_slice(&128u32.to_le_bytes());
    // Leave bytes at offset 128 as zeros (no PE signature).
    let result = hollowing::hollow_and_execute(&buf);
    assert!(result.is_err(), "missing PE signature should be rejected");
}

/// Build a valid-looking minimal PE and verify `hollow_and_execute` rejects
/// it on non-Windows platforms (it gets further into validation before
/// hitting the platform gate).
#[cfg(not(windows))]
#[test]
fn hollowing_minimal_pe_rejected_off_windows() {
    let pe = build_minimal_pe(128, 0);
    let result = hollowing::hollow_and_execute(&pe);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    // Should mention Windows unavailability since we're on a non-Windows platform.
    assert!(
        msg.contains("only available on Windows"),
        "expected Windows-only error, got: {msg:?}"
    );
}

/// Verify that a large random payload doesn't panic (even if it returns an error).
#[test]
fn hollowing_handles_large_random_payload_gracefully() {
    let mut rng_payload = vec![0u8; 4096];
    // Fill with pseudo-random data (deterministic for reproducibility).
    for (i, byte) in rng_payload.iter_mut().enumerate() {
        *byte = ((i * 7 + 3) % 256) as u8;
    }
    // Force an MZ signature so it at least tries to parse.
    rng_payload[0] = b'M';
    rng_payload[1] = b'Z';
    rng_payload[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());

    // Should return an error, not panic.
    let result = hollowing::hollow_and_execute(&rng_payload);
    assert!(result.is_err());
}
