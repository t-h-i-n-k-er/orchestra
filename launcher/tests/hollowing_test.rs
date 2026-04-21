//! Integration test for the launcher's in-memory execution path.
//!
//! On Windows this test launches a tiny dummy `.exe` via process hollowing
//! and verifies the call returns successfully (the spawned host process is
//! detached and reaped by the system).
//!
//! On non-Windows hosts hollowing is unavailable; we instead verify that
//! the shared `hollowing` crate returns the documented controlled error so
//! callers can surface a clean diagnostic.

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
