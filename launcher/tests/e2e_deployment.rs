//! End-to-end deployment test for the Orchestra launcher.
//!
//! This test exercises the full happy path on Linux:
//!
//! 1. A dummy "agent" shell script is written to a temp directory and an
//!    AES-256-GCM payload is built from it using `common::CryptoSession`.
//! 2. A local `warp` HTTP server hosts the encrypted payload at
//!    `http://127.0.0.1:<port>/agent.enc`.
//! 3. The compiled `launcher` binary is invoked via `assert_cmd` with
//!    `--url` and `--key`.
//! 4. The dummy agent writes a marker file when executed; the test asserts
//!    the marker exists.
//!
//! The test is gated to Linux because in-memory exec on the other platforms
//! is intentionally not enabled in this revision (see `launcher/src/main.rs`).

#![cfg(target_os = "linux")]

use assert_cmd::Command;
use base64::Engine;
use common::CryptoSession;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launcher_downloads_decrypts_and_executes() {
    let dir = tempdir().expect("tempdir");
    let marker = dir.path().join("marker.txt");

    // Build a dummy agent: a shell script that touches the marker file.
    let agent_src = dir.path().join("agent.sh");
    std::fs::write(
        &agent_src,
        format!("#!/bin/sh\necho ok > {}\n", marker.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&agent_src, std::fs::Permissions::from_mode(0o755)).unwrap();

    let plaintext = std::fs::read(&agent_src).unwrap();

    // Encrypt using the same primitive the launcher will use to decrypt.
    let key_bytes = [7u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let session = CryptoSession::from_shared_secret(&key_bytes);
    let payload = session.encrypt(&plaintext);

    let serve_dir = dir.path().to_path_buf();
    std::fs::write(serve_dir.join("agent.enc"), &payload).unwrap();

    // Start a local warp server on an ephemeral port.
    let routes = warp::fs::dir(serve_dir.clone());
    let (addr, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
    let server_handle = tokio::spawn(server);

    // Give the server a moment to be reachable.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let url = format!("http://{addr}/agent.enc");
    let mut cmd = Command::cargo_bin("launcher").expect("launcher binary built");
    cmd.arg("--url").arg(&url).arg("--key").arg(&key_b64);

    // The launcher replaces its process image via execv on success, so the
    // child *is* the dummy script. Wait for it to finish writing the marker.
    let output = cmd.output().expect("spawn launcher");

    // Either execv succeeded (the script ran in place of the launcher) or
    // exit was non-zero — but in both cases the dummy script should have
    // produced the marker before the process tree terminated.
    let mut waited = Duration::ZERO;
    while !marker.exists() && waited < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    }
    assert!(
        marker.exists(),
        "marker file not produced; launcher stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    server_handle.abort();
}
