//! Long-running soak test for the Orchestra command dispatcher.
//!
//! This test exercises `agent::handlers::handle_command` for a configurable
//! duration (default 30 seconds in `cargo test`, 1 hour when the
//! `ORCHESTRA_SOAK_HOURS` environment variable is set) and verifies that
//! resident-memory growth stays within a bounded budget.
//!
//! It is intentionally lightweight (no network I/O, no PTYs) so that it can
//! run in CI without flakiness while still catching obvious leaks in the
//! handler hot path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{config::Config, Command, CryptoSession};
use tokio::sync::Mutex;

/// Try to read the resident-set-size of the current process in KiB.
/// Returns `None` on platforms without `/proc/self/status` (e.g., macOS,
/// Windows) — the test still runs but skips the memory-growth assertion.
fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok());
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn soak_handler_dispatch() {
    // Determine duration: short by default, hours when explicitly requested.
    let secs: u64 = std::env::var("ORCHESTRA_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("ORCHESTRA_SOAK_HOURS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(|h| h * 3600)
        })
        .unwrap_or(30);
    let deadline_overall = Duration::from_secs(secs.saturating_add(60));
    let test_duration = Duration::from_secs(secs);

    eprintln!("soak: running for {secs}s");

    let crypto = Arc::new(CryptoSession::from_shared_secret(b"soak-test"));
    let config = Arc::new(Mutex::new(Config::default()));
    let (out_tx, _out_rx) = tokio::sync::mpsc::channel(16);
    let p2p_mesh = Arc::new(tokio::sync::Mutex::new(agent::p2p::P2pMesh::default()));

    let baseline = rss_kib();
    let started = Instant::now();
    let mut iterations: u64 = 0;

    let work = async {
        while started.elapsed() < test_duration {
            for cmd in [
                Command::Ping,
                Command::GetSystemInfo,
                Command::ListDirectory {
                    path: "/tmp".into(),
                },
            ] {
                let _ =
                    agent::handlers::handle_command(crypto.clone(), config.clone(), cmd, "admin", out_tx.clone(), p2p_mesh.clone())
                        .await;
                iterations += 1;
            }

            if iterations % 5_000 == 0 {
                tokio::task::yield_now().await;
            }
        }
        iterations
    };

    let total = tokio::time::timeout(deadline_overall, work)
        .await
        .expect("soak test exceeded overall deadline");

    let elapsed = started.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed.max(0.001);
    eprintln!("soak: {total} iterations in {elapsed:.1}s ({rate:.0} ops/s)");

    if let (Some(start), Some(end)) = (baseline, rss_kib()) {
        let delta = end as i64 - start as i64;
        eprintln!("soak: RSS {start} -> {end} KiB (Δ {delta:+} KiB)");
        // Allow up to 50 MiB of growth across the run; a real leak in the
        // hot path would dwarf this on a 30-second loop.
        assert!(
            delta < 50 * 1024,
            "Resident memory grew by {delta} KiB, suggesting a leak"
        );
    } else {
        eprintln!("soak: skipping memory-growth check (no /proc/self/status)");
    }

    assert!(total > 0, "Soak loop should have made progress");
}
