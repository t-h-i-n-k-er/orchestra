//! Build script for the Orchestra workspace root.
//!
//! Captures the current git commit hash and build timestamp so that release
//! binaries can identify exactly which source tree they were produced from.
//! The values are injected as `ORCHESTRA_GIT_HASH` and `ORCHESTRA_BUILD_DATE`
//! environment variables that downstream crates read with `env!()`.

use std::process::Command;

fn main() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    let build_date = chrono_like_now();

    println!("cargo:rustc-env=ORCHESTRA_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=ORCHESTRA_BUILD_DATE={build_date}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}

/// Produce an ISO-8601 UTC timestamp without pulling in the `chrono` crate.
fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days since 1970-01-01.
    let days = secs / 86_400;
    let (y, m, d) = days_to_ymd(days as i64);
    let hh = (secs / 3600) % 24;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
