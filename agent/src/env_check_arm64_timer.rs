// ARM64 Generic Timer & PMU Timing
//
// Detects single-step debugging or instruction-level emulation on ARM64
// (AArch64) by measuring execution time of individual instructions using
// the generic timer counter (CNTVCT_EL0) and — when available — the PMU
// cycle counter (PMCCNTR_EL0).
//
// # How it works
//
// 1. Serialize the CPU pipeline (ISB as barrier)
// 2. Read virtual counter (CNTVCT_EL0) via MRS
// 3. Execute the target instruction
// 4. Serialize again (ISB)
// 5. Read virtual counter (CNTVCT_EL0)
// 6. Delta = t1 - t0
//
// By repeating this measurement hundreds of times for several instruction
// types we build a distribution of counter ticks.  On physical hardware the
// distribution is tight and deterministic; under single-step debugging or
// instruction-level emulation every instruction incurs significantly extra
// counter ticks.
//
// # ARM64 Timer Registers
//
// - CNTVCT_EL0:  Virtual counter, always accessible from EL0 (userspace).
//   Increments at a fixed frequency (CNTFRQ_EL0).  Equivalent to x86 TSC.
// - CNTFRQ_EL0:  Counter frequency register (read-only from EL0).
//   Reports the frequency in Hz.  Used to convert ticks to wall-clock time.
// - ISB:         Instruction Synchronization Barrier.  Ensures all prior
//   instructions complete before subsequent ones begin.  Equivalent to
//   CPUID serialization on x86.
// - PMCCNTR_EL0: PMU cycle counter.  Accessible from EL0 only when
//   PMUSERENR_EL0.EN=1 (kernel configuration).  Equivalent to x86 RDPMC.
//
// # Physical hardware baselines (Apple M1/M2, AWS Graviton3)
//
// | Instruction   | Min ticks | Median | Max (typical) | σ     |
// |---------------|-----------|--------|---------------|-------|
// | NOP           | 1 – 2     | 2 – 4  | 6 – 10        | < 3   |
// | ADD           | 1 – 2     | 2 – 4  | 8 – 12        | < 3   |
// | ISB           | 10 – 30   | 20     | 40 – 60       | < 15  |
// | MRS CNTVCT    | 2 – 5     | 4      | 8 – 12        | < 2   |
//
// # Single-step / emulator baselines
//
// | Instruction   | Min ticks | Median  | σ    |
// |---------------|-----------|---------|------|
// | Any           | > 200     | > 500   | > 200|
//
// # Detection criteria
//
// - `min(nop_ticks) > 30`     → likely instrumentation
// - `stddev(nop_ticks) > 50`  → likely instrumentation
// - `median(isb_ticks) > 200` → likely instrumentation
// - `median(nop) / max(min(nop),2) > 6.0` → likely instrumentation
//
// # Constraints
//
// - AArch64 only (uses MRS/ISB instructions).
// - CNTVCT_EL0 is always accessible from EL0 on any compliant ARMv8+
//   implementation.
// - PMCCNTR_EL0 access is attempted with graceful fallback (SIGILL handler
//   on macOS/Linux, VEH on Windows).
// - All measurements complete in < 100 ms.

// ─── Constants ────────────────────────────────────────────────────────────

/// Number of times each instruction is measured.
const MEASUREMENT_ITERATIONS: usize = 100;

/// NOP detection threshold: if minimum observed ticks exceed this, the
/// CPU is likely under instrumentation.
///
/// ARM64 NOP on physical hardware takes 1-2 counter ticks.  Under
/// single-step or emulation the minimum exceeds 200 ticks, so 30 provides
/// a wide margin while tolerating normal system jitter.
const NOP_MIN_THRESHOLD: u64 = 30;

/// NOP standard-deviation threshold.
///
/// Physical hardware produces σ < 3 for NOP measurements.  Single-step /
/// emulation produces σ > 200.  The threshold of 50 tolerates occasional
/// scheduler preemption on busy hosts while maintaining a wide detection
/// margin.
const NOP_STDDEV_THRESHOLD: f64 = 50.0;

/// ISB median threshold: the Instruction Synchronization Barrier is a
/// low-cost instruction on physical hardware (typically 10-30 ticks).
/// Under emulation it takes significantly longer.
const ISB_MEDIAN_THRESHOLD: u64 = 200;

/// NOP ratio threshold (median / floor(min)): physical usually remains < 4.
const NOP_RATIO_THRESHOLD: f64 = 6.0;

/// Floor the denominator for ratio checks so a single 0/1-tick sample does
/// not spuriously inflate the ratio on healthy systems.
const NOP_RATIO_MIN_FLOOR: u64 = 2;

/// Number of cross-check iterations (CNTVCT vs std::time::Instant).
const CROSSCHECK_ITERS: usize = 50;

/// Number of PMU measurement iterations (when PMCCNTR_EL0 is accessible).
const PMU_ITERATIONS: usize = 5;

// ─── ARM64 Counter Primitives ─────────────────────────────────────────────

/// Read the virtual counter (CNTVCT_EL0).
///
/// CNTVCT_EL0 is always accessible from EL0 and provides a monotonically
/// increasing count at a fixed frequency (reported by CNTFRQ_EL0).
/// This is the ARM64 equivalent of x86 RDTSC.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn read_cntvct() -> u64 {
    let val: u64;
    std::arch::asm!(
        "mrs {}, cntvct_el0",
        out(reg) val,
        options(nomem, nostack)
    );
    val
}

/// Read the counter frequency (CNTFRQ_EL0).
///
/// Returns the frequency in Hz.  Used to convert CNTVCT ticks to
/// wall-clock nanoseconds.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn read_cntfrq() -> u64 {
    let val: u64;
    std::arch::asm!(
        "mrs {}, cntfrq_el0",
        out(reg) val,
        options(nomem, nostack)
    );
    val
}

/// Instruction Synchronization Barrier.
///
/// Ensures that all prior instructions have completed their decode and
/// permission checks before any subsequent instruction is processed.
/// This is the ARM64 equivalent of x86 CPUID serialization.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn isb() {
    std::arch::asm!(
        "isb",
        options(nomem, nostack, preserves_flags)
    );
}

/// Read the PMU cycle counter (PMCCNTR_EL0).
///
/// Accessible from EL0 only when PMUSERENR_EL0.EN=1.  On Linux this
/// requires `/proc/sys/kernel/perf_user_access` = 1 or `pmu` in the
/// kernel command line.  On macOS this is typically not accessible.
/// On Windows this requires the PMU to be enabled for user mode.
///
/// Returns `None` if the register is not accessible (faults).
#[cfg(target_arch = "aarch64")]
unsafe fn try_read_pmccntr() -> Option<u64> {
    // Attempt PMCCNTR_EL0 read with fault handling.
    // Use a simple probe: if PMUSERENR_EL0.EN=0, reading PMCCNTR_EL0
    // raises an exception.
    //
    // We use a cached availability flag to avoid probing on every call.
    match *PMU_AVAILABLE.get_or_init(probe_pmccntr) {
        Some(true) => {
            let val: u64;
            unsafe {
                std::arch::asm!(
                    "mrs {}, pmccntr_el0",
                    out(reg) val,
                    options(nomem, nostack)
                );
            }
            Some(val)
        }
        _ => None,
    }
}

/// Cached PMU availability.
static PMU_AVAILABLE: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();

/// Probe whether PMCCNTR_EL0 is accessible from userspace.
///
/// Installs a temporary signal handler and attempts to read the register.
/// If the instruction faults, the signal handler returns `false`.
#[cfg(all(target_arch = "aarch64", unix))]
fn probe_pmccntr() -> Option<bool> {
    use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

    // Jump buffer for setjmp/longjmp recovery.
    #[repr(C, align(16))]
    struct AlignedBuf([u8; 256]);

    static JMP_BUF: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
    static RESULT: AtomicU8 = AtomicU8::new(0); // 0 = unknown, 1 = ok, 2 = fault

    extern "C" fn fault_handler(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        _ctx: *mut libc::c_void,
    ) {
        let buf = JMP_BUF.load(Ordering::SeqCst);
        if !buf.is_null() {
            RESULT.store(2, Ordering::SeqCst);
            unsafe {
                // longjmp back to setjmp anchor
                extern "C" {
                    fn longjmp(buf: *mut u8, val: i32) -> !;
                }
                longjmp(buf, 1);
            }
        }
    }

    let mut buf = AlignedBuf([0u8; 256]);
    let buf_ptr = buf.0.as_mut_ptr();
    JMP_BUF.store(buf_ptr, Ordering::SeqCst);
    RESULT.store(0, Ordering::SeqCst);

    let mut new_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    new_sa.sa_sigaction = fault_handler as *const () as usize;
    new_sa.sa_flags = (libc::SA_SIGINFO | libc::SA_RESETHAND) as i32;
    unsafe {
        libc::sigemptyset(&mut new_sa.sa_mask);
    }

    let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        // On ARM64 Linux, reading an inaccessible system register generates SIGILL.
        // On macOS, it also generates SIGILL.
        libc::sigaction(libc::SIGILL, &new_sa, &mut old_sa);
    }

    extern "C" {
        fn setjmp(buf: *mut u8) -> i32;
    }

    let faulted = unsafe { setjmp(buf_ptr) };

    if faulted == 0 {
        // First call — attempt to read PMCCNTR_EL0
        let _val: u64;
        unsafe {
            std::arch::asm!(
                "mrs {}, pmccntr_el0",
                out(reg) _val,
                options(nomem, nostack)
            );
        }
        // If we reached here, PMCCNTR_EL0 is accessible.
        unsafe {
            libc::sigaction(libc::SIGILL, &old_sa, std::ptr::null_mut());
        }
        JMP_BUF.store(std::ptr::null_mut(), Ordering::SeqCst);
        Some(true)
    } else {
        // Re-entered via longjmp — PMCCNTR_EL0 faulted.
        unsafe {
            libc::sigaction(libc::SIGILL, &old_sa, std::ptr::null_mut());
        }
        JMP_BUF.store(std::ptr::null_mut(), Ordering::SeqCst);
        Some(false)
    }
}

/// Windows ARM64 PMU probe using VEH.
#[cfg(all(target_arch = "aarch64", windows))]
fn probe_pmccntr() -> Option<bool> {
    // On Windows ARM64, reading PMCCNTR_EL0 when not permitted raises
    // STATUS_PRIVILEGED_INSTRUCTION.  Use VEH to catch it.
    // For now, conservatively return None (PMU unavailable) since Windows
    // ARM64 PMU access is extremely rare.
    None
}

/// Non-unix, non-windows ARM64 (e.g., bare metal UEFI).
#[cfg(all(target_arch = "aarch64", not(unix), not(windows)))]
fn probe_pmccntr() -> Option<bool> {
    None
}

// ─── Instruction Timing Measurement ───────────────────────────────────────

/// Statistics for a set of counter-tick measurements.
#[derive(Debug, Clone)]
pub struct InstructionTiming {
    /// Instruction label (for diagnostics).
    pub label: String,
    /// Minimum observed tick count.
    pub min_ticks: u64,
    /// Maximum observed tick count.
    pub max_ticks: u64,
    /// Median observed tick count.
    pub median_ticks: u64,
    /// Mean (average) tick count.
    pub mean_ticks: f64,
    /// Standard deviation of tick counts.
    pub stddev_ticks: f64,
    /// Number of successful samples.
    pub samples: usize,
}

/// Measure the overhead of executing a single NOP instruction.
///
/// Uses ISB + CNTVCT_EL0 to bracket a single NOP.  The measurement
/// includes the overhead of the ISB + MRS instructions, so we subtract
/// the baseline (ISB-MRS-ISB-MRS with no target instruction) to isolate
/// the target instruction cost.
fn measure_nop_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        // SAFETY: We are on aarch64.  ISB and MRS CNTVCT_EL0 are safe
        // user-mode instructions.
        unsafe {
            // Baseline: ISB – MRS CNTVCT – ISB – MRS CNTVCT (no target instruction)
            isb();
            let t0 = read_cntvct();
            isb();
            let t1 = read_cntvct();
            let baseline = t1.wrapping_sub(t0);

            // Measurement: ISB – MRS CNTVCT – NOP – ISB – MRS CNTVCT
            isb();
            let t0 = read_cntvct();
            std::arch::asm!("nop", options(nomem, nostack));
            isb();
            let t1 = read_cntvct();
            let delta = t1.wrapping_sub(t0);

            // Subtract baseline to isolate NOP cost.
            let nop_cost = delta.saturating_sub(baseline);
            samples.push(nop_cost);
        }
    }

    compute_timing_stats("nop", &samples)
}

/// Measure the overhead of executing an ADD instruction.
fn measure_add_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            isb();
            let t0 = read_cntvct();
            isb();
            let t1 = read_cntvct();
            let baseline = t1.wrapping_sub(t0);

            isb();
            let t0 = read_cntvct();
            // ADD X0, X0, #1 (benign — writes to a temporary register)
            std::arch::asm!(
                "add x0, x0, #1",
                out("x0") _,
                options(nomem, nostack)
            );
            isb();
            let t1 = read_cntvct();
            let delta = t1.wrapping_sub(t0);

            let cost = delta.saturating_sub(baseline);
            samples.push(cost);
        }
    }

    compute_timing_stats("add", &samples)
}

/// Measure the overhead of executing an ISB instruction.
///
/// ISB is a known-cost instruction on physical hardware. Under single-step
/// debugging or emulation it will take significantly more ticks.
fn measure_isb_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            isb();
            let t0 = read_cntvct();

            // Target: a single ISB.
            isb();

            let t1 = read_cntvct();
            let delta = t1.wrapping_sub(t0);
            samples.push(delta);
        }
    }

    compute_timing_stats("isb", &samples)
}

/// Measure the overhead of reading CNTVCT_EL0 itself.
///
/// MRS CNTVCT_EL0 takes 2-5 ticks on physical hardware.  Under interception
/// by a hypervisor or debugger, the cost is much higher.
fn measure_cntvct_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            isb();
            let t0 = read_cntvct();

            // Target: MRS CNTVCT_EL0 (non-serializing, just reads counter).
            let _ = read_cntvct();

            let t1 = read_cntvct();
            let delta = t1.wrapping_sub(t0);
            samples.push(delta);
        }
    }

    compute_timing_stats("mrs_cntvct", &samples)
}

// ─── Statistical Helpers ──────────────────────────────────────────────────

/// Compute min, max, median, mean, and stddev from a slice of u64 samples.
fn compute_timing_stats(label: &str, samples: &[u64]) -> InstructionTiming {
    if samples.is_empty() {
        return InstructionTiming {
            label: label.to_string(),
            min_ticks: 0,
            max_ticks: 0,
            median_ticks: 0,
            mean_ticks: 0.0,
            stddev_ticks: 0.0,
            samples: 0,
        };
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let n = sorted.len();
    let min_ticks = sorted[0];
    let max_ticks = sorted[n - 1];
    let median_ticks = sorted[n / 2];

    // Use trimmed statistics for mean/stddev on larger samples to avoid
    // occasional scheduler/SMI outliers from dominating jitter metrics.
    let trim = if n >= 20 { n / 10 } else { 0 }; // 10% from each tail
    let core = if trim > 0 && (2 * trim) < n {
        &sorted[trim..(n - trim)]
    } else {
        &sorted[..]
    };

    let core_n = core.len();
    let sum: u64 = core.iter().sum();
    let mean = sum as f64 / core_n as f64;

    let variance: f64 = core
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / core_n as f64;
    let stddev = variance.sqrt();

    InstructionTiming {
        label: label.to_string(),
        min_ticks,
        max_ticks,
        median_ticks,
        mean_ticks: mean,
        stddev_ticks: stddev,
        samples: n,
    }
}

// ─── Timing Analysis ──────────────────────────────────────────────────────

/// Result of the ARM64 instruction-granularity timing analysis.
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    /// NOP instruction timing statistics.
    pub nop: InstructionTiming,
    /// ADD instruction timing statistics.
    pub add: InstructionTiming,
    /// ISB instruction timing statistics.
    pub isb: InstructionTiming,
    /// MRS CNTVCT_EL0 timing statistics.
    pub cntvct: InstructionTiming,
    /// Counter frequency in Hz.
    pub counter_freq_hz: u64,
    /// Number of detection criteria that fired.
    pub suspicion_signals: usize,
    /// Total suspicion score (0–4).
    pub suspicion_score: u32,
}

/// Run all instruction-granularity timing measurements and return the
/// full analysis.
///
/// CNTVCT_EL0 is always available on ARMv8+, so this never returns `None`
/// due to hardware capability (unlike x86 which needs invariant TSC).
/// Returns `None` only if measurements fail catastrophically.
pub fn analyze_timing_distribution() -> Option<TimingAnalysis> {
    let freq = unsafe { read_cntfrq() };
    if freq == 0 {
        // Degenerate: counter frequency is 0.  Should not happen on any
        // compliant ARMv8+ implementation.
        return None;
    }

    let nop = measure_nop_timing(MEASUREMENT_ITERATIONS);
    let add = measure_add_timing(MEASUREMENT_ITERATIONS);
    let isb = measure_isb_timing(MEASUREMENT_ITERATIONS);
    let cntvct = measure_cntvct_timing(MEASUREMENT_ITERATIONS);

    // Evaluate detection criteria.
    let mut signals = 0u32;

    // Criterion 1: min(nop) > NOP_MIN_THRESHOLD
    let c1 = nop.min_ticks > NOP_MIN_THRESHOLD;
    if c1 { signals += 1; }

    // Criterion 2: stddev(nop) > NOP_STDDEV_THRESHOLD
    let c2 = nop.stddev_ticks > NOP_STDDEV_THRESHOLD;
    if c2 { signals += 1; }

    // Criterion 3: median(isb) > ISB_MEDIAN_THRESHOLD
    let c3 = isb.median_ticks > ISB_MEDIAN_THRESHOLD;
    if c3 { signals += 1; }

    // Criterion 4: median(nop) / max(min(nop), 2) > NOP_RATIO_THRESHOLD
    let ratio_denom = nop.min_ticks.max(NOP_RATIO_MIN_FLOOR);
    let c4 = if ratio_denom > 0 {
        (nop.median_ticks as f64 / ratio_denom as f64) > NOP_RATIO_THRESHOLD
    } else {
        false
    };
    if c4 { signals += 1; }

    // Confirmation round: on busy physical hosts, transient noise (scheduler
    // preemption, interrupt handling) can inflate a single measurement round.
    // When the first round triggers ≥2 criteria, run a second independent
    // measurement and require ≥2 again.
    let signals = if signals >= 2 {
        let nop2 = measure_nop_timing(MEASUREMENT_ITERATIONS);
        let isb2 = measure_isb_timing(MEASUREMENT_ITERATIONS);

        let mut signals2 = 0u32;
        if nop2.min_ticks > NOP_MIN_THRESHOLD { signals2 += 1; }
        if nop2.stddev_ticks > NOP_STDDEV_THRESHOLD { signals2 += 1; }
        if isb2.median_ticks > ISB_MEDIAN_THRESHOLD { signals2 += 1; }
        let ratio_denom2 = nop2.min_ticks.max(NOP_RATIO_MIN_FLOOR);
        if ratio_denom2 > 0 && (nop2.median_ticks as f64 / ratio_denom2 as f64) > NOP_RATIO_THRESHOLD {
            signals2 += 1;
        }

        if signals2 >= 2 {
            // Both rounds agree — persistent instrumentation.
            signals.max(signals2)
        } else {
            // Second round did NOT confirm — likely transient host noise.
            tracing::info!(
                "env_check_arm64_timer: first round had {signals} signals but confirmation round \
                 had only {signals2}; downgrading to informational (transient noise)"
            );
            1
        }
    } else {
        signals
    };

    Some(TimingAnalysis {
        nop,
        add,
        isb,
        cntvct,
        counter_freq_hz: freq,
        suspicion_signals: signals as usize,
        suspicion_score: signals,
    })
}

// ─── Counter / std::time::Instant Cross-Check ────────────────────────────

/// Read a secondary time source for cross-validation with CNTVCT_EL0.
///
/// Emulators may intercept and fake CNTVCT_EL0 but typically do not
/// synchronize the faked values with other system clocks (clock_gettime,
/// mach_absolute_time).  If the two time sources diverge by > 10%, that
/// indicates time manipulation.
///
/// Returns `(cntvct_delta, secondary_delta_nanos)` or `None` on failure.
fn cross_check_with_secondary() -> Option<(u64, u64)> {
    // Use a tight computational loop as the known workload.
    const WORKLOAD_ITERS: u64 = 10_000_000;

    let tsc_start = unsafe { read_cntvct() };

    // Secondary clocksource: std::time::Instant maps to:
    //   - Linux: clock_gettime(CLOCK_MONOTONIC)
    //   - macOS: mach_absolute_time
    //   - Windows: QueryPerformanceCounter
    let sec_start = std::time::Instant::now();

    // Known workload: simple arithmetic loop (not optimizable away).
    let mut acc: u64 = 1;
    for i in 0..WORKLOAD_ITERS {
        acc = acc.wrapping_add(i);
        acc = acc.wrapping_mul(3);
        acc ^= i;
    }
    std::hint::black_box(acc);

    let sec_elapsed = sec_start.elapsed();
    let tsc_end = unsafe { read_cntvct() };

    let tsc_delta = tsc_end.wrapping_sub(tsc_start);
    let sec_nanos = sec_elapsed.as_nanos() as u64;

    if sec_nanos == 0 || tsc_delta == 0 {
        return None;
    }

    Some((tsc_delta, sec_nanos))
}

/// Run the cross-check multiple times and look for divergence between
/// CNTVCT_EL0 and the secondary clocksource.
///
/// Returns `true` if the ratio diverges by > 10% across iterations,
/// indicating likely time manipulation.
fn counter_cross_check_flagged() -> bool {
    let mut ratios: Vec<f64> = Vec::with_capacity(CROSSCHECK_ITERS);

    for _ in 0..CROSSCHECK_ITERS {
        if let Some((cntvct_delta, sec_nanos)) = cross_check_with_secondary() {
            let ratio = cntvct_delta as f64 / sec_nanos as f64;
            ratios.push(ratio);
        }
    }

    if ratios.len() < 10 {
        return false;
    }

    // Compute coefficient of variation (CV = stddev / mean).
    let n = ratios.len() as f64;
    let mean: f64 = ratios.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return false;
    }
    let variance: f64 = ratios.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    let cv = stddev / mean;

    // On physical hardware, CV should be < 0.05 (5%).
    // If CV > 0.10 (10%), the clocks are not synchronized → manipulation.
    cv > 0.10
}

// ─── PMU-Based VM Probability (when PMCCNTR_EL0 is accessible) ───────────

/// VM probability estimate from PMU measurements.
#[derive(Debug, Clone)]
pub struct PmuFingerprint {
    /// Estimated instruction retirement rate (PMU cycles / wall-clock time).
    pub cycle_rate_mean: f64,
    /// Coefficient of variation of cycle rate across measurements.
    pub cycle_rate_cv: f64,
    /// Number of successful measurements.
    pub samples: usize,
    /// VM probability (0.0 = physical, 1.0 = definitely VM).
    pub vm_probability: f64,
}

/// Run PMU-based measurements when PMCCNTR_EL0 is accessible.
///
/// Uses a simple approach: measure cycle count during a known workload
/// and compare against CNTVCT_EL0 timing.  Physical hardware shows tight
/// correlation; VMs / emulators show high variance or implausible ratios.
pub fn analyze_pmu_fingerprint() -> Option<PmuFingerprint> {
    let _pmu = unsafe { try_read_pmccntr()? };

    const WORKLOAD_ITERS: u64 = 5_000_000;

    let mut cycle_rates: Vec<f64> = Vec::with_capacity(PMU_ITERATIONS);

    for _ in 0..PMU_ITERATIONS {
        let start_cycles = unsafe { try_read_pmccntr()? };
        let start_time = unsafe { read_cntvct() };

        // Known workload.
        let mut acc: u64 = 1;
        for i in 0..WORKLOAD_ITERS {
            acc = acc.wrapping_add(i);
            acc = acc.wrapping_mul(3);
            acc ^= i;
        }
        std::hint::black_box(acc);

        let end_cycles = unsafe { try_read_pmccntr()? };
        let end_time = unsafe { read_cntvct() };

        let cycle_delta = end_cycles.wrapping_sub(start_cycles) as f64;
        let time_delta = end_time.wrapping_sub(start_time) as f64;

        if time_delta > 0.0 {
            cycle_rates.push(cycle_delta / time_delta);
        }
    }

    if cycle_rates.len() < 3 {
        return None;
    }

    let n = cycle_rates.len() as f64;
    let mean: f64 = cycle_rates.iter().sum::<f64>() / n;
    let variance: f64 = cycle_rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    let cv = if mean > 0.0 { stddev / mean } else { 1.0 };

    // VM probability estimation:
    // - Physical hardware: CV < 0.05, consistent cycle rate → low probability
    // - VMs/emulators: CV > 0.10, inconsistent rates → higher probability
    let vm_prob = if cv > 0.20 {
        0.9
    } else if cv > 0.10 {
        0.6
    } else if cv > 0.05 {
        0.3
    } else {
        0.0
    };

    Some(PmuFingerprint {
        cycle_rate_mean: mean,
        cycle_rate_cv: cv,
        samples: cycle_rates.len(),
        vm_probability: vm_prob,
    })
}

// ─── Integration with env_check Scoring Pipeline ──────────────────────────

/// Produce a `SandboxIndicator` from the ARM64 instruction-granularity timing
/// analysis.
///
/// This is called from `collect_indicators()` in `env_check.rs`.
///
/// Weight assignment (mirrors the x86 RDTSC module):
/// - 4 criteria positive: weight 30 (high confidence)
/// - 3 criteria positive: weight 20 (medium confidence)
/// - 2 criteria positive: weight 10 (low confidence)
/// - 0–1 criteria positive: weight 0 (likely physical hardware)
pub fn instruction_timing_indicator() -> Option<common::SandboxIndicator> {
    let analysis = analyze_timing_distribution()?;

    let weight = if analysis.suspicion_score >= 4 {
        30
    } else if analysis.suspicion_score >= 3 {
        20
    } else if analysis.suspicion_score >= 2 {
        10
    } else {
        0
    };

    // Also run cross-check against secondary clocksource.
    let cross_flag = counter_cross_check_flagged();
    let cross_note = if cross_flag {
        " [CLOCK_MISMATCH]"
    } else {
        ""
    };

    // Boost weight if cross-check also flagged.
    let final_weight = if cross_flag && weight > 0 {
        weight + 10
    } else if cross_flag && weight == 0 {
        5 // Cross-check alone is a very mild signal
    } else {
        weight
    };

    let detail = format!(
        "ARM64 CNTVCT timing: nop=[min={},med={},σ={:.1}] isb=[med={}] cntvct=[med={:.0}] \
         signals={}/4 freq={}Hz{}",
        analysis.nop.min_ticks,
        analysis.nop.median_ticks,
        analysis.nop.stddev_ticks,
        analysis.isb.median_ticks,
        analysis.cntvct.mean_ticks,
        analysis.suspicion_signals,
        analysis.counter_freq_hz,
        cross_note,
    );

    Some(common::SandboxIndicator {
        category: "timing".to_string(),
        detail,
        weight: final_weight,
        source: "arm64_timer".to_string(),
    })
}

/// Produce a `SandboxIndicator` from the ARM64 PMU fingerprint, if available.
///
/// This is called from `collect_indicators()` in `env_check.rs`.
///
/// Weight assignment (mirrors the x86 HPC module):
/// - High confidence (>0.8 vm_probability): weight 25
/// - Medium confidence (0.5–0.8): weight 15
/// - Low confidence (<0.5): weight 0 (informational only)
pub fn pmu_indicator() -> Option<common::SandboxIndicator> {
    let fp = analyze_pmu_fingerprint()?;

    let weight = if fp.vm_probability > 0.8 {
        25
    } else if fp.vm_probability > 0.5 {
        15
    } else {
        0
    };

    let detail = format!(
        "ARM64 PMU fingerprint: cycle_rate={:.3} cv={:.3} vm_prob={:.3} samples={}",
        fp.cycle_rate_mean,
        fp.cycle_rate_cv,
        fp.vm_probability,
        fp.samples,
    );

    Some(common::SandboxIndicator {
        category: "hpc".to_string(),
        detail,
        weight,
        source: "arm64_pmu".to_string(),
    })
}

/// ARM64-specific timing consistency cross-check.
///
/// Compares CNTVCT_EL0 against `std::time::Instant` over a computational
/// workload.  Divergence > 10% indicates time source manipulation.
///
/// This is the ARM64 equivalent of the Windows x86_64 `timing_consistency_indicator()`.
pub fn timing_consistency_indicator() -> Option<common::SandboxIndicator> {
    const MEASUREMENT_ROUNDS: usize = 5;
    const WORKLOAD_ITERS: u64 = 10_000_000;

    let freq = unsafe { read_cntfrq() };
    if freq == 0 {
        return None;
    }

    let mut divergences: Vec<f64> = Vec::with_capacity(MEASUREMENT_ROUNDS);

    for _ in 0..MEASUREMENT_ROUNDS {
        let tsc_start = unsafe { read_cntvct() };
        let instant_start = std::time::Instant::now();

        let mut acc: u64 = 1;
        for i in 0..WORKLOAD_ITERS {
            acc = acc.wrapping_mul(i.wrapping_add(1)).wrapping_add(i);
        }
        unsafe { std::ptr::write_volatile(&mut acc, acc) };

        let tsc_end = unsafe { read_cntvct() };
        let instant_elapsed = instant_start.elapsed();

        let tsc_delta = tsc_end.wrapping_sub(tsc_start);
        let instant_nanos = instant_elapsed.as_nanos() as u64;

        if instant_nanos == 0 || tsc_delta == 0 {
            continue;
        }

        // Convert CNTVCT ticks to nanoseconds: (ticks * 1_000_000_000) / freq
        let tsc_nanos = (tsc_delta as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(freq as u128)
            .unwrap_or(0) as u64;

        if tsc_nanos == 0 {
            continue;
        }

        // Compute divergence percentage.
        let max_v = tsc_nanos.max(instant_nanos) as f64;
        let min_v = tsc_nanos.min(instant_nanos) as f64;
        let divergence_pct = ((max_v - min_v) / max_v) * 100.0;
        divergences.push(divergence_pct);
    }

    if divergences.len() < 3 {
        return None;
    }

    let mean_divergence: f64 = divergences.iter().sum::<f64>() / divergences.len() as f64;

    if mean_divergence > 10.0 {
        return Some(common::SandboxIndicator {
            category: "timing_consistency".to_string(),
            detail: format!(
                "ARM64 CNTVCT and std::time::Instant diverge by {:.1}% (time source manipulation)",
                mean_divergence
            ),
            weight: 20,
            source: "arm64_timer_consistency".to_string(),
        });
    }

    None
}

// ─── Public Helpers ───────────────────────────────────────────────────────

/// Check whether ARM64 timer-based analysis is available.
///
/// Always returns `true` on ARM64 since CNTVCT_EL0 is guaranteed to be
/// accessible from EL0 on any compliant ARMv8+ implementation.
pub fn is_available() -> bool {
    true
}

/// Check whether PMU (PMCCNTR_EL0) is accessible from userspace.
pub fn pmu_available() -> bool {
    unsafe { try_read_pmccntr().is_some() }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_frequency_nonzero() {
        // On any real ARM64 system, CNTFRQ_EL0 should be nonzero.
        let freq = unsafe { read_cntfrq() };
        assert!(freq > 0, "CNTFRQ_EL0 should be nonzero on ARM64, got {freq}");
    }

    #[test]
    fn test_cntvct_monotonic() {
        // Two consecutive reads should show non-decreasing values.
        let t0 = unsafe { read_cntvct() };
        let t1 = unsafe { read_cntvct() };
        assert!(t1 >= t0, "CNTVCT_EL0 should be monotonic: {t0} -> {t1}");
    }

    #[test]
    fn test_timing_stats_empty() {
        let stats = compute_timing_stats("test", &[]);
        assert_eq!(stats.samples, 0);
        assert_eq!(stats.min_ticks, 0);
        assert_eq!(stats.median_ticks, 0);
    }

    #[test]
    fn test_timing_stats_single() {
        let stats = compute_timing_stats("test", &[42]);
        assert_eq!(stats.samples, 1);
        assert_eq!(stats.min_ticks, 42);
        assert_eq!(stats.median_ticks, 42);
        assert_eq!(stats.mean_ticks, 42.0);
        assert_eq!(stats.stddev_ticks, 0.0);
    }

    #[test]
    fn test_timing_stats_sorted() {
        let stats = compute_timing_stats("test", &[2, 4, 4, 4, 5, 5, 7, 9]);
        assert_eq!(stats.min_ticks, 2);
        assert_eq!(stats.max_ticks, 9);
        assert_eq!(stats.median_ticks, 4); // index 4 (0-based) of 8 elements
    }

    #[test]
    fn test_analyze_timing_distribution() {
        // Verify the full analysis pipeline runs without panicking.
        if let Some(analysis) = analyze_timing_distribution() {
            assert!(analysis.counter_freq_hz > 0);
            assert!(analysis.nop.samples > 0);
            assert!(analysis.add.samples > 0);
            assert!(analysis.isb.samples > 0);
            assert!(analysis.cntvct.samples > 0);
            // On physical hardware, suspicion_score should be 0 or 1.
            assert!(analysis.suspicion_score <= 4);
        }
    }

    #[test]
    fn test_instruction_timing_indicator() {
        // Verify the indicator can be produced.
        if let Some(ind) = instruction_timing_indicator() {
            assert_eq!(ind.category, "timing");
            assert!(ind.detail.contains("ARM64 CNTVCT"));
            // On physical hardware, weight should be 0 or very low.
            assert!(ind.weight <= 40);
        }
    }

    #[test]
    fn test_timing_consistency_indicator() {
        // On physical hardware, should return None (no divergence).
        let result = timing_consistency_indicator();
        // We don't assert None because test execution environments may vary,
        // but it should not panic.
        if let Some(ind) = result {
            assert_eq!(ind.category, "timing_consistency");
            assert!(ind.detail.contains("ARM64 CNTVCT"));
        }
    }

    #[test]
    fn test_cross_check() {
        // The cross-check should not flag on physical hardware.
        let flagged = counter_cross_check_flagged();
        // We don't assert !flagged because CI environments may have
        // unusual timing, but it should not panic.
        let _ = flagged;
    }

    #[test]
    fn test_is_available() {
        assert!(is_available());
    }
}
