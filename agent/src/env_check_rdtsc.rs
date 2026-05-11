// RDTSC Instruction-Granularity Timing
//
// Detects single-step debugging or instruction-level emulation by measuring
// the execution time of individual instructions using RDTSC/RDTSCP.  Classic
// timing checks measure whole-function or sleep-based execution; this module
// operates at individual instruction boundaries where single-step debugging
// introduces measurable per-instruction latency that is statistically
// impossible to hide.
//
// # How it works
//
// 1. Serialize the CPU pipeline (CPUID as barrier)
// 2. Read TSC (t0) via RDTSCP (serializing variant, harder to intercept)
// 3. Execute the target instruction
// 4. Serialize again (CPUID)
// 5. Read TSC (t1)
// 6. Delta = t1 - t0
//
// By repeating this measurement hundreds of times for several instruction
// types we build a distribution of cycle counts.  On physical hardware the
// distribution is tight and deterministic; under single-step debugging or
// instruction-level emulation every instruction incurs 1000+ extra cycles.
//
// # Physical hardware baselines
//
// | Instruction | Min cycles | Median | Max (typical) | σ |
// |-------------|-----------|--------|---------------|------|
// | NOP         | 0 – 1     | 1 – 2  | 3 – 5         | < 1  |
// | MOV         | 1 – 2     | 1 – 2  | 4 – 6         | < 1  |
// | CPUID       | 100 – 150 | 140    | 250           | < 50 |
// | RDTSC       | 20 – 25   | 24     | 35            | < 5  |
//
// # Single-step / emulator baselines
//
// | Instruction | Min cycles | Median  | σ    |
// |-------------|-----------|---------|------|
// | Any         | > 500     | > 1000  | > 500 |
//
// # Detection criteria
//
// - `min(nop_cycles) > 10`    → likely instrumentation
// - `stddev(nop_cycles) > 10`  → likely instrumentation
// - `median(cpuid_cycles) > 1000` → likely instrumentation
// - `median(nop) / min(nop) > 5.0` → likely instrumentation
//
// # Constraints
//
// - x86_64 only (RDTSC/RDTSCP are x86-specific instructions).
// - Prefers RDTSCP over RDTSC (serializing, harder to intercept).
// - Handles non-invariant TSC by detecting CPUID.80000007H:EDX[8] and
//   falling back to coarse timing on old CPUs.
// - All measurements complete in < 50 ms.
// - Gracefully handles VMs that intercept RDTSC (returns inflated values
//   which the statistical analysis correctly flags).

use std::arch::x86_64::__cpuid;

// ─── Constants ────────────────────────────────────────────────────────────

/// Number of times each instruction is measured.
const MEASUREMENT_ITERATIONS: usize = 100;

/// NOP detection threshold: if minimum observed cycles exceed this, the
/// CPU is likely under instrumentation.
const NOP_MIN_THRESHOLD: u64 = 10;

/// NOP standard-deviation threshold: physical hardware produces σ < 1.
const NOP_STDDEV_THRESHOLD: f64 = 10.0;

/// CPUID median threshold: physical hardware 100–250 cycles.
const CPUID_MEDIAN_THRESHOLD: u64 = 1000;

/// NOP ratio threshold (median / min): physical ≈ 1.0–2.0.
const NOP_RATIO_THRESHOLD: f64 = 5.0;

/// Number of HPET/secondary-clocksource cross-check iterations.
const HPET_CROSSCHECK_ITERS: usize = 50;

// ─── TSC Primitives ───────────────────────────────────────────────────────

/// Read the Time Stamp Counter via `rdtsc`.
///
/// This is non-serializing; pair with a serializing instruction (CPUID or
/// use `rdtscp()` instead) when ordering matters.
#[target_feature(enable = "sse2")]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    std::arch::asm!(
        "rdtsc",
        lateout("eax") lo,
        lateout("edx") hi,
        options(nomem, nostack)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Read the Time Stamp Counter via `rdtscp` (serializing variant).
///
/// Returns `(tsc_value, aux_msr)` where `aux_msr` typically contains the
/// current CPU / socket ID (written by the OS to `IA32_TSC_AUX`).
///
/// RDTSCP is preferred over RDTSC because it is partially serializing —
/// it waits until all previous instructions have executed before reading
/// the counter, making it harder for a hypervisor to intercept and fake.
#[target_feature(enable = "sse2")]
unsafe fn rdtscp() -> (u64, u32) {
    let lo: u32;
    let hi: u32;
    let aux: u32;
    std::arch::asm!(
        "rdtscp",
        lateout("eax") lo,
        lateout("edx") hi,
        lateout("ecx") aux,
        options(nomem, nostack)
    );
    (((hi as u64) << 32) | (lo as u64), aux)
}

/// Execute CPUID as a full serialization barrier.
///
/// CPUID is a serializing instruction: all prior instructions complete
/// before it executes, and no later instruction starts until it finishes.
/// We use leaf 0 (vendor string) which is universally supported.
#[target_feature(enable = "sse2")]
unsafe fn serialize_cpuid() {
    let _ = __cpuid(0);
}

// ─── Invariant TSC Detection ──────────────────────────────────────────────

/// Check whether the TSC is invariant (constant-frequency regardless of
/// CPU P-state).  Invariant TSC is indicated by CPUID leaf 0x80000007,
/// EDX bit 8.
///
/// On CPUs without invariant TSC, frequency scaling (turbo / energy
/// saving) can cause misleading cycle counts.  We fall back to coarse
/// timing in that case.
fn has_invariant_tsc() -> bool {
    // First check that extended CPUID leaf 0x80000007 is supported.
    let max_ext = unsafe { __cpuid(0x80000000) };
    if max_ext.eax < 0x80000007 {
        return false;
    }
    let leaf7 = unsafe { __cpuid(0x80000007) };
    // EDX bit 8 = invariant TSC.
    (leaf7.edx & (1 << 8)) != 0
}

// ─── Instruction Timing Measurement ───────────────────────────────────────

/// Statistics for a set of cycle-count measurements.
#[derive(Debug, Clone)]
pub struct InstructionTiming {
    /// Instruction label (for diagnostics).
    pub label: String,
    /// Minimum observed cycle count.
    pub min_cycles: u64,
    /// Maximum observed cycle count.
    pub max_cycles: u64,
    /// Median observed cycle count.
    pub median_cycles: u64,
    /// Mean (average) cycle count.
    pub mean_cycles: f64,
    /// Standard deviation of cycle counts.
    pub stddev_cycles: f64,
    /// Number of successful samples.
    pub samples: usize,
}

/// Measure the overhead of executing a single NOP instruction.
///
/// Uses RDTSCP (serializing) to bracket a single NOP.  The measurement
/// includes the overhead of the two RDTSCP + one CPUID serialization, so
/// we subtract the baseline (RDTSCP–CPUID–RDTSCP with no target instruction)
/// to isolate the target instruction cost.
fn measure_nop_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        // SAFETY: We are on x86_64 with SSE2 (guaranteed by target_feature).
        unsafe {
            // Baseline: RDTSCP – CPUID – RDTSCP (no target instruction)
            serialize_cpuid();
            let (t0, _) = rdtscp();
            serialize_cpuid();
            let (t1, _) = rdtscp();
            let baseline = t1.wrapping_sub(t0);

            // Measurement: RDTSCP – NOP – CPUID – RDTSCP
            serialize_cpuid();
            let (t0, _) = rdtscp();
            std::arch::asm!("nop", options(nomem, nostack));
            serialize_cpuid();
            let (t1, _) = rdtscp();
            let delta = t1.wrapping_sub(t0);

            // Subtract baseline to isolate NOP cost.
            let nop_cost = delta.saturating_sub(baseline);
            samples.push(nop_cost);
        }
    }

    compute_timing_stats("nop", &samples)
}

/// Measure the overhead of executing a `mov eax, 0` instruction.
fn measure_mov_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            serialize_cpuid();
            let (t0, _) = rdtscp();
            serialize_cpuid();
            let (t1, _) = rdtscp();
            let baseline = t1.wrapping_sub(t0);

            serialize_cpuid();
            let (t0, _) = rdtscp();
            std::arch::asm!("xor eax, eax", options(nomem, nostack, preserves_flags));
            serialize_cpuid();
            let (t1, _) = rdtscp();
            let delta = t1.wrapping_sub(t0);

            let cost = delta.saturating_sub(baseline);
            samples.push(cost);
        }
    }

    compute_timing_stats("mov(xor)", &samples)
}

/// Measure the overhead of executing a CPUID instruction.
///
/// CPUID is a known-cost instruction (~100–250 cycles on physical hardware).
/// Under single-step debugging, it will take 1000+ cycles.
fn measure_cpuid_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            // Serialize first, then measure CPUID + RDTSCP.
            serialize_cpuid();
            let (t0, _) = rdtscp();

            // Target: CPUID leaf 1 (feature flags — consistent cost).
            let _ = __cpuid(1);

            let (t1, _) = rdtscp();
            let delta = t1.wrapping_sub(t0);
            samples.push(delta);
        }
    }

    compute_timing_stats("cpuid", &samples)
}

/// Measure the overhead of executing RDTSC itself.
///
/// RDTSC takes ~20–30 cycles on physical hardware.  Under interception by
/// a hypervisor or debugger, the cost is much higher.
fn measure_rdtsc_timing(iterations: usize) -> InstructionTiming {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        unsafe {
            serialize_cpuid();
            let (t0, _) = rdtscp();

            // Target: RDTSC (non-serializing, just reads counter).
            std::arch::asm!("rdtsc", out("eax") _, out("edx") _, options(nomem, nostack));

            let (t1, _) = rdtscp();
            let delta = t1.wrapping_sub(t0);
            samples.push(delta);
        }
    }

    compute_timing_stats("rdtsc", &samples)
}

// ─── Statistical Helpers ──────────────────────────────────────────────────

/// Compute min, max, median, mean, and stddev from a slice of u64 samples.
fn compute_timing_stats(label: &str, samples: &[u64]) -> InstructionTiming {
    if samples.is_empty() {
        return InstructionTiming {
            label: label.to_string(),
            min_cycles: 0,
            max_cycles: 0,
            median_cycles: 0,
            mean_cycles: 0.0,
            stddev_cycles: 0.0,
            samples: 0,
        };
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let n = sorted.len();
    let min_cycles = sorted[0];
    let max_cycles = sorted[n - 1];
    let median_cycles = sorted[n / 2];

    let sum: u64 = sorted.iter().sum();
    let mean = sum as f64 / n as f64;

    let variance: f64 = sorted
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n as f64;
    let stddev = variance.sqrt();

    InstructionTiming {
        label: label.to_string(),
        min_cycles,
        max_cycles,
        median_cycles,
        mean_cycles: mean,
        stddev_cycles: stddev,
        samples: n,
    }
}

// ─── Timing Analysis ──────────────────────────────────────────────────────

/// Result of the instruction-granularity timing analysis.
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    /// NOP instruction timing statistics.
    pub nop: InstructionTiming,
    /// MOV (xor eax, eax) timing statistics.
    pub mov: InstructionTiming,
    /// CPUID timing statistics.
    pub cpuid: InstructionTiming,
    /// RDTSC timing statistics.
    pub rdtsc: InstructionTiming,
    /// Whether the TSC is invariant (constant frequency).
    pub invariant_tsc: bool,
    /// Number of detection criteria that fired.
    pub suspicion_signals: usize,
    /// Total suspicion score (0–4).
    pub suspicion_score: u32,
}

/// Run all instruction-granularity timing measurements and return the
/// full analysis.
///
/// Returns `None` if the TSC is not invariant (unreliable measurements on
/// CPUs with frequency scaling) or if measurements fail.
pub fn analyze_timing_distribution() -> Option<TimingAnalysis> {
    let invariant = has_invariant_tsc();
    if !invariant {
        // Non-invariant TSC: cycle counts are unreliable because the CPU
        // may change frequency during the measurement window.  Fall back
        // to the existing coarse timing check in detect_timing_anomaly().
        return None;
    }

    let nop = measure_nop_timing(MEASUREMENT_ITERATIONS);
    let mov = measure_mov_timing(MEASUREMENT_ITERATIONS);
    let cpuid = measure_cpuid_timing(MEASUREMENT_ITERATIONS);
    let rdtsc = measure_rdtsc_timing(MEASUREMENT_ITERATIONS);

    // Evaluate detection criteria.
    let mut signals = 0u32;

    // Criterion 1: min(nop) > 10
    let c1 = nop.min_cycles > NOP_MIN_THRESHOLD;
    if c1 { signals += 1; }

    // Criterion 2: stddev(nop) > 10
    let c2 = nop.stddev_cycles > NOP_STDDEV_THRESHOLD;
    if c2 { signals += 1; }

    // Criterion 3: median(cpuid) > 1000
    let c3 = cpuid.median_cycles > CPUID_MEDIAN_THRESHOLD;
    if c3 { signals += 1; }

    // Criterion 4: median(nop) / min(nop) > 5.0
    let c4 = if nop.min_cycles > 0 {
        (nop.median_cycles as f64 / nop.min_cycles as f64) > NOP_RATIO_THRESHOLD
    } else {
        false
    };
    if c4 { signals += 1; }

    Some(TimingAnalysis {
        nop,
        mov,
        cpuid,
        rdtsc,
        invariant_tsc: invariant,
        suspicion_signals: signals as usize,
        suspicion_score: signals,
    })
}

// ─── HPET / Secondary Clocksource Cross-Check ────────────────────────────

/// Read a secondary time source for cross-validation with RDTSC.
///
/// Emulators may intercept and fake RDTSC but typically do not synchronize
/// the faked values with other system clocks (HPET, QPC, clock_gettime).
/// If the two time sources diverge by > 10%, that indicates time
/// manipulation.
///
/// Returns `(rdtsc_delta, secondary_delta_nanos)` or `None` if the
/// secondary clocksource is unavailable.
fn cross_check_with_hpet() -> Option<(u64, u64)> {
    // Use a tight computational loop as the known workload.
    const WORKLOAD_ITERS: u64 = 10_000_000;

    // --- Read RDTSC and secondary clock, run workload, read both again ---

    let tsc_start = unsafe { rdtscp().0 };

    // Secondary clocksource: use std::time::Instant which maps to:
    //   - Windows: QueryPerformanceCounter
    //   - Linux: clock_gettime(CLOCK_MONOTONIC)
    //   - macOS: mach_absolute_time
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
    let tsc_end = unsafe { rdtscp().0 };

    let tsc_delta = tsc_end.wrapping_sub(tsc_start);
    let sec_nanos = sec_elapsed.as_nanos() as u64;

    if sec_nanos == 0 || tsc_delta == 0 {
        return None;
    }

    Some((tsc_delta, sec_nanos))
}

/// Run the HPET cross-check multiple times and look for divergence between
/// RDTSC and the secondary clocksource.
///
/// Returns `true` if the RDTSC/secondary ratio diverges by > 10% across
/// iterations, indicating likely time manipulation.
fn hpet_cross_check_flagged() -> bool {
    let mut ratios: Vec<f64> = Vec::with_capacity(HPET_CROSSCHECK_ITERS);

    for _ in 0..HPET_CROSSCHECK_ITERS {
        if let Some((tsc_delta, sec_nanos)) = cross_check_with_hpet() {
            // Approximate TSC frequency from the first measurement:
            // ratio = tsc_cycles / nanoseconds.  On subsequent iterations
            // the ratio should be stable if both clocks are honest.
            let ratio = tsc_delta as f64 / sec_nanos as f64;
            ratios.push(ratio);
        }
    }

    if ratios.len() < 10 {
        // Not enough samples — cannot reliably cross-check.
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

// ─── Integration with env_check Scoring Pipeline ──────────────────────────

/// Produce a `SandboxIndicator` from the instruction-granularity timing
/// analysis, if available.
///
/// This is called from `collect_indicators()` in `env_check.rs`.
///
/// Weight assignment:
/// - 4 criteria positive: weight 30 (high confidence — single-step detected)
/// - 2–3 criteria positive: weight 20 (medium confidence)
/// - 0–1 criteria positive: weight 0 (likely physical hardware)
pub fn instruction_timing_indicator() -> Option<common::SandboxIndicator> {
    let analysis = analyze_timing_distribution()?;

    let weight = if analysis.suspicion_score >= 4 {
        30
    } else if analysis.suspicion_score >= 2 {
        20
    } else {
        0
    };

    // Also run HPET cross-check as an additional signal.
    let hpet_flag = hpet_cross_check_flagged();
    let hpet_note = if hpet_flag {
        " [HPET_MISMATCH]"
    } else {
        ""
    };

    // Boost weight if HPET cross-check also flagged.
    let final_weight = if hpet_flag && weight > 0 {
        weight + 10
    } else if hpet_flag && weight == 0 {
        10 // HPET alone is a mild signal
    } else {
        weight
    };

    let detail = format!(
        "RDTSC timing: nop=[min={},med={},σ={:.1}] cpuid=[med={}] rdtsc=[med={:.0}] signals={}/4{}{}",
        analysis.nop.min_cycles,
        analysis.nop.median_cycles,
        analysis.nop.stddev_cycles,
        analysis.cpuid.median_cycles,
        analysis.rdtsc.mean_cycles,
        analysis.suspicion_signals,
        hpet_note,
        if !analysis.invariant_tsc { " [non-invariant-tsc]" } else { "" },
    );

    Some(common::SandboxIndicator {
        category: "timing".to_string(),
        detail,
        weight: final_weight,
        source: "rdtsc_instruction".to_string(),
    })
}

// ─── Public Helpers ───────────────────────────────────────────────────────

/// Check whether instruction-granularity timing analysis is available
/// on this platform.
pub fn is_available() -> bool {
    has_invariant_tsc()
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_tsc_detection() {
        // Just verify it doesn't panic — actual result depends on host CPU.
        let result = has_invariant_tsc();
        // All modern x86_64 CPUs (Intel since Nehalem, AMD since Zen) have
        // invariant TSC, so this should be true on any reasonable test host.
        assert!(
            result,
            "Expected invariant TSC on this host — is this a very old CPU?"
        );
    }

    #[test]
    fn test_rdtsc_read() {
        // Verify RDTSC returns monotonically increasing values.
        let t0 = unsafe { rdtscp().0 };
        let t1 = unsafe { rdtscp().0 };
        assert!(t1 >= t0, "TSC should be monotonically increasing: t0={t0}, t1={t1}");
    }

    #[test]
    fn test_nop_timing_physical_baseline() {
        if !has_invariant_tsc() {
            return; // Skip on non-invariant TSC.
        }
        let timing = measure_nop_timing(MEASUREMENT_ITERATIONS);
        // On physical hardware, NOP should be very cheap.
        assert!(
            timing.min_cycles < 50,
            "NOP min_cycles unexpectedly high: {} — possible instrumentation",
            timing.min_cycles
        );
        assert!(
            timing.stddev_cycles < 50.0,
            "NOP stddev unexpectedly high: {:.1} — possible instrumentation",
            timing.stddev_cycles
        );
    }

    #[test]
    fn test_cpuid_timing_physical_baseline() {
        if !has_invariant_tsc() {
            return;
        }
        let timing = measure_cpuid_timing(MEASUREMENT_ITERATIONS);
        // CPUID on physical hardware should be 50–500 cycles.
        assert!(
            timing.median_cycles < 1000,
            "CPUID median unexpectedly high: {} — possible instrumentation",
            timing.median_cycles
        );
    }

    #[test]
    fn test_compute_timing_stats_empty() {
        let stats = compute_timing_stats("empty", &[]);
        assert_eq!(stats.min_cycles, 0);
        assert_eq!(stats.max_cycles, 0);
        assert_eq!(stats.median_cycles, 0);
        assert_eq!(stats.mean_cycles, 0.0);
        assert_eq!(stats.stddev_cycles, 0.0);
        assert_eq!(stats.samples, 0);
    }

    #[test]
    fn test_compute_timing_stats_single() {
        let stats = compute_timing_stats("single", &[42u64]);
        assert_eq!(stats.min_cycles, 42);
        assert_eq!(stats.max_cycles, 42);
        assert_eq!(stats.median_cycles, 42);
        assert_eq!(stats.mean_cycles, 42.0);
        assert_eq!(stats.stddev_cycles, 0.0);
    }

    #[test]
    fn test_compute_timing_stats_sorted() {
        let values: Vec<u64> = vec![1, 2, 3, 4, 5];
        let stats = compute_timing_stats("test", &values);
        assert_eq!(stats.min_cycles, 1);
        assert_eq!(stats.max_cycles, 5);
        assert_eq!(stats.median_cycles, 3); // sorted[2]
        assert_eq!(stats.mean_cycles, 3.0);
    }

    #[test]
    fn test_compute_timing_stats_even_count() {
        let values: Vec<u64> = vec![10, 20, 30, 40];
        let stats = compute_timing_stats("test", &values);
        assert_eq!(stats.median_cycles, 30); // sorted[4/2] = sorted[2] = 30
    }

    #[test]
    fn test_suspicion_criteria_physical() {
        if !has_invariant_tsc() {
            return;
        }
        let analysis = analyze_timing_distribution().expect("analysis should succeed with invariant TSC");
        // On physical hardware, 0–1 criteria should fire.
        assert!(
            analysis.suspicion_score <= 1,
            "Physical hardware should not trigger many suspicion criteria, got {}",
            analysis.suspicion_score
        );
    }

    #[test]
    fn test_analyze_timing_returns_some_with_invariant_tsc() {
        if !has_invariant_tsc() {
            return;
        }
        let result = analyze_timing_distribution();
        assert!(result.is_some(), "Should return Some with invariant TSC");
    }

    #[test]
    fn test_hpet_cross_check_runs() {
        // Just verify the cross-check doesn't panic.
        let _flagged = hpet_cross_check_flagged();
    }

    #[test]
    fn test_instruction_timing_indicator_runs() {
        // Verify the full pipeline runs and produces an indicator.
        let indicator = instruction_timing_indicator();
        // May be None if no invariant TSC.
        if has_invariant_tsc() {
            assert!(indicator.is_some(), "Should produce indicator with invariant TSC");
            let ind = indicator.unwrap();
            assert_eq!(ind.category, "timing");
            assert_eq!(ind.source, "rdtsc_instruction");
            assert!(ind.detail.contains("nop="));
        }
    }

    #[test]
    fn test_detection_thresholds_sanity() {
        // Verify the thresholds are internally consistent.
        assert!(NOP_MIN_THRESHOLD < CPUID_MEDIAN_THRESHOLD);
        assert!(NOP_STDDEV_THRESHOLD > 0.0);
        assert!(NOP_RATIO_THRESHOLD > 1.0);
    }
}
