//! Clock tracking for a realtime receiver, sans-io: inputs are parsed sync packets plus the
//! caller's monotonic now; outputs are numbers the host acts on.
//!
//! - Drift ([`ClockTracker::drift`]): a line fit of RTP samples against local seconds, reported as
//!   a [`DriftEstimate`] (ppm and a resample ratio), clamped to [`MAX_DRIFT_PPM`].
//! - Timeline ([`ClockTracker::schedule`], [`ClockTracker::seconds_until`]): the sender-clock NTP
//!   instant an RTP timestamp plays, as an era-safe [`NtpTimestamp`];
//!   [`super::playout::PlayoutScheduler`] plays to it.
//!
//! Drift is [`DriftEstimate::UNSLAVED`] until two sync packets are seen; the schedule is [`None`]
//! until one.
//!
//! The elapsed RTP count is cumulative, so a deliberate RTP jump (a `FLUSH` to a new timeline, a
//! stream restart) steps the fit window: the host makes a fresh tracker, or calls
//! [`ClockTracker::reset`], then.

use std::time::Duration;

use crate::audio::rtp::SyncPacket;
use crate::time::{NtpTimestamp, RtpTimestamp};

/// The bound a fitted drift is clamped to, so a bad sync stream cannot swing the resample ratio
/// audibly.
pub const MAX_DRIFT_PPM: f64 = 1000.0;

/// How many recent sync packets [`ClockTracker`] fits (about a minute at one per second).
pub const WINDOW: usize = 64;

/// What [`ClockTracker::drift`] reports.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct DriftEstimate {
    /// Parts per million the sender's clock runs fast (positive) or slow, clamped to
    /// +/-[`MAX_DRIFT_PPM`].
    pub ppm: f64,
    /// Output frames per input frame for a resampler: `1.0 / (1.0 + ppm / 1e6)`; 1.0 means no
    /// correction.
    pub resample_ratio: f64,
    /// Sync packets the estimate is built from (capped at [`WINDOW`]); two or three is noisy.
    pub samples: usize,
}

impl DriftEstimate {
    /// No estimate yet: no correction, reported as built from zero samples.
    pub const UNSLAVED: Self = Self {
        ppm: 0.0,
        resample_ratio: 1.0,
        samples: 0,
    };
}

/// One sync-packet observation for the drift fit.
#[derive(Debug, Clone, Copy)]
struct Point {
    /// Seconds on the receiver's own clock since the tracker's first sample.
    local_seconds: f64,
    /// Signed RTP samples elapsed since the first sample.
    rtp_elapsed: f64,
}

/// Fits drift and a shared timeline from a realtime stream's sync packets. See the module docs.
///
/// One tracker per stream.
#[derive(Debug, Clone)]
pub struct ClockTracker {
    format_sample_rate: u32,
    /// The previous sync packet's RTP time, for the unwrapped elapsed count.
    previous_rtp: Option<RtpTimestamp>,
    /// Signed RTP samples since the first sync packet, accumulated step by step so it does not
    /// wrap at 2^31 frames.
    rtp_elapsed: f64,
    first_local: Option<Duration>,
    points: Vec<Point>,
    /// The most recent sync packet's RTP time and the sender's NTP timestamp at it, as sent.
    last_sync: Option<(RtpTimestamp, NtpTimestamp)>,
    /// The most recent sync packet's latency: `now - now_without_latency`, in frames.
    latency_frames: Option<u32>,
    /// The most recent sync packet's flags word.
    flags: Option<u16>,
}

impl Default for ClockTracker {
    /// `ClockTracker::new(0)`: a zero rate is taken as one frame per second.
    fn default() -> Self {
        Self::new(0)
    }
}

impl ClockTracker {
    /// A tracker for a stream sampled at `sample_rate`.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        Self {
            format_sample_rate: sample_rate.max(1),
            previous_rtp: None,
            rtp_elapsed: 0.0,
            first_local: None,
            points: Vec::with_capacity(WINDOW),
            last_sync: None,
            latency_frames: None,
            flags: None,
        }
    }

    /// Forgets every observation, as a fresh tracker for the same sample rate.
    pub fn reset(&mut self) {
        *self = Self::new(self.format_sample_rate);
    }

    /// Records one sync packet (`0xD4`) received at `now` on the caller's monotonic clock.
    pub fn observe(&mut self, sync: &SyncPacket, now: Duration) {
        if let Some(previous) = self.previous_rtp {
            self.rtp_elapsed += f64::from(sync.now.signed_frames_since(previous));
        }
        self.previous_rtp = Some(sync.now);
        let first_local = *self.first_local.get_or_insert(now);
        self.points.push(Point {
            local_seconds: now.as_secs_f64() - first_local.as_secs_f64(),
            rtp_elapsed: self.rtp_elapsed,
        });
        self.last_sync = Some((sync.now, sync.ntp));
        self.latency_frames = Some(sync.now.frames_since(sync.now_without_latency));
        self.flags = Some(sync.flags);
        if self.points.len() > WINDOW {
            self.points.remove(0);
        }
    }

    /// How many sync packets are held.
    #[must_use]
    pub fn samples(&self) -> usize {
        self.points.len()
    }

    /// The fitted drift, or [`DriftEstimate::UNSLAVED`] with under two packets or no spread in
    /// time.
    #[must_use]
    pub fn drift(&self) -> DriftEstimate {
        let Some((slope, n)) = self.fit_samples_per_second() else {
            return DriftEstimate::UNSLAVED;
        };
        let nominal = f64::from(self.format_sample_rate);
        if !slope.is_finite() || nominal <= 0.0 {
            return DriftEstimate::UNSLAVED;
        }
        let raw_ppm = (slope - nominal) / nominal * 1e6;
        let ppm = raw_ppm.clamp(-MAX_DRIFT_PPM, MAX_DRIFT_PPM);
        let resample_ratio = (1.0 / (1.0 + ppm / 1e6)).clamp(0.9, 1.1);
        DriftEstimate {
            ppm,
            resample_ratio,
            samples: n,
        }
    }

    /// Least-squares samples per local second; `None` if degenerate.
    fn fit_samples_per_second(&self) -> Option<(f64, usize)> {
        let n = self.points.len();
        if n < 2 {
            return None;
        }
        let count = n as f64;
        let sum_x: f64 = self.points.iter().map(|p| p.local_seconds).sum();
        let sum_y: f64 = self.points.iter().map(|p| p.rtp_elapsed).sum();
        let sum_xx: f64 = self.points.iter().map(|p| p.local_seconds.powi(2)).sum();
        let sum_xy: f64 = self
            .points
            .iter()
            .map(|p| p.local_seconds * p.rtp_elapsed)
            .sum();
        let denom = (count * sum_xx) - (sum_x * sum_x);
        if denom.abs() < f64::EPSILON {
            return None;
        }
        let slope = ((count * sum_xy) - (sum_x * sum_y)) / denom;
        Some((slope, n))
    }

    /// The sender-clock NTP instant at which RTP timestamp `rtp` plays, extrapolated from the
    /// latest sync packet at the nominal rate. Wraps across the 2036 era; `rtp` is read as the
    /// nearest turn of the 32-bit wheel (exact within 2^31 frames). `None` before any sync packet
    /// has been observed.
    #[must_use]
    pub fn schedule(&self, rtp: RtpTimestamp) -> Option<NtpTimestamp> {
        let (sync_rtp, sync_ntp) = self.last_sync?;
        let frames = i128::from(rtp.signed_frames_since(sync_rtp));
        let rate = i128::from(self.format_sample_rate.max(1));
        // Frames to 2^-32 s units, rounded; fits i64.
        let units = ((frames << 33) + rate).div_euclid(2 * rate);
        #[allow(clippy::cast_possible_truncation)]
        let units = units as i64;
        Some(sync_ntp.wrapping_add_units(units))
    }

    /// The latest sync packet's declared latency in frames (`now - now_without_latency`, wrapping):
    /// a frame plays that long after its [`Self::schedule`] instant. The sender's value, unbounded
    /// here; the caller clamps it. `None` before any sync packet.
    #[must_use]
    pub fn latency_frames(&self) -> Option<u32> {
        self.latency_frames
    }

    /// The latest sync packet's flags word, `None` before one.
    #[must_use]
    pub fn sync_flags(&self) -> Option<u16> {
        self.flags
    }

    /// Seconds from `now` (the sender's clock) until `rtp` plays, negative if past; era-safe.
    /// `None` before any sync packet.
    #[must_use]
    pub fn seconds_until(&self, rtp: RtpTimestamp, now: NtpTimestamp) -> Option<f64> {
        self.schedule(rtp).map(|at| at.secs_f64_since(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntp(seconds: u32, fraction: u32) -> NtpTimestamp {
        NtpTimestamp::from_parts(seconds, fraction)
    }

    fn rtp(value: u32) -> RtpTimestamp {
        RtpTimestamp::new(value)
    }

    fn secs(seconds: f64) -> Duration {
        Duration::from_secs_f64(seconds)
    }

    fn sync(rtp_now: u32, ntp: NtpTimestamp) -> SyncPacket {
        SyncPacket::new(false, rtp(rtp_now), ntp, rtp(rtp_now))
    }

    fn sync_at(rtp_now: u32, ntp_seconds: f64) -> SyncPacket {
        sync(
            rtp_now,
            NtpTimestamp::ZERO.wrapping_add_secs_f64(ntp_seconds),
        )
    }

    #[test]
    fn the_drift_fit_survives_the_rtp_elapsed_count_passing_two_to_the_31_and_32_frames() {
        const FRAMES_PER_SYNC: u32 = 10_000_000;
        const TRUE_PPM: f64 = 50.0;
        let mut tracker = ClockTracker::new(44_100);
        // The sender's clock runs TRUE_PPM fast: more frames per local second than nominal.
        let local_per_sync = f64::from(FRAMES_PER_SYNC) / (44_100.0 * (1.0 + TRUE_PPM / 1e6));
        let mut rtp_now = 0u32;
        let mut checked = 0;
        for i in 0..1_000u32 {
            tracker.observe(
                &sync(rtp_now, ntp(1_000, 0)),
                secs(f64::from(i) * local_per_sync),
            );
            rtp_now = rtp_now.wrapping_add(FRAMES_PER_SYNC);
            if tracker.samples() >= 3 {
                let ppm = tracker.drift().ppm;
                assert!((ppm - TRUE_PPM).abs() < 1.0, "sync {i}: {ppm} ppm");
                checked += 1;
            }
        }
        // 1000 syncs span 10^10 frames: past 2^31 and 2^32, and a wrap of the 32-bit timestamp.
        assert!(1_000 * u64::from(FRAMES_PER_SYNC) > 2 * (1u64 << 32));
        assert_eq!(checked, 998);
    }

    #[test]
    fn a_frame_is_scheduled_at_the_sync_packets_timestamp_plus_its_frames_at_the_nominal_rate() {
        let mut tracker = ClockTracker::new(44_100);
        let at = 5_000_000;
        tracker.observe(&sync(at, ntp(1_000, 0)), Duration::ZERO);
        assert_eq!(tracker.schedule(rtp(at)), Some(ntp(1_000, 0)));
        assert_eq!(tracker.schedule(rtp(at + 44_100)), Some(ntp(1_001, 0)));
        assert_eq!(
            tracker.schedule(rtp(at + 22_050)),
            Some(ntp(1_000, 0x8000_0000))
        );
        assert_eq!(
            tracker.schedule(rtp(at - 11_025)),
            Some(ntp(999, 0xC000_0000))
        );
        assert_eq!(tracker.schedule(rtp(at + 1)), Some(ntp(1_000, 97_392)));
        assert_eq!(
            tracker.schedule(rtp(at - 1)),
            Some(ntp(999, 0xFFFF_FFFF - 97_391))
        );
        assert_eq!(
            tracker.seconds_until(rtp(at + 66_150), ntp(1_000, 0)),
            Some(1.5)
        );
        assert_eq!(tracker.seconds_until(rtp(at), ntp(1_002, 0)), Some(-2.0));
    }

    #[test]
    fn the_declared_latency_is_now_minus_now_without_latency_wrapping() {
        let mut tracker = ClockTracker::new(44_100);
        assert_eq!(tracker.latency_frames(), None);
        tracker.observe(
            &SyncPacket::new(false, rtp(1_000), ntp(1, 0), rtp(67_150)),
            Duration::ZERO,
        );
        assert_eq!(tracker.latency_frames(), Some(66_150));
        tracker.observe(
            &SyncPacket::new(false, rtp(u32::MAX - 99), ntp(2, 0), rtp(100)),
            secs(1.0),
        );
        assert_eq!(tracker.latency_frames(), Some(200), "across the RTP wrap");
    }

    #[test]
    fn the_rtp_wrap_between_the_sync_packet_and_the_frame_is_one_turn_of_the_wheel() {
        let mut tracker = ClockTracker::new(48_000);
        let at = u32::MAX - 23_999; // half a second of frames before the RTP clock wraps
        tracker.observe(&sync(at, ntp(7, 0)), Duration::ZERO);
        assert_eq!(
            tracker.schedule(rtp(24_000)),
            Some(ntp(8, 0)),
            "one second later"
        );
        assert_eq!(
            tracker.schedule(rtp(at).wrapping_sub(48_000)),
            Some(ntp(6, 0))
        );
    }

    /// RFC 5905 §6: era 0 ends 2036-02-07 06:28:16 UTC; 8 Feb 00:00 UTC is era 1 offset 63,104.
    #[test]
    fn a_frame_scheduled_across_the_2036_era_wrap_lands_on_era_1s_published_timestamp() {
        const ERA_1_OFFSET_OF_8_FEB_2036: u32 = 63_104;
        let rate = 8_000; // low enough that 63,114 s of frames is inside the 2^31 extension range
        let mut tracker = ClockTracker::new(rate);
        let sent_at = ntp(u32::MAX - 9, 0); // 2036-02-07 06:28:06 UTC, era 0
        let at = 1_234;
        tracker.observe(&sync(at, sent_at), Duration::ZERO);
        let frame = rtp(at + 63_114 * rate);
        assert_eq!(
            tracker.schedule(frame),
            Some(ntp(ERA_1_OFFSET_OF_8_FEB_2036, 0))
        );
        assert_eq!(tracker.seconds_until(frame, sent_at), Some(63_114.0));
        assert_eq!(tracker.seconds_until(frame, ntp(63_000, 0)), Some(104.0));
        let mut after = ClockTracker::new(44_100);
        after.observe(&sync(at, ntp(0, 0x4000_0000)), Duration::ZERO);
        assert_eq!(
            after.schedule(rtp(at).wrapping_sub(44_100)),
            Some(ntp(u32::MAX, 0x4000_0000))
        );
        assert_eq!(
            after.seconds_until(rtp(at), ntp(u32::MAX, 0x8000_0000)),
            Some(0.75)
        );
    }

    #[test]
    fn late_in_the_era_the_schedule_keeps_every_bit_of_the_fraction() {
        let mut tracker = ClockTracker::new(44_100);
        let sent_at = ntp(0xF000_0000, 0x0000_0041);
        tracker.observe(&sync(9, sent_at), Duration::ZERO);
        assert_eq!(tracker.schedule(rtp(9)), Some(sent_at));
        assert_eq!(
            tracker.seconds_until(rtp(9), ntp(0xF000_0000, 0x0000_0001)),
            Some(f64::from(0x40u32) / 4_294_967_296.0)
        );
    }

    #[test]
    fn a_default_tracker_schedules_without_dividing_by_zero() {
        let mut tracker = ClockTracker::default();
        assert_eq!(tracker.schedule(rtp(5)), None);
        tracker.observe(&sync(5, ntp(10, 0)), Duration::ZERO);
        assert_eq!(
            tracker.schedule(rtp(7)),
            Some(ntp(12, 0)),
            "one frame per second"
        );
        assert_eq!(tracker.seconds_until(rtp(7), ntp(10, 0)), Some(2.0));
        assert_eq!(tracker.drift(), DriftEstimate::UNSLAVED);
    }

    #[test]
    fn fewer_than_two_sync_packets_reports_unslaved() {
        let mut tracker = ClockTracker::new(44_100);
        assert_eq!(tracker.drift(), DriftEstimate::UNSLAVED);
        tracker.observe(&sync_at(0, 1000.0), Duration::ZERO);
        assert_eq!(tracker.drift(), DriftEstimate::UNSLAVED);
        assert!(
            tracker.schedule(rtp(0)).is_some(),
            "one sync is enough to schedule, just not to fit drift"
        );
    }

    /// A steadily fast or slow sender clock over a simulated hour is recovered within a tight
    /// bound.
    #[test]
    fn a_sender_running_200_ppm_fast_or_slow_is_recovered_within_5_ppm_over_a_simulated_hour() {
        for true_ppm in [200.0, -200.0, 0.0] {
            let sample_rate = 44_100u32;
            let mut tracker = ClockTracker::new(sample_rate);
            let true_rate = f64::from(sample_rate) * (1.0 + true_ppm / 1e6);
            let mut at: u32 = 1_000_000; // an arbitrary non-zero start, exercising the offset math
            for second in 0..3600u32 {
                let local_seconds = f64::from(second);
                // The sender's NTP clock is exact here; only its sample clock drifts.
                let sender_ntp = 1_700_000_000.0 + local_seconds;
                tracker.observe(&sync_at(at, sender_ntp), secs(local_seconds));
                at = at.wrapping_add(true_rate.round() as u32);
            }
            let estimate = tracker.drift();
            assert!(
                (estimate.ppm - true_ppm).abs() < 5.0,
                "true {true_ppm} ppm, estimated {} ppm",
                estimate.ppm
            );
            let expected_ratio = 1.0 / (1.0 + true_ppm / 1e6);
            assert!(
                (estimate.resample_ratio - expected_ratio).abs() < 1e-4,
                "true ratio {expected_ratio}, estimated {}",
                estimate.resample_ratio
            );
            assert_eq!(
                estimate.samples, WINDOW,
                "only the most recent window is kept"
            );
        }
    }

    #[test]
    fn drift_beyond_the_clamp_is_bounded_not_unbounded() {
        let mut tracker = ClockTracker::new(44_100);
        let mut at: u32 = 0;
        // 5% fast stands in for a corrupted sync stream.
        for second in 0..10u32 {
            tracker.observe(
                &sync_at(at, 1_700_000_000.0 + f64::from(second)),
                secs(f64::from(second)),
            );
            at = at.wrapping_add((44_100.0 * 1.05) as u32);
        }
        let estimate = tracker.drift();
        assert_eq!(estimate.ppm, MAX_DRIFT_PPM);
        assert!(estimate.resample_ratio >= 0.9 && estimate.resample_ratio <= 1.1);
    }

    /// Two trackers fed the same sync packets compute the same schedule.
    #[test]
    fn two_trackers_fed_the_same_sync_packets_schedule_the_same_frame_identically() {
        let mut a = ClockTracker::new(44_100);
        let mut b = ClockTracker::new(44_100);
        let mut at: u32 = 500;
        for second in 0..10u32 {
            let packet = sync_at(at, 1_700_000_100.0 + f64::from(second));
            a.observe(&packet, secs(f64::from(second)));
            b.observe(&packet, secs(f64::from(second) + 0.5)); // each receiver's own clock
            at = at.wrapping_add(44_100);
        }
        let target = rtp(at.wrapping_add(22_050)); // half a second past the last sync
        let (sa, sb) = (a.schedule(target), b.schedule(target));
        assert!(sa.is_some());
        assert_eq!(
            sa, sb,
            "both receivers computed the sender's own clock, not their local one"
        );
    }

    /// Never panics on arbitrary sync-packet fields, clock readings or RTP wraparound.
    #[test]
    fn arbitrary_inputs_never_panic() {
        let mut seed = 0xC10C_5EEDu64;
        let mut next = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            seed
        };
        for sample_rate in [
            None,
            Some(0u32),
            Some(1),
            Some(44_100),
            Some(48_000),
            Some(u32::MAX),
        ] {
            let mut tracker = sample_rate.map_or_else(ClockTracker::default, ClockTracker::new);
            for _ in 0..200 {
                let now = rtp((next() >> 32) as u32);
                let sent = NtpTimestamp::from_bits(next());
                let local_bits = next();
                let local = if local_bits % 7 == 0 {
                    Duration::MAX
                } else {
                    Duration::from_nanos(local_bits)
                };
                tracker.observe(&SyncPacket::new(local_bits % 2 == 0, now, sent, now), local);
                let _ = tracker.drift();
                let _ = tracker.latency_frames();
                let frame = rtp((next() >> 32) as u32);
                let _ = tracker.schedule(frame);
                let _ = tracker.seconds_until(frame, NtpTimestamp::from_bits(next()));
            }
        }
    }
}
