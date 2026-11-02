//! One realtime send timeline shared by several receivers (the sender's half of multi-room),
//! sans-io.
//!
//! Frame `k` carries RTP timestamp `rtp_base + k` and is stamped as sent at `origin + k / rate`
//! in every member's session, so every member's sync packets describe the same line. NTP time is
//! era-safe ([`NtpTimestamp`]), so it crosses the 2036 boundary cleanly. Pacing sends against a
//! local clock is the embedding application's job.

use super::rtp::SyncPacket;
use crate::time::{NtpTimestamp, RtpTimestamp};

/// A shared realtime send timeline. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendTimeline {
    origin: NtpTimestamp,
    rtp_base: RtpTimestamp,
    sample_rate: u32,
}

impl SendTimeline {
    /// A timeline whose frame 0 is sent at NTP time `origin` with RTP timestamp `rtp_base`, at
    /// `sample_rate` frames a second (a zero rate is taken as 1).
    #[must_use]
    pub fn new(origin: NtpTimestamp, rtp_base: RtpTimestamp, sample_rate: u32) -> Self {
        Self {
            origin,
            rtp_base,
            sample_rate: sample_rate.max(1),
        }
    }

    /// Frame 0's NTP time.
    #[must_use]
    pub fn origin(&self) -> NtpTimestamp {
        self.origin
    }

    /// Frame 0's RTP timestamp.
    #[must_use]
    pub fn rtp_base(&self) -> RtpTimestamp {
        self.rtp_base
    }

    /// Frames a second.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Frame `frame`'s RTP timestamp: `rtp_base + frame`, wrapping at 2^32 as RTP does.
    #[must_use]
    pub fn rtp_of(&self, frame: u64) -> RtpTimestamp {
        // Truncation intended: the RTP timestamp is the frame count modulo 2^32.
        #[allow(clippy::cast_possible_truncation)]
        self.rtp_base.wrapping_add(frame as u32)
    }

    /// The NTP time frame `frame` is sent at: `origin + frame / rate`, rounded to the nearest
    /// 2^-32 s, with wrapping arithmetic.
    #[must_use]
    pub fn ntp_of(&self, frame: u64) -> NtpTimestamp {
        let rate = u128::from(self.sample_rate);
        let units = ((u128::from(frame) << 33) + rate) / (2 * rate);
        // Truncation and the sign bit intended: the NTP timestamp wraps with its era.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let units = units as u64 as i64;
        self.origin.wrapping_add_units(units)
    }

    /// The frame being sent at NTP time `at`, rounded to the nearest frame (the inverse of
    /// [`Self::ntp_of`]); negative before the origin. Correct across an era boundary within 68
    /// years of the origin.
    #[must_use]
    pub fn frame_at(&self, at: NtpTimestamp) -> i64 {
        let units = at.units_since(self.origin);
        let frames =
            (i128::from(units) * i128::from(self.sample_rate) + (1 << 31)).div_euclid(1 << 32);
        // |units| < 2^63 and rate < 2^32, so frames fits in i64.
        #[allow(clippy::cast_possible_truncation)]
        let frames = frames as i64;
        frames
    }

    /// The sync packet a member sends before the packet whose first frame is `frame`: that
    /// frame's RTP timestamp as `now`, its send time as the NTP time, and `now - latency_frames`
    /// as the frame playing then. Every member sends the same bytes for a frame, except `first`.
    #[must_use]
    pub fn sync_packet(&self, first: bool, frame: u64, latency_frames: u32) -> SyncPacket {
        let now = self.rtp_of(frame);
        SyncPacket::new(
            first,
            now.wrapping_sub(latency_frames),
            self.ntp_of(frame),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::ClockTracker;
    use std::time::Duration;

    fn ntp(seconds: u32, fraction: u32) -> NtpTimestamp {
        NtpTimestamp::from_parts(seconds, fraction)
    }

    fn rtp(value: u32) -> RtpTimestamp {
        RtpTimestamp::new(value)
    }

    #[test]
    fn frames_map_to_rtp_and_ntp_on_one_line() {
        let timeline = SendTimeline::new(ntp(1_000, 0), rtp(5_000), 44_100);
        assert_eq!(timeline.rtp_of(0), rtp(5_000));
        assert_eq!(timeline.rtp_of(352), rtp(5_352));
        assert_eq!(timeline.ntp_of(0), ntp(1_000, 0));
        assert_eq!(timeline.ntp_of(44_100), ntp(1_001, 0));
        assert_eq!(timeline.ntp_of(22_050), ntp(1_000, 0x8000_0000));
        // One frame is 97 391.54... units, rounded to nearest as `ClockTracker::schedule` does.
        assert_eq!(timeline.ntp_of(1), ntp(1_000, 97_392));
        assert_eq!(timeline.frame_at(ntp(1_001, 0)), 44_100);
        assert_eq!(timeline.frame_at(ntp(999, 0)), -44_100);
        assert_eq!(timeline.frame_at(timeline.ntp_of(12_345)), 12_345);
    }

    #[test]
    fn the_rtp_timestamp_wraps_and_the_ntp_time_crosses_the_2036_era() {
        // Frame 0 ten seconds before era 0 ends; the RTP base a frame before its own wrap.
        let timeline = SendTimeline::new(ntp(u32::MAX - 9, 0), rtp(u32::MAX), 8_000);
        assert_eq!(timeline.rtp_of(1), rtp(0));
        // RFC 5905 Figure 4: 8 February 2036 is era 1, offset 63,104, 63,114 s after this origin.
        assert_eq!(timeline.ntp_of(63_114 * 8_000), ntp(63_104, 0));
        assert_eq!(timeline.frame_at(ntp(63_104, 0)), 63_114 * 8_000);
        // Past 2^32 frames the RTP timestamp has wrapped and the NTP time keeps counting.
        let far = (1u64 << 32) + 7;
        assert_eq!(timeline.rtp_of(far), rtp(6));
        assert!(
            (timeline.ntp_of(far).secs_f64_since(timeline.origin()) - far as f64 / 8_000.0).abs()
                < 1e-6
        );
    }

    /// The headline claim: a receiver that reads either member's sync packet schedules every frame
    /// at the same sender-clock instant, whichever member it came from and wherever along the
    /// timeline that member joined.
    #[test]
    fn two_members_sync_packets_schedule_every_frame_identically() {
        let timeline = SendTimeline::new(ntp(3_900_000_000, 0x1234_5678), rtp(0xFFFF_0000), 44_100);
        let latency = 66_150;
        let mut early = ClockTracker::new(44_100);
        let mut late = ClockTracker::new(44_100);
        // One member has sent since frame 0; the other joined three seconds in.
        early.observe(&timeline.sync_packet(true, 0, latency), Duration::ZERO);
        early.observe(
            &timeline.sync_packet(false, 4 * 44_100, latency),
            Duration::from_secs(4),
        );
        late.observe(
            &timeline.sync_packet(true, 3 * 44_100 + 352, latency),
            Duration::ZERO,
        );
        for frame in [0u64, 100, 44_100 * 5 + 17, 1 << 20] {
            let rtp = timeline.rtp_of(frame);
            assert_eq!(early.schedule(rtp), late.schedule(rtp), "frame {frame}");
            assert_eq!(
                early.schedule(rtp),
                Some(timeline.ntp_of(frame)),
                "frame {frame}"
            );
            assert_eq!(early.latency_frames(), Some(latency));
        }
    }

    #[test]
    fn a_sync_packet_says_the_frame_minus_the_latency_plays_at_its_send_time() {
        let timeline = SendTimeline::new(ntp(2_000, 0), rtp(10), 44_100);
        let sync = timeline.sync_packet(true, 44_100, 66_150);
        assert!(sync.first);
        assert_eq!(sync.now, rtp(44_110));
        assert_eq!(
            sync.now_without_latency,
            rtp(10u32.wrapping_add(44_100).wrapping_sub(66_150))
        );
        assert_eq!(sync.ntp, ntp(2_001, 0));
    }

    #[test]
    fn a_zero_rate_is_one_frame_a_second_not_a_division_by_zero() {
        let timeline = SendTimeline::new(ntp(5, 0), rtp(0), 0);
        assert_eq!(timeline.sample_rate(), 1);
        assert_eq!(timeline.ntp_of(3), ntp(8, 0));
        assert_eq!(timeline.frame_at(ntp(8, 0)), 3);
    }

    #[test]
    fn arbitrary_inputs_never_panic() {
        let mut seed = 0x71AE_11AEu64;
        let mut next = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            seed
        };
        for rate in [0u32, 1, 44_100, 48_000, u32::MAX] {
            for _ in 0..200 {
                let timeline = SendTimeline::new(
                    NtpTimestamp::from_bits(next()),
                    rtp((next() >> 32) as u32),
                    rate,
                );
                let frame = next();
                let _ = timeline.rtp_of(frame);
                let _ = timeline.ntp_of(frame);
                let _ = timeline.frame_at(NtpTimestamp::from_bits(next()));
                let _ = timeline.sync_packet(frame % 2 == 0, frame, (next() >> 32) as u32);
            }
        }
    }
}
