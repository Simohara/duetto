//! RAOP timing copied from pyatv 0.18.0 StreamContext, ControlClient and
//! StreamClient. The sample head is an absolute NTP-derived counter; RTP is
//! relative to the stream start, with the receiver's configured latency added.
use cidermill_airplay::{NtpTimestamp, RtpTimestamp, audio::rtp::SyncPacket};
use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

pub const RATE: u32 = 44_100;
pub const PACKET_FRAMES: u32 = 352;
/// Default receiver playout buffer. pyatv uses 1.5 s; 2 s, the `latencyMax`
/// every stream SETUP declares, leaves more time for late and retransmitted
/// packets on a lossy network, at the cost of 0.5 s more delay.
pub const DEFAULT_LATENCY_FRAMES: u32 = RATE * 2;
static LATENCY_FRAMES: AtomicU32 = AtomicU32::new(DEFAULT_LATENCY_FRAMES);

/// 300-2000 ms in frames: above the declared `latencyMin` (250 ms) and at most
/// the declared `latencyMax` (2 s).
pub fn buffer_frames(ms: u32) -> u32 {
    ms.clamp(300, 2000) * RATE / 1000
}
/// Applies to sessions started afterwards; a running session keeps its value.
pub fn set_buffer_ms(ms: u32) {
    LATENCY_FRAMES.store(buffer_frames(ms), Ordering::Release);
}

/// System time read once, then advanced by the monotonic clock. Windows time
/// synchronisation steps the system clock by tens of ms; timing replies and
/// sync packets must keep describing one continuous timeline.
pub fn ntp_now() -> NtpTimestamp {
    static BASE: OnceLock<(NtpTimestamp, Instant)> = OnceLock::new();
    let (ntp, at) = *BASE.get_or_init(|| (NtpTimestamp::now(), Instant::now()));
    ntp.wrapping_add(at.elapsed())
}
const MAX_PACKETS_COMPENSATE: u64 = 3;

#[derive(Clone, Copy, Debug)]
pub struct StartEpoch {
    pub ntp: NtpTimestamp,
    pub instant: Instant,
}
impl StartEpoch {
    pub fn now() -> Self {
        Self {
            ntp: ntp_now(),
            instant: Instant::now(),
        }
    }
}

/// Published only after all sessions are ready and capture is primed. Reading
/// this clock never blocks RTSP, sync or cancellation on a slower speaker.
#[derive(Default)]
pub struct SharedStart {
    epoch: OnceLock<StartEpoch>,
}
impl SharedStart {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&self) -> StartEpoch {
        *self.epoch.get_or_init(StartEpoch::now)
    }
}

pub struct PlaybackClock {
    start_head: u64,
    start: Instant,
    latency: u32,
}
impl PlaybackClock {
    /// `latency`: this session's receiver buffer in frames, its first RTP timestamp.
    pub fn new(epoch: StartEpoch, latency: u32) -> Self {
        // timing.ntp2ts: int((ntp >> 16) * rate) >> 16. Keep the
        // unwrapped absolute head separately from the 32-bit wire RTP value.
        let start_head = (((epoch.ntp.to_bits() >> 16) as u128 * RATE as u128) >> 16) as u64;
        Self {
            start_head,
            start: epoch.instant,
            latency,
        }
    }

    /// Frames of the shared timeline elapsed since the common start. Sync
    /// packets must report this, not a session's send progress: pyatv paces
    /// sending to real time, but shared capture arrives in bursts and each
    /// speaker's queue differs, so send progress jitters by tens of ms per
    /// speaker and a receiver tracking it moves its playout independently.
    pub fn frames_now(&self) -> u64 {
        (self.start.elapsed().as_nanos() * RATE as u128 / 1_000_000_000) as u64
    }

    /// The configured buffer, read once per session.
    pub fn first_timestamp() -> RtpTimestamp {
        RtpTimestamp::new(LATENCY_FRAMES.load(Ordering::Acquire))
    }

    pub fn sync_packet(&self, first: bool, frames_sent: u64) -> [u8; 20] {
        let head = self.start_head + frames_sent;
        // Match timing.ts2ntp's Python true division and its 16-bit fractional
        // quantization, rather than substituting the wall clock at send time.
        let ntp = NtpTimestamp::from_bits(
            (((head as f64 * 65_536.0 / RATE as f64) as u128) << 16) as u64,
        );
        SyncPacket::new(
            first,
            RtpTimestamp::new(frames_sent as u32),
            ntp,
            RtpTimestamp::new((frames_sent as u32).wrapping_add(self.latency)),
        )
        .encode()
    }
}

/// Called after the primary packet, as in StreamClient._stream_data.
/// At most three extra packets are sent per lap; no sample/packet is skipped.
pub fn catch_up_packets(frames_sent_after_first: u64, elapsed: Duration) -> u64 {
    let expected_frames = (elapsed.as_nanos() * RATE as u128 / 1_000_000_000) as u64;
    (expected_frames.saturating_sub(frames_sent_after_first) / PACKET_FRAMES as u64)
        .min(MAX_PACKETS_COMPENSATE)
}

/// The absolute stream duration minus elapsed monotonic time. Ordinary audio
/// and generated tones use the same pyatv schedule, with no per-lap drift.
pub fn sleep_after(frames_sent: u64, elapsed: Duration) -> Duration {
    Duration::from_secs_f64(frames_sent as f64 / RATE as f64).saturating_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    #[test]
    fn sync_bytes_match_local_pyatv_golden_output_and_rtp_wrap() {
        // Generated by local pyatv 0.18.0 timing.ntp2ts/ts2ntp and
        // packets.SyncPacket.encode at NTP 4000000000.5 seconds with a
        // 88200-frame latency (the same script reproduces pyatv's 66150 bytes).
        let clock = PlaybackClock::new(
            StartEpoch {
                ntp: NtpTimestamp::from_parts(4_000_000_000, 0x8000_0000),
                instant: Instant::now(),
            },
            88_200,
        );
        for (index, (frames, expected)) in [
            (0, "90d4000700000000ee6b28008000000000015888"),
            (352, "80d4000700000160ee6b2800820b0000000159e8"),
            (44100, "80d400070000ac44ee6b280180000000000204cc"),
            (4294967647, "80d400070000015fee6ca4700e7e0000000159e7"),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = clock.sync_packet(index == 0, frames);
            let encoded: String = bytes.iter().map(|value| format!("{value:02x}")).collect();
            assert_eq!(encoded, expected);
        }
        assert_eq!(PlaybackClock::first_timestamp().get(), 88200);
    }

    #[test]
    fn sync_position_follows_the_shared_clock_not_send_progress() {
        let started = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        let clock = PlaybackClock::new(
            StartEpoch {
                ntp: NtpTimestamp::now(),
                instant: started,
            },
            88_200,
        );
        let frames = clock.frames_now();
        // Two seconds of real time, independent of how much was sent.
        assert!((88_200..88_200 + 4_410).contains(&frames), "{frames}");
        // Two speakers on one epoch report the same position.
        let other = PlaybackClock::new(
            StartEpoch {
                ntp: NtpTimestamp::now(),
                instant: started,
            },
            88_200,
        );
        assert!(other.frames_now().abs_diff(clock.frames_now()) < 441);
    }

    #[test]
    fn buffer_setting_is_kept_inside_the_declared_latency_range() {
        assert_eq!(buffer_frames(300), 13_230);
        assert_eq!(buffer_frames(100), 13_230);
        assert_eq!(buffer_frames(2000), 88_200);
        assert_eq!(buffer_frames(5000), 88_200);
        assert_eq!(buffer_frames(1000), 44_100);
    }

    #[test]
    fn timing_clock_is_monotonic_and_near_system_time() {
        let a = ntp_now();
        let b = ntp_now();
        assert!(b.to_bits() >= a.to_bits());
        let system = NtpTimestamp::now();
        assert!(system.secs_f64_since(b).abs() < 1.0);
    }

    #[test]
    fn catch_up_is_capped_at_three_without_skipping_audio() {
        assert_eq!(catch_up_packets(352, Duration::ZERO), 0);
        assert_eq!(catch_up_packets(352, Duration::from_secs(1)), 3);
        assert_eq!(catch_up_packets(43_748, Duration::from_secs(1)), 1);
        assert_eq!(catch_up_packets(44_100, Duration::from_secs(1)), 0);
        assert_eq!(
            sleep_after(44_100, Duration::from_millis(900)),
            Duration::from_millis(100)
        );
        assert_eq!(
            sleep_after(44_100, Duration::from_millis(1100)),
            Duration::ZERO
        );
    }

    #[test]
    fn group_members_receive_one_identical_epoch() {
        let start = Arc::new(SharedStart::new());
        let peer = start.clone();
        let worker = thread::spawn(move || peer.start());
        let epoch = start.start();
        let other = worker.join().unwrap();
        assert_eq!(epoch.ntp, other.ntp);
        assert_eq!(epoch.instant, other.instant);
    }

    #[test]
    fn constructing_the_group_does_not_start_its_media_clock() {
        let start = SharedStart::new();
        assert!(start.epoch.get().is_none());
        let ready = Instant::now();
        assert!(start.start().instant >= ready);
    }
}
