//! A realtime stream end to end, sans-io: [`RealtimeReceiver`], [`ClockTracker`] and
//! [`PlayoutScheduler`] assembled the way a receiver plays one. No socket, thread or sink.
//!
//! The host feeds datagrams in ([`RealtimeStream::on_data`], [`RealtimeStream::on_control`]),
//! sends what [`RealtimeStream::retransmit_requests`] returns to the sender's control port, and
//! drains [`RealtimeStream::poll`] (see [`super::stream`]).
//!
//! - Decoded packets wait for the sink's device to open, and at the start and after a `FLUSH` for
//!   a sync packet that describes the new timeline: its RTP time at most
//!   [`RealtimeStreamConfig::sync_behind_flush`] frames before the `FLUSH`'s `rtptime`, and within
//!   a hold's worth of frames at 48 kHz after it. Each wait lasts at most
//!   [`RealtimeStreamConfig::hold_limit`] and is given up once: a sender that never sends a fitting
//!   sync packet is then placed on its latest one (or played as it comes), and a device that never
//!   opens is no longer waited for.
//! - Each packet is then placed ([`PlayoutScheduler`]) against the host's [`ClockEstimate`] and
//!   [`SinkDelay`]. A placement that starts with silence yields [`StreamOutput::Silence`] and
//!   places the packet again on the next poll, so the write's own time comes off its head.
//! - Resampling: placed, the scheduler's correction alone (the offset already carries the
//!   sender's drift and the sink's delay the device's); played as it comes, the sync-packet fit's
//!   ratio once it is trustworthy: [`DRIFT_MIN_SYNC_PACKETS`] are in and the fit is inside
//!   [`MAX_DRIFT_PPM`] (a fit at the clamp over a short, noisy series is not applied). Until then
//!   the ratio is 1.0, and a placed stream's own correction ([`super::playout::MAX_CORRECTION_PPM`]) holds it.
//!
//! Unproven beyond this crate's own sender, pyatv and one machine.

use std::collections::VecDeque;
use std::time::Duration;

use super::audio::{AudioStreamFormat, PcmPacket, RealtimeReceiver, RealtimeStats};
use super::clock::{ClockTracker, MAX_DRIFT_PPM};
use super::connection::AudioStreamSetup;
use super::playout::{Playout, PlayoutScheduler, PlayoutStats};
use super::stream::{ScheduledPacket, SinkDelay, StreamNotice, StreamOutput, MAX_QUEUED_NOTICES};
use crate::audio::rtp::{SyncPacket, RETRANSMIT_REQUEST_LEN};
use crate::error::Result;
use crate::time::RtpTimestamp;
use crate::timing::ClockEstimate;

/// The default longest latency a sender may ask for, and the default hold: 1.5 s (pyatv's and this
/// crate's sender's) plus the quarter second added for a flag-7 sync packet, under a sink that
/// holds two seconds.
pub const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(1_750);

/// The default for [`RealtimeStreamConfig::sync_behind_flush`]: four 352-frame packets.
pub const SYNC_BEHIND_FLUSH_FRAMES: u32 = 4 * 352;

/// Sync packets the drift fit needs before its ratio is used for packets played as they come:
/// about a quarter of a minute at one a second. A fit over fewer, with timing round trips of tens
/// of milliseconds, swings by hundreds of ppm and to the clamp. A fit at the clamp
/// ([`MAX_DRIFT_PPM`]) is never applied, whatever its count.
pub const DRIFT_MIN_SYNC_PACKETS: usize = 16;

/// The most decoded packets held, whatever the hold and the packet size: 221 packets is a 1.75 s
/// hold at 44.1 kHz and 352 frames, so this leaves room for 48 kHz and longer holds while tiny
/// packets cannot make the hold a large allocation.
pub const MAX_HELD_PACKETS: usize = 512;

/// Frames per second the sync-packet window after a `FLUSH` is measured at: the highest common
/// rate, so it is never narrower than a hold.
const SYNC_WINDOW_RATE: f64 = 48_000.0;

/// How a [`RealtimeStream`] plays.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct RealtimeStreamConfig {
    /// The longest latency honoured: the most audio the sink is asked to hold ahead.
    pub max_latency: Duration,
    /// The longest a packet waits for a sink that is starting or a sync packet that fits.
    pub hold_limit: Duration,
    /// How far before a `FLUSH`'s `rtptime`, in frames, a sync packet may name its RTP time and
    /// still end the wait for the new timeline.
    pub sync_behind_flush: u32,
    /// Later packets that may wait behind a missing one before it is concealed
    /// ([`RealtimeReceiver::set_conceal_after`]).
    pub conceal_after: u64,
}

impl Default for RealtimeStreamConfig {
    fn default() -> Self {
        Self {
            max_latency: DEFAULT_MAX_LATENCY,
            hold_limit: DEFAULT_MAX_LATENCY,
            sync_behind_flush: SYNC_BEHIND_FLUSH_FRAMES,
            conceal_after: super::audio::CONCEAL_AFTER_PACKETS,
        }
    }
}

/// What a [`RealtimeStream`] has seen and done.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct RealtimeStreamStats {
    /// Receive: packets opened, late, concealed, retransmitted, and so on.
    pub receive: RealtimeStats,
    /// Placement: scheduled, resyncs, silence and skipped frames, the error and latency.
    pub playout: PlayoutStats,
    /// Decoded packets waiting to be placed.
    pub held: usize,
}

/// One realtime stream, from datagrams to placed PCM. See the module docs.
pub struct RealtimeStream {
    receiver: RealtimeReceiver,
    clock: ClockTracker,
    playout: PlayoutScheduler,
    config: RealtimeStreamConfig,
    format: AudioStreamFormat,
    /// The last sync packet given to the clock.
    observed_sync: Option<SyncPacket>,
    begun: bool,
    held: VecDeque<PcmPacket>,
    held_since: Option<Duration>,
    /// The most packets held: a hold's worth, plus one.
    most_held: usize,
    /// No sync packet for the current timeline since the start or the last `FLUSH`.
    awaiting_sync: bool,
    /// The `FLUSH`'s `rtptime` while a sync packet for the new timeline is awaited.
    flush_rtp: Option<RtpTimestamp>,
    placing: bool,
    device_given_up: bool,
    /// The sync-packet fit's ratio, for packets played as they come.
    drift_ratio: f64,
    /// The ratio last handed out.
    ratio: f64,
    out: VecDeque<StreamOutput>,
    /// A packet whose placement asked for silence first: placed again on the next poll.
    replace: Option<ScheduledPacket>,
}

impl std::fmt::Debug for RealtimeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealtimeStream")
            .field("format", &self.format)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl RealtimeStream {
    /// A stream with the `SETUP`'s `shk` and format.
    ///
    /// # Errors
    ///
    /// A format [`RealtimeReceiver::new`] refuses.
    pub fn new(
        key: [u8; 32],
        format: AudioStreamFormat,
        config: RealtimeStreamConfig,
    ) -> Result<Self> {
        Ok(Self::over(
            RealtimeReceiver::new(key, format)?,
            format,
            config,
        ))
    }

    /// A stream of an AirPlay 1 sender's unencrypted audio ([`RealtimeReceiver::new_unencrypted`]).
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn new_unencrypted(
        format: AudioStreamFormat,
        config: RealtimeStreamConfig,
    ) -> Result<Self> {
        Ok(Self::over(
            RealtimeReceiver::new_unencrypted(format)?,
            format,
            config,
        ))
    }

    fn over(
        mut receiver: RealtimeReceiver,
        format: AudioStreamFormat,
        config: RealtimeStreamConfig,
    ) -> Self {
        receiver.set_conceal_after(config.conceal_after);
        let rate = f64::from(format.sample_rate.max(1));
        let spf = f64::from(format.frames_per_packet.max(1));
        // A hold's worth of frames, plus one packet, and never past the ceiling. Saturating
        // float-to-int.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let packets = (config.hold_limit.as_secs_f64() * rate / spf).ceil() as usize;
        let most_held = packets.saturating_add(1).min(MAX_HELD_PACKETS);
        Self {
            receiver,
            clock: ClockTracker::new(format.sample_rate),
            playout: PlayoutScheduler::new(format.sample_rate, config.max_latency.as_secs_f64()),
            config,
            format,
            observed_sync: None,
            begun: false,
            held: VecDeque::new(),
            held_since: None,
            most_held,
            awaiting_sync: true,
            flush_rtp: None,
            placing: false,
            device_given_up: false,
            drift_ratio: 1.0,
            ratio: 1.0,
            out: VecDeque::new(),
            replace: None,
        }
    }

    /// A stream for what a stream `SETUP` negotiated.
    ///
    /// # Errors
    ///
    /// As [`Self::new`]; and a wrapped-key stream (`aes_cbc_key`), whose audio is drained as
    /// access units from a [`RealtimeReceiver`] instead. An `unencrypted` stream (AirPlay 1) is
    /// [`Self::new_unencrypted`].
    pub fn from_setup(setup: &AudioStreamSetup, config: RealtimeStreamConfig) -> Result<Self> {
        #[cfg(feature = "mirror")]
        if setup.aes_cbc_key.is_some() {
            return Err(crate::error::AirPlayError::InvalidState(
                "a wrapped-key stream is drained as access units (RealtimeReceiver::new_aes_cbc)"
                    .to_owned(),
            ));
        }
        if setup.unencrypted {
            return Self::new_unencrypted(setup.format, config);
        }
        Self::new(setup.shared_key, setup.format, config)
    }

    /// The format.
    #[must_use]
    pub fn format(&self) -> AudioStreamFormat {
        self.format
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> RealtimeStreamConfig {
        self.config
    }

    /// The sender's sync mapping and drift.
    #[must_use]
    pub fn clock(&self) -> &ClockTracker {
        &self.clock
    }

    /// The receive half: reorder, retransmit and decode state.
    #[must_use]
    pub fn receiver(&self) -> &RealtimeReceiver {
        &self.receiver
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> RealtimeStreamStats {
        RealtimeStreamStats {
            receive: self.receiver.stats(),
            playout: self.playout.stats(),
            held: self.held.len(),
        }
    }

    /// Whether the stream is placed on the sender's timeline (the last [`StreamOutput::Placing`]).
    #[must_use]
    pub fn is_placing(&self) -> bool {
        self.placing
    }

    /// Whether packets wait for a sync packet on the current timeline.
    #[must_use]
    pub fn awaiting_sync(&self) -> bool {
        self.awaiting_sync
    }

    /// One datagram from the data port.
    ///
    /// # Errors
    ///
    /// A packet that does not open or parse; it is counted and dropped, and the stream goes on.
    pub fn on_data(&mut self, datagram: &[u8]) -> Result<()> {
        self.receiver.on_data(datagram)
    }

    /// One datagram from the control port: a retransmit reply, or a sync packet. Of the sync packets
    /// that arrive between two polls, the next [`Self::poll`] gives the stream's clock the newest
    /// (unless it repeats the last one taken), at that poll's now. `Ok(false)` for anything else.
    ///
    /// # Errors
    ///
    /// A reply that does not open, or a sync packet that does not parse.
    pub fn on_control(&mut self, datagram: &[u8]) -> Result<bool> {
        self.receiver.on_control(datagram)
    }

    fn observe(&mut self, sync: SyncPacket, now: Duration) {
        self.observed_sync = Some(sync);
        self.clock.observe(&sync, now);
        if self.accepts_sync(&sync) {
            self.awaiting_sync = false;
            self.flush_rtp = None;
        }
        let drift = self.clock.drift();
        if drift.samples >= DRIFT_MIN_SYNC_PACKETS && drift.ppm.abs() < MAX_DRIFT_PPM {
            self.drift_ratio = drift.resample_ratio;
        }
        // At most one a poll, so never dropped.
        self.out
            .push_back(StreamOutput::Notice(StreamNotice::Sync { drift }));
    }

    /// Whether `sync` describes the timeline after the last `FLUSH`.
    fn accepts_sync(&self, sync: &SyncPacket) -> bool {
        self.flush_rtp.is_none_or(|flushed| {
            let ahead = sync.now.signed_frames_since(flushed);
            // Saturating float-to-int: a window past i32 frames is no bound.
            #[allow(clippy::cast_possible_truncation)]
            let window = (self.config.hold_limit.as_secs_f64() * SYNC_WINDOW_RATE) as i32;
            let behind = i32::try_from(self.config.sync_behind_flush).unwrap_or(i32::MAX);
            (-behind..=window).contains(&ahead)
        })
    }

    /// The retransmit requests due at monotonic `now`, for the sender's control port.
    pub fn retransmit_requests(&mut self, now: Duration) -> Vec<[u8; RETRANSMIT_REQUEST_LEN]> {
        self.receiver.retransmit_requests(now)
    }

    /// `FLUSH` with `RTP-Info`'s values: what is held or queued goes, the clock tracker and drift
    /// correction start over, the stream is no longer placed, and the next packets wait for a sync
    /// packet on the new timeline. A stream whose hold runs out before the first new sync places
    /// packets unscheduled, as they come. Flush the sink too.
    pub fn flush(&mut self, sequence: Option<u16>, rtp_time: Option<RtpTimestamp>) {
        self.receiver.flush(sequence, rtp_time);
        // The new timeline may jump in RTP time; the old fit says nothing about it.
        self.clock.reset();
        self.drift_ratio = 1.0;
        self.held.clear();
        self.held_since = None;
        self.awaiting_sync = true;
        self.flush_rtp = rtp_time;
        self.placing = false;
        self.playout.flush();
        self.replace = None;
        self.out.retain(|out| {
            !matches!(
                out,
                StreamOutput::Placing(_) | StreamOutput::Silence(_) | StreamOutput::Packet(_)
            )
        });
    }

    /// The next thing for the host to do, at monotonic `now`, with the latest estimate of the
    /// sender's clock (`None` before one) and the sink's delay read now. `None` when there is
    /// nothing until more arrives or time passes.
    pub fn poll(
        &mut self,
        now: Duration,
        clock: Option<ClockEstimate>,
        sink: SinkDelay,
    ) -> Option<StreamOutput> {
        if let Some(sync) = self.receiver.last_sync() {
            if self.observed_sync != Some(sync) {
                self.observe(sync, now);
            }
        }
        loop {
            if let Some(out) = self.out.pop_front() {
                return Some(out);
            }
            if let Some(packet) = self.replace.take() {
                self.place_again(packet, now, clock, sink);
                continue;
            }
            if self.place_next(now, clock, sink) {
                continue;
            }
            match self.receiver.next_pcm() {
                Ok(Some(pcm)) => self.offer(pcm, now),
                Ok(None) => return None,
                Err(e) => {
                    return Some(StreamOutput::Notice(StreamNotice::DecodeFailed {
                        sequence: None,
                        error: e.to_string(),
                    }))
                }
            }
        }
    }

    fn notice(&mut self, notice: StreamNotice) {
        if self.out.len() < MAX_QUEUED_NOTICES {
            self.out.push_back(StreamOutput::Notice(notice));
        }
    }

    /// A decoded packet: the first begins the sink; it waits in the hold.
    fn offer(&mut self, pcm: PcmPacket, now: Duration) {
        if !self.begun {
            self.begun = true;
            self.out.push_back(StreamOutput::Begin {
                sample_rate: pcm.sample_rate,
                channels: pcm.channels,
                sequence: u32::from(pcm.sequence),
            });
        }
        if self.held.is_empty() {
            self.held_since = Some(now);
        }
        self.held.push_back(pcm);
        // Never more than a hold's worth: the oldest are late by then anyway.
        while self.held.len() > self.most_held {
            self.held.pop_front();
        }
    }

    /// Places the oldest held packet, unless the sink is starting or a sync packet is awaited and
    /// the hold has not run out. Whether it placed one.
    fn place_next(&mut self, now: Duration, clock: Option<ClockEstimate>, sink: SinkDelay) -> bool {
        if self.held.is_empty() {
            return false;
        }
        let holding = self
            .held_since
            .is_some_and(|since| now.saturating_sub(since) < self.config.hold_limit);
        let starting = !self.device_given_up && sink == SinkDelay::Starting;
        if holding && (starting || self.awaiting_sync) {
            return false;
        }
        if self.awaiting_sync {
            self.awaiting_sync = false;
            self.flush_rtp = None;
            let latest_sync = self.clock.latency_frames().is_some();
            self.notice(StreamNotice::SyncWaitEnded { latest_sync });
        }
        if starting {
            self.device_given_up = true;
            self.notice(StreamNotice::DeviceNotStarted);
        }
        let Some(pcm) = self.held.pop_front() else {
            return false;
        };
        if self.held.is_empty() {
            self.held_since = None;
        }
        self.place(pcm, now, clock, sink);
        true
    }

    fn set_placing(&mut self, placing: bool) {
        if self.placing != placing {
            self.placing = placing;
            self.out.push_back(StreamOutput::Placing(placing));
        }
    }

    fn frames_of(&self, samples: &[i16]) -> u32 {
        u32::try_from(samples.len() / usize::from(self.format.channels.max(1))).unwrap_or(0)
    }

    /// When frame 0 of `timestamp` should be heard on the host's monotonic clock.
    fn due(&self, timestamp: RtpTimestamp, clock: Option<ClockEstimate>) -> Option<Duration> {
        let latency = self.playout.stats().latency?;
        let sent = self.clock.schedule(timestamp)?;
        clock?.local_instant(sent.wrapping_add_secs_f64(latency))
    }

    fn place(
        &mut self,
        pcm: PcmPacket,
        now: Duration,
        clock: Option<ClockEstimate>,
        sink: SinkDelay,
    ) {
        let frames = self.frames_of(&pcm.samples);
        let sender_now = clock.map(|c| c.sender_time(now));
        let delay = sink.known().map(|d| d.as_secs_f64());
        let placement = self
            .playout
            .place(pcm.timestamp, frames, &self.clock, sender_now, delay);
        let due = match placement {
            Playout::Unscheduled => None,
            _ => self.due(pcm.timestamp, clock),
        };
        let mut packet = ScheduledPacket {
            samples: pcm.samples,
            channels: pcm.channels,
            sample_rate: pcm.sample_rate,
            sequence: u32::from(pcm.sequence),
            timestamp: pcm.timestamp,
            concealed: pcm.concealed,
            skip: None,
            resample_ratio: self.ratio,
            due,
            placement,
        };
        match placement {
            Playout::Play {
                silence,
                skip,
                correction_ppm,
                ..
            } => {
                self.ratio = 1.0 + correction_ppm / 1e6;
                self.set_placing(true);
                packet.resample_ratio = self.ratio;
                packet.skip = Some(skip);
                if silence > 0 {
                    self.out.push_back(StreamOutput::Silence(silence));
                    self.replace = Some(packet);
                    return;
                }
            }
            Playout::Drop { .. } => {}
            Playout::Unscheduled => {
                self.ratio = self.drift_ratio;
                packet.resample_ratio = self.ratio;
                self.set_placing(false);
                // What is written now is not placed: no later reading of the sink is its floor.
                self.playout.sink_written();
                packet.skip = Some(0);
            }
        }
        self.out.push_back(StreamOutput::Packet(packet));
    }

    /// The packet after its silence was written: placed again on a fresh reading, so the write's
    /// time comes off its head.
    fn place_again(
        &mut self,
        mut packet: ScheduledPacket,
        now: Duration,
        clock: Option<ClockEstimate>,
        sink: SinkDelay,
    ) {
        let frames = self.frames_of(&packet.samples);
        let sender_now = clock.map(|c| c.sender_time(now));
        let delay = sink.known().map(|d| d.as_secs_f64());
        match self
            .playout
            .place_again(packet.timestamp, frames, &self.clock, sender_now, delay)
        {
            Playout::Play {
                silence: more,
                skip: head,
                ..
            } => {
                if more > 0 {
                    self.out.push_back(StreamOutput::Silence(more));
                }
                packet.skip = Some(head);
            }
            Playout::Drop { .. } => packet.skip = None,
            Playout::Unscheduled => {}
        }
        self.out.push_back(StreamOutput::Packet(packet));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::format::{audio_format, compression};
    use crate::audio::rtp::{retransmit_reply, PacketSealer, RetransmitRequest, RtpHeader};
    use crate::audio::SendTimeline;
    use crate::time::NtpTimestamp;

    const KEY: [u8; 32] = [9; 32];
    const RATE: u32 = 44_100;
    const SPF: u32 = 352;
    /// The latency every sync packet declares: one second.
    const LATENCY: u32 = RATE;
    /// The first packet's sequence number: near the wrap, so it is crossed.
    const SEQ0: u16 = 65_500;
    /// The device's own latency, behind what its queue holds.
    const DEVICE: f64 = 0.05;
    /// How close to its time a packet must be heard.
    const ON_TIME: f64 = 0.001;

    fn epoch() -> NtpTimestamp {
        NtpTimestamp::from_parts(3_900_000_000, 0)
    }

    fn secs(seconds: f64) -> Duration {
        Duration::from_secs_f64(seconds.max(0.0))
    }

    fn format() -> AudioStreamFormat {
        AudioStreamFormat::new(compression::LPCM, audio_format::PCM_44100_16_2, RATE, SPF)
    }

    /// When packet `k` of a timeline begun at host time `start` is sent.
    fn sent_at(start: f64, k: u64) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let frames = (k * u64::from(SPF)) as f64;
        start + frames / f64::from(RATE)
    }

    /// A sender whose frame 0 goes at host time `start` (its clock and the host's agree): LPCM
    /// packets whose every sample is the packet's index plus one, and sync packets declaring
    /// [`LATENCY`] with `flags`.
    struct Sender {
        sealer: PacketSealer,
        timeline: SendTimeline,
        start: f64,
        sequence: u16,
        flags: u16,
        sealed: Vec<(u16, Vec<u8>)>,
    }

    impl Sender {
        fn new(start: f64, rtp_base: u32, sequence: u16) -> Self {
            Self {
                sealer: PacketSealer::new(&KEY),
                timeline: SendTimeline::new(
                    epoch().wrapping_add_secs_f64(start),
                    RtpTimestamp::new(rtp_base),
                    RATE,
                ),
                start,
                sequence,
                flags: 0,
                sealed: Vec::new(),
            }
        }

        /// Packet `k`, sealed, and kept for a retransmit.
        fn packet(&mut self, k: u64) -> Vec<u8> {
            let timestamp = self.timeline.rtp_of(k * u64::from(SPF));
            let sequence = self.sequence.wrapping_add(u16::try_from(k).unwrap());
            let header = RtpHeader::audio(k == 0, sequence, timestamp, 1).encode();
            let value = i16::try_from(k % 30_000 + 1).unwrap().to_be_bytes();
            let payload: Vec<u8> = std::iter::repeat_n(value, SPF as usize * 2)
                .flatten()
                .collect();
            let sealed = self.sealer.seal(&header, &payload).unwrap();
            self.sealed.push((sequence, sealed.clone()));
            sealed
        }

        fn sync(&self, k: u64) -> [u8; crate::audio::rtp::SYNC_PACKET_LEN] {
            let mut sync = self
                .timeline
                .sync_packet(k == 0, k * u64::from(SPF), LATENCY);
            sync.flags = self.flags;
            sync.encode()
        }

        /// When frame 0 of packet `k` should be heard, on the host's clock.
        fn heard_at(&self, k: u64) -> f64 {
            sent_at(self.start, k) + f64::from(LATENCY) / f64::from(RATE)
        }
    }

    /// A device that plays what it is given back to back, `latency` behind its queue, and says it
    /// is starting until a host time.
    struct Device {
        play_end: f64,
        latency: f64,
        starting_until: f64,
    }

    impl Device {
        fn delay(&self, now: f64) -> SinkDelay {
            if now < self.starting_until {
                return SinkDelay::Starting;
            }
            SinkDelay::Known(secs((self.play_end - now).max(0.0) + self.latency))
        }

        /// Queues `frames` at `now`; when the first is heard.
        fn write(&mut self, now: f64, frames: u32) -> f64 {
            let start = self.play_end.max(now);
            self.play_end = start + f64::from(frames) / f64::from(RATE);
            start + self.latency
        }

        fn flush(&mut self, now: f64) {
            self.play_end = now;
        }
    }

    /// A packet the host wrote (or dropped), and when its frame 0 is heard.
    #[derive(Debug, Clone)]
    struct Heard {
        value: i16,
        concealed: bool,
        heard: Option<f64>,
        due: Option<f64>,
        ratio: f64,
    }

    /// The host: one stream, its device, and everything that came out.
    struct Host {
        stream: RealtimeStream,
        device: Device,
        offset: f64,
        outputs: Vec<StreamOutput>,
        heard: Vec<Heard>,
        requests: Vec<[u8; RETRANSMIT_REQUEST_LEN]>,
    }

    impl Host {
        fn new() -> Self {
            Self {
                stream: RealtimeStream::new(KEY, format(), RealtimeStreamConfig::default())
                    .unwrap(),
                device: Device {
                    play_end: 0.0,
                    latency: DEVICE,
                    starting_until: 0.0,
                },
                offset: 0.0,
                outputs: Vec::new(),
                heard: Vec::new(),
                requests: Vec::new(),
            }
        }

        /// Acts on every output at `now`.
        fn drain(&mut self, now: f64) {
            let estimate = Some(ClockEstimate::new(epoch(), self.offset, 0.001));
            while let Some(out) = self
                .stream
                .poll(secs(now), estimate, self.device.delay(now))
            {
                match &out {
                    StreamOutput::Silence(frames) => {
                        self.device.write(now, *frames);
                    }
                    StreamOutput::Packet(packet) => {
                        let heard = packet.skip.map(|skip| {
                            let frames = u32::try_from(packet.frames()).unwrap() - skip;
                            self.device.write(now, frames) - f64::from(skip) / f64::from(RATE)
                        });
                        self.heard.push(Heard {
                            value: packet.samples[0],
                            concealed: packet.concealed,
                            heard,
                            due: packet.due.map(|d| d.as_secs_f64()),
                            ratio: packet.resample_ratio,
                        });
                    }
                    _ => {}
                }
                self.outputs.push(out);
            }
        }

        /// Sends packets `range` in real time, a sync packet before every 125th, leaving out those
        /// `drop` names, and acts on everything as it comes.
        fn play(&mut self, sender: &mut Sender, range: std::ops::Range<u64>, drop: &[u64]) {
            for k in range {
                let now = sent_at(sender.start, k);
                if k % 125 == 0 {
                    self.stream.on_control(&sender.sync(k)).unwrap();
                }
                let packet = sender.packet(k);
                if !drop.contains(&k) {
                    self.stream.on_data(&packet).unwrap();
                }
                self.requests
                    .extend(self.stream.retransmit_requests(secs(now)));
                self.drain(now);
            }
        }

        fn notices(&self) -> Vec<&StreamNotice> {
            self.outputs
                .iter()
                .filter_map(|o| match o {
                    StreamOutput::Notice(n) => Some(n),
                    _ => None,
                })
                .collect()
        }

        fn placings(&self) -> Vec<bool> {
            self.outputs
                .iter()
                .filter_map(|o| match o {
                    StreamOutput::Placing(p) => Some(*p),
                    _ => None,
                })
                .collect()
        }

        /// The worst error, in seconds, of the packets heard from `heard[from..]` whose values are
        /// in `values`, against `expected` of their index.
        fn worst(
            &self,
            from: usize,
            values: std::ops::Range<i16>,
            expected: impl Fn(u64) -> f64,
        ) -> f64 {
            self.heard[from..]
                .iter()
                .filter(|h| values.contains(&h.value) && !h.concealed)
                .filter_map(|h| {
                    let k = u64::try_from(h.value - 1).unwrap();
                    h.heard.map(|heard| (heard - expected(k)).abs())
                })
                .fold(0.0, f64::max)
        }
    }

    #[test]
    fn every_packet_is_heard_at_its_timestamp_plus_the_declared_latency() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..400, &[]);
        assert!(
            matches!(
                host.outputs[..4],
                [
                    StreamOutput::Notice(StreamNotice::Sync { .. }),
                    StreamOutput::Begin {
                        sample_rate: RATE,
                        channels: 2,
                        sequence: 65_500
                    },
                    StreamOutput::Placing(true),
                    StreamOutput::Silence(_),
                ]
            ),
            "{:?}",
            &host.outputs[..4]
        );
        assert_eq!(host.heard.len(), 400);
        let worst = host.worst(0, 1..401, |k| sender.heard_at(k));
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);
        // Each due is its frame's send time plus the latency: monotonic, a packet apart.
        for (k, heard) in host.heard.iter().enumerate() {
            let due = heard.due.expect("placed");
            assert!((due - sender.heard_at(k as u64)).abs() < 1e-6, "{k}: {due}");
        }
        let spacing = f64::from(SPF) / f64::from(RATE);
        for pair in host.heard.windows(2) {
            let step = pair[1].due.unwrap() - pair[0].due.unwrap();
            assert!((step - spacing).abs() < 1e-6, "{step}");
        }
        let stats = host.stream.stats();
        assert_eq!(stats.playout.scheduled, 400);
        assert_eq!(stats.playout.resyncs, 0);
        assert_eq!(stats.playout.latency, Some(1.0));
        assert_eq!(stats.receive.packets_played, 400);
        assert_eq!(host.placings(), [true]);
    }

    #[test]
    fn a_flag_7_sync_packet_adds_a_quarter_second() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        sender.flags = crate::audio::rtp::SYNC_FLAGS;
        host.play(&mut sender, 0..200, &[]);
        let worst = host.worst(0, 1..201, |k| sender.heard_at(k) + 0.25);
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);
    }

    #[test]
    fn a_lost_packet_is_asked_for_and_its_retransmit_plays_in_its_place() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..42, &[40]);
        assert_eq!(host.requests.len(), 1, "asked once the gap shows");
        let request = RetransmitRequest::parse(&host.requests[0]).unwrap();
        let (lost, sealed) = sender.sealed[40].clone();
        assert_eq!(request.lost_sequences().collect::<Vec<_>>(), [lost]);
        host.play(&mut sender, 42..50, &[]);
        assert_eq!(host.requests.len(), 2, "and again after the retry interval");
        host.stream
            .on_control(&retransmit_reply(lost, &sealed))
            .unwrap();
        host.drain(sent_at(0.0, 49));
        host.play(&mut sender, 50..200, &[]);
        let stats = host.stream.stats().receive;
        assert_eq!(stats.packets_retransmitted, 1);
        assert_eq!(stats.packets_concealed, 0);
        assert_eq!(
            host.heard.iter().map(|h| h.value).collect::<Vec<_>>(),
            (1..=200).collect::<Vec<i16>>()
        );
        let worst = host.worst(0, 1..201, |k| sender.heard_at(k));
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);
    }

    #[test]
    fn a_packet_never_retransmitted_is_concealed_on_the_timeline() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..200, &[60]);
        let stats = host.stream.stats().receive;
        assert_eq!(stats.packets_concealed, 1);
        assert_eq!(stats.retransmit_requests, 3, "asked for three times");
        assert_eq!(host.requests.len(), 3);
        let concealed: Vec<_> = host.heard.iter().filter(|h| h.concealed).collect();
        assert_eq!(concealed.len(), 1);
        assert_eq!(concealed[0].value, 0, "silence");
        assert!((concealed[0].heard.unwrap() - sender.heard_at(60)).abs() < ON_TIME);
        let worst = host.worst(0, 1..201, |k| sender.heard_at(k));
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);
        assert_eq!(host.stream.stats().playout.resyncs, 0);
    }

    #[test]
    fn reordered_packets_play_in_order_and_a_repeat_is_late() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..20, &[]);
        let (twenty, twenty_one) = (sender.packet(20), sender.packet(21));
        host.stream.on_data(&twenty_one).unwrap();
        host.stream.on_data(&twenty).unwrap();
        assert!(host
            .stream
            .retransmit_requests(secs(sent_at(0.0, 21)))
            .is_empty());
        host.drain(sent_at(0.0, 21));
        // A repeat of one already played.
        host.stream.on_data(&twenty).unwrap();
        host.play(&mut sender, 22..60, &[]);
        assert_eq!(
            host.heard.iter().map(|h| h.value).collect::<Vec<_>>(),
            (1..=60).collect::<Vec<i16>>()
        );
        let stats = host.stream.stats().receive;
        assert_eq!(stats.gaps_detected, 1);
        assert_eq!(stats.packets_late, 1);
        assert_eq!(stats.packets_concealed, 0);
    }

    /// The estimate of the sender's clock steps 60 ms. Ahead, packets read late: whole ones are
    /// dropped until the device has played down to the new time. Behind, they read early, and
    /// silence fills the gap. Either way the stream is re-placed once.
    #[test]
    fn a_clock_offset_step_re_places_the_stream() {
        for step in [0.060, -0.060] {
            let mut host = Host::new();
            let mut sender = Sender::new(0.0, 1_000, SEQ0);
            host.play(&mut sender, 0..200, &[]);
            let before = host.stream.stats().playout;
            host.offset = step;
            host.play(&mut sender, 200..600, &[]);
            let stats = host.stream.stats().playout;
            assert_eq!(stats.resyncs, 1, "{step}: {stats:?}");
            if step > 0.0 {
                assert!(stats.dropped_packets >= 6, "{stats:?}");
            } else {
                let added = stats.silence_frames - before.silence_frames;
                assert!((2_600..2_700).contains(&added), "{stats:?}");
            }
            let worst = host.worst(300, 300..601, |k| sender.heard_at(k) - step);
            assert!(worst < ON_TIME, "{step}: worst {:.3} ms", worst * 1e3);
        }
    }

    /// The sink's delay steps: by 80 ms, the stream is re-placed; by 10 ms, it is pulled back by
    /// resampling (which this host does not do, so the correction stays asked for).
    #[test]
    fn a_sink_delay_change_is_re_placed_or_resampled_towards() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..200, &[]);
        host.device.latency += 0.080;
        host.play(&mut sender, 200..600, &[]);
        assert_eq!(host.stream.stats().playout.resyncs, 1);
        let worst = host.worst(300, 300..601, |k| sender.heard_at(k));
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);

        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..200, &[]);
        assert_eq!(host.heard[199].ratio, 1.0);
        host.device.latency += 0.010;
        host.play(&mut sender, 200..400, &[]);
        let stats = host.stream.stats().playout;
        assert_eq!(stats.resyncs, 0);
        assert!(stats.correction_ppm < 0.0, "{stats:?}");
        assert!(host.heard.last().unwrap().ratio < 1.0);
    }

    /// A `FLUSH` to a timeline whose RTP time jumps leaves no trace of the jump in the drift fit.
    #[test]
    fn a_flush_to_a_new_rtp_timeline_starts_the_drift_fit_over() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..2_400, &[]);
        assert!(host.stream.clock().drift().samples >= DRIFT_MIN_SYNC_PACKETS);
        let at = sent_at(0.0, 2_400);
        let mut seeked = Sender::new(at, 3_000_000_000, SEQ0.wrapping_add(2_400));
        host.stream.flush(
            Some(SEQ0.wrapping_add(2_400)),
            Some(RtpTimestamp::new(3_000_000_000)),
        );
        host.device.flush(at);
        assert_eq!(
            host.stream.clock().drift(),
            super::super::clock::DriftEstimate::UNSLAVED
        );
        host.play(&mut seeked, 0..600, &[]);
        let drift = host.stream.clock().drift();
        assert!(drift.samples >= 2, "{drift:?}");
        assert!(drift.ppm.abs() < 5.0, "{drift:?}");
    }

    /// After a `FLUSH` (a seek), packets on the new timeline wait for a sync packet that describes
    /// it, and are then placed on it.
    #[test]
    fn after_a_flush_packets_wait_for_the_new_timelines_sync_packet() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..200, &[]);
        let at = sent_at(0.0, 200);
        let mut seeked = Sender::new(at, 900_000, SEQ0.wrapping_add(200));
        host.stream.flush(
            Some(SEQ0.wrapping_add(200)),
            Some(RtpTimestamp::new(900_000)),
        );
        host.device.flush(at);
        assert!(host.stream.awaiting_sync());
        assert!(!host.stream.is_placing());
        let before = host.heard.len();
        // The new timeline, its first sync packet only before the twentieth packet.
        for k in 0..200 {
            let now = sent_at(at, k);
            if k == 20 {
                host.stream.on_control(&seeked.sync(k)).unwrap();
            }
            host.stream.on_data(&seeked.packet(k)).unwrap();
            host.drain(now);
            if k == 19 {
                assert_eq!(host.heard.len(), before, "held for the sync packet");
            }
        }
        assert_eq!(host.heard.len(), before + 200);
        assert_eq!(host.placings(), [true, true]);
        let worst = host.worst(before, 1..201, |k| seeked.heard_at(k));
        assert!(worst < ON_TIME, "worst {:.3} ms", worst * 1e3);
        assert!(!host
            .notices()
            .iter()
            .any(|n| matches!(n, StreamNotice::SyncWaitEnded { .. })));
    }

    /// A sender that sends no sync packet is held once at the start, then played as it comes.
    #[test]
    fn with_no_sync_packet_the_wait_ends_once_and_packets_play_as_they_come() {
        let mut host = Host::new();
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        let mut first_written = None;
        for k in 0..400 {
            let now = sent_at(0.0, k);
            host.stream.on_data(&sender.packet(k)).unwrap();
            host.drain(now);
            if first_written.is_none() && !host.heard.is_empty() {
                first_written = Some(now);
            }
        }
        let ended: Vec<_> = host
            .notices()
            .into_iter()
            .filter(|n| matches!(n, StreamNotice::SyncWaitEnded { .. }))
            .cloned()
            .collect();
        assert_eq!(ended, [StreamNotice::SyncWaitEnded { latest_sync: false }]);
        let first = first_written.unwrap();
        assert!(
            (DEFAULT_MAX_LATENCY.as_secs_f64()..1.76).contains(&first),
            "{first}"
        );
        assert!(host.placings().is_empty());
        assert_eq!(host.heard.len(), 400);
        assert!(host.heard.iter().all(|h| h.due.is_none() && h.ratio == 1.0));
        assert_eq!(host.stream.stats().playout.unscheduled, 400);
    }

    /// A sink still starting holds the stream for one hold; then the stream plays as it comes,
    /// and is placed once the device reports a delay.
    #[test]
    fn a_device_that_does_not_start_is_waited_for_once() {
        let mut host = Host::new();
        host.device.starting_until = 2.5;
        let mut sender = Sender::new(0.0, 1_000, SEQ0);
        host.play(&mut sender, 0..600, &[]);
        let given_up = host
            .notices()
            .into_iter()
            .filter(|n| matches!(n, StreamNotice::DeviceNotStarted))
            .count();
        assert_eq!(given_up, 1);
        assert_eq!(host.placings(), [true]);
        assert!(host.stream.stats().playout.unscheduled > 50);
    }

    /// After a `FLUSH`, a sync packet naming a time up to [`SYNC_BEHIND_FLUSH_FRAMES`] before its
    /// `rtptime` ends the wait; one from further back (before a seek) does not, nor one further
    /// ahead than a hold.
    #[test]
    fn a_sync_just_behind_the_flush_ends_the_wait_and_a_stale_one_does_not() {
        let mut stream =
            RealtimeStream::new(KEY, format(), RealtimeStreamConfig::default()).unwrap();
        let sync = |now: u32| {
            let now = RtpTimestamp::new(now);
            SyncPacket::new(false, now - 8_820, NtpTimestamp::from_parts(1, 0), now).encode()
        };
        for (now, accepted) in [
            (100_000 - 5_000, false),
            (100_000 + 200_000, false),
            (100_000 - SYNC_BEHIND_FLUSH_FRAMES, true),
            (100_000 - SYNC_BEHIND_FLUSH_FRAMES - 1, false),
        ] {
            stream.flush(None, Some(RtpTimestamp::new(100_000)));
            stream.on_control(&sync(now)).unwrap();
            while stream
                .poll(Duration::ZERO, None, SinkDelay::Unknown)
                .is_some()
            {}
            assert_eq!(!stream.awaiting_sync(), accepted, "{now}");
        }
        stream.flush(None, Some(RtpTimestamp::new(100_000)));
        stream.on_control(&sync(100_000 + 352)).unwrap();
        while stream
            .poll(Duration::ZERO, None, SinkDelay::Unknown)
            .is_some()
        {}
        assert!(!stream.awaiting_sync());
        assert_eq!(stream.flush_rtp, None);
    }

    /// Feeds sync packets `k = 0, 125, ...` (one a second) to a bare stream, each heard `jitter(i)`
    /// seconds late and on a local clock `skew` times the sender's; after each, the fit and the
    /// ratio the stream would play as-it-comes packets by.
    fn drift_series(
        count: u64,
        skew: f64,
        jitter: impl Fn(u64) -> f64,
    ) -> Vec<(super::super::clock::DriftEstimate, f64)> {
        let mut stream =
            RealtimeStream::new(KEY, format(), RealtimeStreamConfig::default()).unwrap();
        let sender = Sender::new(0.0, 1_000, SEQ0);
        let mut seen = Vec::new();
        for i in 0..count {
            let k = i * 125;
            stream.on_control(&sender.sync(k)).unwrap();
            let now = secs(sent_at(0.0, k) * skew + jitter(i));
            while let Some(out) = stream.poll(now, None, SinkDelay::Unknown) {
                if let StreamOutput::Notice(StreamNotice::Sync { drift }) = out {
                    seen.push((drift, stream.drift_ratio));
                }
            }
        }
        seen
    }

    /// A clean series of sync packets from a sender 300 ppm off is applied from the sixteenth packet,
    /// and not before.
    #[test]
    fn a_clean_drift_fit_is_applied_from_the_minimum_packet_count() {
        let seen = drift_series(20, 1.0 - 300e-6, |_| 0.0);
        for (i, (drift, ratio)) in seen.iter().enumerate() {
            if drift.samples < DRIFT_MIN_SYNC_PACKETS {
                assert_eq!(*ratio, 1.0, "{i}: {drift:?}");
            } else {
                assert!((drift.ppm - 300.0).abs() < 5.0, "{i}: {drift:?}");
                assert_eq!(*ratio, drift.resample_ratio, "{i}: {drift:?}");
                assert!(*ratio < 0.9998, "{i}: {ratio}");
            }
        }
        assert_eq!(seen.last().unwrap().0.samples, 20);
    }

    /// Wi-Fi-sized timing noise (tens of milliseconds) swings the early fit to the clamp. Such a
    /// fit is never applied, however many packets it has; the ratio stays 1.0 until a fit inside
    /// the clamp arrives.
    #[test]
    fn a_noisy_early_drift_fit_at_the_clamp_is_not_applied() {
        const JITTER_MS: [f64; 8] = [0.0, 40.0, -30.0, 35.0, -40.0, 30.0, 40.0, -25.0];
        let seen = drift_series(16, 1.0, |i| JITTER_MS[i as usize % 8] / 1000.0);
        let clamped = seen
            .iter()
            .filter(|(d, _)| d.ppm.abs() >= MAX_DRIFT_PPM)
            .count();
        assert!(clamped >= 3, "the series must hit the clamp: {seen:?}");
        assert!(
            seen.iter().any(|(d, r)| d.samples < DRIFT_MIN_SYNC_PACKETS
                && d.ppm.abs() < MAX_DRIFT_PPM
                && d.ppm.abs() > 300.0
                && *r == 1.0),
            "an early fit inside the clamp is not applied either: {seen:?}"
        );
        for (drift, ratio) in &seen {
            if drift.ppm.abs() >= MAX_DRIFT_PPM || drift.samples < DRIFT_MIN_SYNC_PACKETS {
                assert_eq!(*ratio, 1.0, "{drift:?}");
            }
        }
    }

    /// A repeated sync packet is taken once; each new one is, with the drift so far.
    #[test]
    fn each_new_sync_packet_is_observed_once() {
        let mut stream =
            RealtimeStream::new(KEY, format(), RealtimeStreamConfig::default()).unwrap();
        let sender = Sender::new(0.0, 1_000, SEQ0);
        let mut syncs = 0;
        for k in [0, 0, 125, 250, 250] {
            stream.on_control(&sender.sync(k)).unwrap();
            let now = secs(sent_at(0.0, k));
            while let Some(out) = stream.poll(now, None, SinkDelay::Unknown) {
                if let StreamOutput::Notice(StreamNotice::Sync { drift }) = out {
                    syncs += 1;
                    // A fit needs two.
                    assert_eq!(drift.samples, if syncs < 2 { 0 } else { syncs });
                }
            }
        }
        assert_eq!(syncs, 3);
        assert_eq!(stream.clock().samples(), 3);
        assert_eq!(stream.stats().receive.sync_packets, 5);
    }

    /// Of the sync packets that arrive between two polls, only the newest is taken: one for the
    /// new timeline followed by one from before the `FLUSH` does not end the wait, and the reverse
    /// does, each with one observation at the poll's now.
    #[test]
    fn of_a_burst_of_sync_packets_only_the_newest_is_taken() {
        let flushed = RtpTimestamp::new(100_000);
        let sync = |now: u32| {
            let now = RtpTimestamp::new(now);
            SyncPacket::new(false, now - 8_820, NtpTimestamp::from_parts(1, 0), now).encode()
        };
        let (fresh, stale) = (sync(100_352), sync(40_000));
        for (burst, ends_wait) in [([fresh, stale], false), ([stale, fresh], true)] {
            let mut stream =
                RealtimeStream::new(KEY, format(), RealtimeStreamConfig::default()).unwrap();
            stream.flush(None, Some(flushed));
            for packet in burst {
                stream.on_control(&packet).unwrap();
            }
            assert!(stream.awaiting_sync(), "nothing taken before a poll");
            let mut notices = 0;
            while let Some(out) = stream.poll(secs(1.0), None, SinkDelay::Unknown) {
                assert!(matches!(
                    out,
                    StreamOutput::Notice(StreamNotice::Sync { .. })
                ));
                notices += 1;
            }
            assert_eq!(notices, 1);
            assert_eq!(stream.clock().samples(), 1);
            assert_eq!(!stream.awaiting_sync(), ends_wait);
            assert_eq!(stream.stats().receive.sync_packets, 2);
        }
    }

    /// The hold keeps a hold's worth of packets, but never more than [`MAX_HELD_PACKETS`],
    /// however small the packets or long the hold.
    #[test]
    fn the_hold_is_bounded_by_frames_and_by_packets() {
        let held = |rate: u32, spf: u32, hold: Duration| {
            let format =
                AudioStreamFormat::new(compression::LPCM, audio_format::PCM_44100_16_2, rate, spf);
            let config = RealtimeStreamConfig {
                hold_limit: hold,
                ..RealtimeStreamConfig::default()
            };
            RealtimeStream::new(KEY, format, config).unwrap().most_held
        };
        assert_eq!(held(44_100, 352, DEFAULT_MAX_LATENCY), 221);
        assert_eq!(held(8_000, 4_096, DEFAULT_MAX_LATENCY), 5);
        assert_eq!(held(192_000, 1, DEFAULT_MAX_LATENCY), MAX_HELD_PACKETS);
        assert_eq!(held(44_100, 352, Duration::MAX), MAX_HELD_PACKETS);
        assert_eq!(held(44_100, 352, Duration::ZERO), 1);
    }

    #[cfg(feature = "mirror")]
    #[test]
    fn a_wrapped_key_setup_is_refused() {
        let mut setup = AudioStreamSetup {
            stream_type: 96,
            format: format(),
            shared_key: KEY,
            data_port: 1,
            control_port: 2,
            sender_control_port: 3,
            unencrypted: false,
            aes_cbc_key: None,
        };
        assert!(RealtimeStream::from_setup(&setup, RealtimeStreamConfig::default()).is_ok());
        setup.aes_cbc_key = Some(super::super::connection::AesCbcAudioKey {
            key: [1; 16],
            iv: [2; 16],
        });
        assert!(RealtimeStream::from_setup(&setup, RealtimeStreamConfig::default()).is_err());
    }
}
