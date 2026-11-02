//! A buffered (`type: 103`) stream end to end, sans-io: [`BufferedReceiver`] and
//! [`PacketDecoder`] with the queue and the placement a receiver plays one by. No socket, thread
//! or sink.
//!
//! The host feeds the TCP data connection's bytes to [`BufferedStream::on_data`] (reading only
//! while [`BufferedStream::wants_data`]), hands it `SETRATEANCHORTIME`, `FLUSH` and a replaced
//! connection, and drains [`BufferedStream::poll`] (see [`super::stream`]) with its clock's now and
//! a [`PtpReading`] of the sender's PTP clock on that same clock.
//!
//! - A packet is due at the anchor's network time plus its RTP distance from the anchor, moved by
//!   the PTP offset; it is scheduled only while the clock followed is the anchor's timeline. Any
//!   non-zero rate plays at 1; a rate-0 anchor pauses (the queue is kept).
//! - Packets wait, decoded (at most [`BufferedStreamConfig::max_queued`]), until due within the
//!   sink's floor (its first delay, capped at [`BufferedStreamConfig::max_latency`]) plus
//!   [`BufferedStreamConfig::write_ahead`].
//! - The first packet, and any after a flush, a new mapping, a break in RTP time or a sustained
//!   error, is placed: silence ahead if early, frames off its head if late, dropped if wholly late.
//!   An error past [`super::playout::RESYNC_THRESHOLD`] is sustained once it has held in one
//!   direction for [`super::playout::SUSTAINED_ERROR_TIME`] of consecutive audio, or at once past
//!   [`super::playout::GROSS_ERROR`] (the realtime playout's rule); until then the packet is an
//!   outlier, written as it is and counted in [`BufferedStreamStats::ignored_outliers`], and a
//!   packet back inside the threshold ends the run. A sink that cannot say its delay is placed by
//!   the clock once and never re-placed. No resampling: drift between two machines is not
//!   corrected.
//! - A `FLUSH` drops what is queued from before its `rtptime`, and anything still arriving from
//!   before it; without one, everything received so far and packets from before the last one. A
//!   play anchor on a new mapping ends that filter.
//!
//! Unproven beyond this crate's own sender and receiver on one machine; no Apple buffered stream.

use std::collections::VecDeque;
use std::time::Duration;

use super::audio::{AudioStreamFormat, PacketDecoder};
use super::buffered::{BufferedReceiver, BufferedStats};
use super::connection::BufferedAudioStreamSetup;
use super::playout::{Playout, GROSS_ERROR, RESYNC_THRESHOLD, SUSTAINED_ERROR_TIME};
use super::realtime_stream::DEFAULT_MAX_LATENCY;
use super::stream::{ScheduledPacket, SinkDelay, StreamNotice, StreamOutput, MAX_QUEUED_NOTICES};
use crate::audio::control::RateAnchor;
use crate::error::Result;
use crate::time::RtpTimestamp;

/// The default for [`BufferedStreamConfig::write_ahead`]: about what a realtime stream holds.
pub const DEFAULT_WRITE_AHEAD: Duration = Duration::from_millis(250);

/// The default for [`BufferedStreamConfig::max_queued`].
pub const DEFAULT_MAX_QUEUED: Duration = Duration::from_secs(8);

const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// How a [`BufferedStream`] plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedStreamConfig {
    /// The cap on the sink's floor, so a sink reporting a huge delay cannot make a placement write
    /// minutes of silence.
    pub max_latency: Duration,
    /// The longest the stream waits for a sink that is starting.
    pub hold_limit: Duration,
    /// How far ahead of the instant it is due, beyond the sink's floor, a packet is handed out.
    pub write_ahead: Duration,
    /// The most decoded audio queued; past it nothing more is decoded and
    /// [`BufferedStream::wants_data`] says not to read.
    pub max_queued: Duration,
}

impl Default for BufferedStreamConfig {
    fn default() -> Self {
        Self {
            max_latency: DEFAULT_MAX_LATENCY,
            hold_limit: DEFAULT_MAX_LATENCY,
            write_ahead: DEFAULT_WRITE_AHEAD,
            max_queued: DEFAULT_MAX_QUEUED,
        }
    }
}

/// The sender's PTP clock as the host's follower sees it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpReading {
    /// The grandmaster followed, once identified.
    pub grandmaster: Option<u64>,
    /// Local minus master, in nanoseconds ([`crate::audio::ptp::one_way_offset`]), on the clock
    /// the host's now is read from.
    pub offset_nanos: Option<i128>,
}

impl PtpReading {
    /// A reading.
    #[must_use]
    pub fn new(grandmaster: Option<u64>, offset_nanos: Option<i128>) -> Self {
        Self {
            grandmaster,
            offset_nanos,
        }
    }
}

/// What [`BufferedStream::set_anchor`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnchorChange {
    /// The anchor only restated the mapping (same timeline, same RTP-to-time line): nothing
    /// changed.
    pub same_mapping: bool,
    /// What the sink holds was placed on the old mapping: flush it.
    pub flush_sink: bool,
}

/// What a [`BufferedStream`] has seen and done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedStreamStats {
    /// Packets decrypted, over every data connection.
    pub packets_opened: u64,
    /// Packets that did not decrypt or parse.
    pub packets_rejected: u64,
    /// Packets that opened and did not decode.
    pub packets_undecodable: u64,
    /// Packets decoded.
    pub packets_decoded: u64,
    /// Packets dropped: by a flush, as arriving from before one, or wholly late.
    pub packets_dropped: u64,
    /// Packets placed afresh.
    pub packets_placed: u64,
    /// Placements of a packet that followed the last after a sustained error past the threshold,
    /// or one past the gross bound.
    pub resyncs: u64,
    /// Packets that followed the last, were heard off by more than the threshold and were written
    /// as they were: outliers, including the packets of a run that later became a resync.
    pub ignored_outliers: u64,
    /// Frames of silence handed out ahead of packets.
    pub silence_frames: u64,
    /// Frames dropped from heads, wholly late packets included.
    pub skipped_frames: u64,
    /// Packets handed out to be written.
    pub packets_played: u64,
    /// How far off the last packet placed against a known sink delay is heard, in nanoseconds:
    /// under a frame after a placement.
    pub error_nanos: Option<i128>,
    /// The PTP offset last scheduled by (local minus master, nanoseconds).
    pub offset_nanos: Option<i128>,
}

/// One decoded packet waiting for its time.
struct Queued {
    rtp: RtpTimestamp,
    sequence: u32,
    samples: Vec<i16>,
}

/// One buffered stream, from the data connection's bytes to placed PCM. See the module docs.
pub struct BufferedStream {
    key: [u8; 32],
    sample_rate: u32,
    channels: u8,
    receiver: BufferedReceiver,
    decoder: PacketDecoder,
    config: BufferedStreamConfig,
    /// [`BufferedStreamConfig::max_queued`] in frames.
    max_queued: u64,
    /// Opened packets wait undecoded because the queue is full.
    backlog: bool,
    queue: VecDeque<Queued>,
    queued_frames: u64,
    begun: bool,
    /// Placed since the last flush, anchor or break, and `next_rtp` follows.
    placed: bool,
    next_rtp: RtpTimestamp,
    /// Seconds of consecutive audio whose error has stayed past the threshold, and its sign.
    outlier_secs: f64,
    outlier_late: bool,
    /// The RTP time just past the last packet decoded.
    received_end: Option<RtpTimestamp>,
    /// The sink's first delay, capped.
    floor: Option<Duration>,
    starting_since: Option<Duration>,
    /// A `FLUSH`'s `rtptime`: packets before it still arriving are dropped.
    flushed_before: Option<RtpTimestamp>,
    other_timeline_noticed: bool,
    /// Receive counters of data connections already replaced.
    earlier: BufferedStats,
    stats: BufferedStreamStats,
    out: VecDeque<StreamOutput>,
}

impl std::fmt::Debug for BufferedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedStream")
            .field("sample_rate", &self.sample_rate)
            .field("channels", &self.channels)
            .field("queued", &self.queue.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// The offset to schedule `anchor` by: only while the clock followed is the anchor's timeline.
fn clock_for(anchor: RateAnchor, ptp: PtpReading) -> Option<i128> {
    (ptp.grandmaster == Some(anchor.timeline_id))
        .then_some(ptp.offset_nanos)
        .flatten()
}

/// Whether `new` only restates `old`'s mapping: both play, on the same timeline, and `new`'s RTP
/// time falls where `old` already put it, to within a frame.
fn same_mapping(old: RateAnchor, new: RateAnchor, sample_rate: u32) -> bool {
    if old.rate == 0 || new.rate == 0 || old.timeline_id != new.timeline_id {
        return false;
    }
    let rate = i128::from(sample_rate.max(1));
    let frames = i128::from(new.rtp_time.signed_frames_since(old.rtp_time));
    let expected = frames * NANOS_PER_SECOND / rate;
    let actual = nanos_i128(new.network_time.to_nanos()) - nanos_i128(old.network_time.to_nanos());
    (actual - expected).abs() <= NANOS_PER_SECOND / rate
}

fn nanos_i128(nanos: u128) -> i128 {
    i128::try_from(nanos).unwrap_or(i128::MAX)
}

impl BufferedStream {
    /// A stream with the `SETUP`'s `shk` and format.
    ///
    /// # Errors
    ///
    /// A format [`PacketDecoder::new`] refuses.
    pub fn new(
        key: [u8; 32],
        format: AudioStreamFormat,
        config: BufferedStreamConfig,
    ) -> Result<Self> {
        let decoder = PacketDecoder::new(format)?;
        let sample_rate = format.sample_rate.max(1);
        // Saturating float-to-int: the cap is a few seconds of frames.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let max_queued = (config.max_queued.as_secs_f64() * f64::from(sample_rate)) as u64;
        Ok(Self {
            key,
            sample_rate,
            channels: format.channels.max(1),
            receiver: BufferedReceiver::new(key, sample_rate),
            decoder,
            config,
            max_queued,
            backlog: false,
            queue: VecDeque::new(),
            queued_frames: 0,
            begun: false,
            placed: false,
            next_rtp: RtpTimestamp::default(),
            outlier_secs: 0.0,
            outlier_late: false,
            received_end: None,
            floor: None,
            starting_since: None,
            flushed_before: None,
            other_timeline_noticed: false,
            earlier: BufferedStats::default(),
            stats: BufferedStreamStats::default(),
            out: VecDeque::new(),
        })
    }

    /// A stream for what a buffered stream `SETUP` negotiated.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn from_setup(
        setup: &BufferedAudioStreamSetup,
        config: BufferedStreamConfig,
    ) -> Result<Self> {
        Self::new(setup.shared_key, setup.format, config)
    }

    /// Frames per second.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Channels.
    #[must_use]
    pub fn channels(&self) -> u8 {
        self.channels
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> BufferedStreamConfig {
        self.config
    }

    /// The anchor, if one has arrived.
    #[must_use]
    pub fn anchor(&self) -> Option<RateAnchor> {
        self.receiver.anchor()
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> BufferedStreamStats {
        self.stats
    }

    /// Decoded packets waiting for their time.
    #[must_use]
    pub fn queued_packets(&self) -> usize {
        self.queue.len()
    }

    /// Decoded frames waiting for their time.
    #[must_use]
    pub fn queued_frames(&self) -> u64 {
        self.queued_frames
    }

    /// Whether to read the data connection: there is room, and nothing opened waits undecoded.
    /// Not reading lets TCP's flow control slow the sender.
    #[must_use]
    pub fn wants_data(&self) -> bool {
        !self.backlog && self.queued_frames < self.max_queued
    }

    /// Bytes from the data connection: each whole frame is decrypted and decoded, in order, up to
    /// the queue's cap. A packet that does not open or decode is dropped and counted.
    ///
    /// # Errors
    ///
    /// A malformed length prefix: the connection's framing is broken. What came before it is kept.
    pub fn on_data(&mut self, bytes: &[u8]) -> Result<()> {
        let fed = self.receiver.on_data(bytes);
        self.decode();
        fed
    }

    /// The sender opened another data connection in place of the old one: whatever the old one
    /// left half read is dropped. The anchor, the queue and the counters stay.
    pub fn restart_connection(&mut self) {
        let old = self.receiver.stats();
        self.earlier.packets_opened += old.packets_opened;
        self.earlier.packets_rejected += old.packets_rejected;
        let anchor = self.receiver.anchor();
        self.receiver = BufferedReceiver::new(self.key, self.sample_rate);
        if let Some(anchor) = anchor {
            self.receiver.set_anchor(anchor);
        }
        self.backlog = false;
    }

    /// A `SETRATEANCHORTIME`. One that restates the mapping changes nothing; otherwise the next
    /// packet is placed afresh, and a play anchor ends a `FLUSH`'s filter (the sender may go on
    /// from a lower RTP time). A rate-0 anchor pauses, keeping the queue.
    pub fn set_anchor(&mut self, anchor: RateAnchor) -> AnchorChange {
        let same_mapping = self
            .receiver
            .anchor()
            .is_some_and(|old| same_mapping(old, anchor, self.sample_rate));
        self.receiver.set_anchor(anchor);
        let mut flush_sink = false;
        if !same_mapping {
            flush_sink = self.placed;
            self.placed = false;
            self.drop_pending();
            if anchor.rate != 0 {
                self.flushed_before = None;
            }
        }
        AnchorChange {
            same_mapping,
            flush_sink,
        }
    }

    /// `FLUSH` with its `rtptime`, if any: drops what is queued from before it, and anything still
    /// arriving from before it; without one, everything received so far (the frame half read too)
    /// and packets from before the last one. How many packets went. Flush the sink too, once it
    /// has begun.
    pub fn flush(&mut self, rtp_time: Option<RtpTimestamp>) -> u64 {
        let before = self.queue.len();
        match rtp_time {
            Some(flushed) => {
                self.queue.retain(|q| !flushed.is_after(q.rtp));
                self.flushed_before = Some(flushed);
            }
            None => {
                self.queue.clear();
                self.flushed_before = self.received_end;
            }
        }
        let channels = usize::from(self.channels);
        self.queued_frames = self
            .queue
            .iter()
            .map(|q| (q.samples.len() / channels) as u64)
            .sum();
        self.placed = false;
        self.drop_pending();
        let mut dropped = (before - self.queue.len()) as u64;
        if rtp_time.is_none() {
            dropped += self.receiver.flush();
            self.backlog = false;
        }
        self.stats.packets_dropped += dropped;
        dropped
    }

    /// The next thing for the host to do, at `now` on the clock the PTP offset is measured against,
    /// with the follower's reading and the sink's delay read now. `None` when nothing is due.
    pub fn poll(
        &mut self,
        now: Duration,
        ptp: PtpReading,
        sink: SinkDelay,
    ) -> Option<StreamOutput> {
        if let Some(out) = self.out.pop_front() {
            return Some(out);
        }
        self.decode();
        if let Some(out) = self.out.pop_front() {
            return Some(out);
        }
        self.place_next(now, ptp, sink);
        self.out.pop_front()
    }

    fn notice(&mut self, notice: StreamNotice) {
        if self.out.len() < MAX_QUEUED_NOTICES {
            self.out.push_back(StreamOutput::Notice(notice));
        }
    }

    /// Placement outputs not yet taken are stale.
    fn drop_pending(&mut self) {
        self.out
            .retain(|out| !matches!(out, StreamOutput::Silence(_) | StreamOutput::Packet(_)));
    }

    /// Opened packets to decoded, queued PCM, up to the cap.
    fn decode(&mut self) {
        loop {
            if self.queued_frames >= self.max_queued {
                self.backlog = true;
                break;
            }
            let Some(packet) = self.receiver.next_packet() else {
                self.backlog = false;
                break;
            };
            if self
                .flushed_before
                .is_some_and(|flushed| flushed.is_after(packet.rtp_time))
            {
                self.stats.packets_dropped += 1;
                continue;
            }
            self.flushed_before = None;
            match self.decoder.decode(&packet.payload) {
                Ok(samples) => {
                    self.stats.packets_decoded += 1;
                    self.offer(packet.rtp_time, packet.sequence, samples);
                }
                Err(e) => {
                    self.stats.packets_undecodable += 1;
                    self.notice(StreamNotice::DecodeFailed {
                        sequence: Some(packet.sequence),
                        error: e.to_string(),
                    });
                }
            }
        }
        let now = self.receiver.stats();
        self.stats.packets_opened = self.earlier.packets_opened + now.packets_opened;
        self.stats.packets_rejected = self.earlier.packets_rejected + now.packets_rejected;
    }

    fn offer(&mut self, rtp: RtpTimestamp, sequence: u32, samples: Vec<i16>) {
        if !self.begun {
            self.begun = true;
            self.out.push_back(StreamOutput::Begin {
                sample_rate: self.sample_rate,
                channels: self.channels,
                sequence,
            });
        }
        let frames = (samples.len() / usize::from(self.channels)) as u64;
        self.queued_frames += frames;
        self.received_end = Some(rtp.wrapping_add(u32::try_from(frames).unwrap_or(0)));
        self.queue.push_back(Queued {
            rtp,
            sequence,
            samples,
        });
    }

    /// Whole frames in `nanos`, rounded down; none for a negative span.
    fn frames(&self, nanos: i128) -> u64 {
        let frames = nanos.max(0).saturating_mul(i128::from(self.sample_rate)) / NANOS_PER_SECOND;
        u64::try_from(frames).unwrap_or(u64::MAX)
    }

    /// Nanoseconds in `frames`.
    fn nanos(&self, frames: u64) -> i128 {
        i128::from(frames) * NANOS_PER_SECOND / i128::from(self.sample_rate)
    }

    /// Hands out the oldest queued packet if it is due, placing it when it must be.
    fn place_next(&mut self, now: Duration, ptp: PtpReading, sink: SinkDelay) {
        let Some(anchor) = self.receiver.anchor() else {
            return;
        };
        if anchor.rate == 0 {
            return;
        }
        let Some(offset) = clock_for(anchor, ptp) else {
            if ptp.offset_nanos.is_some() && !self.other_timeline_noticed {
                self.other_timeline_noticed = true;
                self.notice(StreamNotice::OtherTimeline {
                    anchor: anchor.timeline_id,
                    followed: ptp.grandmaster,
                });
            }
            return;
        };
        self.stats.offset_nanos = Some(offset);
        let Some(head) = self.queue.front() else {
            return;
        };
        let Some(due) = self.receiver.play_nanos(head.rtp, offset) else {
            return;
        };
        let (delay, measured) = match sink {
            SinkDelay::Known(delay) => {
                self.starting_since = None;
                (delay, true)
            }
            SinkDelay::Unknown => (Duration::ZERO, false),
            SinkDelay::Starting => {
                let since = *self.starting_since.get_or_insert(now);
                if now.saturating_sub(since) < self.config.hold_limit {
                    return;
                }
                (Duration::ZERO, false)
            }
        };
        let floor = *self.floor.get_or_insert(delay.min(self.config.max_latency));
        let now = nanos_i128(now.as_nanos());
        let lead = due.saturating_sub(now);
        let ahead = floor.saturating_add(self.config.write_ahead);
        if lead > nanos_i128(ahead.as_nanos()) {
            return;
        }
        let Some(packet) = self.queue.pop_front() else {
            return;
        };
        let frames = (packet.samples.len() / usize::from(self.channels)) as u64;
        self.queued_frames = self.queued_frames.saturating_sub(frames);
        // Positive: heard late.
        let error = now
            .saturating_add(nanos_i128(delay.as_nanos()))
            .saturating_sub(due);
        let follows = self.placed && packet.rtp == self.next_rtp;
        #[allow(clippy::cast_possible_truncation)]
        let threshold = (RESYNC_THRESHOLD * 1e9) as i128;
        #[allow(clippy::cast_possible_truncation)]
        let gross = (GROSS_ERROR * 1e9) as i128;
        let within = !measured || error.unsigned_abs() <= threshold.unsigned_abs();
        #[allow(clippy::cast_precision_loss)]
        let seconds = |nanos: i128| nanos as f64 / 1e9;
        // Past the threshold, a packet that follows the last is re-placed only when the error is
        // gross or has held in one direction for a sustained time; until then it is an outlier.
        let mut resync = false;
        if follows && !within {
            if error.unsigned_abs() > gross.unsigned_abs() {
                resync = true;
            } else {
                let late = error > 0;
                if self.outlier_secs > 0.0 && late != self.outlier_late {
                    self.outlier_secs = 0.0;
                }
                self.outlier_late = late;
                #[allow(clippy::cast_precision_loss)]
                {
                    self.outlier_secs += frames as f64 / f64::from(self.sample_rate.max(1));
                }
                if self.outlier_secs >= SUSTAINED_ERROR_TIME {
                    resync = true;
                } else {
                    self.stats.ignored_outliers += 1;
                }
            }
        } else {
            self.outlier_secs = 0.0;
        }
        let mut silence = 0u64;
        let mut skip = 0u64;
        // How far off the packet's first frame is heard once placed: under a frame either way.
        let mut heard_error = error;
        if !follows || resync {
            self.outlier_secs = 0.0;
            if follows {
                self.stats.resyncs += 1;
            }
            if error < 0 {
                silence = self.frames(error.saturating_neg());
                self.stats.silence_frames = self.stats.silence_frames.saturating_add(silence);
                heard_error = error.saturating_add(self.nanos(silence));
            } else {
                skip = self.frames(error);
                if skip >= frames {
                    // Wholly late: none of it is heard, and the next packet is placed afresh.
                    self.stats.skipped_frames = self.stats.skipped_frames.saturating_add(frames);
                    self.stats.packets_dropped += 1;
                    self.placed = false;
                    let dropped = self.packet(
                        packet,
                        due,
                        None,
                        Playout::Drop {
                            error: seconds(error),
                        },
                    );
                    self.out.push_back(StreamOutput::Packet(dropped));
                    return;
                }
                self.stats.skipped_frames = self.stats.skipped_frames.saturating_add(skip);
                heard_error = error.saturating_sub(self.nanos(skip));
            }
            self.stats.packets_placed += 1;
            self.placed = true;
            if silence > 0 {
                self.out.push_back(StreamOutput::Silence(
                    u32::try_from(silence).unwrap_or(u32::MAX),
                ));
            }
            self.notice(StreamNotice::Placed {
                timestamp: packet.rtp,
                error: seconds(error),
                sink_delay: measured.then_some(delay),
            });
        }
        if measured {
            self.stats.error_nanos = Some(heard_error);
        }
        self.next_rtp = packet.rtp.wrapping_add(u32::try_from(frames).unwrap_or(0));
        self.stats.packets_played += 1;
        let skip = u32::try_from(skip).unwrap_or(u32::MAX);
        let placement = Playout::Play {
            silence: u32::try_from(silence).unwrap_or(u32::MAX),
            skip,
            correction_ppm: 0.0,
            error: seconds(error),
        };
        let packet = self.packet(packet, due, Some(skip), placement);
        self.out.push_back(StreamOutput::Packet(packet));
    }

    fn packet(
        &self,
        queued: Queued,
        due: i128,
        skip: Option<u32>,
        placement: Playout,
    ) -> ScheduledPacket {
        ScheduledPacket {
            samples: queued.samples,
            channels: self.channels,
            sample_rate: self.sample_rate,
            sequence: queued.sequence,
            timestamp: queued.rtp,
            concealed: false,
            skip,
            resample_ratio: 1.0,
            due: u64::try_from(due).ok().map(Duration::from_nanos),
            placement,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::format::{audio_format, compression};
    use crate::audio::ptp::NetworkTime;
    use crate::audio::rtp::{frame_buffered, BufferedHeader, PacketSealer};

    const KEY: [u8; 32] = [5; 32];
    const RATE: u32 = 48_000;
    const SPF: usize = 352;
    const MS: i128 = 1_000_000;
    /// A packet's length, in nanoseconds.
    const PACKET: i128 = SPF as i128 * NANOS_PER_SECOND / RATE as i128;
    const TIMELINE: u64 = 7;

    fn rtp(value: u32) -> RtpTimestamp {
        RtpTimestamp::new(value)
    }

    fn format(rate: u32) -> AudioStreamFormat {
        AudioStreamFormat::new(
            compression::LPCM,
            audio_format::PCM_44100_16_2,
            rate,
            u32::try_from(SPF).unwrap(),
        )
    }

    fn stream() -> BufferedStream {
        BufferedStream::new(KEY, format(RATE), BufferedStreamConfig::default()).unwrap()
    }

    /// A stream whose packet at RTP time `r` is due at `base + r / RATE` (master and local clocks
    /// agree).
    fn anchored(base: i128) -> BufferedStream {
        let mut s = stream();
        s.set_anchor(RateAnchor::play(
            NetworkTime::from_nanos(u128::try_from(base).unwrap()),
            TIMELINE,
            rtp(0),
        ));
        s
    }

    /// A loud packet (never mistaken for silence) at `at`.
    fn offer(s: &mut BufferedStream, at: u32) {
        s.offer(rtp(at), at, vec![1000; SPF * 2]);
    }

    fn frames_of(ns: i128) -> usize {
        usize::try_from(ns * i128::from(RATE) / NANOS_PER_SECOND).unwrap()
    }

    fn nanos(ns: i128) -> Duration {
        Duration::from_nanos(u64::try_from(ns).unwrap())
    }

    /// A sink that records each write's length in frames and whether it was all silence.
    struct Sink {
        delay: SinkDelay,
        writes: Vec<(usize, bool)>,
    }

    impl Sink {
        fn new(delay: SinkDelay) -> Self {
            Self {
                delay,
                writes: Vec::new(),
            }
        }
    }

    /// Acts on everything due at `now` with the follower reading `ptp`; whether a packet was
    /// written.
    fn pump_with(s: &mut BufferedStream, sink: &mut Sink, now: i128, ptp: PtpReading) -> bool {
        let mut wrote = false;
        while let Some(out) = s.poll(nanos(now), ptp, sink.delay) {
            match out {
                StreamOutput::Silence(frames) => {
                    sink.writes.push((usize::try_from(frames).unwrap(), true));
                }
                StreamOutput::Packet(packet) if packet.skip.is_some() => {
                    let audible = packet.audible();
                    sink.writes
                        .push((audible.len() / 2, audible.iter().all(|v| *v == 0)));
                    wrote = true;
                }
                _ => {}
            }
        }
        wrote
    }

    fn pump_at(s: &mut BufferedStream, sink: &mut Sink, now: i128) -> bool {
        pump_with(s, sink, now, PtpReading::new(Some(TIMELINE), Some(0)))
    }

    #[test]
    fn a_flush_across_the_rtp_wrap_drops_only_what_lies_before_it() {
        let mut s = stream();
        for at in [u32::MAX - SPF as u32 + 1, 0, SPF as u32] {
            offer(&mut s, at);
        }
        assert_eq!(
            s.flush(Some(rtp(0))),
            1,
            "only the packet just before the wrap"
        );
        assert_eq!(s.queue.front().map(|q| q.rtp), Some(rtp(0)));
        assert_eq!(s.flushed_before, Some(rtp(0)));
        assert_eq!(s.stats().packets_dropped, 1);
    }

    #[test]
    fn a_packet_not_yet_due_waits() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        offer(&mut s, 0);
        // Due a second from now: past the floor (0) plus the write-ahead (250 ms).
        assert!(!pump_at(&mut s, &mut sink, 9_000 * MS));
        assert!(sink.writes.is_empty());
        assert_eq!(s.queued_packets(), 1);
    }

    #[test]
    fn an_early_first_packet_is_preceded_by_silence() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        offer(&mut s, 0);
        assert!(pump_at(&mut s, &mut sink, 9_900 * MS));
        assert_eq!(sink.writes, vec![(frames_of(100 * MS), true), (SPF, false)]);
        assert_eq!(s.stats().packets_placed, 1);
        assert_eq!(s.stats().silence_frames, 4_800);
        assert_eq!(s.stats().error_nanos, Some(0));
    }

    #[test]
    fn a_late_first_packet_loses_its_head() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        offer(&mut s, 0);
        assert!(pump_at(&mut s, &mut sink, 10_002 * MS));
        assert_eq!(sink.writes, vec![(SPF - 96, false)]);
        assert_eq!(s.stats().skipped_frames, 96);
    }

    #[test]
    fn a_wholly_late_packet_is_dropped_and_the_next_one_placed() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        for at in [0, SPF as u32] {
            offer(&mut s, at);
        }
        // 10 ms late: the first packet (7.3 ms) is gone, the second loses its first 2.7 ms.
        assert!(pump_at(&mut s, &mut sink, 10_010 * MS));
        let skipped = frames_of(10 * MS - PACKET);
        assert_eq!(sink.writes, vec![(SPF - skipped, false)]);
        assert_eq!(s.stats().packets_dropped, 1);
        assert_eq!(s.stats().packets_placed, 1);
    }

    #[test]
    fn a_following_packet_is_written_as_is() {
        let base = 10_000 * MS;
        let mut s = anchored(base);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        let t0 = base - 200 * MS;
        offer(&mut s, 0);
        assert!(pump_at(&mut s, &mut sink, t0));
        // A moment later the sink holds the silence and the packet, less what it has played: the
        // next packet is heard exactly when it is due.
        let t1 = t0 + 5 * MS;
        sink.delay = SinkDelay::Known(nanos((base + PACKET) - t1));
        offer(&mut s, SPF as u32);
        assert!(pump_at(&mut s, &mut sink, t1));
        assert_eq!(s.stats().resyncs, 0);
        assert_eq!(s.stats().ignored_outliers, 0);
        assert_eq!(s.stats().packets_placed, 1);
    }

    /// Plays packet 0 (placed) and then one packet per entry of `errors` (nanoseconds heard late,
    /// per packet), each with a sink delay that makes it heard that far off. Returns the stream,
    /// the sink and the index of the first entry that was re-placed (a resync).
    fn run_errors(errors: &[i128]) -> (BufferedStream, Sink, Option<usize>) {
        let base = 10_000 * MS;
        let mut s = anchored(base);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        let t0 = base - 200 * MS;
        offer(&mut s, 0);
        assert!(pump_at(&mut s, &mut sink, t0));
        let mut first = None;
        for (i, error) in errors.iter().enumerate() {
            let n = i as i128 + 1;
            let now = t0 + n * PACKET;
            let due = base + n * PACKET;
            sink.delay = SinkDelay::Known(nanos(due - now + error));
            offer(&mut s, u32::try_from(n).unwrap() * SPF as u32);
            let before = s.stats().resyncs;
            // A packet heard late by more than itself is dropped, so nothing may be written.
            pump_at(&mut s, &mut sink, now);
            if first.is_none() && s.stats().resyncs > before {
                first = Some(i);
            }
        }
        (s, sink, first)
    }

    /// One packet heard 60 ms late, then back on time: written as it is, counted, no re-placement.
    #[test]
    fn an_isolated_error_spike_is_ignored() {
        let mut errors = vec![0; 40];
        errors[20] = 60 * MS;
        let (s, sink, first) = run_errors(&errors);
        assert_eq!(first, None);
        assert_eq!(s.stats().resyncs, 0);
        assert_eq!(s.stats().ignored_outliers, 1);
        assert_eq!(s.stats().packets_placed, 1);
        assert!(sink.writes.iter().skip(1).all(|w| *w == (SPF, false)));
    }

    /// A 70 ms error that stays is re-placed once, on the packet that completes 0.1 s of audio
    /// (14 packets of 352 frames at 48 kHz), and the 13 before it are outliers.
    #[test]
    fn a_sustained_error_is_placed_again_once_after_a_tenth_of_a_second() {
        let errors: Vec<i128> = (0..60).map(|i| if i >= 10 { 70 * MS } else { 0 }).collect();
        let (s, _, first) = run_errors(&errors);
        assert_eq!(first, Some(10 + 13));
        assert_eq!(s.stats().resyncs, 1);
        assert_eq!(s.stats().ignored_outliers, 13);
    }

    /// Past the gross bound the first packet is placed again.
    #[test]
    fn a_gross_error_is_placed_again_at_once() {
        let errors: Vec<i128> = (0..30)
            .map(|i| if i >= 10 { 600 * MS } else { 0 })
            .collect();
        let (s, _, first) = run_errors(&errors);
        assert_eq!(first, Some(10));
        assert_eq!(s.stats().resyncs, 1);
        assert_eq!(s.stats().ignored_outliers, 0);
    }

    /// Outliers that flip sign, or are cut by a packet back inside the threshold, do not add up.
    #[test]
    fn outliers_of_opposite_signs_or_with_a_good_packet_between_do_not_accumulate() {
        let flipping: Vec<i128> = (0..60)
            .map(|i| match i {
                0..=4 => 0,
                _ if i % 2 == 0 => 70 * MS,
                _ => -70 * MS,
            })
            .collect();
        let (s, _, first) = run_errors(&flipping);
        assert_eq!(first, None);
        assert_eq!(s.stats().resyncs, 0);
        let broken: Vec<i128> = (0..60)
            .map(|i| if i >= 5 && i % 10 != 0 { 70 * MS } else { 0 })
            .collect();
        let (s, _, first) = run_errors(&broken);
        assert_eq!(first, None);
        assert_eq!(s.stats().resyncs, 0);
        assert!(s.stats().ignored_outliers > 0);
    }

    /// A late run that turns early starts the count over: 10 late then 10 early outliers are
    /// 20 packets of outliers but never 14 of one sign.
    #[test]
    fn an_opposite_sign_packet_restarts_the_run() {
        let errors: Vec<i128> = (0..40)
            .map(|i| match i {
                0..=4 => 0,
                5..=14 => 70 * MS,
                _ => -70 * MS,
            })
            .collect();
        let (s, _, first) = run_errors(&errors);
        // The early run reaches 14 packets on its own, 14 packets after it began.
        assert_eq!(first, Some(15 + 13));
        assert_eq!(s.stats().resyncs, 1);
    }

    #[test]
    fn a_sink_that_cannot_say_is_placed_once_and_never_again() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Unknown);
        for at in [0, SPF as u32] {
            offer(&mut s, at);
        }
        // Both due within the write-ahead: the first is placed (silence), the second follows even
        // though, by the clock alone, it reads 100 ms early.
        assert!(pump_at(&mut s, &mut sink, 9_900 * MS));
        assert_eq!(
            sink.writes,
            vec![(frames_of(100 * MS), true), (SPF, false), (SPF, false)]
        );
        assert_eq!(s.stats().resyncs, 0);
        assert_eq!(s.stats().packets_placed, 1);
        assert_eq!(s.stats().error_nanos, None, "nothing measured");
    }

    #[test]
    fn a_starting_sink_holds_the_stream_for_a_hold() {
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Starting);
        offer(&mut s, 0);
        assert!(!pump_at(&mut s, &mut sink, 10_000 * MS));
        assert!(sink.writes.is_empty());
        // A hold later the stream is placed by the clock: the first packet is wholly late by
        // then, and the next, due 47 ms on, goes behind silence.
        let hold = i128::try_from(DEFAULT_MAX_LATENCY.as_nanos()).unwrap();
        offer(&mut s, 245 * SPF as u32);
        assert!(pump_at(&mut s, &mut sink, 10_000 * MS + hold));
        assert_eq!(s.stats().packets_dropped, 1);
        assert_eq!(sink.writes.len(), 2);
        assert!(sink.writes[0].1, "silence first");
    }

    #[test]
    fn a_huge_sink_delay_cannot_make_a_placement_write_minutes_of_silence() {
        // The sink says an hour; the floor is capped, so the first packet goes at most the cap
        // plus the write-ahead early.
        let mut s = anchored(10_000 * MS);
        let mut sink = Sink::new(SinkDelay::Known(Duration::from_secs(3600)));
        offer(&mut s, 0);
        let cap = i128::try_from((DEFAULT_MAX_LATENCY + DEFAULT_WRITE_AHEAD).as_nanos()).unwrap();
        assert!(!pump_at(&mut s, &mut sink, 10_000 * MS - cap - MS));
        assert!(sink.writes.is_empty());
    }

    /// The PTP offset moves the play time: an anchor on a master clock five seconds ahead of this
    /// machine's places packet `R0` five seconds before the anchor's network time; with the offset
    /// ignored, or applied with the wrong sign, nothing would be written.
    #[test]
    fn the_ptp_offset_moves_the_play_time() {
        let master_n0: i128 = 1_000_000 * NANOS_PER_SECOND;
        let offset: i128 = -5_000 * MS; // local − master
        let local_n0 = master_n0 + offset;
        let make = || {
            let mut s = stream();
            s.set_anchor(RateAnchor::play(
                NetworkTime::from_nanos(u128::try_from(master_n0).unwrap()),
                TIMELINE,
                rtp(4_000),
            ));
            offer(&mut s, 4_000);
            s
        };
        for wrong in [0, 5_000 * MS] {
            let mut s = make();
            let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
            let ptp = PtpReading::new(Some(TIMELINE), Some(wrong));
            assert!(!pump_with(&mut s, &mut sink, local_n0 - 50 * MS, ptp));
            assert!(sink.writes.is_empty(), "offset {wrong}: {:?}", sink.writes);
        }
        let mut s = make();
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        let ptp = PtpReading::new(Some(TIMELINE), Some(offset));
        assert!(pump_with(&mut s, &mut sink, local_n0 - 50 * MS, ptp));
        assert_eq!(sink.writes, vec![(frames_of(50 * MS), true), (SPF, false)]);
        assert_eq!(s.stats().offset_nanos, Some(offset));
    }

    #[test]
    fn a_stream_is_scheduled_only_on_the_anchors_own_timeline() {
        let anchor = RateAnchor::play(NetworkTime::from_nanos(1), 0xAB, rtp(0));
        let reading = PtpReading::new;
        assert_eq!(clock_for(anchor, reading(Some(0xAB), Some(-5))), Some(-5));
        assert_eq!(
            clock_for(anchor, reading(Some(0xCD), Some(-5))),
            None,
            "another clock"
        );
        assert_eq!(
            clock_for(anchor, reading(None, Some(-5))),
            None,
            "no grandmaster yet"
        );
        assert_eq!(
            clock_for(anchor, reading(Some(0xAB), None)),
            None,
            "no offset yet"
        );
        // Held, and said once.
        let mut s = anchored(10_000 * MS);
        offer(&mut s, 0);
        let mut notices = 0;
        for _ in 0..3 {
            while let Some(out) = s.poll(
                nanos(10_000 * MS),
                reading(Some(9), Some(0)),
                SinkDelay::Unknown,
            ) {
                if matches!(out, StreamOutput::Begin { .. }) {
                    continue;
                }
                assert_eq!(
                    out,
                    StreamOutput::Notice(StreamNotice::OtherTimeline {
                        anchor: TIMELINE,
                        followed: Some(9)
                    })
                );
                notices += 1;
            }
        }
        assert_eq!(notices, 1);
        assert_eq!(s.queued_packets(), 1);
    }

    #[test]
    fn an_anchor_that_restates_the_mapping_is_the_same_mapping() {
        let n = |ms: u128| NetworkTime::from_nanos(1_000_000_000_000 + ms * 1_000_000);
        let old = RateAnchor::play(n(0), 9, rtp(48_000));
        // One second later on both lines: the same mapping.
        assert!(same_mapping(
            old,
            RateAnchor::play(n(1_000), 9, rtp(96_000)),
            RATE
        ));
        // The RTP time shifted a tenth of a second: a new mapping.
        assert!(!same_mapping(
            old,
            RateAnchor::play(n(1_000), 9, rtp(100_800)),
            RATE
        ));
        // Another timeline, or a pause: never the same.
        assert!(!same_mapping(
            old,
            RateAnchor::play(n(1_000), 8, rtp(96_000)),
            RATE
        ));
        assert!(!same_mapping(
            old,
            RateAnchor::pause(n(1_000), 9, rtp(96_000)),
            RATE
        ));
        // Only a new mapping, once something was placed, asks for the sink to be flushed.
        let mut s = stream();
        assert_eq!(
            s.set_anchor(old),
            AnchorChange {
                same_mapping: false,
                flush_sink: false
            }
        );
        s.placed = true;
        assert!(
            s.set_anchor(RateAnchor::play(n(1_000), 9, rtp(96_000)))
                .same_mapping
        );
        assert_eq!(
            s.set_anchor(RateAnchor::play(n(1_000), 9, rtp(100_800))),
            AnchorChange {
                same_mapping: false,
                flush_sink: true
            }
        );
    }

    #[test]
    fn a_flush_without_rtptime_drops_everything_received_so_far() {
        let mut s = stream();
        for at in [0, SPF as u32] {
            offer(&mut s, at);
        }
        assert_eq!(s.flush(None), 2);
        assert_eq!(s.queued_frames(), 0);
        // A packet from before the FLUSH still in flight is dropped; the next one is not.
        assert_eq!(s.flushed_before, Some(rtp(2 * SPF as u32)));
        assert!(s.flushed_before.unwrap().is_after(rtp(SPF as u32)));
        assert!(!s.flushed_before.unwrap().is_after(rtp(2 * SPF as u32)));
    }

    /// Sealed, framed packets at these RTP times, as the data connection carries them.
    fn framed(rtps: impl IntoIterator<Item = u32>) -> Vec<u8> {
        let mut sealer = PacketSealer::new(&KEY);
        let mut bytes = Vec::new();
        for (i, at) in rtps.into_iter().enumerate() {
            let header = BufferedHeader::new(u32::try_from(i).unwrap(), rtp(at), 0).encode();
            let sealed = sealer.seal(&header, &vec![0x11; SPF * 4]).unwrap();
            bytes.extend(frame_buffered(&sealed).unwrap());
        }
        bytes
    }

    /// An rtptime-less `FLUSH` drops what came before; a sender that then restarts at a *lower*
    /// RTP time is dropped by that filter only until its play anchor on the new mapping arrives.
    #[test]
    fn a_sender_that_restarts_lower_after_a_flush_is_heard_once_it_anchors() {
        let mut s = stream();
        let base = 100_000u32;
        s.on_data(&framed((0..3).map(|i| base + i * SPF as u32)))
            .unwrap();
        assert_eq!(s.queued_packets(), 3);
        s.flush(None);
        assert_eq!(s.queued_packets(), 0);
        // A restart at RTP 0, before its anchor: still behind the FLUSH, dropped.
        s.on_data(&framed([0])).unwrap();
        assert_eq!(s.queued_packets(), 0);
        // The anchor on the new mapping: from here the restarted stream is heard.
        s.set_anchor(RateAnchor::play(
            NetworkTime::from_nanos(1_000_000_000_000),
            7,
            rtp(SPF as u32),
        ));
        s.on_data(&framed([SPF as u32])).unwrap();
        assert_eq!(s.queued_packets(), 1);
        assert_eq!(s.queue[0].rtp, rtp(SPF as u32));
        assert_eq!(s.stats().packets_dropped, 4);
        assert_eq!(s.stats().packets_decoded, 4);
    }

    /// A pause anchor does not end the filter: what the FLUSH dropped stays dropped.
    #[test]
    fn a_pause_anchor_keeps_a_flush_filter() {
        let mut s = stream();
        s.on_data(&framed([5_000])).unwrap();
        s.flush(None);
        s.set_anchor(RateAnchor::pause(NetworkTime::from_nanos(1), 7, rtp(0)));
        s.on_data(&framed([0])).unwrap();
        assert_eq!(s.queued_packets(), 0);
    }

    /// The queue's cap holds after decode, not only before a read: one read's worth of packets
    /// past it waits, opened but undecoded, and [`BufferedStream::wants_data`] says not to read.
    #[test]
    fn decoding_stops_at_the_cap_and_the_rest_waits_undecoded() {
        let config = BufferedStreamConfig {
            max_queued: Duration::from_nanos(u64::try_from(3 * PACKET + 1).unwrap()),
            ..BufferedStreamConfig::default()
        };
        let mut s = BufferedStream::new(KEY, format(RATE), config).unwrap();
        assert_eq!(s.max_queued, 3 * SPF as u64);
        s.on_data(&framed((0..7).map(|i| i * SPF as u32))).unwrap();
        assert_eq!(s.queued_packets(), 3, "decoded up to the cap");
        assert!(!s.wants_data(), "the rest waits");
        assert_eq!(s.stats().packets_opened, 7);
        // Room again: the rest decode.
        s.flush(Some(rtp(3 * SPF as u32)));
        s.decode();
        assert_eq!(s.queued_packets(), 3);
        s.queue.clear();
        s.queued_frames = 0;
        s.decode();
        assert_eq!(s.queued_packets(), 1);
        assert!(s.wants_data());
    }

    /// A replaced data connection drops what the old one left half read, keeps the anchor, and
    /// counts on from where it was.
    #[test]
    fn a_replaced_connection_starts_a_fresh_frame_and_keeps_the_anchor_and_counts() {
        let mut s = anchored(10_000 * MS);
        let first = framed([0, SPF as u32]);
        let half = first.len() - 10;
        s.on_data(&first[..half]).unwrap();
        assert_eq!(s.stats().packets_opened, 1);
        s.restart_connection();
        assert!(s.anchor().is_some());
        s.on_data(&framed([2 * SPF as u32])).unwrap();
        assert_eq!(s.stats().packets_opened, 2);
        assert_eq!(
            s.queue.iter().map(|q| q.rtp).collect::<Vec<_>>(),
            [rtp(0), rtp(2 * SPF as u32)]
        );
    }

    /// The first decoded packet begins the sink; one that does not decode is said and counted.
    #[test]
    fn the_first_packet_begins_the_sink_and_a_bad_one_is_said() {
        let format = AudioStreamFormat::new(
            compression::ALAC,
            audio_format::ALAC_44100_16_2,
            44_100,
            u32::try_from(SPF).unwrap(),
        );
        let mut s = BufferedStream::new(KEY, format, BufferedStreamConfig::default()).unwrap();
        s.on_data(&framed([0])).unwrap();
        let out = s.poll(Duration::ZERO, PtpReading::default(), SinkDelay::Unknown);
        assert!(
            matches!(
                out,
                Some(StreamOutput::Notice(StreamNotice::DecodeFailed {
                    sequence: Some(0),
                    ..
                }))
            ),
            "{out:?}"
        );
        assert_eq!(s.stats().packets_undecodable, 1);
        let mut s = stream();
        s.on_data(&framed([0])).unwrap();
        assert_eq!(
            s.poll(Duration::ZERO, PtpReading::default(), SinkDelay::Unknown),
            Some(StreamOutput::Begin {
                sample_rate: RATE,
                channels: 2,
                sequence: 0
            })
        );
        assert_eq!(
            s.poll(Duration::ZERO, PtpReading::default(), SinkDelay::Unknown),
            None
        );
    }

    /// Packets are handed out a write-ahead before they are due, each with its due instant.
    #[test]
    fn packets_go_a_write_ahead_early_with_their_due_instants() {
        let base = 10_000 * MS;
        let mut s = anchored(base);
        let mut sink = Sink::new(SinkDelay::Known(Duration::ZERO));
        for i in 0..100u32 {
            offer(&mut s, i * SPF as u32);
        }
        let mut dues = Vec::new();
        let ptp = PtpReading::new(Some(TIMELINE), Some(0));
        let now = base - 100 * MS;
        while let Some(out) = s.poll(nanos(now), ptp, sink.delay) {
            if let StreamOutput::Packet(p) = out {
                dues.push(p.due.unwrap());
            } else if let StreamOutput::Silence(frames) = out {
                sink.writes.push((frames as usize, true));
            }
        }
        // Due up to now plus the write-ahead: 150 ms past the first, 21 packets.
        assert_eq!(dues.len(), 21);
        for (i, due) in dues.iter().enumerate() {
            let want = base
                + i128::try_from(i).unwrap() * SPF as i128 * NANOS_PER_SECOND / i128::from(RATE);
            assert_eq!(*due, nanos(want));
        }
    }
}
