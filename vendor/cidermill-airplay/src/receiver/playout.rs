//! When a realtime receiver should play each packet: the receiver's half of multi-room, sans-io.
//!
//! For every decoded packet, compares the instant it **will** be heard if written to the sink now
//! (sender clock now, from [`crate::timing::ClockFilter`], plus the sink's delay) with the instant
//! it **should** be heard ([`super::ClockTracker`]), and says what to do about the difference:
//!
//! - **At the start or a discontinuity** (RTP gap, `FLUSH`, an error past [`GROSS_ERROR`]):
//!   fix it at once with silence, or by skipping frames or the packet.
//! - **A sustained error**: one past [`RESYNC_THRESHOLD`] that has held, in the same direction,
//!   for [`SUSTAINED_ERROR_TIME`] of consecutive audio is re-placed like a discontinuity. Until
//!   then the packet is an outlier: it is played on the stream's current placement and correction,
//!   kept out of the averaged error, and counted in [`PlayoutStats::ignored_outliers`]. A single
//!   packet whose sink reading jumps, or an output that briefly ran dry, costs nothing; a packet
//!   back inside the threshold ends the run.
//! - **In between**: an error averaged over [`ERROR_WINDOW`] packets beyond [`SYNC_TOLERANCE`]
//!   yields a resampling correction of at most [`MAX_CORRECTION_PPM`], to multiply into the drift
//!   corrector's ratio.
//!
//! Design: shairport-sync `player.c`, correcting by resampling ratio instead of single frames.
//! The latency placed at is the sync packet's (plus [`FLAG7_LATENCY_OFFSET_FRAMES`] for flag 7),
//! capped at the scheduler's maximum and raised to the sink's floor plus [`SINK_FLOOR_MARGIN`].
//! The sink's delay must be continuous: count what the device still holds of its current period.
//! [`Playout::Unscheduled`] means play as it comes. Two receivers on two machines, heard, is
//! unproven.

use std::collections::VecDeque;

use super::clock::ClockTracker;
use crate::time::{NtpTimestamp, RtpTimestamp};

/// Averaged error, in seconds, tolerated before correcting (shairport-sync's default). Assumed
/// inaudible between two rooms.
pub const SYNC_TOLERANCE: f64 = 0.002;

/// Past this error, in seconds, for [`SUSTAINED_ERROR_TIME`], the stream is re-placed instead of
/// resampled towards (shairport-sync's default). A shorter excursion is an outlier and is ignored.
pub const RESYNC_THRESHOLD: f64 = 0.050;

/// Past this error, in seconds, the timeline is plainly wrong and the stream is re-placed at once,
/// without waiting for [`SUSTAINED_ERROR_TIME`].
pub const GROSS_ERROR: f64 = 0.5;

/// How long, in seconds of consecutive audio, an error must stay past [`RESYNC_THRESHOLD`] (in one
/// direction) before the stream is re-placed. About a dozen packets: longer than any one-packet
/// misreading of the sink's delay, short enough that a real step is followed within a tenth of a
/// second.
pub const SUSTAINED_ERROR_TIME: f64 = 0.1;

/// Correction time constant, in seconds: an averaged error `e` asks for `-e / 5 s` of resampling,
/// capped at [`MAX_CORRECTION_PPM`].
pub const CORRECTION_TIME: f64 = 5.0;

/// The largest correction, in parts per million.
pub const MAX_CORRECTION_PPM: f64 = 500.0;

/// How many packets' errors are averaged.
pub const ERROR_WINDOW: usize = 32;

/// Latency in frames at 44.1 kHz (scaled for other rates) added to a sync packet's declared latency
/// when its flags word is 7. Assumed to match Apple receivers, as shairport-sync does; if not, this
/// is the one number to change.
pub const FLAG7_LATENCY_OFFSET_FRAMES: u32 = 11_025;

/// Added to a sink's minimum delay, in seconds, when a sender asks for less latency than the sink
/// can give: room for network jitter.
pub const SINK_FLOOR_MARGIN: f64 = 0.050;

/// What to do with one decoded packet.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Playout {
    /// Nothing to schedule by (no sync packet, offset or sink delay): write the packet as it comes.
    Unscheduled,
    /// Write `silence` frames of silence, then the packet from frame `skip` on, and resample by
    /// `correction_ppm` on top of the drift correction (negative: play faster, the stream is late).
    Play {
        /// Frames of silence to write before the packet (an early start).
        silence: u32,
        /// Frames to drop from the head of the packet (a late start).
        skip: u32,
        /// Extra resampling, in parts per million of the rate: `ratio * (1 + ppm / 1e6)`.
        correction_ppm: f64,
        /// The error this packet was placed with, in seconds: positive is late.
        error: f64,
    },
    /// Every frame of the packet is already past: drop it.
    Drop {
        /// How late it is, in seconds.
        error: f64,
    },
}

/// What the scheduler has done, for a log line or a counter.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct PlayoutStats {
    /// Packets placed against the sender's timeline.
    pub scheduled: u64,
    /// Packets played as they came, with nothing to schedule by.
    pub unscheduled: u64,
    /// Times the stream was re-placed (a sustained error past [`RESYNC_THRESHOLD`], or one past
    /// [`GROSS_ERROR`]).
    pub resyncs: u64,
    /// Packets whose error was past [`RESYNC_THRESHOLD`] and that were played on the current
    /// placement instead: outliers, including the packets of a run that later became a resync.
    pub ignored_outliers: u64,
    /// Frames of silence written ahead of packets.
    pub silence_frames: u64,
    /// Frames dropped from the heads of late packets, whole dropped packets included.
    pub skipped_frames: u64,
    /// Whole packets dropped as late.
    pub dropped_packets: u64,
    /// The latest averaged error, in seconds (positive: late), once one has been measured.
    pub error: Option<f64>,
    /// The correction last asked for, in parts per million.
    pub correction_ppm: f64,
    /// The latency the stream is placed at, in seconds, once a packet has been placed.
    pub latency: Option<f64>,
    /// Whether the sender asked for more latency than the maximum, and was capped.
    pub latency_capped: bool,
    /// Whether the sender asked for less than the sink can give, and was raised to its floor.
    pub latency_raised: bool,
}

/// Places a realtime stream's packets on the sender's timeline. See the module docs.
///
/// One per stream, beside the stream's [`ClockTracker`]; [`Self::flush`] on a `FLUSH`.
#[derive(Debug, Clone)]
pub struct PlayoutScheduler {
    sample_rate: u32,
    max_latency_frames: u32,
    /// The sink's first reported delay for a stream, before anything is written to it.
    floor: Option<f64>,
    /// The sink holds audio this scheduler did not place ([`Self::sink_written`]).
    floor_unreadable: bool,
    anchored: bool,
    correcting: bool,
    next_rtp: Option<RtpTimestamp>,
    errors: VecDeque<f64>,
    /// Seconds of consecutive audio whose error has stayed past the threshold, and its sign.
    outlier_secs: f64,
    outlier_late: bool,
    stats: PlayoutStats,
}

impl PlayoutScheduler {
    /// A scheduler for `sample_rate` frames a second (one, if zero), honouring a declared latency
    /// up to `max_latency` seconds (the most the sink can hold ahead); a longer one is clamped.
    #[must_use]
    pub fn new(sample_rate: u32, max_latency: f64) -> Self {
        let sample_rate = sample_rate.max(1);
        let max_latency = if max_latency.is_finite() {
            max_latency.max(0.0)
        } else {
            0.0
        };
        // Saturating float-to-int: a bound past u32 frames is no bound.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let max_latency_frames = (max_latency * f64::from(sample_rate)).round() as u32;
        Self {
            sample_rate,
            max_latency_frames,
            floor: None,
            floor_unreadable: false,
            anchored: false,
            correcting: false,
            next_rtp: None,
            errors: VecDeque::with_capacity(ERROR_WINDOW),
            outlier_secs: 0.0,
            outlier_late: false,
            stats: PlayoutStats::default(),
        }
    }

    /// What the scheduler has done so far.
    #[must_use]
    pub fn stats(&self) -> PlayoutStats {
        self.stats
    }

    /// A `FLUSH`: what comes next is placed afresh, and the sink's floor is read again.
    pub fn flush(&mut self) {
        self.unanchor();
        self.next_rtp = None;
        self.floor = None;
        self.floor_unreadable = false;
    }

    /// The application wrote to the sink without a placement: until the next [`Self::flush`], no
    /// sink reading is its floor.
    pub fn sink_written(&mut self) {
        self.floor_unreadable = true;
    }

    /// Places the packet just placed again from scratch, once the silence its placement asked for
    /// has been written, so the write's own duration comes off the head as a skip. Not counted as
    /// a resync or a second packet.
    pub fn place_again(
        &mut self,
        rtp: RtpTimestamp,
        frames: u32,
        clock: &ClockTracker,
        sender_now: Option<NtpTimestamp>,
        sink_delay: Option<f64>,
    ) -> Playout {
        self.unanchor();
        self.next_rtp = None;
        self.stats.scheduled = self.stats.scheduled.saturating_sub(1);
        self.place(rtp, frames, clock, sender_now, sink_delay)
    }

    /// Places the decoded packet of `frames` frames starting at RTP timestamp `rtp`.
    /// `sender_now` is the **sender's** clock now (`None` before an offset is known);
    /// `sink_delay` is seconds until a frame written now plays (`None` if unknown).
    pub fn place(
        &mut self,
        rtp: RtpTimestamp,
        frames: u32,
        clock: &ClockTracker,
        sender_now: Option<NtpTimestamp>,
        sink_delay: Option<f64>,
    ) -> Playout {
        let continuous = self.next_rtp == Some(rtp);
        self.next_rtp = Some(rtp.wrapping_add(frames));
        if !continuous {
            self.unanchor();
        }
        let delay = sink_delay.filter(|d| d.is_finite() && *d >= 0.0);
        let (Some(now), Some(delay), Some(sent), Some(latency)) = (
            sender_now,
            delay,
            clock.schedule(rtp),
            clock.latency_frames(),
        ) else {
            self.unanchor();
            self.stats.unscheduled += 1;
            return Playout::Unscheduled;
        };
        self.stats.scheduled += 1;
        let rate = f64::from(self.sample_rate);
        let offset = if clock.sync_flags() == Some(crate::audio::rtp::SYNC_FLAGS) {
            f64::from(FLAG7_LATENCY_OFFSET_FRAMES) * rate / 44_100.0
        } else {
            0.0
        };
        let asked = f64::from(latency) + offset;
        let max = f64::from(self.max_latency_frames);
        let mut latency = asked.min(max) / rate;
        self.stats.latency_capped = asked > max;
        // The sink's first reading, before anything is written, is the least it can do.
        if !self.anchored && self.floor.is_none() && !self.floor_unreadable {
            self.floor = Some(delay);
        }
        self.stats.latency_raised = false;
        if let Some(floor) = self.floor {
            // Never past the maximum: a floor is the sink's, and a sink that cannot do better than
            // the maximum plays late by the difference rather than holding more than it may.
            let raised = (floor + SINK_FLOOR_MARGIN).min(max / rate);
            if latency < raised {
                latency = raised;
                self.stats.latency_raised = true;
            }
        }
        self.stats.latency = Some(latency);
        let should = sent.wrapping_add_secs_f64(latency);
        let will = now.wrapping_add_secs_f64(delay);
        let error = will.secs_f64_since(should);

        if self.anchored {
            if error.abs() > GROSS_ERROR {
                self.stats.resyncs += 1;
                self.unanchor();
            } else if error.abs() > RESYNC_THRESHOLD {
                let late = error > 0.0;
                if self.outlier_secs > 0.0 && late != self.outlier_late {
                    self.outlier_secs = 0.0;
                }
                self.outlier_late = late;
                self.outlier_secs += f64::from(frames) / rate;
                if self.outlier_secs >= SUSTAINED_ERROR_TIME {
                    self.stats.resyncs += 1;
                    self.unanchor();
                } else {
                    // An outlier: not averaged, and the correction stays as it was.
                    self.stats.ignored_outliers += 1;
                    return Playout::Play {
                        silence: 0,
                        skip: 0,
                        correction_ppm: self.stats.correction_ppm,
                        error,
                    };
                }
            } else {
                self.outlier_secs = 0.0;
            }
        }
        if !self.anchored {
            return self.anchor(error, frames, delay);
        }

        if self.errors.len() == ERROR_WINDOW {
            self.errors.pop_front();
        }
        self.errors.push_back(error);
        #[allow(clippy::cast_precision_loss)]
        let mean = self.errors.iter().sum::<f64>() / self.errors.len() as f64;
        if mean.abs() > SYNC_TOLERANCE {
            self.correcting = true;
        } else if mean.abs() < SYNC_TOLERANCE / 4.0 {
            self.correcting = false;
        }
        let correction_ppm = if self.correcting {
            (-mean / CORRECTION_TIME * 1e6).clamp(-MAX_CORRECTION_PPM, MAX_CORRECTION_PPM)
        } else {
            0.0
        };
        self.stats.error = Some(mean);
        self.stats.correction_ppm = correction_ppm;
        Playout::Play {
            silence: 0,
            skip: 0,
            correction_ppm,
            error,
        }
    }

    /// Anchors a packet: silence if early, a skip if late, dropped if every frame is past.
    /// Silence never takes the sink (`delay`) past the maximum latency.
    fn anchor(&mut self, error: f64, frames: u32, delay: f64) -> Playout {
        let rate = f64::from(self.sample_rate);
        self.stats.error = Some(error);
        self.stats.correction_ppm = 0.0;
        if error <= 0.0 {
            // Saturating float-to-int, then bounded by the room the sink has under the maximum.
            let room = (f64::from(self.max_latency_frames) - delay * rate).max(0.0);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let silence = (-error * rate).min(room).round() as u32;
            self.anchored = true;
            self.stats.silence_frames += u64::from(silence);
            return Playout::Play {
                silence,
                skip: 0,
                correction_ppm: 0.0,
                error,
            };
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let skip = (error * rate).round() as u64;
        if skip >= u64::from(frames) {
            self.stats.skipped_frames += u64::from(frames);
            self.stats.dropped_packets += 1;
            return Playout::Drop { error };
        }
        // skip < frames, so it fits.
        #[allow(clippy::cast_possible_truncation)]
        let skip = skip as u32;
        self.anchored = true;
        self.stats.skipped_frames += u64::from(skip);
        Playout::Play {
            silence: 0,
            skip,
            correction_ppm: 0.0,
            error,
        }
    }

    fn unanchor(&mut self) {
        self.anchored = false;
        self.correcting = false;
        self.errors.clear();
        self.outlier_secs = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::SendTimeline;
    use std::time::Duration;

    /// The RTP timestamp every test timeline starts at.
    const BASE: RtpTimestamp = RtpTimestamp::new(7);

    const RATE: u32 = 44_100;
    const SPF: u32 = 352;
    const LATENCY: u32 = 66_150; // pyatv's and this crate's sender's: 1.5 s
    const MAX_LATENCY: f64 = 1.8;

    /// A stream on a timeline starting at `origin`, its sync packet for frame 0 observed.
    /// A stream on a timeline starting at `origin`, its sync packet for frame 0 observed — with
    /// flags 0, so the tests of placement read the declared latency alone (the flag-7 offset has
    /// tests of its own).
    fn clock_for(timeline: &SendTimeline) -> ClockTracker {
        let mut sync = timeline.sync_packet(true, 0, LATENCY);
        sync.flags = 0;
        let mut clock = ClockTracker::new(RATE);
        clock.observe(&sync, Duration::ZERO);
        clock
    }

    /// A sink as the app's `PcmRenderBuffer` behaves, with a device a fixed `device` seconds
    /// behind it. Unless `scheduled`, it holds its audio back until `prebuffer` frames are queued
    /// (and again after it runs dry) and reports its delay as if the queue were at least that deep.
    /// `scheduled`, it plays whatever it has, which is what the app's buffer does once the receiver
    /// says it places audio itself.
    struct PrimingSink {
        queued: f64,
        primed: bool,
        prebuffer: f64,
        device: f64,
        scheduled: bool,
        capacity: f64,
    }

    impl PrimingSink {
        fn new(scheduled: bool) -> Self {
            Self {
                queued: 0.0,
                primed: false,
                prebuffer: 0.25 * f64::from(RATE),
                device: 0.06,
                scheduled,
                capacity: 2.0 * f64::from(RATE),
            }
        }
        fn delay(&self) -> f64 {
            let queued = if self.primed || self.scheduled {
                self.queued
            } else {
                self.queued.max(self.prebuffer)
            };
            queued / f64::from(RATE) + self.device
        }
        fn write(&mut self, frames: f64) {
            self.queued = (self.queued + frames).min(self.capacity);
            if !self.primed
                && ((self.scheduled && self.queued > 0.0) || self.queued >= self.prebuffer)
            {
                self.primed = true;
            }
        }
        fn advance(&mut self, seconds: f64) {
            if self.primed {
                self.queued -= seconds * f64::from(RATE);
                if self.queued <= 0.0 {
                    self.queued = 0.0;
                    self.primed = false;
                }
            }
        }
    }

    /// A sender declaring a latency the sink cannot give (0.1 s, 0.25 s, against a quarter-second
    /// prebuffer) is raised to the sink's floor and played, not placed as late and dropped for
    /// ever: twenty seconds, every packet played, with a sink that waits for its prebuffer and with
    /// one that plays what it is given.
    #[test]
    fn a_latency_below_what_the_sink_can_give_is_raised_to_its_floor_and_plays() {
        for scheduled in [false, true] {
            for declared in [0.1, 0.25] {
                let timeline = SendTimeline::new(at(0.0), BASE, RATE);
                let mut sync = timeline.sync_packet(true, 0, (declared * f64::from(RATE)) as u32);
                sync.flags = 0;
                let mut clock = ClockTracker::new(RATE);
                clock.observe(&sync, Duration::ZERO);
                let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
                let mut sink = PrimingSink::new(scheduled);
                let packet = f64::from(SPF) / f64::from(RATE);
                let (mut played, mut dropped) = (0u32, 0u32);
                for n in 0..(20.0 / packet) as u64 {
                    #[allow(clippy::cast_precision_loss)]
                    let now = n as f64 * packet + 0.003;
                    match scheduler.place(
                        timeline.rtp_of(n * u64::from(SPF)),
                        SPF,
                        &clock,
                        Some(at(now)),
                        Some(sink.delay()),
                    ) {
                        Playout::Play { silence, skip, .. } => {
                            played += 1;
                            sink.write(f64::from(silence) + f64::from(SPF - skip));
                        }
                        Playout::Drop { .. } => dropped += 1,
                        other => panic!("{other:?}"),
                    }
                    sink.advance(packet);
                }
                let stats = scheduler.stats();
                let what = format!("scheduled {scheduled}, declared {declared}: {stats:?}");
                assert!(
                    dropped == 0 && played > 2_490,
                    "{what}; {played} played, {dropped} dropped"
                );
                // The prebuffering sink's reading pretends its queue is a full prebuffer until it
                // primes, which the silence placed at the start does not move; the first reading
                // after priming corrects that with one resync, a fifth of a second in. The app's
                // scheduled sink has no such step.
                assert!(stats.resyncs <= u64::from(!scheduled), "{what}");
                let floor = if scheduled { 0.06 } else { 0.31 } + SINK_FLOOR_MARGIN;
                assert_eq!(stats.latency_raised, declared < floor, "{what}");
                assert!(
                    (stats.latency.unwrap() - declared.max(floor)).abs() < 1e-9,
                    "{what}"
                );
            }
        }
    }

    /// Every sender in view sets the sync packet's flags word to 7, and for it a quarter second is
    /// added to the declared latency, as shairport-sync does; a packet with other flags is placed
    /// at what it declares.
    #[test]
    fn a_flag_7_sync_packet_is_heard_a_quarter_second_after_its_declared_latency() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        for (flags, heard) in [(7u16, 1.75), (4, 1.5)] {
            let mut sync = timeline.sync_packet(true, 0, LATENCY);
            sync.flags = flags;
            let mut clock = ClockTracker::new(RATE);
            clock.observe(&sync, Duration::ZERO);
            let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
            let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(0.0));
            let Playout::Play { silence, .. } = placed else {
                panic!("{placed:?}")
            };
            assert_eq!(
                silence,
                (heard * f64::from(RATE)).round() as u32,
                "flags {flags}"
            );
            assert_eq!(scheduler.stats().latency, Some(heard));
            assert!(!scheduler.stats().latency_capped);
        }
    }

    /// A reading of the sender's clock gone stale by seconds (the sender's wall clock stepped and
    /// the offset has not caught up) makes every packet read seconds early; the silence written
    /// still never takes the sink past the maximum latency.
    #[test]
    fn silence_never_takes_the_sink_past_the_maximum_latency() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(-3.0)), Some(1.5));
        let Playout::Play { silence, .. } = placed else {
            panic!("{placed:?}")
        };
        assert_eq!(
            silence,
            ((MAX_LATENCY - 1.5) * f64::from(RATE)).round() as u32
        );
        let placed = scheduler.place_again(
            timeline.rtp_of(0),
            SPF,
            &clock,
            Some(at(-3.0)),
            Some(MAX_LATENCY),
        );
        assert!(
            matches!(placed, Playout::Play { silence: 0, .. }),
            "{placed:?}"
        );
        assert_eq!(
            scheduler.stats().scheduled,
            1,
            "placing again is not a second packet"
        );
    }

    /// A sink already holding audio played as it came (a device slow to start, whose hold ran out)
    /// has no readable floor until a `FLUSH`: a room is not locked seconds behind its group by what
    /// it held then. And a floor past the maximum raises the latency only to the maximum.
    #[test]
    fn a_sink_written_unplaced_has_no_floor_and_no_floor_raises_past_the_maximum() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let mut sync = timeline.sync_packet(true, 0, 8_820); // 0.2 s
        let mut clock = ClockTracker::new(RATE);
        clock.observe(&sync, Duration::ZERO);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        scheduler.sink_written();
        scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(1.7));
        let stats = scheduler.stats();
        assert!(!stats.latency_raised, "{stats:?}");
        assert!(
            (stats.latency.unwrap() - 0.45).abs() < 1e-9,
            "0.2 s declared + flag 7: {stats:?}"
        );
        // After a FLUSH the (emptied) sink is read again; a floor past the maximum is capped.
        scheduler.flush();
        sync.flags = 0;
        clock.observe(&sync, Duration::from_secs(1));
        scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(2.5));
        let stats = scheduler.stats();
        assert!(stats.latency_raised);
        assert!(
            (stats.latency.unwrap() - MAX_LATENCY).abs() < 1e-9,
            "{stats:?}"
        );
    }

    /// The floor is the sink's first reading, and a `FLUSH` (which empties the sink) reads it
    /// again; placing again keeps it.
    #[test]
    fn the_floor_is_read_once_per_stream_and_again_after_a_flush() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let mut sync = timeline.sync_packet(true, 0, 4_410); // 0.1 s
        sync.flags = 0;
        let mut clock = ClockTracker::new(RATE);
        clock.observe(&sync, Duration::ZERO);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(0.2));
        assert_eq!(scheduler.stats().latency, Some(0.2 + SINK_FLOOR_MARGIN));
        scheduler.place_again(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(0.5));
        assert_eq!(
            scheduler.stats().latency,
            Some(0.2 + SINK_FLOOR_MARGIN),
            "kept"
        );
        scheduler.flush();
        scheduler.place(
            timeline.rtp_of(u64::from(SPF)),
            SPF,
            &clock,
            Some(at(0.01)),
            Some(0.03),
        );
        assert_eq!(
            scheduler.stats().latency,
            Some(0.1),
            "0.03 + margin is under what was asked"
        );
        assert!(!scheduler.stats().latency_raised);
    }

    fn at(seconds: f64) -> NtpTimestamp {
        NtpTimestamp::from_parts(3_900_000_000, 0).wrapping_add_secs_f64(seconds)
    }

    #[test]
    fn nothing_to_schedule_by_plays_as_it_comes() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let empty = ClockTracker::new(RATE);
        let clock = clock_for(&timeline);
        let rtp = timeline.rtp_of(0);
        assert_eq!(
            scheduler.place(rtp, SPF, &empty, Some(at(0.0)), Some(0.0)),
            Playout::Unscheduled
        );
        assert_eq!(
            scheduler.place(rtp, SPF, &clock, None, Some(0.0)),
            Playout::Unscheduled
        );
        assert_eq!(
            scheduler.place(rtp, SPF, &clock, Some(at(0.0)), None),
            Playout::Unscheduled
        );
        assert_eq!(
            scheduler.place(rtp, SPF, &clock, Some(at(0.0)), Some(f64::NAN)),
            Playout::Unscheduled
        );
        assert_eq!(scheduler.stats().unscheduled, 4);
        assert_eq!(scheduler.stats().scheduled, 0);
    }

    /// The first packet, sent now, is heard 1.5 s from now: with a sink 60 ms behind, 1.44 s of
    /// silence goes first. The next packet then lands on time, with nothing to correct.
    #[test]
    fn an_early_first_packet_waits_behind_exactly_enough_silence() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(0.060));
        let Playout::Play {
            silence,
            skip,
            correction_ppm,
            error,
        } = placed
        else {
            panic!("{placed:?}");
        };
        assert_eq!(silence, (1.44 * f64::from(RATE)).round() as u32);
        assert_eq!((skip, correction_ppm), (0, 0.0));
        assert!((error + 1.44).abs() < 1e-6, "{error}");
        // 8 ms later the sink holds the silence and the packet, less 8 ms it has played.
        let held =
            0.060 + f64::from(silence + SPF) / f64::from(RATE) - f64::from(SPF) / f64::from(RATE);
        let next = scheduler.place(
            timeline.rtp_of(u64::from(SPF)),
            SPF,
            &clock,
            Some(at(f64::from(SPF) / f64::from(RATE))),
            Some(held),
        );
        let Playout::Play {
            silence,
            skip,
            correction_ppm,
            error,
        } = next
        else {
            panic!("{next:?}");
        };
        assert_eq!((silence, skip, correction_ppm), (0, 0, 0.0));
        assert!(error.abs() < 1.0 / f64::from(RATE), "{error}");
    }

    /// Writing the silence took 2 ms and the sink was empty: placed again on a fresh reading, the
    /// packet loses 2 ms of its head instead of landing 2 ms late.
    #[test]
    fn placing_again_after_the_silence_takes_the_writes_time_off_the_packets_head() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let rtp = timeline.rtp_of(0);
        let Playout::Play { silence, .. } =
            scheduler.place(rtp, SPF, &clock, Some(at(0.0)), Some(0.0))
        else {
            panic!("placed");
        };
        // The device started 2 ms after the reading, so it holds the silence less nothing played.
        let written = f64::from(silence) / f64::from(RATE);
        let again = scheduler.place_again(rtp, SPF, &clock, Some(at(0.002)), Some(written));
        let Playout::Play { silence, skip, .. } = again else {
            panic!("{again:?}");
        };
        assert_eq!(silence, 0);
        assert!((87..=89).contains(&skip), "{skip}");
        assert_eq!(scheduler.stats().resyncs, 0);
        // And the stream goes on from there as usual.
        let next = scheduler.place(
            timeline.rtp_of(u64::from(SPF)),
            SPF,
            &clock,
            Some(at(0.002 + f64::from(SPF - skip) / f64::from(RATE))),
            Some(written),
        );
        assert!(
            matches!(
                next,
                Playout::Play {
                    silence: 0,
                    skip: 0,
                    ..
                }
            ),
            "{next:?}"
        );
    }

    #[test]
    fn a_late_first_packet_loses_its_head_and_one_later_than_a_packet_is_dropped() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        // Arrived 1.505 s after it was sent, with an empty sink: 5 ms late.
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(1.505)), Some(0.0));
        assert!(
            matches!(
                placed,
                Playout::Play {
                    silence: 0,
                    skip: 220..=221,
                    ..
                }
            ),
            "{placed:?}"
        );
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(1.6)), Some(0.0));
        assert!(matches!(placed, Playout::Drop { .. }), "{placed:?}");
        assert_eq!(scheduler.stats().dropped_packets, 1);
        // The next packet, 8 ms on and still late, is placed from scratch: dropped too; one
        // that is only a little late keeps its tail.
        let second = scheduler.place(
            timeline.rtp_of(u64::from(SPF)),
            SPF,
            &clock,
            Some(at(1.6)),
            Some(0.0),
        );
        assert!(matches!(second, Playout::Drop { .. }), "{second:?}");
        let rtp = timeline.rtp_of(u64::from(SPF) * 12); // 95.8 ms of audio later: 4.2 ms late
        let third = scheduler.place(rtp, SPF, &clock, Some(at(1.6)), Some(0.0));
        let Playout::Play { skip, .. } = third else {
            panic!("{third:?}")
        };
        assert!((180..190).contains(&skip), "{skip}");
    }

    /// A sender asking for ten seconds gets the sink's bound: never more silence than the sink
    /// can hold.
    #[test]
    fn a_sender_latency_past_the_bound_is_clamped_to_it() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let mut clock = ClockTracker::new(RATE);
        clock.observe(&timeline.sync_packet(true, 0, 10 * RATE), Duration::ZERO);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(0.0)), Some(0.0));
        assert!(
            matches!(placed, Playout::Play { silence, .. } if silence == (MAX_LATENCY * f64::from(RATE)) as u32),
            "{placed:?}"
        );
    }

    /// A simulated device draining its buffer at the device's own rate, with a clock of the
    /// receiver's: the frame written now is heard after everything queued before it.
    /// With a `period`, it takes its audio from the queue in whole periods (a WASAPI shared-mode
    /// device's 10 ms) into a hardware buffer it then plays continuously. Its delay counts what is
    /// still unplayed there as well as the queue — a continuous reading, as a sink must give (the
    /// queue alone jumps by a period at a time, and anchoring the first packet on one phase of
    /// that sawtooth biases every later reading by up to half a period).
    struct Device {
        queued: f64,
        rate_factor: f64,
        latency: f64,
        period: f64,
        pending: f64,
    }

    impl Device {
        fn delay(&self) -> f64 {
            let in_hardware = if self.period > 0.0 {
                self.period
                    * f64::from(RATE)
                    * self.rate_factor
                    * (1.0 - self.pending / self.period)
            } else {
                0.0
            };
            self.latency + (self.queued + in_hardware) / f64::from(RATE)
        }
        fn advance(&mut self, seconds: f64) {
            if self.period <= 0.0 {
                self.queued = (self.queued - seconds * f64::from(RATE) * self.rate_factor).max(0.0);
                return;
            }
            self.pending += seconds;
            while self.pending >= self.period {
                self.pending -= self.period;
                self.queued =
                    (self.queued - self.period * f64::from(RATE) * self.rate_factor).max(0.0);
            }
        }
    }

    /// Runs a stream for `seconds` through a device `device_ppm` fast, the receiver resampling by
    /// whatever the scheduler asks (and no drift correction: the sender and the receiver share a
    /// clock here, only the device differs). Returns the worst averaged error after the first
    /// ten seconds, and the final one.
    fn run(device_ppm: f64, period: f64, seconds: u32, correct: bool) -> (f64, f64) {
        run_with_sender(0.0, device_ppm, period, seconds, correct)
    }

    /// [`run`], with the sender's clock (its send times, its sync packets, its answers to timing
    /// requests) `sender_ppm` fast against the receiver's: what the drift corrector's sync-packet
    /// fit measures, seen here only through the offset the receiver reads each time.
    fn run_with_sender(
        sender_ppm: f64,
        device_ppm: f64,
        period: f64,
        seconds: u32,
        correct: bool,
    ) -> (f64, f64) {
        let sender_rate = 1.0 + sender_ppm / 1e6;
        let timeline = SendTimeline::new(at(0.0), RtpTimestamp::new(11), RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let mut device = Device {
            queued: 0.0,
            rate_factor: 1.0 + device_ppm / 1e6,
            latency: 0.02,
            period,
            pending: 0.0,
        };
        let packet_seconds = f64::from(SPF) / f64::from(RATE);
        let packets = u64::from(seconds) * u64::from(RATE) / u64::from(SPF);
        let (mut worst, mut last) = (0.0f64, 0.0f64);
        let mut ratio = 1.0;
        for n in 0..packets {
            // Sent at the sender's n × packet, which is earlier on the receiver's clock if the
            // sender's runs fast; arrives 3 ms later.
            #[allow(clippy::cast_precision_loss)]
            let now = n as f64 * packet_seconds / sender_rate + 0.003;
            let placed = scheduler.place(
                timeline.rtp_of(n * u64::from(SPF)),
                SPF,
                &clock,
                Some(at(now * sender_rate)),
                Some(device.delay()),
            );
            let Playout::Play {
                silence,
                skip,
                correction_ppm,
                ..
            } = placed
            else {
                panic!("packet {n}: {placed:?}");
            };
            if correct {
                ratio = 1.0 + correction_ppm / 1e6;
            }
            device.queued += f64::from(silence) + f64::from(SPF - skip) * ratio;
            device.advance(packet_seconds / sender_rate);
            if let Some(error) = scheduler.stats().error {
                #[allow(clippy::cast_precision_loss)]
                if n as f64 * packet_seconds > 10.0 {
                    worst = worst.max(error.abs());
                }
                last = error;
            }
        }
        (worst, last)
    }

    /// The headline claim: a device 100 ppm off the receiver's clock is held within the tolerance
    /// for a simulated ten minutes; uncorrected it drifts 60 ms, past the resync threshold, which
    /// would re-place it with an audible jump.
    #[test]
    fn a_device_100_ppm_off_is_held_within_the_tolerance_for_ten_minutes() {
        for (ppm, period) in [(100.0, 0.0), (-100.0, 0.0), (100.0, 0.01), (-100.0, 0.01)] {
            let (worst, last) = run(ppm, period, 600, true);
            assert!(
                worst <= SYNC_TOLERANCE + 0.001,
                "{ppm} ppm, {period} s: worst {worst}"
            );
            assert!(
                last.abs() <= SYNC_TOLERANCE,
                "{ppm} ppm, {period} s: last {last}"
            );
        }
        let (_, uncorrected) = run(100.0, 0.0, 300, false);
        assert!(uncorrected.abs() > 0.020, "uncorrected: {uncorrected}");
    }

    /// The sender's clock off the receiver's by 200 ppm, and the device off by 100 the other way:
    /// held within the tolerance by the offset the receiver re-reads alone, with no drift fit
    /// from the sync packets — which is why the embedding application leaves that fit out of a
    /// stream that is scheduled.
    #[test]
    fn a_sender_200_ppm_off_and_a_device_off_the_other_way_are_held_together() {
        for (sender, device) in [(200.0, -100.0), (-200.0, 100.0)] {
            let (worst, last) = run_with_sender(sender, device, 0.01, 600, true);
            assert!(
                worst <= SYNC_TOLERANCE + 0.001,
                "{sender}/{device} ppm: worst {worst}"
            );
            assert!(
                last.abs() <= SYNC_TOLERANCE,
                "{sender}/{device} ppm: last {last}"
            );
        }
    }

    #[test]
    fn a_small_error_is_left_alone_and_a_larger_one_pulled_back_the_right_way() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let packet = f64::from(SPF) / f64::from(RATE);
        for (late, expect_sign) in [(0.001, 0.0f64), (0.0024, -1.0), (-0.0024, 1.0)] {
            let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
            // Anchored on time, then every packet `late` off.
            scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(1.5)), Some(0.0));
            let mut correction = 0.0;
            for n in 1..=u64::try_from(ERROR_WINDOW).unwrap() {
                #[allow(clippy::cast_precision_loss)]
                let now = 1.5 + n as f64 * packet + late;
                let placed = scheduler.place(
                    timeline.rtp_of(n * u64::from(SPF)),
                    SPF,
                    &clock,
                    Some(at(now)),
                    Some(0.0),
                );
                let Playout::Play { correction_ppm, .. } = placed else {
                    panic!("{placed:?}")
                };
                correction = correction_ppm;
            }
            assert_eq!(
                correction.signum() * expect_sign.abs(),
                expect_sign,
                "{late}: {correction}"
            );
            if expect_sign != 0.0 {
                assert!(
                    (correction.abs() - 0.0024 / CORRECTION_TIME * 1e6).abs() < 1.0,
                    "{correction}"
                );
            }
        }
    }

    /// A step in the receiver's reading of the sender's clock (a new offset estimate, or the
    /// sender's clock itself stepping) past the gross bound re-places the stream at once.
    #[test]
    fn a_gross_clock_step_resyncs_at_once() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let packet = f64::from(SPF) / f64::from(RATE);
        let frame = |n: u64| timeline.rtp_of(n * u64::from(SPF));
        #[allow(clippy::cast_precision_loss)]
        let on_time = |n: u64| 1.5 + n as f64 * packet;
        scheduler.place(frame(0), SPF, &clock, Some(at(on_time(0))), Some(0.0));
        scheduler.place(frame(1), SPF, &clock, Some(at(on_time(1))), Some(0.0));
        // The reading jumps 30 ms late: past the threshold? No — resampled towards, not re-placed.
        let placed = scheduler.place(
            frame(2),
            SPF,
            &clock,
            Some(at(on_time(2) + 0.03)),
            Some(0.0),
        );
        assert!(
            matches!(
                placed,
                Playout::Play {
                    silence: 0,
                    skip: 0,
                    ..
                }
            ),
            "{placed:?}"
        );
        assert_eq!(scheduler.stats().resyncs, 0);
        // 600 ms late: re-placed at once, and a packet is only 8 ms, so this one goes.
        let placed = scheduler.place(frame(3), SPF, &clock, Some(at(on_time(3) + 0.6)), Some(0.0));
        assert!(matches!(placed, Playout::Drop { .. }), "{placed:?}");
        assert_eq!(scheduler.stats().resyncs, 1);
        // Back on time: placed afresh (not another resync), then 600 ms early: silence at once.
        scheduler.place(frame(4), SPF, &clock, Some(at(on_time(4))), Some(0.0));
        let placed = scheduler.place(frame(5), SPF, &clock, Some(at(on_time(5) - 0.6)), Some(0.0));
        assert!(
            matches!(placed, Playout::Play { silence, .. } if silence == (0.6 * f64::from(RATE)).round() as u32),
            "{placed:?}"
        );
        assert_eq!(scheduler.stats().resyncs, 2);
    }

    /// Places packets `0..count` on time, with `skew(n)` seconds added to packet `n`'s reading of
    /// the sender's clock.
    fn run_skewed(count: u64, skew: impl Fn(u64) -> f64) -> (PlayoutScheduler, Vec<Playout>) {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let packet = f64::from(SPF) / f64::from(RATE);
        let mut placed = Vec::new();
        for n in 0..count {
            #[allow(clippy::cast_precision_loss)]
            let now = 1.5 + n as f64 * packet + skew(n);
            placed.push(scheduler.place(
                timeline.rtp_of(n * u64::from(SPF)),
                SPF,
                &clock,
                Some(at(now)),
                Some(0.0),
            ));
        }
        (scheduler, placed)
    }

    /// One packet whose reading jumps 70 ms, then back: no resync, no correction, and the average
    /// does not see it.
    #[test]
    fn an_isolated_error_spike_is_ignored() {
        let (scheduler, placed) = run_skewed(60, |n| if n == 30 { 0.07 } else { 0.0 });
        for (n, p) in placed.iter().enumerate() {
            assert!(
                matches!(p, Playout::Play { skip: 0, correction_ppm, .. } if *correction_ppm == 0.0),
                "{n}: {p:?}"
            );
        }
        let stats = scheduler.stats();
        assert_eq!(stats.resyncs, 0);
        assert_eq!(stats.ignored_outliers, 1);
        assert!(stats.error.unwrap().abs() < 1e-9, "{:?}", stats.error);
    }

    /// An error of 70 ms that stays: exactly one resync, on the packet that completes
    /// [`SUSTAINED_ERROR_TIME`], and none after it.
    #[test]
    fn a_sustained_error_resyncs_once_after_the_window() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let packet = f64::from(SPF) / f64::from(RATE);
        let mut first_resync = None;
        for n in 0..80u64 {
            let skew = if n >= 10 { 0.07 } else { 0.0 };
            #[allow(clippy::cast_precision_loss)]
            let now = 1.5 + n as f64 * packet + skew;
            scheduler.place(
                timeline.rtp_of(n * u64::from(SPF)),
                SPF,
                &clock,
                Some(at(now)),
                Some(0.0),
            );
            if first_resync.is_none() && scheduler.stats().resyncs == 1 {
                first_resync = Some(n);
            }
        }
        // 13 packets of 352 frames at 44.1 kHz are the first to reach 0.1 s; the 13th resyncs.
        assert_eq!(first_resync, Some(10 + 12));
        assert_eq!(scheduler.stats().resyncs, 1);
        assert_eq!(scheduler.stats().ignored_outliers, 12);
    }

    /// Outliers that flip sign do not add up to a sustained error.
    #[test]
    fn outliers_of_opposite_signs_do_not_accumulate() {
        let (scheduler, _) = run_skewed(60, |n| match n {
            0..=4 => 0.0,
            _ if n % 2 == 0 => 0.07,
            _ => -0.07,
        });
        assert_eq!(scheduler.stats().resyncs, 0);
    }

    /// An error past the gross bound is re-placed on its first packet.
    #[test]
    fn a_gross_error_resyncs_on_its_first_packet() {
        let (scheduler, _) = run_skewed(20, |n| if n >= 10 { GROSS_ERROR + 0.01 } else { 0.0 });
        assert_eq!(scheduler.stats().resyncs, 1);
        assert_eq!(scheduler.stats().ignored_outliers, 0);
    }

    /// The packet indices at which `skew(n)` seconds added to packet `n`'s clock reading makes a
    /// `rate` Hz stream of 352-frame packets resync, with the scheduler at the end.
    fn resyncs_at(
        rate: u32,
        count: u64,
        skew: impl Fn(u64) -> f64,
    ) -> (Vec<u64>, PlayoutScheduler) {
        let timeline = SendTimeline::new(at(0.0), BASE, rate);
        let mut sync = timeline.sync_packet(true, 0, rate * 3 / 2);
        sync.flags = 0;
        let mut clock = ClockTracker::new(rate);
        clock.observe(&sync, Duration::ZERO);
        let mut scheduler = PlayoutScheduler::new(rate, MAX_LATENCY);
        let packet = f64::from(SPF) / f64::from(rate);
        let (mut hits, mut seen) = (Vec::new(), 0);
        for n in 0..count {
            #[allow(clippy::cast_precision_loss)]
            let now = 1.5 + n as f64 * packet + skew(n);
            scheduler.place(
                timeline.rtp_of(n * u64::from(SPF)),
                SPF,
                &clock,
                Some(at(now)),
                Some(0.0),
            );
            if scheduler.stats().resyncs > seen {
                seen = scheduler.stats().resyncs;
                hits.push(n);
            }
        }
        (hits, scheduler)
    }

    /// The window is audio time, counted in the stream's own frames: at 48 kHz a 352-frame packet
    /// is 7.33 ms, so the run needs 14 packets, not the 13 of 44.1 kHz.
    #[test]
    fn the_sustained_window_is_counted_in_the_streams_own_rate() {
        let skew = |n| if n >= 10 { 0.07 } else { 0.0 };
        let (hits, scheduler) = resyncs_at(48_000, 80, skew);
        assert_eq!(hits, vec![10 + 13]);
        assert_eq!(scheduler.stats().ignored_outliers, 13);
        let (hits, _) = resyncs_at(44_100, 80, skew);
        assert_eq!(hits, vec![10 + 12]);
    }

    /// 49 ms is inside the threshold: never an outlier, and it enters the average (which asks for
    /// a correction). 51 ms is past it: a resync once the run is long enough, and only once.
    #[test]
    fn the_threshold_edge_is_exact() {
        let (hits, scheduler) = resyncs_at(RATE, 80, |n| if n >= 10 { 0.049 } else { 0.0 });
        assert!(hits.is_empty());
        let stats = scheduler.stats();
        assert_eq!(stats.ignored_outliers, 0);
        assert!(stats.error.unwrap() > 0.02, "{:?}", stats.error);
        assert!(stats.correction_ppm < 0.0, "{}", stats.correction_ppm);

        let (hits, scheduler) = resyncs_at(RATE, 80, |n| if n >= 10 { 0.051 } else { 0.0 });
        assert_eq!(hits, vec![10 + 12]);
        assert_eq!(scheduler.stats().resyncs, 1);
    }

    /// A packet of the opposite sign in the middle of a late run starts the run over.
    #[test]
    fn an_opposite_sign_packet_restarts_a_late_run() {
        let skew = |n| match n {
            22 => -0.07,
            10.. => 0.07,
            _ => 0.0,
        };
        let (hits, _) = resyncs_at(RATE, 80, skew);
        // The early packet at 22 counts as the run's first; the late run restarts at 23.
        assert_eq!(hits, vec![23 + 12]);
    }

    #[test]
    fn a_timestamp_discontinuity_or_a_flush_places_afresh() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(at(1.5)), Some(0.0));
        // 20 ms early — under the resync threshold, but after a jump in the timestamps it is
        // placed at once rather than resampled towards.
        let jumped = timeline.rtp_of(u64::from(SPF) * 100);
        let placed = scheduler.place(
            jumped,
            SPF,
            &clock,
            Some(at(1.5 + 100.0 * f64::from(SPF) / f64::from(RATE) - 0.02)),
            Some(0.0),
        );
        assert!(
            matches!(placed, Playout::Play { silence: 882, .. }),
            "{placed:?}"
        );
        scheduler.flush();
        let placed = scheduler.place(
            jumped.wrapping_add(SPF),
            SPF,
            &clock,
            Some(at(1.5 + 101.0 * f64::from(SPF) / f64::from(RATE) - 0.01)),
            Some(0.0),
        );
        assert!(
            matches!(placed, Playout::Play { silence: 441, .. }),
            "{placed:?}"
        );
        assert_eq!(
            scheduler.stats().resyncs,
            0,
            "neither is a resync of a stream on its timeline"
        );
    }

    /// The schedule, the reading of the sender's clock and the error are all era-safe: a stream
    /// whose sync packet was sent before the 2036 wrap and whose frames play after it is placed
    /// exactly as one in the middle of an era.
    #[test]
    fn a_stream_across_the_2036_era_wrap_is_placed_as_any_other() {
        let origin = NtpTimestamp::from_parts(u32::MAX, 0xFFFF_0000); // 15 µs before era 0 ends
        let timeline = SendTimeline::new(origin, BASE, RATE);
        let clock = clock_for(&timeline);
        let mut scheduler = PlayoutScheduler::new(RATE, MAX_LATENCY);
        let now = origin.wrapping_add_secs_f64(0.25); // already in era 1
        let placed = scheduler.place(timeline.rtp_of(0), SPF, &clock, Some(now), Some(0.05));
        assert!(
            matches!(placed, Playout::Play { silence, .. } if silence == (1.2 * f64::from(RATE)).round() as u32),
            "{placed:?}"
        );
    }

    /// Two receivers fed the same sync packets, reading the same sender clock, with sinks of
    /// different depths: each places its first frame so that it is heard at the same instant.
    #[test]
    fn two_receivers_with_different_sinks_place_the_first_frame_at_the_same_instant() {
        let timeline = SendTimeline::new(at(0.0), BASE, RATE);
        let (a_clock, b_clock) = (clock_for(&timeline), clock_for(&timeline));
        let (mut a, mut b) = (
            PlayoutScheduler::new(RATE, MAX_LATENCY),
            PlayoutScheduler::new(RATE, MAX_LATENCY),
        );
        let rtp = timeline.rtp_of(0);
        let (a_now, b_now) = (0.004, 0.009); // each got the packet at its own moment
        let (a_delay, b_delay) = (0.060, 0.210); // a WASAPI device and a slower one
        let heard = |placed: Playout, now: f64, delay: f64| match placed {
            Playout::Play {
                silence, skip: 0, ..
            } => now + delay + f64::from(silence) / f64::from(RATE),
            other => panic!("{other:?}"),
        };
        let a_at = heard(
            a.place(rtp, SPF, &a_clock, Some(at(a_now)), Some(a_delay)),
            a_now,
            a_delay,
        );
        let b_at = heard(
            b.place(rtp, SPF, &b_clock, Some(at(b_now)), Some(b_delay)),
            b_now,
            b_delay,
        );
        assert!((a_at - 1.5).abs() <= 0.5 / f64::from(RATE), "{a_at}");
        assert!(
            (a_at - b_at).abs() <= 1.0 / f64::from(RATE),
            "{a_at} vs {b_at}"
        );
    }

    #[test]
    fn arbitrary_inputs_never_panic() {
        let mut seed = 0x91A7_0017_u64;
        let mut next = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            seed
        };
        for (rate, max) in [
            (0u32, 0.0),
            (1, f64::NAN),
            (44_100, 1.8),
            (u32::MAX, f64::INFINITY),
            (48_000, -3.0),
        ] {
            let mut scheduler = PlayoutScheduler::new(rate, max);
            let mut clock = ClockTracker::new(rate);
            for i in 0..500u32 {
                if next() % 5 == 0 {
                    let sync = crate::audio::rtp::SyncPacket::new(
                        false,
                        RtpTimestamp::new((next() >> 32) as u32),
                        NtpTimestamp::from_bits(next()),
                        RtpTimestamp::new((next() >> 32) as u32),
                    );
                    clock.observe(&sync, Duration::from_secs(u64::from(i)));
                }
                if next() % 50 == 0 {
                    scheduler.flush();
                }
                let delay = match next() % 6 {
                    0 => None,
                    1 => Some(f64::NAN),
                    2 => Some(-1.0),
                    3 => Some(f64::INFINITY),
                    _ => Some(f64::from_bits(next()) % 1e6),
                };
                let now = (next() % 7 != 0).then(|| NtpTimestamp::from_bits(next()));
                let _ = scheduler.place(
                    RtpTimestamp::new((next() >> 32) as u32),
                    (next() >> 48) as u32,
                    &clock,
                    now,
                    delay,
                );
                let _ = scheduler.stats();
            }
        }
    }
}
