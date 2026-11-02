//! What a receive stream asks of its host, shared by [`super::RealtimeStream`] and
//! [`super::BufferedStream`]: the sink's delay going in, and [`StreamOutput`]s coming out, in the
//! order the host acts on them.
//!
//! A host's loop, per pass: feed what arrived, then call `poll` with its monotonic now, its clock
//! estimate and [`SinkDelay`] read fresh, acting on each output before the next call, until it
//! returns `None`. Fresh readings matter: after [`StreamOutput::Silence`] the next call re-places
//! the packet against what the write left in the sink.

use std::time::Duration;

use super::clock::DriftEstimate;
use super::playout::Playout;
use crate::time::RtpTimestamp;

/// What the host's sink says of when a sample written now is heard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SinkDelay {
    /// It cannot say (a file, say): the stream plays as packets come.
    #[default]
    Unknown,
    /// Its device is still opening: the stream is held for it, once, up to the stream's hold.
    Starting,
    /// This long: what it holds, what its device has yet to play of what it took, and the device's
    /// own latency. It must be continuous; a reading that steps by a device period at a time biases
    /// every placement (see [`super::playout`]).
    Known(Duration),
}

impl SinkDelay {
    /// The delay, if known.
    #[must_use]
    pub fn known(self) -> Option<Duration> {
        match self {
            Self::Known(delay) => Some(delay),
            Self::Unknown | Self::Starting => None,
        }
    }
}

/// One thing for the host to do, in order.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StreamOutput {
    /// The first audio: open the sink at this shape, so its device starts while packets wait.
    Begin {
        /// Frames per second.
        sample_rate: u32,
        /// Channels.
        channels: u8,
        /// The first packet's sequence number.
        sequence: u32,
    },
    /// The stream is now placed on the sender's timeline (`true`) or played as packets come.
    /// A sink that waits for a prebuffer should play what it holds while placed: the placement is
    /// the prebuffer. Raised on changes only; after a flush the stream is not placed. Realtime
    /// streams only.
    Placing(bool),
    /// Write this many frames of silence now, before polling again.
    Silence(u32),
    /// A decoded packet and where it goes.
    Packet(ScheduledPacket),
    /// Something to log or count.
    Notice(StreamNotice),
}

/// A decoded packet, placed.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ScheduledPacket {
    /// Interleaved 16-bit samples, the whole packet.
    pub samples: Vec<i16>,
    /// Channels.
    pub channels: u8,
    /// Frames per second.
    pub sample_rate: u32,
    /// Its sequence number.
    pub sequence: u32,
    /// The RTP timestamp of its first frame.
    pub timestamp: RtpTimestamp,
    /// Silence standing in for a packet that never arrived.
    pub concealed: bool,
    /// Frames to drop from its head before writing it; `None`: write none of it (every frame is
    /// past). A host that resamples applies the skip to the resampled frames, and still runs a
    /// dropped packet through the resampler if the resampler must see every packet.
    pub skip: Option<u32>,
    /// Output frames per input frame to resample this packet by: 1.0 for none, and always from a
    /// buffered stream.
    pub resample_ratio: f64,
    /// When its first frame should be heard, on the clock the host's now is read from (for a
    /// buffered stream, the one its PTP offset is measured against); `None` when nothing places
    /// it.
    pub due: Option<Duration>,
    /// How it was placed: [`Playout::Unscheduled`] when it plays as it comes. After a
    /// [`StreamOutput::Silence`], the first placement's.
    pub placement: Playout,
}

impl ScheduledPacket {
    /// Frames in [`Self::samples`].
    #[must_use]
    pub fn frames(&self) -> usize {
        self.samples.len() / usize::from(self.channels.max(1))
    }

    /// The samples to write when not resampling: from [`Self::skip`] on, or none.
    #[must_use]
    pub fn audible(&self) -> &[i16] {
        let Some(skip) = self.skip else {
            return &[];
        };
        let from = usize::try_from(skip)
            .unwrap_or(usize::MAX)
            .saturating_mul(usize::from(self.channels.max(1)));
        self.samples.get(from..).unwrap_or_default()
    }
}

/// Something a stream did that a host may log or count.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StreamNotice {
    /// A realtime stream observed a new sync packet; the fitted drift so far.
    Sync {
        /// [`super::ClockTracker::drift`] after it.
        drift: DriftEstimate,
    },
    /// A realtime stream's hold ran out with no sync packet for its new timeline: it stops
    /// waiting, once, and places on the latest sync packet if there is one (`latest_sync`), else
    /// plays as packets come.
    SyncWaitEnded {
        /// Whether any sync packet has arrived to place on.
        latest_sync: bool,
    },
    /// A realtime stream's sink stayed [`SinkDelay::Starting`] for a whole hold: it is no longer
    /// held for it.
    DeviceNotStarted,
    /// A packet did not decode; the stream goes on.
    DecodeFailed {
        /// Its sequence number, when known.
        sequence: Option<u32>,
        /// Why.
        error: String,
    },
    /// A buffered stream placed a packet afresh: its first packet, or one after a flush, a new
    /// mapping, a break in RTP time or an error past [`super::playout::RESYNC_THRESHOLD`] that
    /// was sustained (or past [`super::playout::GROSS_ERROR`]).
    Placed {
        /// The packet's RTP timestamp.
        timestamp: RtpTimestamp,
        /// How far off it would have been heard, written now, in seconds: positive is late.
        error: f64,
        /// The sink's delay it was placed against; `None` when unknown (placed by the clock).
        sink_delay: Option<Duration>,
    },
    /// A buffered stream is anchored on a PTP timeline other than the one the host follows, and
    /// holds. Raised once per stream.
    OtherTimeline {
        /// The anchor's timeline.
        anchor: u64,
        /// The grandmaster followed, if identified.
        followed: Option<u64>,
    },
}

/// The most notices a stream queues for a host that does not poll.
pub(crate) const MAX_QUEUED_NOTICES: usize = 64;
