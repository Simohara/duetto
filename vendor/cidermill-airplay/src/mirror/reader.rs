//! The receiver's half, sans-io: the data connection's bytes in (any split), frames out.
//!
//! Every video payload is decrypted as soon as it is complete, in arrival order, before anything
//! else is decided about it: the keystream runs across all of them. Bounds (payload sizes, rate,
//! picture size, NAL counts, strict `avcC`, no HEVC) are checked before allocating; any failure is
//! terminal and the host closes the connection. Silence is the host's to time. Feed what one
//! bounded socket read returned.

use std::collections::VecDeque;
use std::time::Duration;

use crate::error::{AirPlayError, Result};
use crate::time::NtpTimestamp;

use super::avc::{
    nal_type, parse_sps, split_avcc, AvcConfig, SpsInfo, NAL_IDR, NAL_SPS, START_CODE,
};
use super::key::{StreamCipher, StreamKey};
use super::packet::{ntp_from_header, HeaderDimensions, PacketHeader, PayloadKind, OPTION_HEVC};
use super::{
    HEADER_LEN, MAX_BYTES_PER_SECOND, MAX_CODEC_BYTES, MAX_FRAME_BYTES, MAX_PACKETS_PER_SECOND,
    MAX_REPORT_BYTES,
};

/// The rate is counted in this many slices of a second: a sliding one-second window.
const SLICES: usize = 10;

/// One slice's span.
const SLICE: Duration = Duration::from_millis(100);

/// What one slice counted, and its index (time / [`SLICE`]).
#[derive(Debug, Clone, Copy, Default)]
struct Slice {
    index: u128,
    packets: u32,
    bytes: u64,
}

/// What the stream said.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MirrorEvent {
    /// A codec record: the SPS and PPS every following IDR is prefixed with.
    CodecConfig {
        /// The record.
        config: AvcConfig,
        /// What its SPS says (the size this crate trusts).
        sps: SpsInfo,
        /// What the header said (logged, not trusted).
        header: HeaderDimensions,
        /// The header timestamp, as the sender's NTP time.
        timestamp: NtpTimestamp,
    },
    /// One access unit, decrypted, as Annex B; an IDR, and the first frame after a codec record
    /// that changed the parameter sets, is prefixed with the SPS and PPS.
    Frame {
        /// When the sender captured it, on its NTP clock.
        timestamp: NtpTimestamp,
        /// Whether it carries an IDR slice (or the header said so).
        idr: bool,
        /// The access unit.
        annex_b: Vec<u8>,
    },
    /// A heartbeat.
    Heartbeat,
    /// A streaming report, skipped.
    Report {
        /// Its size.
        len: u32,
    },
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReaderStats {
    /// Packets read whole.
    pub packets: u64,
    /// Frames handed out.
    pub frames: u64,
    /// Frames decrypted and dropped because no codec record had come yet.
    pub frames_before_codec: u64,
    /// Codec records.
    pub codec_records: u64,
    /// Heartbeats.
    pub heartbeats: u64,
    /// Reports skipped.
    pub reports: u64,
    /// Bytes read, headers included.
    pub bytes: u64,
}

/// See the module docs.
pub struct MirrorStreamReader {
    cipher: StreamCipher,
    buffer: Vec<u8>,
    config: Option<AvcConfig>,
    /// A codec record changed the parameter sets: the next frame is prefixed with them.
    config_pending: bool,
    failed: bool,
    slices: [Slice; SLICES],
    stats: ReaderStats,
    events: VecDeque<MirrorEvent>,
}

impl std::fmt::Debug for MirrorStreamReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorStreamReader")
            .field("buffered", &self.buffer.len())
            .field("failed", &self.failed)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

fn refuse(message: impl Into<String>) -> AirPlayError {
    AirPlayError::Protocol(format!("mirror stream: {}", message.into()))
}

impl MirrorStreamReader {
    /// A reader at the start of this stream's keystream.
    #[must_use]
    pub fn new(key: &StreamKey) -> Self {
        Self {
            cipher: key.cipher(),
            buffer: Vec::new(),
            config: None,
            config_pending: false,
            failed: false,
            slices: [Slice::default(); SLICES],
            stats: ReaderStats::default(),
            events: VecDeque::new(),
        }
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> ReaderStats {
        self.stats
    }

    /// The codec record in force, if one has come.
    #[must_use]
    pub fn config(&self) -> Option<&AvcConfig> {
        self.config.as_ref()
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<MirrorEvent> {
        self.events.pop_front()
    }

    /// Feeds bytes read at `now` (any monotonic time; only differences are used).
    ///
    /// # Errors
    ///
    /// A bound or a format failed (see the module docs). Terminal: every later call fails too.
    pub fn feed(&mut self, bytes: &[u8], now: Duration) -> Result<()> {
        if self.failed {
            return Err(refuse("the stream already failed"));
        }
        self.buffer.extend_from_slice(bytes);
        let result = self.drain(now);
        if result.is_err() {
            self.failed = true;
            self.buffer = Vec::new();
        }
        result
    }

    fn drain(&mut self, now: Duration) -> Result<()> {
        loop {
            if self.buffer.len() < HEADER_LEN {
                return Ok(());
            }
            let header = PacketHeader::decode(&self.buffer)?;
            check_header(&header)?;
            let len = usize::try_from(header.payload_len).map_err(|_| refuse("size"))?;
            let total = HEADER_LEN + len;
            if self.buffer.len() < total {
                return Ok(());
            }
            let mut payload = self.buffer[HEADER_LEN..total].to_vec();
            self.buffer.drain(..total);
            self.count(len as u64, total as u64, now)?;
            self.packet(&header, &mut payload)?;
        }
    }

    fn count(&mut self, payload: u64, total: u64, now: Duration) -> Result<()> {
        // Indexes start at 1 so an unwritten slice (0) is never in the window.
        let index = now.as_nanos() / SLICE.as_nanos() + 1;
        #[allow(clippy::cast_possible_truncation)]
        let slot = &mut self.slices[(index % SLICES as u128) as usize];
        if slot.index != index {
            *slot = Slice {
                index,
                packets: 0,
                bytes: 0,
            };
        }
        slot.packets += 1;
        slot.bytes += payload;
        self.stats.packets += 1;
        self.stats.bytes += total;
        let recent = self
            .slices
            .iter()
            .filter(|s| s.index != 0 && s.index + SLICES as u128 > index && s.index <= index);
        let (packets, bytes) = recent.fold((0u64, 0u64), |(p, b), s| {
            (p + u64::from(s.packets), b + s.bytes)
        });
        if packets > u64::from(MAX_PACKETS_PER_SECOND) {
            return Err(refuse("too many packets in a second"));
        }
        if bytes > MAX_BYTES_PER_SECOND {
            return Err(refuse("too many bytes in a second"));
        }
        Ok(())
    }

    fn packet(&mut self, header: &PacketHeader, payload: &mut [u8]) -> Result<()> {
        match header.kind {
            PayloadKind::Video => {
                // Always first: the keystream advances over every video payload in order.
                self.cipher.apply(payload);
                let Some(config) = &self.config else {
                    self.stats.frames_before_codec += 1;
                    return Ok(());
                };
                let nals = split_avcc(payload)?;
                // An in-band SPS is held to the same size bound.
                for nal in nals.iter().filter(|n| nal_type(n) == Some(NAL_SPS)) {
                    let sps = parse_sps(nal)?;
                    if !sps.within_bounds() {
                        return Err(refuse(format!(
                            "an in-band SPS names {}x{}",
                            sps.width, sps.height
                        )));
                    }
                }
                let idr = header.is_idr() || nals.iter().any(|n| nal_type(n) == Some(NAL_IDR));
                let mut annex_b = Vec::with_capacity(payload.len() + 4 * nals.len() + 64);
                if self.config_pending || nals.iter().any(|n| nal_type(n) == Some(NAL_IDR)) {
                    annex_b.extend_from_slice(&config.annex_b());
                }
                self.config_pending = false;
                for nal in nals {
                    annex_b.extend_from_slice(&START_CODE);
                    annex_b.extend_from_slice(nal);
                }
                self.stats.frames += 1;
                self.events.push_back(MirrorEvent::Frame {
                    timestamp: ntp_from_header(header.timestamp),
                    idr,
                    annex_b,
                });
            }
            PayloadKind::CodecConfig => {
                if header.option == OPTION_HEVC || payload.get(4..8) == Some(b"hvc1") {
                    return Err(refuse("HEVC is not supported"));
                }
                let config = AvcConfig::parse(payload)?;
                let sps = parse_sps(&config.sps)?;
                if !sps.within_bounds() {
                    return Err(refuse(format!(
                        "{}x{} is out of bounds",
                        sps.width, sps.height
                    )));
                }
                self.stats.codec_records += 1;
                if self.config.as_ref() != Some(&config) {
                    self.config_pending = true;
                }
                self.config = Some(config.clone());
                self.events.push_back(MirrorEvent::CodecConfig {
                    config,
                    sps,
                    header: header.dimensions,
                    timestamp: ntp_from_header(header.timestamp),
                });
            }
            PayloadKind::Heartbeat => {
                self.stats.heartbeats += 1;
                self.events.push_back(MirrorEvent::Heartbeat);
            }
            PayloadKind::Report => {
                self.stats.reports += 1;
                self.events.push_back(MirrorEvent::Report {
                    len: header.payload_len,
                });
            }
            PayloadKind::Other(kind) => return Err(refuse(format!("unknown payload type {kind}"))),
        }
        Ok(())
    }
}

/// A header's size checked against its type, before its payload is buffered.
fn check_header(header: &PacketHeader) -> Result<()> {
    let len = header.payload_len;
    let ok = match header.kind {
        PayloadKind::Video => (1..=MAX_FRAME_BYTES).contains(&len),
        PayloadKind::CodecConfig => (1..=MAX_CODEC_BYTES).contains(&len),
        PayloadKind::Heartbeat => len == 0,
        PayloadKind::Report => len <= MAX_REPORT_BYTES,
        PayloadKind::Other(kind) => return Err(refuse(format!("unknown payload type {kind}"))),
    };
    if ok {
        Ok(())
    } else {
        Err(refuse(format!(
            "a {:?} payload of {len} bytes",
            header.kind
        )))
    }
}
