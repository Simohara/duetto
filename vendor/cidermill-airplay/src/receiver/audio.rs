//! The realtime audio path of a receiver, sans-io: sealed RTP packets in, interleaved PCM out,
//! retransmit requests out when a sequence gap is seen.
//!
//! - Data port: open the packet, place it in a reorder buffer keyed on extended sequence number,
//!   decode (ALAC `ct: 2`, or 16-bit big-endian LPCM `ct: 1`; anything else is refused at
//!   [`RealtimeReceiver::new`]).
//! - Control port: `0xD6` retransmit replies feed the same path; `0xD4` sync packets are kept;
//!   gaps produce `0xD5` retransmit requests (pyatv's layout).
//! - A missing head is waited for, then concealed with silence after [`CONCEAL_AFTER_PACKETS`].
//!
//! The sequence number is unauthenticated, so a packet is placed only if it agrees with its
//! authenticated timestamp (`(seq - highest) * spf`); late or replayed packets are dropped.
//! Packets that disagree open a candidate timeline on probation, which restarts the stream once its
//! lead reaches [`FORWARD_RESTART_PACKETS`] or [`BACKWARD_RESTART_PACKETS`], so a replay cannot
//! pull the stream back without out-sending the real sender. Retransmit replies never open one.
//! Assumed: senders advance the RTP timestamp by exactly `spf` per sequence number; if not, they
//! resync via probation with delay.
//!
//! [`RealtimeReceiver::flush`] restarts at the request's `RTP-Info`; the first packet after it is
//! checked against the named `seq`/`rtptime` where given and trusted otherwise.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::audio::alac::AlacConfig;
use crate::audio::format::{audio_format, compression};
#[cfg(feature = "mirror")]
use crate::audio::rtp::open_packet_aes_cbc;
use crate::audio::rtp::{
    open_packet, RtpHeader, SyncPacket, RETRANSMIT_REPLY_PAYLOAD_TYPE, SYNC_PAYLOAD_TYPE,
};
use crate::error::{AirPlayError, Result};
use crate::time::RtpTimestamp;

/// Later packets that may queue behind a missing one before it is concealed (about 255 ms at
/// 352 frames and 44.1 kHz).
pub const CONCEAL_AFTER_PACKETS: u64 = 32;

/// How long to wait before asking for a missing packet again.
pub const RETRANSMIT_RETRY: Duration = Duration::from_millis(60);

/// How many times one missing packet is asked for.
pub const RETRANSMIT_ATTEMPTS: u32 = 3;

/// A packet further ahead of the head than this restarts the stream at it.
pub const RESYNC_DISTANCE: u64 = 1000;

/// The lead a candidate timeline needs to restart the stream when its first packet lies at or
/// behind the highest packet's timestamp.
pub const BACKWARD_RESTART_PACKETS: usize = 32;

/// The lead a candidate timeline needs when its first packet lies after the highest packet's
/// timestamp (RFC 3550 appendix A.1).
pub const FORWARD_RESTART_PACKETS: usize = 2;

/// The most packets a candidate timeline holds; beyond it the oldest is let go.
pub const MAX_HELD_PACKETS: usize = 2 * BACKWARD_RESTART_PACKETS;

/// Where extended sequence numbers start: far enough from zero that a packet placed behind it
/// never underflows.
const FIRST_EXTENDED: u64 = 1 << 20;

/// How far ahead of a candidate timeline's highest packet a packet may lie and still count on it
/// (RFC 3550 appendix A.1).
pub const MAX_DROPOUT: u16 = 3000;

/// How far behind the highest packet a sequence number may arrive and still be placed (RFC 3550
/// appendix A.1).
pub const MAX_MISORDER: u16 = 100;

/// The largest `spf` accepted; keeps a hostile `SETUP` from sizing the decoder's buffers.
pub const MAX_FRAMES_PER_PACKET: u32 = 4096;

/// The lowest `sr` accepted; the bounds keep a hostile `SETUP` from sizing a host's buffers.
pub const MIN_SAMPLE_RATE: u32 = 8_000;

/// The highest `sr` accepted. See [`MIN_SAMPLE_RATE`].
pub const MAX_SAMPLE_RATE: u32 = 192_000;

/// `spf` and `sr` inside the bounds every receiver here holds them to.
pub(crate) fn check_shape(format: &AudioStreamFormat) -> Result<()> {
    if format.frames_per_packet == 0 || format.frames_per_packet > MAX_FRAMES_PER_PACKET {
        return Err(AirPlayError::Protocol(format!(
            "spf {} is outside 1..={MAX_FRAMES_PER_PACKET}",
            format.frames_per_packet
        )));
    }
    if !(MIN_SAMPLE_RATE..=MAX_SAMPLE_RATE).contains(&format.sample_rate) {
        return Err(AirPlayError::Protocol(format!(
            "sr {} is outside {MIN_SAMPLE_RATE}..={MAX_SAMPLE_RATE}",
            format.sample_rate
        )));
    }
    Ok(())
}

pub use crate::audio::rtp::RETRANSMIT_REQUEST_LEN;

/// The audio shape a stream `SETUP` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioStreamFormat {
    /// `ct`.
    pub compression: u64,
    /// `audioFormat`.
    pub audio_format: u64,
    /// `sr`.
    pub sample_rate: u32,
    /// `spf`.
    pub frames_per_packet: u32,
    /// Bits per sample, from `audioFormat` (16 when the bit is not one we know).
    pub bits_per_sample: u8,
    /// Channels, from `audioFormat` (2 when unknown).
    pub channels: u8,
}

impl AudioStreamFormat {
    /// The shape from the stream `SETUP`'s numbers; depth and channels come from the `audioFormat`
    /// bit, and an unknown bit means 16-bit stereo.
    #[must_use]
    pub fn new(
        compression: u64,
        audio_format: u64,
        sample_rate: u32,
        frames_per_packet: u32,
    ) -> Self {
        let bits_per_sample = match audio_format {
            audio_format::ALAC_44100_24_2 | audio_format::ALAC_48000_24_2 => 24,
            _ => 16,
        };
        Self {
            compression,
            audio_format,
            sample_rate,
            frames_per_packet,
            bits_per_sample,
            channels: 2,
        }
    }
}

/// Interleaved 16-bit PCM for one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PcmPacket {
    /// Samples, interleaved (L, R, L, R…). 24-bit sources are shifted down to 16 bits.
    pub samples: Vec<i16>,
    /// Channels.
    pub channels: u8,
    /// Frames per second.
    pub sample_rate: u32,
    /// The RTP sequence number this came from.
    pub sequence: u16,
    /// The RTP timestamp of its first frame (for a concealed packet, the one its slot would have
    /// carried). What a playout scheduler maps to a play time.
    pub timestamp: RtpTimestamp,
    /// Whether this is silence standing in for a packet that never arrived.
    pub concealed: bool,
}

/// One decrypted, **undecoded** access unit (AAC-ELD) of a wrapped-key Apple stream, drained
/// through the same reorder pipeline as [`PcmPacket`].
#[cfg(feature = "mirror")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccessUnitPacket {
    /// The decrypted access unit, undecoded. Empty for a concealed slot.
    pub payload: Vec<u8>,
    /// Channels the stream declared.
    pub channels: u8,
    /// Frames per second the stream declared.
    pub sample_rate: u32,
    /// The RTP sequence number this came from.
    pub sequence: u16,
    /// The RTP timestamp of its first frame.
    pub timestamp: RtpTimestamp,
    /// Whether this stands in for a packet that never arrived (then `payload` is empty).
    pub concealed: bool,
}

/// What the receiver has seen, for a log line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RealtimeStats {
    /// Data-port packets that opened.
    pub packets_opened: u64,
    /// Packets that did not authenticate or parse.
    pub packets_rejected: u64,
    /// Packets that arrived after their slot was played (or twice).
    pub packets_late: u64,
    /// Missing sequence numbers detected.
    pub gaps_detected: u64,
    /// Retransmit requests sent (one request may name several packets).
    pub retransmit_requests: u64,
    /// Packets that came back in a `0xD6` reply.
    pub packets_retransmitted: u64,
    /// Packets replaced by silence.
    pub packets_concealed: u64,
    /// PCM packets released.
    pub packets_played: u64,
    /// Sync packets read.
    pub sync_packets: u64,
    /// Restarts: a packet more than [`RESYNC_DISTANCE`] ahead, or a candidate timeline whose lead
    /// reached its threshold.
    pub resyncs: u64,
    /// Authenticated packets whose sequence number disagrees with their timestamp, so were held on
    /// a candidate timeline or dropped.
    pub packets_unplaced: u64,
}

/// What [`RealtimeReceiver::place`] made of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// This extended sequence number.
    At(u64),
    /// The current stream's numbering, but further behind than [`MAX_MISORDER`].
    Stale,
    /// Not the current stream's numbering (its timestamp disagrees).
    Foreign,
}

/// Where a packet came from: only the data port can move the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Data,
    Retransmit,
}

/// A timeline other than the stream's, on probation.
struct Probation {
    /// Held packets, `(timestamp, payload)` by extended sequence number.
    held: BTreeMap<u64, (RtpTimestamp, Vec<u8>)>,
    /// This timeline's highest packet so far, and its timestamp.
    highest: u64,
    highest_timestamp: RtpTimestamp,
    /// Packets at or below this were held and let go; a repeat of one is not counted again.
    floor: u64,
    /// New packets on this timeline, less those the stream placed (or a third timeline sent).
    lead: usize,
    /// The lead that restarts the stream here: [`FORWARD_RESTART_PACKETS`] or
    /// [`BACKWARD_RESTART_PACKETS`].
    needed: usize,
}

impl Probation {
    fn new(sequence: u16, timestamp: RtpTimestamp, payload: Vec<u8>, needed: usize) -> Self {
        let first = FIRST_EXTENDED + u64::from(sequence);
        Self {
            held: BTreeMap::from([(first, (timestamp, payload))]),
            highest: first,
            highest_timestamp: timestamp,
            floor: 0,
            lead: 1,
            needed,
        }
    }

    /// Where a packet falls on this timeline, if it is on it: within [`MAX_MISORDER`] behind or
    /// [`MAX_DROPOUT`] ahead of the highest packet, and `delta × spf` from its timestamp.
    fn follow(&self, sequence: u16, timestamp: RtpTimestamp, spf: u32) -> Option<u64> {
        let low = (self.highest & 0xFFFF) as u16;
        let delta = i64::from(sequence.wrapping_sub(low) as i16);
        if delta < -i64::from(MAX_MISORDER) || delta > i64::from(MAX_DROPOUT) {
            return None;
        }
        // Truncation intended: the timestamp wraps at 2^32, and so does this product.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let advance = (delta * i64::from(spf)) as u32;
        if timestamp != self.highest_timestamp.wrapping_add(advance) {
            return None;
        }
        self.highest.checked_add_signed(delta)
    }
}

/// Decodes one stream's packets to interleaved 16-bit PCM: **ALAC** (24-bit keeps the top 16 bits)
/// or **16-bit big-endian LPCM**. Shared by [`RealtimeReceiver`] and hosts of a buffered stream
/// ([`super::buffered::BufferedReceiver`]). AAC is refused by [`Self::new`].
pub struct PacketDecoder {
    inner: PcmDecoder,
}

enum PcmDecoder {
    Alac(Box<alac::Decoder>, Vec<i32>, AlacShape),
    /// Channels and frames per packet: a payload is cut to whole frames, at most `spf`.
    Lpcm(usize, usize),
}

/// What [`alac_hazard`] needs to walk a packet's element headers.
#[derive(Clone, Copy)]
struct AlacShape {
    bit_depth: u32,
    frame_length: u32,
}

impl std::fmt::Debug for PacketDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.inner {
            PcmDecoder::Alac(..) => "PacketDecoder(ALAC)",
            PcmDecoder::Lpcm(..) => "PacketDecoder(LPCM)",
        })
    }
}

impl PacketDecoder {
    /// A decoder for `format`.
    ///
    /// # Errors
    ///
    /// `spf` outside `1..=`[`MAX_FRAMES_PER_PACKET`], `sr` outside
    /// [`MIN_SAMPLE_RATE`]`..=`[`MAX_SAMPLE_RATE`], an ALAC shape the decoder refuses, LPCM other
    /// than 16-bit, or a compression type other than LPCM (1) and ALAC (2).
    pub fn new(format: AudioStreamFormat) -> Result<Self> {
        check_shape(&format)?;
        let inner = match format.compression {
            compression::ALAC => {
                let config = AlacConfig::new(
                    format.frames_per_packet,
                    format.bits_per_sample,
                    format.channels,
                    format.sample_rate,
                )?;
                let info = alac::StreamInfo::from_cookie(&config.magic_cookie()).map_err(|e| {
                    AirPlayError::Protocol(format!("ALAC configuration refused: {e:?}"))
                })?;
                let capacity = format.frames_per_packet as usize * usize::from(format.channels);
                let shape = AlacShape {
                    bit_depth: u32::from(format.bits_per_sample),
                    frame_length: format.frames_per_packet,
                };
                PcmDecoder::Alac(Box::new(alac::Decoder::new(info)), vec![0; capacity], shape)
            }
            compression::LPCM => {
                if format.bits_per_sample != 16 {
                    return Err(AirPlayError::Protocol(
                        "LPCM other than 16-bit is not decoded".to_owned(),
                    ));
                }
                PcmDecoder::Lpcm(
                    usize::from(format.channels),
                    format.frames_per_packet as usize,
                )
            }
            other => {
                return Err(AirPlayError::Protocol(format!(
                    "compression type {other} is not decoded here (1 LPCM and 2 ALAC are)"
                )))
            }
        };
        Ok(Self { inner })
    }

    /// One packet's payload to interleaved samples. LPCM is cut to whole frames, at most `spf` of
    /// them, so a short or ragged payload never shifts the channels of what follows.
    ///
    /// # Errors
    ///
    /// A frame the ALAC decoder refuses, or one whose element headers have a shape the decoder
    /// would panic on (refused before it is called).
    ///
    /// The ALAC decoder is a third-party crate that can still panic on hostile input this check
    /// cannot see (for instance an arithmetic overflow in a build with overflow checks). That
    /// panic is caught and returned as an error, which needs `panic = "unwind"` (the default);
    /// under `panic = "abort"` it ends the process.
    pub fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>> {
        match &mut self.inner {
            PcmDecoder::Lpcm(channels, spf) => {
                let frame_bytes = 2 * (*channels).max(1);
                let frames = (payload.len() / frame_bytes).min(*spf);
                Ok(lpcm16_be(&payload[..frames * frame_bytes]))
            }
            PcmDecoder::Alac(decoder, scratch, shape) => {
                if let Some(why) = alac_hazard(payload, *shape) {
                    return Err(AirPlayError::Protocol(format!("ALAC frame refused: {why}")));
                }
                // The `alac` crate can panic on hostile input; never panic on peer bytes.
                let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder
                        .decode_packet(payload, scratch.as_mut_slice())
                        .map(<[i32]>::to_vec)
                }))
                .map_err(|_| AirPlayError::Protocol("ALAC decoder panicked on a frame".to_owned()))?
                .map_err(|e| AirPlayError::Protocol(format!("ALAC frame refused: {e:?}")))?;
                // i32 samples are left-justified for any depth.
                Ok(decoded.iter().map(|&s| (s >> 16) as i16).collect())
            }
        }
    }
}

/// A big-endian bit reader over a packet, for [`alac_hazard`].
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Bits<'_> {
    fn read(&mut self, count: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            let byte = *self.bytes.get(self.at / 8)?;
            value = (value << 1) | u32::from((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        Some(value)
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        let to = self.at.checked_add(count)?;
        (to <= self.bytes.len() * 8).then(|| self.at = to)
    }
}

/// Why the `alac` crate would panic on this packet, when its element headers show it: an LPC
/// order of 31 (an assertion in the crate), an LPC quantization of 0 or a fill count of 15 + 0
/// (an integer underflow), or a sample shift wider than the bit depth. Walks the headers the way
/// the crate reads them, up to the first compressed element's predictor headers; what lies past
/// that element's residuals is left to the crate and the `catch_unwind` around it. A shape the
/// crate refuses on its own is passed through for it to refuse.
fn alac_hazard(packet: &[u8], shape: AlacShape) -> Option<&'static str> {
    const SCE: u32 = 0;
    const CPE: u32 = 1;
    const LFE: u32 = 3;
    const DSE: u32 = 4;
    const FIL: u32 = 6;
    let mut bits = Bits {
        bytes: packet,
        at: 0,
    };
    loop {
        match bits.read(3)? {
            tag @ (SCE | CPE | LFE) => {
                let channels = if tag == CPE { 2 } else { 1 };
                bits.read(4)?;
                if bits.read(12)? != 0 {
                    return None;
                }
                let partial = bits.read(1)? == 1;
                let shift = bits.read(2)?;
                if shift > 2 {
                    return None;
                }
                if shift * 8 > shape.bit_depth {
                    return Some("a sample shift wider than the bit depth");
                }
                let uncompressed = bits.read(1)? == 1;
                let samples = if partial {
                    bits.read(32)?
                } else {
                    shape.frame_length
                };
                if samples > shape.frame_length {
                    return None;
                }
                if uncompressed {
                    if shift != 0 {
                        return None;
                    }
                    let width = (samples as usize)
                        .checked_mul(channels)?
                        .checked_mul(shape.bit_depth as usize)?;
                    bits.skip(width)?;
                    continue;
                }
                bits.read(16)?;
                for _ in 0..channels {
                    bits.read(4)?;
                    let quant = bits.read(4)?;
                    bits.read(3)?;
                    let order = bits.read(5)?;
                    if order == 31 {
                        return Some("an LPC order of 31");
                    }
                    if quant == 0 && samples > order + 1 {
                        return Some("an LPC quantization of 0");
                    }
                    bits.skip(order as usize * 16)?;
                }
                return None;
            }
            DSE => {
                bits.read(4)?;
                let align = bits.read(1)? == 1;
                let mut count = bits.read(8)?;
                if count == 255 {
                    count += bits.read(8)?;
                }
                if align {
                    bits.skip((8 - bits.at % 8) % 8)?;
                }
                bits.skip(count as usize * 8)?;
            }
            FIL => {
                let mut count = bits.read(4)?;
                if count == 15 {
                    let extra = bits.read(8)?;
                    if extra == 0 {
                        return Some("a fill element whose count underflows");
                    }
                    count += extra - 1;
                }
                bits.skip(count as usize * 8)?;
            }
            _ => return None,
        }
    }
}

enum Decoder {
    Pcm(PacketDecoder),
    /// A wrapped-key Apple sender's AAC-ELD, decrypted but **not decoded**. Drained through
    /// [`RealtimeReceiver::next_access_unit`]; [`RealtimeReceiver::next_pcm`] refuses it.
    #[cfg(feature = "mirror")]
    Undecoded,
}

/// One realtime stream. See the module docs.
pub struct RealtimeReceiver {
    key: [u8; 32],
    /// AirPlay 1's clear audio: packets are read with [`crate::raop::open_clear_packet`].
    clear: bool,
    /// A wrapped-key sender's AES-128-CBC key and IV: when set, packets are opened with
    /// [`crate::audio::rtp::open_packet_aes_cbc`] instead of ChaCha20.
    #[cfg(feature = "mirror")]
    aes_cbc: Option<super::connection::AesCbcAudioKey>,
    format: AudioStreamFormat,
    decoder: Decoder,
    head: Option<u64>,
    /// The highest packet placed (after a `FLUSH` naming `seq` and `rtptime`, the slot before it).
    highest: Option<u64>,
    /// The authenticated RTP timestamp of `highest`.
    highest_timestamp: RtpTimestamp,
    /// A `FLUSH`'s `rtptime` when it came without `seq`.
    flushed_to: Option<RtpTimestamp>,
    /// A candidate timeline, waiting for a lead that restarts the stream on it.
    probation: Option<Probation>,
    buffer: BTreeMap<u64, Vec<u8>>,
    /// Missing packets: when each was last asked for, and how many times.
    missing: BTreeMap<u64, (Option<Duration>, u32)>,
    request_sequence: u16,
    last_sync: Option<SyncPacket>,
    stats: RealtimeStats,
    /// Packets that may queue behind a missing one before it is concealed.
    conceal_after: u64,
}

impl std::fmt::Debug for RealtimeReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealtimeReceiver")
            .field("format", &self.format)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl RealtimeReceiver {
    /// A receiver for one stream: `key` is the stream `SETUP`'s `shk`.
    pub fn new(key: [u8; 32], format: AudioStreamFormat) -> Result<Self> {
        let decoder = Decoder::Pcm(PacketDecoder::new(format)?);
        Ok(Self {
            key,
            clear: false,
            #[cfg(feature = "mirror")]
            aes_cbc: None,
            format,
            decoder,
            head: None,
            highest: None,
            highest_timestamp: RtpTimestamp::new(0),
            flushed_to: None,
            probation: None,
            buffer: BTreeMap::new(),
            missing: BTreeMap::new(),
            request_sequence: 0,
            last_sync: None,
            stats: RealtimeStats::default(),
            conceal_after: CONCEAL_AFTER_PACKETS,
        })
    }

    /// A receiver for an AirPlay 1 sender's **unencrypted** audio ([`crate::raop`]): packets carry
    /// no seal, so nothing authenticates them; the host pins the data port to the sender.
    pub fn new_unencrypted(format: AudioStreamFormat) -> Result<Self> {
        let mut receiver = Self::new([0u8; 32], format)?;
        receiver.clear = true;
        Ok(receiver)
    }

    /// A receiver for a **wrapped-key** sender's audio (the `mirror` feature): AES-128-CBC with
    /// `key` from [`crate::mirror::MirrorKey::from_session_key`] and `iv` the `SETUP`'s `eiv`.
    /// Audio is decrypted but not decoded: drain it with [`Self::next_access_unit`].
    #[cfg(feature = "mirror")]
    pub fn new_aes_cbc(
        cbc: super::connection::AesCbcAudioKey,
        format: AudioStreamFormat,
    ) -> Result<Self> {
        check_shape(&format)?;
        Ok(Self {
            key: [0u8; 32],
            clear: false,
            aes_cbc: Some(cbc),
            format,
            decoder: Decoder::Undecoded,
            head: None,
            highest: None,
            highest_timestamp: RtpTimestamp::new(0),
            flushed_to: None,
            probation: None,
            buffer: BTreeMap::new(),
            missing: BTreeMap::new(),
            request_sequence: 0,
            last_sync: None,
            stats: RealtimeStats::default(),
            conceal_after: CONCEAL_AFTER_PACKETS,
        })
    }

    /// Conceals a missing packet once `packets` later ones wait (for low-latency streams), clamped
    /// to `1..=`[`CONCEAL_AFTER_PACKETS`].
    pub fn set_conceal_after(&mut self, packets: u64) {
        self.conceal_after = packets.clamp(1, CONCEAL_AFTER_PACKETS);
    }

    /// Later packets that may wait behind a missing one before it is concealed.
    #[must_use]
    pub fn conceal_after(&self) -> u64 {
        self.conceal_after
    }

    /// The format.
    #[must_use]
    pub fn format(&self) -> AudioStreamFormat {
        self.format
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> RealtimeStats {
        self.stats
    }

    /// The last sync packet the sender sent, if any.
    #[must_use]
    pub fn last_sync(&self) -> Option<SyncPacket> {
        self.last_sync
    }

    /// `FLUSH` with `RTP-Info: seq=N;rtptime=T`: drop what is held and start again there. Either
    /// may be missing; the first packet is then trusted or checked against what is given.
    pub fn flush(&mut self, next_sequence: Option<u16>, next_timestamp: Option<RtpTimestamp>) {
        self.reset();
        match (next_sequence, next_timestamp) {
            (Some(sequence), Some(timestamp)) => {
                let head = FIRST_EXTENDED + u64::from(sequence);
                self.head = Some(head);
                self.highest = Some(head - 1);
                self.highest_timestamp = timestamp.wrapping_sub(self.format.frames_per_packet);
            }
            (sequence, timestamp) => {
                self.head = sequence.map(|s| FIRST_EXTENDED + u64::from(s));
                self.flushed_to = timestamp;
            }
        }
    }

    /// Drops what is held and forgets where the stream was.
    fn reset(&mut self) {
        self.buffer.clear();
        self.missing.clear();
        self.head = None;
        self.highest = None;
        self.flushed_to = None;
        self.probation = None;
    }

    /// Opens a packet with this stream's cipher (ChaCha20-Poly1305, or AES-128-CBC if wrapped).
    fn open(&self, packet: &[u8]) -> Result<crate::audio::rtp::OpenedPacket> {
        if self.clear {
            return crate::raop::open_clear_packet(packet);
        }
        #[cfg(feature = "mirror")]
        if let Some(cbc) = &self.aes_cbc {
            return open_packet_aes_cbc(&cbc.key, &cbc.iv, packet);
        }
        open_packet(&self.key, packet)
    }

    /// One datagram from the data port.
    pub fn on_data(&mut self, datagram: &[u8]) -> Result<()> {
        let opened = match self.open(datagram) {
            Ok(opened) => opened,
            Err(e) => {
                self.stats.packets_rejected += 1;
                return Err(e);
            }
        };
        let header = RtpHeader::parse(&opened.header)?;
        self.stats.packets_opened += 1;
        self.insert(
            header.sequence,
            header.timestamp,
            opened.payload,
            Origin::Data,
        );
        Ok(())
    }

    /// One datagram from the control port: a retransmit reply (`0xD6`) or a sync packet (`0xD4`).
    /// Anything else is ignored (`Ok(false)`).
    pub fn on_control(&mut self, datagram: &[u8]) -> Result<bool> {
        let Some(&kind) = datagram.get(1) else {
            return Ok(false);
        };
        match kind & 0x7F {
            RETRANSMIT_REPLY_PAYLOAD_TYPE => {
                let inner = datagram.get(4..).unwrap_or_default();
                let opened = match self.open(inner) {
                    Ok(opened) => opened,
                    Err(e) => {
                        self.stats.packets_rejected += 1;
                        return Err(e);
                    }
                };
                let header = RtpHeader::parse(&opened.header)?;
                self.stats.packets_retransmitted += 1;
                self.insert(
                    header.sequence,
                    header.timestamp,
                    opened.payload,
                    Origin::Retransmit,
                );
                Ok(true)
            }
            SYNC_PAYLOAD_TYPE => {
                self.last_sync = Some(SyncPacket::parse(datagram)?);
                self.stats.sync_packets += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// `sequence` extended relative to the flushed-to head, for the first packet (no highest yet).
    fn extend_from_head(&self, sequence: u16) -> u64 {
        let Some(head) = self.head else {
            return FIRST_EXTENDED + u64::from(sequence);
        };
        let low = (head & 0xFFFF) as u16;
        let delta = i64::from(sequence.wrapping_sub(low) as i16);
        head.saturating_add_signed(delta)
    }

    /// Where a packet goes relative to the highest one. It belongs to the stream's numbering only
    /// if its authenticated timestamp agrees (`delta × spf`). Such a packet is placed if inside or
    /// ahead of the window, **stale** if further behind than [`MAX_MISORDER`], and anything that
    /// disagrees is **foreign**.
    fn place(&self, highest: u64, sequence: u16, timestamp: RtpTimestamp) -> Placement {
        let low = (highest & 0xFFFF) as u16;
        let ahead = sequence.wrapping_sub(low);
        let delta = i64::from(ahead as i16);
        // Truncation intended: the timestamp wraps at 2^32, and so does this product.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let advance = (delta * i64::from(self.format.frames_per_packet)) as u32;
        if timestamp != self.highest_timestamp.wrapping_add(advance) {
            return Placement::Foreign;
        }
        if delta < -i64::from(MAX_MISORDER) {
            return Placement::Stale;
        }
        highest
            .checked_add_signed(delta)
            .map_or(Placement::Stale, Placement::At)
    }

    fn insert(&mut self, sequence: u16, timestamp: RtpTimestamp, payload: Vec<u8>, origin: Origin) {
        let ext = match self.highest {
            Some(highest) => match self.place(highest, sequence, timestamp) {
                Placement::At(ext) => ext,
                Placement::Stale => {
                    // Late or replayed: never probation, so replays cannot pull the stream back.
                    self.stats.packets_late += 1;
                    return;
                }
                Placement::Foreign => {
                    let needed = if timestamp.is_after(self.highest_timestamp) {
                        FORWARD_RESTART_PACKETS
                    } else {
                        BACKWARD_RESTART_PACKETS
                    };
                    self.unplaced(sequence, timestamp, payload, origin, needed);
                    return;
                }
            },
            None => {
                if self
                    .flushed_to
                    .is_some_and(|flushed| flushed.is_after(timestamp))
                {
                    // Before the `FLUSH`'s `rtptime`: held like a packet behind the stream.
                    self.unplaced(
                        sequence,
                        timestamp,
                        payload,
                        origin,
                        BACKWARD_RESTART_PACKETS,
                    );
                    return;
                }
                self.extend_from_head(sequence)
            }
        };
        let head = match self.head {
            Some(head) => head,
            None => {
                self.head = Some(ext);
                ext
            }
        };
        if ext < head || self.buffer.contains_key(&ext) {
            self.stats.packets_late += 1;
            return;
        }
        // A data packet the stream really took counts against any candidate timeline.
        if origin == Origin::Data {
            self.against_probation();
        }
        if ext - head > RESYNC_DISTANCE {
            self.stats.resyncs += 1;
            self.reset();
            self.head = Some(ext);
            self.highest = Some(ext);
            self.highest_timestamp = timestamp;
            self.buffer.insert(ext, payload);
            return;
        }
        let expected = self.highest.map_or(head, |h| h + 1);
        for gap in expected.max(head)..ext {
            if !self.buffer.contains_key(&gap) && !self.missing.contains_key(&gap) {
                self.missing.insert(gap, (None, 0));
                self.stats.gaps_detected += 1;
            }
        }
        self.missing.remove(&ext);
        if self.highest.is_none_or(|h| ext > h) {
            self.highest = Some(ext);
            self.highest_timestamp = timestamp;
        }
        self.buffer.insert(ext, payload);
    }

    /// An unplaceable packet: a retransmit reply is dropped, a data packet goes on probation.
    fn unplaced(
        &mut self,
        sequence: u16,
        timestamp: RtpTimestamp,
        payload: Vec<u8>,
        origin: Origin,
        needed: usize,
    ) {
        match origin {
            Origin::Data => self.on_probation(sequence, timestamp, payload, needed),
            Origin::Retransmit => self.stats.packets_unplaced += 1,
        }
    }

    /// A data packet that could not be placed: on the candidate it raises the lead (restarting the
    /// stream at the threshold); on a third timeline it lowers it. `needed` is the threshold for a
    /// candidate this packet opens.
    fn on_probation(
        &mut self,
        sequence: u16,
        timestamp: RtpTimestamp,
        payload: Vec<u8>,
        needed: usize,
    ) {
        let spf = self.format.frames_per_packet;
        self.stats.packets_unplaced += 1;
        if let Some(run) = self.probation.as_mut() {
            if let Some(ext) = run.follow(sequence, timestamp, spf) {
                if ext <= run.floor || run.held.contains_key(&ext) {
                    return;
                }
                run.held.insert(ext, (timestamp, payload));
                if ext > run.highest {
                    run.highest = ext;
                    run.highest_timestamp = timestamp;
                }
                while run.held.len() > MAX_HELD_PACKETS {
                    if let Some((oldest, _)) = run.held.pop_first() {
                        run.floor = oldest;
                    }
                }
                run.lead += 1;
                if run.lead >= run.needed {
                    self.restart_on_probation();
                }
                return;
            }
            run.lead = run.lead.saturating_sub(1);
            if run.lead > 0 {
                return;
            }
        }
        self.probation = Some(Probation::new(sequence, timestamp, payload, needed));
    }

    /// A data packet the stream placed: one less for the candidate, which is dropped at zero.
    fn against_probation(&mut self) {
        if let Some(run) = self.probation.as_mut() {
            run.lead = run.lead.saturating_sub(1);
            if run.lead == 0 {
                self.probation = None;
            }
        }
    }

    /// Restarts the stream on the candidate timeline, dropping what was waiting as a `FLUSH` would,
    /// and places what the candidate held, in order.
    fn restart_on_probation(&mut self) {
        let Some(run) = self.probation.take() else {
            return;
        };
        self.stats.resyncs += 1;
        self.reset();
        for (ext, (timestamp, payload)) in run.held {
            // Truncation intended: the low 16 bits are the sequence number.
            #[allow(clippy::cast_possible_truncation)]
            let sequence = ext as u16;
            self.insert(sequence, timestamp, payload, Origin::Data);
        }
    }

    /// The retransmit requests due at `now` (the caller's monotonic clock, time since any fixed
    /// origin), each ready to send to the sender's control port. Consecutive missing packets share
    /// one request.
    pub fn retransmit_requests(&mut self, now: Duration) -> Vec<[u8; RETRANSMIT_REQUEST_LEN]> {
        let head = self.head.unwrap_or(0);
        self.missing
            .retain(|&ext, (_, attempts)| ext >= head && *attempts < RETRANSMIT_ATTEMPTS);
        let due: Vec<u64> = self
            .missing
            .iter()
            .filter(|(_, (last, _))| last.is_none_or(|t| now.saturating_sub(t) >= RETRANSMIT_RETRY))
            .map(|(&ext, _)| ext)
            .collect();
        let mut out = Vec::new();
        let mut run: Option<(u64, u16)> = None;
        for ext in due {
            if let Some(entry) = self.missing.get_mut(&ext) {
                entry.0 = Some(now);
                entry.1 += 1;
            }
            run = match run {
                Some((first, count)) if first + u64::from(count) == ext && count < u16::MAX => {
                    Some((first, count + 1))
                }
                Some((first, count)) => {
                    out.push(self.request(first, count));
                    Some((ext, 1))
                }
                None => Some((ext, 1)),
            };
        }
        if let Some((first, count)) = run {
            out.push(self.request(first, count));
        }
        out
    }

    fn request(&mut self, first: u64, count: u16) -> [u8; RETRANSMIT_REQUEST_LEN] {
        self.stats.retransmit_requests += 1;
        self.request_sequence = self.request_sequence.wrapping_add(1);
        retransmit_request(self.request_sequence, (first & 0xFFFF) as u16, count)
    }

    /// Takes the head slot when a packet is ready or a gap should be concealed (`None` payload).
    /// Shared by [`Self::next_pcm`] and [`Self::next_access_unit`].
    fn drain_head(&mut self) -> Option<(Option<Vec<u8>>, u16, RtpTimestamp)> {
        let head = self.head?;
        let payload = match self.buffer.remove(&head) {
            Some(payload) => Some(payload),
            None => {
                let waiting = self.highest.map_or(0, |h| h.saturating_sub(head));
                if self.buffer.is_empty() || waiting < self.conceal_after {
                    return None;
                }
                None
            }
        };
        self.head = Some(head + 1);
        self.missing.remove(&head);
        let sequence = (head & 0xFFFF) as u16;
        // Every placed packet agrees with the highest one: `delta × spf` from its timestamp.
        let behind = self.highest.map_or(0, |h| h.saturating_sub(head));
        // Truncation intended: RTP timestamps wrap at 2^32, and so does this product.
        #[allow(clippy::cast_possible_truncation)]
        let timestamp = self
            .highest_timestamp
            .wrapping_sub((behind as u32).wrapping_mul(self.format.frames_per_packet));
        Some((payload, sequence, timestamp))
    }

    /// The next PCM packet, if one is ready.
    pub fn next_pcm(&mut self) -> Result<Option<PcmPacket>> {
        let Some((payload, sequence, timestamp)) = self.drain_head() else {
            return Ok(None);
        };
        let frames = self.format.frames_per_packet as usize;
        let channels = usize::from(self.format.channels);
        let (samples, concealed) = match payload {
            Some(payload) => (self.decode(&payload)?, false),
            None => {
                self.stats.packets_concealed += 1;
                (vec![0i16; frames * channels], true)
            }
        };
        self.stats.packets_played += 1;
        Ok(Some(PcmPacket {
            samples,
            channels: self.format.channels,
            sample_rate: self.format.sample_rate,
            sequence,
            timestamp,
            concealed,
        }))
    }

    /// The next decrypted, **undecoded** access unit of a wrapped-key stream. A concealed slot
    /// yields an empty payload with `concealed` set.
    #[cfg(feature = "mirror")]
    pub fn next_access_unit(&mut self) -> Option<AccessUnitPacket> {
        let (payload, sequence, timestamp) = self.drain_head()?;
        let concealed = payload.is_none();
        if concealed {
            self.stats.packets_concealed += 1;
        }
        self.stats.packets_played += 1;
        Some(AccessUnitPacket {
            payload: payload.unwrap_or_default(),
            sample_rate: self.format.sample_rate,
            channels: self.format.channels,
            sequence,
            timestamp,
            concealed,
        })
    }

    fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>> {
        match &mut self.decoder {
            Decoder::Pcm(decoder) => decoder.decode(payload),
            #[cfg(feature = "mirror")]
            Decoder::Undecoded => Err(AirPlayError::InvalidState(
                "a wrapped-key Apple stream is drained as access units (next_access_unit), not PCM"
                    .to_owned(),
            )),
        }
    }
}

/// Interleaved big-endian 16-bit samples. A trailing odd byte is dropped; cutting a payload to
/// whole frames is the caller's ([`PacketDecoder::decode`] does).
#[must_use]
pub fn lpcm16_be(payload: &[u8]) -> Vec<i16> {
    let (pairs, _) = payload.as_chunks::<2>();
    pairs.iter().map(|pair| i16::from_be_bytes(*pair)).collect()
}

/// A retransmit request in pyatv's layout: `80 D5 <request seq> <first lost> <count>`, all
/// big-endian `u16`.
#[must_use]
pub fn retransmit_request(
    sequence: u16,
    first_lost: u16,
    count: u16,
) -> [u8; RETRANSMIT_REQUEST_LEN] {
    crate::audio::rtp::RetransmitRequest::new(sequence, first_lost, count).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Big-endian bit writer for hand-built ALAC packets.
    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        at: usize,
    }

    impl BitWriter {
        fn put(&mut self, count: usize, value: u32) -> &mut Self {
            for i in (0..count).rev() {
                if self.at.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                let bit = u8::try_from((value >> i) & 1).unwrap();
                *self.bytes.last_mut().unwrap() |= bit << (7 - self.at % 8);
                self.at += 1;
            }
            self
        }
    }

    fn alac_stereo() -> PacketDecoder {
        PacketDecoder::new(AudioStreamFormat::new(2, 1 << 18, 44_100, 352)).unwrap()
    }

    /// A compressed stereo element (CPE) with the given LPC order and quantization on its first
    /// channel, followed by enough zero bits for the residuals of both channels to decode.
    fn compressed_pair(order: u32, quant: u32) -> Vec<u8> {
        let mut bits = BitWriter::default();
        bits.put(3, 1).put(4, 0).put(12, 0); // CPE, instance, unused
        bits.put(1, 0).put(2, 0).put(1, 0); // not partial, no shift, compressed
        bits.put(8, 0).put(8, 0); // mix bits, mix res
        bits.put(4, 0).put(4, quant).put(3, 4).put(5, order);
        for _ in 0..order {
            bits.put(16, 0);
        }
        bits.put(4, 0).put(4, 9).put(3, 4).put(5, 0);
        let mut packet = bits.bytes;
        packet.resize(packet.len() + 4096, 0);
        packet
    }

    fn refused_without_a_panic(packet: &[u8]) {
        let error = alac_stereo().decode(packet).expect_err("refused");
        let text = error.to_string();
        assert!(
            text.contains("refused") && !text.contains("panicked"),
            "{text}"
        );
    }

    #[test]
    fn an_lpc_order_of_31_is_refused_before_the_decoder_asserts_on_it() {
        refused_without_a_panic(&compressed_pair(31, 9));
    }

    #[test]
    fn an_lpc_quantization_of_0_is_refused_before_the_decoder_underflows() {
        refused_without_a_panic(&compressed_pair(0, 0));
    }

    #[test]
    fn a_fill_count_that_underflows_is_refused_before_the_decoder_sees_it() {
        let mut bits = BitWriter::default();
        bits.put(3, 6).put(4, 15).put(8, 0); // FIL, count 15 + 0 - 1
        let mut packet = bits.bytes;
        packet.resize(64, 0);
        refused_without_a_panic(&packet);
    }

    #[test]
    fn an_ordinary_order_and_quantization_still_reach_the_decoder() {
        let shape = AlacShape {
            bit_depth: 16,
            frame_length: 352,
        };
        assert_eq!(alac_hazard(&compressed_pair(8, 9), shape), None);
        assert_eq!(alac_hazard(&[], shape), None);
    }

    #[test]
    fn lpcm_is_cut_to_whole_frames() {
        let mut decoder =
            PacketDecoder::new(AudioStreamFormat::new(1, 1 << 11, 44_100, 352)).unwrap();
        // Six bytes of stereo are one frame and half of another: the half is dropped.
        assert_eq!(
            decoder.decode(&[0, 1, 0, 2, 0, 3]).unwrap(),
            vec![1, 2],
            "one whole frame"
        );
        assert_eq!(decoder.decode(&[0, 1, 0]).unwrap(), Vec::<i16>::new());
    }

    #[test]
    fn lpcm_is_capped_at_frames_per_packet() {
        let mut decoder =
            PacketDecoder::new(AudioStreamFormat::new(1, 1 << 11, 44_100, 352)).unwrap();
        let samples = decoder.decode(&vec![0u8; 400 * 4]).unwrap();
        assert_eq!(samples.len(), 352 * 2);
    }
}
