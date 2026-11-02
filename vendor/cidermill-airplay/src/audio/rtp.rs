//! Audio packets: the RTP header, the per-packet ChaCha20-Poly1305 seal, the buffered channel's
//! length-prefixed framing, RTP timestamp arithmetic, and the realtime sync packet.
//!
//! ```text
//!   [ 12-byte RTP header ][ ciphertext ][ 16-byte Poly1305 tag ][ 8-byte nonce ]
//!            ^ bytes 4..12 (timestamp + SSRC) are the AEAD associated data
//! ```
//!
//! The key is the stream `SETUP`'s `shk`; the 12-byte nonce is four zero bytes plus the trailer (a
//! little-endian counter), as in the control channel ([`crate::cipher::hap_nonce`]). The seal
//! matches pyatv byte for byte. Realtime (UDP) headers follow RFC 3550; buffered (TCP) headers
//! reuse bytes 1..4 as a 23-bit sequence with the marker bit set. Observed: an Apple TV on tvOS 26
//! accepts realtime packets and requests withheld ones by sequence, but that does not show it
//! authenticated the seal. Buffered packets are taken by an Apple TV after a pause anchor and
//! played by this crate's receiver.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};

use crate::cipher::hap_nonce;
use crate::error::{AirPlayError, Result};
use crate::time::{NtpTimestamp, RtpTimestamp};

/// Length of the RTP header.
pub const HEADER_LEN: usize = 12;
/// Length of the Poly1305 tag in the trailer.
pub const TAG_LEN: usize = 16;
/// Length of the nonce carried in the trailer.
pub const NONCE_LEN: usize = 8;
/// Length of the whole trailer (tag + nonce).
pub const TRAILER_LEN: usize = TAG_LEN + NONCE_LEN;

/// The RTP version byte: V=2, no padding, no extension, no CSRCs.
pub const VERSION_BYTE: u8 = 0x80;
/// The marker bit in byte 1.
pub const MARKER_BIT: u8 = 0x80;
/// Payload type of a realtime audio packet (96, dynamic).
pub const AUDIO_PAYLOAD_TYPE: u8 = 0x60;
/// Payload type of a realtime sync packet on the control port (`0xD4` with the marker bit).
pub const SYNC_PAYLOAD_TYPE: u8 = 0x54;
/// Payload type of a retransmit request from the receiver (`0xD5` with the marker bit).
pub const RETRANSMIT_REQUEST_PAYLOAD_TYPE: u8 = 0x55;
/// Payload type of a retransmitted packet on the control port (`0xD6` with the marker bit).
pub const RETRANSMIT_REPLY_PAYLOAD_TYPE: u8 = 0x56;

/// The largest buffered sequence number: 23 bits.
pub const BUFFERED_SEQUENCE_MASK: u32 = 0x007F_FFFF;

/// A realtime (RFC 3550) RTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpHeader {
    /// The marker bit; set on the first packet of a stream.
    pub marker: bool,
    /// 7-bit payload type; [`AUDIO_PAYLOAD_TYPE`] for audio.
    pub payload_type: u8,
    /// 16-bit sequence number, wrapping.
    pub sequence: u16,
    /// RTP timestamp in frames.
    pub timestamp: RtpTimestamp,
    /// Synchronisation source.
    pub ssrc: u32,
}

impl RtpHeader {
    /// An audio packet header.
    #[must_use]
    pub fn audio(first: bool, sequence: u16, timestamp: RtpTimestamp, ssrc: u32) -> Self {
        Self {
            marker: first,
            payload_type: AUDIO_PAYLOAD_TYPE,
            sequence,
            timestamp,
            ssrc,
        }
    }

    /// The 12 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION_BYTE;
        out[1] = (self.payload_type & 0x7F) | if self.marker { MARKER_BIT } else { 0 };
        out[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.get().to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        out
    }

    /// Reads a header from the front of a packet.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = header_bytes(bytes)?;
        Ok(Self {
            marker: header[1] & MARKER_BIT != 0,
            payload_type: header[1] & 0x7F,
            sequence: u16::from_be_bytes([header[2], header[3]]),
            timestamp: RtpTimestamp::new(be32(&header[4..8])),
            ssrc: be32(&header[8..12]),
        })
    }
}

/// A buffered-audio RTP header: bytes 1..4 carry a 23-bit sequence with the marker bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedHeader {
    /// 23-bit sequence number; higher bits are masked off on encode.
    pub sequence: u32,
    /// RTP timestamp in frames.
    pub timestamp: RtpTimestamp,
    /// The format identifier (see [`super::format::buffered_ssrc`]), not a random source id.
    pub ssrc: u32,
}

impl BufferedHeader {
    /// A buffered header.
    #[must_use]
    pub fn new(sequence: u32, timestamp: RtpTimestamp, ssrc: u32) -> Self {
        Self {
            sequence,
            timestamp,
            ssrc,
        }
    }

    /// The 12 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let marked = 0x0080_0000 | (self.sequence & BUFFERED_SEQUENCE_MASK);
        out[0] = VERSION_BYTE;
        out[1..4].copy_from_slice(&marked.to_be_bytes()[1..4]);
        out[4..8].copy_from_slice(&self.timestamp.get().to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        out
    }

    /// Reads a header the way shairport-sync does: the low 23 bits of bytes 0..4.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = header_bytes(bytes)?;
        Ok(Self {
            sequence: be32(&header[0..4]) & BUFFERED_SEQUENCE_MASK,
            timestamp: RtpTimestamp::new(be32(&header[4..8])),
            ssrc: be32(&header[8..12]),
        })
    }
}

fn header_bytes(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < HEADER_LEN {
        return Err(AirPlayError::Protocol(format!(
            "an RTP packet needs {HEADER_LEN} header bytes, got {}",
            bytes.len()
        )));
    }
    Ok(&bytes[..HEADER_LEN])
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The associated data of a packet: the header's timestamp and SSRC.
#[must_use]
pub fn associated_data(header: &[u8; HEADER_LEN]) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&header[4..12]);
    aad
}

/// Seals audio packets with the stream key, one nonce per packet.
pub struct PacketSealer {
    cipher: ChaCha20Poly1305,
    next_nonce: u64,
}

impl std::fmt::Debug for PacketSealer {
    /// Deliberately opaque: key material must never reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketSealer")
            .field("next_nonce", &self.next_nonce)
            .finish_non_exhaustive()
    }
}

impl PacketSealer {
    /// A sealer whose first packet uses nonce counter 0.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self::with_counter(key, 0)
    }

    /// A sealer starting at a given nonce counter.
    #[must_use]
    pub fn with_counter(key: &[u8; 32], next_nonce: u64) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            next_nonce,
        }
    }

    /// The counter the next [`Self::seal`] will use.
    #[must_use]
    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Seals one packet: `header || ciphertext || tag || nonce[4..12]`.
    ///
    /// The nonce counter advances once per packet; wraparound is unreachable in practice.
    pub fn seal(&mut self, header: &[u8; HEADER_LEN], payload: &[u8]) -> Result<Vec<u8>> {
        let counter = self.next_nonce;
        let nonce = hap_nonce(counter);
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
        out.extend_from_slice(header);
        out.extend_from_slice(payload);
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &Nonce::from(nonce),
                &associated_data(header),
                (&mut out[HEADER_LEN..]).into(),
            )
            .map_err(|_| AirPlayError::Protocol("audio packet seal failed".to_owned()))?;
        out.extend_from_slice(&tag);
        out.extend_from_slice(&nonce[4..]);
        self.next_nonce = counter.wrapping_add(1);
        Ok(out)
    }
}

/// A packet opened by [`open_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenedPacket {
    /// The 12 header bytes, as sent.
    pub header: [u8; HEADER_LEN],
    /// The decrypted payload.
    pub payload: Vec<u8>,
    /// The nonce counter read from the trailer.
    pub nonce: u64,
}

/// Opens a sealed packet the way a receiver does: nonce from the last 8 bytes, tag before it,
/// header bytes 4..12 as associated data.
///
/// For round trips, fuzzing and receiver doubles.
pub fn open_packet(key: &[u8; 32], packet: &[u8]) -> Result<OpenedPacket> {
    if packet.len() < HEADER_LEN + TRAILER_LEN {
        return Err(AirPlayError::Protocol(format!(
            "a sealed audio packet is at least {} bytes, got {}",
            HEADER_LEN + TRAILER_LEN,
            packet.len()
        )));
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&packet[..HEADER_LEN]);
    let nonce_at = packet.len() - NONCE_LEN;
    let tag_at = nonce_at - TAG_LEN;
    let mut counter = [0u8; NONCE_LEN];
    counter.copy_from_slice(&packet[nonce_at..]);
    let counter = u64::from_le_bytes(counter);
    let mut payload = packet[HEADER_LEN..tag_at].to_vec();
    let tag = Tag::try_from(&packet[tag_at..nonce_at])
        .map_err(|_| AirPlayError::Protocol("audio packet tag is not 16 bytes".to_owned()))?;
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_inout_detached(
            &Nonce::from(hap_nonce(counter)),
            &associated_data(&header),
            payload.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| AirPlayError::Protocol("audio packet failed to authenticate".to_owned()))?;
    Ok(OpenedPacket {
        header,
        payload,
        nonce: counter,
    })
}

/// Opens a wrapped-key Apple sender's realtime audio packet: whole 16-byte blocks of the payload
/// are AES-128-CBC decrypted with `iv` (reset for every packet), and trailing bytes are plaintext.
///
/// # Security
///
/// Unlike [`open_packet`] there is no AEAD tag, so a tampered or replayed packet is not detected.
/// Use it only on a pair-verified connection, with `key` from `MirrorKey::from_session_key` and
/// `iv` the `SETUP`'s `eiv`. `nonce` in the result is always 0.
#[cfg(feature = "mirror")]
pub fn open_packet_aes_cbc(key: &[u8; 16], iv: &[u8; 16], packet: &[u8]) -> Result<OpenedPacket> {
    use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
    if packet.len() < HEADER_LEN {
        return Err(AirPlayError::Protocol(format!(
            "an AES-CBC audio packet needs at least {HEADER_LEN} header bytes, got {}",
            packet.len()
        )));
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&packet[..HEADER_LEN]);
    let mut payload = packet[HEADER_LEN..].to_vec();
    let whole = payload.len() / 16 * 16;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut payload[..whole])
        .map_err(|_| AirPlayError::Protocol("AES-CBC audio decrypt failed".to_owned()))?;
    // Bytes past the last whole block are already plaintext.
    Ok(OpenedPacket {
        header,
        payload,
        nonce: 0,
    })
}

/// Length of the buffered channel's length prefix.
pub const FRAME_PREFIX_LEN: usize = 2;

/// Frames one packet for the buffered TCP data channel: a big-endian `u16` length that includes
/// the two prefix bytes themselves, then the packet.
pub fn frame_buffered(packet: &[u8]) -> Result<Vec<u8>> {
    let total = packet
        .len()
        .checked_add(FRAME_PREFIX_LEN)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| {
            AirPlayError::Protocol(format!(
                "a buffered audio packet of {} bytes does not fit the 16-bit length prefix",
                packet.len()
            ))
        })?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}

/// Recovers packets from a buffered data channel byte stream, the inverse of [`frame_buffered`].
///
/// Bounded: it holds at most one partial frame plus whatever the caller pushed at once.
#[derive(Debug, Default)]
pub struct BufferedFrameDecoder {
    pending: Vec<u8>,
}

impl BufferedFrameDecoder {
    /// An empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// Bytes held that do not yet form a whole frame.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// The next whole packet, `Ok(None)` if more bytes are needed, or an error for a length
    /// prefix that cannot describe a frame (less than the prefix itself). An error is terminal:
    /// the stream has lost its framing.
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.pending.len() < FRAME_PREFIX_LEN {
            return Ok(None);
        }
        let total = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
        if total < FRAME_PREFIX_LEN {
            return Err(AirPlayError::Protocol(format!(
                "buffered frame length {total} is shorter than its own prefix"
            )));
        }
        if self.pending.len() < total {
            return Ok(None);
        }
        let packet = self.pending[FRAME_PREFIX_LEN..total].to_vec();
        self.pending.drain(..total);
        Ok(Some(packet))
    }
}

/// RTP timestamp and sequence arithmetic for one stream.
///
/// Packet `n` carries `first_timestamp + n × frames_per_packet` (mod 2^32); a short final packet
/// is zero-padded, so it still advances by a whole packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpClock {
    /// Frames per second.
    pub sample_rate: u32,
    /// Frames per packet.
    pub frames_per_packet: u32,
    /// The timestamp of packet 0.
    pub first_timestamp: RtpTimestamp,
}

impl RtpClock {
    /// A clock for a stream.
    #[must_use]
    pub fn new(sample_rate: u32, frames_per_packet: u32, first_timestamp: RtpTimestamp) -> Self {
        Self {
            sample_rate,
            frames_per_packet,
            first_timestamp,
        }
    }

    /// The RTP timestamp of packet `index`, wrapping at 2^32.
    #[must_use]
    pub fn timestamp_of_packet(&self, index: u64) -> RtpTimestamp {
        let frames = index.wrapping_mul(u64::from(self.frames_per_packet));
        // Truncation to 32 bits IS the RTP wrap.
        self.first_timestamp.wrapping_add(frames as u32)
    }

    /// Nanoseconds spanned by `frames` at this rate (floor).
    #[must_use]
    pub fn nanos_for_frames(&self, frames: u64) -> u128 {
        if self.sample_rate == 0 {
            return 0;
        }
        u128::from(frames) * 1_000_000_000 / u128::from(self.sample_rate)
    }

    /// Frames spanned by `nanos` at this rate (floor).
    #[must_use]
    pub fn frames_for_nanos(&self, nanos: u128) -> u128 {
        nanos * u128::from(self.sample_rate) / 1_000_000_000
    }
}

/// The realtime sequence number of packet `index`, wrapping at 2^16.
#[must_use]
pub fn realtime_sequence(first: u16, index: u64) -> u16 {
    // Truncation to 16 bits IS the RTP wrap.
    first.wrapping_add(index as u16)
}

/// The buffered sequence number of packet `index`, wrapping at 2^23.
#[must_use]
pub fn buffered_sequence(first: u32, index: u64) -> u32 {
    (u64::from(first).wrapping_add(index) & u64::from(BUFFERED_SEQUENCE_MASK)) as u32
}

/// Length of a realtime sync packet.
pub const SYNC_PACKET_LEN: usize = 20;

/// The flags word every sync packet this crate sends carries.
pub const SYNC_FLAGS: u16 = 7;

/// The realtime control-channel sync packet.
///
/// ```text
///   0x90 (first) / 0x80, 0xD4, 0x0007,
///   now_without_latency (u32), ntp (u64, 32.32), now (u32)
/// ```
///
/// Sent about once a second on a realtime stream; buffered streams use `SETRATEANCHORTIME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncPacket {
    /// Whether this is the first sync of the stream (`0x90` rather than `0x80`).
    pub first: bool,
    /// The second 16-bit word: 7 from current senders, 4 from older AirPlay
    /// ([`crate::receiver::playout::FLAG7_LATENCY_OFFSET_FRAMES`] applies at 7).
    pub flags: u16,
    /// The RTP time now, minus the latency.
    pub now_without_latency: RtpTimestamp,
    /// The sender's clock when `now` is sent.
    pub ntp: NtpTimestamp,
    /// The RTP time now.
    pub now: RtpTimestamp,
}

impl SyncPacket {
    /// A sync packet.
    #[must_use]
    pub fn new(
        first: bool,
        now_without_latency: RtpTimestamp,
        ntp: NtpTimestamp,
        now: RtpTimestamp,
    ) -> Self {
        Self {
            first,
            flags: SYNC_FLAGS,
            now_without_latency,
            ntp,
            now,
        }
    }

    /// The 20 packet bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SYNC_PACKET_LEN] {
        let mut out = [0u8; SYNC_PACKET_LEN];
        out[0] = if self.first { 0x90 } else { 0x80 };
        out[1] = MARKER_BIT | SYNC_PAYLOAD_TYPE;
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..8].copy_from_slice(&self.now_without_latency.get().to_be_bytes());
        out[8..16].copy_from_slice(&self.ntp.to_bits().to_be_bytes());
        out[16..20].copy_from_slice(&self.now.get().to_be_bytes());
        out
    }
}

impl SyncPacket {
    /// Reads a sync packet off a receiver's control port (`0x80`/`0x90`, `0xD4`), the inverse of
    /// [`Self::encode`]. An error for anything shorter or of another payload type.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SYNC_PACKET_LEN {
            return Err(AirPlayError::Protocol(format!(
                "a sync packet is {SYNC_PACKET_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[1] & 0x7F != SYNC_PAYLOAD_TYPE {
            return Err(AirPlayError::Protocol(format!(
                "payload type {:#04x} is not a sync packet",
                bytes[1]
            )));
        }
        Ok(Self {
            first: bytes[0] & 0x10 != 0,
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            now_without_latency: RtpTimestamp::new(be32(&bytes[4..8])),
            ntp: NtpTimestamp::from_parts(be32(&bytes[8..12]), be32(&bytes[12..16])),
            now: RtpTimestamp::new(be32(&bytes[16..20])),
        })
    }
}

/// Length of a retransmit request.
pub const RETRANSMIT_REQUEST_LEN: usize = 8;

/// The most packets [`RetransmitRequest::lost_sequences`] yields.
pub const MAX_RETRANSMIT_PACKETS: u16 = 1024;

/// A receiver's request for realtime packets it did not get (`0x80 0xD5`): the request's own
/// sequence, the first lost sequence and the count, all big-endian `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetransmitRequest {
    /// The request's own sequence number (bytes 2..4).
    pub sequence: u16,
    /// The first sequence number that was lost.
    pub first_lost: u16,
    /// How many consecutive packets from `first_lost` are wanted.
    pub count: u16,
}

impl RetransmitRequest {
    /// A request.
    #[must_use]
    pub fn new(sequence: u16, first_lost: u16, count: u16) -> Self {
        Self {
            sequence,
            first_lost,
            count,
        }
    }

    /// Parses a request. Shorter than eight bytes, not RTP version 2, or another payload type is
    /// an error; bytes after the eighth are ignored.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let Some(head) = bytes.get(..RETRANSMIT_REQUEST_LEN) else {
            return Err(AirPlayError::Protocol(format!(
                "a retransmit request is {RETRANSMIT_REQUEST_LEN} bytes, got {}",
                bytes.len()
            )));
        };
        if head[0] & 0xC0 != VERSION_BYTE {
            return Err(AirPlayError::Protocol(format!(
                "a retransmit request is RTP version 2, byte 0 was {:#04x}",
                head[0]
            )));
        }
        if head[1] & 0x7F != RETRANSMIT_REQUEST_PAYLOAD_TYPE {
            return Err(AirPlayError::Protocol(format!(
                "not a retransmit request: payload type {:#04x}",
                head[1] & 0x7F
            )));
        }
        let be = |at: usize| u16::from_be_bytes([head[at], head[at + 1]]);
        Ok(Self {
            sequence: be(2),
            first_lost: be(4),
            count: be(6),
        })
    }

    /// The eight request bytes, marker bit set.
    #[must_use]
    pub fn encode(&self) -> [u8; RETRANSMIT_REQUEST_LEN] {
        let mut out = [0u8; RETRANSMIT_REQUEST_LEN];
        out[0] = VERSION_BYTE;
        out[1] = MARKER_BIT | RETRANSMIT_REQUEST_PAYLOAD_TYPE;
        out[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        out[4..6].copy_from_slice(&self.first_lost.to_be_bytes());
        out[6..8].copy_from_slice(&self.count.to_be_bytes());
        out
    }

    /// The sequence numbers asked for, wrapping at 2^16, at most [`MAX_RETRANSMIT_PACKETS`].
    pub fn lost_sequences(&self) -> impl Iterator<Item = u16> {
        let first = self.first_lost;
        (0..self.count.min(MAX_RETRANSMIT_PACKETS)).map(move |i| first.wrapping_add(i))
    }
}

/// The retransmit reply (`0x80 0xD6`) for the sealed packet `sequence`: the sequence, then the
/// original packet whole.
#[must_use]
pub fn retransmit_reply(sequence: u16, original: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + original.len());
    out.push(VERSION_BYTE);
    out.push(MARKER_BIT | RETRANSMIT_REPLY_PAYLOAD_TYPE);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(original);
    out
}

/// A frame count as an NTP time, `((frames << 16) / rate) << 16`, as pyatv's sync packets carry
/// it; zero at a zero rate.
#[must_use]
pub fn timestamp_to_ntp(timestamp: u64, sample_rate: u32) -> NtpTimestamp {
    if sample_rate == 0 {
        return NtpTimestamp::ZERO;
    }
    NtpTimestamp::from_bits(
        (((u128::from(timestamp) << 16) / u128::from(sample_rate)) as u64) << 16,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_retransmit_request_round_trips_in_pyatvs_layout() {
        // OBSERVED from an Apple TV: `80 d5 00 01 <seq> 00 01` for one withheld packet.
        let raw = [0x80, 0xD5, 0x00, 0x01, 0x12, 0x34, 0x00, 0x01];
        let request = super::RetransmitRequest::parse(&raw).unwrap();
        assert_eq!(request, super::RetransmitRequest::new(1, 0x1234, 1));
        assert_eq!(request.encode(), raw);
        assert_eq!(request.lost_sequences().collect::<Vec<_>>(), [0x1234]);
        let unmarked = [0x80, 0x55, 0, 0, 0xFF, 0xFF, 0, 2, 9];
        let wrapping = super::RetransmitRequest::parse(&unmarked).unwrap();
        assert_eq!(wrapping.lost_sequences().collect::<Vec<_>>(), [0xFFFF, 0]);
        assert_eq!(
            super::RetransmitRequest::new(0, 0, u16::MAX)
                .lost_sequences()
                .count(),
            usize::from(super::MAX_RETRANSMIT_PACKETS)
        );
    }

    #[test]
    fn short_or_foreign_bytes_are_not_a_retransmit_request() {
        for bad in [
            &[0x80, 0xD5, 0, 0, 0, 0, 0][..],
            &[0x40, 0xD5, 0, 0, 0, 0, 0, 1],
            &[0x80, 0xD4, 0, 0, 0, 0, 0, 1],
            &[],
        ] {
            assert!(super::RetransmitRequest::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_retransmit_reply_is_the_prefix_then_the_original() {
        let original = [0x80, 0x60, 0x12, 0x34, 9, 9, 9, 9, 9, 9, 9, 9, 1, 2];
        let reply = super::retransmit_reply(0x1234, &original);
        assert_eq!(&reply[..4], &[0x80, 0xD6, 0x12, 0x34]);
        assert_eq!(&reply[4..], &original);
    }

    use super::*;

    #[test]
    fn realtime_header_round_trips() {
        let header = RtpHeader::audio(true, 0xFFFE, RtpTimestamp::new(0x0102_0304), 0xDEAD_BEEF);
        let bytes = header.encode();
        assert_eq!(bytes[..2], [0x80, 0xE0]);
        assert_eq!(RtpHeader::parse(&bytes).unwrap(), header);
    }

    #[test]
    fn buffered_header_sets_the_marker_and_masks_to_23_bits() {
        let header = BufferedHeader::new(0x00FF_FFFF, RtpTimestamp::new(7), 0x1500_0000);
        let bytes = header.encode();
        assert_eq!(bytes[..4], [0x80, 0xFF, 0xFF, 0xFF]);
        assert_eq!(BufferedHeader::parse(&bytes).unwrap().sequence, 0x7F_FFFF);
        let low = BufferedHeader::new(5, RtpTimestamp::new(0), 0).encode();
        assert_eq!(low[..4], [0x80, 0x80, 0x00, 0x05]);
    }

    #[test]
    fn seal_then_open_round_trips_and_advances_the_nonce() {
        let key = [7u8; 32];
        let mut sealer = PacketSealer::new(&key);
        let header = RtpHeader::audio(false, 1, RtpTimestamp::new(2), 3).encode();
        let first = sealer.seal(&header, b"abc").unwrap();
        let second = sealer.seal(&header, b"abc").unwrap();
        assert_ne!(first, second, "a new nonce changes the ciphertext");
        let opened = open_packet(&key, &second).unwrap();
        assert_eq!(opened.payload, b"abc");
        assert_eq!(opened.nonce, 1);
        assert_eq!(opened.header, header);
    }

    #[test]
    fn a_tampered_timestamp_fails_authentication() {
        let key = [9u8; 32];
        let mut packet = PacketSealer::new(&key)
            .seal(
                &RtpHeader::audio(false, 1, RtpTimestamp::new(2), 3).encode(),
                b"payload",
            )
            .unwrap();
        packet[7] ^= 1; // the timestamp is associated data
        assert!(open_packet(&key, &packet).is_err());
    }

    // KAT: NIST SP 800-38A F.2.2 (CBC-AES128.Decrypt) behind a 12-byte RTP header.
    #[cfg(feature = "mirror")]
    #[test]
    fn aes_cbc_audio_decrypt_matches_the_nist_vector() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let ciphertext = hex::decode(concat!(
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7",
        ))
        .unwrap();
        let expected = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ))
        .unwrap();
        let header = RtpHeader::audio(false, 1, RtpTimestamp::new(2), 3).encode();
        let mut packet = header.to_vec();
        packet.extend_from_slice(&ciphertext);
        let opened = open_packet_aes_cbc(&key, &iv, &packet).unwrap();
        assert_eq!(opened.header, header);
        assert_eq!(opened.payload, expected);
        assert_eq!(opened.nonce, 0);
    }

    // Trailing bytes are plaintext and come through verbatim; the IV resets per packet.
    #[cfg(feature = "mirror")]
    #[test]
    fn aes_cbc_audio_keeps_the_remainder_and_resets_the_iv_each_packet() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        // One whole block (NIST F.2.2 block 1) plus five trailing plaintext bytes.
        let block = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();
        let tail = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let header = RtpHeader::audio(false, 1, RtpTimestamp::new(2), 3).encode();
        let make = || {
            let mut p = header.to_vec();
            p.extend_from_slice(&block);
            p.extend_from_slice(&tail);
            p
        };
        let first = open_packet_aes_cbc(&key, &iv, &make()).unwrap();
        let second = open_packet_aes_cbc(&key, &iv, &make()).unwrap();
        let expected_block = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(first.payload[..16], expected_block[..]);
        assert_eq!(
            first.payload[16..],
            tail,
            "the remainder is carried in the clear"
        );
        assert_eq!(
            first.payload, second.payload,
            "the IV is reset per packet, not chained"
        );
    }

    #[cfg(feature = "mirror")]
    #[test]
    fn aes_cbc_audio_rejects_a_packet_with_no_header() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        assert!(open_packet_aes_cbc(&key, &iv, &[0u8; 8]).is_err());
    }

    #[test]
    fn framing_prefix_counts_itself() {
        let framed = frame_buffered(&[1, 2, 3]).unwrap();
        assert_eq!(framed, [0, 5, 1, 2, 3]);
        let mut decoder = BufferedFrameDecoder::new();
        decoder.push(&framed[..3]);
        assert_eq!(decoder.next_packet().unwrap(), None);
        decoder.push(&framed[3..]);
        assert_eq!(decoder.next_packet().unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(decoder.buffered(), 0);
        assert!(frame_buffered(&vec![0; 65_534]).is_err());
        assert!(frame_buffered(&vec![0; 65_533]).is_ok());
    }

    #[test]
    fn a_prefix_shorter_than_itself_is_an_error() {
        let mut decoder = BufferedFrameDecoder::new();
        decoder.push(&[0, 1, 9]);
        assert!(decoder.next_packet().is_err());
    }

    #[test]
    fn a_sync_packet_parses_back() {
        let rtp = RtpTimestamp::new;
        let packet = SyncPacket::new(true, rtp(1), NtpTimestamp::from_parts(2, 3), rtp(4));
        assert_eq!(SyncPacket::parse(&packet.encode()).unwrap(), packet);
        let later = SyncPacket::new(false, rtp(5), NtpTimestamp::from_parts(6, 7), rtp(8));
        assert_eq!(SyncPacket::parse(&later.encode()).unwrap(), later);
        assert!(SyncPacket::parse(&[0x80, 0xD5, 0, 1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn timestamps_and_sequences_wrap() {
        let first = RtpTimestamp::new(u32::MAX - 351);
        let clock = RtpClock::new(44_100, 352, first);
        assert_eq!(clock.timestamp_of_packet(0), first);
        assert_eq!(clock.timestamp_of_packet(1), RtpTimestamp::new(0));
        assert_eq!(clock.timestamp_of_packet(1).frames_since(first), 352);
        assert_eq!(realtime_sequence(65_535, 1), 0);
        assert_eq!(buffered_sequence(0x7F_FFFF, 1), 0);
        assert_eq!(clock.nanos_for_frames(44_100), 1_000_000_000);
        assert_eq!(clock.frames_for_nanos(1_000_000_000), 44_100);
    }
}
