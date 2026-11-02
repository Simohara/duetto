//! The 128-byte little-endian header in front of every packet on the mirroring data connection.
//!
//! Layout: payload size (0..4), type (4: 0 video, 1 codec record, 2 heartbeat, 5 report), `0x10`
//! IDR flag (5), option (6..8), timestamp (8..16: NTP Q32.32 minus the 1900-1970 seconds),
//! codec-record `f32` sizes (16/20, 40/44 source; 56/60 output). ASSUMED for Apple devices.

use crate::error::{AirPlayError, Result};
use crate::time::NtpTimestamp;

use super::HEADER_LEN;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970); a mirroring timestamp omits them.
pub const NTP_UNIX_OFFSET_SECONDS: u32 = 2_208_988_800;

/// Byte 5 of a video packet's header that carries an IDR.
pub const IDR_FLAG: u8 = 0x10;

/// The option an H.264 codec record carries.
pub const OPTION_H264: u16 = 0x0116;

/// The option an H.264 codec record carries while the sender's screen sleeps.
pub const OPTION_H264_SLEEPING: u16 = 0x0156;

/// The option an HEVC codec record carries (refused: this crate reads H.264 only).
pub const OPTION_HEVC: u16 = 0x011e;

/// What a payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PayloadKind {
    /// `0`: one access unit as AVCC, encrypted.
    Video,
    /// `1`: the codec record (`avcC`), clear.
    CodecConfig,
    /// `2`: a heartbeat, no payload.
    Heartbeat,
    /// `5`: a streaming report (a plist), clear.
    Report,
    /// Anything else.
    Other(u8),
}

impl PayloadKind {
    /// The kind byte 4 names.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Video,
            1 => Self::CodecConfig,
            2 => Self::Heartbeat,
            5 => Self::Report,
            other => Self::Other(other),
        }
    }

    /// The byte this kind is written as.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Video => 0,
            Self::CodecConfig => 1,
            Self::Heartbeat => 2,
            Self::Report => 5,
            Self::Other(byte) => byte,
        }
    }
}

/// The picture sizes a codec record carries. Never trusted: the coded size comes from the SPS
/// ([`super::avc::SpsInfo`]).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HeaderDimensions {
    /// Source width (offsets 16 and 40).
    pub source_width: f32,
    /// Source height (offsets 20 and 44).
    pub source_height: f32,
    /// Output width (offset 56).
    pub width: f32,
    /// Output height (offset 60).
    pub height: f32,
}

/// One packet's header.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacketHeader {
    /// Bytes of payload that follow.
    pub payload_len: u32,
    /// What the payload is.
    pub kind: PayloadKind,
    /// Byte 5: [`IDR_FLAG`] on a video packet with an IDR.
    pub flags: u8,
    /// Bytes 6–7.
    pub option: u16,
    /// The timestamp as written (see [`ntp_from_header`]).
    pub timestamp: u64,
    /// The sizes a codec record carries (zero otherwise).
    pub dimensions: HeaderDimensions,
}

impl PacketHeader {
    /// A header for `kind` with nothing else set.
    #[must_use]
    pub fn new(kind: PayloadKind, payload_len: u32, timestamp: u64) -> Self {
        Self {
            payload_len,
            kind,
            flags: 0,
            option: 0,
            timestamp,
            dimensions: HeaderDimensions::default(),
        }
    }

    /// Whether byte 5 marks an IDR.
    #[must_use]
    pub fn is_idr(&self) -> bool {
        self.flags & IDR_FLAG != 0
    }

    /// Reads a header from the first [`HEADER_LEN`] bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// Fewer than [`HEADER_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header: &[u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| AirPlayError::Protocol("mirror header is short".to_owned()))?;
        let u32_at = |at: usize| {
            u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        let f32_at = |at: usize| {
            f32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&header[8..16]);
        Ok(Self {
            payload_len: u32_at(0),
            kind: PayloadKind::from_byte(header[4]),
            flags: header[5],
            option: u16::from_le_bytes([header[6], header[7]]),
            timestamp: u64::from_le_bytes(timestamp),
            dimensions: HeaderDimensions {
                source_width: f32_at(16),
                source_height: f32_at(20),
                width: f32_at(56),
                height: f32_at(60),
            },
        })
    }

    /// The header's 128 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.payload_len.to_le_bytes());
        out[4] = self.kind.to_byte();
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.option.to_le_bytes());
        out[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        if self.kind == PayloadKind::CodecConfig {
            let d = self.dimensions;
            out[16..20].copy_from_slice(&d.source_width.to_le_bytes());
            out[20..24].copy_from_slice(&d.source_height.to_le_bytes());
            out[40..44].copy_from_slice(&d.source_width.to_le_bytes());
            out[44..48].copy_from_slice(&d.source_height.to_le_bytes());
            out[56..60].copy_from_slice(&d.width.to_le_bytes());
            out[60..64].copy_from_slice(&d.height.to_le_bytes());
        }
        out
    }
}

/// An NTP time as a mirroring header writes it: seconds less [`NTP_UNIX_OFFSET_SECONDS`] (wrapping)
/// in the high half, fraction low.
#[must_use]
pub fn header_from_ntp(ntp: NtpTimestamp) -> u64 {
    ntp.to_bits()
        .wrapping_sub(u64::from(NTP_UNIX_OFFSET_SECONDS) << 32)
}

/// The NTP time a mirroring header's timestamp names (the inverse of [`header_from_ntp`]).
#[must_use]
pub fn ntp_from_header(timestamp: u64) -> NtpTimestamp {
    NtpTimestamp::from_bits(timestamp.wrapping_add(u64::from(NTP_UNIX_OFFSET_SECONDS) << 32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fields_sit_at_their_offsets_little_endian() {
        let mut header =
            PacketHeader::new(PayloadKind::CodecConfig, 0x0102_0304, 0x1122_3344_5566_7788);
        header.option = OPTION_H264;
        header.dimensions = HeaderDimensions {
            source_width: 1920.0,
            source_height: 1080.0,
            width: 1280.0,
            height: 720.0,
        };
        let bytes = header.encode();
        assert_eq!(&bytes[0..4], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(bytes[4], 1);
        assert_eq!(&bytes[6..8], &[0x16, 0x01]);
        assert_eq!(
            &bytes[8..16],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(&bytes[16..20], &1920f32.to_le_bytes());
        assert_eq!(&bytes[40..44], &1920f32.to_le_bytes());
        assert_eq!(&bytes[60..64], &720f32.to_le_bytes());
        assert_eq!(PacketHeader::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn an_idr_video_header_round_trips_and_a_short_one_is_refused() {
        let mut header = PacketHeader::new(PayloadKind::Video, 1234, 42);
        header.flags = IDR_FLAG;
        let decoded = PacketHeader::decode(&header.encode()).unwrap();
        assert!(decoded.is_idr());
        assert_eq!(decoded.dimensions, HeaderDimensions::default());
        assert!(PacketHeader::decode(&[0u8; HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn the_timestamp_drops_the_1900_to_1970_seconds_and_wraps() {
        let ntp = NtpTimestamp::from_parts(3_900_000_000, 0x8000_0000);
        let written = header_from_ntp(ntp);
        assert_eq!(
            written,
            (u64::from(3_900_000_000u32 - NTP_UNIX_OFFSET_SECONDS) << 32) | 0x8000_0000
        );
        assert_eq!(ntp_from_header(written), ntp);
        let early = NtpTimestamp::from_parts(5, 7);
        assert_eq!(ntp_from_header(header_from_ntp(early)), early);
    }
}
