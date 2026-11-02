//! ALAC for AirPlay: the magic cookie, its SDP `fmtp` spelling, and a verbatim (uncompressed)
//! frame encoder.
//!
//! Verbatim frames set the element header's escape flag, so every ALAC decoder accepts them; the
//! cost is bandwidth (about 1.4 Mbit/s for 16-bit stereo). The cookie is the 24-byte big-endian
//! `ALACSpecificConfig`. This crate's receiver decodes these frames
//! ([`crate::receiver::PacketDecoder`]).

use super::format::{compression, StreamFormat};
use crate::error::{AirPlayError, Result};

/// `ID_SCE`: a single channel element.
const ID_SCE: u32 = 0;
/// `ID_CPE`: a channel pair element.
const ID_CPE: u32 = 1;
/// `ID_END`: end of frame.
const ID_END: u32 = 7;

/// Length of the `ALACSpecificConfig` magic cookie.
pub const MAGIC_COOKIE_LEN: usize = 24;

/// `compatibleVersion`; must be 0.
pub const COMPATIBLE_VERSION: u8 = 0;
/// `pb`.
pub const PB: u8 = 40;
/// `mb`.
pub const MB: u8 = 10;
/// `kb`.
pub const KB: u8 = 14;
/// `maxRun`.
pub const MAX_RUN: u16 = 255;

/// The ALAC stream configuration a receiver decodes with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AlacConfig {
    /// `frameLength`: frames per packet (352 on AirPlay).
    pub frame_length: u32,
    /// `bitDepth`: 16 or 24.
    pub bit_depth: u8,
    /// `numChannels`: 1 or 2.
    pub channels: u8,
    /// `sampleRate`.
    pub sample_rate: u32,
}

impl AlacConfig {
    /// A configuration. Only 16- and 24-bit, mono or stereo, is supported by the encoder.
    pub fn new(frame_length: u32, bit_depth: u8, channels: u8, sample_rate: u32) -> Result<Self> {
        if !matches!(bit_depth, 16 | 24) {
            return Err(AirPlayError::Protocol(format!(
                "ALAC verbatim encoding supports 16- and 24-bit samples, not {bit_depth}"
            )));
        }
        if !matches!(channels, 1 | 2) {
            return Err(AirPlayError::Protocol(format!(
                "ALAC verbatim encoding supports 1 or 2 channels, not {channels}"
            )));
        }
        if frame_length == 0 {
            return Err(AirPlayError::Protocol(
                "an ALAC frame length of 0 cannot hold audio".to_owned(),
            ));
        }
        Ok(Self {
            frame_length,
            bit_depth,
            channels,
            sample_rate,
        })
    }

    /// The configuration for a stream format, which must be ALAC.
    pub fn for_format(format: &StreamFormat) -> Result<Self> {
        if format.compression != compression::ALAC {
            return Err(AirPlayError::Protocol(format!(
                "stream compression {} is not ALAC",
                format.compression
            )));
        }
        Self::new(
            format.frames_per_packet,
            format.bits_per_sample,
            format.channels,
            format.sample_rate,
        )
    }

    /// The 24-byte `ALACSpecificConfig`, big-endian; `maxFrameBytes` and `avgBitRate` are 0.
    #[must_use]
    pub fn magic_cookie(&self) -> [u8; MAGIC_COOKIE_LEN] {
        let mut out = [0u8; MAGIC_COOKIE_LEN];
        out[0..4].copy_from_slice(&self.frame_length.to_be_bytes());
        out[4] = COMPATIBLE_VERSION;
        out[5] = self.bit_depth;
        out[6] = PB;
        out[7] = MB;
        out[8] = KB;
        out[9] = self.channels;
        out[10..12].copy_from_slice(&MAX_RUN.to_be_bytes());
        // 12..16 maxFrameBytes = 0, 16..20 avgBitRate = 0
        out[20..24].copy_from_slice(&self.sample_rate.to_be_bytes());
        out
    }

    /// The cookie as an SDP `a=fmtp:` line, the eleven fields in decimal.
    #[must_use]
    pub fn fmtp(&self, payload_type: u8) -> String {
        format!(
            "a=fmtp:{payload_type} {} {COMPATIBLE_VERSION} {} {PB} {MB} {KB} {} {MAX_RUN} 0 0 {}",
            self.frame_length, self.bit_depth, self.channels, self.sample_rate
        )
    }

    /// The size of a verbatim frame carrying `frames` frames.
    #[must_use]
    pub fn verbatim_frame_len(&self, frames: usize) -> usize {
        let partial = frames != self.frame_length as usize;
        let bits = 3
            + 4
            + 12
            + 4
            + if partial { 32 } else { 0 }
            + frames * usize::from(self.channels) * usize::from(self.bit_depth)
            + 3;
        bits.div_ceil(8)
    }

    /// Encodes interleaved samples (L, R, L, R, … for stereo) as one verbatim ALAC frame.
    ///
    /// Up to `frame_length` frames; fewer sets the partial-frame flag. Each sample must fit
    /// `bit_depth` bits signed.
    pub fn encode_verbatim(&self, interleaved: &[i32]) -> Result<Vec<u8>> {
        let channels = usize::from(self.channels);
        if interleaved.is_empty() || !interleaved.len().is_multiple_of(channels) {
            return Err(AirPlayError::Protocol(format!(
                "{} samples is not a whole number of {channels}-channel frames",
                interleaved.len()
            )));
        }
        let frames = interleaved.len() / channels;
        if frames > self.frame_length as usize {
            return Err(AirPlayError::Protocol(format!(
                "{frames} frames exceed the ALAC frame length {}",
                self.frame_length
            )));
        }
        let depth = u32::from(self.bit_depth);
        let min = -(1i64 << (depth - 1));
        let max = (1i64 << (depth - 1)) - 1;
        if let Some(bad) = interleaved
            .iter()
            .find(|&&sample| !(min..=max).contains(&i64::from(sample)))
        {
            return Err(AirPlayError::Protocol(format!(
                "sample {bad} does not fit {depth} bits"
            )));
        }

        let partial = frames != self.frame_length as usize;
        let mut bits = BitWriter::with_capacity(self.verbatim_frame_len(frames));
        bits.put(if channels == 2 { ID_CPE } else { ID_SCE }, 3);
        bits.put(0, 4); // element instance tag
        bits.put(0, 12); // unused, must be zero
        bits.put(u32::from(partial), 1);
        bits.put(0, 2); // bytesShifted
        bits.put(1, 1); // escape: uncompressed
        if partial {
            // frames <= frame_length (a u32), so this cannot truncate.
            bits.put(frames as u32, 32);
        }
        let mask = (1u32 << depth) - 1;
        for &sample in interleaved {
            // Two's complement truncated to `depth` bits; the decoder sign-extends.
            bits.put(sample as u32 & mask, depth);
        }
        bits.put(ID_END, 3);
        Ok(bits.finish())
    }

    /// [`Self::encode_verbatim`] for 16-bit samples.
    pub fn encode_verbatim_i16(&self, interleaved: &[i16]) -> Result<Vec<u8>> {
        let widened: Vec<i32> = interleaved.iter().map(|&s| i32::from(s)).collect();
        self.encode_verbatim(&widened)
    }
}

/// MSB-first bit writer.
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    count: u32,
}

impl BitWriter {
    fn with_capacity(bytes: usize) -> Self {
        Self {
            out: Vec::with_capacity(bytes),
            acc: 0,
            count: 0,
        }
    }

    /// Appends the low `width` bits of `value` (width <= 32).
    fn put(&mut self, value: u32, width: u32) {
        debug_assert!(width <= 32);
        if width == 0 {
            return;
        }
        let masked = u64::from(value) & ((1u64 << width) - 1);
        self.acc = (self.acc << width) | masked;
        self.count += width;
        while self.count >= 8 {
            self.count -= 8;
            self.out.push((self.acc >> self.count) as u8);
        }
        self.acc &= (1u64 << self.count) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.out.push((self.acc << (8 - self.count)) as u8);
        }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cd() -> AlacConfig {
        AlacConfig::new(352, 16, 2, 44_100).unwrap()
    }

    #[test]
    fn a_partial_stereo_frame_starts_with_the_classic_raop_header() {
        // 0x20 0x00 0x12: ID_CPE, instance 0, unused 0, partial=1, shift=0, escape=1.
        let frame = cd().encode_verbatim(&[0, 0]).unwrap();
        assert_eq!(frame[..3], [0x20, 0x00, 0x12]);
    }

    #[test]
    fn a_full_stereo_frame_has_no_count_and_the_right_length() {
        let samples = vec![0x1234i32; 352 * 2];
        let frame = cd().encode_verbatim(&samples).unwrap();
        assert_eq!(frame[..3], [0x20, 0x00, 0x02]);
        assert_eq!(frame.len(), cd().verbatim_frame_len(352));
        assert_eq!(frame.len(), 1412);
    }

    #[test]
    fn samples_outside_the_bit_depth_are_refused() {
        assert!(cd().encode_verbatim(&[40_000, 0]).is_err());
        let hi = AlacConfig::new(352, 24, 2, 48_000).unwrap();
        assert!(hi.encode_verbatim(&[8_388_607, -8_388_608]).is_ok());
        assert!(hi.encode_verbatim(&[8_388_608, 0]).is_err());
    }

    #[test]
    fn too_many_or_ragged_frames_are_refused() {
        assert!(cd().encode_verbatim(&vec![0; 353 * 2]).is_err());
        assert!(cd().encode_verbatim(&[0, 0, 0]).is_err());
        assert!(cd().encode_verbatim(&[]).is_err());
        assert!(AlacConfig::new(352, 20, 2, 44_100).is_err());
        assert!(AlacConfig::new(352, 16, 6, 44_100).is_err());
    }

    #[test]
    fn the_cookie_is_big_endian_alac_specific_config() {
        assert_eq!(
            hex::encode(cd().magic_cookie()),
            "000001600010280a0e0200ff00000000000000000000ac44"
        );
    }
}
