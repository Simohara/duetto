//! The H.264 around the packets: the `avcC` record, the SPS (coded picture size), and Annex B /
//! AVCC access units. Reads peer-chosen bytes: every length is checked and nothing panics.

use crate::error::{AirPlayError, Result};

use super::{MAX_AREA, MAX_NALS_PER_FRAME, MAX_SIDE, MIN_SIDE};

/// NAL unit type of an IDR slice.
pub const NAL_IDR: u8 = 5;
/// NAL unit type of a sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// NAL unit type of a picture parameter set.
pub const NAL_PPS: u8 = 8;
/// NAL unit type of an access unit delimiter.
pub const NAL_AUD: u8 = 9;

/// The four-byte Annex B start code this module writes.
pub const START_CODE: [u8; 4] = [0, 0, 0, 1];

fn protocol(message: &str) -> AirPlayError {
    AirPlayError::Protocol(format!("mirror H.264: {message}"))
}

/// A NAL unit's type (the low five bits of its first byte), or `None` for an empty unit.
#[must_use]
pub fn nal_type(nal: &[u8]) -> Option<u8> {
    nal.first().map(|b| b & 0x1F)
}

/// The `avcC` record: one SPS and one PPS, four-byte lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvcConfig {
    /// `AVCProfileIndication`.
    pub profile: u8,
    /// `profile_compatibility`.
    pub compatibility: u8,
    /// `AVCLevelIndication`.
    pub level: u8,
    /// The sequence parameter set, a whole NAL unit.
    pub sps: Vec<u8>,
    /// The picture parameter set, a whole NAL unit.
    pub pps: Vec<u8>,
}

impl AvcConfig {
    /// A record for this SPS and PPS; profile, compatibility and level are the SPS's bytes 1–3.
    ///
    /// # Errors
    ///
    /// An SPS shorter than four bytes, either set not of its NAL type, or one over 65 535 bytes.
    pub fn from_parameter_sets(sps: &[u8], pps: &[u8]) -> Result<Self> {
        if sps.len() < 4 || nal_type(sps) != Some(NAL_SPS) {
            return Err(protocol("not an SPS"));
        }
        if nal_type(pps) != Some(NAL_PPS) {
            return Err(protocol("not a PPS"));
        }
        if sps.len() > usize::from(u16::MAX) || pps.len() > usize::from(u16::MAX) {
            return Err(protocol("a parameter set is over 65535 bytes"));
        }
        Ok(Self {
            profile: sps[1],
            compatibility: sps[2],
            level: sps[3],
            sps: sps.to_vec(),
            pps: pps.to_vec(),
        })
    }

    /// Reads a record: version 1, four-byte lengths, exactly one SPS and one PPS; trailing bytes
    /// are tolerated.
    ///
    /// # Errors
    ///
    /// Any of those does not hold.
    pub fn parse(record: &[u8]) -> Result<Self> {
        let byte = |at: usize| {
            record
                .get(at)
                .copied()
                .ok_or_else(|| protocol("avcC is short"))
        };
        let length = |at: usize| -> Result<usize> {
            Ok(usize::from(u16::from_be_bytes([byte(at)?, byte(at + 1)?])))
        };
        if byte(0)? != 1 {
            return Err(protocol("avcC version is not 1"));
        }
        if byte(4)? & 0x03 != 3 {
            return Err(protocol("avcC NAL lengths are not four bytes"));
        }
        if byte(5)? & 0x1F != 1 {
            return Err(protocol("avcC does not carry exactly one SPS"));
        }
        let sps_len = length(6)?;
        let sps_end = 8usize
            .checked_add(sps_len)
            .ok_or_else(|| protocol("avcC SPS length"))?;
        let sps = record
            .get(8..sps_end)
            .ok_or_else(|| protocol("avcC SPS runs past the record"))?;
        if byte(sps_end)? != 1 {
            return Err(protocol("avcC does not carry exactly one PPS"));
        }
        let pps_len = length(sps_end + 1)?;
        let pps_start = sps_end + 3;
        let pps = record
            .get(pps_start..pps_start + pps_len)
            .ok_or_else(|| protocol("avcC PPS runs past the record"))?;
        let config = Self::from_parameter_sets(sps, pps)?;
        Ok(Self {
            profile: byte(1)?,
            compatibility: byte(2)?,
            level: byte(3)?,
            ..config
        })
    }

    /// The record's bytes: version 1, four-byte lengths, one SPS, one PPS, nothing after.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + self.sps.len() + self.pps.len());
        out.extend_from_slice(&[1, self.profile, self.compatibility, self.level, 0xFF, 0xE1]);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.sps.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sps);
        out.push(1);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.pps.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.pps);
        out
    }

    /// The SPS and PPS as Annex B (start code before each).
    #[must_use]
    pub fn annex_b(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sps.len() + self.pps.len());
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(&self.sps);
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(&self.pps);
        out
    }
}

/// The NAL units of an Annex B access unit, without their start codes or trailing zero bytes.
/// Bytes before the first start code are ignored; empty units are skipped.
#[must_use]
pub fn split_annex_b(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            starts.push((i, i + 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut nals = Vec::with_capacity(starts.len());
    for (n, &(_, payload)) in starts.iter().enumerate() {
        let end = starts.get(n + 1).map_or(bytes.len(), |&(code, _)| code);
        let mut nal = &bytes[payload..end];
        while let Some((&0, rest)) = nal.split_last() {
            nal = rest;
        }
        if !nal.is_empty() {
            nals.push(nal);
        }
    }
    nals
}

/// NAL units written as AVCC: a four-byte big-endian length before each.
///
/// # Errors
///
/// A unit over `u32::MAX` bytes.
pub fn to_avcc<'a>(nals: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for nal in nals {
        let len = u32::try_from(nal.len()).map_err(|_| protocol("a NAL unit is too long"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(nal);
    }
    Ok(out)
}

/// The NAL units of an AVCC payload: lengths must fit, units be non-empty with forbidden-zero
/// clear, at most [`MAX_NALS_PER_FRAME`].
///
/// # Errors
///
/// Any of those failing.
pub fn split_avcc(payload: &[u8]) -> Result<Vec<&[u8]>> {
    let mut nals = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (len, after) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| protocol("a NAL length is cut short"))?;
        let len = usize::try_from(u32::from_be_bytes(*len))
            .map_err(|_| protocol("a NAL length does not fit"))?;
        if len == 0 {
            return Err(protocol("an empty NAL unit"));
        }
        let nal = after
            .get(..len)
            .ok_or_else(|| protocol("a NAL unit runs past the payload"))?;
        if nal[0] & 0x80 != 0 {
            return Err(protocol("a NAL unit's forbidden-zero bit is set"));
        }
        if nals.len() == MAX_NALS_PER_FRAME {
            return Err(protocol("too many NAL units in one frame"));
        }
        nals.push(nal);
        rest = &after[len..];
    }
    Ok(nals)
}

/// What the SPS says about the picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsInfo {
    /// `profile_idc`.
    pub profile: u8,
    /// `level_idc`.
    pub level: u8,
    /// `chroma_format_idc` (1 when the profile does not send it).
    pub chroma_format: u32,
    /// The displayed width: the coded width less the cropping.
    pub width: u32,
    /// The displayed height: the coded height less the cropping.
    pub height: u32,
}

impl SpsInfo {
    /// Whether the size is inside [`MIN_SIDE`]…[`MAX_SIDE`] per side and [`MAX_AREA`] in all.
    #[must_use]
    pub fn within_bounds(&self) -> bool {
        (MIN_SIDE..=MAX_SIDE).contains(&self.width)
            && (MIN_SIDE..=MAX_SIDE).contains(&self.height)
            && u64::from(self.width) * u64::from(self.height) <= MAX_AREA
    }
}

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`), giving the RBSP.
fn rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0usize;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// A big-endian bit reader over an RBSP, with Exp-Golomb codes (§9.1).
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Bits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn bit(&mut self) -> Result<u32> {
        let byte = self
            .bytes
            .get(self.at / 8)
            .ok_or_else(|| protocol("the SPS is cut short"))?;
        let bit = (byte >> (7 - (self.at % 8))) & 1;
        self.at += 1;
        Ok(u32::from(bit))
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut value = 0;
        for _ in 0..n {
            value = (value << 1) | self.bit()?;
        }
        Ok(value)
    }

    fn flag(&mut self) -> Result<bool> {
        Ok(self.bit()? == 1)
    }

    /// `ue(v)`; at most 31 leading zeros, so the value fits a u32.
    fn ue(&mut self) -> Result<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return Err(protocol("an Exp-Golomb code is too long"));
            }
        }
        let rest = self.bits(zeros)?;
        let value = (1u64 << zeros) - 1 + u64::from(rest);
        u32::try_from(value).map_err(|_| protocol("an Exp-Golomb code does not fit"))
    }

    /// `se(v)`.
    fn se(&mut self) -> Result<i64> {
        let k = i64::from(self.ue()?);
        Ok(if k % 2 == 1 { (k + 1) / 2 } else { -(k / 2) })
    }
}

/// Profiles whose SPS carries the chroma format, bit depths and scaling matrices (§7.3.2.1.1).
const HIGH_PROFILES: [u8; 13] = [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];

fn skip_scaling_list(bits: &mut Bits<'_>, size: usize) -> Result<()> {
    let mut last = 8i64;
    let mut next = 8i64;
    for _ in 0..size {
        if next != 0 {
            let delta = bits.se()?;
            if !(-128..=127).contains(&delta) {
                return Err(protocol("a scaling list delta is out of range"));
            }
            next = (last + delta + 256).rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Ok(())
}

/// Reads the picture size from an SPS NAL unit (with its header byte).
///
/// # Errors
///
/// Not an SPS, cut short, a code out of range, or a size that overflows.
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo> {
    if nal_type(nal) != Some(NAL_SPS) {
        return Err(protocol("not an SPS"));
    }
    let rbsp = rbsp(&nal[1..]);
    let mut bits = Bits::new(&rbsp);
    #[allow(clippy::cast_possible_truncation)]
    let profile = bits.bits(8)? as u8;
    bits.bits(8)?; // constraint flags and reserved bits
    #[allow(clippy::cast_possible_truncation)]
    let level = bits.bits(8)? as u8;
    if bits.ue()? > 31 {
        return Err(protocol("seq_parameter_set_id is out of range"));
    }
    let mut chroma_format = 1;
    let mut separate_planes = false;
    if HIGH_PROFILES.contains(&profile) {
        chroma_format = bits.ue()?;
        if chroma_format > 3 {
            return Err(protocol("chroma_format_idc is out of range"));
        }
        if chroma_format == 3 {
            separate_planes = bits.flag()?;
        }
        if bits.ue()? > 6 || bits.ue()? > 6 {
            return Err(protocol("a bit depth is out of range"));
        }
        bits.flag()?; // qpprime_y_zero_transform_bypass_flag
        if bits.flag()? {
            let lists = if chroma_format == 3 { 12 } else { 8 };
            for i in 0..lists {
                if bits.flag()? {
                    skip_scaling_list(&mut bits, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    if bits.ue()? > 12 {
        return Err(protocol("log2_max_frame_num_minus4 is out of range"));
    }
    match bits.ue()? {
        0 => {
            if bits.ue()? > 12 {
                return Err(protocol(
                    "log2_max_pic_order_cnt_lsb_minus4 is out of range",
                ));
            }
        }
        1 => {
            bits.flag()?;
            bits.se()?;
            bits.se()?;
            let cycle = bits.ue()?;
            if cycle > 255 {
                return Err(protocol(
                    "num_ref_frames_in_pic_order_cnt_cycle is out of range",
                ));
            }
            for _ in 0..cycle {
                bits.se()?;
            }
        }
        2 => {}
        _ => return Err(protocol("pic_order_cnt_type is out of range")),
    }
    bits.ue()?; // max_num_ref_frames
    bits.flag()?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = u64::from(bits.ue()?) + 1;
    let height_units = u64::from(bits.ue()?) + 1;
    let frame_mbs_only = bits.flag()?;
    if !frame_mbs_only {
        bits.flag()?; // mb_adaptive_frame_field_flag
    }
    bits.flag()?; // direct_8x8_inference_flag
    let (mut left, mut right, mut top, mut bottom) = (0u64, 0u64, 0u64, 0u64);
    if bits.flag()? {
        left = u64::from(bits.ue()?);
        right = u64::from(bits.ue()?);
        top = u64::from(bits.ue()?);
        bottom = u64::from(bits.ue()?);
    }
    let field_factor = if frame_mbs_only { 1 } else { 2 };
    // Table 6-1 SubWidthC/SubHeightC.
    let (sub_width, sub_height) = match (chroma_format, separate_planes) {
        (0, _) | (3, true) => (1, 1),
        (1, _) => (2, 2),
        (2, _) => (2, 1),
        _ => (1, 1),
    };
    let crop_x = sub_width;
    let crop_y = sub_height * field_factor;
    let coded_width = width_mbs * 16;
    let coded_height = height_units * 16 * field_factor;
    let width = coded_width
        .checked_sub((left + right) * crop_x)
        .ok_or_else(|| protocol("the cropping is wider than the picture"))?;
    let height = coded_height
        .checked_sub((top + bottom) * crop_y)
        .ok_or_else(|| protocol("the cropping is taller than the picture"))?;
    Ok(SpsInfo {
        profile,
        level,
        chroma_format,
        width: u32::try_from(width).map_err(|_| protocol("the width does not fit"))?,
        height: u32::try_from(height).map_err(|_| protocol("the height does not fit"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annex_b_splits_on_both_start_codes_and_drops_trailing_zeros() {
        let bytes = [
            0xAA, 0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x68, 3, 0, 0, 1, 0x65, 4, 5, 0, 0,
        ];
        let nals = split_annex_b(&bytes);
        assert_eq!(
            nals,
            vec![&[0x67, 1, 2][..], &[0x68, 3][..], &[0x65, 4, 5][..]]
        );
    }

    #[test]
    fn avcc_round_trips_and_every_bad_length_is_refused() {
        let nals: Vec<&[u8]> = vec![&[0x65, 1, 2, 3], &[0x06, 9]];
        let avcc = to_avcc(nals.iter().copied()).unwrap();
        assert_eq!(split_avcc(&avcc).unwrap(), nals);
        for bad in [
            &[0, 0, 0][..],                   // a cut length
            &[0, 0, 0, 0][..],                // an empty unit
            &[0, 0, 0, 5, 0x65, 1][..],       // past the payload
            &[0, 0, 0, 1, 0x85][..],          // forbidden-zero bit
            &[0xFF, 0xFF, 0xFF, 0xFF, 1][..], // a huge length
        ] {
            assert!(split_avcc(bad).is_err(), "{bad:?}");
        }
        let many: Vec<u8> = std::iter::repeat_n([0u8, 0, 0, 1, 0x06], MAX_NALS_PER_FRAME + 1)
            .flatten()
            .collect();
        assert!(split_avcc(&many).is_err());
    }

    #[test]
    fn avcc_record_round_trips_and_tolerates_a_high_profile_trailer() {
        let sps = [0x67, 100, 0, 40, 0xAC];
        let pps = [0x68, 0xEE, 0x3C, 0x80];
        let config = AvcConfig::from_parameter_sets(&sps, &pps).unwrap();
        let mut record = config.encode();
        assert_eq!(AvcConfig::parse(&record).unwrap(), config);
        record.extend_from_slice(&[0xFD, 0xF8, 0xF8, 0x00]);
        assert_eq!(AvcConfig::parse(&record).unwrap(), config);
        for cut in 0..config.encode().len() {
            assert!(AvcConfig::parse(&config.encode()[..cut]).is_err(), "{cut}");
        }
        let mut two_sps = config.encode();
        two_sps[5] = 0xE2;
        assert!(AvcConfig::parse(&two_sps).is_err());
        let mut two_byte_lengths = config.encode();
        two_byte_lengths[4] = 0xFD;
        assert!(AvcConfig::parse(&two_byte_lengths).is_err());
    }

    #[test]
    fn emulation_prevention_is_removed() {
        assert_eq!(rbsp(&[0, 0, 3, 1, 0, 0, 3, 0]), vec![0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn exp_golomb_codes_read_as_the_standard_tabulates() {
        // 1 | 010 | 011 | 00100 | 00101 -> ue 0, 1, 2, 3, 4
        let mut bits = Bits::new(&[0b1010_0110, 0b0100_0010, 0b1000_0000]);
        for expected in 0..5 {
            assert_eq!(bits.ue().unwrap(), expected);
        }
        // se: codeNum 1 -> 1, 2 -> -1
        let mut bits = Bits::new(&[0b0100_1100]);
        assert_eq!(bits.se().unwrap(), 1);
        assert_eq!(bits.se().unwrap(), -1);
        // 32 leading zeros is refused rather than overflowing.
        assert!(Bits::new(&[0, 0, 0, 0, 0x80]).ue().is_err());
    }
}
