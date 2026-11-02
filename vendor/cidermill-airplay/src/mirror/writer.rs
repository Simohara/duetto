//! The sender's half, sans-io: access units in, packets out.
//!
//! [`MirrorStreamWriter::access_unit`] turns an Annex B access unit into plaintext packets (a codec
//! record before every IDR, then the video packet), which may be queued and dropped, keeping
//! [`OutgoingPacket::is_key`]. [`MirrorStreamWriter::seal`] encrypts with the next keystream bytes,
//! so call it exactly once per packet, in wire order, as it is written. Drop before sealing, never
//! after.

use crate::error::{AirPlayError, Result};
use crate::time::NtpTimestamp;

use super::avc::{
    nal_type, parse_sps, split_annex_b, to_avcc, AvcConfig, NAL_AUD, NAL_IDR, NAL_PPS, NAL_SPS,
};
use super::key::{StreamCipher, StreamKey};
use super::packet::{
    header_from_ntp, HeaderDimensions, PacketHeader, PayloadKind, IDR_FLAG, OPTION_H264,
};
use super::{MAX_CODEC_BYTES, MAX_FRAME_BYTES};

/// A packet ready to be sealed, payload still in the clear.
#[derive(Clone, PartialEq)]
pub struct OutgoingPacket {
    header: PacketHeader,
    payload: Vec<u8>,
}

impl std::fmt::Debug for OutgoingPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingPacket")
            .field("kind", &self.header.kind)
            .field("idr", &self.header.is_idr())
            .field("timestamp", &self.header.timestamp)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl OutgoingPacket {
    /// What it carries.
    #[must_use]
    pub fn kind(&self) -> PayloadKind {
        self.header.kind
    }

    /// Whether it is a video packet with an IDR.
    #[must_use]
    pub fn is_idr(&self) -> bool {
        self.header.kind == PayloadKind::Video && self.header.is_idr()
    }

    /// Whether a queue that must drop frames keeps it: a codec record or an IDR.
    #[must_use]
    pub fn is_key(&self) -> bool {
        self.header.kind == PayloadKind::CodecConfig || self.is_idr()
    }

    /// Its header.
    #[must_use]
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    /// Bytes on the wire once sealed.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        super::HEADER_LEN + self.payload.len()
    }
}

/// See the module docs.
pub struct MirrorStreamWriter {
    cipher: StreamCipher,
    /// The encoder's current parameter sets, and the size their SPS names.
    config: Option<AvcConfig>,
    size: (u32, u32),
    /// Parameter sets changed in a unit that carried no slice: the next frame takes the record.
    record_owed: bool,
}

impl std::fmt::Debug for MirrorStreamWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorStreamWriter")
            .field("has_config", &self.config.is_some())
            .finish_non_exhaustive()
    }
}

impl MirrorStreamWriter {
    /// A writer at the start of this stream's keystream.
    #[must_use]
    pub fn new(key: &StreamKey) -> Self {
        Self {
            cipher: key.cipher(),
            config: None,
            size: (0, 0),
            record_owed: false,
        }
    }

    /// The encoder's current parameter sets, if any have come.
    #[must_use]
    pub fn config(&self) -> Option<&AvcConfig> {
        self.config.as_ref()
    }

    /// The packets for one Annex B access unit captured at `at` (the sender's NTP clock):
    /// a codec record before every IDR and whenever the parameter sets change, then the video
    /// packet with SPS, PPS and AUD removed. Parameter sets in bounds are remembered as current,
    /// even from a unit refused for carrying no slice (the next frame then takes the record).
    ///
    /// # Errors
    ///
    /// No slice data, a bad or out-of-bounds SPS, parameter sets whose record would be over
    /// [`MAX_CODEC_BYTES`] (a reader refuses it), no parameter sets yet, or a payload over
    /// [`MAX_FRAME_BYTES`]. Nothing was encrypted, so the caller may skip the unit (and should
    /// request an IDR).
    pub fn access_unit(&mut self, annex_b: &[u8], at: NtpTimestamp) -> Result<Vec<OutgoingPacket>> {
        let timestamp = header_from_ntp(at);
        let nals = split_annex_b(annex_b);
        let mut sps = None;
        let mut pps = None;
        let mut rest = Vec::with_capacity(nals.len());
        for nal in nals {
            match nal_type(nal) {
                Some(NAL_SPS) => sps = Some(nal),
                Some(NAL_PPS) => pps = Some(nal),
                Some(NAL_AUD) => {}
                _ => rest.push(nal),
            }
        }
        let mut changed = false;
        if sps.is_some() || pps.is_some() {
            let current = self.config.as_ref();
            let sps = sps.or(current.map(|c| c.sps.as_slice()));
            let pps = pps.or(current.map(|c| c.pps.as_slice()));
            let (Some(sps), Some(pps)) = (sps, pps) else {
                return Err(AirPlayError::Protocol(
                    "mirror: an SPS without a PPS, or the reverse, and none before".to_owned(),
                ));
            };
            let config = AvcConfig::from_parameter_sets(sps, pps)?;
            if self.config.as_ref() != Some(&config) {
                if !u32::try_from(config.encode().len()).is_ok_and(|len| len <= MAX_CODEC_BYTES) {
                    return Err(AirPlayError::Protocol(
                        "mirror: the parameter sets' record is over the size cap".to_owned(),
                    ));
                }
                let info = parse_sps(sps)?;
                if !info.within_bounds() {
                    return Err(AirPlayError::Protocol(format!(
                        "mirror: {}x{} is out of bounds",
                        info.width, info.height
                    )));
                }
                self.config = Some(config);
                changed = true;
                // Owed until a frame carries it, whatever refuses this unit below.
                self.record_owed = true;
                self.size = (info.width, info.height);
            }
        }
        if rest.is_empty() {
            return Err(AirPlayError::Protocol(
                "mirror: an access unit with no slice data".to_owned(),
            ));
        }
        let Some(config) = &self.config else {
            return Err(AirPlayError::Protocol(
                "mirror: a frame before any SPS and PPS".to_owned(),
            ));
        };
        let idr = rest.iter().any(|nal| nal_type(nal) == Some(NAL_IDR));
        let payload = to_avcc(rest)?;
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|len| *len <= MAX_FRAME_BYTES)
            .ok_or_else(|| {
                AirPlayError::Protocol("mirror: a frame over the size cap".to_owned())
            })?;
        let mut packets = Vec::with_capacity(2);
        // A new PPS can arrive with a P-frame, so a change needs a record too.
        if idr || changed || self.record_owed {
            self.record_owed = false;
            let record = config.encode();
            #[allow(clippy::cast_precision_loss)]
            let (width, height) = (self.size.0 as f32, self.size.1 as f32);
            let mut header = PacketHeader::new(
                PayloadKind::CodecConfig,
                u32::try_from(record.len()).unwrap_or(u32::MAX),
                timestamp,
            );
            header.option = OPTION_H264;
            header.dimensions = HeaderDimensions {
                source_width: width,
                source_height: height,
                width,
                height,
            };
            packets.push(OutgoingPacket {
                header,
                payload: record,
            });
        }
        let mut header = PacketHeader::new(PayloadKind::Video, len, timestamp);
        if idr {
            header.flags = IDR_FLAG;
        }
        packets.push(OutgoingPacket { header, payload });
        Ok(packets)
    }

    /// A heartbeat (no payload, no timestamp).
    #[must_use]
    pub fn heartbeat() -> OutgoingPacket {
        OutgoingPacket {
            header: PacketHeader::new(PayloadKind::Heartbeat, 0, 0),
            payload: Vec::new(),
        }
    }

    /// The bytes to write for `packet`, video encrypted with the next keystream bytes. Once per
    /// packet, in wire order.
    #[must_use]
    pub fn seal(&mut self, packet: OutgoingPacket) -> Vec<u8> {
        let OutgoingPacket {
            header,
            mut payload,
        } = packet;
        if header.kind == PayloadKind::Video {
            self.cipher.apply(&mut payload);
        }
        let mut out = Vec::with_capacity(super::HEADER_LEN + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        out
    }
}
