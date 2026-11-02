//! What a stream `SETUP` names: stream type, compression code, `audioFormat` bit, and the SSRC
//! format identifier of buffered packets. Each value is a wire constant a receiver matches exactly.

/// The `type` of a stream in a stream `SETUP`.
///
/// **Realtime** (96) is RTP over UDP with a control port for sync and retransmission.
/// **Buffered** (103) is length-prefixed RTP over one TCP connection, timed by a
/// `SETRATEANCHORTIME` against a PTP clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamType {
    /// `type: 96` — realtime audio over UDP.
    Realtime,
    /// `type: 103` — buffered audio over TCP.
    Buffered,
}

impl StreamType {
    /// The wire code for [`Self::Realtime`].
    pub const REALTIME_CODE: u64 = 96;
    /// The wire code for [`Self::Buffered`]. Assumed from two open receivers.
    pub const BUFFERED_CODE: u64 = 103;

    /// The `type` value on the wire.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::Realtime => Self::REALTIME_CODE,
            Self::Buffered => Self::BUFFERED_CODE,
        }
    }

    /// Maps a wire `type`, or `None` for a stream type that is not audio (110 screen, 120
    /// playback, 130 remote control) or not known.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            Self::REALTIME_CODE => Some(Self::Realtime),
            Self::BUFFERED_CODE => Some(Self::Buffered),
            _ => None,
        }
    }
}

/// `ct`, the compression type.
///
/// The AAC codes are disputed between sources (4 and 8 here, 3 and 4 elsewhere); this crate
/// never sends AAC.
pub mod compression {
    /// Linear PCM.
    pub const LPCM: u64 = 1;
    /// Apple Lossless.
    pub const ALAC: u64 = 2;
    /// AAC-LC. Disputed; not sent by this crate.
    pub const AAC_LC: u64 = 4;
    /// AAC-ELD. Disputed; not sent by this crate.
    pub const AAC_ELD: u64 = 8;
}

/// `audioFormat` bits.
pub mod audio_format {
    /// PCM, 44.1 kHz, 16-bit, stereo (bit 11).
    pub const PCM_44100_16_2: u64 = 1 << 11;
    /// ALAC, 44.1 kHz, 16-bit, stereo (bit 18).
    pub const ALAC_44100_16_2: u64 = 1 << 18;
    /// ALAC, 44.1 kHz, 24-bit, stereo (bit 19).
    pub const ALAC_44100_24_2: u64 = 1 << 19;
    /// ALAC, 48 kHz, 16-bit, stereo (bit 20).
    pub const ALAC_48000_16_2: u64 = 1 << 20;
    /// ALAC, 48 kHz, 24-bit, stereo (bit 21).
    pub const ALAC_48000_24_2: u64 = 1 << 21;
    /// AAC-LC, 44.1 kHz, stereo (bit 22).
    pub const AAC_LC_44100_2: u64 = 1 << 22;
    /// AAC-LC, 48 kHz, stereo (bit 23).
    pub const AAC_LC_48000_2: u64 = 1 << 23;
}

/// The format identifiers a **buffered** packet carries in its RTP SSRC field.
///
/// A buffered packet's SSRC names the encoding, and shairport-sync drops a packet whose SSRC it
/// does not recognise. Values are assumed from that project. No Apple value is known for 16-bit
/// ALAC at 44.1 kHz, so a buffered stream uses [`super::StreamFormat::ALAC_48000_24_STEREO`].
pub mod buffered_ssrc {
    /// ALAC, 48 kHz, 24-bit, stereo.
    pub const ALAC_48000_S24_2: u32 = 0x1500_0000;
    /// AAC, 44.1 kHz, stereo.
    pub const AAC_44100_F24_2: u32 = 0x1600_0000;
    /// AAC, 48 kHz, stereo.
    pub const AAC_48000_F24_2: u32 = 0x1700_0000;
}

/// Frames per packet for ALAC over AirPlay (`spf`).
pub const ALAC_FRAMES_PER_PACKET: u32 = 352;

/// One concrete stream shape: codec, rate, depth, channels, packet size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StreamFormat {
    /// `ct` — see [`compression`].
    pub compression: u64,
    /// `audioFormat` — see [`audio_format`].
    pub audio_format: u64,
    /// `sr`, frames per second.
    pub sample_rate: u32,
    /// Bits per sample of the source PCM.
    pub bits_per_sample: u8,
    /// Channel count.
    pub channels: u8,
    /// `spf`, frames per packet.
    pub frames_per_packet: u32,
}

impl StreamFormat {
    /// ALAC 44.1 kHz/16-bit/stereo, 352 frames a packet (realtime).
    pub const ALAC_44100_16_STEREO: Self = Self {
        compression: compression::ALAC,
        audio_format: audio_format::ALAC_44100_16_2,
        sample_rate: 44_100,
        bits_per_sample: 16,
        channels: 2,
        frames_per_packet: ALAC_FRAMES_PER_PACKET,
    };

    /// ALAC 48 kHz/24-bit/stereo, 352 frames a packet: the one ALAC shape with a known buffered
    /// SSRC (see [`buffered_ssrc`]).
    pub const ALAC_48000_24_STEREO: Self = Self {
        compression: compression::ALAC,
        audio_format: audio_format::ALAC_48000_24_2,
        sample_rate: 48_000,
        bits_per_sample: 24,
        channels: 2,
        frames_per_packet: ALAC_FRAMES_PER_PACKET,
    };

    /// Raw PCM 44.1 kHz/16-bit/stereo.
    pub const PCM_44100_16_STEREO: Self = Self {
        compression: compression::LPCM,
        audio_format: audio_format::PCM_44100_16_2,
        sample_rate: 44_100,
        bits_per_sample: 16,
        channels: 2,
        frames_per_packet: ALAC_FRAMES_PER_PACKET,
    };

    /// The SSRC a buffered packet of this format must carry, if one is known.
    #[must_use]
    pub fn buffered_ssrc(&self) -> Option<u32> {
        match self.audio_format {
            audio_format::ALAC_48000_24_2 if self.compression == compression::ALAC => {
                Some(buffered_ssrc::ALAC_48000_S24_2)
            }
            _ => None,
        }
    }

    /// The `latencyMin` a sender names, in frames: a quarter second.
    #[must_use]
    pub fn latency_min(&self) -> u32 {
        self.sample_rate / 4
    }

    /// The `latencyMax` a sender names, in frames: two seconds.
    #[must_use]
    pub fn latency_max(&self) -> u32 {
        self.sample_rate.saturating_mul(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_type_codes_round_trip() {
        for kind in [StreamType::Realtime, StreamType::Buffered] {
            assert_eq!(StreamType::from_code(kind.code()), Some(kind));
        }
        assert_eq!(StreamType::from_code(130), None);
    }

    #[test]
    fn only_the_48k_24_bit_alac_shape_has_a_buffered_ssrc() {
        assert_eq!(
            StreamFormat::ALAC_48000_24_STEREO.buffered_ssrc(),
            Some(0x1500_0000)
        );
        assert_eq!(StreamFormat::ALAC_44100_16_STEREO.buffered_ssrc(), None);
        assert_eq!(StreamFormat::PCM_44100_16_STEREO.buffered_ssrc(), None);
    }

    #[test]
    fn latencies_match_pyatv_at_44_1_khz() {
        assert_eq!(StreamFormat::ALAC_44100_16_STEREO.latency_min(), 11_025);
        assert_eq!(StreamFormat::ALAC_44100_16_STEREO.latency_max(), 88_200);
    }
}
