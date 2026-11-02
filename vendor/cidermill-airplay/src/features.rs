//! The AirPlay feature word: the `features` field of `/info` and of the `_airplay._tcp` /
//! `_raop._tcp` TXT records. Bit names follow pyatv 0.18.0's `AirPlayFlags` table.

use std::fmt;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// A 64-bit AirPlay feature word.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features(pub u64);

impl Features {
    /// No bits.
    pub const EMPTY: Self = Self(0);
    /// `SupportsAirPlayVideoV1`.
    pub const VIDEO_V1: Self = Self(1 << 0);
    /// `SupportsAirPlayScreen`: screen mirroring.
    pub const SCREEN: Self = Self(1 << 7);
    /// `SupportsAirPlayAudio`.
    pub const AUDIO: Self = Self(1 << 9);
    /// `AudioRedundant`.
    pub const AUDIO_REDUNDANT: Self = Self(1 << 11);
    /// `Authentication_4`: the sender-authentication scheme Apple senders require of a receiver.
    /// No preset here sets it.
    pub const AUTHENTICATION_4: Self = Self(1 << 14);
    /// `AudioFormats_0`.
    pub const AUDIO_FORMATS_0: Self = Self(1 << 18);
    /// `AudioFormats_1`.
    pub const AUDIO_FORMATS_1: Self = Self(1 << 19);
    /// `AudioFormats_2`.
    pub const AUDIO_FORMATS_2: Self = Self(1 << 20);
    /// Bit 22: unnamed in pyatv's table; set in shairport-sync's word.
    pub const BIT_22: Self = Self(1 << 22);
    /// `Authentication_1`: RSA (AirPort Express).
    pub const AUTHENTICATION_RSA: Self = Self(1 << 23);
    /// `Authentication_8`: MFi.
    pub const AUTHENTICATION_MFI: Self = Self(1 << 26);
    /// `HasUnifiedAdvertiserInfo`.
    pub const UNIFIED_ADVERTISER_INFO: Self = Self(1 << 30);
    /// `SupportsUnifiedMediaControl`.
    pub const UNIFIED_MEDIA_CONTROL: Self = Self(1 << 38);
    /// `SupportsBufferedAudio`.
    pub const BUFFERED_AUDIO: Self = Self(1 << 40);
    /// `SupportsPTP`.
    pub const PTP: Self = Self(1 << 41);
    /// `SupportsHKPairingAndAccessControl`.
    pub const HK_PAIRING_AND_ACCESS_CONTROL: Self = Self(1 << 46);
    /// Bit 47: unnamed in pyatv's table; set in shairport-sync's word.
    pub const BIT_47: Self = Self(1 << 47);
    /// `SupportsCoreUtilsPairingAndEncryption`: transient pairing.
    pub const CORE_UTILS_PAIRING_AND_ENCRYPTION: Self = Self(1 << 48);

    /// A realtime audio receiver that pairs with HAP: ALAC and LPCM, unified advertisement and
    /// media control, HomeKit and transient pairing. What this crate's sender and pyatv need, no
    /// more.
    pub const MINIMAL_AUDIO: Self = Self(
        Self::AUDIO.0
            | Self::AUDIO_FORMATS_0.0
            | Self::AUDIO_FORMATS_1.0
            | Self::UNIFIED_ADVERTISER_INFO.0
            | Self::UNIFIED_MEDIA_CONTROL.0
            | Self::HK_PAIRING_AND_ACCESS_CONTROL.0
            | Self::CORE_UTILS_PAIRING_AND_ENCRYPTION.0,
    );

    /// shairport-sync's AirPlay 2 default word (`config.airplay_features` in `shairport.c`).
    /// It sets [`Self::AUTHENTICATION_4`], [`Self::BUFFERED_AUDIO`] and [`Self::PTP`].
    pub const SHAIRPORT_SYNC_AIRPLAY2: Self = Self(0x0001_8340_405C_4A00);

    /// The raw word.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any bit of `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// These bits and `other`'s.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// These bits without `other`'s.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The TXT spelling: `0xLOW,0xHIGH`, upper-case hex, as every Apple record writes it.
    #[must_use]
    pub fn to_txt(self) -> String {
        format!("0x{:X},0x{:X}", self.0 & 0xFFFF_FFFF, self.0 >> 32)
    }

    /// Parses the TXT spelling (`0xLOW,0xHIGH`) or a single hex (`0x…`) or decimal number.
    #[must_use]
    pub fn parse_txt(text: &str) -> Option<Self> {
        let number = |part: &str| {
            let part = part.trim();
            match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => part.parse::<u64>().ok(),
            }
        };
        match text.split_once(',') {
            Some((low, high)) => {
                let low = u32::try_from(number(low)?).ok()?;
                let high = u32::try_from(number(high)?).ok()?;
                Some(Self((u64::from(high) << 32) | u64::from(low)))
            }
            None => number(text).map(Self),
        }
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Features({:#018x})", self.0)
    }
}

impl fmt::Display for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_txt())
    }
}

impl From<u64> for Features {
    fn from(bits: u64) -> Self {
        Self(bits)
    }
}

impl From<Features> for u64 {
    fn from(features: Features) -> Self {
        features.0
    }
}

impl BitOr for Features {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.with(rhs)
    }
}

impl BitOrAssign for Features {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for Features {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Features {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for Features {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Features;

    #[test]
    fn the_txt_spelling_is_low_half_first_and_reads_back() {
        let word = Features(0x3C17_7FDE_4A7F_DFD5);
        assert_eq!(word.to_txt(), "0x4A7FDFD5,0x3C177FDE");
        assert_eq!(Features::parse_txt(&word.to_txt()), Some(word));
        assert_eq!(Features::parse_txt("0x200"), Some(Features::AUDIO));
        assert_eq!(Features::parse_txt("512"), Some(Features::AUDIO));
        assert_eq!(Features::parse_txt("0x1,0x100000000"), None);
        assert_eq!(Features::parse_txt("nope"), None);
    }

    #[test]
    fn minimal_audio_claims_audio_and_no_authentication_scheme() {
        let auth = Features::AUTHENTICATION_4
            | Features::AUTHENTICATION_RSA
            | Features::AUTHENTICATION_MFI;
        assert!(!Features::MINIMAL_AUDIO.intersects(auth));
        assert!(Features::MINIMAL_AUDIO.contains(Features::AUDIO));
        assert!(!Features::MINIMAL_AUDIO.intersects(Features::SCREEN | Features::VIDEO_V1));
        assert!(Features::SHAIRPORT_SYNC_AIRPLAY2
            .contains(Features::AUTHENTICATION_4 | Features::BUFFERED_AUDIO | Features::PTP));
        assert_eq!(
            Features::SHAIRPORT_SYNC_AIRPLAY2
                .without(Features::AUTHENTICATION_4 | Features::BUFFERED_AUDIO | Features::PTP),
            Features(0x0001_8040_405C_0A00)
        );
    }
}
