//! Parsing of the `GET /info` reply: a receiver's own description of itself (model, firmware,
//! authoritative feature bitfield, stream formats, UDP mirroring, HDR ceiling).
//!
//! Prefer it over mDNS TXT guesses once a connection exists. Shapes captured from an `AppleTV14,1`
//! (tvOS build 23L243) and an `AudioAccessory5,1`.

use std::collections::BTreeMap;

use plist::Value;

use crate::error::{AirPlayError, Result};

/// One display mode a receiver reports it can drive.
///
/// Parsed but unproven: neither captured device populated `displays`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisplayMode {
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
    /// Refresh rate in Hz, when reported.
    pub refresh_hz: Option<u32>,
    /// Display identifier, used when a receiver exposes more than one.
    pub uuid: Option<String>,
    /// Maximum frames per second the receiver wants, when reported.
    pub max_fps: Option<u32>,
}

/// Bitmasks of the stream formats a receiver accepts, one per stream kind, carried verbatim.
///
/// Do not read these as "this device offers that stream kind": a HomePod reported the same
/// `screenStream` as an Apple TV and `receiverHDRCapability = "4k60"`. Feature bit 7 separates
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SupportedFormats {
    /// Formats accepted for the mirroring video stream.
    pub screen_stream: Option<i64>,
    /// Formats accepted for the realtime audio stream.
    pub audio_stream: Option<i64>,
    /// Formats accepted for the buffered (AirPlay 2) audio stream.
    pub buffer_stream: Option<i64>,
    /// Formats accepted for the low-latency audio stream.
    pub low_latency_audio_stream: Option<i64>,
}

/// The parsed `/info` reply.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct DeviceInfo {
    /// Friendly name.
    pub name: Option<String>,
    /// Model identifier, e.g. `AppleTV14,1`.
    pub model: Option<String>,
    /// Firmware / source version, e.g. `940.23.1`.
    pub source_version: Option<String>,
    /// OS build, e.g. `23L243`. Finer-grained than `source_version` for interop quirks.
    pub os_build_version: Option<String>,
    /// Device id (MAC-shaped) — matches the mDNS `deviceid`.
    pub device_id: Option<String>,
    /// Hardware MAC address, which is NOT the same value as the device id.
    pub mac_address: Option<String>,
    /// Protocol version string.
    pub protocol_version: Option<String>,
    /// The 64-bit feature bitfield, authoritative here rather than inferred from TXT.
    pub features: Option<crate::Features>,
    /// The base64 `featuresEx` extension string, carried verbatim; its layout is not documented.
    pub features_ex: Option<String>,
    /// Status flags. Observed identical to the mDNS `flags` value.
    pub status_flags: Option<u32>,
    /// Ed25519 public key, hex-encoded.
    pub public_key_hex: Option<String>,
    /// Pairing identity (`pi`) — the identifier used in HAP pair-verify.
    pub pairing_identity: Option<String>,
    /// Public service identity (`psi`).
    pub service_identity: Option<String>,
    /// Volume the receiver would start at, in the AirPlay dB scale (-30..0).
    pub initial_volume: Option<f64>,
    /// Receiver-defined volume-control model. Observed 4 on Apple TV, 3 on HomePod.
    pub volume_control_type: Option<i64>,
    /// Whether the receiver supports mirroring over UDP rather than TCP.
    pub has_udp_mirroring: Option<bool>,
    /// Whether the receiver will let a sender record the screen stream.
    pub can_record_screen_stream: Option<bool>,
    /// HDR ceiling, e.g. `4k60`. Absent on audio-only receivers.
    pub receiver_hdr_capability: Option<String>,
    /// The address the receiver sees us at. Useful when diagnosing a multi-homed sender.
    pub sender_address: Option<String>,
    /// Which stream kinds and formats the receiver accepts.
    pub supported_formats: SupportedFormats,
    /// The `playbackCapabilities` booleans, verbatim.
    pub playback_capabilities: BTreeMap<String, bool>,
    /// Display modes the receiver advertises.
    pub displays: Vec<DisplayMode>,
    /// Audio latency hints.
    pub audio_latencies: Vec<AudioLatency>,
    /// Top-level keys present in the reply, for diagnostics and fixture-writing.
    pub keys: Vec<String>,
}

/// One audio-latency entry from `/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioLatency {
    /// Receiver-defined audio type index.
    pub audio_type: Option<i64>,
    /// Input latency in microseconds.
    pub input_latency: Option<i64>,
    /// Output latency in microseconds.
    pub output_latency: Option<i64>,
}

impl std::fmt::Display for DeviceInfo {
    /// `Name (Model), sourceVersion / osBuild` — the one-line identity a log or a diagnostic
    /// shows, with each part omitted when the receiver did not send it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.name.as_deref().unwrap_or("?"),
            self.model.as_deref().unwrap_or("?")
        )?;
        if let Some(sv) = &self.source_version {
            write!(f, ", {sv}")?;
        }
        if let Some(os) = &self.os_build_version {
            write!(f, " / {os}")?;
        }
        Ok(())
    }
}

impl DeviceInfo {
    /// Parses an `/info` body (binary or XML plist).
    ///
    /// Every field is optional and an unexpected shape is skipped, not rejected: the peer is
    /// unauthenticated.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "/info is not a readable plist")?;
        let dict = value
            .as_dictionary()
            .ok_or_else(|| AirPlayError::Protocol("/info is not a plist dictionary".to_owned()))?;

        let mut info = DeviceInfo {
            keys: dict.keys().map(ToOwned::to_owned).collect(),
            name: string_of(dict.get("name")),
            model: string_of(dict.get("model")),
            source_version: string_of(dict.get("sourceVersion")),
            os_build_version: string_of(dict.get("osBuildVersion")),
            device_id: string_of(dict.get("deviceID")),
            mac_address: string_of(dict.get("macAddress")),
            protocol_version: string_of(dict.get("protocolVersion")),
            features_ex: string_of(dict.get("featuresEx")),
            pairing_identity: string_of(dict.get("pi")),
            service_identity: string_of(dict.get("psi")),
            receiver_hdr_capability: string_of(dict.get("receiverHDRCapability")),
            sender_address: string_of(dict.get("senderAddress")),
            has_udp_mirroring: bool_of(dict.get("hasUDPMirroringSupport")),
            can_record_screen_stream: bool_of(dict.get("canRecordScreenStream")),
            volume_control_type: dict.get("volumeControlType").and_then(signed_of),
            features: dict.get("features").and_then(bits_of).map(crate::Features),
            ..DeviceInfo::default()
        };

        info.public_key_hex = dict.get("pk").and_then(|v| match v {
            Value::Data(bytes) => Some(hex::encode(bytes)),
            Value::String(text) => Some(text.clone()),
            _ => None,
        });
        info.status_flags = dict
            .get("statusFlags")
            .and_then(unsigned_of)
            .and_then(|v| u32::try_from(v).ok());
        info.initial_volume = dict.get("initialVolume").and_then(|v| match v {
            Value::Real(r) => Some(*r),
            Value::Integer(i) => i.as_signed().map(|s| s as f64),
            _ => None,
        });

        if let Some(Value::Dictionary(formats)) = dict.get("supportedFormats") {
            info.supported_formats = SupportedFormats {
                screen_stream: formats.get("screenStream").and_then(signed_of),
                audio_stream: formats.get("audioStream").and_then(signed_of),
                buffer_stream: formats.get("bufferStream").and_then(signed_of),
                low_latency_audio_stream: formats.get("lowLatencyAudioStream").and_then(signed_of),
            };
        }

        if let Some(Value::Dictionary(capabilities)) = dict.get("playbackCapabilities") {
            for (key, value) in capabilities {
                if let Some(flag) = bool_of(Some(value)) {
                    info.playback_capabilities.insert(key.clone(), flag);
                }
            }
        }

        if let Some(Value::Array(displays)) = dict.get("displays") {
            for display in displays {
                let Some(entry) = display.as_dictionary() else {
                    continue;
                };
                let (Some(width), Some(height)) = (
                    entry.get("width").and_then(unsigned_of),
                    entry.get("height").and_then(unsigned_of),
                ) else {
                    continue;
                };
                let (Ok(width), Ok(height)) = (u32::try_from(width), u32::try_from(height)) else {
                    continue;
                };
                info.displays.push(DisplayMode {
                    width,
                    height,
                    refresh_hz: entry.get("refreshRate").and_then(refresh_hz_of),
                    uuid: string_of(entry.get("uuid")),
                    max_fps: entry
                        .get("maxFPS")
                        .and_then(unsigned_of)
                        .and_then(|v| u32::try_from(v).ok()),
                });
            }
        }

        if let Some(Value::Array(latencies)) = dict.get("audioLatencies") {
            for latency in latencies {
                let Some(entry) = latency.as_dictionary() else {
                    continue;
                };
                info.audio_latencies.push(AudioLatency {
                    audio_type: entry.get("type").and_then(signed_of),
                    input_latency: entry.get("inputLatencyMicros").and_then(signed_of),
                    output_latency: entry.get("outputLatencyMicros").and_then(signed_of),
                });
            }
        }

        Ok(info)
    }

    /// Whether feature bit 7 says the receiver takes a screen.
    #[must_use]
    pub fn supports_screen(&self) -> bool {
        self.features
            .is_some_and(|f| f.contains(crate::Features::SCREEN))
    }

    /// Whether the feature bitfield says the receiver takes audio (bit 9).
    #[must_use]
    pub fn supports_audio(&self) -> bool {
        self.features
            .is_some_and(|f| f.contains(crate::Features::AUDIO))
    }

    /// The raw 64-bit feature bitfield, or `None` when the reply had none.
    #[must_use]
    pub fn raw_features(&self) -> Option<u64> {
        self.features.map(crate::Features::bits)
    }

    /// Whether the receiver offers a mirroring video stream. Reads feature bit 7, not
    /// `supportedFormats.screenStream` (a HomePod advertises the same mask as an Apple TV).
    #[must_use]
    pub fn accepts_screen_stream(&self) -> bool {
        self.supports_screen()
    }
}

fn string_of(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn bool_of(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Boolean(flag)) => Some(*flag),
        Some(Value::Integer(i)) => i.as_signed().map(|v| v != 0),
        _ => None,
    }
}

fn unsigned_of(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(i) => i
            .as_unsigned()
            .or_else(|| i.as_signed().and_then(|s| u64::try_from(s).ok())),
        Value::Real(r) if *r >= 0.0 => Some(*r as u64),
        _ => None,
    }
}

/// A 64-bit flag word: an integer written signed with bit 63 set is the same bits, not a negative
/// number.
fn bits_of(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(i) => i
            .as_unsigned()
            .or_else(|| i.as_signed().map(i64::cast_unsigned)),
        _ => unsigned_of(value),
    }
}

fn signed_of(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(i) => i
            .as_signed()
            .or_else(|| i.as_unsigned().and_then(|u| i64::try_from(u).ok())),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}

/// Refresh rate is reported either as Hz or as a frame duration in seconds, depending on the
/// receiver; normalize both to whole Hz.
fn refresh_hz_of(value: &Value) -> Option<u32> {
    match value {
        Value::Integer(i) => i.as_unsigned().and_then(|v| u32::try_from(v).ok()),
        Value::Real(r) if *r > 1.0 => Some(r.round() as u32),
        Value::Real(r) if *r > 0.0 => Some((1.0 / *r).round() as u32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_info() -> DeviceInfo {
        DeviceInfo::default()
    }

    fn parse_dict(dict: plist::Dictionary) -> DeviceInfo {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(dict)).unwrap();
        DeviceInfo::parse(&body).unwrap()
    }

    #[test]
    fn a_features_word_written_signed_with_bit_63_set_keeps_its_bits() {
        let bits = 0x8000_0000_445F_8A00_u64;
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "features".to_owned(),
            Value::Integer(bits.cast_signed().into()),
        );
        assert_eq!(parse_dict(dict).raw_features(), Some(bits));
    }

    #[test]
    fn a_display_with_an_oversized_side_is_skipped_not_zeroed() {
        let display = |width: u64| {
            let mut entry = plist::Dictionary::new();
            entry.insert("width".to_owned(), Value::Integer(width.into()));
            entry.insert("height".to_owned(), Value::Integer(1080u64.into()));
            Value::Dictionary(entry)
        };
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "displays".to_owned(),
            Value::Array(vec![display(1 << 33), display(1920)]),
        );
        let info = parse_dict(dict);
        assert_eq!(info.displays.len(), 1);
        assert_eq!(info.displays[0].width, 1920);
    }

    #[test]
    fn display_all_fields() {
        let info = DeviceInfo {
            name: Some("Den TV".to_owned()),
            model: Some("AppleTV14,1".to_owned()),
            source_version: Some("940.23.1".to_owned()),
            os_build_version: Some("23L243".to_owned()),
            ..minimal_info()
        };
        assert_eq!(info.to_string(), "Den TV (AppleTV14,1), 940.23.1 / 23L243");
    }

    #[test]
    fn display_name_and_model_only() {
        let info = DeviceInfo {
            name: Some("Living Room".to_owned()),
            model: Some("AudioAccessory5,1".to_owned()),
            ..minimal_info()
        };
        assert_eq!(info.to_string(), "Living Room (AudioAccessory5,1)");
    }

    #[test]
    fn display_missing_name_and_model() {
        let info = minimal_info();
        assert_eq!(info.to_string(), "? (?)");
    }

    #[test]
    fn display_source_version_without_os_build() {
        let info = DeviceInfo {
            name: Some("TV".to_owned()),
            model: Some("M".to_owned()),
            source_version: Some("940.23.1".to_owned()),
            ..minimal_info()
        };
        assert_eq!(info.to_string(), "TV (M), 940.23.1");
    }

    #[test]
    fn display_os_build_without_source_version() {
        let info = DeviceInfo {
            name: Some("TV".to_owned()),
            model: Some("M".to_owned()),
            os_build_version: Some("23L243".to_owned()),
            ..minimal_info()
        };
        assert_eq!(info.to_string(), "TV (M) / 23L243");
    }
}
