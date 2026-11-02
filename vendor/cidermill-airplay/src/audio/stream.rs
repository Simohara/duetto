//! The stream `SETUP` body (the second `SETUP` of an audio session) and the parser for its reply.
//!
//! The realtime body matches pyatv's `setup_audio_stream` key for key; a buffered stream is the
//! same dictionary with `type: 103`, which no sender reference pins. Observed on tvOS 26
//! (`AppleTV14,1`) for realtime ALAC and LPCM at 44.1 kHz.

use plist::Value;

use super::format::{StreamFormat, StreamType};
use crate::error::{AirPlayError, Result};

/// `audioMode`.
pub const AUDIO_MODE: &str = "default";

/// What a stream `SETUP` asks for.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamSetup {
    /// Realtime or buffered.
    pub stream_type: StreamType,
    /// Codec, rate, depth, channels, packet size.
    pub format: StreamFormat,
    /// Our UDP control port (sync packets, retransmission).
    pub control_port: u16,
    /// `shk`: the 32-byte key every audio packet is sealed with; draw it from a CSPRNG per stream.
    pub shared_key: [u8; 32],
    /// `streamConnectionID`.
    pub stream_connection_id: u64,
    /// `supportsDynamicStreamID`; `false`, as stream ids never change mid-session.
    pub supports_dynamic_stream_id: bool,
}

impl std::fmt::Debug for StreamSetup {
    /// The key is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSetup")
            .field("stream_type", &self.stream_type)
            .field("format", &self.format)
            .field("control_port", &self.control_port)
            .field("shared_key", &"<redacted>")
            .field("stream_connection_id", &self.stream_connection_id)
            .finish_non_exhaustive()
    }
}

impl StreamSetup {
    /// A stream `SETUP` with default values for everything not given.
    #[must_use]
    pub fn new(
        stream_type: StreamType,
        format: StreamFormat,
        control_port: u16,
        shared_key: [u8; 32],
        stream_connection_id: u64,
    ) -> Self {
        Self {
            stream_type,
            format,
            control_port,
            shared_key,
            stream_connection_id,
            supports_dynamic_stream_id: false,
        }
    }

    /// The `streams[0]` dictionary.
    #[must_use]
    pub fn stream_dictionary(&self) -> plist::Dictionary {
        let mut stream = plist::Dictionary::new();
        let int = |v: u64| Value::Integer(v.into());
        stream.insert("audioFormat".into(), int(self.format.audio_format));
        stream.insert("audioMode".into(), Value::String(AUDIO_MODE.into()));
        stream.insert("controlPort".into(), int(u64::from(self.control_port)));
        stream.insert("ct".into(), int(self.format.compression));
        stream.insert("isMedia".into(), Value::Boolean(true));
        stream.insert(
            "latencyMax".into(),
            int(u64::from(self.format.latency_max())),
        );
        stream.insert(
            "latencyMin".into(),
            int(u64::from(self.format.latency_min())),
        );
        stream.insert("shk".into(), Value::Data(self.shared_key.to_vec()));
        stream.insert("spf".into(), int(u64::from(self.format.frames_per_packet)));
        stream.insert("sr".into(), int(u64::from(self.format.sample_rate)));
        stream.insert("type".into(), int(self.stream_type.code()));
        stream.insert(
            "supportsDynamicStreamID".into(),
            Value::Boolean(self.supports_dynamic_stream_id),
        );
        stream.insert("streamConnectionID".into(), int(self.stream_connection_id));
        stream
    }

    /// The whole body as a value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut body = plist::Dictionary::new();
        body.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(self.stream_dictionary())]),
        );
        Value::Dictionary(body)
    }

    /// The serialised body (binary plist).
    pub fn body(&self) -> Result<Vec<u8>> {
        super::encode_plist(&self.to_value(), "stream SETUP")
    }
}

/// The reply to a stream `SETUP`.
///
/// Receivers vary in which keys they send; only `dataPort` is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamSetupResponse {
    /// `type` as the receiver echoed it, if it did.
    pub stream_type: Option<u64>,
    /// Where audio goes: UDP for realtime, TCP for buffered.
    pub data_port: u16,
    /// The receiver's control port (realtime sync/retransmit), or 0.
    pub control_port: u16,
    /// `streamID`, which a stream `TEARDOWN` names; not every receiver sends it.
    pub stream_id: Option<u64>,
    /// `audioBufferSize` in bytes (buffered only): how far ahead a sender may run.
    pub audio_buffer_size: Option<u64>,
    /// `arrivalToRenderLatencyMs`: observed as 108 from an Apple TV; nothing here acts on it.
    pub arrival_to_render_latency_ms: Option<u64>,
}

impl StreamSetupResponse {
    /// Parses the reply body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "stream SETUP reply is not a readable plist")?;
        let stream = value
            .as_dictionary()
            .and_then(|d| d.get("streams"))
            .and_then(Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                AirPlayError::Protocol("stream SETUP reply has no streams[0] dictionary".to_owned())
            })?;
        let unsigned = |key: &str| stream.get(key).and_then(Value::as_unsigned_integer);
        let port = |key: &str| unsigned(key).and_then(|v| u16::try_from(v).ok());
        let data_port = port("dataPort").filter(|&p| p != 0).ok_or_else(|| {
            AirPlayError::Protocol("stream SETUP reply names no dataPort".to_owned())
        })?;
        Ok(Self {
            stream_type: unsigned("type"),
            data_port,
            control_port: port("controlPort").unwrap_or(0),
            stream_id: unsigned("streamID"),
            audio_buffer_size: unsigned("audioBufferSize"),
            arrival_to_render_latency_ms: unsigned("arrivalToRenderLatencyMs"),
        })
    }
}
