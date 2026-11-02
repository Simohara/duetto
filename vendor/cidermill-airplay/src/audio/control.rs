//! The control-channel bodies an audio session sends besides the stream `SETUP`: `SETPEERS`,
//! `SETPEERSX`, `SETRATEANCHORTIME`, the two `TEARDOWN` shapes, `FLUSH`'s `RTP-Info`, and the PTP
//! [`TimingPeerInfo`] of the session `SETUP`.
//!
//! `SETPEERS` and `TEARDOWN` match a real iPhone's bytes (iOS 13.2.3); `SETRATEANCHORTIME` has no
//! sender capture, and its keys follow two open receivers.

use plist::Value;

use super::format::StreamType;
use super::ptp::NetworkTime;
use crate::error::{AirPlayError, Result};
use crate::time::RtpTimestamp;

/// `Content-Type` of a `SETPEERS` body (not a MIME type).
pub const SET_PEERS_CONTENT_TYPE: &str = "/peer-list-changed";

/// `Content-Type` of a `SETPEERSX` body.
pub const SET_PEERS_X_CONTENT_TYPE: &str = "/peer-list-changed-x";

/// How often a sender posts `/feedback`.
pub const FEEDBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// The `SETPEERS` body: a binary-plist array of address strings, one for every address of every
/// peer in the PTP group (receivers and the sender itself).
pub fn set_peers_body<S: AsRef<str>>(addresses: &[S]) -> Result<Vec<u8>> {
    let array = addresses
        .iter()
        .map(|a| Value::String(a.as_ref().to_owned()))
        .collect();
    super::encode_plist(&Value::Array(array), "SETPEERS")
}

/// The `SETPEERSX` body: a binary-plist array of full peer dictionaries
/// ([`TimingPeerInfo::to_value`]), sent instead of `SETPEERS` to a receiver that advertises
/// feature bit 52.
///
/// Observed on tvOS 26: answered 200, and with the sender's clock named the Apple TV stops
/// announcing its own at once.
pub fn set_peers_x_body(peers: &[TimingPeerInfo]) -> Result<Vec<u8>> {
    let array = peers.iter().map(TimingPeerInfo::to_value).collect();
    super::encode_plist(&Value::Array(array), "SETPEERSX")
}

/// A `SETRATEANCHORTIME`: "RTP time `rtp_time` plays at PTP time `network_time` on the timeline
/// `timeline_id`, at rate `rate`" (1 = play, 0 = pause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateAnchor {
    /// When `rtp_time` plays, on the PTP timeline.
    pub network_time: NetworkTime,
    /// `networkTimeTimelineID`: the grandmaster clock identity the time is on.
    pub timeline_id: u64,
    /// The RTP timestamp that plays at `network_time`.
    pub rtp_time: RtpTimestamp,
    /// `rate`: 1 plays, 0 pauses.
    pub rate: u32,
}

impl RateAnchor {
    /// An anchor that starts (or resumes) playback.
    #[must_use]
    pub fn play(network_time: NetworkTime, timeline_id: u64, rtp_time: RtpTimestamp) -> Self {
        Self {
            network_time,
            timeline_id,
            rtp_time,
            rate: 1,
        }
    }

    /// An anchor that pauses at `rtp_time`.
    #[must_use]
    pub fn pause(network_time: NetworkTime, timeline_id: u64, rtp_time: RtpTimestamp) -> Self {
        Self {
            rate: 0,
            ..Self::play(network_time, timeline_id, rtp_time)
        }
    }

    /// The anchor that makes packet `first_rtp_time` play `lead_nanos` after the master time
    /// `master_now_nanos` (from [`super::ptp::ClockFilter::master_nanos`]).
    #[must_use]
    pub fn start_at(
        master_now_nanos: u128,
        lead_nanos: u128,
        timeline_id: u64,
        first_rtp_time: RtpTimestamp,
    ) -> Self {
        Self::play(
            NetworkTime::from_nanos(master_now_nanos + lead_nanos),
            timeline_id,
            first_rtp_time,
        )
    }

    /// The body as a value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let int = |v: u64| Value::Integer(v.into());
        let mut dict = plist::Dictionary::new();
        dict.insert("networkTimeSecs".into(), int(self.network_time.secs));
        dict.insert("networkTimeFrac".into(), int(self.network_time.frac));
        dict.insert("networkTimeTimelineID".into(), int(self.timeline_id));
        dict.insert("rtpTime".into(), int(u64::from(self.rtp_time.get())));
        dict.insert("rate".into(), int(u64::from(self.rate)));
        Value::Dictionary(dict)
    }

    /// The serialised body (binary plist).
    pub fn body(&self) -> Result<Vec<u8>> {
        super::encode_plist(&self.to_value(), "SETRATEANCHORTIME")
    }

    /// Reads a `SETRATEANCHORTIME` body a sender sent (the receiver's side). Missing fields
    /// default to 0.
    ///
    /// # Errors
    ///
    /// The body is not a readable plist dictionary.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "SETRATEANCHORTIME is not a readable plist")?;
        let dict = value.as_dictionary().ok_or_else(|| {
            AirPlayError::Protocol("SETRATEANCHORTIME is not a dictionary".to_owned())
        })?;
        let uint = |key: &str| {
            dict.get(key)
                .and_then(Value::as_unsigned_integer)
                .unwrap_or(0)
        };
        Ok(Self {
            network_time: NetworkTime {
                secs: uint("networkTimeSecs"),
                frac: uint("networkTimeFrac"),
            },
            timeline_id: uint("networkTimeTimelineID"),
            rtp_time: RtpTimestamp::new(u32::try_from(uint("rtpTime")).unwrap_or(0)),
            rate: u32::try_from(uint("rate")).unwrap_or(0),
        })
    }
}

/// The `TEARDOWN` body that ends one stream but keeps the session: `{"streams": [{"streamID",
/// "type"}]}`.
pub fn teardown_stream_body(stream_type: StreamType, stream_id: u64) -> Result<Vec<u8>> {
    let mut stream = plist::Dictionary::new();
    stream.insert("streamID".into(), Value::Integer(stream_id.into()));
    stream.insert("type".into(), Value::Integer(stream_type.code().into()));
    let mut body = plist::Dictionary::new();
    body.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(stream)]),
    );
    super::encode_plist(&Value::Dictionary(body), "stream TEARDOWN")
}

/// The `TEARDOWN` body that ends the session: an empty dictionary.
pub fn teardown_session_body() -> Result<Vec<u8>> {
    super::encode_plist(
        &Value::Dictionary(plist::Dictionary::new()),
        "session TEARDOWN",
    )
}

/// The `RTP-Info` header a realtime `FLUSH` carries: `seq=<first sequence>;rtptime=<first
/// timestamp>`.
#[must_use]
pub fn rtp_info(sequence: u32, rtp_time: RtpTimestamp) -> String {
    format!("seq={sequence};rtptime={rtp_time}")
}

/// The PTP identity a session `SETUP` names under `timingPeerInfo` (and a reply names back).
///
/// The optional keys are the ones an Apple TV's reply carries (observed on tvOS 26); each is
/// written only when set. `ClockID` is an 8-byte, so signed, plist integer; `ClockPorts` maps a
/// peer `ID` to the PTP port used toward it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TimingPeerInfo {
    /// `Addresses`: every address of the device.
    pub addresses: Vec<String>,
    /// `ID`: a UUID for a sender; receivers answer with a UUID or an IP address.
    pub id: String,
    /// `ClockID`: the device's PTP clock identity.
    pub clock_id: Option<u64>,
    /// `DeviceType`.
    pub device_type: Option<u64>,
    /// `ClockPorts`: peer `ID` -> the PTP port number this device uses toward that peer.
    pub clock_ports: Vec<(String, u16)>,
    /// `SupportsClockPortMatchingOverride`.
    pub supports_clock_port_matching_override: Option<bool>,
}

impl TimingPeerInfo {
    /// A timing peer.
    #[must_use]
    pub fn new(addresses: Vec<String>, id: String) -> Self {
        Self {
            addresses,
            id,
            ..Self::default()
        }
    }

    /// `{"Addresses": [...], "ID": ...}` plus whichever optional keys are set.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "Addresses".into(),
            Value::Array(
                self.addresses
                    .iter()
                    .map(|a| Value::String(a.clone()))
                    .collect(),
            ),
        );
        dict.insert("ID".into(), Value::String(self.id.clone()));
        if let Some(clock) = self.clock_id {
            // The 64 bits as a signed integer, as an Apple TV writes it.
            dict.insert("ClockID".into(), Value::Integer((clock as i64).into()));
        }
        if let Some(kind) = self.device_type {
            dict.insert("DeviceType".into(), Value::Integer(kind.into()));
        }
        if !self.clock_ports.is_empty() {
            let mut ports = plist::Dictionary::new();
            for (peer, port) in &self.clock_ports {
                ports.insert(peer.clone(), Value::Integer(u64::from(*port).into()));
            }
            dict.insert("ClockPorts".into(), Value::Dictionary(ports));
        }
        if let Some(value) = self.supports_clock_port_matching_override {
            dict.insert(
                "SupportsClockPortMatchingOverride".into(),
                Value::Boolean(value),
            );
        }
        Value::Dictionary(dict)
    }

    /// Reads a peer dictionary (a `timingPeerInfo`, or one entry of `timingPeerList` /
    /// `SETPEERSX`). `None` if it is not a dictionary; missing keys stay empty.
    #[must_use]
    pub fn from_value(value: &Value) -> Option<Self> {
        let info = value.as_dictionary()?;
        let addresses = info
            .get("Addresses")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_string)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let id = info
            .get("ID")
            .and_then(Value::as_string)
            .unwrap_or_default()
            .to_owned();
        let integer = |v: &Value| {
            v.as_unsigned_integer()
                .or_else(|| v.as_signed_integer().map(|i| i as u64))
        };
        let clock_ports = info
            .get("ClockPorts")
            .and_then(Value::as_dictionary)
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(|(peer, port)| {
                        let port = u16::try_from(integer(port)?).ok()?;
                        Some((peer.clone(), port))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            addresses,
            id,
            clock_id: info.get("ClockID").and_then(integer),
            device_type: info.get("DeviceType").and_then(integer),
            clock_ports,
            supports_clock_port_matching_override: info
                .get("SupportsClockPortMatchingOverride")
                .and_then(Value::as_boolean),
        })
    }

    /// Reads `timingPeerInfo` from a session `SETUP` reply, if it has one.
    pub fn from_setup_reply(body: &[u8]) -> Result<Option<Self>> {
        let value = crate::safe_plist::parse(body, "SETUP reply is not a readable plist")?;
        Ok(value
            .as_dictionary()
            .and_then(|d| d.get("timingPeerInfo"))
            .and_then(Self::from_value))
    }
}
