//! The order a real sender puts its requests in, as data, plus a classifier that names any request
//! as a step, so a capture can be replayed and compared with this crate's own orders.
//!
//! Observed from an iPhone on iOS 26.7 (`AirPlay/960.13.1`): each tap opened a remote-control
//! session and a media session on separate TCP connections (`GET /info`, pairing, sender
//! authentication, session `SETUP`). `tests/iphone_sender_observed.rs` replays them through
//! [`classify`].
//!
//! [`SenderStep::SenderAuthentication`] (`POST /fp-setup`) is a named variant with no bytes behind
//! it: this crate does not implement it, so comparisons diverge there on purpose.
//!
//! Where our orders differ otherwise (asserted in the tests): the iPhone's pair-verify attempts
//! then transient pair-setup with `X-Apple-HKP: 4` ([`IOS_TRANSIENT_HKP`], selectable as
//! [`crate::pairing::TransientStyle::Ios26`]); an encrypted `GET /info` after session `SETUP`;
//! PTP for the media session; `GET_PARAMETER volume` before `RECORD`; `RECORD` before any stream
//! `SETUP` and `SETPEERSX` after it; now-playing `POST /command` pushes ([`crate::command`]); and a
//! `type: 130` data stream `SETUP` ([`crate::datastream`]). Nothing after the `type: 130` request
//! has been seen from a real sender.

use crate::rtsp::Request;

/// `X-Apple-HKP` on the iPhone's transient pair-setup. Observed. Compare
/// [`crate::pairing::constants::HKP_TRANSIENT`] (`1`), which an Apple TV answered.
pub const IOS_TRANSIENT_HKP: u8 = 4;

/// The two `X-Apple-HKP` values the iPhone tried pair-verify with, in order, before transient
/// pair-setup. Observed.
pub const IOS_PAIR_VERIFY_HKP_LADDER: [u8; 2] = [6, 3];

/// Header the iPhone put on every pairing request: seconds since 2001-01-01 UTC
/// (`CFAbsoluteTime`). Observed.
pub const ABSOLUTE_TIME_HEADER: &str = "X-Apple-AbsoluteTime";

/// Seconds between the Unix epoch and 2001-01-01T00:00:00Z.
pub const CF_ABSOLUTE_TIME_OFFSET: u64 = 978_307_200;

/// The [`ABSOLUTE_TIME_HEADER`] value for a Unix time in seconds (0 before 2001).
#[must_use]
pub fn cf_absolute_time(unix_seconds: u64) -> u64 {
    unix_seconds.saturating_sub(CF_ABSOLUTE_TIME_OFFSET)
}

/// Which session a session `SETUP` opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionKind {
    /// `isRemoteControlOnly: true`.
    RemoteControl,
    /// Everything else.
    Media,
}

/// Which stream a stream `SETUP` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamKind {
    /// Audio: `type` 96 (realtime) or 103 (buffered).
    Audio {
        /// `type`.
        stream_type: u64,
    },
    /// The MediaRemote data stream, `type` 130.
    DataStream {
        /// `controlType`.
        control_type: u64,
    },
    /// A `type` this module does not name.
    Other {
        /// `type`, if it had one.
        stream_type: Option<u64>,
    },
}

/// Which `POST /command` push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandKind {
    /// `updateMRNowPlayingInfo`.
    NowPlayingInfo,
    /// `updateMRPlaybackState`.
    PlaybackState,
    /// `updateMRSupportedCommands`.
    SupportedCommands,
    /// `updateMRNowPlayingClient`.
    NowPlayingClient,
    /// Any other body.
    Other,
}

/// One request of a sender's sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SenderStep {
    /// `GET /info` with a `{"qualifier": ["txtAirPlay"]}` body, before pairing.
    InfoQuery,
    /// `GET /info` with no body (after the session `SETUP`, encrypted).
    InfoRefresh,
    /// `POST /pair-verify`, with its `X-Apple-HKP`.
    PairVerify {
        /// The header's value, if numeric.
        hkp: Option<u8>,
    },
    /// `POST /pair-setup`, with its `X-Apple-HKP`.
    PairSetup {
        /// The header's value, if numeric.
        hkp: Option<u8>,
    },
    /// `POST /fp-setup`: **the sender authenticates itself here** (feature bit 14,
    /// [`crate::Features::AUTHENTICATION_4`]). Not implemented, by policy; the flag is always
    /// `true` and exists so the reason is in the type, not a comment.
    SenderAuthentication {
        /// Always `true`.
        not_implemented_by_policy: bool,
    },
    /// A session `SETUP` (no `streams`).
    SessionSetup(SessionKind),
    /// A stream `SETUP` (`streams`).
    StreamSetup(StreamKind),
    /// `GET_PARAMETER` asking for `volume`.
    GetVolume,
    /// `RECORD`.
    Record,
    /// `SETPEERS`.
    SetPeers,
    /// `SETPEERSX`.
    SetPeersX,
    /// `POST /command`.
    Command(CommandKind),
    /// `SETRATEANCHORTIME`.
    SetRateAnchor,
    /// `FLUSH`.
    Flush,
    /// `POST /feedback`.
    Feedback,
    /// `POST /play`.
    Play,
    /// `POST /rate`.
    Rate,
    /// `TEARDOWN`.
    Teardown,
    /// `SET_PARAMETER` (volume, DMAP now-playing, artwork or progress —
    /// [`crate::audio::AudioSendState::set_volume`] and friends). Not yet seen from a real Apple
    /// sender's realtime audio session; the phone's own `SET_PARAMETER` traffic in
    /// `SenderStep::Command` is the MediaRemote data channel instead.
    SetParameter,
    /// Anything else.
    Other,
}

/// The sender-authentication step, as it appears in every real sequence.
pub const SENDER_AUTHENTICATION: SenderStep = SenderStep::SenderAuthentication {
    not_implemented_by_policy: true,
};

use SenderStep::{
    Command, InfoQuery, InfoRefresh, PairSetup, PairVerify, Record, SessionSetup, SetPeersX,
    StreamSetup,
};

/// The request orders a real iPhone used.
#[derive(Debug, Clone, Copy)]
pub struct RealSenderSequence;

impl RealSenderSequence {
    /// A remote-control session's connection, request by request. Observed six times, identical.
    pub const REMOTE_CONTROL: &'static [SenderStep] = &[
        InfoQuery,
        PairVerify { hkp: Some(6) },
        PairVerify { hkp: Some(3) },
        PairSetup { hkp: Some(4) },
        PairSetup { hkp: Some(4) },
        SENDER_AUTHENTICATION,
        SENDER_AUTHENTICATION,
        SessionSetup(SessionKind::RemoteControl),
        InfoRefresh,
        Record,
        StreamSetup(StreamKind::DataStream { control_type: 2 }),
    ];

    /// A media session's connection, request by request, up to where the capture stops. Observed
    /// twice; one ended with the `controlType: 1` data stream `SETUP`, the other with `POST
    /// /feedback`.
    pub const MEDIA: &'static [SenderStep] = &[
        InfoQuery,
        PairVerify { hkp: Some(6) },
        PairVerify { hkp: Some(3) },
        PairSetup { hkp: Some(4) },
        PairSetup { hkp: Some(4) },
        SENDER_AUTHENTICATION,
        SENDER_AUTHENTICATION,
        SessionSetup(SessionKind::Media),
        InfoRefresh,
        SenderStep::GetVolume,
        Record,
        SetPeersX,
        Command(CommandKind::NowPlayingInfo),
        Command(CommandKind::PlaybackState),
        Command(CommandKind::SupportedCommands),
        Command(CommandKind::NowPlayingClient),
        Command(CommandKind::PlaybackState),
        Command(CommandKind::SupportedCommands),
        Command(CommandKind::NowPlayingClient),
        StreamSetup(StreamKind::DataStream { control_type: 1 }),
    ];

    /// pyatv 0.18.0's remote-control session after pairing (`AP2Session.setup_remote_control`,
    /// read): session `SETUP`, `RECORD`, the `controlType: 2` data stream. The iPhone's order
    /// minus sender authentication and the encrypted `GET /info`.
    pub const PYATV_REMOTE_CONTROL_AFTER_PAIRING: &'static [SenderStep] = &[
        SessionSetup(SessionKind::RemoteControl),
        Record,
        StreamSetup(StreamKind::DataStream { control_type: 2 }),
    ];

    /// Where a sequence stops being pairing and sender authentication: the index of its session
    /// `SETUP`.
    #[must_use]
    pub fn session_start(sequence: &[SenderStep]) -> Option<usize> {
        sequence
            .iter()
            .position(|s| matches!(s, SenderStep::SessionSetup(_)))
    }
}

/// The index of the first step where two sequences differ (or where the shorter one ends), `None`
/// when they are equal.
#[must_use]
pub fn first_divergence(real: &[SenderStep], ours: &[SenderStep]) -> Option<usize> {
    let common = real.len().min(ours.len());
    (0..common)
        .find(|&i| real[i] != ours[i])
        .or((real.len() != ours.len()).then_some(common))
}

/// Our audio session's step as a [`SenderStep`], for comparing [`crate::audio::AudioSendState`]
/// with a real sender. `stream_type` is the stream `SETUP`'s `type`.
#[must_use]
pub fn from_audio_step(step: crate::audio::Step, stream_type: u64) -> SenderStep {
    use crate::audio::Step as A;
    match step {
        A::StreamSetup => StreamSetup(StreamKind::Audio { stream_type }),
        A::SetPeers => SenderStep::SetPeers,
        A::Feedback => SenderStep::Feedback,
        A::Record => Record,
        A::Flush => SenderStep::Flush,
        A::SetRateAnchor => SenderStep::SetRateAnchor,
        A::TeardownStream | A::TeardownSession => SenderStep::Teardown,
        A::SetParameter => SenderStep::SetParameter,
    }
}

/// Names a request as a step. Reads the method, the target, `X-Apple-HKP` and - for `SETUP`,
/// `GET /info`, `GET_PARAMETER` and `/command` - the body. **Never reads a `/fp-setup` body.**
#[must_use]
pub fn classify(request: &Request) -> SenderStep {
    let path = request
        .uri
        .split_once('?')
        .map_or(request.uri.as_str(), |(p, _)| p);
    let hkp = || {
        request
            .headers
            .get(crate::pairing::constants::HKP_HEADER)
            .and_then(|v| v.trim().parse().ok())
    };
    match (request.method.as_str(), path) {
        ("GET", "/info") if request.body.is_empty() => InfoRefresh,
        ("GET", "/info") => InfoQuery,
        ("POST", "/pair-verify") => PairVerify { hkp: hkp() },
        ("POST", "/pair-setup") => PairSetup { hkp: hkp() },
        ("POST", "/fp-setup") => SENDER_AUTHENTICATION,
        ("POST", "/command") => Command(command_kind(&request.body)),
        ("POST", "/feedback") => SenderStep::Feedback,
        ("POST", "/play") => SenderStep::Play,
        ("POST", "/rate") => SenderStep::Rate,
        ("SETUP", _) => setup_kind(&request.body),
        ("GET_PARAMETER", _) if request.body.trim_ascii() == b"volume" => SenderStep::GetVolume,
        ("RECORD", _) => Record,
        ("SETPEERS", _) => SenderStep::SetPeers,
        ("SETPEERSX", _) => SetPeersX,
        ("SETRATEANCHORTIME", _) => SenderStep::SetRateAnchor,
        ("FLUSH", _) => SenderStep::Flush,
        ("TEARDOWN", _) => SenderStep::Teardown,
        _ => SenderStep::Other,
    }
}

fn setup_kind(body: &[u8]) -> SenderStep {
    let value = crate::safe_plist::from_bytes(body).ok();
    let Some(dict) = value.as_ref().and_then(plist::Value::as_dictionary) else {
        return SenderStep::Other;
    };
    if let Some(stream) = dict.get("streams").and_then(plist::Value::as_array) {
        let first = stream.first().and_then(plist::Value::as_dictionary);
        let number = |key: &str| {
            first
                .and_then(|s| s.get(key))
                .and_then(plist::Value::as_unsigned_integer)
        };
        return StreamSetup(match number("type") {
            Some(t) if t == crate::datastream::STREAM_TYPE => StreamKind::DataStream {
                control_type: number("controlType").unwrap_or(0),
            },
            Some(t @ (96 | 103)) => StreamKind::Audio { stream_type: t },
            other => StreamKind::Other { stream_type: other },
        });
    }
    let remote = dict
        .get("isRemoteControlOnly")
        .and_then(plist::Value::as_boolean)
        .unwrap_or(false);
    SessionSetup(if remote {
        SessionKind::RemoteControl
    } else {
        SessionKind::Media
    })
}

fn command_kind(body: &[u8]) -> CommandKind {
    let value = crate::safe_plist::from_bytes(body).ok();
    match value
        .as_ref()
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| d.get("type"))
        .and_then(plist::Value::as_string)
    {
        Some(crate::command::UPDATE_NOW_PLAYING_INFO) => CommandKind::NowPlayingInfo,
        Some(crate::command::UPDATE_PLAYBACK_STATE) => CommandKind::PlaybackState,
        Some(crate::command::UPDATE_SUPPORTED_COMMANDS) => CommandKind::SupportedCommands,
        Some(crate::command::UPDATE_NOW_PLAYING_CLIENT) => CommandKind::NowPlayingClient,
        _ => CommandKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capture_s_absolute_time_is_its_wall_clock() {
        // 17:40:01 UTC on the capture day.
        assert_eq!(cf_absolute_time(1_790_185_201), 811_878_001);
        assert_eq!(cf_absolute_time(0), 0);
    }

    #[test]
    fn divergence_is_the_first_differing_index_or_the_shorter_length() {
        let a = [InfoQuery, Record];
        assert_eq!(first_divergence(&a, &a), None);
        assert_eq!(first_divergence(&a, &[InfoQuery]), Some(1));
        assert_eq!(first_divergence(&a, &[InfoRefresh, Record]), Some(0));
    }

    #[test]
    fn both_sessions_start_after_the_sender_authentication_step() {
        for sequence in [
            RealSenderSequence::REMOTE_CONTROL,
            RealSenderSequence::MEDIA,
        ] {
            let start = RealSenderSequence::session_start(sequence).unwrap();
            assert_eq!(sequence[start - 1], SENDER_AUTHENTICATION);
        }
    }
}
