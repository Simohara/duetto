//! The now-playing pushes an AirPlay 2 media session carries as `POST /command`, sans-io: body
//! builders for a sender and a parser for a receiver.
//!
//! Observed from an iPhone (iOS 26.7): right after `SETPEERSX` it sends, on the control connection,
//! `updateMRNowPlayingInfo`, `updateMRPlaybackState`, `updateMRSupportedCommands` and
//! `updateMRNowPlayingClient` bodies, each a binary plist `{"type": <name>, "params": {...}}`.
//! The event-channel direction has not been seen; [`MrCommand::from_dictionary`] parses it.
//!
//! - `mrPlaybackState`: values observed; names assumed from pyatv 0.18.0 `Common.proto`
//!   (1 playing, 2 paused, 3 stopped, 4 interrupted, 5 seeking).
//! - `kCommandInfoCommandKey`: raw command numbers; the skip commands (17, 18) are fixed by their
//!   skip interval, the rest follow pyatv's `Command` enum minus one. 24 (seek) is assumed.
//! - `mrNowPlayingClient`: a serialised `NowPlayingClient` protobuf ([`NowPlayingClient::encode`]).

use plist::Value;

use crate::datastream::{decode_varint, encode_varint};
use crate::error::{AirPlayError, Result};

/// The request path.
pub const PATH: &str = "/command";

/// `type` of the now-playing-info push.
pub const UPDATE_NOW_PLAYING_INFO: &str = "updateMRNowPlayingInfo";
/// `type` of the playback-state push.
pub const UPDATE_PLAYBACK_STATE: &str = "updateMRPlaybackState";
/// `type` of the supported-commands push.
pub const UPDATE_SUPPORTED_COMMANDS: &str = "updateMRSupportedCommands";
/// `type` of the now-playing-client push.
pub const UPDATE_NOW_PLAYING_CLIENT: &str = "updateMRNowPlayingClient";

/// The now-playing-info `type` the iPhone sent: text metadata.
pub const NOW_PLAYING_INFO_TEXT: &str = "npi-text";
/// The merge policy the iPhone sent.
pub const MERGE_POLICY_REPLACE: &str = "replace";

/// `params` key of a playback state.
pub const KEY_PLAYBACK_STATE: &str = "mrPlaybackState";
/// `params` key of the supported-commands array.
pub const KEY_SUPPORTED_COMMANDS: &str = "mrSupportedCommandsFromSender";
/// `params` key of the now-playing client.
pub const KEY_NOW_PLAYING_CLIENT: &str = "mrNowPlayingClient";
/// Key of a command's number, inside each nested command-info plist.
pub const KEY_COMMAND: &str = "kCommandInfoCommandKey";
/// Key of a command's enabled flag.
pub const KEY_ENABLED: &str = "kCommandInfoEnabledKey";
/// Key of a command's options dictionary.
pub const KEY_OPTIONS: &str = "kCommandInfoOptionsKey";
/// Option key carrying skip intervals in seconds.
pub const OPTION_SKIP_INTERVAL: &str = "kMRMediaRemoteOptionSkipInterval";

/// MediaRemote command numbers as they appear under [`KEY_COMMAND`]. See the module docs for which
/// names are proven by the capture and which are ASSUMED.
pub mod commands {
    /// Play.
    pub const PLAY: u64 = 0;
    /// Pause.
    pub const PAUSE: u64 = 1;
    /// Toggle play/pause.
    pub const TOGGLE_PLAY_PAUSE: u64 = 2;
    /// Begin fast-forward.
    pub const BEGIN_FAST_FORWARD: u64 = 8;
    /// End fast-forward.
    pub const END_FAST_FORWARD: u64 = 9;
    /// Begin rewind.
    pub const BEGIN_REWIND: u64 = 10;
    /// End rewind.
    pub const END_REWIND: u64 = 11;
    /// Skip forward: carries a skip interval in the capture.
    pub const SKIP_FORWARD: u64 = 17;
    /// Skip backward: carries a skip interval in the capture.
    pub const SKIP_BACKWARD: u64 = 18;
    /// Seek to a playback position. ASSUMED name.
    pub const SEEK_TO_PLAYBACK_POSITION: u64 = 24;
}

/// A MediaRemote playback state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlaybackState {
    /// 0.
    Unknown,
    /// 1.
    Playing,
    /// 2.
    Paused,
    /// 3.
    Stopped,
    /// 4.
    Interrupted,
    /// 5.
    Seeking,
    /// Anything else, kept as sent.
    Other(u64),
}

impl PlaybackState {
    /// The number on the wire.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::Unknown => 0,
            Self::Playing => 1,
            Self::Paused => 2,
            Self::Stopped => 3,
            Self::Interrupted => 4,
            Self::Seeking => 5,
            Self::Other(code) => code,
        }
    }

    /// Maps a number.
    #[must_use]
    pub fn from_code(code: u64) -> Self {
        match code {
            0 => Self::Unknown,
            1 => Self::Playing,
            2 => Self::Paused,
            3 => Self::Stopped,
            4 => Self::Interrupted,
            5 => Self::Seeking,
            other => Self::Other(other),
        }
    }
}

/// One entry of `mrSupportedCommandsFromSender`, which travels as a **nested binary plist** inside
/// a data value.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CommandInfo {
    /// `kCommandInfoCommandKey` ([`commands`]).
    pub command: u64,
    /// `kCommandInfoEnabledKey`.
    pub enabled: bool,
    /// `kCommandInfoOptionsKey`, empty when absent.
    pub options: plist::Dictionary,
}

impl CommandInfo {
    /// An enabled command with no options.
    #[must_use]
    pub fn enabled(command: u64) -> Self {
        Self {
            command,
            enabled: true,
            options: plist::Dictionary::new(),
        }
    }

    /// An enabled command whose options carry skip intervals, as the iPhone sends skip-forward and
    /// skip-backward (`[15.0]`).
    #[must_use]
    pub fn with_skip_intervals(command: u64, seconds: &[f64]) -> Self {
        let mut options = plist::Dictionary::new();
        options.insert(
            OPTION_SKIP_INTERVAL.into(),
            Value::Array(seconds.iter().map(|s| Value::Real(*s)).collect()),
        );
        Self {
            options,
            ..Self::enabled(command)
        }
    }

    /// The skip intervals, if the options carry any.
    #[must_use]
    pub fn skip_intervals(&self) -> Vec<f64> {
        self.options
            .get(OPTION_SKIP_INTERVAL)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_real).collect())
            .unwrap_or_default()
    }

    fn to_nested_plist(&self) -> Result<Vec<u8>> {
        let mut dict = plist::Dictionary::new();
        if !self.options.is_empty() {
            dict.insert(KEY_OPTIONS.into(), Value::Dictionary(self.options.clone()));
        }
        dict.insert(KEY_COMMAND.into(), Value::Integer(self.command.into()));
        dict.insert(KEY_ENABLED.into(), Value::Boolean(self.enabled));
        encode(&Value::Dictionary(dict), "command info")
    }

    fn from_nested_plist(bytes: &[u8]) -> Option<Self> {
        let value = crate::safe_plist::from_bytes(bytes).ok()?;
        let dict = value.as_dictionary()?;
        Some(Self {
            command: dict.get(KEY_COMMAND).and_then(unsigned)?,
            enabled: dict
                .get(KEY_ENABLED)
                .and_then(Value::as_boolean)
                .unwrap_or(false),
            options: dict
                .get(KEY_OPTIONS)
                .and_then(Value::as_dictionary)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

/// A MediaRemote `NowPlayingClient`: who is playing. Every field is optional, as in the protobuf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NowPlayingClient {
    /// 1: `processIdentifier`.
    pub process_identifier: Option<i32>,
    /// 2: `bundleIdentifier`.
    pub bundle_identifier: Option<String>,
    /// 3: `parentApplicationBundleIdentifier`.
    pub parent_application_bundle_identifier: Option<String>,
    /// 4: `processUserIdentifier`.
    pub process_user_identifier: Option<i32>,
    /// 5: `nowPlayingVisibility`.
    pub now_playing_visibility: Option<i32>,
    /// 7: `displayName`.
    pub display_name: Option<String>,
    /// 8: `bundleIdentifierHierarchy` (repeated).
    pub bundle_identifier_hierarchy: Vec<String>,
}

impl NowPlayingClient {
    /// A client named by its bundle identifier and process id.
    #[must_use]
    pub fn new(process_identifier: i32, bundle_identifier: &str) -> Self {
        Self {
            process_identifier: Some(process_identifier),
            bundle_identifier: Some(bundle_identifier.to_owned()),
            ..Self::default()
        }
    }

    /// The serialised protobuf, fields in number order (what protobuf serialisers emit).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let varint = |out: &mut Vec<u8>, field: u64, value: i32| {
            out.extend_from_slice(&encode_varint(field << 3));
            // int32: negative values are sign-extended to ten bytes, as protobuf requires.
            out.extend_from_slice(&encode_varint(i64::from(value) as u64));
        };
        let string = |out: &mut Vec<u8>, field: u64, value: &str| {
            out.extend_from_slice(&encode_varint((field << 3) | 2));
            out.extend_from_slice(&encode_varint(value.len() as u64));
            out.extend_from_slice(value.as_bytes());
        };
        if let Some(v) = self.process_identifier {
            varint(&mut out, 1, v);
        }
        if let Some(v) = &self.bundle_identifier {
            string(&mut out, 2, v);
        }
        if let Some(v) = &self.parent_application_bundle_identifier {
            string(&mut out, 3, v);
        }
        if let Some(v) = self.process_user_identifier {
            varint(&mut out, 4, v);
        }
        if let Some(v) = self.now_playing_visibility {
            varint(&mut out, 5, v);
        }
        if let Some(v) = &self.display_name {
            string(&mut out, 7, v);
        }
        for v in &self.bundle_identifier_hierarchy {
            string(&mut out, 8, v);
        }
        out
    }

    /// Reads a serialised protobuf, skipping fields it does not know. Malformed input is an error,
    /// never a panic.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bad = |what: &str| AirPlayError::Protocol(format!("NowPlayingClient: {what}"));
        let mut client = Self::default();
        let mut rest = bytes;
        while !rest.is_empty() {
            let (key, used) = decode_varint(rest).ok_or_else(|| bad("bad tag"))?;
            rest = &rest[used..];
            let (field, wire) = (key >> 3, key & 7);
            match wire {
                0 => {
                    let (value, used) = decode_varint(rest).ok_or_else(|| bad("bad varint"))?;
                    rest = &rest[used..];
                    let value = value as i64 as i32;
                    match field {
                        1 => client.process_identifier = Some(value),
                        4 => client.process_user_identifier = Some(value),
                        5 => client.now_playing_visibility = Some(value),
                        _ => {}
                    }
                }
                2 => {
                    let (length, used) = decode_varint(rest).ok_or_else(|| bad("bad length"))?;
                    rest = &rest[used..];
                    let length = usize::try_from(length)
                        .ok()
                        .filter(|&l| l <= rest.len())
                        .ok_or_else(|| bad("length past the end"))?;
                    let (value, after) = rest.split_at(length);
                    rest = after;
                    let text = || String::from_utf8_lossy(value).into_owned();
                    match field {
                        2 => client.bundle_identifier = Some(text()),
                        3 => client.parent_application_bundle_identifier = Some(text()),
                        7 => client.display_name = Some(text()),
                        8 => client.bundle_identifier_hierarchy.push(text()),
                        _ => {}
                    }
                }
                1 => rest = rest.get(8..).ok_or_else(|| bad("truncated fixed64"))?,
                5 => rest = rest.get(4..).ok_or_else(|| bad("truncated fixed32"))?,
                _ => return Err(bad("unsupported wire type")),
            }
        }
        Ok(client)
    }
}

/// One `POST /command` push.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MrCommand {
    /// `updateMRNowPlayingInfo`.
    NowPlayingInfo {
        /// `params.type`, e.g. [`NOW_PLAYING_INFO_TEXT`].
        info_type: String,
        /// `params.params`: the metadata itself (empty in the capture).
        info: plist::Dictionary,
        /// `params.mergePolicy`, e.g. [`MERGE_POLICY_REPLACE`].
        merge_policy: Option<String>,
    },
    /// `updateMRPlaybackState`.
    PlaybackState(PlaybackState),
    /// `updateMRSupportedCommands`. An entry that is not a readable nested plist is skipped.
    SupportedCommands(Vec<CommandInfo>),
    /// `updateMRNowPlayingClient`, decoded.
    NowPlayingClient(NowPlayingClient),
}

impl MrCommand {
    /// The `type` string.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::NowPlayingInfo { .. } => UPDATE_NOW_PLAYING_INFO,
            Self::PlaybackState(_) => UPDATE_PLAYBACK_STATE,
            Self::SupportedCommands(_) => UPDATE_SUPPORTED_COMMANDS,
            Self::NowPlayingClient(_) => UPDATE_NOW_PLAYING_CLIENT,
        }
    }

    /// The iPhone's opening now-playing-info push: text, empty, replace.
    #[must_use]
    pub fn empty_text_info() -> Self {
        Self::NowPlayingInfo {
            info_type: NOW_PLAYING_INFO_TEXT.to_owned(),
            info: plist::Dictionary::new(),
            merge_policy: Some(MERGE_POLICY_REPLACE.to_owned()),
        }
    }

    /// The body as a value: `{"type": …, "params": {…}}`.
    pub fn to_value(&self) -> Result<Value> {
        let mut params = plist::Dictionary::new();
        match self {
            Self::NowPlayingInfo {
                info_type,
                info,
                merge_policy,
            } => {
                params.insert("type".into(), Value::String(info_type.clone()));
                params.insert("params".into(), Value::Dictionary(info.clone()));
                if let Some(policy) = merge_policy {
                    params.insert("mergePolicy".into(), Value::String(policy.clone()));
                }
            }
            Self::PlaybackState(state) => {
                params.insert(
                    KEY_PLAYBACK_STATE.into(),
                    Value::Integer(state.code().into()),
                );
            }
            Self::SupportedCommands(commands) => {
                let entries = commands
                    .iter()
                    .map(|c| c.to_nested_plist().map(Value::Data))
                    .collect::<Result<Vec<_>>>()?;
                params.insert(KEY_SUPPORTED_COMMANDS.into(), Value::Array(entries));
            }
            Self::NowPlayingClient(client) => {
                params.insert(KEY_NOW_PLAYING_CLIENT.into(), Value::Data(client.encode()));
            }
        }
        let mut body = plist::Dictionary::new();
        body.insert("type".into(), Value::String(self.type_name().to_owned()));
        body.insert("params".into(), Value::Dictionary(params));
        Ok(Value::Dictionary(body))
    }

    /// The serialised body (binary plist).
    pub fn body(&self) -> Result<Vec<u8>> {
        encode(&self.to_value()?, self.type_name())
    }

    /// `POST /command RTSP/1.0` with this body - how the iPhone sends it on its control connection.
    pub fn request(&self) -> Result<crate::rtsp::Request> {
        let mut request =
            crate::rtsp::Request::new("POST", PATH, crate::rtsp::Protocol::Rtsp, self.body()?);
        request
            .headers
            .set("Content-Type", crate::session::PLIST_CONTENT_TYPE);
        Ok(request)
    }

    /// Reads a push from its already-decoded dictionary. `None` for a `type` this module does not
    /// model, or a known `type` whose `params` lack the key that makes it that message.
    #[must_use]
    pub fn from_dictionary(dict: &plist::Dictionary) -> Option<Self> {
        let kind = dict.get("type").and_then(Value::as_string)?;
        let params = dict.get("params").and_then(Value::as_dictionary)?;
        match kind {
            UPDATE_NOW_PLAYING_INFO => Some(Self::NowPlayingInfo {
                info_type: params.get("type").and_then(Value::as_string)?.to_owned(),
                info: params
                    .get("params")
                    .and_then(Value::as_dictionary)
                    .cloned()
                    .unwrap_or_default(),
                merge_policy: params
                    .get("mergePolicy")
                    .and_then(Value::as_string)
                    .map(str::to_owned),
            }),
            UPDATE_PLAYBACK_STATE => Some(Self::PlaybackState(PlaybackState::from_code(
                params.get(KEY_PLAYBACK_STATE).and_then(unsigned)?,
            ))),
            UPDATE_SUPPORTED_COMMANDS => Some(Self::SupportedCommands(
                params
                    .get(KEY_SUPPORTED_COMMANDS)
                    .and_then(Value::as_array)?
                    .iter()
                    .filter_map(Value::as_data)
                    .filter_map(CommandInfo::from_nested_plist)
                    .collect(),
            )),
            UPDATE_NOW_PLAYING_CLIENT => Some(Self::NowPlayingClient(
                NowPlayingClient::decode(
                    params
                        .get(KEY_NOW_PLAYING_CLIENT)
                        .and_then(Value::as_data)?,
                )
                .ok()?,
            )),
            _ => None,
        }
    }

    /// Reads a push from its body bytes. An error for a body that is not a plist dictionary;
    /// `Ok(None)` as in [`Self::from_dictionary`].
    pub fn parse(body: &[u8]) -> Result<Option<Self>> {
        let value = crate::safe_plist::parse(body, "/command body is not a plist")?;
        let dict = value.as_dictionary().ok_or_else(|| {
            AirPlayError::Protocol("/command body is not a dictionary".to_owned())
        })?;
        Ok(Self::from_dictionary(dict))
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    value.as_unsigned_integer().or_else(|| {
        value
            .as_signed_integer()
            .and_then(|v| u64::try_from(v).ok())
    })
}

fn encode(value: &Value, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value)
        .map_err(|e| AirPlayError::Protocol(format!("could not encode the {what} body: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_round_trips() {
        let cases = [
            MrCommand::empty_text_info(),
            MrCommand::PlaybackState(PlaybackState::Stopped),
            MrCommand::PlaybackState(PlaybackState::Other(99)),
            MrCommand::SupportedCommands(vec![]),
            MrCommand::SupportedCommands(vec![
                CommandInfo::enabled(commands::PLAY),
                CommandInfo::with_skip_intervals(commands::SKIP_FORWARD, &[15.0]),
            ]),
            MrCommand::NowPlayingClient(NowPlayingClient::new(379, "com.apple.airplayd")),
        ];
        for command in cases {
            let parsed = MrCommand::parse(&command.body().unwrap()).unwrap();
            assert_eq!(parsed.as_ref(), Some(&command), "{}", command.type_name());
        }
    }

    #[test]
    fn a_negative_process_id_encodes_as_ten_bytes_and_decodes_back() {
        let client = NowPlayingClient {
            process_identifier: Some(-1),
            ..NowPlayingClient::default()
        };
        let bytes = client.encode();
        assert_eq!(bytes.len(), 11);
        assert_eq!(NowPlayingClient::decode(&bytes).unwrap(), client);
    }

    #[test]
    fn malformed_protobufs_are_errors() {
        for bytes in [
            &[0x12, 0x05, b'a'][..],
            &[0x80][..],
            &[0x0B][..],
            &[0x09, 1, 2][..],
        ] {
            assert!(NowPlayingClient::decode(bytes).is_err(), "{bytes:02x?}");
        }
    }

    #[test]
    fn an_unmodelled_type_is_none_not_an_error() {
        let mut dict = plist::Dictionary::new();
        dict.insert("type".into(), Value::String("updateInfo".into()));
        dict.insert("params".into(), Value::Dictionary(plist::Dictionary::new()));
        assert_eq!(MrCommand::from_dictionary(&dict), None);
        assert!(MrCommand::parse(b"not a plist").is_err());
    }
}
