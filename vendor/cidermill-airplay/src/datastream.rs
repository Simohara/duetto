//! The MediaRemote data channel of an AirPlay 2 remote-control session, sans-io: the stream
//! `SETUP` that asks for it (`type: 130`), the reply's `dataPort`, the channel's keys and framing.
//!
//! After a remote-control session `SETUP` (see [`crate::session::SetupParams::ios_remote_control`])
//! and `RECORD`, the sender asks for this stream, connects to the returned `dataPort`, and
//! exchanges MediaRemote protobuf messages over HAP framing ([`crate::cipher::EncryptedTransport`])
//! under keys derived from the session's shared secret (HKDF-SHA512; no FairPlay involved).
//!
//! Request, keys and framing pinned against pyatv 0.18.0 (`tools/mediaremote-vectors`) and an
//! iPhone (iOS 26.7). No receiver has answered one from this crate.
//!
//! The seed's sign: pyatv draws a non-negative seed; the iPhone sent negative 64-bit seeds. Assumed
//! that a receiver formats the seed as signed decimal. [`DataStreamSetup::dedicated`] takes an
//! `i64` so what is sent and what is hashed agree.

use plist::Value;

use crate::error::{AirPlayError, Result};
use crate::pairing::{hkdf_key, SessionKeys};

/// `type` of the MediaRemote data stream.
pub const STREAM_TYPE: u64 = 130;

/// `controlType` of the dedicated-socket data stream (the remote-control session's).
pub const CONTROL_TYPE_DEDICATED: u64 = 2;

/// `controlType` the iPhone's **media** session asked for, with no seed and no dedicated socket.
/// OBSERVED once; what it controls is unknown.
pub const CONTROL_TYPE_MEDIA_SESSION: u64 = 1;

/// `clientTypeUUID` of the MediaRemote client. The iPhone and pyatv 0.18.0 send the same value.
pub const MEDIAREMOTE_CLIENT_TYPE_UUID: &str = "1910A70F-DBC0-4242-AF95-115DB30604E1";

/// `clientTypeUUID` of the iPhone's media-session `controlType: 1` stream. OBSERVED once; nothing
/// names it.
pub const MEDIA_SESSION_CLIENT_TYPE_UUID: &str = "A6B27562-B43A-4F2D-B75F-82391E250194";

/// The suffix of the media-session stream's `channelID`: `<receiver deviceID>-RCS-<n>`. OBSERVED
/// once, with `n` = 23.
pub const MEDIA_SESSION_CHANNEL_INFIX: &str = "-RCS-";

/// HKDF salt prefix; the seed follows in decimal.
pub const SALT_PREFIX: &str = "DataStream-Salt";

/// HKDF info for the key the **client** (the sender) encrypts with.
pub const OUTPUT_INFO: &str = "DataStream-Output-Encryption-Key";

/// HKDF info for the key the client decrypts with.
pub const INPUT_INFO: &str = "DataStream-Input-Encryption-Key";

/// Length of a frame header.
pub const HEADER_LEN: usize = 32;

/// The largest frame the decoder buffers; a larger declared size is treated as garbage.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Message type of a request: `sync` and eight zero bytes.
pub const MESSAGE_TYPE_SYNC: [u8; 12] = *b"sync\0\0\0\0\0\0\0\0";

/// Message type of a reply: `rply` and eight zero bytes.
pub const MESSAGE_TYPE_REPLY: [u8; 12] = *b"rply\0\0\0\0\0\0\0\0";

/// Command of a request carrying messages.
pub const COMMAND_COMM: [u8; 4] = *b"comm";

/// The data stream `SETUP` a sender sends.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataStreamSetup {
    /// `controlType`.
    pub control_type: u64,
    /// `channelID`: opaque. pyatv sends an upper-case UUID; the iPhone sent a UUID or a
    /// four-character code.
    pub channel_id: String,
    /// `seed`: salts the channel's keys. `None` writes no seed.
    pub seed: Option<i64>,
    /// `clientUUID`: an upper-case UUID naming this client.
    pub client_uuid: String,
    /// `clientTypeUUID`.
    pub client_type_uuid: String,
    /// `wantsDedicatedSocket`, written when set.
    pub wants_dedicated_socket: Option<bool>,
}

impl DataStreamSetup {
    /// The remote-control session's stream: `controlType` 2, a seed, the MediaRemote client type,
    /// `wantsDedicatedSocket: true` - the iPhone's and pyatv's key set exactly.
    #[must_use]
    pub fn dedicated(channel_id: String, seed: i64, client_uuid: String) -> Self {
        Self {
            control_type: CONTROL_TYPE_DEDICATED,
            channel_id,
            seed: Some(seed),
            client_uuid,
            client_type_uuid: MEDIAREMOTE_CLIENT_TYPE_UUID.to_owned(),
            wants_dedicated_socket: Some(true),
        }
    }

    /// The iPhone's media-session stream: `controlType` 1, `channelID` `<receiver_id>-RCS-<index>`,
    /// its own client type, no seed, no dedicated socket. OBSERVED once; nothing here knows what
    /// the receiver does with it.
    #[must_use]
    pub fn media_session(receiver_id: &str, index: u32, client_uuid: String) -> Self {
        Self {
            control_type: CONTROL_TYPE_MEDIA_SESSION,
            channel_id: format!("{receiver_id}{MEDIA_SESSION_CHANNEL_INFIX}{index}"),
            seed: None,
            client_uuid,
            client_type_uuid: MEDIA_SESSION_CLIENT_TYPE_UUID.to_owned(),
            wants_dedicated_socket: None,
        }
    }

    /// The `streams[0]` dictionary.
    #[must_use]
    pub fn stream_dictionary(&self) -> plist::Dictionary {
        let mut stream = plist::Dictionary::new();
        stream.insert(
            "controlType".into(),
            Value::Integer(self.control_type.into()),
        );
        stream.insert("channelID".into(), Value::String(self.channel_id.clone()));
        if let Some(seed) = self.seed {
            stream.insert("seed".into(), Value::Integer(seed.into()));
        }
        stream.insert("clientUUID".into(), Value::String(self.client_uuid.clone()));
        stream.insert("type".into(), Value::Integer(STREAM_TYPE.into()));
        if let Some(dedicated) = self.wants_dedicated_socket {
            stream.insert("wantsDedicatedSocket".into(), Value::Boolean(dedicated));
        }
        stream.insert(
            "clientTypeUUID".into(),
            Value::String(self.client_type_uuid.clone()),
        );
        stream
    }

    /// `{"streams": [ … ]}`.
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
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, &self.to_value()).map_err(|e| {
            AirPlayError::Protocol(format!("could not encode the data stream SETUP: {e}"))
        })?;
        Ok(out)
    }

    /// The keys for this stream's channel, if it has a seed ([`keys`]).
    pub fn keys(&self, session: &SessionKeys) -> Result<Option<([u8; 32], [u8; 32])>> {
        self.seed
            .map(|seed| keys(&session.shared_secret, seed))
            .transpose()
    }
}

/// The reply to a data stream `SETUP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataStreamSetupResponse {
    /// `streams[0].dataPort`: where the channel is. Required.
    pub data_port: u16,
    /// `streams[0].type`, when echoed.
    pub stream_type: Option<u64>,
    /// `streams[0].streamID`, when given.
    pub stream_id: Option<u64>,
}

impl DataStreamSetupResponse {
    /// Parses the reply body. Without a non-zero `dataPort` there is no channel, so that is an
    /// error.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "data stream SETUP reply is not a plist")?;
        let stream = value
            .as_dictionary()
            .and_then(|d| d.get("streams"))
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                AirPlayError::Protocol("data stream SETUP reply has no streams[0]".to_owned())
            })?;
        let unsigned = |key: &str| stream.get(key).and_then(Value::as_unsigned_integer);
        let data_port = unsigned("dataPort")
            .and_then(|p| u16::try_from(p).ok())
            .filter(|&p| p != 0)
            .ok_or_else(|| {
                AirPlayError::Protocol("data stream SETUP reply names no dataPort".to_owned())
            })?;
        Ok(Self {
            data_port,
            stream_type: unsigned("type"),
            stream_id: unsigned("streamID"),
        })
    }
}

/// The HKDF salt for a seed: `DataStream-Salt<seed>`.
#[must_use]
pub fn salt(seed: i64) -> String {
    format!("{SALT_PREFIX}{seed}")
}

/// The channel keys from the session's shared secret: `(write_key, read_key)` from the **sender's**
/// point of view. Not crossed: the sender opens this connection.
pub fn keys(shared_secret: &[u8], seed: i64) -> Result<([u8; 32], [u8; 32])> {
    let salt = salt(seed);
    Ok((
        hkdf_key(shared_secret, salt.as_bytes(), OUTPUT_INFO.as_bytes())?,
        hkdf_key(shared_secret, salt.as_bytes(), INPUT_INFO.as_bytes())?,
    ))
}

impl SessionKeys {
    /// The MediaRemote data channel's keys for `seed` ([`keys`]): `(write_key, read_key)`.
    pub fn data_stream_keys(&self, seed: i64) -> Result<([u8; 32], [u8; 32])> {
        keys(&self.shared_secret, seed)
    }
}

/// One data-channel frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataFrame {
    /// 12 bytes: [`MESSAGE_TYPE_SYNC`], [`MESSAGE_TYPE_REPLY`] or anything else a peer sends.
    pub message_type: [u8; 12],
    /// 4 bytes: [`COMMAND_COMM`] on a request, zeros on a reply.
    pub command: [u8; 4],
    /// The sequence number; a reply carries its request's.
    pub seqno: u64,
    /// The padding word; 0 on everything pyatv sends.
    pub padding: u32,
    /// The payload after the header.
    pub payload: Vec<u8>,
}

impl DataFrame {
    /// A `sync`/`comm` request carrying `payload` (usually [`wrap_messages`]'s output).
    #[must_use]
    pub fn request(seqno: u64, payload: Vec<u8>) -> Self {
        Self {
            message_type: MESSAGE_TYPE_SYNC,
            command: COMMAND_COMM,
            seqno,
            padding: 0,
            payload,
        }
    }

    /// The payload-less `rply` answering request `seqno`.
    #[must_use]
    pub fn reply(seqno: u64) -> Self {
        Self {
            message_type: MESSAGE_TYPE_REPLY,
            command: [0; 4],
            seqno,
            padding: 0,
            payload: Vec::new(),
        }
    }

    /// Whether this is a request that wants a reply (its type starts `sync`).
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.message_type.starts_with(b"sync")
    }

    /// Whether this is a reply (its type starts `rply`).
    #[must_use]
    pub fn is_reply(&self) -> bool {
        self.message_type.starts_with(b"rply")
    }

    /// The wire bytes, header then payload. Fails only for a payload too large to count in 32 bits.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let size = u32::try_from(HEADER_LEN + self.payload.len())
            .map_err(|_| AirPlayError::Protocol("data frame too large".to_owned()))?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&self.message_type);
        out.extend_from_slice(&self.command);
        out.extend_from_slice(&self.seqno.to_be_bytes());
        out.extend_from_slice(&self.padding.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// What [`DataFrameDecoder::next_frame`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedFrame {
    /// A whole frame.
    Frame(DataFrame),
    /// A header declared a size below [`HEADER_LEN`] or above [`MAX_FRAME_BYTES`]: nothing says
    /// where the next frame starts, so everything buffered was dropped.
    Dropped {
        /// How many bytes went.
        bytes: usize,
    },
}

/// Splits the channel's decrypted bytes into frames. Never panics, never grows past
/// [`MAX_FRAME_BYTES`] plus one read.
#[derive(Debug, Default)]
pub struct DataFrameDecoder {
    buffer: Vec<u8>,
}

impl DataFrameDecoder {
    /// An empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds decrypted bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes buffered and not yet framed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The next frame, a report of dropped bytes, or `None` when more bytes are needed.
    pub fn next_frame(&mut self) -> Option<DecodedFrame> {
        if self.buffer.len() < HEADER_LEN {
            return None;
        }
        let size = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        if !(HEADER_LEN..=MAX_FRAME_BYTES).contains(&size) {
            let bytes = self.buffer.len();
            self.buffer.clear();
            return Some(DecodedFrame::Dropped { bytes });
        }
        if self.buffer.len() < size {
            return None;
        }
        let raw: Vec<u8> = self.buffer.drain(..size).collect();
        let mut message_type = [0u8; 12];
        message_type.copy_from_slice(&raw[4..16]);
        let mut command = [0u8; 4];
        command.copy_from_slice(&raw[16..20]);
        let mut seqno = [0u8; 8];
        seqno.copy_from_slice(&raw[20..28]);
        let padding = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]);
        Some(DecodedFrame::Frame(DataFrame {
            message_type,
            command,
            seqno: u64::from_be_bytes(seqno),
            padding,
            payload: raw[HEADER_LEN..].to_vec(),
        }))
    }
}

/// A protobuf varint.
#[must_use]
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a protobuf varint: `(value, bytes consumed)`, or `None` when it is truncated or longer
/// than ten bytes.
#[must_use]
pub fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (index, &byte) in bytes.iter().enumerate().take(10) {
        let shift = 7 * index as u32;
        let part = u64::from(byte & 0x7F);
        if shift == 63 && part > 1 {
            return None;
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// Joins serialised protobuf messages the way a sender does: each prefixed by its varint length.
#[must_use]
pub fn join_messages<M: AsRef<[u8]>>(messages: &[M]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        let message = message.as_ref();
        out.extend_from_slice(&encode_varint(message.len() as u64));
        out.extend_from_slice(message);
    }
    out
}

/// Splits a `data` blob back into messages.
///
/// A message that begins with `0x08` (field 1, varint - the `type` every `ProtocolMessage` starts
/// with) is taken to be **unprefixed** and to run to the end, as pyatv's reader does: a length
/// prefix of 8 could never hold a whole message, and pyatv reports that one message (its
/// `ConfigureConnectionMessage`) arrives that way. A truncated length is an error.
pub fn split_messages(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest[0] == 0x08 {
            out.push(rest.to_vec());
            break;
        }
        let (length, used) = decode_varint(rest)
            .ok_or_else(|| AirPlayError::Protocol("bad message length varint".to_owned()))?;
        let body = &rest[used..];
        let length = usize::try_from(length)
            .ok()
            .filter(|&l| l <= body.len())
            .ok_or_else(|| {
                AirPlayError::Protocol(format!(
                    "message says {length} bytes, {} remain",
                    body.len()
                ))
            })?;
        out.push(body[..length].to_vec());
        rest = &body[length..];
    }
    Ok(out)
}

/// The payload of a request: `{"params": {"data": <join_messages(messages)>}}` as a binary plist.
pub fn wrap_messages<M: AsRef<[u8]>>(messages: &[M]) -> Result<Vec<u8>> {
    let mut params = plist::Dictionary::new();
    params.insert("data".into(), Value::Data(join_messages(messages)));
    let mut body = plist::Dictionary::new();
    body.insert("params".into(), Value::Dictionary(params));
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(body)).map_err(|e| {
        AirPlayError::Protocol(format!("could not encode the data frame payload: {e}"))
    })?;
    Ok(out)
}

/// The messages in a frame payload: `params.data`, split. `Ok(None)` for a readable plist without
/// `params.data` (pyatv logs and ignores those); an error for a payload that is not a plist.
pub fn unwrap_messages(payload: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
    let value = crate::safe_plist::parse(payload, "data frame payload is not a plist")?;
    let Some(data) = value
        .as_dictionary()
        .and_then(|d| d.get("params"))
        .and_then(Value::as_dictionary)
        .and_then(|p| p.get("data"))
        .and_then(Value::as_data)
    else {
        return Ok(None);
    };
    split_messages(data).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_the_edges() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, u64::MAX] {
            let bytes = encode_varint(value);
            assert_eq!(decode_varint(&bytes), Some((value, bytes.len())), "{value}");
        }
        assert_eq!(decode_varint(&[0x80]), None, "truncated");
        assert_eq!(decode_varint(&[0xFF; 11]), None, "too long");
        assert_eq!(
            decode_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]),
            None,
            "overflows 64 bits"
        );
    }

    #[test]
    fn a_frame_round_trips_through_the_decoder_in_pieces() {
        let frame = DataFrame::request(0x1_2345_6789, b"payload".to_vec());
        let bytes = frame.encode().unwrap();
        let mut decoder = DataFrameDecoder::new();
        for byte in &bytes[..bytes.len() - 1] {
            decoder.push(std::slice::from_ref(byte));
            assert_eq!(decoder.next_frame(), None);
        }
        decoder.push(&bytes[bytes.len() - 1..]);
        assert_eq!(decoder.next_frame(), Some(DecodedFrame::Frame(frame)));
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn an_impossible_size_drops_the_buffer_instead_of_waiting() {
        let mut decoder = DataFrameDecoder::new();
        let mut bytes = DataFrame::reply(1).encode().unwrap();
        bytes[0..4].copy_from_slice(&4u32.to_be_bytes());
        decoder.push(&bytes);
        assert_eq!(
            decoder.next_frame(),
            Some(DecodedFrame::Dropped { bytes: 32 })
        );
        decoder.push(&u32::MAX.to_be_bytes());
        decoder.push(&[0; 28]);
        assert_eq!(
            decoder.next_frame(),
            Some(DecodedFrame::Dropped { bytes: 32 })
        );
    }

    #[test]
    fn a_short_message_length_is_an_error_not_a_panic() {
        assert!(split_messages(&[0x05, 0x01]).is_err());
        assert!(split_messages(&[0x80]).is_err());
        assert_eq!(split_messages(&[]).unwrap(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn a_reply_needs_a_data_port() {
        let setup = DataStreamSetup::dedicated("C".into(), 1, "U".into());
        // A request body is not a reply: it has streams[0] but no dataPort.
        assert!(DataStreamSetupResponse::parse(&setup.body().unwrap()).is_err());
        assert!(DataStreamSetupResponse::parse(b"junk").is_err());
    }
}
