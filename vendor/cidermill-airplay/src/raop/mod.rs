//! AirPlay 1 (RAOP) audio: the SDP an `ANNOUNCE` carries, the `Transport` header of a `SETUP` and
//! its reply, the requests a sender sends, the RTP packets, and the `et` set a `_raop._tcp` record
//! advertises. In the clear (`et` 0) both ways; a sender can also send `et` 1 with the `raop-rsa`
//! feature (the `rsa` module), and a receiver takes `et` 0 only. Sans-io; nothing here opens a
//! socket.
//!
//! ```text
//!   OPTIONS *                                   (optional; answers the methods)
//!   ANNOUNCE  rtsp://<local>/<id>   application/sdp   m=audio 0 RTP/AVP 96
//!                                                     a=rtpmap:96 AppleLossless
//!                                                     a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100
//!   SETUP     Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=C;timing_port=T
//!        <--  Transport: ...;server_port=S;control_port=C';timing_port=T'   Session: <id>
//!   RECORD    Range: npt=0-   RTP-Info: seq=N;rtptime=R
//!   FLUSH     RTP-Info: seq=N;rtptime=R
//!   SET_PARAMETER  text/parameters  "volume: -20.000000"
//!   ... audio: 12-byte RTP header + one ALAC frame, in the clear, UDP to S
//!       sync:  0x90/0x80 0xD4 to C' about once a second ([`crate::audio::rtp::SyncPacket`])
//!       timing: the receiver asks our port T the time ([`crate::timing::TimingPacket`])
//!       retransmit: 0xD5 requests from C', answered 0xD6 ([`crate::audio::rtp::retransmit_reply`])
//!   TEARDOWN
//! ```
//!
//! The sync, timing and retransmit packets are AirPlay 2's realtime ones byte for byte; only the
//! control exchange and the missing seal differ. With the `raop-rsa` feature a sender can also send
//! `et` 1 (the `rsa` module: an AES key wrapped with the AirPort Express **public** key, AES-CBC
//! audio); a receiver never takes it (that would need the private key). 3 and 5 (FairPlay) and 4 (MFi-SAP)
//! are not implemented: [`parse_announce`] marks an SDP that carries a wrapped key as encrypted.
//!
//! Wire shape from pyatv 0.18.0's `support/rtsp.py` and `protocols/raop` (MIT), read for behaviour.

use std::net::IpAddr;

#[cfg(feature = "raop-rsa")]
pub mod rsa;

use crate::audio::alac::AlacConfig;
use crate::audio::format::{audio_format, compression, ALAC_FRAMES_PER_PACKET};
use crate::audio::rtp::{OpenedPacket, HEADER_LEN};
use crate::client::SenderConnection;
use crate::error::{AirPlayError, Result};
use crate::receiver::AudioStreamFormat;
use crate::rtsp::{Protocol, Request, Response};
use crate::time::RtpTimestamp;

/// `Content-Type` of an `ANNOUNCE` body.
pub const SDP_CONTENT_TYPE: &str = "application/sdp";

/// The dynamic RTP payload type the SDP names (96).
pub const PAYLOAD_TYPE: u8 = 96;

/// The largest `ANNOUNCE` body [`parse_announce`] reads.
pub const MAX_SDP_BYTES: usize = 8192;

/// The `Transport` a sender's `SETUP` opens with, before its two ports.
pub const TRANSPORT_REQUEST: &str = "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record";

/// The `Transport` a receiver's reply opens with, before its ports.
pub const TRANSPORT_REPLY: &str = "RTP/AVP/UDP;unicast;mode=record";

/// The `Session` a receiver of this crate answers a `SETUP` with.
pub const RECEIVER_SESSION: &str = "1";

/// `Audio-Jack-Status` in a receiver's `SETUP` reply: what an AirPort Express says.
pub const AUDIO_JACK_STATUS: &str = "connected; type=analog";

/// The set of `et` values a `_raop._tcp` record lists: bit `n` for `et` `n` (0 to 31).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EncryptionTypes(u32);

impl EncryptionTypes {
    /// `et` 0: audio in the clear.
    pub const UNENCRYPTED: u8 = 0;
    /// `et` 1: an AES key wrapped with RSA (the key AirPort Express holds).
    pub const RSA: u8 = 1;
    /// `et` 3: FairPlay.
    pub const FAIRPLAY: u8 = 3;
    /// `et` 4: MFi-SAP.
    pub const MFI_SAP: u8 = 4;
    /// `et` 5: FairPlay SAP v2.5.
    pub const FAIRPLAY_SAP_25: u8 = 5;

    /// Reads an `et` value: comma-separated decimal numbers, as `0,1,3`. A number this type cannot
    /// hold (32 or more) or a token that is not a number is skipped; an empty or absent value is
    /// the empty set.
    #[must_use]
    pub fn parse(txt: &str) -> Self {
        let mut bits = 0u32;
        for token in txt.split(',') {
            if let Ok(n) = token.trim().parse::<u8>() {
                if n < 32 {
                    bits |= 1 << n;
                }
            }
        }
        Self(bits)
    }

    /// The set from its bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Bit `n` set for `et` `n`.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `et` lists `value`.
    #[must_use]
    pub const fn contains(self, value: u8) -> bool {
        value < 32 && self.0 & (1 << value) != 0
    }

    /// Whether the receiver takes audio in the clear (`et` lists 0). A sender prefers it; `et` 1
    /// needs the `raop-rsa` feature.
    #[must_use]
    pub const fn allows_unencrypted(self) -> bool {
        self.contains(Self::UNENCRYPTED)
    }

    /// Whether no value was listed.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The codec an SDP names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RaopCodec {
    /// `AppleLossless`: one ALAC frame per packet, shaped by the `fmtp` line.
    Alac,
    /// `L16`: big-endian 16-bit PCM.
    Pcm,
}

/// What an `ANNOUNCE` said about the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Announce {
    /// The codec.
    pub codec: RaopCodec,
    /// Frames per second.
    pub sample_rate: u32,
    /// Channels.
    pub channels: u8,
    /// Bits per sample.
    pub bits_per_sample: u8,
    /// Frames per packet (the `fmtp` frame length; [`ALAC_FRAMES_PER_PACKET`] when absent).
    pub frames_per_packet: u32,
    /// The SDP carries a wrapped key (`rsaaeskey`, `fpaeskey`, `aesiv`): its audio is encrypted.
    pub encrypted: bool,
}

impl Announce {
    /// The receiver's stream format for this announcement: the realtime `ct` and `audioFormat`
    /// numbers AirPlay 2 uses for the same shape, with depth and channels from the SDP.
    #[must_use]
    pub fn stream_format(&self) -> AudioStreamFormat {
        let (ct, bit) = match (self.codec, self.sample_rate, self.bits_per_sample) {
            (RaopCodec::Alac, 44_100, 24) => (compression::ALAC, audio_format::ALAC_44100_24_2),
            (RaopCodec::Alac, 48_000, 16) => (compression::ALAC, audio_format::ALAC_48000_16_2),
            (RaopCodec::Alac, 48_000, 24) => (compression::ALAC, audio_format::ALAC_48000_24_2),
            (RaopCodec::Alac, _, _) => (compression::ALAC, audio_format::ALAC_44100_16_2),
            (RaopCodec::Pcm, _, _) => (compression::LPCM, audio_format::PCM_44100_16_2),
        };
        let mut format = AudioStreamFormat::new(ct, bit, self.sample_rate, self.frames_per_packet);
        format.bits_per_sample = self.bits_per_sample;
        format.channels = self.channels;
        format
    }
}

/// The `ANNOUNCE` body for an ALAC stream shaped by `alac`: session `session_id`, from `local` to
/// `remote` — pyatv's lines, with `AppleLossless` where pyatv says `L16`.
#[must_use]
pub fn announce_body(session_id: u32, local: IpAddr, remote: IpAddr, alac: &AlacConfig) -> String {
    announce_body_with(session_id, local, remote, alac, "")
}

/// [`announce_body`] with `key_lines` appended (`a=rsaaeskey:…` and `a=aesiv:…`, each ending
/// CRLF, as `rsa::RaopAesKey::sdp_lines` writes them) — OwnTone's order.
#[must_use]
pub fn announce_body_with(
    session_id: u32,
    local: IpAddr,
    remote: IpAddr,
    alac: &AlacConfig,
    key_lines: &str,
) -> String {
    let family = |ip: IpAddr| if ip.is_ipv4() { "IP4" } else { "IP6" };
    format!(
        "v=0\r\no=iTunes {session_id} 0 IN {} {local}\r\ns=iTunes\r\nc=IN {} {remote}\r\nt=0 0\r\n\
         m=audio 0 RTP/AVP {PAYLOAD_TYPE}\r\na=rtpmap:{PAYLOAD_TYPE} AppleLossless\r\n{}\r\n{key_lines}",
        family(local),
        family(remote),
        alac.fmtp(PAYLOAD_TYPE)
    )
}

/// Reads an `ANNOUNCE` body: the first `m=audio` line's payload type, its `rtpmap` and `fmtp`, and
/// whether a key is wrapped in it. Never panics.
///
/// # Errors
///
/// A body over [`MAX_SDP_BYTES`] or not UTF-8; no `m=audio` line; a codec other than
/// `AppleLossless` and `L16`; an ALAC stream with no `fmtp`, or numbers out of their range.
pub fn parse_announce(body: &[u8]) -> Result<Announce> {
    if body.len() > MAX_SDP_BYTES {
        return Err(sdp_error("the SDP is too long"));
    }
    let text = std::str::from_utf8(body).map_err(|_| sdp_error("the SDP is not UTF-8"))?;
    let mut payload: Option<&str> = None;
    let mut rtpmap: Option<&str> = None;
    let mut fmtp: Option<&str> = None;
    let mut encrypted = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(media) = line.strip_prefix("m=audio ") {
            if payload.is_none() {
                payload = media.split_whitespace().nth(2);
            }
        } else if let Some(attribute) = line.strip_prefix("a=") {
            let (name, value) = attribute.split_once(':').unwrap_or((attribute, ""));
            match name {
                "rtpmap" => rtpmap = rtpmap.or(Some(value)),
                "fmtp" => fmtp = fmtp.or(Some(value)),
                "rsaaeskey" | "fpaeskey" | "aesiv" => encrypted = true,
                _ => {}
            }
        }
    }
    let payload = payload.ok_or_else(|| sdp_error("no m=audio line"))?;
    // The attribute lines name the payload type first: `96 AppleLossless`.
    fn for_payload<'a>(value: Option<&'a str>, payload: &str) -> Option<&'a str> {
        let (pt, rest) = value?.split_once(' ')?;
        (pt == payload).then_some(rest.trim())
    }
    let rtpmap =
        for_payload(rtpmap, payload).ok_or_else(|| sdp_error("no rtpmap for the audio"))?;
    let mut parts = rtpmap.split('/');
    let codec = match parts.next().unwrap_or("") {
        "AppleLossless" => RaopCodec::Alac,
        "L16" => RaopCodec::Pcm,
        _ => return Err(sdp_error("the codec is neither AppleLossless nor L16")),
    };
    let rate_from_map = parts.next().and_then(|r| r.parse::<u32>().ok());
    let channels_from_map = parts.next().and_then(|c| c.parse::<u8>().ok());
    let numbers: Vec<u32> = for_payload(fmtp, payload)
        .map(|v| {
            v.split_whitespace()
                .map_while(|n| n.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default();
    // The eleven ALAC fields: frameLength, compatibleVersion, bitDepth, pb, mb, kb, numChannels,
    // maxRun, maxFrameBytes, avgBitRate, sampleRate.
    let announce = if numbers.len() >= 11 {
        Announce {
            codec,
            frames_per_packet: numbers[0],
            bits_per_sample: u8::try_from(numbers[2]).unwrap_or(0),
            channels: u8::try_from(numbers[6]).unwrap_or(0),
            sample_rate: numbers[10],
            encrypted,
        }
    } else if codec == RaopCodec::Pcm {
        Announce {
            codec,
            frames_per_packet: ALAC_FRAMES_PER_PACKET,
            bits_per_sample: 16,
            channels: channels_from_map.unwrap_or(2),
            sample_rate: rate_from_map.unwrap_or(44_100),
            encrypted,
        }
    } else {
        return Err(sdp_error("an ALAC stream needs its eleven fmtp fields"));
    };
    if announce.frames_per_packet == 0
        || announce.channels == 0
        || announce.sample_rate == 0
        || !matches!(announce.bits_per_sample, 16 | 24)
    {
        return Err(sdp_error("the stream's shape is out of range"));
    }
    Ok(announce)
}

fn sdp_error(why: &str) -> AirPlayError {
    AirPlayError::Protocol(format!("ANNOUNCE: {why}"))
}

/// The ports a `Transport` header names. Any may be missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transport {
    /// `server_port`: the receiver's audio data port (in a reply).
    pub server_port: Option<u16>,
    /// `control_port`: the sender's (request) or the receiver's (reply) control port.
    pub control_port: Option<u16>,
    /// `timing_port`: the sender's (request) or the receiver's (reply) timing port.
    pub timing_port: Option<u16>,
}

impl Transport {
    /// Reads the ports out of a `Transport` value (`key=value` options split by `;`). An option
    /// that is not a port number is ignored. Never panics.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        let mut out = Self::default();
        for option in value.split(';') {
            let Some((key, port)) = option.split_once('=') else {
                continue;
            };
            let port = port.trim().parse::<u16>().ok();
            match key.trim() {
                "server_port" => out.server_port = port,
                "control_port" => out.control_port = port,
                "timing_port" => out.timing_port = port,
                _ => {}
            }
        }
        out
    }

    /// A sender's `Transport`: its control and timing ports.
    #[must_use]
    pub fn request(control_port: u16, timing_port: u16) -> String {
        format!("{TRANSPORT_REQUEST};control_port={control_port};timing_port={timing_port}")
    }

    /// A receiver's reply `Transport`: its data and control ports, and its timing port when it
    /// has one of its own.
    #[must_use]
    pub fn reply(server_port: u16, control_port: u16, timing_port: Option<u16>) -> String {
        let mut out =
            format!("{TRANSPORT_REPLY};server_port={server_port};control_port={control_port}");
        if let Some(timing) = timing_port {
            out.push_str(&format!(";timing_port={timing}"));
        }
        out
    }
}

/// What a sender needs from a receiver's `SETUP` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetupReply {
    /// Where audio goes (UDP).
    pub server_port: u16,
    /// Where sync packets go, and retransmit requests come from (UDP).
    pub control_port: u16,
    /// The receiver's timing port, when it named one.
    pub timing_port: Option<u16>,
    /// `Session`, sent back on every later request (`1` when the reply had none).
    pub session: String,
}

impl SetupReply {
    /// Reads a `SETUP` reply.
    ///
    /// # Errors
    ///
    /// A status other than 2xx, or a `Transport` without `server_port` or `control_port`.
    pub fn parse(response: &Response) -> Result<Self> {
        if !response.is_success() {
            return Err(AirPlayError::Protocol(format!(
                "SETUP was answered {} {}",
                response.status, response.reason
            )));
        }
        let transport = Transport::parse(response.headers.get("Transport").unwrap_or(""));
        let (Some(server_port), Some(control_port)) =
            (transport.server_port, transport.control_port)
        else {
            return Err(AirPlayError::Protocol(
                "the SETUP reply's Transport names no server_port or control_port".to_owned(),
            ));
        };
        let session = response
            .headers
            .get("Session")
            .map(|s| s.split(';').next().unwrap_or("").trim())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()))
            .unwrap_or(RECEIVER_SESSION)
            .to_owned();
        Ok(Self {
            server_port,
            control_port,
            timing_port: transport.timing_port,
            session,
        })
    }
}

/// An audio packet in the clear: the header, then the payload.
#[must_use]
pub fn clear_packet(header: &[u8; HEADER_LEN], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(payload);
    packet
}

/// Splits a clear audio packet into its header and payload. `nonce` in the result is 0.
///
/// # Security
///
/// Nothing authenticates the packet: anyone who can reach the data port can inject one. A host
/// pins the port to the sender's address.
///
/// # Errors
///
/// A packet shorter than its header.
pub fn open_clear_packet(packet: &[u8]) -> Result<OpenedPacket> {
    let Some((header, payload)) = packet.split_first_chunk::<HEADER_LEN>() else {
        return Err(AirPlayError::Protocol(format!(
            "an audio packet needs {HEADER_LEN} header bytes, got {}",
            packet.len()
        )));
    };
    Ok(OpenedPacket {
        header: *header,
        payload: payload.to_vec(),
        nonce: 0,
    })
}

/// The requests an AirPlay 1 sender sends, over a [`SenderConnection`] (which stamps `CSeq`,
/// `User-Agent` and the rest at encode).
#[derive(Debug, Clone)]
pub struct RaopRequests {
    uri: String,
    session: Option<String>,
}

impl RaopRequests {
    /// The requests of a session on `connection`, whose URI is
    /// [`SenderConnection::session_uri`].
    #[must_use]
    pub fn new(connection: &SenderConnection) -> Self {
        Self {
            uri: connection.session_uri(),
            session: None,
        }
    }

    /// The session URI every request but `OPTIONS` names.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Remembers the `Session` a `SETUP` reply gave, for every later request.
    pub fn set_session(&mut self, session: impl Into<String>) {
        self.session = Some(session.into());
    }

    fn request(&self, connection: &SenderConnection, method: &str, body: Vec<u8>) -> Request {
        let mut request = connection.with_session_headers(Request::new(
            method,
            self.uri.clone(),
            Protocol::Rtsp,
            body,
        ));
        if let Some(session) = &self.session {
            request.headers.set("Session", session.clone());
        }
        request
    }

    /// `OPTIONS *`.
    #[must_use]
    pub fn options(&self, connection: &SenderConnection) -> Request {
        connection.with_session_headers(Request::new("OPTIONS", "*", Protocol::Rtsp, Vec::new()))
    }

    /// `ANNOUNCE` of an ALAC stream shaped by `alac`, to `remote`.
    #[must_use]
    pub fn announce(
        &self,
        connection: &SenderConnection,
        remote: IpAddr,
        alac: &AlacConfig,
    ) -> Request {
        let body = announce_body(
            connection.rtsp_session_id(),
            connection.local_ip(),
            remote,
            alac,
        );
        let mut request = self.request(connection, "ANNOUNCE", body.into_bytes());
        request.headers.set("Content-Type", SDP_CONTENT_TYPE);
        request
    }

    /// `ANNOUNCE` of an ALAC stream encrypted with `key` (`et` 1): its SDP carries the key wrapped
    /// under `public` and the IV.
    ///
    /// # Errors
    ///
    /// The key does not wrap under `public` ([`rsa::RaopAesKey::sdp_lines`]).
    #[cfg(feature = "raop-rsa")]
    pub fn announce_encrypted(
        &self,
        connection: &SenderConnection,
        remote: IpAddr,
        alac: &AlacConfig,
        key: &rsa::RaopAesKey,
        public: &rsa::RsaPublicKey,
        rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<Request> {
        let lines = key.sdp_lines(public, rng)?;
        let body = announce_body_with(
            connection.rtsp_session_id(),
            connection.local_ip(),
            remote,
            alac,
            &lines,
        );
        let mut request = self.request(connection, "ANNOUNCE", body.into_bytes());
        request.headers.set("Content-Type", SDP_CONTENT_TYPE);
        Ok(request)
    }

    /// `SETUP` naming our control and timing ports.
    #[must_use]
    pub fn setup(
        &self,
        connection: &SenderConnection,
        control_port: u16,
        timing_port: u16,
    ) -> Request {
        let mut request = self.request(connection, "SETUP", Vec::new());
        request
            .headers
            .set("Transport", Transport::request(control_port, timing_port));
        request
    }

    /// `RECORD` from sequence `sequence` at `rtp_time`.
    #[must_use]
    pub fn record(
        &self,
        connection: &SenderConnection,
        sequence: u16,
        rtp_time: RtpTimestamp,
    ) -> Request {
        let mut request = self.request(connection, "RECORD", Vec::new());
        request.headers.set("Range", "npt=0-");
        request.headers.set(
            "RTP-Info",
            crate::audio::control::rtp_info(u32::from(sequence), rtp_time),
        );
        request
    }

    /// `FLUSH`: the stream (re)starts at `sequence` and `rtp_time`.
    #[must_use]
    pub fn flush(
        &self,
        connection: &SenderConnection,
        sequence: u16,
        rtp_time: RtpTimestamp,
    ) -> Request {
        let mut request = self.request(connection, "FLUSH", Vec::new());
        request.headers.set(
            "RTP-Info",
            crate::audio::control::rtp_info(u32::from(sequence), rtp_time),
        );
        request
    }

    /// `SET_PARAMETER` `volume: <dB>`, clamped to 0 (loudest) to -144 (mute).
    #[must_use]
    pub fn volume(&self, connection: &SenderConnection, db: f64) -> Request {
        let db = if db.is_finite() {
            db.clamp(-144.0, 0.0)
        } else {
            -144.0
        };
        let mut request = self.request(
            connection,
            "SET_PARAMETER",
            format!("volume: {db:.6}\r\n").into_bytes(),
        );
        request
            .headers
            .set("Content-Type", crate::session::TEXT_PARAMETERS_CONTENT_TYPE);
        request
    }

    /// [`Self::set_parameter`] with `RTP-Info: rtptime=` naming the frame the metadata belongs to,
    /// as pyatv sends DMAP metadata and artwork.
    #[must_use]
    pub fn set_parameter_at(
        &self,
        connection: &SenderConnection,
        content_type: &str,
        body: Vec<u8>,
        rtp_time: RtpTimestamp,
    ) -> Request {
        let mut request = self.set_parameter(connection, content_type, body);
        request
            .headers
            .set("RTP-Info", format!("rtptime={}", rtp_time.get()));
        request
    }

    /// `SET_PARAMETER` with a body of `content_type` (DMAP metadata, artwork, `progress`).
    #[must_use]
    pub fn set_parameter(
        &self,
        connection: &SenderConnection,
        content_type: &str,
        body: Vec<u8>,
    ) -> Request {
        let mut request = self.request(connection, "SET_PARAMETER", body);
        request.headers.set("Content-Type", content_type);
        request
    }

    /// `TEARDOWN`.
    #[must_use]
    pub fn teardown(&self, connection: &SenderConnection) -> Request {
        self.request(connection, "TEARDOWN", Vec::new())
    }
}
