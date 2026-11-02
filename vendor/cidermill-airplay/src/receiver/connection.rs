//! One control connection of a receiver, sans-io: bytes in, bytes out, events for the host.
//!
//! [`ReceiverConnection`] is the server-side twin of [`crate::client::ControlChannel`] minus the
//! socket. It answers RTSP/HTTP requests, switches to ChaCha20-Poly1305 framing after the pairing
//! reply that earned keys, and reports what a host must act on as a [`ReceiverEvent`]. Ports come
//! from the host's [`PortAllocator`]; nothing here binds.
//!
//! - `GET /info`, the pairing routes ([`super::pairing`]), session and stream `SETUP`
//!   (types 96, 103, 110, 130), `SET_PARAMETER`, `RECORD`, `FLUSH`, `TEARDOWN` and the URL routes
//!   are answered here; the buffered, mirror and URL routes follow [`ReceiverSwitches`].
//! - A request [`ReceiverConfig::extension`] claims is relayed to it, before the encryption gate.
//! - `/fp-setup`, `/fp-setup2` and `/auth-setup` unclaimed get a bodiless **404**: this crate
//!   answers no sender-authentication scheme itself.
//! - Anything needing a session key is refused **470** until pairing has encrypted the connection.
//! - Before pairing, bodies are capped at [`crate::rtsp::PRE_AUTH_MAX_BODY_BYTES`] and every PIN
//!   tried goes through the receiver-wide [`super::pin::PinGate`]; a refused `/pair-pin-start` is
//!   a **503** with HAP's error TLV8. Failed PINs are counted per source
//!   ([`ReceiverConnection::set_peer_ip`]), with a receiver-wide net behind them. Connection limits and idle timeouts belong to the host; per
//!   connection this type keeps one live session and at most one open stream of each type (a
//!   repeat `SETUP` replaces the earlier one), bounds the `SETUP`s a connection may ever make
//!   ([`MAX_SESSION_SETUPS_PER_CONNECTION`], [`MAX_STREAMS_PER_CONNECTION`]), and caps mirror streams
//!   (`MAX_MIRROR_STREAMS_PER_SESSION`, with the `mirror` feature).
//!
//! # Host duties
//!
//! - Close what a `TEARDOWN` or a replacing `SETUP` released: [`ReceiverEvent::PortsReleased`] lists
//!   every `(PortKind, port)` the library had asked the host for that is no longer in use. A
//!   session `TEARDOWN` releases the event port, every open stream's ports and the mirror's; a
//!   per-stream one only those of the open streams it names. A session `SETUP` while one is live
//!   releases the same as a session `TEARDOWN`, and a stream `SETUP` replaces an open stream of its
//!   type. A failed second port of a realtime stream names the first. Nothing else identifies
//!   them, and the connection ending releases all of them.
//! - The exact orders. Session `TEARDOWN`: `MirrorTeardown`, `PortsReleased`, `Teardown`. Stream
//!   `TEARDOWN`: `MirrorTeardown` (only if it names the mirror), `PortsReleased` (if any),
//!   `Teardown`. Replacing session `SETUP`: `MirrorTeardown` (only if mirror ports were held),
//!   `PortsReleased`, then the new `SessionSetup`. Replacing stream `SETUP`: `PortsReleased`, then
//!   the new stream's event.
//! - Match a released port on transport as well as number: the number spaces overlap. TCP:
//!   `Event`, `DataStream`, `MirrorData`, `BufferedAudioData`. UDP: `AudioData`, `AudioControl`.
//! - `PortsReleased` does not end workers. The host also stops what is bound to a replaced data
//!   stream or a replaced session's event channel, and to anything a `TEARDOWN` named.
//! - Drain the events after every receive; the host acts only on what it drains.
//! - Honour a buffered stream's `wants_data`: stop reading its socket while it is false.
//! - Pin each UDP control and data socket's accepted source to the paired peer's address. Sync
//!   packets and AES-CBC audio carry no integrity of their own, so any other source can inject.

use std::collections::VecDeque;
use std::time::Duration;

use plist::Value;
use rand_core::CryptoRng;

use super::audio::AudioStreamFormat;
use super::config::ReceiverConfig;
#[cfg(doc)]
use super::config::ReceiverSwitches;
use super::controllers::PairedController;
use super::identity::info_qualifiers;
use super::pairing::{refusal_reply, PairSetupServer, PairVerifyServer, PairingOutcome};
use super::pin::{PinAfterFailure, PinStart};
use crate::audio::TimingPeerInfo;
use crate::cipher::EncryptedTransport;
use crate::command::MrCommand;
use crate::dmap::NowPlaying;
use crate::error::{AirPlayError, Result};
use crate::extension::{ExtensionSession, EXCHANGE_DEADLINE, EXCHANGE_MAX_STEPS};
use crate::pairing::SessionKeys;
use crate::rtsp::{Decoder, Protocol, Request, Response, MAX_BODY_BYTES, PRE_AUTH_MAX_BODY_BYTES};
use crate::sequence::{classify, SenderStep};
use crate::time::RtpTimestamp;
use crate::tlv8::Tlv8;

/// What the `Server` header says: `AirTunes/<srcvers>`.
pub const SERVER_PRODUCT: &str = "AirTunes";

/// `kTLVError_Unknown`: the answer to a pairing the controller store could not keep.
const PAIRING_ERROR_UNKNOWN: u8 = 0x01;

/// `arrivalToRenderLatencyMs` in a realtime stream `SETUP` reply. Assumed; an Apple TV says 108.
pub const ARRIVAL_TO_RENDER_LATENCY_MS: u64 = 300;

/// The methods `OPTIONS` lists.
pub const PUBLIC_METHODS: &str = "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, \
     GET_PARAMETER, SET_PARAMETER, POST, GET, SETPEERS, SETPEERSX, SETRATEANCHORTIME";

/// Which port a `SETUP` needs from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortKind {
    /// TCP: the event channel the sender connects to.
    Event,
    /// UDP: a realtime audio stream's data port.
    AudioData,
    /// UDP: a realtime audio stream's control port (sync packets in, retransmit requests out).
    AudioControl,
    /// TCP: a MediaRemote data channel (`type: 130`).
    DataStream,
    /// TCP: a screen-mirroring data connection (`type: 110`, the `mirror` feature).
    MirrorData,
    /// TCP: a **buffered** audio stream's data connection (`type: 103`): the sender connects and
    /// writes length-prefixed packets ([`super::buffered::BufferedReceiver`]).
    BufferedAudioData,
}

/// Hands out the ports a `SETUP` names: the host binds (or reserves) one of the kind asked and
/// returns its number. Any `FnMut(PortKind) -> Result<u16>` is one.
pub trait PortAllocator {
    /// A port of this kind.
    ///
    /// # Errors
    ///
    /// None could be bound; the `SETUP` is then refused.
    fn allocate_port(&mut self, kind: PortKind) -> Result<u16>;
}

impl<F: FnMut(PortKind) -> Result<u16>> PortAllocator for F {
    fn allocate_port(&mut self, kind: PortKind) -> Result<u16> {
        self(kind)
    }
}

/// The timing the sender's session `SETUP` asked for.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SessionTiming {
    /// `timingProtocol: NTP` with the sender's timing port: query it.
    Ntp {
        /// The sender's UDP timing port.
        port: u16,
    },
    /// `timingProtocol: PTP`, with the sender's peer entry if it gave one.
    Ptp {
        /// `timingPeerInfo`.
        peer: Option<TimingPeerInfo>,
    },
    /// `timingProtocol: None` (a remote-control session).
    None,
}

/// A wrapped-key sender's realtime-audio key: AES-128-CBC with a 16-byte key and the session
/// `SETUP`'s `eiv` ([`AudioStreamSetup::aes_cbc_key`]). Zeroed on drop; `Debug` shows nothing.
#[cfg(feature = "mirror")]
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct AesCbcAudioKey {
    /// The AES-128 key, used directly with no per-stream expansion.
    pub key: [u8; 16],
    /// The CBC IV: the session `SETUP`'s `eiv`, reset for every packet.
    pub iv: [u8; 16],
}

#[cfg(feature = "mirror")]
impl std::fmt::Debug for AesCbcAudioKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCbcAudioKey(<redacted>)")
    }
}

/// What a realtime audio stream `SETUP` resolved to
/// ([`ReceiverConnection::wrapped_key_audio_keying`]).
#[cfg(feature = "mirror")]
enum AudioKeying {
    /// The ordinary ChaCha20 `shk` path (cidermill-airplay/open).
    Shk,
    /// A wrapped-key Apple sender's AES-128-CBC key.
    AesCbc(AesCbcAudioKey),
    /// Refuse the `SETUP` with this status.
    Refuse(u16, &'static str),
}

/// A realtime audio stream a `SETUP` opened.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioStreamSetup {
    /// `type` (96).
    pub stream_type: u64,
    /// The codec and shape.
    pub format: AudioStreamFormat,
    /// `shk`: the ChaCha20-Poly1305 packet key. All-zero for a wrapped-key sender (see
    /// `aes_cbc_key`).
    pub shared_key: [u8; 32],
    /// Our data port (allocated).
    pub data_port: u16,
    /// Our control port (allocated).
    pub control_port: u16,
    /// The sender's control port, where retransmit requests go (0 when it named none).
    pub sender_control_port: u16,
    /// An AirPlay 1 stream in the clear ([`crate::raop`]): `shared_key` is all-zero and unused.
    pub unencrypted: bool,
    /// A wrapped-key sender's AES-128-CBC key and IV (key unwrapped by
    /// [`ReceiverConfig::extension`]); `None` is the ChaCha20 `shk` path.
    #[cfg(feature = "mirror")]
    pub aes_cbc_key: Option<AesCbcAudioKey>,
}

impl std::fmt::Debug for AudioStreamSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("AudioStreamSetup");
        s.field("stream_type", &self.stream_type)
            .field("format", &self.format)
            .field("shared_key", &"<redacted>")
            .field("data_port", &self.data_port)
            .field("control_port", &self.control_port)
            .field("sender_control_port", &self.sender_control_port)
            .field("unencrypted", &self.unencrypted);
        #[cfg(feature = "mirror")]
        s.field("aes_cbc_key", &self.aes_cbc_key);
        s.finish()
    }
}

/// A **buffered** audio stream (`type: 103`) a `SETUP` opened: one TCP data connection, scheduled
/// on a PTP timeline. ChaCha only; a wrapped-key buffered stream is refused 501.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedAudioStreamSetup {
    /// `type` (103).
    pub stream_type: u64,
    /// The codec and shape.
    pub format: AudioStreamFormat,
    /// `shk`: the ChaCha20-Poly1305 packet key.
    pub shared_key: [u8; 32],
    /// Our data port (allocated) — the sender connects to it over TCP.
    pub data_port: u16,
}

impl std::fmt::Debug for BufferedAudioStreamSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedAudioStreamSetup")
            .field("stream_type", &self.stream_type)
            .field("format", &self.format)
            .field("shared_key", &"<redacted>")
            .field("data_port", &self.data_port)
            .finish()
    }
}

/// How the connection came to be encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptedBy {
    /// Transient pair-setup (PIN 3939, nothing stored).
    Transient,
    /// Pair-verify against a stored controller.
    PairVerify {
        /// The controller's identifier.
        controller: String,
    },
}

/// Something the host should know or act on.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ReceiverEvent {
    /// A request was answered — for the log.
    Request {
        /// What it was ([`crate::sequence::classify`]).
        step: SenderStep,
        /// Method.
        method: String,
        /// Target.
        uri: String,
        /// The status we answered.
        status: u16,
        /// Request body length (decrypted).
        request_bytes: usize,
        /// Response body length.
        response_bytes: usize,
    },
    /// Show this PIN to the user, replacing any shown before.
    ShowPin {
        /// The digits.
        pin: String,
    },
    /// Hide the PIN: none is valid any more. `locked` when PIN pairing has locked for every
    /// sender after too many failed attempts overall ([`super::pin::GLOBAL_MAX_FAILURES`]); one
    /// sender's own lock does not withdraw the PIN.
    PinWithdrawn {
        /// PIN pairing is locked.
        locked: bool,
    },
    /// A PIN pair-setup stored a controller.
    Paired {
        /// Its identifier.
        controller: String,
    },
    /// The connection is encrypted from the next byte on.
    Encrypted(EncryptedBy),
    /// A session `SETUP`.
    SessionSetup {
        /// Timing.
        timing: SessionTiming,
        /// The event port allocated (listen on it; the sender connects).
        event_port: u16,
        /// `isRemoteControlOnly`.
        remote_control_only: bool,
        /// The sender's `name`.
        sender_name: Option<String>,
        /// Whether the session carries the `cidermillMirror` marker and no `ekey`, so its audio
        /// stream is the mirror's (low latency). Always `false` without the `mirror` feature.
        pairing_keyed_mirror: bool,
    },
    /// A realtime audio stream.
    AudioStream(AudioStreamSetup),
    /// A buffered audio stream (`type: 103`): accept the sender's TCP connection on `data_port` and
    /// read it with a [`super::buffered::BufferedReceiver`].
    BufferedAudioStream(BufferedAudioStreamSetup),
    /// A `SETRATEANCHORTIME`: the buffered stream plays RTP time `rtp_time` at `network_time` on
    /// PTP timeline `timeline_id`, at `rate` (1 plays, 0 pauses). Raised only for a plist
    /// dictionary body.
    RateAnchor(crate::audio::RateAnchor),
    /// A MediaRemote data channel (`type: 130`).
    DataStream {
        /// `controlType`.
        control_type: u64,
        /// `seed`, when sent.
        seed: Option<i64>,
        /// The port allocated, when the stream has a seed.
        data_port: Option<u16>,
    },
    /// `RECORD`.
    Record,
    /// `FLUSH`, with `RTP-Info`'s values.
    Flush {
        /// `seq=`.
        sequence: Option<u16>,
        /// `rtptime=`.
        rtp_time: Option<RtpTimestamp>,
    },
    /// `TEARDOWN`: of the whole session, or of its streams only.
    Teardown {
        /// Whether the session ends.
        whole_session: bool,
    },
    /// Volume in dB.
    Volume(f64),
    /// Now-playing metadata.
    Metadata(NowPlaying),
    /// `progress: start/current/end` (RTP timestamps), parsed best-effort.
    Progress(ReceiverProgress),
    /// Artwork.
    Artwork {
        /// Its `Content-Type`.
        content_type: String,
        /// The image bytes, exactly as sent.
        data: Vec<u8>,
    },
    /// A `POST /command` push.
    Command(Box<MrCommand>),
    /// A screen-mirroring stream (`type: 110`): listen on `data_port` for the sender's connection
    /// and read it with a [`crate::mirror::MirrorStreamReader`] over `key`.
    #[cfg(feature = "mirror")]
    MirrorStream {
        /// `streamConnectionID`.
        stream_connection_id: u64,
        /// The TCP port allocated.
        data_port: u16,
        /// The stream's key and IV (derived from the pairing; never logged).
        key: crate::mirror::StreamKey,
    },
    /// Ports the library asked the host for that are no longer in use: the host closes them. Raised
    /// for a `TEARDOWN` (of the open streams it names, or of the whole session) and for a `SETUP`
    /// that replaces an open session or stream of the same type, before the event that follows.
    PortsReleased {
        /// The kind and number of each port, as allocated.
        ports: Vec<(PortKind, u16)>,
    },
    /// A `TEARDOWN` that names the mirroring stream (`streams: [{type: 110}]`). Also raised, as
    /// [`ReceiverEvent::Teardown`] is, for a `TEARDOWN` of the whole session.
    #[cfg(feature = "mirror")]
    MirrorTeardown,
    /// A sender-authentication request (`/fp-setup`, `/fp-setup2`, `/auth-setup`) arrived that no
    /// extension claims, and was refused.
    AuthenticationRefused {
        /// The path.
        path: String,
    },
    /// `POST /play`: a media URL to play. Scheme `http`/`https` with no credentials is checked
    /// here; the host applies its own reachability bounds.
    PlayUrl {
        /// The media URL.
        url: String,
        /// `Start-Position`: a fraction of the duration in `[0, 1]`, or 0 when none was sent.
        start_position: f64,
    },
    /// `POST /rate?value=X`: 0 pauses, a positive value plays (usually 1).
    Rate {
        /// The requested rate.
        value: f64,
    },
    /// `POST /scrub?position=X`: seek to `X` seconds from the start.
    Scrub {
        /// Seconds from the start.
        position: f64,
    },
    /// `POST /stop`: stop URL/photo playback and let the item end.
    StopPlayback,
    /// `PUT /photo`: show this image.
    Photo {
        /// The image bytes, exactly as sent.
        data: Vec<u8>,
        /// Its `Content-Type` (e.g. `image/jpeg`), lower-cased.
        content_type: String,
    },
}

/// One control connection. See the module docs.
pub struct ReceiverConnection {
    config: std::sync::Arc<ReceiverConfig>,
    local_ip: std::net::IpAddr,
    decoder: Decoder,
    cipher: Option<EncryptedTransport>,
    keys: Option<SessionKeys>,
    pending_keys: Option<(SessionKeys, EncryptedBy)>,
    setup: PairSetupServer,
    verify: PairVerifyServer,
    rng: Box<dyn CryptoRng + Send>,
    events: VecDeque<ReceiverEvent>,
    volume: f64,
    next_stream_id: u64,
    /// The live session's event port; a session `SETUP` replaces it.
    session_port: Option<u16>,
    /// Session `SETUP`s that allocated a port, ever, against [`MAX_SESSION_SETUPS_PER_CONNECTION`].
    sessions_set_up: usize,
    /// The non-mirror streams open, by `type`, with the ports each holds: one per type.
    open_streams: Vec<(u64, Vec<(PortKind, u16)>)>,
    /// Non-mirror stream `SETUP`s that allocated ports, ever, against
    /// [`MAX_STREAMS_PER_CONNECTION`].
    streams_set_up: usize,
    /// The mirror data ports not yet released.
    #[cfg(feature = "mirror")]
    mirror_ports: Vec<(PortKind, u16)>,
    encrypted_by: Option<EncryptedBy>,
    /// The extension session, started on the first request [`ReceiverConfig::extension`] claims.
    ext_session: Option<Box<dyn ExtensionSession>>,
    /// How many claimed requests this connection has relayed, against [`EXCHANGE_MAX_STEPS`].
    ext_steps: u32,
    /// The exchange finished; the session is kept for a stream `SETUP` to unwrap the `ekey`.
    ext_done: bool,
    /// When the whole exchange must finish by ([`EXCHANGE_DEADLINE`]), on the caller's clock.
    ext_deadline: Option<Duration>,
    /// The exchange failed: later claimed requests on this connection are refused, never restarted.
    ext_failed: bool,
    /// Recent `POST /play` / `PUT /photo` arrivals, for the [`URL_PLAYBACK_MAX_PER_SECOND`] bound.
    media_push_times: std::collections::VecDeque<Duration>,
    /// The caller's monotonic clock at the request being answered.
    now: Duration,
    /// An AirPlay 1 `ANNOUNCE` accepted in the clear ([`ReceiverSwitches::airplay1_audio`]): the
    /// connection may then set up one unencrypted stream.
    raop: Option<crate::raop::Announce>,
    #[cfg(feature = "mirror")]
    mirror: MirrorState,
}

/// Session `SETUP`s one connection may make over its whole life. A connection has one live session
/// (a repeat replaces it), so this bounds churn, not concurrency.
pub const MAX_SESSION_SETUPS_PER_CONNECTION: usize = 64;

/// Non-mirror stream `SETUP`s (audio, buffered audio, data stream) one connection may make over
/// its whole life. At most one of each type is open (a repeat replaces it), so this bounds churn,
/// not concurrency. Mirror streams have their own cap.
pub const MAX_STREAMS_PER_CONNECTION: usize = 1024;

/// Mirroring state: the session `SETUP`'s key marker and the stream ids used (a repeat would repeat
/// a keystream).
#[cfg(feature = "mirror")]
#[derive(Debug, Default)]
struct MirrorState {
    marker: Option<crate::mirror::MirrorMarker>,
    stream_ids: Vec<u64>,
    /// A wrapped-key sender's `ekey` and `eiv` from the session `SETUP`. Opaque, never logged.
    ekey: Option<Vec<u8>>,
    eiv: Option<Vec<u8>>,
}

/// Mirroring streams one connection may set up over its whole life, not per session: a stream id
/// is never reused under the same key, so ids are not forgotten at a session `TEARDOWN`. A sender
/// needs one per mirroring start.
#[cfg(feature = "mirror")]
#[doc(alias = "MAX_MIRROR_STREAMS_PER_CONNECTION")]
pub const MAX_MIRROR_STREAMS_PER_SESSION: usize = 64;

/// Whether this crate answers `method path` itself; a [`ReceiverConfig::extension`] is offered only
/// the rest.
fn answered_by_crate(method: &str, path: &str) -> bool {
    matches!(
        method,
        "OPTIONS"
            | "SETUP"
            | "GET_PARAMETER"
            | "SET_PARAMETER"
            | "RECORD"
            | "FLUSH"
            | "TEARDOWN"
            | "SETPEERS"
            | "SETPEERSX"
            | "SETRATEANCHORTIME"
    ) || matches!(
        (method, path),
        ("GET", "/info" | "/scrub" | "/playback-info")
            | (
                "POST",
                "/pair-pin-start"
                    | "/pair-setup"
                    | "/pair-verify"
                    | "/command"
                    | "/play"
                    | "/rate"
                    | "/scrub"
                    | "/stop"
                    | "/feedback"
                    | "/audioMode"
            )
            | ("PUT", "/photo")
    )
}

/// The requests an AirPlay 1 sender may make in the clear once its `ANNOUNCE` was accepted.
fn airplay1_method(method: &str, path: &str) -> bool {
    matches!(
        method,
        "SETUP" | "RECORD" | "FLUSH" | "SET_PARAMETER" | "GET_PARAMETER" | "TEARDOWN"
    ) || (method, path) == ("POST", "/feedback")
}

/// The largest wrapped key (`ekey`) handed to an extension to unwrap (72 bytes observed).
#[cfg(feature = "mirror")]
pub const WRAPPED_KEY_MAX: usize = 256;

impl std::fmt::Debug for ReceiverConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverConnection")
            .field("encrypted", &self.cipher.is_some())
            .finish_non_exhaustive()
    }
}

impl ReceiverConnection {
    /// A connection. `local_ip` is the address the sender reached us on (for PTP `timingPeerInfo`).
    #[must_use]
    pub fn new(
        config: std::sync::Arc<ReceiverConfig>,
        local_ip: std::net::IpAddr,
        rng: Box<dyn CryptoRng + Send>,
    ) -> Self {
        let accessory = config.identity().accessory();
        let mut decoder = Decoder::new();
        decoder.set_max_body(PRE_AUTH_MAX_BODY_BYTES);
        Self {
            setup: PairSetupServer::with_gate(
                accessory.clone(),
                config.allow_transient(),
                config.fixed_pin().map(str::to_owned),
                std::sync::Arc::clone(config.pin_gate()),
            ),
            verify: PairVerifyServer::new(accessory),
            volume: config.initial_volume(),
            config,
            local_ip,
            decoder,
            cipher: None,
            keys: None,
            pending_keys: None,
            rng,
            events: VecDeque::new(),
            next_stream_id: 1,
            session_port: None,
            sessions_set_up: 0,
            open_streams: Vec::new(),
            streams_set_up: 0,
            #[cfg(feature = "mirror")]
            mirror_ports: Vec::new(),
            encrypted_by: None,
            ext_session: None,
            ext_steps: 0,
            ext_done: false,
            ext_deadline: None,
            ext_failed: false,
            media_push_times: std::collections::VecDeque::new(),
            now: Duration::ZERO,
            raop: None,
            #[cfg(feature = "mirror")]
            mirror: MirrorState::default(),
        }
    }

    /// Names the sender's address, which the PIN limits count failed attempts against. A host
    /// that knows the peer calls this right after [`Self::new`]; without it every connection
    /// shares one unknown source and one sender's failures lock them all.
    pub fn set_peer_ip(&mut self, peer: std::net::IpAddr) {
        self.setup.set_source(peer);
    }

    /// The configuration this connection was built from.
    #[must_use]
    pub fn config(&self) -> &std::sync::Arc<ReceiverConfig> {
        &self.config
    }

    /// Whether the connection is encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// Whether an AirPlay 1 sender's `ANNOUNCE` was accepted in the clear on this connection
    /// ([`ReceiverSwitches::airplay1_audio`]): a host admits it as it does a paired one.
    #[must_use]
    pub fn is_airplay1(&self) -> bool {
        self.cipher.is_none() && self.raop.is_some()
    }

    /// The session keys (receiver orientation), once pairing produced them.
    #[must_use]
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }

    /// The event channel's transport (receiver orientation), once pairing produced keys.
    #[must_use]
    pub fn event_transport(&self) -> Option<EncryptedTransport> {
        let keys = super::pairing::receiver_event_keys(self.keys.as_ref()?).ok()?;
        Some(keys.transport())
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<ReceiverEvent> {
        self.events.pop_front()
    }

    /// Feeds bytes read from the socket; returns the bytes to write back (possibly none). `now` is
    /// the caller's monotonic clock (time since any fixed origin); it times the extension exchange
    /// and the URL playback rate bound.
    ///
    /// An error (an unauthenticated frame or unframeable request) is terminal for the connection.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        ports: &mut dyn PortAllocator,
        now: Duration,
    ) -> Result<Vec<u8>> {
        match &mut self.cipher {
            Some(cipher) => {
                cipher.push(bytes);
                while let Some(plain) = cipher.open_next()? {
                    self.decoder.push(&plain);
                }
            }
            None => self.decoder.push(bytes),
        }
        let mut out = Vec::new();
        while let Some(request) = self.decoder.next_request()? {
            let response = self.answer(&request, ports, now);
            let wire = response.encode();
            match &mut self.cipher {
                Some(cipher) => out.extend(cipher.seal(&wire)?),
                None => out.extend(wire),
            }
            if let Some((keys, how)) = self.pending_keys.take() {
                if self.decoder.buffered() > 0 {
                    return Err(AirPlayError::Protocol(
                        "a sender pipelined plaintext past the pairing that encrypts the channel"
                            .to_owned(),
                    ));
                }
                self.cipher = Some(EncryptedTransport::from_keys(
                    &keys.write_key,
                    &keys.read_key,
                ));
                self.decoder.set_max_body(MAX_BODY_BYTES);
                self.keys = Some(keys);
                self.encrypted_by = Some(how.clone());
                self.events.push_back(ReceiverEvent::Encrypted(how));
            }
        }
        Ok(out)
    }

    /// Answers one request — the part a test can drive with no framing at all. `now` as for
    /// [`Self::receive`].
    pub fn answer(
        &mut self,
        request: &Request,
        ports: &mut dyn PortAllocator,
        now: Duration,
    ) -> Response {
        self.now = now;
        let step = classify(request);
        let mut response = match self.route(request, ports) {
            Ok(response) => response,
            Err(e) => {
                log::debug!("{} {} refused: {e}", request.method, request.uri);
                Response::new(request.protocol, 400, "Bad Request", Vec::new())
            }
        };
        if let Some(cseq) = request.headers.get("CSeq") {
            response.headers.set("CSeq", cseq.trim().to_owned());
        }
        response.headers.set(
            "Server",
            format!("{SERVER_PRODUCT}/{}", self.config.identity().source_version),
        );
        response
            .headers
            .set("Content-Length", response.body.len().to_string());
        self.events.push_back(ReceiverEvent::Request {
            step,
            method: request.method.clone(),
            uri: request.uri.clone(),
            status: response.status,
            request_bytes: request.body.len(),
            response_bytes: response.body.len(),
        });
        response
    }

    fn route(&mut self, request: &Request, ports: &mut dyn PortAllocator) -> Result<Response> {
        let protocol = request.protocol;
        let path = request
            .uri
            .split_once('?')
            .map_or(request.uri.as_str(), |(p, _)| p);
        let method = request.method.as_str();
        match (method, path) {
            ("GET", "/info") => {
                let qualifiers = info_qualifiers(&request.body);
                let body = self.config.info_body(&qualifiers, self.volume)?;
                return Ok(plist_response(protocol, body));
            }
            ("OPTIONS", _) => {
                let mut response = ok(protocol);
                response.headers.set("Public", PUBLIC_METHODS);
                return Ok(response);
            }
            ("POST", "/pair-pin-start") => {
                return Ok(match self.setup.start_pin(&mut *self.rng) {
                    PinStart::Show(pin) => {
                        self.events.push_back(ReceiverEvent::ShowPin { pin });
                        ok(protocol)
                    }
                    PinStart::Refused(refusal) => {
                        let mut response = Response::new(
                            protocol,
                            503,
                            "Service Unavailable",
                            refusal_reply(2, refusal).encode(),
                        );
                        response
                            .headers
                            .set("Content-Type", "application/octet-stream");
                        response
                    }
                    _ => ok(protocol),
                });
            }
            ("POST", "/pair-setup") => {
                let message = Tlv8::decode(&request.body)?;
                let outcome = self.setup.handle(&message, &mut *self.rng)?;
                return Ok(self.pairing_response(protocol, outcome));
            }
            ("POST", "/pair-verify") => {
                let message = Tlv8::decode(&request.body)?;
                let controllers = std::sync::Arc::clone(self.config.controllers());
                let lookup = |id: &[u8]| controllers.get(id);
                let outcome = self.verify.handle(&message, &mut *self.rng, &lookup)?;
                return Ok(self.pairing_response(protocol, outcome));
            }
            _ => {}
        }
        // A claimed request is the extension's, before the encryption gate (handshakes run
        // unpaired). Only requests this crate does not answer itself are offered.
        if !answered_by_crate(method, path)
            && self
                .config
                .extension()
                .is_some_and(|ext| ext.claims(method, path))
        {
            return self.extension_relay(request, path);
        }
        if method == "POST" && matches!(path, "/fp-setup" | "/fp-setup2" | "/auth-setup") {
            // No extension claimed this sender-authentication scheme: a bodiless 404.
            self.events.push_back(ReceiverEvent::AuthenticationRefused {
                path: path.to_owned(),
            });
            return Ok(Response::new(protocol, 404, "Not Found", Vec::new()));
        }
        if self.cipher.is_none() && method == "ANNOUNCE" && self.airplay1_allowed() {
            return Ok(self.announce_request(request));
        }
        let airplay1 =
            self.is_airplay1() && self.airplay1_allowed() && airplay1_method(method, path);
        if self.cipher.is_none() && !airplay1 {
            return Ok(Response::new(
                protocol,
                470,
                "Connection Authorization Required",
                Vec::new(),
            ));
        }
        match (method, path) {
            ("SETUP", _) if airplay1 => self.raop_setup(request, ports),
            ("SETUP", _) => self.setup_request(request, ports),
            ("GET_PARAMETER", _) => {
                let body = String::from_utf8_lossy(&request.body);
                if body
                    .lines()
                    .any(|l| l.trim().eq_ignore_ascii_case("volume"))
                {
                    let mut response = Response::new(
                        protocol,
                        200,
                        "OK",
                        format!("volume: {:.6}\r\n", self.volume).into_bytes(),
                    );
                    response
                        .headers
                        .set("Content-Type", crate::session::TEXT_PARAMETERS_CONTENT_TYPE);
                    Ok(response)
                } else {
                    Ok(ok(protocol))
                }
            }
            ("SET_PARAMETER", _) => {
                self.set_parameter(request)?;
                Ok(ok(protocol))
            }
            ("RECORD", _) => {
                self.events.push_back(ReceiverEvent::Record);
                Ok(ok(protocol))
            }
            ("FLUSH", _) => {
                let (sequence, rtp_time) = rtp_info(request.headers.get("RTP-Info"));
                self.events
                    .push_back(ReceiverEvent::Flush { sequence, rtp_time });
                Ok(ok(protocol))
            }
            ("TEARDOWN", _) => {
                let streams_only =
                    plist_dictionary(&request.body).is_some_and(|d| d.contains_key("streams"));
                let mut released = Vec::new();
                if !streams_only {
                    released = self.release_session(true);
                } else {
                    #[cfg(feature = "mirror")]
                    if names_mirror_stream(&request.body) {
                        self.events.push_back(ReceiverEvent::MirrorTeardown);
                        released.append(&mut self.mirror_ports);
                    }
                    // Only a type that is open is released, and once.
                    for stream_type in stream_types_named(&request.body) {
                        if let Some(at) = self
                            .open_streams
                            .iter()
                            .position(|(t, _)| *t == stream_type)
                        {
                            released.extend(self.open_streams.remove(at).1);
                        }
                    }
                }
                if !released.is_empty() {
                    self.events
                        .push_back(ReceiverEvent::PortsReleased { ports: released });
                }
                self.events.push_back(ReceiverEvent::Teardown {
                    whole_session: !streams_only,
                });
                Ok(ok(protocol))
            }
            ("POST", "/command") => {
                if let Some(command) = MrCommand::parse(&request.body)? {
                    self.events
                        .push_back(ReceiverEvent::Command(Box::new(command)));
                }
                Ok(ok(protocol))
            }
            ("POST", "/play") => self.play_request(protocol, request),
            ("POST", "/rate") => self.rate_request(protocol, request),
            ("POST", "/scrub") => self.scrub_request(protocol, request),
            ("GET", "/scrub") => self.playback_position(protocol),
            ("GET", "/playback-info") => self.playback_info(protocol),
            ("POST", "/stop") => self.stop_playback(protocol),
            ("PUT", "/photo") => self.photo_request(protocol, request),
            ("SETRATEANCHORTIME", _) => {
                if let Ok(anchor) = crate::audio::RateAnchor::parse(&request.body) {
                    self.events.push_back(ReceiverEvent::RateAnchor(anchor));
                }
                Ok(ok(protocol))
            }
            ("POST", "/feedback" | "/audioMode") | ("SETPEERS" | "SETPEERSX", _) => {
                Ok(ok(protocol))
            }
            _ => Ok(Response::new(protocol, 404, "Not Found", Vec::new())),
        }
    }

    /// Relays a request [`ReceiverConfig::extension`] claimed to this connection's
    /// [`ExtensionSession`], started on the first one. Its reply is a `200`; once finished the
    /// session is kept for [`ExtensionSession::unwrap_session_key`]. Bounded by
    /// [`EXCHANGE_MAX_STEPS`] and [`EXCHANGE_DEADLINE`]; a failure becomes a `400`.
    ///
    /// The relayed bytes are the extension's and never logged; only step index and length are.
    fn extension_relay(&mut self, request: &Request, path: &str) -> Result<Response> {
        let protocol = request.protocol;
        let octets = |body: Vec<u8>| {
            let mut response = Response::new(protocol, 200, "OK", body);
            response
                .headers
                .set("Content-Type", "application/octet-stream");
            response
        };
        // Finished earlier: answer the empty 200 without driving the session again.
        if self.ext_done {
            return Ok(octets(Vec::new()));
        }
        if self.ext_failed {
            return Err(AirPlayError::Protocol(
                "the receiver extension's exchange already failed on this connection".to_owned(),
            ));
        }

        if self.ext_session.is_none() {
            let extension =
                self.config.extension().cloned().ok_or_else(|| {
                    AirPlayError::InvalidState("no receiver extension".to_owned())
                })?;
            self.ext_session = Some(extension.start().inspect_err(|_| self.ext_failed = true)?);
            self.ext_steps = 0;
            self.ext_deadline = Some(self.now.saturating_add(EXCHANGE_DEADLINE));
        }

        if self.ext_steps >= EXCHANGE_MAX_STEPS {
            self.ext_session = None;
            self.ext_failed = true;
            return Err(AirPlayError::Protocol(format!(
                "the receiver extension's exchange did not finish within {EXCHANGE_MAX_STEPS} steps"
            )));
        }
        if self.ext_deadline.is_some_and(|d| self.now >= d) {
            self.ext_session = None;
            self.ext_failed = true;
            return Err(AirPlayError::Protocol(
                "the receiver extension's exchange did not finish within its time limit".to_owned(),
            ));
        }

        // Opaque: only the step index and byte length are ever logged.
        log::debug!(
            "receiver extension step {} ({path}): {} byte(s) in",
            self.ext_steps,
            request.body.len()
        );
        let stepped = match self.ext_session.as_mut() {
            Some(session) => session.step(request),
            None => Err(AirPlayError::InvalidState(
                "the receiver extension's session is gone".to_owned(),
            )),
        };
        let reply = match stepped {
            Ok(Some(data)) => data,
            Ok(None) => {
                // Finished. Keep the session: a stream `SETUP` may need it to unwrap `ekey`.
                self.ext_done = true;
                Vec::new()
            }
            Err(e) => {
                self.ext_session = None;
                self.ext_failed = true;
                return Err(e);
            }
        };
        self.ext_steps = self.ext_steps.saturating_add(1);
        log::debug!(
            "receiver extension step {} ({path}): {} byte(s) out",
            self.ext_steps,
            reply.len()
        );
        Ok(octets(reply))
    }

    fn pairing_response(&mut self, protocol: Protocol, outcome: PairingOutcome) -> Response {
        let reply = match outcome {
            PairingOutcome::Reply(reply) => reply,
            PairingOutcome::ShowPin { reply, pin } => {
                self.events.push_back(ReceiverEvent::ShowPin { pin });
                reply
            }
            PairingOutcome::Failed { reply, pin } => {
                match pin {
                    PinAfterFailure::Replaced(pin) => {
                        self.events.push_back(ReceiverEvent::ShowPin { pin });
                    }
                    PinAfterFailure::LockedOut => {
                        self.events
                            .push_back(ReceiverEvent::PinWithdrawn { locked: true });
                    }
                    _ => {}
                }
                reply
            }
            PairingOutcome::Paired {
                reply,
                controller,
                controller_key,
            } => {
                let stored = self
                    .config
                    .controllers()
                    .add(PairedController::new(controller.clone(), controller_key));
                match stored {
                    Ok(()) => {
                        self.events.push_back(ReceiverEvent::Paired {
                            controller: String::from_utf8_lossy(&controller).into_owned(),
                        });
                        reply
                    }
                    Err(e) => {
                        log::warn!("a paired controller could not be stored: {e}");
                        let mut refused = Tlv8::new();
                        refused.push_byte(crate::tlv8::tag::STATE, 6);
                        refused.push_byte(crate::tlv8::tag::ERROR, PAIRING_ERROR_UNKNOWN);
                        refused
                    }
                }
            }
            PairingOutcome::Encrypt {
                reply,
                keys,
                controller,
            } => {
                let how = match controller {
                    Some(id) => EncryptedBy::PairVerify {
                        controller: String::from_utf8_lossy(&id).into_owned(),
                    },
                    None => EncryptedBy::Transient,
                };
                self.pending_keys = Some((*keys, how));
                reply
            }
        };
        let mut response = Response::new(protocol, 200, "OK", reply.encode());
        response
            .headers
            .set("Content-Type", "application/octet-stream");
        response
    }

    /// Whether AirPlay 1 in the clear is answered: the switch is on and the receiver asks no PIN
    /// (an AirPlay 1 sender cannot pair, so a PIN-only receiver refuses it as it refuses any sender
    /// that has not paired).
    fn airplay1_allowed(&self) -> bool {
        self.config.switches().airplay1_audio() && self.config.allow_transient()
    }

    /// An AirPlay 1 `ANNOUNCE` in the clear: its SDP read ([`crate::raop::parse_announce`]) and
    /// kept for the `SETUP`. A key in it (`et` 1, 3, 4 or 5), or a codec or shape the decoder does
    /// not read: 415.
    fn announce_request(&mut self, request: &Request) -> Response {
        let protocol = request.protocol;
        match crate::raop::parse_announce(&request.body) {
            Ok(announce)
                if !announce.encrypted
                    && super::audio::PacketDecoder::new(announce.stream_format()).is_ok() =>
            {
                self.raop = Some(announce);
                // Admitted as a paired sender is: artwork and metadata may be larger than the
                // pre-pairing cap.
                self.decoder.set_max_body(MAX_BODY_BYTES);
                ok(protocol)
            }
            Ok(_) => Response::new(protocol, 415, "Unsupported Media Type", Vec::new()),
            Err(e) => {
                log::debug!("ANNOUNCE refused: {e}");
                Response::new(protocol, 400, "Bad Request", Vec::new())
            }
        }
    }

    /// An AirPlay 1 `SETUP`: the ports from its `Transport` header, a data and a control port
    /// allocated, then a session (timing over NTP to the sender's `timing_port`, no event channel)
    /// and an unencrypted realtime stream in the format the `ANNOUNCE` gave. A repeat replaces the
    /// stream, as a repeated AirPlay 2 stream `SETUP` does.
    fn raop_setup(&mut self, request: &Request, ports: &mut dyn PortAllocator) -> Result<Response> {
        let protocol = request.protocol;
        let Some(announce) = self.raop else {
            return Ok(Response::new(
                protocol,
                455,
                "Method Not Valid in This State",
                Vec::new(),
            ));
        };
        if self.sessions_set_up >= MAX_SESSION_SETUPS_PER_CONNECTION
            || self.streams_set_up >= MAX_STREAMS_PER_CONNECTION
        {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        }
        let transport =
            crate::raop::Transport::parse(request.headers.get("Transport").unwrap_or(""));
        let format = announce.stream_format();
        let data_port = ports.allocate_port(PortKind::AudioData)?;
        let control_port = match ports.allocate_port(PortKind::AudioControl) {
            Ok(port) => port,
            Err(e) => {
                self.events.push_back(ReceiverEvent::PortsReleased {
                    ports: vec![(PortKind::AudioData, data_port)],
                });
                return Err(e);
            }
        };
        self.sessions_set_up += 1;
        self.open_stream(
            crate::audio::StreamType::REALTIME_CODE,
            vec![
                (PortKind::AudioData, data_port),
                (PortKind::AudioControl, control_port),
            ],
        );
        self.events.push_back(ReceiverEvent::SessionSetup {
            timing: SessionTiming::Ntp {
                port: transport.timing_port.unwrap_or(0),
            },
            event_port: 0,
            remote_control_only: false,
            sender_name: None,
            pairing_keyed_mirror: false,
        });
        self.events
            .push_back(ReceiverEvent::AudioStream(AudioStreamSetup {
                stream_type: crate::audio::StreamType::REALTIME_CODE,
                format,
                shared_key: [0u8; 32],
                data_port,
                control_port,
                sender_control_port: transport.control_port.unwrap_or(0),
                unencrypted: true,
                #[cfg(feature = "mirror")]
                aes_cbc_key: None,
            }));
        let mut response = ok(protocol);
        response.headers.set(
            "Transport",
            crate::raop::Transport::reply(data_port, control_port, None),
        );
        response
            .headers
            .set("Session", crate::raop::RECEIVER_SESSION);
        response
            .headers
            .set("Audio-Jack-Status", crate::raop::AUDIO_JACK_STATUS);
        Ok(response)
    }

    fn setup_request(
        &mut self,
        request: &Request,
        ports: &mut dyn PortAllocator,
    ) -> Result<Response> {
        let protocol = request.protocol;
        let dict = plist_dictionary(&request.body).ok_or_else(|| {
            AirPlayError::Protocol("SETUP body is not a plist dictionary".to_owned())
        })?;
        if let Some(streams) = dict.get("streams").and_then(Value::as_array) {
            let stream = streams
                .first()
                .and_then(Value::as_dictionary)
                .ok_or_else(|| AirPlayError::Protocol("SETUP streams[0] is missing".to_owned()))?;
            return self.stream_setup(protocol, stream, ports);
        }

        if self.sessions_set_up >= MAX_SESSION_SETUPS_PER_CONNECTION {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        }
        let timing = match dict.get("timingProtocol").and_then(Value::as_string) {
            Some("NTP") => SessionTiming::Ntp {
                port: unsigned(&dict, "timingPort")
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(0),
            },
            Some("PTP") => SessionTiming::Ptp {
                peer: dict
                    .get("timingPeerInfo")
                    .and_then(TimingPeerInfo::from_value),
            },
            _ => SessionTiming::None,
        };
        // From the marker, not stream order: a mirror session's audio is the mirror's.
        let pairing_keyed_mirror = {
            #[cfg(feature = "mirror")]
            {
                matches!(
                    crate::mirror::MirrorMarker::of_session(&dict),
                    crate::mirror::MirrorMarker::PairingKeyed { .. }
                )
            }
            #[cfg(not(feature = "mirror"))]
            {
                false
            }
        };
        let event_port = ports.allocate_port(PortKind::Event)?;
        self.sessions_set_up += 1;
        if self.session_port.is_some() {
            // A new session replaces the live one: release it as a session `TEARDOWN` does.
            let released = self.release_session(false);
            if !released.is_empty() {
                self.events
                    .push_back(ReceiverEvent::PortsReleased { ports: released });
            }
        }
        self.session_port = Some(event_port);
        // Only now: a failed allocation leaves the live session's key material as it was.
        #[cfg(feature = "mirror")]
        {
            self.mirror.marker = Some(crate::mirror::MirrorMarker::of_session(&dict));
            // Keep a wrapped-key sender's `ekey`/`eiv` for the stream `SETUP`'s unwrap. Opaque.
            self.mirror.ekey = dict
                .get(crate::mirror::setup::WRAPPED_KEY)
                .and_then(Value::as_data)
                .map(<[u8]>::to_vec);
            self.mirror.eiv = dict
                .get(crate::mirror::setup::WRAPPED_KEY_IV)
                .and_then(Value::as_data)
                .map(<[u8]>::to_vec);
        }
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "eventPort".into(),
            Value::Integer(u64::from(event_port).into()),
        );
        reply.insert("timingPort".into(), Value::Integer(0.into()));
        if matches!(timing, SessionTiming::Ptp { .. }) {
            let mut peer = plist::Dictionary::new();
            peer.insert(
                "Addresses".into(),
                Value::Array(vec![Value::String(self.local_ip.to_string())]),
            );
            peer.insert(
                "ID".into(),
                Value::String(self.config.identity().device_id.to_ascii_lowercase()),
            );
            reply.insert("timingPeerInfo".into(), Value::Dictionary(peer));
        }
        self.events.push_back(ReceiverEvent::SessionSetup {
            timing,
            event_port,
            remote_control_only: dict
                .get("isRemoteControlOnly")
                .and_then(Value::as_boolean)
                .unwrap_or(false),
            sender_name: dict
                .get("name")
                .and_then(Value::as_string)
                .map(str::to_owned),
            pairing_keyed_mirror,
        });
        Ok(plist_response(protocol, encode(&reply)?))
    }

    /// Releases the live session's resources: every open stream's ports, the mirror's and the
    /// event port. `MirrorTeardown` is raised first when the mirror held ports, or always with
    /// `always_mirror_teardown`. The caller raises `PortsReleased` with what comes back.
    fn release_session(&mut self, always_mirror_teardown: bool) -> Vec<(PortKind, u16)> {
        let mut released = Vec::new();
        #[cfg(feature = "mirror")]
        if always_mirror_teardown || !self.mirror_ports.is_empty() {
            self.events.push_back(ReceiverEvent::MirrorTeardown);
            released.append(&mut self.mirror_ports);
        }
        #[cfg(not(feature = "mirror"))]
        let _ = always_mirror_teardown;
        for (_, ports) in self.open_streams.drain(..) {
            released.extend(ports);
        }
        released.extend(self.session_port.take().map(|port| (PortKind::Event, port)));
        released
    }

    /// Records a non-mirror stream as open with its ports; one of the same type already open is
    /// replaced and its ports released.
    fn open_stream(&mut self, stream_type: u64, ports: Vec<(PortKind, u16)>) {
        self.streams_set_up += 1;
        if let Some(at) = self
            .open_streams
            .iter()
            .position(|(t, _)| *t == stream_type)
        {
            let (_, old) = self.open_streams.remove(at);
            self.events
                .push_back(ReceiverEvent::PortsReleased { ports: old });
        }
        self.open_streams.push((stream_type, ports));
    }

    fn stream_setup(
        &mut self,
        protocol: Protocol,
        stream: &plist::Dictionary,
        ports: &mut dyn PortAllocator,
    ) -> Result<Response> {
        let stream_type = unsigned(stream, "type").unwrap_or(0);
        #[cfg(feature = "mirror")]
        let counted = stream_type != crate::mirror::STREAM_TYPE;
        #[cfg(not(feature = "mirror"))]
        let counted = true;
        if counted && self.streams_set_up >= MAX_STREAMS_PER_CONNECTION {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        }
        let mut entry = plist::Dictionary::new();
        entry.insert("type".into(), Value::Integer(stream_type.into()));
        match stream_type {
            crate::audio::StreamType::REALTIME_CODE => {
                let number = |k: &str| unsigned(stream, k).unwrap_or(0);
                let format = AudioStreamFormat::new(
                    number("ct"),
                    number("audioFormat"),
                    u32::try_from(number("sr")).unwrap_or(0),
                    u32::try_from(number("spf")).unwrap_or(0),
                );
                // A wrapped-key sender keys audio with AES-128-CBC from the session `SETUP`'s
                // ekey/eiv; gated like the mirror stream.
                #[cfg(feature = "mirror")]
                let aes_cbc_key = match self.wrapped_key_audio_keying()? {
                    AudioKeying::Shk => None,
                    AudioKeying::AesCbc(key) => Some(key),
                    AudioKeying::Refuse(code, reason) => {
                        return Ok(Response::new(protocol, code, reason, Vec::new()))
                    }
                };
                // `shk` is required for ChaCha and absent (all-zero) for AES-CBC.
                #[cfg(feature = "mirror")]
                let shk_required = aes_cbc_key.is_none();
                #[cfg(not(feature = "mirror"))]
                let shk_required = true;
                let key: [u8; 32] = if shk_required {
                    stream
                        .get("shk")
                        .and_then(Value::as_data)
                        .and_then(|k| k.try_into().ok())
                        .ok_or_else(|| {
                            AirPlayError::Protocol("stream SETUP has no 32-byte shk".to_owned())
                        })?
                } else {
                    [0u8; 32]
                };
                // A shape the receive path would refuse is refused here, at `SETUP`.
                let playable = if shk_required {
                    super::audio::PacketDecoder::new(format).is_ok()
                } else {
                    super::audio::check_shape(&format).is_ok()
                };
                if !playable {
                    return Ok(Response::new(protocol, 501, "Not Implemented", Vec::new()));
                }
                let data_port = ports.allocate_port(PortKind::AudioData)?;
                let control_port = match ports.allocate_port(PortKind::AudioControl) {
                    Ok(port) => port,
                    Err(e) => {
                        // The data port is bound and nothing will use it: name it for the host.
                        self.events.push_back(ReceiverEvent::PortsReleased {
                            ports: vec![(PortKind::AudioData, data_port)],
                        });
                        return Err(e);
                    }
                };
                self.open_stream(
                    stream_type,
                    vec![
                        (PortKind::AudioData, data_port),
                        (PortKind::AudioControl, control_port),
                    ],
                );
                entry.insert(
                    "arrivalToRenderLatencyMs".into(),
                    Value::Integer(ARRIVAL_TO_RENDER_LATENCY_MS.into()),
                );
                entry.insert(
                    "controlPort".into(),
                    Value::Integer(u64::from(control_port).into()),
                );
                entry.insert(
                    "dataPort".into(),
                    Value::Integer(u64::from(data_port).into()),
                );
                self.events
                    .push_back(ReceiverEvent::AudioStream(AudioStreamSetup {
                        stream_type,
                        format,
                        shared_key: key,
                        data_port,
                        control_port,
                        sender_control_port: u16::try_from(number("controlPort")).unwrap_or(0),
                        unencrypted: false,
                        #[cfg(feature = "mirror")]
                        aes_cbc_key,
                    }));
            }
            crate::audio::format::StreamType::BUFFERED_CODE => {
                // Buffered (type 103): only the ChaCha `shk` path, and only when the host can play
                // one; a wrapped-key buffered stream has no `shk` and is 501.
                if !self.config.switches().buffered_audio() {
                    return Ok(Response::new(protocol, 501, "Not Implemented", Vec::new()));
                }
                // Needs pair-verify assurance: a buffered stream holds seconds of audio.
                if !matches!(self.encrypted_by, Some(EncryptedBy::PairVerify { .. })) {
                    return Ok(Response::new(protocol, 403, "Forbidden", Vec::new()));
                }
                let Some(key) = stream
                    .get("shk")
                    .and_then(Value::as_data)
                    .and_then(|k| <[u8; 32]>::try_from(k).ok())
                else {
                    return Ok(Response::new(protocol, 501, "Not Implemented", Vec::new()));
                };
                let number = |k: &str| unsigned(stream, k).unwrap_or(0);
                let format = AudioStreamFormat::new(
                    number("ct"),
                    number("audioFormat"),
                    u32::try_from(number("sr")).unwrap_or(0),
                    u32::try_from(number("spf")).unwrap_or(0),
                );
                // A format the decoder cannot read is refused here, not dropped later.
                if super::audio::PacketDecoder::new(format).is_err() {
                    return Ok(Response::new(protocol, 501, "Not Implemented", Vec::new()));
                }
                let data_port = ports.allocate_port(PortKind::BufferedAudioData)?;
                self.open_stream(stream_type, vec![(PortKind::BufferedAudioData, data_port)]);
                entry.insert(
                    "dataPort".into(),
                    Value::Integer(u64::from(data_port).into()),
                );
                self.events.push_back(ReceiverEvent::BufferedAudioStream(
                    BufferedAudioStreamSetup {
                        stream_type,
                        format,
                        shared_key: key,
                        data_port,
                    },
                ));
            }
            #[cfg(feature = "mirror")]
            crate::mirror::STREAM_TYPE => return self.mirror_setup(protocol, stream, ports),
            crate::datastream::STREAM_TYPE => {
                let seed = stream.get("seed").and_then(Value::as_signed_integer);
                let data_port = match seed {
                    Some(_) => {
                        let port = ports.allocate_port(PortKind::DataStream)?;
                        self.open_stream(stream_type, vec![(PortKind::DataStream, port)]);
                        entry.insert("dataPort".into(), Value::Integer(u64::from(port).into()));
                        Some(port)
                    }
                    None => None,
                };
                entry.insert(
                    "streamID".into(),
                    Value::Integer(self.next_stream_id.into()),
                );
                self.next_stream_id += 1;
                self.events.push_back(ReceiverEvent::DataStream {
                    control_type: unsigned(stream, "controlType").unwrap_or(0),
                    seed,
                    data_port,
                });
            }
            _ => {
                return Ok(Response::new(protocol, 501, "Not Implemented", Vec::new()));
            }
        }
        let mut body = plist::Dictionary::new();
        body.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(entry)]),
        );
        Ok(plist_response(protocol, encode(&body)?))
    }

    /// How a realtime audio stream `SETUP` is keyed, decided from the session.
    #[cfg(feature = "mirror")]
    fn wrapped_key_audio_keying(&mut self) -> Result<AudioKeying> {
        use crate::mirror::{MirrorKey, MirrorMarker};
        match self.mirror.marker {
            // A wrapped-key Apple sender, with an extension configured: the AES-CBC path.
            Some(MirrorMarker::WrappedKey) if self.config.extension().is_some() => {}
            // A wrapped key and no extension: its audio cannot be keyed (as the mirror answers
            // 501).
            Some(MirrorMarker::WrappedKey) => {
                return Ok(AudioKeying::Refuse(501, "Not Implemented"))
            }
            // Open or unmarked: the ChaCha20 `shk` path.
            _ => return Ok(AudioKeying::Shk),
        }
        // Same assurance the mirror asks: a key stored at PIN pairing, not just the transient PIN.
        if !matches!(self.encrypted_by, Some(EncryptedBy::PairVerify { .. })) {
            return Ok(AudioKeying::Refuse(403, "Forbidden"));
        }
        let Some(ekey) = self.mirror.ekey.clone() else {
            return Ok(AudioKeying::Refuse(400, "Bad Request")); // wrapped-key marker but no `ekey`
        };
        if ekey.is_empty() || ekey.len() > WRAPPED_KEY_MAX {
            return Ok(AudioKeying::Refuse(400, "Bad Request")); // length-checked before the extension
        }
        let Some(iv) = self
            .mirror
            .eiv
            .as_deref()
            .and_then(|eiv| <[u8; 16]>::try_from(eiv).ok())
        else {
            return Ok(AudioKeying::Refuse(400, "Bad Request")); // the CBC IV must be the 16-byte `eiv`
        };
        let shared = self
            .keys
            .as_ref()
            .ok_or_else(|| AirPlayError::InvalidState("no session keys".to_owned()))?
            .shared_secret
            .clone();
        let Some(session) = self.ext_session.as_mut() else {
            // An extension is configured, but no exchange ran on this connection.
            return Ok(AudioKeying::Refuse(501, "Not Implemented"));
        };
        // One unwrap per `SETUP`; the base is composed with the pair-verify secret, used directly.
        match session.unwrap_session_key(&ekey) {
            Ok(session_key) => {
                let base = MirrorKey::from_session_key(&session_key, &shared);
                Ok(AudioKeying::AesCbc(AesCbcAudioKey {
                    key: *base.as_bytes(),
                    iv,
                }))
            }
            Err(_) => {
                self.ext_session = None; // drop a failing session, as the mirror unwrap and the relay do
                Ok(AudioKeying::Refuse(400, "Bad Request"))
            }
        }
    }

    /// A `type: 110` stream `SETUP`.
    #[cfg(feature = "mirror")]
    fn mirror_setup(
        &mut self,
        protocol: Protocol,
        stream: &plist::Dictionary,
        ports: &mut dyn PortAllocator,
    ) -> Result<Response> {
        use crate::mirror::setup::PAIRING_KEYED_VERSION;
        use crate::mirror::{MirrorKey, MirrorMarker, MirrorStreamReply, MirrorStreamSetup};

        let status =
            |code: u16, reason: &str| Ok(Response::new(protocol, code, reason, Vec::new()));
        if !self.config.switches().mirroring() {
            return status(501, "Not Implemented");
        }
        match self.mirror.marker {
            Some(MirrorMarker::PairingKeyed {
                version: PAIRING_KEYED_VERSION,
            }) => {}
            // A wrapped-key sender (`ekey`) needs an extension; without one it is 501.
            Some(MirrorMarker::WrappedKey) if self.config.extension().is_some() => {}
            // A wrapped key with no extension, or a cidermill-airplay version this crate does not
            // know: 501.
            Some(MirrorMarker::WrappedKey | MirrorMarker::PairingKeyed { .. }) => {
                return status(501, "Not Implemented");
            }
            _ => return status(400, "Bad Request"),
        }
        // Needs pair-verify assurance: a key stored at PIN pairing, not the transient PIN.
        if !matches!(self.encrypted_by, Some(EncryptedBy::PairVerify { .. })) {
            return status(403, "Forbidden");
        }
        let Ok(setup) = MirrorStreamSetup::from_entry(stream) else {
            return status(400, "Bad Request");
        };
        let id = setup.stream_connection_id;
        if self.mirror.stream_ids.contains(&id)
            || self.mirror.stream_ids.len() >= MAX_MIRROR_STREAMS_PER_SESSION
        {
            return status(400, "Bad Request");
        }
        let shared = self
            .keys
            .as_ref()
            .ok_or_else(|| AirPlayError::InvalidState("no session keys".to_owned()))?
            .shared_secret
            .clone();
        // The base key comes from the pairing secret, or from an `ekey` unwrapped once through the
        // extension and composed with it.
        let base = match self.mirror.marker {
            Some(MirrorMarker::WrappedKey) => {
                let Some(ekey) = self.mirror.ekey.clone() else {
                    return status(400, "Bad Request"); // wrapped-key marker but no `ekey`
                };
                if ekey.is_empty() || ekey.len() > WRAPPED_KEY_MAX {
                    return status(400, "Bad Request"); // length-checked before the extension sees it
                }
                let Some(session) = self.ext_session.as_mut() else {
                    // An extension is configured, but no exchange ran on this connection.
                    return status(501, "Not Implemented");
                };
                match session.unwrap_session_key(&ekey) {
                    Ok(session_key) => MirrorKey::from_session_key(&session_key, &shared),
                    Err(_) => {
                        self.ext_session = None; // drop a failing session, as the relay does
                        return status(400, "Bad Request");
                    }
                }
            }
            _ => MirrorKey::from_pairing(&shared)?,
        };
        let key = base.stream(id);
        let data_port = ports.allocate_port(PortKind::MirrorData)?;
        self.mirror.stream_ids.push(id);
        self.mirror_ports.push((PortKind::MirrorData, data_port));
        self.events.push_back(ReceiverEvent::MirrorStream {
            stream_connection_id: id,
            data_port,
            key,
        });
        let mut body = plist::Dictionary::new();
        body.insert(
            "streams".into(),
            Value::Array(vec![MirrorStreamReply { data_port }.to_value()]),
        );
        Ok(plist_response(protocol, encode(&body)?))
    }

    fn set_parameter(&mut self, request: &Request) -> Result<()> {
        let content_type = request
            .headers
            .get("Content-Type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.starts_with("image/") {
            self.events.push_back(ReceiverEvent::Artwork {
                content_type,
                data: request.body.clone(),
            });
        } else if content_type == crate::dmap::METADATA_CONTENT_TYPE {
            self.events
                .push_back(ReceiverEvent::Metadata(NowPlaying::decode(&request.body)?));
        } else {
            let text = String::from_utf8_lossy(&request.body);
            for line in text.lines() {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                match name.trim().to_ascii_lowercase().as_str() {
                    "volume" => {
                        if let Ok(db) = value.trim().parse::<f64>() {
                            if db.is_finite() {
                                self.volume = db.clamp(-144.0, 0.0);
                                self.events.push_back(ReceiverEvent::Volume(self.volume));
                            }
                        }
                    }
                    "progress" => {
                        self.events
                            .push_back(ReceiverEvent::Progress(ReceiverProgress::parse(
                                value.trim(),
                            )))
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The gate every URL-playback route passes: switch on (else 404) and the connection
    /// **pair-verified** (else 403). Returns the refusal, or `None` to go on.
    fn url_playback_gate(&self, protocol: Protocol) -> Option<Response> {
        if !self.config.switches().url_playback() {
            return Some(Response::new(protocol, 404, "Not Found", Vec::new()));
        }
        if !matches!(self.encrypted_by, Some(EncryptedBy::PairVerify { .. })) {
            return Some(Response::new(protocol, 403, "Forbidden", Vec::new()));
        }
        None
    }

    /// Bounds `POST /play` and `PUT /photo` to [`URL_PLAYBACK_MAX_PER_SECOND`] a second so a sender
    /// cannot thrash the player. Returns a `429` to refuse, or `None` (and records this one).
    fn media_push_rate_refusal(&mut self, protocol: Protocol) -> Option<Response> {
        let now = self.now;
        while self
            .media_push_times
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= Duration::from_secs(1))
        {
            self.media_push_times.pop_front();
        }
        if self.media_push_times.len() >= URL_PLAYBACK_MAX_PER_SECOND as usize {
            return Some(Response::new(
                protocol,
                429,
                "Too Many Requests",
                Vec::new(),
            ));
        }
        self.media_push_times.push_back(now);
        None
    }

    /// `POST /play`: a media URL to play, in a binary plist or `text/parameters` body.
    fn play_request(&mut self, protocol: Protocol, request: &Request) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        if let Some(refusal) = self.media_push_rate_refusal(protocol) {
            return Ok(refusal);
        }
        let Some((url, start_position)) = parse_play_body(&request.body) else {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        };
        if url.len() > MAX_PLAY_URL_BYTES || !media_url_allowed(&url) {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        }
        self.events.push_back(ReceiverEvent::PlayUrl {
            url,
            start_position,
        });
        Ok(ok(protocol))
    }

    /// `POST /rate?value=X`: 0 pauses, positive plays.
    fn rate_request(&mut self, protocol: Protocol, request: &Request) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        let Some(value) = query_number(&request.uri, "value") else {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        };
        self.events.push_back(ReceiverEvent::Rate { value });
        Ok(ok(protocol))
    }

    /// `POST /scrub?position=X`: seek to `X` seconds.
    fn scrub_request(&mut self, protocol: Protocol, request: &Request) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        let Some(position) = query_number(&request.uri, "position") else {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        };
        self.events.push_back(ReceiverEvent::Scrub { position });
        Ok(ok(protocol))
    }

    /// `GET /scrub`: answers the minimal valid shape; live playback state is not reported.
    fn playback_position(&self, protocol: Protocol) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        let mut response = Response::new(
            protocol,
            200,
            "OK",
            b"duration: 0.000000\r\nposition: 0.000000\r\n".to_vec(),
        );
        response
            .headers
            .set("Content-Type", crate::session::TEXT_PARAMETERS_CONTENT_TYPE);
        Ok(response)
    }

    /// `GET /playback-info`: a minimal valid plist with no live state.
    fn playback_info(&self, protocol: Protocol) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        let mut info = plist::Dictionary::new();
        info.insert("duration".into(), Value::Real(0.0));
        info.insert("position".into(), Value::Real(0.0));
        info.insert("rate".into(), Value::Real(0.0));
        info.insert("readyToPlay".into(), Value::Boolean(false));
        Ok(plist_response(protocol, encode(&info)?))
    }

    /// `POST /stop`: stop URL/photo playback.
    fn stop_playback(&mut self, protocol: Protocol) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        self.events.push_back(ReceiverEvent::StopPlayback);
        Ok(ok(protocol))
    }

    /// `PUT /photo`: an image to show, bounded to [`MAX_PHOTO_BYTES`].
    fn photo_request(&mut self, protocol: Protocol, request: &Request) -> Result<Response> {
        if let Some(refusal) = self.url_playback_gate(protocol) {
            return Ok(refusal);
        }
        if let Some(refusal) = self.media_push_rate_refusal(protocol) {
            return Ok(refusal);
        }
        // Reject an oversize photo on its declared `Content-Length`; the body length is the
        // fallback.
        let declared = request
            .headers
            .get("Content-Length")
            .and_then(|v| v.trim().parse::<usize>().ok());
        if declared.is_some_and(|n| n > MAX_PHOTO_BYTES) || request.body.len() > MAX_PHOTO_BYTES {
            return Ok(Response::new(
                protocol,
                413,
                "Request Entity Too Large",
                Vec::new(),
            ));
        }
        let content_type = request
            .headers
            .get("Content-Type")
            .unwrap_or("image/jpeg")
            .to_ascii_lowercase();
        if request.body.is_empty() || !content_type.starts_with("image/") {
            return Ok(Response::new(protocol, 400, "Bad Request", Vec::new()));
        }
        self.events.push_back(ReceiverEvent::Photo {
            data: request.body.clone(),
            content_type,
        });
        Ok(ok(protocol))
    }
}

/// The largest `PUT /photo` accepted; larger is refused `413`.
pub const MAX_PHOTO_BYTES: usize = 3 * 1024 * 1024;

/// The longest `Content-Location` URL a `POST /play` may carry.
pub const MAX_PLAY_URL_BYTES: usize = 4096;

/// `POST /play` + `PUT /photo` accepted from one connection in any one second.
pub const URL_PLAYBACK_MAX_PER_SECOND: u32 = 4;

/// A query parameter parsed as a finite number; `None` if absent or not finite.
fn query_number(uri: &str, key: &str) -> Option<f64> {
    let query = uri.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name != key {
            return None;
        }
        value.parse::<f64>().ok().filter(|v| v.is_finite())
    })
}

/// Whether a media URL is one the receiver will hand its player: `http`/`https` only, no user name
/// or password. The host checks the host name against its own and link-local addresses.
fn media_url_allowed(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    !authority.is_empty() && !authority.contains('@')
}

/// `POST /play`'s body: a binary plist or `text/parameters` with `Content-Location` and
/// `Start-Position`. Returns the URL and start position (clamped to `[0, 1]`, 0 if absent).
fn parse_play_body(body: &[u8]) -> Option<(String, f64)> {
    if let Some(dict) = plist_dictionary(body) {
        if let Some(url) = dict.get("Content-Location").and_then(Value::as_string) {
            let start = dict
                .get("Start-Position")
                .and_then(Value::as_real)
                .filter(|v| v.is_finite())
                .unwrap_or(0.0)
                .clamp(0.0, 1.0);
            return Some((url.to_owned(), start));
        }
    }
    let text = String::from_utf8_lossy(body);
    let mut url = None;
    let mut start = 0.0;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-location" => url = Some(value.trim().to_owned()),
            "start-position" => {
                if let Ok(v) = value.trim().parse::<f64>() {
                    if v.is_finite() {
                        start = v.clamp(0.0, 1.0);
                    }
                }
            }
            _ => {}
        }
    }
    url.filter(|u| !u.is_empty()).map(|u| (u, start))
}

/// The distinct non-mirror stream types a `TEARDOWN` body's `streams` names.
fn stream_types_named(body: &[u8]) -> Vec<u64> {
    let mut types = Vec::new();
    let streams = plist_dictionary(body)
        .and_then(|d| d.get("streams").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    for stream in streams.iter().filter_map(Value::as_dictionary) {
        let Some(stream_type) = unsigned(stream, "type") else {
            continue;
        };
        #[cfg(feature = "mirror")]
        if stream_type == crate::mirror::STREAM_TYPE {
            continue;
        }
        if !types.contains(&stream_type) {
            types.push(stream_type);
        }
    }
    types
}

/// Whether a `TEARDOWN` body's `streams` names a `type: 110` stream.
#[cfg(feature = "mirror")]
fn names_mirror_stream(body: &[u8]) -> bool {
    plist_dictionary(body)
        .and_then(|d| d.get("streams").and_then(Value::as_array).cloned())
        .is_some_and(|streams| {
            streams.iter().any(|s| {
                s.as_dictionary()
                    .and_then(|d| d.get("type"))
                    .and_then(crate::mirror::setup::integer)
                    == Some(crate::mirror::STREAM_TYPE)
            })
        })
}

fn ok(protocol: Protocol) -> Response {
    Response::new(protocol, 200, "OK", Vec::new())
}

fn plist_response(protocol: Protocol, body: Vec<u8>) -> Response {
    let mut response = Response::new(protocol, 200, "OK", body);
    response
        .headers
        .set("Content-Type", crate::session::PLIST_CONTENT_TYPE);
    response
}

fn encode(dict: &plist::Dictionary) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(dict.clone()))
        .map_err(|e| AirPlayError::Protocol(format!("could not encode a reply: {e}")))?;
    Ok(out)
}

fn plist_dictionary(body: &[u8]) -> Option<plist::Dictionary> {
    if body.is_empty() {
        return None;
    }
    crate::safe_plist::from_bytes(body).ok()?.into_dictionary()
}

fn unsigned(dict: &plist::Dictionary, key: &str) -> Option<u64> {
    dict.get(key).and_then(Value::as_unsigned_integer)
}

/// `progress: start/current/end`, an AirPlay `SET_PARAMETER`: three RTP timestamps in the stream's
/// own clock rate. Parsing never fails: an unparseable value leaves that field `None` and
/// [`Self::raw`] is kept. Converting to seconds needs the stream's sample rate, which the caller
/// has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiverProgress {
    /// The header's value, unparsed.
    pub raw: String,
    /// `start`: the RTP time playback began at.
    pub start: Option<RtpTimestamp>,
    /// `current`: the RTP time now.
    pub current: Option<RtpTimestamp>,
    /// `end`: the RTP time the item ends at.
    pub end: Option<RtpTimestamp>,
}

impl ReceiverProgress {
    /// Parses `start/current/end`. Never panics on any input.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut fields = raw.split('/').map(str::trim);
        let mut next = || {
            fields
                .next()
                .and_then(|f| f.parse().ok())
                .map(RtpTimestamp::new)
        };
        Self {
            raw: raw.to_owned(),
            start: next(),
            current: next(),
            end: next(),
        }
    }
}

/// `RTP-Info: seq=N;rtptime=M` — either half may be missing.
#[must_use]
pub fn rtp_info(header: Option<&str>) -> (Option<u16>, Option<RtpTimestamp>) {
    let mut sequence = None;
    let mut rtp_time = None;
    for part in header.unwrap_or_default().split(';') {
        match part.trim().split_once('=') {
            Some(("seq", v)) => sequence = v.trim().parse().ok(),
            Some(("rtptime", v)) => rtp_time = v.trim().parse().ok().map(RtpTimestamp::new),
            _ => {}
        }
    }
    (sequence, rtp_time)
}

#[cfg(test)]
mod url_playback_tests {
    use super::{media_url_allowed, parse_play_body, query_number};

    #[test]
    fn only_http_and_https_urls_without_credentials_are_allowed() {
        assert!(media_url_allowed("http://192.0.2.50:8080/v.mp4"));
        assert!(media_url_allowed("https://example.test/a/b.m3u8?x=1"));
        assert!(media_url_allowed("http://host/path"));
        // Refused: other schemes, credentials in the authority, an empty authority.
        assert!(!media_url_allowed("ftp://host/x"));
        assert!(!media_url_allowed("file:///etc/passwd"));
        assert!(!media_url_allowed("httpx://host/x"));
        assert!(!media_url_allowed("http://user:pass@host/x"));
        assert!(!media_url_allowed("https://user@host/x"));
        assert!(!media_url_allowed("http:///noauthority"));
        assert!(!media_url_allowed(""));
    }

    #[test]
    fn a_query_number_is_read_and_a_non_finite_or_missing_one_is_not() {
        assert_eq!(query_number("/rate?value=1.000000", "value"), Some(1.0));
        assert_eq!(query_number("/scrub?position=12.5", "position"), Some(12.5));
        assert_eq!(query_number("/rate?value=0", "value"), Some(0.0));
        assert_eq!(query_number("/rate?a=1&value=2&b=3", "value"), Some(2.0));
        assert_eq!(query_number("/rate", "value"), None);
        assert_eq!(query_number("/rate?value=nan", "value"), None);
        assert_eq!(query_number("/rate?value=inf", "value"), None);
        assert_eq!(query_number("/rate?value=abc", "value"), None);
    }

    #[test]
    fn a_play_body_is_read_from_text_or_a_plist_and_the_start_is_clamped() {
        // text/parameters
        let (url, start) =
            parse_play_body(b"Content-Location: http://host/v.mp4\r\nStart-Position: 0.25\r\n")
                .expect("a URL");
        assert_eq!(url, "http://host/v.mp4");
        assert!((start - 0.25).abs() < 1e-9);
        // Out-of-range start is clamped; a missing one is 0.
        assert_eq!(
            parse_play_body(b"Content-Location: http://h/x\r\nStart-Position: 9\r\n")
                .unwrap()
                .1,
            1.0
        );
        assert_eq!(
            parse_play_body(b"Content-Location: http://h/x\r\n")
                .unwrap()
                .1,
            0.0
        );
        // A binary plist with the same keys.
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "Content-Location".into(),
            plist::Value::String("http://h/y".into()),
        );
        dict.insert("Start-Position".into(), plist::Value::Real(0.5));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let (url, start) = parse_play_body(&body).expect("a URL");
        assert_eq!(url, "http://h/y");
        assert!((start - 0.5).abs() < 1e-9);
        // No Content-Location: nothing.
        assert!(parse_play_body(b"Start-Position: 0.5\r\n").is_none());
        assert!(parse_play_body(b"").is_none());
    }
}
