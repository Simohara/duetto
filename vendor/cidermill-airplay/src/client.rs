//! The sender's control connection. [`SenderConnection`] is the sans-io half: it stamps requests
//! (`CSeq`, `User-Agent`, the session headers), seals and opens the encrypted framing, and decodes
//! replies. It touches no socket, so any transport can drive it, blocking or async.
//! [`ControlChannel`] is the thin blocking wrapper that drives it over a [`Read`] + [`Write`]
//! stream, a `TcpStream` by default.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use rand_core::CryptoRng;

use super::cipher::EncryptedTransport;
use super::info::DeviceInfo;
#[cfg(feature = "legacy")]
use super::legacy::{self, LegacyCredentials, LegacyStep, PairSetupPin};
use super::pairing::{
    self, HapCredentials, PairSetup, PairVerify, SessionKeys, SetupMode, Step, TransientStyle,
};
use super::play::{self, PlaybackInfo};
use super::rtsp::{Decoder, Protocol, Request, Response};
use super::session::{self, EventChannel};
use super::tlv8::Tlv8;
use crate::error::{AirPlayError, Result};

/// Default AirPlay control port.
pub const AIRPLAY_PORT: u16 = 7000;

/// How long we wait for a receiver to answer; a liveness bound, not a latency target.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The status an idle receiver answers `/playback-info` and `/scrub` with (observed: tvOS 23L243,
/// empty body).
const IDLE_STATUS: u16 = 500;

/// Largest reply we will read into memory on the control channel.
const MAX_REPLY_BYTES: usize = 32 * 1024 * 1024;

/// AirPlay version in the `User-Agent`; assumed checked loosely. macOS 26.5.2 sends `950.7.1`.
const AIRPLAY_CLIENT_VERSION: &str = "540.31";

/// Request-line protocol token. Observed: a real Apple sender writes `RTSP/1.0`; receivers also
/// accepted `HTTP/1.1`.
pub const SESSION_PROTOCOL: Protocol = Protocol::Rtsp;

/// How a sender authenticates its control connection ([`ControlChannel::authenticate`]).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Auth<'a> {
    /// HAP pair-verify with a stored pairing; checks the receiver's identity.
    Stored(&'a HapCredentials),
    /// Transient pair-setup (fixed PIN, nothing stored) with its requests shaped as given.
    Transient(TransientStyle),
    /// Legacy pair-verify: authenticates the connection for the v1 media endpoints, no encryption.
    #[cfg(feature = "legacy")]
    Legacy(&'a LegacyCredentials),
}

/// The headers that set one pairing request apart; everything else is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingHeaders {
    /// `X-Apple-HKP`.
    pub hkp: String,
    /// `Content-Type`.
    pub content_type: &'static str,
    /// Whether `X-Apple-PD: 1` is sent.
    pub pd: bool,
    /// Whether `X-Apple-AbsoluteTime` is sent (and the iPhone's header order used).
    pub absolute_time: bool,
}

impl PairingHeaders {
    /// HAP pair-verify and PIN pair-setup: `X-Apple-HKP: 3` with `X-Apple-PD`.
    #[must_use]
    pub fn verify() -> Self {
        Self {
            hkp: pairing::constants::HKP_VERIFY.to_owned(),
            content_type: "application/octet-stream",
            pd: true,
            absolute_time: false,
        }
    }

    /// A transient pair-setup in `style`.
    #[must_use]
    pub fn transient(style: TransientStyle) -> Self {
        Self {
            hkp: style.hkp().to_owned(),
            content_type: style.content_type(),
            pd: style.sends_pd(),
            absolute_time: style.sends_absolute_time(),
        }
    }

    /// One of `style`'s abandoned pair-verify probes, with `X-Apple-HKP: hkp`.
    #[must_use]
    pub fn verify_probe(style: TransientStyle, hkp: u8) -> Self {
        Self {
            hkp: hkp.to_string(),
            content_type: "application/octet-stream",
            pd: true,
            absolute_time: style.sends_absolute_time(),
        }
    }
}

/// The sans-io state of a sender's control connection. [`Self::encode`] stamps and seals a request,
/// [`Self::push`] takes the receiver's bytes, [`Self::next_response`] yields replies.
pub struct SenderConnection {
    host: String,
    local_ip: IpAddr,
    sequence: u32,
    outstanding: std::collections::VecDeque<u32>,
    app_name: String,
    user_agent: String,
    client_name: String,
    session_id: String,
    rtsp_session_id: u32,
    dacp_id: String,
    active_remote: u32,
    protocol: Protocol,
    decoder: Decoder,
    encryption: Option<EncryptedTransport>,
    keys: Option<SessionKeys>,
    /// Why the connection was retired; every later request fails at once.
    failed: Option<String>,
}

impl std::fmt::Debug for SenderConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderConnection")
            .field("host", &self.host)
            .field("sequence", &self.sequence)
            .field("session_id", &self.session_id)
            .field("encrypted", &self.encryption.is_some())
            .finish_non_exhaustive()
    }
}

impl SenderConnection {
    /// A connection to `host` from `local_ip` (what [`Self::session_uri`] names), session ids drawn
    /// from `rng`.
    pub fn new(host: impl Into<String>, local_ip: IpAddr, rng: &mut dyn CryptoRng) -> Self {
        let app_name = crate::DEFAULT_CLIENT_NAME.to_owned();
        let session_id = new_session_id(rng);
        let rtsp_session_id = rng.next_u32();
        let dacp_id = format!("{:016X}", rng.next_u64());
        let active_remote = rng.next_u32();
        Self {
            host: host.into(),
            local_ip,
            sequence: 0,
            outstanding: std::collections::VecDeque::new(),
            // Observed: HomePod 27 answers 403 to any request whose User-Agent does not start
            // with `AirPlay/`, and `/play` refuses a bare product string.
            user_agent: user_agent(&app_name),
            client_name: app_name.clone(),
            app_name,
            session_id,
            rtsp_session_id,
            dacp_id,
            active_remote,
            protocol: SESSION_PROTOCOL,
            decoder: Decoder::new(),
            encryption: None,
            keys: None,
            failed: None,
        }
    }

    /// The receiver's host, sent as `Host`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The local address the session URI names.
    #[must_use]
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// The request-line protocol token.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Overrides the request-line protocol token ([`SESSION_PROTOCOL`]).
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }

    /// The app name in the `User-Agent` (`"AirPlay/{ver} {app_name}/{ver}"`).
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Sets the app name in the `User-Agent`, from the next request on.
    pub fn set_app_name(&mut self, name: impl Into<String>) {
        self.app_name = name.into();
        self.user_agent = user_agent(&self.app_name);
    }

    /// The name a receiver shows for this sender (`X-Apple-Client-Name`).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// Sets the name a receiver shows for this sender.
    pub fn set_client_name(&mut self, name: impl Into<String>) {
        self.client_name = name.into();
    }

    /// The UUID the media endpoints carry as `X-Apple-Session-ID`.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The numeric id at the end of [`Self::session_uri`].
    #[must_use]
    pub fn rtsp_session_id(&self) -> u32 {
        self.rtsp_session_id
    }

    /// Sets the numeric session id (random by default), to replay a recorded session.
    pub fn set_rtsp_session_id(&mut self, id: u32) {
        self.rtsp_session_id = id;
    }

    /// The session URI a v2 `SETUP`/`RECORD` is addressed to: `rtsp://<local ip>/<id>` (ours).
    #[must_use]
    pub fn session_uri(&self) -> String {
        format!("rtsp://{}/{}", self.local_ip, self.rtsp_session_id)
    }

    /// The `DACP-ID` (and `Client-Instance`) this session announces.
    #[must_use]
    pub fn dacp_id(&self) -> &str {
        &self.dacp_id
    }

    /// The `Active-Remote` token that goes with [`Self::dacp_id`].
    #[must_use]
    pub fn active_remote(&self) -> u32 {
        self.active_remote
    }

    /// Whether the connection has switched to encrypted framing.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// The keys [`Self::enable_encryption`] switched to, for the event channel and stream keys.
    #[must_use]
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }

    /// Switches to ChaCha20-Poly1305 framing (see [`super::cipher`]) from the next request; refuses
    /// a second call (re-keying desyncs the counters).
    pub fn enable_encryption(&mut self, keys: &SessionKeys) -> Result<()> {
        if self.encryption.is_some() {
            return Err(AirPlayError::InvalidState(
                "the control channel is already encrypted".to_owned(),
            ));
        }
        self.encryption = Some(EncryptedTransport::new(keys));
        self.keys = Some(keys.clone());
        Ok(())
    }

    /// Why an earlier failure retired the connection, if one did.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Retires the connection: later calls fail with [`AirPlayError::ConnectionRetired`]; a
    /// transport calls this on a failed read or write.
    pub fn retire(&mut self, reason: impl Into<String>) {
        if self.failed.is_none() {
            self.failed = Some(reason.into());
        }
    }

    fn usable(&self) -> Result<()> {
        match &self.failed {
            Some(why) => Err(AirPlayError::ConnectionRetired {
                reason: why.clone(),
            }),
            None => Ok(()),
        }
    }

    /// Stamps `Host`, `User-Agent`, `CSeq` and `Connection` on `request`; returns the bytes to
    /// write, sealed once encrypted.
    ///
    /// # Errors
    ///
    /// A request [`Request::validate`] refuses (a line break in a header, say), before anything is
    /// sealed or counted; a retired connection.
    pub fn encode(&mut self, mut request: Request) -> Result<Vec<u8>> {
        self.usable()?;
        let pyatv_pairing = request.protocol == Protocol::Http
            && request.headers.get("User-Agent") == Some("AirPlay/320.20");
        request.headers.set("Host", self.host.clone());
        if request.headers.get("User-Agent").is_none() {
            request.headers.set("User-Agent", self.user_agent.clone());
        }
        if !pyatv_pairing {
            request.headers.set("CSeq", self.sequence.to_string());
        }
        request.headers.set("Connection", "keep-alive");
        let plain = request.try_encode()?;
        let wire = match &mut self.encryption {
            Some(transport) => match transport.seal(&plain) {
                Ok(wire) => wire,
                Err(e) => {
                    // The frame counter may have advanced: out of step.
                    self.failed = Some(e.to_string());
                    return Err(e);
                }
            },
            None => plain,
        };
        self.outstanding.push_back(self.sequence);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(wire)
    }

    /// Feeds bytes the receiver sent. A frame that does not open retires the connection.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.usable()?;
        let Some(transport) = &mut self.encryption else {
            self.decoder.push(bytes);
            return Ok(());
        };
        transport.push(bytes);
        loop {
            match transport.open_next() {
                Ok(Some(plaintext)) => self.decoder.push(&plaintext),
                Ok(None) => return Ok(()),
                Err(e) => {
                    self.failed = Some(e.to_string());
                    return Err(e);
                }
            }
        }
    }

    /// The next complete reply, or `None` until more bytes arrive. A reply that does not decode or
    /// is out of `CSeq` order retires the connection.
    pub fn next_response(&mut self) -> Result<Option<Response>> {
        self.usable()?;
        let result = self.decode_response();
        if let Err(e) = &result {
            self.failed = Some(e.to_string());
        }
        result
    }

    /// The CSeq the next encoded request will carry. Used by concurrent RTSP
    /// transports to correlate replies without coupling them to TCP read order.
    #[must_use]
    pub fn next_sequence(&self) -> u32 {
        self.sequence
    }

    /// Forget a request whose application deadline expired. Its eventual reply
    /// is still decoded, but must not satisfy any later request.
    pub fn forget_response(&mut self, sequence: u32) {
        self.outstanding.retain(|pending| *pending != sequence);
    }

    /// Decode a reply without enforcing FIFO request order. pyatv dispatches
    /// RTSP replies by CSeq, so a delayed feedback reply may follow another
    /// control reply. The caller must perform that CSeq correlation itself.
    /// Framing, authentication and maximum reply limits remain enforced.
    pub fn next_response_unordered(&mut self) -> Result<Option<Response>> {
        self.usable()?;
        let result = (|| {
            if let Some(response) = self.decoder.next_response()? {
                if let Some(sequence) = response.sequence() {
                    self.forget_response(sequence);
                }
                return Ok(Some(response));
            }
            if self.decoder.buffered() > MAX_REPLY_BYTES {
                return Err(AirPlayError::Protocol(
                    "receiver sent more than the reply cap without completing a message".to_owned(),
                ));
            }
            Ok(None)
        })();
        if let Err(error) = &result {
            self.failed = Some(error.to_string());
        }
        result
    }

    fn decode_response(&mut self) -> Result<Option<Response>> {
        if let Some(response) = self.decoder.next_response()? {
            let expected = self.outstanding.pop_front();
            if let (Some(reply), Some(expected)) = (response.sequence(), expected) {
                if reply != expected {
                    return Err(AirPlayError::Protocol(format!(
                        "CSeq mismatch: sent {expected}, reply has {reply}"
                    )));
                }
            }
            return Ok(Some(response));
        }
        if self.decoder.buffered() > MAX_REPLY_BYTES {
            return Err(AirPlayError::Protocol(
                "receiver sent more than the reply cap without completing a message".to_owned(),
            ));
        }
        Ok(None)
    }

    /// Encrypted bytes that arrived but did not open (after [`AirPlayError::Decrypt`]), to diagnose
    /// which keys the receiver used.
    #[must_use]
    pub fn unopened_ciphertext(&self) -> &[u8] {
        match &self.encryption {
            Some(transport) => transport.pending_bytes(),
            None => &[],
        }
    }

    fn new_request(&self, method: &str, uri: impl Into<String>, body: Vec<u8>) -> Request {
        Request::new(method, uri, self.protocol, body)
    }

    /// Adds the session headers `DACP-ID`, `Active-Remote` and `Client-Instance`.
    #[must_use]
    pub fn with_session_headers(&self, mut request: Request) -> Request {
        request.headers.set("DACP-ID", self.dacp_id.clone());
        request
            .headers
            .set("Active-Remote", self.active_remote.to_string());
        request.headers.set("Client-Instance", self.dacp_id.clone());
        request
    }

    /// `GET /info`.
    #[must_use]
    pub fn info_request(&self) -> Request {
        self.new_request("GET", "/info", Vec::new())
    }

    /// A pairing `POST` of `body` to `path`; `X-Apple-HKP` is required (a current Apple TV answers
    /// 470 without it).
    #[must_use]
    pub fn pairing_request(&self, path: &str, body: &Tlv8, headers: &PairingHeaders) -> Request {
        let mut request = self.new_request("POST", path, body.encode());
        // pyatv 0.18 transient authentication uses HTTP pairing requests, not
        // the iOS26 RTSP variant. Keep its observed header set distinct.
        if headers.hkp == "4" && headers.content_type == "application/octet-stream"
            && !headers.pd && !headers.absolute_time
        {
            request.protocol = Protocol::Http;
            request.headers.set("Content-Type", headers.content_type);
            request.headers.set(pairing::constants::HKP_HEADER, headers.hkp.clone());
            request.headers.set("User-Agent", "AirPlay/320.20");
            return request;
        }
        let name = self.client_name.clone();
        let h = &mut request.headers;
        if headers.absolute_time {
            // The iPhone's header order.
            let unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            h.set(
                crate::sequence::ABSOLUTE_TIME_HEADER,
                crate::sequence::cf_absolute_time(unix).to_string(),
            );
            h.set(pairing::constants::HKP_HEADER, headers.hkp.clone());
            h.set(pairing::constants::CLIENT_NAME_HEADER, name);
            if headers.pd {
                h.set(pairing::constants::PD_HEADER, pairing::constants::PD_VALUE);
            }
            h.set("Content-Type", headers.content_type);
        } else {
            h.set("Content-Type", headers.content_type);
            h.set(pairing::constants::HKP_HEADER, headers.hkp.clone());
            if headers.pd {
                h.set(pairing::constants::PD_HEADER, pairing::constants::PD_VALUE);
            }
            h.set(pairing::constants::CLIENT_NAME_HEADER, name);
        }
        request
    }

    /// `POST /pair-pin-start`, with `X-Apple-HKP: hkp` and the HAP headers when given.
    #[must_use]
    pub fn pin_start_request(&self, hkp: Option<&str>) -> Request {
        let mut request = self.new_request("POST", pairing::constants::PIN_START_PATH, Vec::new());
        request.headers.set("Content-Length", "0");
        if let Some(hkp) = hkp {
            request.headers.set(pairing::constants::HKP_HEADER, hkp);
            request
                .headers
                .set(pairing::constants::PD_HEADER, pairing::constants::PD_VALUE);
            request.headers.set(
                pairing::constants::CLIENT_NAME_HEADER,
                self.client_name.clone(),
            );
        }
        request
    }

    /// `POST` of an opaque `body` with `content_type` and `X-Apple-Session-ID`.
    #[must_use]
    pub fn post_bytes_request(&self, path: &str, body: Vec<u8>, content_type: &str) -> Request {
        let mut request = self.new_request("POST", path, body);
        request.headers.set("Content-Type", content_type);
        request
            .headers
            .set("X-Apple-Session-ID", self.session_id.clone());
        request
    }

    /// The v1 `POST /play`; `start_position` is a fraction of the duration.
    pub fn play_url_v1_request(&self, url: &str, start_position: f64) -> Result<Request> {
        let body = play::play_body(url, start_position, &self.session_id)?;
        let mut request = self.new_request("POST", "/play", body);
        request.headers.set("Content-Type", play::PLAY_CONTENT_TYPE);
        self.play_headers(&mut request);
        Ok(request)
    }

    /// The v2 `POST /play`; `start_position_seconds` is in seconds.
    pub fn play_url_request(&self, url: &str, start_position_seconds: f64) -> Result<Request> {
        let body = session::play_body(url, start_position_seconds, &self.session_id)?;
        let mut request = self.new_request("POST", "/play", body);
        request
            .headers
            .set("Content-Type", session::PLIST_CONTENT_TYPE);
        self.play_headers(&mut request);
        Ok(self.with_session_headers(request))
    }

    fn play_headers(&self, request: &mut Request) {
        request
            .headers
            .set("X-Apple-ProtocolVersion", play::PLAY_PROTOCOL_VERSION);
        request
            .headers
            .set("X-Apple-Stream-ID", play::PLAY_STREAM_ID);
        request
            .headers
            .set("X-Apple-Session-ID", self.session_id.clone());
    }

    /// The session `SETUP` for `params`.
    pub fn setup_request(&self, params: &session::SetupParams) -> Result<Request> {
        let body = session::setup_body(params)?;
        Ok(self.plist_session_request("SETUP", self.session_uri(), body))
    }

    /// `RECORD`.
    #[must_use]
    pub fn record_request(&self) -> Request {
        self.with_session_headers(self.new_request("RECORD", self.session_uri(), Vec::new()))
    }

    /// `POST /feedback`, the keep-alive.
    #[must_use]
    pub fn feedback_request(&self) -> Request {
        self.with_session_headers(self.new_request("POST", "/feedback", Vec::new()))
    }

    /// `TEARDOWN` of the whole session.
    #[must_use]
    pub fn teardown_request(&self) -> Request {
        self.with_session_headers(self.new_request("TEARDOWN", self.session_uri(), Vec::new()))
    }

    /// `POST /rate?value=1.000000`: the v2 rate, six decimals.
    #[must_use]
    pub fn set_rate_request(&self, rate: f64) -> Request {
        self.with_session_headers(self.new_request(
            "POST",
            format!("/rate?value={rate:.6}"),
            Vec::new(),
        ))
    }

    /// `PUT /setProperty?<name>` with a `{"value": …}` plist body.
    pub fn set_property_request(&self, name: &str, value: plist::Value) -> Result<Request> {
        let body = session::property_body(value)?;
        Ok(self.plist_session_request("PUT", format!("/setProperty?{name}"), body))
    }

    /// The v1 `POST /rate`: 0 pauses, 1 resumes.
    #[must_use]
    pub fn set_rate_v1_request(&self, rate: f32) -> Request {
        self.media_post_request(&format!("/rate?value={rate}"))
    }

    /// `POST /scrub` to an absolute position in seconds (v1). A position that is not finite is sent
    /// as 0.
    #[must_use]
    pub fn scrub_request(&self, position_seconds: f64) -> Request {
        let position_seconds = if position_seconds.is_finite() {
            position_seconds
        } else {
            0.0
        };
        self.media_post_request(&format!("/scrub?position={position_seconds}"))
    }

    /// `POST /stop` (v1).
    #[must_use]
    pub fn stop_request(&self) -> Request {
        self.media_post_request("/stop")
    }

    /// `GET /playback-info`.
    #[must_use]
    pub fn playback_info_request(&self) -> Request {
        let mut request = self.new_request("GET", "/playback-info", Vec::new());
        request
            .headers
            .set("X-Apple-Session-ID", self.session_id.clone());
        request
    }

    /// `OPTIONS *`.
    #[must_use]
    pub fn options_request(&self) -> Request {
        self.new_request("OPTIONS", "*", Vec::new())
    }

    /// The `type: 110` stream `SETUP` of a pairing-keyed mirror.
    #[cfg(feature = "mirror")]
    pub fn mirror_stream_setup_request(&self, stream_connection_id: u64) -> Result<Request> {
        let body = crate::mirror::MirrorStreamSetup {
            stream_connection_id,
        }
        .to_body()?;
        Ok(self.plist_session_request("SETUP", self.session_uri(), body))
    }

    /// The `TEARDOWN` that ends the mirror stream and keeps the session.
    #[cfg(feature = "mirror")]
    pub fn mirror_teardown_request(&self) -> Result<Request> {
        let body = crate::mirror::setup::teardown_body()?;
        Ok(self.plist_session_request("TEARDOWN", self.session_uri(), body))
    }

    fn plist_session_request(&self, method: &str, uri: String, body: Vec<u8>) -> Request {
        let mut request = self.new_request(method, uri, body);
        request
            .headers
            .set("Content-Type", session::PLIST_CONTENT_TYPE);
        self.with_session_headers(request)
    }

    fn media_post_request(&self, path: &str) -> Request {
        let mut request = self.new_request("POST", path, Vec::new());
        request.headers.set("Content-Length", "0");
        request
            .headers
            .set("X-Apple-Session-ID", self.session_id.clone());
        request
    }
}

/// A media session [`ControlChannel::start_media_session`] opened: keep it alive while the session
/// runs and drop it after [`ControlChannel::teardown`].
#[derive(Debug)]
#[non_exhaustive]
pub struct MediaSession {
    /// The session `SETUP` reply.
    pub setup: session::SetupResponse,
    /// Answers the receiver's NTP timing requests.
    pub timing: crate::timing::TimingServer,
    /// The receiver's event channel, when its `SETUP` named a port.
    pub events: Option<EventChannel>,
}

/// Builds a [`ControlChannel`]: `ControlChannel::builder(host).port(..).timeout(..).connect()`.
#[derive(Debug, Clone)]
#[must_use]
pub struct ControlChannelBuilder {
    host: String,
    port: u16,
    timeout: Duration,
    app_name: Option<String>,
    client_name: Option<String>,
    protocol: Protocol,
}

impl ControlChannelBuilder {
    /// The receiver's control port. Default [`AIRPLAY_PORT`].
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// The connect, read and write timeout, and the longest one request and its reply may take
    /// ([`ControlChannel::set_timeout`]). Default [`DEFAULT_TIMEOUT`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The app name in the `User-Agent`. Default [`crate::DEFAULT_CLIENT_NAME`].
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// The name a receiver shows for this sender. Default the app name.
    pub fn client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    /// The request-line protocol token. Default [`SESSION_PROTOCOL`].
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// The configured [`SenderConnection`] for the caller's own transport, from `local_ip`.
    pub fn sans_io(self, local_ip: IpAddr) -> SenderConnection {
        let mut connection = SenderConnection::new(self.host, local_ip, &mut crate::OsRng);
        connection.set_protocol(self.protocol);
        if let Some(app_name) = self.app_name {
            connection.set_client_name(app_name.clone());
            connection.set_app_name(app_name);
        }
        if let Some(client_name) = self.client_name {
            connection.set_client_name(client_name);
        }
        connection
    }

    /// A channel over a stream the caller opened from `local_ip`.
    pub fn over<S: Read + Write>(self, stream: S, local_ip: IpAddr) -> ControlChannel<S> {
        let timeout = self.timeout;
        let mut channel = ControlChannel::from_stream(stream, self.sans_io(local_ip));
        channel.set_timeout(timeout);
        channel
    }

    /// Connects over TCP.
    pub fn connect(self) -> Result<ControlChannel> {
        let resolved = resolve(&self.host, self.port)?;
        let timeout = self.timeout;
        let stream = TcpStream::connect_timeout(&resolved, timeout).map_err(|source| {
            AirPlayError::Connect {
                addr: resolved.to_string(),
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| AirPlayError::io_context("set read timeout", e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| AirPlayError::io_context("set write timeout", e))?;
        // Nagle would add a round trip to every small pairing step.
        stream.set_nodelay(true).ok();
        let local_ip = stream
            .local_addr()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |addr| addr.ip());
        Ok(self.over(stream, local_ip))
    }
}

/// A blocking AirPlay control channel over a stream: a [`SenderConnection`] driven by `S`.
pub struct ControlChannel<S = TcpStream> {
    stream: S,
    connection: SenderConnection,
    timeout: Duration,
}

impl<S> std::fmt::Debug for ControlChannel<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlChannel")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl ControlChannel {
    /// Starts building a TCP control channel to `host`.
    pub fn builder(host: impl Into<String>) -> ControlChannelBuilder {
        ControlChannelBuilder {
            host: host.into(),
            port: AIRPLAY_PORT,
            timeout: DEFAULT_TIMEOUT,
            app_name: None,
            client_name: None,
            protocol: SESSION_PROTOCOL,
        }
    }

    /// Connects to `host` on [`AIRPLAY_PORT`] with every default.
    pub fn connect_default(host: impl Into<String>) -> Result<Self> {
        Self::builder(host).connect()
    }
}

impl<S: Read + Write> ControlChannel<S> {
    /// A channel over a stream the caller opened, driving `connection`, with [`DEFAULT_TIMEOUT`].
    pub fn from_stream(stream: S, connection: SenderConnection) -> Self {
        Self {
            stream,
            connection,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The sans-io state.
    #[must_use]
    pub fn connection(&self) -> &SenderConnection {
        &self.connection
    }

    /// The sans-io state, to change a setting mid-connection.
    pub fn connection_mut(&mut self) -> &mut SenderConnection {
        &mut self.connection
    }

    /// The stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The stream, mutably. Bytes written or read past the channel put it out of step.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// The stream and the sans-io state.
    pub fn into_parts(self) -> (S, SenderConnection) {
        (self.stream, self.connection)
    }

    /// Sets the timeout: the longest one request and its reply may take (checked between reads),
    /// and what [`Self::open_event_channel`] uses. A stream's own read and write timeouts are the
    /// caller's ([`ControlChannelBuilder::connect`] sets both to the same value).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The timeout ([`Self::set_timeout`]).
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The host this channel talks to.
    #[must_use]
    pub fn host(&self) -> &str {
        self.connection.host()
    }

    /// [`SenderConnection::session_uri`].
    #[must_use]
    pub fn session_uri(&self) -> String {
        self.connection.session_uri()
    }

    /// [`SenderConnection::rtsp_session_id`].
    #[must_use]
    pub fn rtsp_session_id(&self) -> u32 {
        self.connection.rtsp_session_id()
    }

    /// Whether the connection has switched to encrypted framing.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.connection.is_encrypted()
    }

    /// The session keys pairing produced, once encrypted.
    #[must_use]
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.connection.session_keys()
    }

    /// [`SenderConnection::enable_encryption`].
    pub fn enable_encryption(&mut self, keys: &SessionKeys) -> Result<()> {
        self.connection.enable_encryption(keys)
    }

    /// Whether, and why, an earlier failure retired the connection.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.connection.failure()
    }

    /// Sends a request and reads its reply; any status is returned. A failed read or write retires
    /// the connection.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        let result = self.exchange(request);
        if let Err(AirPlayError::Io(e)) = &result {
            self.connection.retire(e.to_string());
        }
        result
    }

    /// One request and its reply, within [`Self::timeout`] of starting: a receiver that sends
    /// its reply a byte at a time cannot hold the caller past it. The deadline is checked between
    /// reads, so over a stream whose reads time out after `timeout` (as [`ControlChannelBuilder::connect`]
    /// sets) an exchange ends within twice `timeout`.
    fn exchange(&mut self, request: Request) -> Result<Response> {
        let deadline = std::time::Instant::now() + self.timeout;
        let wire = self.connection.encode(request)?;
        self.stream.write_all(&wire)?;
        self.stream.flush().ok();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            if let Some(response) = self.connection.next_response()? {
                return Ok(response);
            }
            if std::time::Instant::now() >= deadline {
                return Err(AirPlayError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the receiver's reply did not arrive within the timeout",
                )));
            }
            let read = self.stream.read(&mut buffer)?;
            if read == 0 {
                return Err(AirPlayError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "receiver closed the connection mid-reply",
                )));
            }
            self.connection.push(&buffer[..read])?;
        }
    }

    fn checked(&mut self, what: &str, request: Request) -> Result<Response> {
        let response = self.request(request)?;
        if !response.is_success() {
            return Err(format_error(what, response.status, &response.body));
        }
        Ok(response)
    }

    /// Sends a request built elsewhere (e.g. by [`crate::audio::AudioSendState`]) with the session
    /// headers.
    pub fn session_request(&mut self, request: Request) -> Result<Response> {
        let request = self.connection.with_session_headers(request);
        self.request(request)
    }

    /// `GET /info` — what the receiver says about itself.
    pub fn device_info(&mut self) -> Result<DeviceInfo> {
        let request = self.connection.info_request();
        DeviceInfo::parse(&self.checked("/info", request)?.body)
    }

    /// POSTs a TLV8 body to a pairing endpoint with `X-Apple-HKP: hkp` and decodes the reply.
    pub fn post_tlv(&mut self, path: &str, body: &Tlv8, hkp: &str) -> Result<Tlv8> {
        let headers = PairingHeaders {
            hkp: hkp.to_owned(),
            ..PairingHeaders::verify()
        };
        self.post_pairing(path, body, &headers, None)
    }

    /// The one place a pairing request is sent; `log` gets a line per request and reply (no key
    /// material).
    fn post_pairing(
        &mut self,
        path: &str,
        body: &Tlv8,
        headers: &PairingHeaders,
        mut log: Option<&mut Vec<String>>,
    ) -> Result<Tlv8> {
        let request = self.connection.pairing_request(path, body, headers);
        if let Some(log) = log.as_deref_mut() {
            log.push(format!(
                "--> POST {path} ({} bytes) X-Apple-HKP: {}, Content-Type: {}{}{}: {}",
                request.body.len(),
                headers.hkp,
                headers.content_type,
                if headers.pd { ", X-Apple-PD: 1" } else { "" },
                if headers.absolute_time {
                    ", X-Apple-AbsoluteTime"
                } else {
                    ""
                },
                pairing::describe_tlv(body)
            ));
        }
        let response = match self.request(request) {
            Ok(response) => response,
            Err(e) => {
                if let Some(log) = log.as_deref_mut() {
                    log.push(format!("<-- no reply: {e}"));
                }
                return Err(e);
            }
        };
        if !response.is_success() {
            if let Some(log) = log.as_deref_mut() {
                log.push(format!(
                    "<-- {} {} ({} bytes)",
                    response.status,
                    response.reason,
                    response.body.len()
                ));
            }
            return Err(format_error(path, response.status, &response.body));
        }
        let decoded = Tlv8::decode(&response.body);
        if let Some(log) = log {
            log.push(format!(
                "<-- {} {} ({} bytes): {}",
                response.status,
                response.reason,
                response.body.len(),
                match &decoded {
                    Ok(tlv) => pairing::describe_tlv(tlv),
                    Err(e) => format!("not TLV8: {e}"),
                }
            ));
        }
        decoded
    }

    /// Pairs as `auth` says, switches to encrypted framing when keys result, and keeps them
    /// ([`Self::session_keys`]). A credential the receiver no longer honours is
    /// [`AirPlayError::PairVerifyRefused`] or [`AirPlayError::Pairing`].
    pub fn authenticate(&mut self, auth: Auth<'_>, rng: &mut dyn CryptoRng) -> Result<()> {
        match auth {
            Auth::Stored(credentials) => {
                let keys = self.pair_verify_keys(credentials, rng)?;
                self.enable_encryption(&keys)
            }
            Auth::Transient(style) => {
                let keys = self.pair_setup_transient_as(style, rng)?;
                self.enable_encryption(&keys)
            }
            #[cfg(feature = "legacy")]
            Auth::Legacy(credentials) => self.legacy_pair_verify(credentials, rng),
        }
    }

    /// Opens the event channel a session `SETUP` named on `port`.
    pub fn open_event_channel(&self, port: u16) -> Result<EventChannel> {
        let keys = self.session_keys().ok_or_else(|| {
            AirPlayError::InvalidState(
                "the event channel needs an authenticated, encrypted connection".to_owned(),
            )
        })?;
        EventChannel::connect(self.host(), port, keys, self.timeout)
    }

    /// Runs a transient pair-setup ([`TransientStyle::Classic`]), no user interaction.
    /// # Security
    /// Authenticates the channel, not the device: the PIN is a published constant.
    pub fn pair_setup_transient(&mut self, rng: &mut dyn CryptoRng) -> Result<SessionKeys> {
        self.pair_setup_transient_as(TransientStyle::Classic, rng)
    }

    /// Runs a transient pair-setup shaped as `style` says; [`TransientStyle::Ios26`] sends two
    /// abandoned pair-verify M1s (`X-Apple-HKP` 6, 3) then M1 with `X-Apple-HKP: 4`, the shape a
    /// HomePod mini accepts; Apple TVs refuse transient pairing in every shape.
    pub fn pair_setup_transient_as(
        &mut self,
        style: TransientStyle,
        rng: &mut dyn CryptoRng,
    ) -> Result<SessionKeys> {
        let mut trace = Vec::new();
        let result = self.pair_setup_transient_traced(style, rng, &mut trace);
        for line in trace {
            log::debug!("{line}");
        }
        result
    }

    /// [`Self::pair_setup_transient_as`] with every request and reply appended to `trace`, success
    /// or not.
    pub fn pair_setup_transient_traced(
        &mut self,
        style: TransientStyle,
        rng: &mut dyn CryptoRng,
        log: &mut Vec<String>,
    ) -> Result<SessionKeys> {
        for &hkp in style.verify_probe_hkps() {
            // A throwaway identity: the probe is abandoned after M2.
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let mut probe = PairVerify::new(ed25519_dalek::SigningKey::from_bytes(&seed), rng);
            let m1 = probe.start()?;
            let headers = PairingHeaders::verify_probe(style, hkp);
            self.post_pairing("/pair-verify", &m1, &headers, Some(log))?;
            log.push(format!(
                "    pair-verify with X-Apple-HKP: {hkp} abandoned after M2 (no pairing held)"
            ));
        }

        let headers = PairingHeaders::transient(style);
        let mut setup = PairSetup::transient(style, rng);
        let mut message = setup.start()?;

        loop {
            let reply = self.post_pairing("/pair-setup", &message, &headers, Some(log))?;
            match setup.handle(&reply)? {
                Step::Send(next) => message = next,
                Step::Done(keys) => return Ok(*keys),
                Step::Paired(_) => {
                    return Err(AirPlayError::UnexpectedPairingStep(
                        "a transient pair-setup left a stored pairing behind".to_owned(),
                    ))
                }
                Step::NeedPin => {
                    return Err(AirPlayError::UnexpectedPairingStep(
                        "receiver asked for a PIN during a transient pair-setup".to_owned(),
                    ))
                }
            }
        }
    }

    /// `POST /pair-pin-start`: makes the receiver display a four-digit PIN (no `X-Apple-HKP`; see
    /// [`Self::hap_pin_start`]).
    #[cfg(feature = "legacy")]
    pub fn legacy_pin_start(&mut self) -> Result<()> {
        self.pin_start(None)
    }

    /// `POST /pair-pin-start` with `X-Apple-HKP: 3`, as a credential-less Apple sender does
    /// (observed); a HAP error body is [`AirPlayError::Pairing`].
    pub fn hap_pin_start(&mut self) -> Result<()> {
        self.pin_start(Some(pairing::constants::HKP_PIN))
    }

    fn pin_start(&mut self, hkp: Option<&str>) -> Result<()> {
        let request = self.connection.pin_start_request(hkp);
        let response = self.request(request)?;
        if !response.is_success() {
            if let Some(code) = Tlv8::decode(&response.body)
                .ok()
                .and_then(|tlv| tlv.get_byte(crate::tlv8::tag::ERROR))
            {
                return Err(AirPlayError::Pairing(crate::PairingError::from_code(code)));
            }
            return Err(format_error(
                pairing::constants::PIN_START_PATH,
                response.status,
                &response.body,
            ));
        }
        Ok(())
    }

    /// Runs the three-step legacy `/pair-setup-pin` with the on-screen PIN; persist the credentials
    /// for [`Self::legacy_pair_verify`].
    #[cfg(feature = "legacy")]
    pub fn legacy_pair_setup(
        &mut self,
        credentials: LegacyCredentials,
        pin: &str,
        rng: &mut dyn CryptoRng,
    ) -> Result<LegacyCredentials> {
        let mut setup = PairSetupPin::new(credentials, pin, rng);
        let mut body = setup.start()?;

        loop {
            let reply = self.post_bytes(
                legacy::PAIR_SETUP_PIN_PATH,
                body,
                legacy::PLIST_CONTENT_TYPE,
            )?;
            match setup.handle(&reply)? {
                LegacyStep::Send(next) => body = next,
                LegacyStep::Done => return Ok(setup.credentials().clone()),
            }
        }
    }

    /// Runs legacy `/pair-verify` for stored credentials; authenticates this connection only, not a
    /// reconnect.
    #[cfg(feature = "legacy")]
    pub fn legacy_pair_verify(
        &mut self,
        credentials: &LegacyCredentials,
        rng: &mut dyn CryptoRng,
    ) -> Result<()> {
        let mut verify = legacy::PairVerify::new(credentials, rng);
        let first = verify.start()?;
        let reply = self.post_bytes(legacy::PAIR_VERIFY_PATH, first, legacy::OCTET_CONTENT_TYPE)?;
        let second = verify.handle(&reply)?;
        self.post_bytes(legacy::PAIR_VERIFY_PATH, second, legacy::OCTET_CONTENT_TYPE)?;
        Ok(())
    }

    /// The v1 `POST /play`: hand the receiver a URL; `start_position` is a fraction (0.0-1.0),
    /// ignored by modern receivers (see [`Self::play_url`]).
    pub fn play_url_v1(&mut self, url: &str, start_position: f64) -> Result<()> {
        let request = self.connection.play_url_v1_request(url, start_position)?;
        self.checked("/play", request).map(drop)
    }

    /// `SETUP`: the reply carries the session's ephemeral ports; without it `/play` is accepted and
    /// ignored.
    pub fn setup(&mut self, params: &session::SetupParams) -> Result<session::SetupResponse> {
        let request = self.connection.setup_request(params)?;
        session::SetupResponse::parse(&self.checked("SETUP", request)?.body)
    }

    /// `RECORD` - tells the receiver the session is live and it may start.
    pub fn record(&mut self) -> Result<()> {
        let request = self.connection.record_request();
        self.checked("RECORD", request).map(drop)
    }

    /// `POST /feedback`, the v2 keep-alive; any status is accepted.
    pub fn feedback(&mut self) -> Result<()> {
        let request = self.connection.feedback_request();
        self.request(request).map(drop)
    }

    /// The v2 `POST /play`, after [`Self::setup`] and [`Self::record`] on an encrypted channel.
    pub fn play_url(&mut self, url: &str, start_position_seconds: f64) -> Result<()> {
        let request = self
            .connection
            .play_url_request(url, start_position_seconds)?;
        self.checked("/play (v2)", request).map(drop)
    }

    /// Opens a media session on an authenticated channel: a timing server, the session `SETUP`
    /// (NTP) and the event channel. Any failure after a 2xx `SETUP` sends a best-effort `TEARDOWN`.
    pub fn start_media_session(&mut self) -> Result<MediaSession> {
        let timing = crate::timing::TimingServer::start_on(
            self.connection.local_ip(),
            std::sync::Arc::new(crate::time::NtpTimestamp::now),
        )?;
        let mut rng = crate::OsRng;
        let mut params = session::SetupParams::new(
            crate::util::random_mac(&mut rng),
            crate::util::uuid_v4(&mut rng),
            self.connection.client_name().to_owned(),
        );
        params.timing_port = Some(timing.port());
        let request = self.connection.setup_request(&params)?;
        let reply = self.checked("SETUP", request)?;
        let opened = session::SetupResponse::parse(&reply.body).and_then(|setup| {
            let events = match setup.event_port {
                0 => None,
                port => Some(self.open_event_channel(port)?),
            };
            Ok((setup, events))
        });
        match opened {
            Ok((setup, events)) => Ok(MediaSession {
                setup,
                timing,
                events,
            }),
            Err(e) => {
                let _ = self.teardown();
                Err(e)
            }
        }
    }

    /// The whole v2 URL flow on an authenticated channel: [`Self::start_media_session`], then
    /// `RECORD`, `/play` and `/rate`. A failure after `SETUP` sends a best-effort `TEARDOWN`.
    pub fn start_url_playback(
        &mut self,
        url: &str,
        start_position_seconds: f64,
    ) -> Result<MediaSession> {
        let session = self.start_media_session()?;
        let started = self
            .record()
            .and_then(|()| self.play_url(url, start_position_seconds))
            .and_then(|()| self.start_playback());
        match started {
            Ok(()) => Ok(session),
            Err(e) => {
                let _ = self.teardown();
                Err(e)
            }
        }
    }

    /// The commands a v2 sender sends after `/play`; `/rate` is required or the item stays paused.
    pub fn start_playback(&mut self) -> Result<()> {
        // Errors are reported but not fatal: an unknown property must not stop playback.
        let _ = self.set_property("isInterestedInDateRange", plist::Value::Boolean(true));
        let _ = self.set_property("actionAtItemEnd", plist::Value::Integer(0.into()));
        self.set_rate(1.0)
    }

    /// The v2 `POST /rate?value=1.000000` — the six-decimal form a real sender writes.
    pub fn set_rate(&mut self, rate: f64) -> Result<()> {
        let request = self.connection.set_rate_request(rate);
        self.checked("/rate", request).map(drop)
    }

    /// `PUT /setProperty?<name>` with a `{"value": …}` plist body.
    pub fn set_property(&mut self, name: &str, value: plist::Value) -> Result<()> {
        let request = self.connection.set_property_request(name, value)?;
        self.checked(&format!("/setProperty?{name}"), request)
            .map(drop)
    }

    /// The v1 `POST /rate` — 0.0 pauses, 1.0 resumes.
    pub fn set_rate_v1(&mut self, rate: f32) -> Result<()> {
        let request = self.connection.set_rate_v1_request(rate);
        let path = request.uri.clone();
        self.checked(&path, request).map(drop)
    }

    /// `POST /scrub` — seek to an absolute position in seconds.
    pub fn scrub(&mut self, position_seconds: f64) -> Result<()> {
        let request = self.connection.scrub_request(position_seconds);
        let path = request.uri.clone();
        self.checked(&path, request).map(drop)
    }

    /// `POST /stop` — end playback and return the receiver to its home screen.
    pub fn stop_playback(&mut self) -> Result<()> {
        let request = self.connection.stop_request();
        self.checked("/stop", request).map(drop)
    }

    /// `GET /playback-info`: rate, position, duration. An empty 500 is idle (observed on
    /// `AppleTV14,1` / tvOS 23L243); a 500 with a body is an error.
    pub fn playback_info(&mut self) -> Result<PlaybackInfo> {
        let request = self.connection.playback_info_request();
        let response = self.request(request)?;
        if response.status == IDLE_STATUS && response.body.is_empty() {
            return Ok(PlaybackInfo {
                is_idle: true,
                ..PlaybackInfo::default()
            });
        }
        if !response.is_success() {
            return Err(format_error(
                "/playback-info",
                response.status,
                &response.body,
            ));
        }
        PlaybackInfo::parse(&response.body)
    }

    /// POSTs a binary-plist body to a legacy pairing endpoint and returns the reply body.
    #[cfg(feature = "legacy")]
    pub fn post_plist(&mut self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        self.post_bytes(path, body, legacy::PLIST_CONTENT_TYPE)
    }

    /// POSTs `body` to `path`, returns the reply body, failing on non-2xx; bytes are never logged.
    pub fn post_bytes(&mut self, path: &str, body: Vec<u8>, content_type: &str) -> Result<Vec<u8>> {
        let request = self.connection.post_bytes_request(path, body, content_type);
        Ok(self.checked(path, request)?.body)
    }

    /// Runs pair-verify with a long-term identity and **no** check of who answers.
    /// # Security
    /// Encrypted but unauthenticated; use [`Self::authenticate`] with [`Auth::Stored`] outside
    /// demos.
    pub fn pair_verify_unauthenticated(
        &mut self,
        identity: ed25519_dalek::SigningKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<SessionKeys> {
        let verify = PairVerify::new(identity, rng);
        self.run_pair_verify(verify)
    }

    /// Runs HAP `/pair-verify` against a stored pairing, returning the session keys without
    /// switching the connection over.
    pub fn pair_verify_keys(
        &mut self,
        credentials: &HapCredentials,
        rng: &mut dyn CryptoRng,
    ) -> Result<SessionKeys> {
        let verify = PairVerify::with_credentials(credentials, rng)?;
        self.run_pair_verify(verify)
    }

    fn run_pair_verify(&mut self, mut verify: PairVerify) -> Result<SessionKeys> {
        let mut message = verify.start()?;
        loop {
            let reply = self.post_tlv("/pair-verify", &message, pairing::constants::HKP_VERIFY)?;
            match verify.handle(&reply)? {
                Step::Send(next) => message = next,
                Step::Done(keys) => return Ok(*keys),
                Step::Paired(_) | Step::NeedPin => {
                    return Err(AirPlayError::UnexpectedPairingStep(
                        "pair-verify produced something other than session keys".to_owned(),
                    ))
                }
            }
        }
    }

    /// Runs a HAP PIN pair-setup ending with a stored pairing: `/pair-pin-start` to show the PIN,
    /// then the six-message `/pair-setup` with `pin` at once, so `pin` must be fixed or already on
    /// screen. For a PIN a person reads off a fresh prompt, call [`Self::hap_pin_start`], then
    /// [`Self::hap_pair_setup_shown_pin`]. Every tested Apple TV answers 470 here; its credential
    /// comes from Companion pairing.
    pub fn hap_pair_setup_pin(
        &mut self,
        pin: &str,
        rng: &mut dyn CryptoRng,
    ) -> Result<HapCredentials> {
        self.hap_pin_start()?;
        self.hap_pair_setup_shown_pin(pin, rng)
    }

    /// The second half of a HAP PIN pairing: `/pair-setup` with the PIN a person read off the
    /// receiver, without another `/pair-pin-start`; call [`Self::hap_pin_start`] first.
    /// A refusal is [`AirPlayError::Pairing`] with HAP's code.
    pub fn hap_pair_setup_shown_pin(
        &mut self,
        pin: &str,
        rng: &mut dyn CryptoRng,
    ) -> Result<HapCredentials> {
        let mut setup = PairSetup::new(SetupMode::Pin, rng);
        setup.set_pin(pin);
        let mut message = setup.start()?;

        loop {
            let reply = self.post_tlv("/pair-setup", &message, pairing::constants::HKP_PIN)?;
            match setup.handle(&reply)? {
                Step::Send(next) => message = next,
                Step::Paired(credentials) => return Ok(*credentials),
                Step::Done(_) => {
                    return Err(AirPlayError::UnexpectedPairingStep(
                        "a PIN pair-setup ended without leaving a pairing behind".to_owned(),
                    ))
                }
                Step::NeedPin => {
                    return Err(AirPlayError::UnexpectedPairingStep(
                        "the receiver asked for a PIN that was already supplied".to_owned(),
                    ))
                }
            }
        }
    }

    /// `TEARDOWN` of the current RTSP session. Does not close the event channel; drop the channel
    /// after.
    pub fn teardown(&mut self) -> Result<()> {
        let request = self.connection.teardown_request();
        self.checked("TEARDOWN", request).map(drop)
    }

    /// The `type: 110` stream `SETUP` of a pairing-keyed mirror and its reply; a refusal is
    /// [`AirPlayError::Status`] (403 not PIN-paired, 501 unsupported).
    #[cfg(feature = "mirror")]
    pub fn mirror_stream_setup(
        &mut self,
        stream_connection_id: u64,
    ) -> Result<crate::mirror::MirrorStreamReply> {
        let request = self
            .connection
            .mirror_stream_setup_request(stream_connection_id)?;
        crate::mirror::MirrorStreamReply::parse(&self.checked("SETUP", request)?.body)
    }

    /// `TEARDOWN` of the mirror stream, keeping the session.
    #[cfg(feature = "mirror")]
    pub fn mirror_teardown(&mut self) -> Result<()> {
        let request = self.connection.mirror_teardown_request()?;
        self.checked("TEARDOWN", request).map(drop)
    }

    /// `OPTIONS *` — the raw response; its `Public` header lists the methods.
    pub fn options(&mut self) -> Result<Response> {
        let request = self.connection.options_request();
        self.request(request)
    }
}

/// Resolves `host` (a name or an IP literal, IPv6 unbracketed) and `port` to its first address.
pub(crate) fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    let connect = |source| AirPlayError::Connect {
        addr: match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{host}]:{port}"),
            Err(_) => format!("{host}:{port}"),
        },
        source,
    };
    (host, port)
        .to_socket_addrs()
        .map_err(connect)?
        .next()
        .ok_or_else(|| {
            connect(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ))
        })
}

fn user_agent(app_name: &str) -> String {
    format!(
        "AirPlay/{} {app_name}/{}",
        AIRPLAY_CLIENT_VERSION,
        env!("CARGO_PKG_VERSION")
    )
}

/// Turns a non-2xx response into an [`AirPlayError::Status`] with the `reason`/`error` a
/// binary-plist body gives.
pub(crate) fn format_error(path: &str, status: u16, body: &[u8]) -> AirPlayError {
    let reason = plist_error_reason(body).map(|reason| {
        let char_count = reason.chars().count();
        if char_count > 256 {
            let truncated: String = reason.chars().take(256).collect();
            format!("{truncated}\u{2026}")
        } else {
            reason
        }
    });
    AirPlayError::Status {
        path: path.to_owned(),
        code: status,
        reason,
    }
}

/// Looks for a `reason` or `error` string (case-insensitive key) in a binary plist body.
fn plist_error_reason(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let value = crate::safe_plist::from_bytes(body).ok()?;
    let dict = value.as_dictionary()?;
    dict.iter().find_map(|(key, value)| {
        matches!(key.to_ascii_lowercase().as_str(), "reason" | "error")
            .then(|| value.as_string())
            .flatten()
            .map(str::to_owned)
    })
}

/// A UUID-shaped session id; receivers correlate the media endpoints by it.
fn new_session_id(rng: &mut dyn CryptoRng) -> String {
    crate::util::uuid_v4(rng)
}

#[cfg(test)]
mod user_agent_tests {
    use super::*;

    #[test]
    fn the_user_agent_starts_with_the_airplay_token_for_any_app_name() {
        for name in ["cidermill-airplay", "My App", ""] {
            let ua = user_agent(name);
            assert!(ua.starts_with("AirPlay/"), "{ua}");
            assert!(ua.contains(name), "{ua}");
        }
    }
}

#[cfg(test)]
mod error_formatting_tests {
    use super::*;

    fn binary_plist(dict: plist::Dictionary) -> Vec<u8> {
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dict)).expect("encode");
        out
    }

    #[test]
    fn a_status_only_body_falls_back_to_no_reason() {
        let error = format_error("/pair-setup", 470, b"");
        assert_eq!(format!("{error}"), "/pair-setup returned 470");
        assert!(matches!(error, AirPlayError::Status { code: 470, .. }));
    }

    #[test]
    fn an_unparseable_body_falls_back_to_no_reason() {
        let error = format_error("/pair-setup", 470, b"not a plist");
        assert_eq!(format!("{error}"), "/pair-setup returned 470");
    }

    #[test]
    fn a_reason_key_in_the_plist_body_is_folded_into_the_message() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "reason".to_owned(),
            plist::Value::String("Not authorized".to_owned()),
        );
        let error = format_error("/play", 470, &binary_plist(dict));
        assert_eq!(format!("{error}"), "/play returned 470: Not authorized");
    }

    #[test]
    fn the_error_key_is_recognised_case_insensitively_too() {
        let mut dict = plist::Dictionary::new();
        dict.insert("Error".to_owned(), plist::Value::String("busy".to_owned()));
        let error = format_error("/play", 503, &binary_plist(dict));
        assert_eq!(format!("{error}"), "/play returned 503: busy");
    }

    #[test]
    fn a_long_reason_is_truncated_with_an_ellipsis() {
        let mut dict = plist::Dictionary::new();
        let long_reason: String = "x".repeat(300);
        dict.insert("reason".to_owned(), plist::Value::String(long_reason));
        let error = format_error("/play", 470, &binary_plist(dict));
        let msg = format!("{error}");
        assert!(msg.contains(&"x".repeat(256)), "should contain 256 x's");
        assert!(
            msg.ends_with('\u{2026}'),
            "should end with an ellipsis, got: {msg}"
        );
        assert!(
            !msg.contains(&"x".repeat(300)),
            "should not contain all 300 x's"
        );
    }

    #[test]
    fn a_short_reason_is_not_truncated() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "reason".to_owned(),
            plist::Value::String("short".to_owned()),
        );
        let error = format_error("/play", 470, &binary_plist(dict));
        let msg = format!("{error}");
        assert!(
            msg.ends_with("short"),
            "should end with the reason, got: {msg}"
        );
        assert!(
            !msg.contains('\u{2026}'),
            "should not contain ellipsis for short reason"
        );
    }

    #[test]
    fn a_refused_connection_keeps_its_error_kind() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let error = ControlChannel::builder("127.0.0.1")
            .port(port)
            .timeout(std::time::Duration::from_millis(500))
            .connect()
            .unwrap_err();
        // Refused on most systems; Windows retries the SYN and times out instead.
        assert!(
            matches!(&error, AirPlayError::Connect { source, .. } if matches!(
                source.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            )),
            "{error:?}"
        );
    }

    /// A receiver that dribbles its reply a byte at a time, each well inside the read timeout:
    /// the exchange still ends at its deadline instead of blocking for as long as the bytes come.
    #[test]
    fn a_reply_dribbled_a_byte_at_a_time_cannot_outlast_the_timeout() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = std::sync::Arc::clone(&stop);
        let dribbler = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            // A status line and headers that never end.
            let endless = b"RTSP/1.0 200 OK\r\nX-Pad: "
                .iter()
                .chain(std::iter::repeat(&b'a'));
            let began = std::time::Instant::now();
            for byte in endless {
                // Bounded, so a regression fails the timing assertion rather than hanging.
                if stopping.load(std::sync::atomic::Ordering::Relaxed)
                    || began.elapsed() > std::time::Duration::from_secs(3)
                    || socket.write_all(&[*byte]).is_err()
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });
        let timeout = std::time::Duration::from_millis(400);
        let mut channel = ControlChannel::builder("127.0.0.1")
            .port(port)
            .timeout(timeout)
            .connect()
            .expect("connect");
        let started = std::time::Instant::now();
        let error = channel.device_info().unwrap_err();
        let took = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            matches!(&error, AirPlayError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{error:?}"
        );
        assert!(took >= timeout, "{took:?}");
        assert!(
            took < timeout * 2 + std::time::Duration::from_millis(500),
            "{took:?}"
        );
        assert!(channel.failure().is_some(), "the connection is retired");
        drop(channel);
        dribbler.join().expect("dribbler");
    }

    #[test]
    fn a_dictionary_with_neither_key_falls_back_to_no_reason() {
        let mut dict = plist::Dictionary::new();
        dict.insert("somethingElse".to_owned(), plist::Value::Boolean(true));
        let error = format_error("/play", 500, &binary_plist(dict));
        assert_eq!(format!("{error}"), "/play returned 500");
    }

    /// A receiver that never answers: the request times out and the connection is retired.
    #[test]
    fn a_timed_out_request_retires_the_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let holder = std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            std::thread::sleep(std::time::Duration::from_secs(2));
            drop(socket);
        });
        let mut channel = ControlChannel::builder("127.0.0.1")
            .port(port)
            .timeout(std::time::Duration::from_millis(200))
            .connect()
            .expect("connect");
        let first = channel.device_info().unwrap_err();
        assert!(
            matches!(&first, AirPlayError::Io(e) if matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )),
            "{first:?}"
        );
        assert!(channel.failure().is_some());
        let started = std::time::Instant::now();
        let second = channel.device_info().unwrap_err();
        assert!(
            matches!(second, AirPlayError::ConnectionRetired { .. }),
            "{second}"
        );
        assert!(second.to_string().contains("cannot be used"), "{second}");
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        holder.join().expect("holder");
    }
}

#[cfg(test)]
mod sans_io_tests {
    use super::*;
    use crate::cipher::EncryptedTransport;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// A receiver double behind an in-memory stream: answers 200 with the `CSeq`, sealed once
    /// `keys` set.
    #[derive(Default)]
    struct Loopback {
        decoder: Decoder,
        incoming: Option<EncryptedTransport>,
        outgoing: Option<EncryptedTransport>,
        replies: std::collections::VecDeque<u8>,
        seen: Vec<Request>,
        cseq_offset: u32,
    }

    impl Loopback {
        fn encrypted(keys: &SessionKeys) -> Self {
            Self {
                incoming: Some(EncryptedTransport::from_keys(
                    &keys.read_key,
                    &keys.write_key,
                )),
                outgoing: Some(EncryptedTransport::from_keys(
                    &keys.read_key,
                    &keys.write_key,
                )),
                ..Self::default()
            }
        }
    }

    impl Write for Loopback {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match &mut self.incoming {
                Some(cipher) => {
                    cipher.push(bytes);
                    while let Some(plain) = cipher.open_next().map_err(std::io::Error::other)? {
                        self.decoder.push(&plain);
                    }
                }
                None => self.decoder.push(bytes),
            }
            while let Some(request) = self.decoder.next_request().map_err(std::io::Error::other)? {
                let cseq: u32 = request.headers.get("CSeq").unwrap().parse().unwrap();
                let mut response = Response::new(Protocol::Rtsp, 200, "OK", Vec::new());
                response
                    .headers
                    .set("CSeq", (cseq + self.cseq_offset).to_string());
                let wire = match &mut self.outgoing {
                    Some(cipher) => cipher.seal(&response.encode()).unwrap(),
                    None => response.encode(),
                };
                self.replies.extend(wire);
                self.seen.push(request);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            // A byte at a time, so every reply arrives split.
            match (buffer.first_mut(), self.replies.pop_front()) {
                (Some(slot), Some(byte)) => {
                    *slot = byte;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn keys() -> SessionKeys {
        SessionKeys {
            shared_secret: vec![7; 32],
            write_key: [0x11; 32],
            read_key: [0x22; 32],
        }
    }

    #[test]
    fn a_scrub_to_a_position_that_is_not_finite_is_sent_as_zero() {
        let connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        for position in [f64::NAN, f64::INFINITY] {
            assert_eq!(connection.scrub_request(position).uri, "/scrub?position=0");
        }
        assert_eq!(connection.scrub_request(12.5).uri, "/scrub?position=12.5");
    }

    #[test]
    fn a_request_with_a_line_break_in_a_header_is_refused_before_it_takes_a_sequence_number() {
        let mut connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        let mut request = connection.post_bytes_request("/x", Vec::new(), "a\r\nX-Injected: 1");
        assert!(connection.encode(request.clone()).is_err());
        request.headers.set("Content-Type", "text/plain");
        let wire = String::from_utf8(connection.encode(request).unwrap()).unwrap();
        assert!(wire.contains("CSeq: 0\r\n"), "{wire}");
    }

    #[test]
    fn a_channel_over_any_stream_stamps_requests_and_reads_replies() {
        let connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        let mut channel = ControlChannel::from_stream(Loopback::default(), connection);
        channel.record().unwrap();
        channel.feedback().unwrap();
        let (stream, connection) = channel.into_parts();
        let record = &stream.seen[0];
        assert_eq!(record.method, "RECORD");
        assert_eq!(record.uri, connection.session_uri());
        assert!(record.uri.starts_with("rtsp://192.0.2.7/"));
        assert_eq!(record.headers.get("CSeq"), Some("0"));
        assert_eq!(record.headers.get("Host"), Some("receiver.local"));
        assert_eq!(record.headers.get("DACP-ID"), Some(connection.dacp_id()));
        assert_eq!(stream.seen[1].headers.get("CSeq"), Some("1"));
        let mut fixed = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        fixed.set_rtsp_session_id(3_141_592_653);
        assert_eq!(fixed.session_uri(), "rtsp://192.0.2.7/3141592653");
    }

    #[test]
    fn an_unreadable_setup_reply_is_torn_down() {
        let local = std::net::Ipv4Addr::LOCALHOST.into();
        let connection = SenderConnection::new("receiver.local", local, &mut crate::OsRng);
        let mut channel = ControlChannel::from_stream(Loopback::default(), connection);
        // The loopback answers every request 200 with no body, which is not a SETUP plist.
        assert!(matches!(
            channel.start_media_session(),
            Err(AirPlayError::Protocol(_))
        ));
        let methods: Vec<_> = channel
            .get_ref()
            .seen
            .iter()
            .map(|r| r.method.as_str())
            .collect();
        assert_eq!(methods, ["SETUP", "TEARDOWN"]);
    }

    #[test]
    fn an_encrypted_channel_seals_requests_and_opens_split_replies() {
        let mut connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        connection.enable_encryption(&keys()).unwrap();
        let mut channel = ControlChannel::from_stream(Loopback::encrypted(&keys()), connection);
        channel.record().unwrap();
        channel.teardown().unwrap();
        assert_eq!(channel.get_ref().seen.len(), 2);
        assert_eq!(channel.session_keys(), Some(&keys()));
    }

    #[test]
    fn the_default_client_name_is_the_app_name() {
        let connection = ControlChannel::builder("receiver.local")
            .app_name("Example")
            .sans_io(LOCAL);
        assert_eq!(connection.client_name(), "Example");
        assert!(connection.app_name() == "Example");
        let named = ControlChannel::builder("receiver.local")
            .app_name("Example")
            .client_name("Kitchen")
            .sans_io(LOCAL);
        assert_eq!(named.client_name(), "Kitchen");
        let request = named.pairing_request("/pair-setup", &Tlv8::new(), &PairingHeaders::verify());
        assert_eq!(
            request.headers.get(pairing::constants::CLIENT_NAME_HEADER),
            Some("Kitchen")
        );
    }

    #[test]
    fn a_reply_to_another_request_retires_the_connection() {
        let connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        let stream = Loopback {
            cseq_offset: 5,
            ..Loopback::default()
        };
        let mut channel = ControlChannel::from_stream(stream, connection);
        let error = channel.record().unwrap_err();
        assert!(error.to_string().contains("CSeq mismatch"), "{error}");
        assert!(matches!(
            channel.record(),
            Err(AirPlayError::ConnectionRetired { .. })
        ));
    }

    #[test]
    fn a_frame_that_does_not_open_is_decrypt_and_retires() {
        let mut connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        connection.enable_encryption(&keys()).unwrap();
        let _ = connection.encode(connection.options_request()).unwrap();
        let mut stranger = EncryptedTransport::from_keys(&[0x33; 32], &[0x44; 32]);
        let wire = stranger.seal(b"RTSP/1.0 200 OK\r\n\r\n").unwrap();
        assert!(matches!(connection.push(&wire), Err(AirPlayError::Decrypt)));
        assert!(connection.failure().is_some());
        assert!(matches!(
            connection.encode(connection.options_request()),
            Err(AirPlayError::ConnectionRetired { .. })
        ));
    }

    #[cfg(feature = "mirror")]
    #[test]
    fn the_mirror_stream_requests_are_session_plists() {
        let connection = SenderConnection::new("receiver.local", LOCAL, &mut crate::OsRng);
        let setup = connection.mirror_stream_setup_request(42).unwrap();
        assert_eq!(setup.method, "SETUP");
        assert_eq!(setup.uri, connection.session_uri());
        assert_eq!(
            setup.headers.get("Content-Type"),
            Some(session::PLIST_CONTENT_TYPE)
        );
        assert!(setup.headers.get("DACP-ID").is_some());
        let value = plist::Value::from_reader(std::io::Cursor::new(&setup.body)).unwrap();
        let entry = value.as_dictionary().unwrap()["streams"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap()
            .clone();
        let parsed = crate::mirror::MirrorStreamSetup::from_entry(&entry).unwrap();
        assert_eq!(parsed.stream_connection_id, 42);
        let teardown = connection.mirror_teardown_request().unwrap();
        assert_eq!(teardown.method, "TEARDOWN");
        assert_eq!(
            teardown.body,
            crate::mirror::setup::teardown_body().unwrap()
        );
    }

    #[test]
    fn an_ipv6_literal_host_connects() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            return; // No IPv6 loopback here.
        };
        let port = listener.local_addr().unwrap().port();
        let channel = ControlChannel::builder("::1")
            .port(port)
            .timeout(std::time::Duration::from_secs(2))
            .connect()
            .expect("an unbracketed IPv6 literal connects");
        assert_eq!(channel.host(), "::1");
        let error = resolve("::1", 1).map(|a| a.to_string()).unwrap();
        assert_eq!(error, "[::1]:1");
        drop(listener);
    }

    #[test]
    fn a_connection_and_its_ids_replay_from_one_generator() {
        use rand::SeedableRng;
        let a = SenderConnection::new("h", LOCAL, &mut rand::rngs::StdRng::seed_from_u64(9));
        let b = SenderConnection::new("h", LOCAL, &mut rand::rngs::StdRng::seed_from_u64(9));
        assert_eq!(a.session_uri(), b.session_uri());
        assert_eq!(a.session_id(), b.session_id());
        assert_eq!(a.dacp_id(), b.dacp_id());
    }

    #[test]
    fn a_channel_over_a_stream_keeps_the_builders_timeout() {
        let channel = ControlChannel::builder("receiver.local")
            .timeout(std::time::Duration::from_millis(1234))
            .over(Loopback::default(), LOCAL);
        assert_eq!(channel.timeout(), std::time::Duration::from_millis(1234));
    }

    #[test]
    fn the_event_channel_needs_keys() {
        let connection = SenderConnection::new("127.0.0.1", LOCAL, &mut crate::OsRng);
        let channel = ControlChannel::from_stream(Loopback::default(), connection);
        assert!(matches!(
            channel.open_event_channel(1),
            Err(AirPlayError::InvalidState(_))
        ));
    }
}
