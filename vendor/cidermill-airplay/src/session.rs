//! The AirPlay 2 session: `SETUP`, `RECORD` and the `/play` a modern receiver acts on.
//!
//! The v1 send ([`super::play`]) is answered 200 and ignored by receivers that set feature bits 38
//! and 48 (observed on two Apple TVs); those need this sequence. Layout: pyatv 0.18.0 airplayv2.py.
//!
//! ```text
//!   pair-verify                     (the channel is encrypted from here)
//!   SETUP  rtsp://<us>/<session>    binary plist -> eventPort, timingPort
//!   RECORD rtsp://<us>/<session>
//!   POST /play                      Content-Location + a sender description
//!   POST /rate?value=1.0            without this the receiver stays paused
//! ```
//! Sans-io: this module builds bodies and reads replies; [`super::client`] owns the socket.
//! [`SetupParams::ios_remote_control`] / [`SetupParams::ios_media`] reproduce an iPhone's two
//! `SETUP`s (observed, iOS 26.7). The sender's FairPlay step is outside this crate by policy
//! ([`crate::sequence`]).

use plist::Value;

use crate::error::{AirPlayError, Result};

/// The model a sender claims to be in `SETUP` and `/play` (pyatv's value; a real iPhone sends
/// [`IOS_SENDER_MODEL`]).
pub const SENDER_MODEL: &str = "iPhone14,3";

/// The `sourceVersion` a sender reports (the AirPlay implementation version). Assumed: receivers
/// may gate behaviour on it, so this reports a current sender's value.
pub const SOURCE_VERSION: &str = "690.7.1";

/// The OS a sender claims to run.
pub const OS_NAME: &str = "iPhone OS";

/// The OS version a sender claims to run.
pub const OS_VERSION: &str = "16.5";

/// The OS build a sender claims to run.
pub const OS_BUILD_VERSION: &str = "20F66";

/// Content type of every v2 body.
pub const PLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// `model` a real iPhone sent. Observed.
pub const IOS_SENDER_MODEL: &str = "iPhone16,1";

/// `sourceVersion` a real iPhone sent (its `User-Agent: AirPlay/960.13.1`). Observed.
pub const IOS_SOURCE_VERSION: &str = "960.13.1";

/// `osName` a real iPhone sent; the same string pyatv uses. Observed.
pub const IOS_OS_NAME: &str = "iPhone OS";

/// `osVersion` a real iPhone sent. Observed.
pub const IOS_OS_VERSION: &str = "26.7";

/// `osBuildVersion` a real iPhone sent. Observed.
pub const IOS_OS_BUILD_VERSION: &str = "23H24";

/// The `User-Agent` a real iPhone put on every request, pairing included. Observed.
pub const IOS_USER_AGENT: &str = "AirPlay/960.13.1";

/// Who a sender says it is: the five identity strings a session `SETUP` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SenderIdentity {
    /// `model`.
    pub model: String,
    /// `sourceVersion`: the AirPlay implementation version.
    pub source_version: String,
    /// `osName`.
    pub os_name: String,
    /// `osVersion`.
    pub os_version: String,
    /// `osBuildVersion`.
    pub os_build_version: String,
}

impl SenderIdentity {
    /// pyatv's identity (iOS 16.5 on an `iPhone14,3`); the default.
    pub const PYATV: IdentityStrs = IdentityStrs {
        model: SENDER_MODEL,
        source_version: SOURCE_VERSION,
        os_name: OS_NAME,
        os_version: OS_VERSION,
        os_build_version: OS_BUILD_VERSION,
    };

    /// A real iPhone's identity on iOS 26.7. Observed.
    pub const IOS_26_7: IdentityStrs = IdentityStrs {
        model: IOS_SENDER_MODEL,
        source_version: IOS_SOURCE_VERSION,
        os_name: IOS_OS_NAME,
        os_version: IOS_OS_VERSION,
        os_build_version: IOS_OS_BUILD_VERSION,
    };
}

impl Default for SenderIdentity {
    /// [`SenderIdentity::PYATV`].
    fn default() -> Self {
        Self::PYATV.into()
    }
}

/// A [`SenderIdentity`] as string constants, so the known identities can be `const`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IdentityStrs {
    /// `model`.
    pub model: &'static str,
    /// `sourceVersion`.
    pub source_version: &'static str,
    /// `osName`.
    pub os_name: &'static str,
    /// `osVersion`.
    pub os_version: &'static str,
    /// `osBuildVersion`.
    pub os_build_version: &'static str,
}

impl From<IdentityStrs> for SenderIdentity {
    fn from(strs: IdentityStrs) -> Self {
        Self {
            model: strs.model.to_owned(),
            source_version: strs.source_version.to_owned(),
            os_name: strs.os_name.to_owned(),
            os_version: strs.os_version.to_owned(),
            os_build_version: strs.os_build_version.to_owned(),
        }
    }
}

/// The identifiers a real sender puts in its session `SETUP`s. Observed: `deviceID`, `macAddress`
/// and `sessionCorrelationUUID` were identical across eight captured sessions; `sessionUUID`
/// changed each time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionIds {
    /// `deviceID`.
    pub device_id: String,
    /// `macAddress`.
    pub mac_address: String,
    /// `sessionUUID`, upper-case.
    pub session_uuid: String,
    /// `sessionCorrelationUUID`, upper-case; also the `ID` of the sender's timing peer.
    pub session_correlation_uuid: String,
    /// `name`: what the receiver may show.
    pub name: String,
}

impl SessionIds {
    /// The identifiers, as given.
    #[must_use]
    pub fn new(
        device_id: String,
        mac_address: String,
        session_uuid: String,
        session_correlation_uuid: String,
        name: String,
    ) -> Self {
        Self {
            device_id,
            mac_address,
            session_uuid,
            session_correlation_uuid,
            name,
        }
    }
}

/// What the sender tells the receiver about itself in `SETUP`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetupParams {
    /// A MAC-shaped sender id. The receiver correlates the session by it.
    pub device_id: String,
    /// An upper-case UUID naming this session.
    pub session_uuid: String,
    /// The UDP port our timing server listens on, or `None` for `timingProtocol: None`. A media
    /// session needs a port and a [`crate::timing::TimingServer`] answering it (observed, tvOS
    /// 23L243: NTP `SETUP` hangs unanswered; a media `SETUP` with `None` gets 500). `None` is valid
    /// only with [`Self::remote_control_only`], and is [`Self::new`]'s default because it cannot
    /// hang.
    pub timing_port: Option<u16>,
    /// The name the receiver may show on screen.
    pub name: String,
    /// Whether this is a remote-control channel rather than a media one (observed, tvOS 23L243).
    pub remote_control_only: bool,
    /// PTP timing: when set, `SETUP` names `timingProtocol: PTP` with this `timingPeerInfo` (and as
    /// a one-item `timingPeerList`); [`Self::timing_port`] is ignored. Assumed shape. Default
    /// `None`.
    pub timing_peer_info: Option<crate::audio::TimingPeerInfo>,
    /// `model`, `sourceVersion` and the OS strings. Default [`SenderIdentity::PYATV`].
    pub identity: SenderIdentity,
    /// `macAddress`, when it should differ from [`Self::device_id`]. `None` sends `device_id`
    /// twice.
    pub mac_address: Option<String>,
    /// `sessionCorrelationUUID`. Written only when set; an iPhone sends it, pyatv does not.
    pub session_correlation_uuid: Option<String>,
    /// `statsCollectionEnabled`. Written only when set; an iPhone sends `false`.
    pub stats_collection_enabled: Option<bool>,
    /// `updateSessionRequest`. Written only when set; an iPhone sends `false`.
    pub update_session_request: Option<bool>,
    /// `isMultiSelectAirPlay`. Written only when set; an iPhone sends `false` in its media session.
    pub is_multi_select_airplay: Option<bool>,
    /// A cidermill-airplay mirroring session: writes `isScreenMirroringSession: true` and
    /// `cidermillMirror: 1`
    /// ([`crate::mirror::setup::MirrorMarker::write_pairing_keyed`]); the receiver derives the base
    /// key from the pairing.
    #[cfg(feature = "mirror")]
    pub pairing_keyed_mirror: bool,
}

impl SetupParams {
    /// Creates setup parameters for a media or remote-control session.
    #[must_use]
    pub fn new(device_id: String, session_uuid: String, name: String) -> Self {
        Self {
            device_id,
            session_uuid,
            timing_port: None,
            name,
            remote_control_only: false,
            timing_peer_info: None,
            identity: SenderIdentity::default(),
            mac_address: None,
            session_correlation_uuid: None,
            stats_collection_enabled: None,
            update_session_request: None,
            is_multi_select_airplay: None,
            #[cfg(feature = "mirror")]
            pairing_keyed_mirror: false,
        }
    }

    /// The remote-control session `SETUP` a real iPhone sends, with [`SenderIdentity::IOS_26_7`].
    /// Observed.
    #[must_use]
    pub fn ios_remote_control(ids: SessionIds) -> Self {
        let mut params = Self::ios_common(ids);
        params.remote_control_only = true;
        params
    }

    /// The media session `SETUP` a real iPhone sends: PTP, with `peer` as `timingPeerInfo` and the
    /// one `timingPeerList` entry, `isMultiSelectAirPlay: false`; `peer`'s `ID` is the correlation
    /// UUID, no `ClockID` (that comes in `SETPEERSX`). Observed.
    #[must_use]
    pub fn ios_media(ids: SessionIds, peer: crate::audio::TimingPeerInfo) -> Self {
        let mut params = Self::ios_common(ids);
        params.timing_peer_info = Some(peer);
        params.is_multi_select_airplay = Some(false);
        params
    }

    fn ios_common(ids: SessionIds) -> Self {
        let mut params = Self::new(ids.device_id, ids.session_uuid, ids.name);
        params.identity = SenderIdentity::IOS_26_7.into();
        params.mac_address = Some(ids.mac_address);
        params.session_correlation_uuid = Some(ids.session_correlation_uuid);
        params.stats_collection_enabled = Some(false);
        params.update_session_request = Some(false);
        params
    }
}

/// Builds the `SETUP` body: pyatv's dictionary by default, or an iPhone's via
/// [`SetupParams::ios_remote_control`] / [`SetupParams::ios_media`]. Keys are case-sensitive.
pub fn setup_body(params: &SetupParams) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "deviceID".to_owned(),
        Value::String(params.device_id.clone()),
    );
    dict.insert(
        "sessionUUID".to_owned(),
        Value::String(params.session_uuid.clone()),
    );
    match (&params.timing_peer_info, params.timing_port) {
        (Some(peer), _) => {
            dict.insert("timingProtocol".to_owned(), Value::String("PTP".to_owned()));
            dict.insert("timingPeerInfo".to_owned(), peer.to_value());
            dict.insert(
                "timingPeerList".to_owned(),
                Value::Array(vec![peer.to_value()]),
            );
        }
        (None, Some(port)) => {
            dict.insert(
                "timingPort".to_owned(),
                Value::Integer(i64::from(port).into()),
            );
            dict.insert("timingProtocol".to_owned(), Value::String("NTP".to_owned()));
        }
        (None, None) => {
            dict.insert(
                "timingProtocol".to_owned(),
                Value::String("None".to_owned()),
            );
        }
    }
    if params.remote_control_only {
        dict.insert("isRemoteControlOnly".to_owned(), Value::Boolean(true));
    }
    dict.insert(
        "macAddress".to_owned(),
        Value::String(
            params
                .mac_address
                .clone()
                .unwrap_or_else(|| params.device_id.clone()),
        ),
    );
    let identity = &params.identity;
    dict.insert("model".to_owned(), Value::String(identity.model.clone()));
    dict.insert("name".to_owned(), Value::String(params.name.clone()));
    dict.insert(
        "osBuildVersion".to_owned(),
        Value::String(identity.os_build_version.clone()),
    );
    dict.insert("osName".to_owned(), Value::String(identity.os_name.clone()));
    dict.insert(
        "osVersion".to_owned(),
        Value::String(identity.os_version.clone()),
    );
    dict.insert(
        "sourceVersion".to_owned(),
        Value::String(identity.source_version.clone()),
    );
    if let Some(uuid) = &params.session_correlation_uuid {
        dict.insert(
            "sessionCorrelationUUID".to_owned(),
            Value::String(uuid.clone()),
        );
    }
    let flags = [
        ("statsCollectionEnabled", params.stats_collection_enabled),
        ("updateSessionRequest", params.update_session_request),
        ("isMultiSelectAirPlay", params.is_multi_select_airplay),
    ];
    for (key, value) in flags {
        if let Some(value) = value {
            dict.insert(key.to_owned(), Value::Boolean(value));
        }
    }
    #[cfg(feature = "mirror")]
    if params.pairing_keyed_mirror {
        crate::mirror::setup::MirrorMarker::write_pairing_keyed(&mut dict);
    }

    encode(&Value::Dictionary(dict), "SETUP")
}

/// What the receiver answers `SETUP` with; the ephemeral ports are in neither mDNS nor `/info`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SetupResponse {
    /// Where the receiver wants an encrypted event channel, or 0 when it named none.
    pub event_port: u16,
    /// The receiver's own timing port, or 0.
    pub timing_port: u16,
    body: Vec<u8>,
}

impl SetupResponse {
    /// Parses the `SETUP` reply body. A missing port is 0, not an error; the caller decides.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "SETUP reply is not a readable plist")?;
        let dict = value.as_dictionary().ok_or_else(|| {
            AirPlayError::Protocol("SETUP reply is not a plist dictionary".to_owned())
        })?;

        let port = |key: &str| -> u16 {
            dict.get(key)
                .and_then(plist::Value::as_unsigned_integer)
                .and_then(|value| u16::try_from(value).ok())
                .unwrap_or(0)
        };

        Ok(Self {
            event_port: port("eventPort"),
            timing_port: port("timingPort"),
            body: body.to_vec(),
        })
    }

    /// The reply body as it arrived.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The receiver's PTP identity (`timingPeerInfo`), when a PTP session's reply names one.
    #[must_use]
    pub fn timing_peer_info(&self) -> Option<crate::audio::TimingPeerInfo> {
        crate::audio::TimingPeerInfo::from_setup_reply(&self.body)
            .ok()
            .flatten()
    }
}

/// Builds the v2 `/play` body. Unlike [`super::play::play_body`], `Start-Position-Seconds` is in
/// seconds, not a fraction of the duration; a negative or non-finite one is sent as 0.
pub fn play_body(url: &str, start_position_seconds: f64, uuid: &str) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("Content-Location".to_owned(), Value::String(url.to_owned()));
    let start = if start_position_seconds.is_finite() {
        start_position_seconds.max(0.0)
    } else {
        0.0
    };
    dict.insert("Start-Position-Seconds".to_owned(), Value::Real(start));
    dict.insert("uuid".to_owned(), Value::String(uuid.to_owned()));
    dict.insert("streamType".to_owned(), Value::Integer(1.into()));
    dict.insert("mediaType".to_owned(), Value::String("file".to_owned()));
    dict.insert("rate".to_owned(), Value::Real(1.0));
    dict.insert("volume".to_owned(), Value::Real(1.0));
    dict.insert("playbackRestrictions".to_owned(), Value::Integer(0.into()));
    dict.insert("referenceRestrictions".to_owned(), Value::Integer(3.into()));
    dict.insert(
        "mightSupportStorePastisKeyRequests".to_owned(),
        Value::Boolean(true),
    );
    dict.insert("model".to_owned(), Value::String(SENDER_MODEL.to_owned()));
    dict.insert(
        "osBuildVersion".to_owned(),
        Value::String(OS_BUILD_VERSION.to_owned()),
    );
    dict.insert(
        "clientBundleID".to_owned(),
        Value::String(format!("com.{}.sender", crate::DEFAULT_CLIENT_NAME)),
    );
    dict.insert(
        "clientProcName".to_owned(),
        Value::String(crate::DEFAULT_CLIENT_NAME.to_owned()),
    );

    encode(&Value::Dictionary(dict), "/play")
}

/// Builds a `PUT /setProperty?<name>` body: a one-key dictionary around the value.
pub fn property_body(value: Value) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("value".to_owned(), value);
    encode(&Value::Dictionary(dict), "setProperty")
}

/// `Content-Type` of a `text/parameters` body (`GET_PARAMETER`, `SET_PARAMETER`).
pub const TEXT_PARAMETERS_CONTENT_TYPE: &str = "text/parameters";

/// The body of the volume query: the parameter name and a CRLF.
pub const VOLUME_PARAMETER_QUERY: &[u8] = b"volume\r\n";

/// `GET_PARAMETER <session> RTSP/1.0` asking for `volume`. Observed from an iPhone between `SETUP`
/// and `RECORD`.
#[must_use]
pub fn get_volume_request(session_uri: &str) -> crate::rtsp::Request {
    let mut request = crate::rtsp::Request::new(
        "GET_PARAMETER",
        session_uri,
        crate::rtsp::Protocol::Rtsp,
        VOLUME_PARAMETER_QUERY.to_vec(),
    );
    request
        .headers
        .set("Content-Type", TEXT_PARAMETERS_CONTENT_TYPE);
    request
}

/// Reads the reply to [`get_volume_request`]: a `text/parameters` body `volume: <dB>\r\n`.
/// Volume is attenuation in dB, 0 loudest and -144 mute. An absent or unreadable line is an error.
pub fn parse_volume_parameter(body: &[u8]) -> Result<f64> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("volume"))
        .and_then(|(_, value)| value.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .ok_or_else(|| AirPlayError::Protocol("no readable volume parameter".to_owned()))
}

fn encode(value: &Value, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value)
        .map_err(|e| AirPlayError::Protocol(format!("could not encode the {what} body: {e}")))?;
    Ok(out)
}

/// How long [`EventChannel::respond`] keeps trying a write the receiver's buffers will not take.
pub const EVENT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long [`EventChannel::respond`] waits between those tries.
pub const EVENT_WRITE_RETRY: std::time::Duration = std::time::Duration::from_millis(5);

/// The event channel a v2 `SETUP` names a port for. Observed on tvOS 23L243: `RECORD` is not
/// answered until something connects to the `eventPort`. Receivers push (`POST /command`) on it; a
/// URL send needs only the socket to exist.
pub struct EventChannel {
    stream: std::net::TcpStream,
    transport: super::cipher::EncryptedTransport,
    /// Why the channel was retired; every later call fails at once without touching the socket.
    failed: Option<String>,
}

impl std::fmt::Debug for EventChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventChannel").finish_non_exhaustive()
    }
}

/// The most bytes one [`EventChannel::poll`] reads before returning; bounds a receiver that never
/// stops talking. The rest is delivered by the next poll.
pub const EVENT_POLL_BUDGET: usize = 256 * 1024;

/// How many times [`EventChannel::connect`] retries a refused connection.
const EVENT_CHANNEL_CONNECT_ATTEMPTS: u32 = 5;

/// Delay between retries.
const EVENT_CHANNEL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

impl EventChannel {
    /// Connects to the receiver's event port and switches to the event keys
    /// ([`super::pairing::SessionKeys::event_keys`]). A refused connection is retried up to 5
    /// times, one second apart; `timeout` is per attempt.
    pub fn connect(
        host: &str,
        port: u16,
        keys: &super::pairing::SessionKeys,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        let resolved = crate::client::resolve(host, port)?;
        let stream = Self::connect_with_retry(
            resolved,
            timeout,
            EVENT_CHANNEL_CONNECT_ATTEMPTS,
            EVENT_CHANNEL_RETRY_DELAY,
        )?;
        stream.set_nodelay(true).ok();
        // Non-blocking for life: a blocking read could hang a healthy session, and a short read
        // timeout leaves a Windows socket indeterminate once it fires (`SO_RCVTIMEO`).
        stream
            .set_nonblocking(true)
            .map_err(|e| AirPlayError::io_context("event channel non-blocking", e))?;

        Ok(Self {
            stream,
            transport: keys.event_keys()?.transport(),
            failed: None,
        })
    }

    /// Convenience wrapper: calls [`Self::connect_with_retry_fn`] with the real connector.
    fn connect_with_retry(
        address: std::net::SocketAddr,
        timeout: std::time::Duration,
        max_attempts: u32,
        retry_delay: std::time::Duration,
    ) -> Result<std::net::TcpStream> {
        Self::connect_with_retry_fn(
            std::net::TcpStream::connect_timeout,
            &address,
            timeout,
            max_attempts,
            retry_delay,
        )
    }

    /// The retry loop, parameterised so tests can inject a fake connector.
    fn connect_with_retry_fn<F>(
        mut connector: F,
        address: &std::net::SocketAddr,
        timeout: std::time::Duration,
        max_attempts: u32,
        retry_delay: std::time::Duration,
    ) -> Result<std::net::TcpStream>
    where
        F: FnMut(
            &std::net::SocketAddr,
            std::time::Duration,
        ) -> std::io::Result<std::net::TcpStream>,
    {
        let mut last_error = None;
        for attempt in 1..=max_attempts {
            match connector(address, timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    log::debug!(
                        "event channel connect to {address} refused (attempt {attempt}/{max_attempts}), {}",
                        if attempt < max_attempts { "retrying" } else { "giving up" }
                    );
                    last_error = Some(e);
                    if attempt < max_attempts {
                        std::thread::sleep(retry_delay);
                    }
                }
                Err(source) => {
                    return Err(AirPlayError::Connect {
                        addr: address.to_string(),
                        source,
                    })
                }
            }
        }
        let last = last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "no connection attempts configured",
            )
        });
        Err(AirPlayError::Connect {
            addr: address.to_string(),
            source: std::io::Error::new(
                last.kind(),
                format!("after {max_attempts} attempts: {last}"),
            ),
        })
    }

    /// The port the receiver gave us, for logging.
    pub fn peer(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr().ok()
    }

    /// Seals `data` through the event transport and writes it, retrying a full send buffer every
    /// [`EVENT_WRITE_RETRY`] for up to [`EVENT_WRITE_TIMEOUT`]; past that it is an `Io` error of
    /// kind `TimedOut`.
    ///
    /// A failed write **retires the channel**: every later call fails at once ([`Self::failure`]
    /// says why).
    pub fn respond(&mut self, data: &[u8]) -> Result<()> {
        self.usable()?;
        let result = self.write_sealed(data);
        if let Err(e) = &result {
            self.failed = Some(e.to_string());
        }
        result
    }

    /// Why an earlier failure retired the channel, or `None` while it is usable.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    fn usable(&self) -> Result<()> {
        match &self.failed {
            Some(why) => Err(AirPlayError::ConnectionRetired {
                reason: why.clone(),
            }),
            None => Ok(()),
        }
    }

    fn write_sealed(&mut self, data: &[u8]) -> Result<()> {
        let sealed = self.transport.seal(data)?;
        let deadline = std::time::Instant::now() + EVENT_WRITE_TIMEOUT;
        write_all_until(&mut self.stream, &sealed, deadline)
    }

    /// Reads whatever the receiver has pushed, without waiting, and returns the decrypted bytes of
    /// the complete frames. Empty is the ordinary answer.
    ///
    /// Reads at most [`EVENT_POLL_BUDGET`] bytes per call. A failed read, a frame that does not
    /// open or a close retires the channel: that call still returns every frame that opened before
    /// it (and fails only when there were none), later calls fail and [`Self::failure`] says why.
    pub fn poll(&mut self) -> Result<Vec<u8>> {
        self.poll_with_budget(EVENT_POLL_BUDGET)
    }

    /// [`Self::poll`] with an explicit byte budget, so tests can exercise the bound cheaply.
    fn poll_with_budget(&mut self, budget: usize) -> Result<Vec<u8>> {
        self.usable()?;
        poll_from(
            &mut self.stream,
            &mut self.transport,
            &mut self.failed,
            budget,
        )
    }
}

/// Writes all of `bytes`, retrying a full send buffer every [`EVENT_WRITE_RETRY`] until
/// `deadline`; past it, a write that would block is a `TimedOut` error.
fn write_all_until(
    stream: &mut impl std::io::Write,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(AirPlayError::Io(std::io::ErrorKind::WriteZero.into())),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(AirPlayError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the receiver did not take an event-channel reply in time",
                    )));
                }
                std::thread::sleep(EVENT_WRITE_RETRY);
            }
            Err(e) => return Err(AirPlayError::Io(e)),
        }
    }
    Ok(())
}

/// The body of [`EventChannel::poll`]: reads up to `budget` bytes from `reader`, then opens every
/// complete frame. A failure is recorded in `failed`; it is returned only when no frame opened
/// before it, so a push that arrived just before a reset is still delivered.
fn poll_from(
    reader: &mut impl std::io::Read,
    transport: &mut super::cipher::EncryptedTransport,
    failed: &mut Option<String>,
    budget: usize,
) -> Result<Vec<u8>> {
    let mut buffer = [0u8; 4096];
    let mut taken = 0usize;
    let mut error = None;
    while taken < budget {
        let want = buffer.len().min(budget - taken);
        match reader.read(&mut buffer[..want]) {
            Ok(0) => {
                *failed = Some("the receiver closed the event channel".to_owned());
                break;
            }
            Ok(read) => {
                taken += read;
                transport.push(&buffer[..read]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                *failed = Some(format!("event channel read: {e}"));
                error = Some(AirPlayError::Io(e));
                break;
            }
        }
    }

    let mut out = Vec::new();
    loop {
        match transport.open_next() {
            Ok(Some(frame)) => out.extend_from_slice(&frame),
            Ok(None) => break,
            Err(e) => {
                if failed.is_none() {
                    *failed = Some(format!("a frame did not open: {e}"));
                }
                error.get_or_insert(e);
                break;
            }
        }
    }
    match error {
        Some(e) if out.is_empty() => Err(e),
        _ => Ok(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SetupParams {
        let mut params = SetupParams::new(
            "AA:BB:CC:DD:EE:FF".to_owned(),
            "8F0D1B62-2C0F-4E1D-9B4C-2E9B0C1A7D33".to_owned(),
            crate::DEFAULT_CLIENT_NAME.to_owned(),
        );
        params.timing_port = Some(51234);
        params
    }

    #[test]
    fn the_default_setup_is_still_pyatvs_key_set() {
        let dict = round_trip(&setup_body(&params()).expect("body"));
        let mut keys: Vec<&str> = dict.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "deviceID",
                "macAddress",
                "model",
                "name",
                "osBuildVersion",
                "osName",
                "osVersion",
                "sessionUUID",
                "sourceVersion",
                "timingPort",
                "timingProtocol"
            ]
        );
        assert_eq!(dict.get("macAddress"), dict.get("deviceID"));
        assert_eq!(
            dict.get("model").and_then(plist::Value::as_string),
            Some(SENDER_MODEL)
        );
    }

    fn round_trip(body: &[u8]) -> plist::Dictionary {
        plist::Value::from_reader(std::io::Cursor::new(body))
            .expect("a plist")
            .into_dictionary()
            .expect("a dictionary")
    }

    #[test]
    fn without_a_timing_port_the_protocol_is_none_and_no_port_is_offered() {
        // The remote-control shape; a media SETUP in this shape is refused with 500.
        let dict = round_trip(
            &setup_body(&SetupParams {
                timing_port: None,
                ..params()
            })
            .expect("body"),
        );

        assert_eq!(
            dict.get("timingProtocol").and_then(plist::Value::as_string),
            Some("None")
        );
        assert!(!dict.contains_key("timingPort"));
    }

    #[test]
    fn setup_names_the_timing_port_and_the_protocol() {
        let dict = round_trip(&setup_body(&params()).expect("body"));

        assert_eq!(
            dict.get("timingPort")
                .and_then(plist::Value::as_unsigned_integer),
            Some(51234)
        );
        assert_eq!(
            dict.get("timingProtocol").and_then(plist::Value::as_string),
            Some("NTP")
        );
        assert!(dict.contains_key("deviceID"));
        assert!(dict.contains_key("sessionUUID"));
    }

    #[test]
    fn a_setup_reply_gives_up_the_ephemeral_ports() {
        let mut dict = plist::Dictionary::new();
        dict.insert("eventPort".to_owned(), Value::Integer(49153.into()));
        dict.insert("timingPort".to_owned(), Value::Integer(0.into()));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(dict)).expect("encode");

        let parsed = SetupResponse::parse(&body).expect("parse");

        assert_eq!(parsed.event_port, 49153);
        assert_eq!(parsed.timing_port, 0);
        assert_eq!(parsed.body(), body.as_slice());
        assert!(parsed.timing_peer_info().is_none());
    }

    #[test]
    fn a_setup_reply_that_names_no_ports_is_not_an_error() {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(plist::Dictionary::new()))
            .expect("encode");

        let parsed = SetupResponse::parse(&body).expect("parse");
        assert_eq!((parsed.event_port, parsed.timing_port), (0, 0));
    }

    #[test]
    fn a_setup_reply_that_is_not_a_plist_is_refused() {
        assert!(SetupResponse::parse(b"nonsense").is_err());
    }

    #[test]
    fn v2_play_counts_the_start_position_in_seconds_not_fractions() {
        // v1's Start-Position is a fraction of the duration; mixing them up starts a film at the
        // end.
        let dict = round_trip(&play_body("http://host/a.mp4", 90.0, "uuid-1").expect("body"));

        assert_eq!(
            dict.get("Start-Position-Seconds")
                .and_then(plist::Value::as_real),
            Some(90.0)
        );
        assert!(!dict.contains_key("Start-Position"));
        assert_eq!(
            dict.get("Content-Location")
                .and_then(plist::Value::as_string),
            Some("http://host/a.mp4")
        );
    }

    #[test]
    fn a_negative_start_position_is_clamped_rather_than_sent() {
        let dict = round_trip(&play_body("http://host/a.mp4", -5.0, "uuid-1").expect("body"));

        assert_eq!(
            dict.get("Start-Position-Seconds")
                .and_then(plist::Value::as_real),
            Some(0.0)
        );
    }

    #[test]
    fn a_non_finite_start_position_is_sent_as_zero() {
        for start in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let dict = round_trip(&play_body("http://host/a.mp4", start, "uuid-1").expect("body"));
            assert_eq!(
                dict.get("Start-Position-Seconds")
                    .and_then(plist::Value::as_real),
                Some(0.0),
                "{start}"
            );
        }
    }

    /// A loopback "receiver" that seals `frames` pushes of `size` bytes each, as fast as the socket
    /// takes them, and an [`EventChannel`] reading them with the matching key.
    fn pushing_receiver(frames: usize, size: usize) -> (EventChannel, std::thread::JoinHandle<()>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("address");
        let (receiver_key, sender_key) = ([0x11u8; 32], [0x22u8; 32]);
        let receiver = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut transport =
                crate::cipher::EncryptedTransport::from_keys(&receiver_key, &sender_key);
            let push = vec![0x5Au8; size];
            for _ in 0..frames {
                let sealed = transport.seal(&push).expect("seal");
                if socket.write_all(&sealed).is_err() {
                    return;
                }
            }
        });
        let stream = std::net::TcpStream::connect(address).expect("connect");
        stream.set_nonblocking(true).expect("non-blocking");
        let channel = EventChannel {
            stream,
            transport: crate::cipher::EncryptedTransport::from_keys(&sender_key, &receiver_key),
            failed: None,
        };
        (channel, receiver)
    }

    #[test]
    fn a_receiver_that_never_stops_pushing_cannot_hold_a_poll() {
        // 600 KB of pushes against a 16 KiB budget: one poll must return at most the budget.
        let (mut channel, receiver) = pushing_receiver(600, 1000);
        let budget = 16 * 1024;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut first = Vec::new();
        while first.is_empty() && std::time::Instant::now() < deadline {
            first = channel.poll_with_budget(budget).expect("poll");
            if first.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }

        assert!(
            !first.is_empty(),
            "the receiver was pushing; something should arrive"
        );
        assert!(
            first.len() <= budget,
            "one poll returned {} bytes against a {budget}-byte budget",
            first.len()
        );

        let mut total = first.len();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while total < 600 * 1000 && std::time::Instant::now() < deadline {
            total += channel.poll_with_budget(budget).expect("poll").len();
        }
        assert_eq!(total, 600 * 1000);
        receiver.join().expect("receiver thread");
    }

    #[test]
    fn pushes_cut_into_tiny_pieces_with_pauses_open_whole_and_in_order() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let (receiver_key, sender_key) = ([0x31u8; 32], [0x42u8; 32]);
        let pushes: Vec<Vec<u8>> = (0..60u8)
            .map(|i| vec![i; 50 + usize::from(i) * 7])
            .collect();
        let expected: Vec<u8> = pushes.concat();
        let writer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut transport =
                crate::cipher::EncryptedTransport::from_keys(&receiver_key, &sender_key);
            let wire: Vec<u8> = pushes
                .iter()
                .flat_map(|p| transport.seal(p).expect("seal"))
                .collect();
            let mut rng = 0x0DDB_A11C_0FFE_E123u64;
            let mut at = 0;
            while at < wire.len() {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let n = usize::try_from(rng % 5 + 1).unwrap().min(wire.len() - at);
                socket.write_all(&wire[at..at + n]).expect("write");
                at += n;
                if rng.is_multiple_of(4) {
                    std::thread::sleep(std::time::Duration::from_micros(rng % 1_000));
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let stream = std::net::TcpStream::connect(address).expect("connect");
        stream.set_nonblocking(true).expect("non-blocking");
        let mut channel = EventChannel {
            stream,
            transport: crate::cipher::EncryptedTransport::from_keys(&sender_key, &receiver_key),
            failed: None,
        };
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while got.len() < expected.len() && std::time::Instant::now() < deadline {
            got.extend(channel.poll().expect("every frame opens"));
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(got, expected);
        writer.join().expect("writer");
    }

    #[test]
    fn a_channel_the_receiver_closed_is_retired_after_what_it_held() {
        let (mut channel, receiver) = pushing_receiver(2, 100);
        receiver.join().expect("receiver thread");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = Vec::new();
        while channel.failure().is_none() && std::time::Instant::now() < deadline {
            got.extend(channel.poll().expect("what was sent opens"));
        }
        assert_eq!(got.len(), 200, "everything sent before the close was read");
        assert!(channel.failure().unwrap().contains("closed"));
        assert!(channel.poll().is_err(), "retired");
        assert!(
            channel
                .respond(
                    b"RTSP/1.0 200 OK

"
                )
                .is_err(),
            "retired"
        );
    }

    /// A reader that hands out its chunks one per read, then fails with `then`.
    struct ScriptedReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
        then: std::io::ErrorKind,
    }

    impl std::io::Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Err(self.then.into()),
            }
        }
    }

    fn event_keys() -> (
        crate::cipher::EncryptedTransport,
        crate::cipher::EncryptedTransport,
    ) {
        let (receiver_key, sender_key) = ([0x11u8; 32], [0x22u8; 32]);
        (
            crate::cipher::EncryptedTransport::from_keys(&receiver_key, &sender_key),
            crate::cipher::EncryptedTransport::from_keys(&sender_key, &receiver_key),
        )
    }

    #[test]
    fn a_push_read_just_before_a_reset_is_delivered_and_the_channel_then_retired() {
        let (mut receiver, mut ours) = event_keys();
        let push = receiver.seal(b"POST /command").expect("seal");
        let mut reader = ScriptedReader {
            chunks: [push].into(),
            then: std::io::ErrorKind::ConnectionReset,
        };
        let mut failed = None;

        let got = poll_from(&mut reader, &mut ours, &mut failed, EVENT_POLL_BUDGET)
            .expect("the push that came before the reset");
        assert_eq!(got, b"POST /command");
        assert!(failed.expect("retired").contains("read"));
    }

    #[test]
    fn a_reset_with_nothing_read_is_an_error_at_once() {
        let (_, mut ours) = event_keys();
        let mut reader = ScriptedReader {
            chunks: std::collections::VecDeque::new(),
            then: std::io::ErrorKind::ConnectionReset,
        };
        let mut failed = None;
        assert!(poll_from(&mut reader, &mut ours, &mut failed, EVENT_POLL_BUDGET).is_err());
        assert!(failed.is_some());
    }

    #[test]
    fn frames_that_opened_before_a_bad_one_are_delivered() {
        let (mut receiver, mut ours) = event_keys();
        let mut stranger = crate::cipher::EncryptedTransport::from_keys(&[0x77; 32], &[0x77; 32]);
        let mut wire = receiver.seal(b"first").expect("seal");
        wire.extend(receiver.seal(b"second").expect("seal"));
        wire.extend(stranger.seal(b"forged").expect("seal"));
        let mut reader = ScriptedReader {
            chunks: [wire].into(),
            then: std::io::ErrorKind::WouldBlock,
        };
        let mut failed = None;

        let got = poll_from(&mut reader, &mut ours, &mut failed, EVENT_POLL_BUDGET)
            .expect("the two good frames");
        assert_eq!(got, b"firstsecond");
        assert!(failed.expect("retired").contains("did not open"));
    }

    #[test]
    fn a_reply_the_receiver_never_takes_times_out() {
        struct Full;
        impl std::io::Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = write_all_until(&mut Full, b"reply", std::time::Instant::now())
            .expect_err("never taken");
        assert!(
            matches!(&error, AirPlayError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{error:?}"
        );
    }

    #[test]
    fn the_default_poll_budget_is_far_above_an_ordinary_push() {
        let (mut channel, receiver) = pushing_receiver(3, 2264);
        receiver.join().expect("receiver thread");

        assert_eq!(channel.poll().expect("poll").len(), 3 * 2264);
    }

    #[test]
    fn connect_with_retry_gives_up_after_the_configured_attempts_and_returns_the_last_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        let address: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = EventChannel::connect_with_retry_fn(
            |_, _| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "simulated refusal",
                ))
            },
            &address,
            std::time::Duration::from_millis(1),
            3,
            std::time::Duration::from_millis(1),
        );

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("after 3 attempts"),
            "expected retry exhaustion message, got: {err_msg}"
        );
    }

    #[test]
    fn connect_with_retry_succeeds_on_a_later_attempt() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let result = EventChannel::connect_with_retry_fn(
            |addr, timeout| {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "simulated refusal",
                    ))
                } else {
                    std::net::TcpStream::connect_timeout(addr, timeout)
                }
            },
            &address,
            std::time::Duration::from_millis(200),
            5,
            std::time::Duration::from_millis(1),
        );

        assert!(result.is_ok(), "should have connected on attempt 3");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn connect_with_retry_does_not_panic_on_zero_attempts() {
        let address: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = EventChannel::connect_with_retry_fn(
            |_, _| {
                panic!("the connector should never be called with max_attempts == 0");
            },
            &address,
            std::time::Duration::from_millis(1),
            0,
            std::time::Duration::from_millis(1),
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("after 0 attempts"),
            "expected zero-attempt message, got: {err_msg}"
        );
    }

    #[test]
    fn connect_with_retry_fails_immediately_on_non_refused_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        let address: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = EventChannel::connect_with_retry_fn(
            |_, _| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated timeout",
                ))
            },
            &address,
            std::time::Duration::from_millis(1),
            5,
            std::time::Duration::from_millis(1),
        );

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "should not have retried"
        );
        assert!(result.is_err());
    }
}
