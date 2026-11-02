//! The audio session as a sans-io state machine, and the packetizer it hands off to.
//!
//! [`AudioSendState`] sequences the control-channel requests after the session `SETUP`, emitting
//! [`Action`]s and consuming responses. It owns no socket and no clock. [`AudioPacketizer`] turns
//! PCM into wire bytes (ALAC verbatim or big-endian LPCM, RTP header, seal, buffered length
//! prefix).
//!
//! ```text
//!   Ntp (realtime, type 96)
//!     SETUP (stream) -> open UDP data -> POST /feedback -> RECORD -> FLUSH (RTP-Info)
//!     -> stream, with /feedback every 2 s -> TEARDOWN
//!
//!   Ptp (buffered, type 103)
//!     SETUP (stream) -> open TCP data -> SETPEERS -> RECORD -> SETRATEANCHORTIME (rate 1)
//!     -> stream, with /feedback every 2 s -> TEARDOWN {streams} -> TEARDOWN {}
//! ```
//!
//! The Ntp order matches pyatv. The Ptp order is assumed from two open receivers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand_core::CryptoRng;

use super::alac::AlacConfig;
use super::control::{self, RateAnchor};
use super::format::{compression, StreamFormat, StreamType};
use super::rtp::{
    buffered_sequence, frame_buffered, realtime_sequence, BufferedHeader, PacketSealer, RtpClock,
    RtpHeader, SyncPacket,
};
use super::stream::{StreamSetup, StreamSetupResponse};
use crate::error::{AirPlayError, Result};
use crate::rtsp::{Protocol, Request, Response};
use crate::session::{PLIST_CONTENT_TYPE, TEXT_PARAMETERS_CONTENT_TYPE};
use crate::time::{NtpTimestamp, RtpTimestamp};

/// How the stream is timed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimingMode {
    /// NTP: the session `SETUP` named a timing port (a [`crate::timing::TimingServer`] answers
    /// it); realtime streams carry sync packets on the control port.
    Ntp,
    /// PTP: the session `SETUP` named `timingPeerInfo`; `SETPEERS` lists every peer's addresses
    /// and a `SETRATEANCHORTIME` starts the stream.
    Ptp {
        /// Every address of every peer, receivers first then the sender.
        peers: Vec<String>,
    },
}

/// Everything the state machine needs to know up front.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AudioSendConfig {
    /// `rtsp://<our address>/<session id>` — [`crate::client::ControlChannel::session_uri`].
    pub session_uri: String,
    /// The stream `SETUP` to send.
    pub stream: StreamSetup,
    /// NTP or PTP.
    pub timing: TimingMode,
    /// Sequence number of the first packet.
    pub first_sequence: u32,
    /// RTP timestamp of the first packet.
    pub first_timestamp: RtpTimestamp,
    /// `/feedback` period.
    pub feedback_interval: Duration,
    /// Whether this configuration, or a clone of it, has handed out its packetizer.
    packetizer_issued: Arc<AtomicBool>,
}

impl AudioSendConfig {
    /// A configuration for `connection`'s session with a fresh stream key, first sequence number
    /// and first timestamp drawn from `rng`. The `streamConnectionID` (and realtime SSRC) is the
    /// session's numeric id.
    pub fn generate(
        connection: &crate::client::SenderConnection,
        stream_type: StreamType,
        format: StreamFormat,
        control_port: u16,
        timing: TimingMode,
        rng: &mut dyn CryptoRng,
    ) -> Self {
        let mut shared_key = [0u8; 32];
        rng.fill_bytes(&mut shared_key);
        let stream = StreamSetup::new(
            stream_type,
            format,
            control_port,
            shared_key,
            u64::from(connection.rtsp_session_id()),
        );
        let first_sequence = u32::from(rng.next_u32() as u16);
        let first_timestamp = RtpTimestamp::new(rng.next_u32());
        Self::new(
            connection.session_uri(),
            stream,
            timing,
            first_sequence,
            first_timestamp,
        )
    }

    /// The same configuration with the first packet at RTP time `first_timestamp` (a timeline's).
    #[must_use]
    pub fn with_first_timestamp(mut self, first_timestamp: RtpTimestamp) -> Self {
        self.first_timestamp = first_timestamp;
        self
    }

    /// This stream's packetizer, starting where `RECORD`/`FLUSH` say. A realtime stream's SSRC is
    /// the low 32 bits of its `streamConnectionID`.
    ///
    /// Handed out once per configuration, clones included: every packetizer starts its nonce
    /// counter at zero, so a second one under the same stream key would reuse ChaCha20-Poly1305
    /// nonces. A second call, on this configuration or any clone of it (an [`AudioSendState`]'s
    /// among them), is [`AirPlayError::InvalidState`]. A configuration built anew ([`Self::new`],
    /// [`Self::generate`]) has a guard of its own, so give each one its own key.
    pub fn packetizer(&self) -> Result<AudioPacketizer> {
        if self.packetizer_issued.swap(true, Ordering::SeqCst) {
            return Err(AirPlayError::InvalidState(
                "this stream's packetizer was already handed out; a second would reuse its nonces"
                    .to_owned(),
            ));
        }
        AudioPacketizer::for_stream(
            &self.stream,
            self.stream.stream_connection_id as u32,
            self.first_sequence,
            self.first_timestamp,
        )
    }

    /// A configuration with the default feedback period.
    #[must_use]
    pub fn new(
        session_uri: String,
        stream: StreamSetup,
        timing: TimingMode,
        first_sequence: u32,
        first_timestamp: RtpTimestamp,
    ) -> Self {
        Self {
            session_uri,
            stream,
            timing,
            first_sequence,
            first_timestamp,
            feedback_interval: control::FEEDBACK_INTERVAL,
            packetizer_issued: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Which request a response belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    /// The stream `SETUP`.
    StreamSetup,
    /// `SETPEERS`.
    SetPeers,
    /// `POST /feedback`.
    Feedback,
    /// `RECORD`.
    Record,
    /// `FLUSH`.
    Flush,
    /// `SETRATEANCHORTIME`.
    SetRateAnchor,
    /// `TEARDOWN` of the stream.
    TeardownStream,
    /// `TEARDOWN` of the session.
    TeardownSession,
    /// `SET_PARAMETER` (volume, now-playing, artwork or progress). The body comes from
    /// [`AudioSendState`]'s FIFO queue in the order the `set_`/`push_` methods were called.
    SetParameter,
}

impl Step {
    /// Whether a non-2xx answer ends the session. `/feedback`, the teardowns and `SET_PARAMETER`
    /// are best effort.
    #[must_use]
    pub fn is_essential(self) -> bool {
        !matches!(
            self,
            Self::Feedback | Self::TeardownStream | Self::TeardownSession | Self::SetParameter
        )
    }
}

/// The data channel's transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataTransport {
    /// Realtime: datagrams to `dataPort`.
    Udp,
    /// Buffered: one TCP connection to `dataPort`, length-prefixed packets.
    Tcp,
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Send this request on the control channel and pass the response to
    /// [`AudioSendState::on_response`].
    Send {
        /// Which request it is.
        step: Step,
        /// The request; the control channel adds `CSeq` and the session headers.
        request: Request,
    },
    /// Open the data channel, then call [`AudioSendState::data_connected`].
    ConnectData {
        /// UDP or TCP.
        transport: DataTransport,
        /// The receiver's `dataPort`.
        data_port: u16,
        /// The receiver's `controlPort` (0 if it named none).
        control_port: u16,
    },
    /// PTP only: compute a [`RateAnchor`] from the followed clock and pass it to
    /// [`AudioSendState::provide_anchor`].
    NeedAnchor,
    /// Start sending packets from these values ([`AudioPacketizer`]). Emitted once.
    StartStreaming {
        /// First sequence number.
        first_sequence: u32,
        /// First RTP timestamp.
        first_timestamp: RtpTimestamp,
    },
    /// Nothing to do until a response, a callback or time passes.
    Wait,
    /// The session is over (torn down).
    Finished,
    /// An essential step failed; the session cannot continue. Repeats until dropped.
    Failed {
        /// Which step.
        step: Step,
        /// The status, if the receiver answered with one.
        status: Option<u16>,
        /// Why.
        reason: String,
    },
}

/// The audio session state machine. See the module docs.
#[derive(Debug)]
pub struct AudioSendState {
    config: AudioSendConfig,
    queue: VecDeque<Step>,
    in_flight: Option<Step>,
    stream: Option<StreamSetupResponse>,
    connect_pending: bool,
    awaiting_connection: bool,
    need_anchor: bool,
    anchor: Option<RateAnchor>,
    streaming: bool,
    announced: bool,
    last_feedback: Option<Duration>,
    stopping: bool,
    finished: bool,
    failure: Option<(Step, Option<u16>, String)>,
    /// One `(Content-Type, body)` pair per queued [`Step::SetParameter`], FIFO.
    pending_set_parameters: VecDeque<(String, Vec<u8>)>,
}

impl AudioSendState {
    /// A session that will start with the stream `SETUP`.
    #[must_use]
    pub fn new(config: AudioSendConfig) -> Self {
        Self {
            config,
            queue: VecDeque::from([Step::StreamSetup]),
            in_flight: None,
            stream: None,
            connect_pending: false,
            awaiting_connection: false,
            need_anchor: false,
            anchor: None,
            streaming: false,
            announced: false,
            last_feedback: None,
            stopping: false,
            finished: false,
            failure: None,
            pending_set_parameters: VecDeque::new(),
        }
    }

    /// The configuration it was built with.
    #[must_use]
    pub fn config(&self) -> &AudioSendConfig {
        &self.config
    }

    /// This stream's packetizer, starting where `RECORD`/`FLUSH` say; a realtime stream's SSRC is
    /// the low 32 bits of its `streamConnectionID`.
    ///
    /// [`AudioSendConfig::packetizer`]: handed out once per configuration and its clones, so a
    /// second call here, or on the configuration it was built from, is
    /// [`AirPlayError::InvalidState`].
    pub fn packetizer(&self) -> Result<AudioPacketizer> {
        self.config.packetizer()
    }

    /// Queues `volume: <dB>\r\n` (`text/parameters`) for the next round, best effort, clamped to
    /// 0 (loudest) to -144 (mute). A no-op once stopped or finished.
    pub fn set_volume(&mut self, db: f64) {
        let clamped = db.clamp(-144.0, 0.0);
        self.queue_set_parameter(
            TEXT_PARAMETERS_CONTENT_TYPE,
            format!("volume: {clamped:.6}\r\n").into_bytes(),
        );
    }

    /// Queues DMAP now-playing metadata ([`crate::dmap::NowPlaying::encode`],
    /// [`crate::dmap::METADATA_CONTENT_TYPE`]) for the next round. Best effort; a no-op once
    /// stopped.
    pub fn push_now_playing(&mut self, dmap: Vec<u8>) {
        self.queue_set_parameter(crate::dmap::METADATA_CONTENT_TYPE, dmap);
    }

    /// Queues artwork (`image/jpeg` or `image/png`,
    /// [`crate::dmap::artwork_content_type`]/[`crate::dmap::ArtworkFormat::content_type`]) for the
    /// next round. Best effort; a no-op once stopped.
    pub fn push_artwork(&mut self, content_type: impl Into<String>, data: Vec<u8>) {
        self.queue_set_parameter(content_type, data);
    }

    /// Queues `progress: start/current/end` ([`crate::dmap::progress_body`],
    /// [`crate::dmap::PROGRESS_CONTENT_TYPE`]) for the next round. Best effort; a no-op once
    /// stopped.
    pub fn push_progress(&mut self, body: Vec<u8>) {
        self.queue_set_parameter(crate::dmap::PROGRESS_CONTENT_TYPE, body);
    }

    fn queue_set_parameter(&mut self, content_type: impl Into<String>, body: Vec<u8>) {
        if self.stopping || self.finished {
            // Nothing left to send it on; best-effort pushes drop silently.
            return;
        }
        self.pending_set_parameters
            .push_back((content_type.into(), body));
        self.queue.push_back(Step::SetParameter);
    }

    /// The stream `SETUP` reply, once it has arrived.
    #[must_use]
    pub fn stream(&self) -> Option<&StreamSetupResponse> {
        self.stream.as_ref()
    }

    /// Whether packets may be sent.
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        self.streaming && !self.stopping && self.failure.is_none()
    }

    /// The next thing to do. `now` is the caller's monotonic clock (time since any fixed origin);
    /// it paces `/feedback`.
    pub fn poll(&mut self, now: Duration) -> Action {
        if let Some((step, status, reason)) = &self.failure {
            return Action::Failed {
                step: *step,
                status: *status,
                reason: reason.clone(),
            };
        }
        if self.in_flight.is_some() || self.awaiting_connection {
            return Action::Wait;
        }
        if self.connect_pending {
            self.connect_pending = false;
            self.awaiting_connection = true;
            let Some(stream) = self.stream else {
                return self.fail(Step::StreamSetup, None, "no stream SETUP reply".to_owned());
            };
            return Action::ConnectData {
                transport: match self.config.stream.stream_type {
                    StreamType::Buffered => DataTransport::Tcp,
                    StreamType::Realtime => DataTransport::Udp,
                },
                data_port: stream.data_port,
                control_port: stream.control_port,
            };
        }
        if let Some(step) = self.queue.pop_front() {
            return match self.request_for(step) {
                Ok(request) => {
                    self.in_flight = Some(step);
                    if step == Step::Feedback {
                        self.last_feedback = Some(now);
                    }
                    Action::Send { step, request }
                }
                Err(e) => self.fail(step, None, e.to_string()),
            };
        }
        if self.finished {
            return Action::Finished;
        }
        if self.need_anchor {
            return Action::NeedAnchor;
        }
        if self.streaming && !self.stopping {
            if !self.announced {
                self.announced = true;
                return Action::StartStreaming {
                    first_sequence: self.config.first_sequence,
                    first_timestamp: self.config.first_timestamp,
                };
            }
            let due = self
                .last_feedback
                .is_none_or(|last| now.saturating_sub(last) >= self.config.feedback_interval);
            if due {
                self.queue.push_back(Step::Feedback);
                return self.poll(now);
            }
        }
        Action::Wait
    }

    /// Feeds the response to the request most recently emitted.
    ///
    /// Errors (and moves to [`Action::Failed`]) when an essential step is refused or its reply
    /// cannot be read; a response with nothing in flight is an error that changes nothing.
    pub fn on_response(&mut self, response: &Response) -> Result<()> {
        let step = self.in_flight.take().ok_or_else(|| {
            AirPlayError::InvalidState("a response arrived with no request in flight".to_owned())
        })?;
        if !response.is_success() {
            if step.is_essential() && !self.stopping {
                self.fail(step, Some(response.status), format!("{step:?} was refused"));
                return Err(AirPlayError::Status {
                    path: format!("{step:?}"),
                    code: response.status,
                    reason: None,
                });
            }
            log::debug!(
                "{step:?} answered {} (best effort, ignored)",
                response.status
            );
        }
        match step {
            Step::StreamSetup => match StreamSetupResponse::parse(&response.body) {
                Ok(stream) => {
                    self.stream = Some(stream);
                    if !self.stopping {
                        self.connect_pending = true;
                    }
                }
                Err(e) => {
                    self.fail(step, Some(response.status), e.to_string());
                    return Err(e);
                }
            },
            Step::Record if !self.stopping => match self.config.timing {
                TimingMode::Ntp => self.queue.push_back(Step::Flush),
                TimingMode::Ptp { .. } => {
                    if self.anchor.is_some() {
                        self.queue.push_back(Step::SetRateAnchor);
                    } else {
                        self.need_anchor = true;
                    }
                }
            },
            Step::Flush | Step::SetRateAnchor if !self.stopping => self.streaming = true,
            Step::TeardownSession => self.finished = true,
            _ => {}
        }
        Ok(())
    }

    /// The data channel is open (after [`Action::ConnectData`]).
    pub fn data_connected(&mut self) {
        if !self.awaiting_connection {
            return;
        }
        self.awaiting_connection = false;
        if self.stopping {
            return;
        }
        match self.config.timing {
            TimingMode::Ntp => {
                self.queue.push_back(Step::Feedback);
                self.queue.push_back(Step::Record);
            }
            TimingMode::Ptp { .. } => {
                self.queue.push_back(Step::SetPeers);
                self.queue.push_back(Step::Record);
            }
        }
    }

    /// The data channel could not be opened: the session fails.
    pub fn data_failed(&mut self, reason: &str) {
        self.awaiting_connection = false;
        self.fail(Step::StreamSetup, None, format!("data channel: {reason}"));
    }

    /// Supplies (or replaces) the rate anchor: held until `RECORD` is accepted, then sent at once.
    /// Also how a running stream is re-anchored.
    pub fn provide_anchor(&mut self, anchor: RateAnchor) {
        self.anchor = Some(anchor);
        if self.need_anchor || self.streaming {
            self.need_anchor = false;
            if !self.stopping {
                self.queue.push_back(Step::SetRateAnchor);
            }
        }
    }

    /// Ends the session: drops anything queued and tears down. A request already in flight still
    /// gets its response fed as usual.
    pub fn stop(&mut self) {
        if self.stopping || self.finished {
            return;
        }
        self.stopping = true;
        self.need_anchor = false;
        self.connect_pending = false;
        // A data channel still being opened is abandoned; a late data_connected() is ignored.
        self.awaiting_connection = false;
        self.queue.clear();
        self.pending_set_parameters.clear();
        if self.stream.is_some() && matches!(self.config.timing, TimingMode::Ptp { .. }) {
            self.queue.push_back(Step::TeardownStream);
        }
        self.queue.push_back(Step::TeardownSession);
    }

    fn fail(&mut self, step: Step, status: Option<u16>, reason: String) -> Action {
        self.failure = Some((step, status, reason.clone()));
        self.queue.clear();
        self.streaming = false;
        Action::Failed {
            step,
            status,
            reason,
        }
    }

    fn request_for(&mut self, step: Step) -> Result<Request> {
        let uri = self.config.session_uri.clone();
        let plist = |method: &str, body: Vec<u8>| {
            let mut request = Request::new(method, uri.clone(), Protocol::Rtsp, body);
            request.headers.set("Content-Type", PLIST_CONTENT_TYPE);
            request
        };
        Ok(match step {
            Step::StreamSetup => plist("SETUP", self.config.stream.body()?),
            Step::SetPeers => {
                let TimingMode::Ptp { peers } = &self.config.timing else {
                    return Err(AirPlayError::InvalidState(
                        "SETPEERS belongs to a PTP session".to_owned(),
                    ));
                };
                let mut request = Request::new(
                    "SETPEERS",
                    uri,
                    Protocol::Rtsp,
                    control::set_peers_body(peers)?,
                );
                request
                    .headers
                    .set("Content-Type", control::SET_PEERS_CONTENT_TYPE);
                request
            }
            Step::Feedback => Request::new("POST", "/feedback", Protocol::Rtsp, Vec::new()),
            Step::Record => Request::new("RECORD", uri, Protocol::Rtsp, Vec::new()),
            Step::Flush => {
                let mut request = Request::new("FLUSH", uri, Protocol::Rtsp, Vec::new());
                request.headers.set("Range", "npt=0-");
                request.headers.set(
                    "RTP-Info",
                    control::rtp_info(self.config.first_sequence, self.config.first_timestamp),
                );
                request
            }
            Step::SetRateAnchor => {
                let anchor = self.anchor.ok_or_else(|| {
                    AirPlayError::InvalidState("no rate anchor was provided".to_owned())
                })?;
                plist("SETRATEANCHORTIME", anchor.body()?)
            }
            Step::TeardownStream => {
                let stream_id = self.stream.and_then(|s| s.stream_id).unwrap_or(0);
                plist(
                    "TEARDOWN",
                    control::teardown_stream_body(self.config.stream.stream_type, stream_id)?,
                )
            }
            Step::TeardownSession => match self.config.timing {
                TimingMode::Ntp => Request::new("TEARDOWN", uri, Protocol::Rtsp, Vec::new()),
                TimingMode::Ptp { .. } => plist("TEARDOWN", control::teardown_session_body()?),
            },
            Step::SetParameter => {
                // Invariant: every queued `SetParameter` has a matching pending body.
                let (content_type, body) =
                    self.pending_set_parameters.pop_front().unwrap_or_default();
                let mut request = Request::new("SET_PARAMETER", uri, Protocol::Rtsp, body);
                request.headers.set("Content-Type", content_type);
                request
            }
        })
    }
}

/// Turns PCM into wire-ready audio packets for one stream.
///
/// Each call to [`Self::packet`] takes up to `spf` interleaved frames and returns what goes on the
/// data channel as-is: a datagram for realtime, a length-prefixed frame for buffered. A short final
/// packet is padded with silence, so every packet advances the RTP timestamp by exactly `spf`.
///
/// `ct: 2` is ALAC (verbatim frames); `ct: 1` is 16-bit big-endian LPCM.
#[derive(Debug)]
pub struct AudioPacketizer {
    stream_type: StreamType,
    codec: Codec,
    sealer: PacketSealer,
    clock: RtpClock,
    ssrc: u32,
    first_sequence: u32,
    index: u64,
}

/// What a packet's payload is.
#[derive(Debug, Clone, Copy)]
enum Codec {
    Alac(AlacConfig),
    Lpcm { channels: usize, frames: usize },
}

impl Codec {
    fn for_format(format: &StreamFormat) -> Result<Self> {
        if format.compression != compression::LPCM {
            return Ok(Self::Alac(AlacConfig::for_format(format)?));
        }
        if format.bits_per_sample != 16 || format.channels == 0 || format.frames_per_packet == 0 {
            return Err(AirPlayError::Protocol(format!(
                "LPCM is packetized as 16-bit with at least one channel and frame, not {} bits, \
                 {} channels, {} frames",
                format.bits_per_sample, format.channels, format.frames_per_packet
            )));
        }
        Ok(Self::Lpcm {
            channels: usize::from(format.channels),
            frames: format.frames_per_packet as usize,
        })
    }

    /// Samples in one whole packet, and its frames.
    fn samples_per_packet(&self) -> (usize, u32) {
        match *self {
            Self::Alac(alac) => (
                alac.frame_length as usize * usize::from(alac.channels),
                alac.frame_length,
            ),
            Self::Lpcm { channels, frames } => (frames * channels, frames as u32),
        }
    }

    /// One packet's payload from exactly a whole packet of samples.
    fn encode(&self, interleaved: &[i32]) -> Result<Vec<u8>> {
        match self {
            Self::Alac(alac) => alac.encode_verbatim(interleaved),
            Self::Lpcm { .. } => Ok(pcm16_be(interleaved)),
        }
    }
}

/// Interleaved samples as big-endian 16-bit PCM; values outside `i16` are clamped.
#[must_use]
pub fn pcm16_be(interleaved: &[i32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(interleaved.len() * 2);
    for &sample in interleaved {
        let clamped = sample.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        out.extend_from_slice(&clamped.to_be_bytes());
    }
    out
}

impl AudioPacketizer {
    /// A packetizer for `setup`'s stream.
    ///
    /// Its nonce counter starts at zero: make one packetizer per stream key, never two from the
    /// same [`StreamSetup`], or packets reuse nonces under that key
    /// ([`AudioSendConfig::packetizer`] enforces this for a configuration and its clones).
    ///
    /// `ssrc`: any source id for realtime; for buffered it must be the format identifier
    /// ([`super::StreamFormat::buffered_ssrc`]), which [`Self::for_stream`] picks.
    pub fn new(
        setup: &StreamSetup,
        ssrc: u32,
        first_sequence: u32,
        first_timestamp: RtpTimestamp,
    ) -> Result<Self> {
        Ok(Self {
            stream_type: setup.stream_type,
            codec: Codec::for_format(&setup.format)?,
            sealer: PacketSealer::new(&setup.shared_key),
            clock: RtpClock::new(
                setup.format.sample_rate,
                setup.format.frames_per_packet,
                first_timestamp,
            ),
            ssrc,
            first_sequence,
            index: 0,
        })
    }

    /// Like [`Self::new`], choosing the SSRC: `realtime_ssrc` for a realtime stream, the format
    /// identifier for a buffered one (an error if the format has none).
    pub fn for_stream(
        setup: &StreamSetup,
        realtime_ssrc: u32,
        first_sequence: u32,
        first_timestamp: RtpTimestamp,
    ) -> Result<Self> {
        let ssrc = match setup.stream_type {
            StreamType::Realtime => realtime_ssrc,
            StreamType::Buffered => setup.format.buffered_ssrc().ok_or_else(|| {
                AirPlayError::Protocol(format!(
                    "no buffered SSRC is known for audio format {:#x}; a receiver would drop \
                     every packet (use StreamFormat::ALAC_48000_24_STEREO)",
                    setup.format.audio_format
                ))
            })?,
        };
        Self::new(setup, ssrc, first_sequence, first_timestamp)
    }

    /// How many packets have been produced.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.index
    }

    /// The sequence number the next packet will carry.
    #[must_use]
    pub fn next_sequence(&self) -> u32 {
        match self.stream_type {
            StreamType::Realtime => {
                u32::from(realtime_sequence(self.first_sequence as u16, self.index))
            }
            StreamType::Buffered => buffered_sequence(self.first_sequence, self.index),
        }
    }

    /// The RTP timestamp the next packet will carry.
    #[must_use]
    pub fn next_timestamp(&self) -> RtpTimestamp {
        self.clock.timestamp_of_packet(self.index)
    }

    /// The stream's clock.
    #[must_use]
    pub fn clock(&self) -> RtpClock {
        self.clock
    }

    /// Moves the stream past `packets` packets without building them: the next packet carries the
    /// sequence number and RTP timestamp it would have after that many calls to [`Self::packet`]
    /// (both wrap as they always do), and [`Self::packets_sent`] counts them. Nothing is encoded or
    /// sealed, so the nonce counter does not move. For a sender that has fallen far behind real
    /// time: the receiver sees a gap, as for lost packets. Only the stream's very first packet
    /// carries the RTP marker, so a skip before any packet leaves none marked.
    pub fn skip(&mut self, packets: u64) {
        self.index = self.index.saturating_add(packets);
    }

    /// Encodes, seals and frames one packet of interleaved samples (at most `spf` frames).
    pub fn packet(&mut self, interleaved: &[i32]) -> Result<Vec<u8>> {
        let (full, frames) = self.codec.samples_per_packet();
        if interleaved.len() > full {
            return Err(AirPlayError::Protocol(format!(
                "{} samples exceed one {frames}-frame packet",
                interleaved.len(),
            )));
        }
        let frame = if interleaved.len() == full {
            self.codec.encode(interleaved)?
        } else {
            let mut padded = interleaved.to_vec();
            padded.resize(full, 0);
            self.codec.encode(&padded)?
        };
        let timestamp = self.next_timestamp();
        let sequence = self.next_sequence();
        let header = match self.stream_type {
            StreamType::Realtime => {
                RtpHeader::audio(self.index == 0, sequence as u16, timestamp, self.ssrc).encode()
            }
            StreamType::Buffered => BufferedHeader::new(sequence, timestamp, self.ssrc).encode(),
        };
        let sealed = self.sealer.seal(&header, &frame)?;
        self.index += 1;
        match self.stream_type {
            StreamType::Realtime => Ok(sealed),
            StreamType::Buffered => frame_buffered(&sealed),
        }
    }

    /// A realtime sync packet for "now": the next packet's timestamp, less `latency_frames`, and
    /// the NTP time the caller's clock gives for it. Send one a second; `first` for the first.
    #[must_use]
    pub fn sync_packet(&self, first: bool, latency_frames: u32, ntp: NtpTimestamp) -> SyncPacket {
        let now = self.next_timestamp();
        SyncPacket {
            first,
            flags: super::rtp::SYNC_FLAGS,
            now_without_latency: now.wrapping_sub(latency_frames),
            ntp,
            now,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::time::RtpTimestamp;

    #[test]
    fn lpcm_is_big_endian_and_clamped() {
        assert_eq!(
            super::pcm16_be(&[1, -2, 40_000, -40_000]),
            [0x00, 0x01, 0xFF, 0xFE, 0x7F, 0xFF, 0x80, 0x00]
        );
    }

    #[test]
    fn an_lpcm_packet_opens_to_its_samples_padded_to_a_whole_packet() {
        use crate::audio::rtp::{open_packet, RtpHeader};
        use crate::audio::{StreamFormat, StreamSetup, StreamType};
        let setup = StreamSetup::new(
            StreamType::Realtime,
            StreamFormat::PCM_44100_16_STEREO,
            6001,
            [0x42; 32],
            7,
        );
        let mut packetizer =
            super::AudioPacketizer::new(&setup, 0xABCD, 65_535, RtpTimestamp::new(1000)).unwrap();
        let first = packetizer.packet(&[1, 2, 3, 4]).unwrap();
        let opened = open_packet(&setup.shared_key, &first).unwrap();
        assert_eq!(opened.payload.len(), 352 * 2 * 2);
        assert_eq!(opened.payload[..8], [0, 1, 0, 2, 0, 3, 0, 4]);
        assert!(opened.payload[8..].iter().all(|&b| b == 0));
        let header = RtpHeader::parse(&opened.header).unwrap();
        assert!(header.marker);
        assert_eq!(
            (header.sequence, header.timestamp.get(), header.ssrc),
            (65_535, 1000, 0xABCD)
        );
        let second = packetizer.packet(&[]).unwrap();
        let header = RtpHeader::parse(&second).unwrap();
        assert!(!header.marker);
        assert_eq!((header.sequence, header.timestamp.get()), (0, 1352));
        assert!(packetizer.packet(&[0; 352 * 2 + 1]).is_err());
    }

    #[test]
    fn a_skip_moves_sequence_and_timestamp_across_their_wraps_without_touching_the_nonce() {
        use crate::audio::rtp::{open_packet, RtpHeader};
        use crate::audio::{StreamFormat, StreamSetup, StreamType};
        let setup = StreamSetup::new(
            StreamType::Realtime,
            StreamFormat::PCM_44100_16_STEREO,
            6001,
            [0x42; 32],
            7,
        );
        // 65 534 and u32::MAX - 351: one packet, then a skip of two, crosses both wraps.
        let first_timestamp = RtpTimestamp::new(u32::MAX - 351);
        let mut packetizer =
            super::AudioPacketizer::new(&setup, 0xABCD, 65_534, first_timestamp).unwrap();
        let first = packetizer.packet(&[]).unwrap();
        packetizer.skip(2);
        assert_eq!(packetizer.packets_sent(), 3);
        assert_eq!(packetizer.next_sequence(), 1);
        assert_eq!(packetizer.next_timestamp().get(), 352 * 2);
        let next = packetizer.packet(&[]).unwrap();
        let header = RtpHeader::parse(&open_packet(&setup.shared_key, &next).unwrap().header)
            .expect("the packet after the skip opens");
        assert!(!header.marker);
        assert_eq!((header.sequence, header.timestamp.get()), (1, 704));
        // Two packets sealed, so two nonces: 0 and 1, the skip notwithstanding.
        let nonce = |p: &[u8]| u64::from_le_bytes(p[p.len() - 8..].try_into().unwrap());
        assert_eq!((nonce(&first), nonce(&next)), (0, 1));
        // The same skip in one go matches a run of single steps, over many wraps.
        let mut stepped =
            super::AudioPacketizer::new(&setup, 0xABCD, 65_534, first_timestamp).unwrap();
        let mut jumped =
            super::AudioPacketizer::new(&setup, 0xABCD, 65_534, first_timestamp).unwrap();
        for _ in 0..200_000 {
            stepped.skip(1);
        }
        jumped.skip(200_000);
        assert_eq!(stepped.next_sequence(), jumped.next_sequence());
        assert_eq!(stepped.next_timestamp(), jumped.next_timestamp());
        assert_eq!(
            jumped.next_sequence(),
            u32::from(65_534u16.wrapping_add(200_000u64 as u16))
        );
    }

    #[test]
    fn lpcm_other_than_16_bit_is_refused() {
        use crate::audio::{StreamFormat, StreamSetup, StreamType};
        let mut format = StreamFormat::PCM_44100_16_STEREO;
        format.bits_per_sample = 24;
        let setup = StreamSetup::new(StreamType::Realtime, format, 1, [0; 32], 1);
        assert!(super::AudioPacketizer::new(&setup, 1, 0, RtpTimestamp::new(0)).is_err());
        let buffered = StreamSetup::new(
            StreamType::Buffered,
            StreamFormat::PCM_44100_16_STEREO,
            1,
            [0; 32],
            1,
        );
        assert!(super::AudioPacketizer::for_stream(&buffered, 1, 0, RtpTimestamp::new(0)).is_err());
    }

    #[test]
    fn a_generated_config_and_its_packetizer_agree() {
        use crate::audio::rtp::{open_packet, RtpHeader};
        use crate::audio::{StreamFormat, StreamType};
        let mut rng = crate::OsRng;
        let mut connection = crate::client::SenderConnection::new(
            "receiver.local",
            std::net::Ipv4Addr::new(192, 0, 2, 7).into(),
            &mut rng,
        );
        connection.set_rtsp_session_id(3_141_592_653);
        let config = super::AudioSendConfig::generate(
            &connection,
            StreamType::Realtime,
            StreamFormat::ALAC_44100_16_STEREO,
            6001,
            super::TimingMode::Ntp,
            &mut rng,
        )
        .with_first_timestamp(RtpTimestamp::new(1000));
        assert_eq!(config.session_uri, "rtsp://192.0.2.7/3141592653");
        assert_eq!(config.stream.stream_connection_id, 3_141_592_653);
        assert!(config.first_sequence <= u32::from(u16::MAX));
        let state = super::AudioSendState::new(config.clone());
        let mut packetizer = state.packetizer().unwrap();
        let refused = |result: crate::Result<super::AudioPacketizer>| {
            matches!(result, Err(crate::AirPlayError::InvalidState(_)))
        };
        assert!(refused(state.packetizer()), "a second from the same state");
        assert!(
            refused(config.packetizer()),
            "a second from the config it was cloned from"
        );
        let other_state = super::AudioSendState::new(config.clone());
        assert!(
            refused(other_state.packetizer()),
            "a second from another clone"
        );
        let packet = packetizer.packet(&[]).unwrap();
        let opened = open_packet(&config.stream.shared_key, &packet).unwrap();
        let header = RtpHeader::parse(&opened.header).unwrap();
        assert_eq!(u32::from(header.sequence), config.first_sequence);
        assert_eq!(header.timestamp, RtpTimestamp::new(1000));
        assert_eq!(header.ssrc, 3_141_592_653);
        let other = super::AudioSendConfig::generate(
            &connection,
            StreamType::Realtime,
            StreamFormat::ALAC_44100_16_STEREO,
            6001,
            super::TimingMode::Ntp,
            &mut rng,
        );
        assert_ne!(other.stream.shared_key, config.stream.shared_key);
    }
}
