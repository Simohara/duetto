//! The AirPlay 2 timing exchange.
//!
//! Observed on `AppleTV14,1` (tvOS 23L243): a `SETUP` naming `timingProtocol: NTP` and a port makes
//! the receiver send 32-byte timing requests to that UDP port and withhold its `SETUP` reply until
//! one is answered. No clock sync is needed for a URL send, but the handshake is not optional.
//!
//! Packet (big-endian, pyatv's `TimingPacket`): an RTP header, then reference, receive and send
//! times as [`NtpTimestamp`]s. Sans-io: [`TimingPacket`] is bytes in and out, and a receiver
//! follows a sender's clock with [`NtpFollower`]; the socket lives in [`TimingServer`] (the
//! sender's side) or with the host.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{AirPlayError, Result};
use crate::time::NtpTimestamp;

/// Wire length of a timing packet.
pub const TIMING_PACKET_LEN: usize = 32;

/// The `type` byte a receiver sends on a timing **request**.
pub const TIMING_REQUEST_TYPE: u8 = 0xD2;

/// The `type` byte we answer with: pyatv's `0x53 | 0x80`.
pub const TIMING_REPLY_TYPE: u8 = 0xD3;

/// The sequence number in a timing reply. Constant in every implementation that sends one.
pub const TIMING_REPLY_SEQNO: u16 = 7;

/// One timing packet, in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimingPacket {
    /// RTP protocol byte, echoed back unchanged.
    pub proto: u8,
    /// Packet type: [`TIMING_REQUEST_TYPE`] inbound, [`TIMING_REPLY_TYPE`] outbound.
    pub packet_type: u8,
    /// Sequence number.
    pub seqno: u16,
    /// Reference time: a request's send time, echoed in the reply.
    pub reftime: NtpTimestamp,
    /// Receive time.
    pub recvtime: NtpTimestamp,
    /// Send time.
    pub sendtime: NtpTimestamp,
}

impl TimingPacket {
    /// Parses a packet, or fails when it is not one.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < TIMING_PACKET_LEN {
            return Err(AirPlayError::Protocol(format!(
                "a timing packet is {TIMING_PACKET_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let time = |offset: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[offset..offset + 8]);
            NtpTimestamp::from_bits(u64::from_be_bytes(word))
        };
        Ok(Self {
            proto: bytes[0],
            packet_type: bytes[1],
            seqno: u16::from_be_bytes([bytes[2], bytes[3]]),
            reftime: time(8),
            recvtime: time(16),
            sendtime: time(24),
        })
    }

    /// Serializes the packet.
    #[must_use]
    pub fn encode(&self) -> [u8; TIMING_PACKET_LEN] {
        let mut out = [0u8; TIMING_PACKET_LEN];
        out[0] = self.proto;
        out[1] = self.packet_type;
        out[2..4].copy_from_slice(&self.seqno.to_be_bytes());
        // out[4..8] is the padding word, and stays zero.
        out[8..16].copy_from_slice(&self.reftime.to_bits().to_be_bytes());
        out[16..24].copy_from_slice(&self.recvtime.to_bits().to_be_bytes());
        out[24..32].copy_from_slice(&self.sendtime.to_bits().to_be_bytes());
        out
    }

    /// Whether this is a timing request ([`TIMING_REQUEST_TYPE`], marker bit ignored): the only
    /// packet a timing responder may answer. Answering anything else lets one spoofed reply bounce
    /// between two responders indefinitely.
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.packet_type & 0x7F == TIMING_REQUEST_TYPE & 0x7F
    }

    /// Builds the reply to a request: its send time becomes the reference time, and both of our
    /// timestamps are now.
    #[must_use]
    pub fn reply_to(request: &Self, now: NtpTimestamp) -> Self {
        Self {
            proto: request.proto,
            packet_type: TIMING_REPLY_TYPE,
            seqno: TIMING_REPLY_SEQNO,
            reftime: request.sendtime,
            recvtime: now,
            sendtime: now,
        }
    }
}

impl TimingPacket {
    /// A timing request, as a receiver sends one (observed from an Apple TV: `80 d2 00 07`, zero
    /// reference and receive times). Read the reply with [`TimingPacket::offset`].
    #[must_use]
    pub fn request(now: NtpTimestamp) -> Self {
        Self {
            proto: 0x80,
            packet_type: TIMING_REQUEST_TYPE,
            seqno: TIMING_REPLY_SEQNO,
            reftime: NtpTimestamp::ZERO,
            recvtime: NtpTimestamp::ZERO,
            sendtime: now,
        }
    }

    /// The NTP estimate from a reply to our request, `received_at` being our clock on arrival:
    /// `(offset, round_trip)` in seconds, the peer's clock minus ours; `None` if not a reply.
    ///
    /// Differences are era-safe ([`NtpTimestamp::secs_f64_since`]). Whether the reply answers our
    /// request is [`TimingClient::on_reply`]'s question.
    #[must_use]
    pub fn offset(&self, received_at: NtpTimestamp) -> Option<(f64, f64)> {
        if self.packet_type != TIMING_REPLY_TYPE {
            return None;
        }
        let (t0, t1, t2, t3) = (self.reftime, self.recvtime, self.sendtime, received_at);
        let offset = (t1.secs_f64_since(t0) + t2.secs_f64_since(t3)) / 2.0;
        let round_trip = t3.secs_f64_since(t0) - t2.secs_f64_since(t1);
        Some((offset, round_trip))
    }
}

/// The receiver's side of the exchange, sans-io: one request outstanding, and a reply counts only
/// if its echoed `reftime` is that request's transmit time (RFC 5905 §8). Stale, replayed and
/// forged replies are dropped. Which address may answer is the socket owner's check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimingClient {
    outstanding: Option<NtpTimestamp>,
}

impl TimingClient {
    /// A client with nothing outstanding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A request sent at `now` (our clock). It replaces any unanswered request.
    pub fn request(&mut self, now: NtpTimestamp) -> [u8; TIMING_PACKET_LEN] {
        self.outstanding = Some(now);
        TimingPacket::request(now).encode()
    }

    /// A datagram that arrived at `received_at`: `(offset, round_trip)` if it answers the
    /// outstanding request, `None` otherwise.
    pub fn on_reply(&mut self, bytes: &[u8], received_at: NtpTimestamp) -> Option<(f64, f64)> {
        let reply = TimingPacket::parse(bytes).ok()?;
        let asked = self.outstanding?;
        if reply.packet_type != TIMING_REPLY_TYPE || reply.reftime != asked {
            return None;
        }
        self.outstanding = None;
        reply.offset(received_at)
    }
}

/// Samples [`ClockFilter`] keeps (RFC 5905 §10's eight stages).
pub const CLOCK_FILTER_SAMPLES: usize = 8;

/// RFC 5905 §10's clock filter, reduced to what a receiver needs: the last
/// [`CLOCK_FILTER_SAMPLES`] `(offset, round_trip)` estimates from [`TimingClient::on_reply`], and
/// the offset of the one with the smallest round trip.
///
/// A step in the peer's clock is followed once [`CLOCK_STEP_REPLIES`] consecutive replies each
/// disagree with the chosen offset by more than their round trips explain (plus
/// [`CLOCK_STEP_THRESHOLD`]) and agree with one another (within [`CLOCK_STEP_AGREEMENT`]); the
/// register then restarts. A lone outlier is ignored.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClockFilter {
    samples: std::collections::VecDeque<(f64, f64)>,
    disagreeing: Vec<(f64, f64)>,
}

/// Seconds a reply's offset must differ from the chosen one to count towards a step.
pub const CLOCK_STEP_THRESHOLD: f64 = 0.050;

/// Consecutive disagreeing replies that make a step.
pub const CLOCK_STEP_REPLIES: usize = 3;

/// Seconds beyond half their round trips within which a run's replies must agree.
pub const CLOCK_STEP_AGREEMENT: f64 = 0.010;

impl ClockFilter {
    /// An empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an estimate: `offset` (peer minus ours) and its `round_trip`, in seconds. A
    /// non-finite sample or a negative round trip is dropped.
    pub fn push(&mut self, offset: f64, round_trip: f64) {
        if !offset.is_finite() || !round_trip.is_finite() || round_trip < 0.0 {
            return;
        }
        if let Some((chosen, chosen_round_trip)) = self.best() {
            let explained = (round_trip + chosen_round_trip) / 2.0 + CLOCK_STEP_THRESHOLD;
            if (offset - chosen).abs() > explained {
                let agrees = self
                    .disagreeing
                    .first()
                    .is_none_or(|&(first, first_round_trip)| {
                        (offset - first).abs()
                            <= (round_trip + first_round_trip) / 2.0 + CLOCK_STEP_AGREEMENT
                    });
                if !agrees {
                    self.disagreeing.clear();
                }
                self.disagreeing.push((offset, round_trip));
                if self.disagreeing.len() >= CLOCK_STEP_REPLIES {
                    self.samples = self.disagreeing.drain(..).collect();
                }
                return;
            }
        }
        self.disagreeing.clear();
        if self.samples.len() == CLOCK_FILTER_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back((offset, round_trip));
    }

    /// The chosen offset (seconds, peer minus ours), or `None` before any sample.
    #[must_use]
    pub fn offset(&self) -> Option<f64> {
        self.best().map(|(offset, _)| offset)
    }

    /// The chosen sample's round trip: the bound on how wrong the offset can be (half of it).
    #[must_use]
    pub fn round_trip(&self) -> Option<f64> {
        self.best().map(|(_, round_trip)| round_trip)
    }

    /// Samples held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether no sample is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Forgets every sample (a new peer, or a clock known to have stepped).
    pub fn clear(&mut self) {
        self.samples.clear();
        self.disagreeing.clear();
    }

    fn best(&self) -> Option<(f64, f64)> {
        // Earliest wins a tie, so a repeated equal round trip does not flip between samples.
        self.samples
            .iter()
            .copied()
            .fold(None, |best: Option<(f64, f64)>, sample| match best {
                Some(b) if b.1 <= sample.1 => Some(b),
                _ => Some(sample),
            })
    }
}

/// How often [`NtpFollower`] asks by default.
pub const NTP_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// What a receiver knows of a sender's clock, small and [`Copy`] so a timing thread can hand it to
/// an audio thread. Local NTP time is `local_epoch` plus the host's monotonic now.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ClockEstimate {
    /// The local NTP reading at monotonic zero (the follower's epoch).
    pub local_epoch: NtpTimestamp,
    /// Seconds the sender's clock reads ahead of ours (sender minus local).
    pub offset: f64,
    /// The round trip of the sample the offset came from, in seconds: the offset is right to
    /// within half of it.
    pub round_trip: f64,
    /// Samples the filter holds (at most [`CLOCK_FILTER_SAMPLES`]).
    pub samples: usize,
}

impl ClockEstimate {
    /// An estimate from a host's own exchange: `offset` (sender minus local) measured against a
    /// local clock that reads `local_epoch` at monotonic zero.
    #[must_use]
    pub fn new(local_epoch: NtpTimestamp, offset: f64, round_trip: f64) -> Self {
        Self {
            local_epoch,
            offset,
            round_trip,
            samples: 1,
        }
    }

    /// The local NTP reading at monotonic `now`.
    #[must_use]
    pub fn local_time(&self, now: Duration) -> NtpTimestamp {
        self.local_epoch.wrapping_add(now)
    }

    /// The sender's clock at monotonic `now`.
    #[must_use]
    pub fn sender_time(&self, now: Duration) -> NtpTimestamp {
        self.local_time(now).wrapping_add_secs_f64(self.offset)
    }

    /// The monotonic instant at which the sender's clock reads `sender`; `None` if before monotonic
    /// zero.
    #[must_use]
    pub fn local_instant(&self, sender: NtpTimestamp) -> Option<Duration> {
        sender
            .wrapping_add_secs_f64(-self.offset)
            .checked_duration_since(self.local_epoch)
    }
}

/// The receiver's half of the NTP exchange, sans-io: when to ask, what to send, and the
/// [`ClockFilter`]ed answer. The host owns the socket, sends what [`Self::poll_request`] returns to
/// the sender's timing port, and feeds what comes back from that address to [`Self::on_reply`].
/// Requests are stamped `local_epoch + now`, so [`Self::estimate`] maps the host's monotonic clock.
#[derive(Debug, Clone, PartialEq)]
pub struct NtpFollower {
    client: TimingClient,
    filter: ClockFilter,
    local_epoch: NtpTimestamp,
    interval: Duration,
    last_request: Option<Duration>,
}

impl NtpFollower {
    /// A follower whose local clock reads `local_epoch` at monotonic zero
    /// ([`NtpTimestamp::now`] at the origin the host's now counts from, say), asking every
    /// [`NTP_REQUEST_INTERVAL`].
    #[must_use]
    pub fn new(local_epoch: NtpTimestamp) -> Self {
        Self {
            client: TimingClient::new(),
            filter: ClockFilter::new(),
            local_epoch,
            interval: NTP_REQUEST_INTERVAL,
            last_request: None,
        }
    }

    /// Asks every `interval` instead.
    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    /// The local NTP reading at monotonic `now`.
    #[must_use]
    pub fn local_time(&self, now: Duration) -> NtpTimestamp {
        self.local_epoch.wrapping_add(now)
    }

    /// A request to send now, if one is due: the first call, then once per interval. It replaces
    /// any unanswered request.
    pub fn poll_request(&mut self, now: Duration) -> Option<[u8; TIMING_PACKET_LEN]> {
        let due = self
            .last_request
            .is_none_or(|last| now.checked_sub(last).is_none_or(|e| e >= self.interval));
        if !due {
            return None;
        }
        self.last_request = Some(now);
        Some(self.client.request(self.local_time(now)))
    }

    /// A datagram from the sender's timing port, arrived at monotonic `now`: `(offset,
    /// round_trip)` in seconds if it answers the outstanding request, `None` otherwise. Every answer
    /// goes to the filter, which may not choose it (an outlier, or a reply towards a step); the
    /// chosen one is [`Self::estimate`]'s.
    pub fn on_reply(&mut self, bytes: &[u8], now: Duration) -> Option<(f64, f64)> {
        let (offset, round_trip) = self.client.on_reply(bytes, self.local_time(now))?;
        self.filter.push(offset, round_trip);
        Some((offset, round_trip))
    }

    /// The chosen estimate, `None` before any reply.
    #[must_use]
    pub fn estimate(&self) -> Option<ClockEstimate> {
        Some(ClockEstimate {
            local_epoch: self.local_epoch,
            offset: self.filter.offset()?,
            round_trip: self.filter.round_trip()?,
            samples: self.filter.len(),
        })
    }

    /// The filter behind [`Self::estimate`].
    #[must_use]
    pub fn filter(&self) -> &ClockFilter {
        &self.filter
    }
}

/// What [`TimingServer::start_with_clock`] answers with: the current time, as an NTP timestamp.
pub type TimingClock = Arc<dyn Fn() -> NtpTimestamp + Send + Sync>;

/// A UDP socket that answers a receiver's timing requests: the thin I/O half of this module.
///
/// Bound on an ephemeral port, announced in `SETUP`, answered from a background thread until the
/// value is dropped.
pub struct TimingServer {
    port: u16,
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    socket: UdpSocket,
}

impl std::fmt::Debug for TimingServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimingServer")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl TimingServer {
    /// Binds an ephemeral UDP port on every interface and starts answering with
    /// [`NtpTimestamp::now`].
    pub fn start() -> Result<Self> {
        Self::start_with_clock(Arc::new(NtpTimestamp::now))
    }

    /// [`Self::start`], answering from `clock`. A sender stamping sync packets from its own
    /// clock (a shared multi-room timeline) must answer timing requests from that clock too.
    pub fn start_with_clock(clock: TimingClock) -> Result<Self> {
        // Bind IPv4 first: [::]:0 does not receive IPv4 datagrams on Windows (IPV6_V6ONLY is
        // not cleared). Falls back to [::]:0 on an IPv6-only network.
        let socket = UdpSocket::bind("0.0.0.0:0").or_else(|_| UdpSocket::bind("[::]:0"));
        Self::serve(socket, clock)
    }

    /// [`Self::start_with_clock`] on one address (`127.0.0.1` for a loopback test).
    pub fn start_on(bind: std::net::IpAddr, clock: TimingClock) -> Result<Self> {
        Self::serve(UdpSocket::bind((bind, 0)), clock)
    }

    fn serve(socket: std::io::Result<UdpSocket>, clock: TimingClock) -> Result<Self> {
        let socket =
            socket.map_err(|e| AirPlayError::io_context("could not bind a timing port", e))?;
        let port = socket
            .local_addr()
            .map_err(|e| AirPlayError::io_context("timing socket has no address", e))?
            .port();
        // The read timeout lets the thread notice a stop request; recv_from is not interruptible.
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(|e| AirPlayError::io_context("set timing read timeout", e))?;

        let worker = socket
            .try_clone()
            .map_err(|e| AirPlayError::io_context("could not clone the timing socket", e))?;
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; 256];
            while flag.load(Ordering::Relaxed) {
                let Ok((read, from)) = worker.recv_from(&mut buffer) else {
                    continue; // A timeout, or a datagram we will never see. Neither is fatal.
                };
                let Ok(request) = TimingPacket::parse(&buffer[..read]) else {
                    continue; // Not a timing packet. Anything may send to an open UDP port.
                };
                if !request.is_request() {
                    continue; // Only requests are answered; a reply answered is a reflection loop.
                }
                let reply = TimingPacket::reply_to(&request, clock());
                let _ = worker.send_to(&reply.encode(), from);
            }
        });

        Ok(Self {
            port,
            running,
            handle: Some(handle),
            socket,
        })
    }

    /// The port to announce in `SETUP`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The bound socket, for a caller that wants to look at it.
    #[must_use]
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl Drop for TimingServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntp(seconds: u32, fraction: u32) -> NtpTimestamp {
        NtpTimestamp::from_parts(seconds, fraction)
    }

    /// A request captured from an Apple TV (tvOS 23L243).
    const REAL_REQUEST: [u8; TIMING_PACKET_LEN] = [
        0x80, 0xd2, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe6, 0x59, 0x5b, 0x21, 0x40, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn a_real_request_parses() {
        let request = TimingPacket::parse(&REAL_REQUEST).expect("parse");

        assert_eq!(request.proto, 0x80);
        assert_eq!(request.packet_type, TIMING_REQUEST_TYPE);
        assert_eq!(request.sendtime, ntp(0xE659_5B21, 0x4000_0000));
    }

    #[test]
    fn a_reply_echoes_the_request_sendtime_as_its_reference() {
        let request = TimingPacket::parse(&REAL_REQUEST).expect("parse");

        let reply = TimingPacket::reply_to(&request, ntp(1, 2));

        assert_eq!(reply.reftime, request.sendtime);
        assert_eq!(reply.packet_type, TIMING_REPLY_TYPE);
        assert_eq!(reply.seqno, TIMING_REPLY_SEQNO);
        assert_eq!(reply.proto, request.proto);
        assert_eq!(reply.recvtime, ntp(1, 2));
        assert_eq!(reply.sendtime, ntp(1, 2));
    }

    #[test]
    fn encode_round_trips() {
        let request = TimingPacket::parse(&REAL_REQUEST).expect("parse");

        assert_eq!(
            TimingPacket::parse(&request.encode()).expect("re-parse"),
            request
        );
    }

    #[test]
    fn a_reply_is_the_length_the_receiver_expects() {
        let request = TimingPacket::parse(&REAL_REQUEST).expect("parse");

        assert_eq!(
            TimingPacket::reply_to(&request, NtpTimestamp::now())
                .encode()
                .len(),
            32
        );
    }

    #[test]
    fn a_request_is_the_shape_an_apple_tv_sends() {
        let ours = TimingPacket::request(ntp(0xE659_5B21, 0x4000_0000)).encode();
        assert_eq!(ours, REAL_REQUEST);
    }

    #[test]
    fn a_reply_to_our_request_gives_offset_and_round_trip() {
        let request = TimingPacket::request(ntp(100, 0));
        let reply = TimingPacket::reply_to(&request, ntp(110, 0));
        let (offset, rtt) = reply.offset(ntp(100, 1 << 31)).expect("a reply");
        assert!((offset - 9.75).abs() < 1e-9, "{offset}");
        assert!((rtt - 0.5).abs() < 1e-9, "{rtt}");
        assert!(request.offset(NtpTimestamp::ZERO).is_none());
    }

    #[test]
    fn offset_and_round_trip_hold_across_the_era_boundary() {
        // We ask half a second before the wrap and read the reply a quarter second later, still
        // before it. The peer's clock is one second ahead of ours, so it receives and answers
        // after the wrap: 0.125 s of flight each way.
        let asked = ntp(u32::MAX, 0x8000_0000);
        let mut reply = TimingPacket::reply_to(&TimingPacket::request(asked), NtpTimestamp::ZERO);
        reply.recvtime = ntp(0, 0xA000_0000); // ours + 1 s + 0.125 s
        reply.sendtime = ntp(0, 0xA000_0000);
        let (offset, rtt) = reply.offset(ntp(u32::MAX, 0xC000_0000)).unwrap();
        assert!((offset - 1.0).abs() < 1e-9, "{offset}");
        assert!((rtt - 0.25).abs() < 1e-9, "{rtt}");
    }

    #[test]
    fn a_client_takes_only_the_reply_to_its_own_outstanding_request() {
        let mut client = TimingClient::new();
        let asked = ntp(1_000, 0);
        let bytes = client.request(asked);
        assert_eq!(
            TimingPacket::parse(&bytes).unwrap(),
            TimingPacket::request(asked)
        );
        // Somebody else's reply (another origin), and junk: ignored, the request still open.
        let other = TimingPacket::reply_to(&TimingPacket::request(ntp(999, 5)), ntp(1_010, 0));
        assert!(client
            .on_reply(&other.encode(), ntp(1_000, 1 << 30))
            .is_none());
        assert!(client.on_reply(b"junk", ntp(1_000, 1 << 30)).is_none());
        // Our own request echoed back is not a reply.
        assert!(client.on_reply(&bytes, ntp(1_000, 1 << 30)).is_none());
        // The real one.
        let reply = TimingPacket::reply_to(&TimingPacket::request(asked), ntp(1_010, 0));
        let (offset, _) = client
            .on_reply(&reply.encode(), ntp(1_000, 1 << 31))
            .unwrap();
        assert!((offset - 9.75).abs() < 1e-9, "{offset}");
        // The same reply again is a duplicate.
        assert!(client
            .on_reply(&reply.encode(), ntp(1_000, 1 << 31))
            .is_none());
    }

    #[test]
    fn a_late_reply_to_an_earlier_request_is_dropped() {
        let mut client = TimingClient::new();
        client.request(ntp(10, 0));
        client.request(ntp(11, 0));
        let late = TimingPacket::reply_to(&TimingPacket::request(ntp(10, 0)), ntp(12, 0));
        assert!(client.on_reply(&late.encode(), ntp(11, 1)).is_none());
        let current = TimingPacket::reply_to(&TimingPacket::request(ntp(11, 0)), ntp(12, 0));
        assert!(client.on_reply(&current.encode(), ntp(11, 1)).is_some());
    }

    #[test]
    fn a_short_packet_is_refused_rather_than_read_past() {
        assert!(TimingPacket::parse(&REAL_REQUEST[..31]).is_err());
        assert!(TimingPacket::parse(&[]).is_err());
    }

    /// Binds a test UDP client on the same address family the server chose.
    fn test_client_for(server: &TimingServer) -> (UdpSocket, std::net::SocketAddr) {
        let server_addr = server.socket().local_addr().expect("server address");
        let (bind, target): (&str, std::net::IpAddr) = if server_addr.is_ipv6() {
            ("[::]:0", "::1".parse().unwrap())
        } else {
            ("0.0.0.0:0", "127.0.0.1".parse().unwrap())
        };
        let client = UdpSocket::bind(bind).expect("bind test client");
        let dest = std::net::SocketAddr::new(target, server.port());
        (client, dest)
    }

    #[test]
    fn the_server_answers_a_real_request_on_a_real_socket() {
        let server = TimingServer::start().expect("start");
        let (client, dest) = test_client_for(&server);
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");

        client.send_to(&REAL_REQUEST, dest).expect("send");

        let mut buffer = [0u8; 64];
        let (read, _) = client.recv_from(&mut buffer).expect("a reply arrives");
        let reply = TimingPacket::parse(&buffer[..read]).expect("parse");

        assert_eq!(reply.packet_type, TIMING_REPLY_TYPE);
        assert_eq!(reply.reftime.era_secs(), 0xE659_5B21);
    }

    #[test]
    fn a_server_on_loopback_answers_from_its_own_clock() {
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let server =
            TimingServer::start_on(loopback, Arc::new(|| ntp(4_000_000_000, 7))).expect("start");
        assert_eq!(server.socket().local_addr().unwrap().ip(), loopback);
        let client = UdpSocket::bind((loopback, 0)).expect("bind");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        client
            .send_to(&REAL_REQUEST, (loopback, server.port()))
            .expect("send");
        let mut buffer = [0u8; 64];
        let (read, _) = client.recv_from(&mut buffer).expect("a reply arrives");
        let reply = TimingPacket::parse(&buffer[..read]).expect("parse");
        assert_eq!(reply.packet_type, TIMING_REPLY_TYPE);
        assert_eq!(reply.recvtime, ntp(4_000_000_000, 7));
    }

    #[test]
    fn junk_on_the_timing_port_is_ignored_rather_than_answered() {
        let server = TimingServer::start().expect("start");
        let (client, dest) = test_client_for(&server);
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .expect("timeout");

        client.send_to(b"not a timing packet", dest).expect("send");

        let mut buffer = [0u8; 64];
        assert!(
            client.recv_from(&mut buffer).is_err(),
            "a short datagram must not be answered"
        );
    }

    #[test]
    fn a_reply_on_the_timing_port_is_not_answered() {
        let server = TimingServer::start().expect("start");
        let (client, dest) = test_client_for(&server);
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .expect("timeout");
        let request = TimingPacket::parse(&REAL_REQUEST).expect("parse");
        let reply = TimingPacket::reply_to(&request, ntp(1, 2));
        assert!(request.is_request());
        assert!(!reply.is_request());

        client.send_to(&reply.encode(), dest).expect("send");

        let mut buffer = [0u8; 64];
        assert!(
            client.recv_from(&mut buffer).is_err(),
            "a timing reply must not be answered"
        );
    }

    #[test]
    fn a_server_with_its_own_clock_answers_from_it() {
        let server = TimingServer::start_with_clock(Arc::new(|| ntp(0x1234_5678, 0x9ABC_DEF0)))
            .expect("start");
        let (client, dest) = test_client_for(&server);
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        client.send_to(&REAL_REQUEST, dest).expect("send");
        let mut buffer = [0u8; 64];
        let (read, _) = client.recv_from(&mut buffer).expect("a reply arrives");
        let reply = TimingPacket::parse(&buffer[..read]).expect("parse");
        assert_eq!(reply.recvtime, ntp(0x1234_5678, 0x9ABC_DEF0));
        assert_eq!(reply.sendtime, ntp(0x1234_5678, 0x9ABC_DEF0));
    }

    /// RFC 5905 §10: of the last eight samples, the one with the smallest delay is chosen; a
    /// queued (slow) reply's larger, asymmetric error never wins over a fast one.
    #[test]
    fn the_clock_filter_takes_the_offset_of_the_shortest_round_trip_of_the_last_eight() {
        let mut filter = ClockFilter::new();
        assert!(filter.is_empty());
        assert_eq!(filter.offset(), None);
        filter.push(0.010, 0.004);
        filter.push(0.030, 0.040); // queued: its offset is off by up to half its round trip
        filter.push(0.011, 0.002);
        filter.push(0.012, 0.003);
        assert_eq!(filter.offset(), Some(0.011));
        assert_eq!(filter.round_trip(), Some(0.002));
        // Eight more slower samples push the best one out of the register.
        for i in 0..CLOCK_FILTER_SAMPLES {
            filter.push(0.020 + f64::from(u8::try_from(i).unwrap()) * 1e-3, 0.005);
        }
        assert_eq!(filter.len(), CLOCK_FILTER_SAMPLES);
        assert_eq!(
            filter.offset(),
            Some(0.020),
            "the earliest of the equal round trips"
        );
        // Junk is dropped rather than chosen.
        filter.push(f64::NAN, 0.0);
        filter.push(0.5, -1.0);
        filter.push(0.5, f64::INFINITY);
        assert_eq!(filter.offset(), Some(0.020));
        filter.clear();
        assert_eq!(filter.offset(), None);
    }

    /// A step in the peer's clock (a wall-clock sender whose time was set) is followed after
    /// three replies that all agree on it, not after the eight the register holds; one outlier
    /// between good replies changes nothing.
    #[test]
    fn the_clock_filter_follows_a_step_after_three_replies_and_ignores_one_outlier() {
        let mut filter = ClockFilter::new();
        for _ in 0..CLOCK_FILTER_SAMPLES {
            filter.push(0.0, 0.001);
        }
        filter.push(-3.0, 0.0005); // one wild reply, even with the shortest round trip
        assert_eq!(filter.offset(), Some(0.0));
        filter.push(0.001, 0.002);
        assert_eq!(
            filter.offset(),
            Some(0.0),
            "an agreeing reply resets the run"
        );
        for step in 1..=CLOCK_STEP_REPLIES {
            filter.push(-3.0 + f64::from(u8::try_from(step).unwrap()) * 1e-4, 0.002);
            let stepped = step == CLOCK_STEP_REPLIES;
            assert_eq!(
                filter.offset().is_some_and(|o| o < -2.9),
                stepped,
                "after {step} replies"
            );
        }
        assert_eq!(
            filter.len(),
            CLOCK_STEP_REPLIES,
            "the register restarted from the run"
        );
    }

    /// Three seconds of a congested path — replies queued 200 ms one way, so each reads 100 ms off
    /// with a 202 ms round trip — is not a step: the round trip explains it, and the good sample
    /// stays chosen.
    #[test]
    fn congestion_that_its_round_trips_explain_is_not_a_step() {
        let mut filter = ClockFilter::new();
        for _ in 0..CLOCK_FILTER_SAMPLES {
            filter.push(0.0, 0.002);
        }
        for _ in 0..3 {
            filter.push(-0.1, 0.202);
            assert_eq!(filter.offset(), Some(0.0));
        }
    }

    /// Outliers with long round trips that do not agree with one another (+80, −120, +200 ms at
    /// 300–500 ms) are neither a step nor chosen.
    #[test]
    fn scattered_outliers_do_not_make_a_step() {
        let mut filter = ClockFilter::new();
        for _ in 0..CLOCK_FILTER_SAMPLES {
            filter.push(0.0, 0.002);
        }
        for (offset, round_trip) in [(0.08, 0.3), (-0.12, 0.4), (0.2, 0.5)] {
            filter.push(offset, round_trip);
            assert_eq!(filter.offset(), Some(0.0));
        }
        // Short round trips that disagree past what they explain but not with one another are not
        // a run either.
        for offset in [0.3, -0.3, 0.3] {
            filter.push(offset, 0.002);
            assert_eq!(filter.offset(), Some(0.0), "{offset}");
        }
    }

    /// The follower asks at once and then once an interval, stamps each request with its epoch
    /// plus the host's now, and turns the reply into an estimate that maps the host's clock to the
    /// sender's both ways.
    #[test]
    fn a_follower_asks_once_an_interval_and_maps_the_hosts_clock_to_the_senders() {
        let epoch = ntp(3_900_000_000, 0);
        let mut follower = NtpFollower::new(epoch);
        assert_eq!(follower.estimate(), None);
        let asked = follower.poll_request(Duration::from_millis(500)).unwrap();
        let request = TimingPacket::parse(&asked).unwrap();
        assert_eq!(request.sendtime, epoch + Duration::from_millis(500));
        assert!(follower
            .poll_request(Duration::from_millis(1_499))
            .is_none());
        // The sender's clock is 2.25 s ahead; 2 ms each way.
        let sender = |local: Duration| (epoch + local).wrapping_add_secs_f64(2.25);
        let reply = TimingPacket::reply_to(&request, sender(Duration::from_millis(502)));
        let (offset, round_trip) = follower
            .on_reply(&reply.encode(), Duration::from_millis(504))
            .unwrap();
        assert!((offset - 2.25).abs() < 1e-9, "{offset}");
        assert!((round_trip - 0.004).abs() < 1e-9, "{round_trip}");
        let estimate = follower.estimate().unwrap();
        assert_eq!((estimate.local_epoch, estimate.samples), (epoch, 1));
        let now = Duration::from_secs(10);
        assert!(estimate.sender_time(now).units_since(sender(now)).abs() <= 1);
        let back = estimate.local_instant(sender(now)).unwrap();
        assert!(back.abs_diff(now) < Duration::from_nanos(2), "{back:?}");
        assert_eq!(estimate.local_instant(epoch), None, "before monotonic zero");
        // The next request is due an interval after the last; a stale reply is not taken.
        let second = follower.poll_request(Duration::from_millis(1_500)).unwrap();
        assert!(follower
            .on_reply(&reply.encode(), Duration::from_millis(1_501))
            .is_none());
        follower.set_interval(Duration::from_millis(100));
        assert!(follower
            .poll_request(Duration::from_millis(1_550))
            .is_none());
        assert!(follower
            .poll_request(Duration::from_millis(1_600))
            .is_some());
        assert_ne!(second, asked);
        assert_eq!(follower.filter().len(), 1);
    }

    /// A step in the sender's clock reaches the estimate after three agreeing replies, as the
    /// filter follows one.
    #[test]
    fn a_follower_follows_a_step_in_the_senders_clock() {
        let epoch = ntp(1_000, 0);
        let mut follower = NtpFollower::new(epoch);
        let mut offset = 0.5;
        for second in 0..20u64 {
            if second == 10 {
                offset = -1.5;
            }
            let now = Duration::from_secs(second);
            let request = TimingPacket::parse(&follower.poll_request(now).unwrap()).unwrap();
            let answered = (epoch + now + Duration::from_millis(1)).wrapping_add_secs_f64(offset);
            let reply = TimingPacket::reply_to(&request, answered);
            follower.on_reply(&reply.encode(), now + Duration::from_millis(2));
            let chosen = follower.estimate().unwrap().offset;
            let stepped = second >= 10 + CLOCK_STEP_REPLIES as u64 - 1;
            let want = if stepped { -1.5 } else { 0.5 };
            assert!((chosen - want).abs() < 1e-6, "{second}: {chosen}");
        }
    }
}
