//! PTP (IEEE 1588-2008) for an AirPlay 2 sender that follows a clock: message layouts, the 80-bit
//! timestamp, the offset/delay solution, a sample filter, and the mapping to the
//! `SETRATEANCHORTIME` network time.
//!
//! This is the follower side only (the grandmaster side is [`super::ptp_serve`]). Offset comes
//! from an end-to-end exchange ([`E2eExchange`]) or the one-way estimate ([`one_way_offset`])
//! that shairport-sync's `nqptp` uses. Layouts parse real third-party PTPv2 bytes; nothing here
//! has followed an Apple grandmaster. Follow_Up TLVs are kept opaque as [`Tlv`]s.

use crate::error::{AirPlayError, Result};

/// UDP port for PTP event messages (Sync, Delay_Req).
pub const EVENT_PORT: u16 = 319;
/// UDP port for PTP general messages (Follow_Up, Delay_Resp, Announce).
pub const GENERAL_PORT: u16 = 320;

/// Length of the common message header.
pub const HEADER_LEN: usize = 34;
/// Length of a PTP timestamp (48-bit seconds + 32-bit nanoseconds).
pub const TIMESTAMP_LEN: usize = 10;
/// Length of a port identity (8-byte clock identity + 16-bit port number).
pub const PORT_IDENTITY_LEN: usize = 10;
/// Length of a Sync, Delay_Req or TLV-less Follow_Up.
pub const SYNC_LEN: usize = HEADER_LEN + TIMESTAMP_LEN;
/// Length of a Delay_Resp.
pub const DELAY_RESP_LEN: usize = HEADER_LEN + TIMESTAMP_LEN + PORT_IDENTITY_LEN;
/// Length of an Announce without TLVs.
pub const ANNOUNCE_LEN: usize = HEADER_LEN + 30;

/// The `versionPTP` this module reads and writes.
pub const VERSION: u8 = 2;

/// Flag bit `twoStepFlag` (flagField octet 0, bit 1): a Follow_Up carries the precise origin.
pub const FLAG_TWO_STEP: u16 = 0x0200;

/// `logMessageInterval` for a Delay_Req, which the standard fixes at 0x7F.
pub const DELAY_REQ_LOG_INTERVAL: i8 = 0x7F;

/// PTP message types (the low nibble of octet 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageType {
    /// 0x0.
    Sync,
    /// 0x1.
    DelayReq,
    /// 0x2.
    PdelayReq,
    /// 0x3.
    PdelayResp,
    /// 0x8.
    FollowUp,
    /// 0x9.
    DelayResp,
    /// 0xA.
    PdelayRespFollowUp,
    /// 0xB.
    Announce,
    /// 0xC.
    Signaling,
    /// 0xD.
    Management,
    /// Anything else.
    Reserved(u8),
}

impl MessageType {
    /// The nibble on the wire.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Sync => 0x0,
            Self::DelayReq => 0x1,
            Self::PdelayReq => 0x2,
            Self::PdelayResp => 0x3,
            Self::FollowUp => 0x8,
            Self::DelayResp => 0x9,
            Self::PdelayRespFollowUp => 0xA,
            Self::Announce => 0xB,
            Self::Signaling => 0xC,
            Self::Management => 0xD,
            Self::Reserved(code) => code & 0x0F,
        }
    }

    /// Maps a nibble.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code & 0x0F {
            0x0 => Self::Sync,
            0x1 => Self::DelayReq,
            0x2 => Self::PdelayReq,
            0x3 => Self::PdelayResp,
            0x8 => Self::FollowUp,
            0x9 => Self::DelayResp,
            0xA => Self::PdelayRespFollowUp,
            0xB => Self::Announce,
            0xC => Self::Signaling,
            0xD => Self::Management,
            other => Self::Reserved(other),
        }
    }

    /// The `controlField` value the standard assigns (Table 23): 0 Sync, 1 Delay_Req, 2 Follow_Up,
    /// 3 Delay_Resp, 5 everything else.
    #[must_use]
    pub fn control_field(self) -> u8 {
        match self {
            Self::Sync => 0,
            Self::DelayReq => 1,
            Self::FollowUp => 2,
            Self::DelayResp => 3,
            Self::Management => 4,
            _ => 5,
        }
    }
}

/// A PTP timestamp: 48-bit seconds and 32-bit nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[non_exhaustive]
pub struct Timestamp {
    /// Seconds (48 bits on the wire).
    pub seconds: u64,
    /// Nanoseconds, below 10^9 in a well-formed timestamp.
    pub nanoseconds: u32,
}

impl Timestamp {
    /// The largest seconds value the wire can carry.
    pub const MAX_SECONDS: u64 = (1 << 48) - 1;

    /// A timestamp from parts.
    #[must_use]
    pub fn new(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }

    /// A timestamp from nanoseconds since the epoch of its timescale.
    #[must_use]
    pub fn from_nanos(nanos: u128) -> Self {
        Self {
            seconds: (nanos / 1_000_000_000) as u64 & Self::MAX_SECONDS,
            nanoseconds: (nanos % 1_000_000_000) as u32,
        }
    }

    /// Nanoseconds since the epoch of its timescale.
    #[must_use]
    pub fn to_nanos(&self) -> u128 {
        u128::from(self.seconds) * 1_000_000_000 + u128::from(self.nanoseconds)
    }

    /// The 10 wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; TIMESTAMP_LEN] {
        let mut out = [0u8; TIMESTAMP_LEN];
        out[0..6].copy_from_slice(&(self.seconds & Self::MAX_SECONDS).to_be_bytes()[2..8]);
        out[6..10].copy_from_slice(&self.nanoseconds.to_be_bytes());
        out
    }

    /// Reads 10 wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < TIMESTAMP_LEN {
            return Err(short("timestamp", TIMESTAMP_LEN, bytes.len()));
        }
        let mut seconds = [0u8; 8];
        seconds[2..8].copy_from_slice(&bytes[0..6]);
        Ok(Self {
            seconds: u64::from_be_bytes(seconds),
            nanoseconds: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        })
    }
}

/// A port identity: the clock identity (an EUI-64) and a port number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct PortIdentity {
    /// The 8-byte clock identity, big-endian. This is what `networkTimeTimelineID` names.
    pub clock_identity: u64,
    /// The port number (1 for a single-port clock).
    pub port_number: u16,
}

impl PortIdentity {
    /// A port identity.
    #[must_use]
    pub fn new(clock_identity: u64, port_number: u16) -> Self {
        Self {
            clock_identity,
            port_number,
        }
    }

    fn encode_into(&self, out: &mut [u8]) {
        out[0..8].copy_from_slice(&self.clock_identity.to_be_bytes());
        out[8..10].copy_from_slice(&self.port_number.to_be_bytes());
    }

    fn parse(bytes: &[u8]) -> Self {
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[0..8]);
        Self {
            clock_identity: u64::from_be_bytes(id),
            port_number: u16::from_be_bytes([bytes[8], bytes[9]]),
        }
    }
}

/// The 34-byte common header (IEEE 1588-2008 Table 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// High nibble of octet 0.
    pub transport_specific: u8,
    /// Low nibble of octet 0.
    pub message_type: MessageType,
    /// `versionPTP`.
    pub version: u8,
    /// `messageLength`, the whole message including the header and any TLVs.
    pub message_length: u16,
    /// `domainNumber`.
    pub domain: u8,
    /// `flagField`.
    pub flags: u16,
    /// `correctionField`: nanoseconds × 2^16, signed.
    pub correction: i64,
    /// Who sent it.
    pub source_port_identity: PortIdentity,
    /// `sequenceId`.
    pub sequence_id: u16,
    /// `controlField`.
    pub control: u8,
    /// `logMessageInterval`.
    pub log_message_interval: i8,
}

impl Header {
    /// A header with the standard's defaults for `message_type`; `message_length` is filled in
    /// by the encoder.
    #[must_use]
    pub fn new(message_type: MessageType, source: PortIdentity, sequence_id: u16) -> Self {
        Self {
            transport_specific: 0,
            message_type,
            version: VERSION,
            message_length: 0,
            domain: 0,
            flags: 0,
            correction: 0,
            source_port_identity: source,
            sequence_id,
            control: message_type.control_field(),
            log_message_interval: 0,
        }
    }

    /// The correction field in whole nanoseconds (arithmetic shift).
    #[must_use]
    pub fn correction_nanos(&self) -> i64 {
        self.correction >> 16
    }

    fn encode_into(&self, out: &mut [u8]) {
        out[0] = (self.transport_specific << 4) | self.message_type.code();
        out[1] = self.version & 0x0F;
        out[2..4].copy_from_slice(&self.message_length.to_be_bytes());
        out[4] = self.domain;
        out[5] = 0;
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..16].copy_from_slice(&self.correction.to_be_bytes());
        out[16..20].fill(0);
        self.source_port_identity.encode_into(&mut out[20..30]);
        out[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        out[32] = self.control;
        out[33] = self.log_message_interval as u8;
    }

    fn parse(bytes: &[u8]) -> Self {
        let mut correction = [0u8; 8];
        correction.copy_from_slice(&bytes[8..16]);
        Self {
            transport_specific: bytes[0] >> 4,
            message_type: MessageType::from_code(bytes[0]),
            version: bytes[1] & 0x0F,
            message_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            domain: bytes[4],
            flags: u16::from_be_bytes([bytes[6], bytes[7]]),
            correction: i64::from_be_bytes(correction),
            source_port_identity: PortIdentity::parse(&bytes[20..30]),
            sequence_id: u16::from_be_bytes([bytes[30], bytes[31]]),
            control: bytes[32],
            log_message_interval: bytes[33] as i8,
        }
    }
}

/// One TLV from the end of a message, uninterpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tlv {
    /// `tlvType` (3 = ORGANIZATION_EXTENSION, which both Apple Follow_Up TLVs are).
    pub tlv_type: u16,
    /// The value, `lengthField` bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// A TLV.
    #[must_use]
    pub fn new(tlv_type: u16, value: Vec<u8>) -> Self {
        Self { tlv_type, value }
    }
}

/// The body of an Announce (Table 25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Announce {
    /// `originTimestamp`.
    pub origin: Timestamp,
    /// `currentUtcOffset`.
    pub current_utc_offset: i16,
    /// `grandmasterPriority1`.
    pub grandmaster_priority1: u8,
    /// `grandmasterClockQuality.clockClass`.
    pub clock_class: u8,
    /// `grandmasterClockQuality.clockAccuracy`.
    pub clock_accuracy: u8,
    /// `grandmasterClockQuality.offsetScaledLogVariance`.
    pub offset_scaled_log_variance: u16,
    /// `grandmasterPriority2`.
    pub grandmaster_priority2: u8,
    /// `grandmasterIdentity`: the timeline a follower anchors against.
    pub grandmaster_identity: u64,
    /// `stepsRemoved`.
    pub steps_removed: u16,
    /// `timeSource`.
    pub time_source: u8,
}

/// A message body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Body {
    /// Sync: the origin timestamp (zero-ish on a two-step clock; see Follow_Up).
    Sync {
        /// `originTimestamp`.
        origin: Timestamp,
    },
    /// Delay_Req.
    DelayReq {
        /// `originTimestamp`.
        origin: Timestamp,
    },
    /// Follow_Up: the precise time the matching Sync left the master.
    FollowUp {
        /// `preciseOriginTimestamp`.
        precise_origin: Timestamp,
        /// TLVs after the body (Apple sends two).
        tlvs: Vec<Tlv>,
    },
    /// Delay_Resp: when the master received our Delay_Req.
    DelayResp {
        /// `receiveTimestamp`.
        receive: Timestamp,
        /// Whose Delay_Req this answers.
        requesting: PortIdentity,
    },
    /// Announce.
    Announce(Announce),
    /// A type this module does not interpret (Pdelay_*, Signaling, Management, reserved).
    Other,
}

/// A parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Message {
    /// The common header.
    pub header: Header,
    /// The body.
    pub body: Body,
}

fn short(what: &str, need: usize, got: usize) -> AirPlayError {
    AirPlayError::Protocol(format!("PTP {what} needs {need} bytes, got {got}"))
}

/// Parses one PTP message. `messageLength` bounds it; trailing bytes are ignored. A version other
/// than 2 is an error.
pub fn parse(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < HEADER_LEN {
        return Err(short("header", HEADER_LEN, bytes.len()));
    }
    let header = Header::parse(bytes);
    if header.version != VERSION {
        return Err(AirPlayError::Protocol(format!(
            "PTP version {} is not 2",
            header.version
        )));
    }
    let length = usize::from(header.message_length);
    if length < HEADER_LEN || length > bytes.len() {
        return Err(AirPlayError::Protocol(format!(
            "PTP messageLength {length} does not fit the {} bytes received",
            bytes.len()
        )));
    }
    let message = &bytes[..length];
    let rest = &message[HEADER_LEN..];
    let body = match header.message_type {
        MessageType::Sync => Body::Sync {
            origin: Timestamp::parse(rest)?,
        },
        MessageType::DelayReq => Body::DelayReq {
            origin: Timestamp::parse(rest)?,
        },
        MessageType::FollowUp => Body::FollowUp {
            precise_origin: Timestamp::parse(rest)?,
            tlvs: parse_tlvs(&rest[TIMESTAMP_LEN..])?,
        },
        MessageType::DelayResp => {
            if rest.len() < TIMESTAMP_LEN + PORT_IDENTITY_LEN {
                return Err(short("Delay_Resp", DELAY_RESP_LEN, HEADER_LEN + rest.len()));
            }
            Body::DelayResp {
                receive: Timestamp::parse(rest)?,
                requesting: PortIdentity::parse(&rest[TIMESTAMP_LEN..]),
            }
        }
        MessageType::Announce => {
            if rest.len() < ANNOUNCE_LEN - HEADER_LEN {
                return Err(short("Announce", ANNOUNCE_LEN, HEADER_LEN + rest.len()));
            }
            let mut identity = [0u8; 8];
            identity.copy_from_slice(&rest[19..27]);
            Body::Announce(Announce {
                origin: Timestamp::parse(rest)?,
                current_utc_offset: i16::from_be_bytes([rest[10], rest[11]]),
                grandmaster_priority1: rest[13],
                clock_class: rest[14],
                clock_accuracy: rest[15],
                offset_scaled_log_variance: u16::from_be_bytes([rest[16], rest[17]]),
                grandmaster_priority2: rest[18],
                grandmaster_identity: u64::from_be_bytes(identity),
                steps_removed: u16::from_be_bytes([rest[27], rest[28]]),
                time_source: rest[29],
            })
        }
        _ => Body::Other,
    };
    Ok(Message { header, body })
}

fn parse_tlvs(mut bytes: &[u8]) -> Result<Vec<Tlv>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(short("TLV header", 4, bytes.len()));
        }
        let tlv_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let value = bytes
            .get(4..4 + length)
            .ok_or_else(|| short("TLV value", 4 + length, bytes.len()))?;
        out.push(Tlv {
            tlv_type,
            value: value.to_vec(),
        });
        bytes = &bytes[4 + length..];
    }
    Ok(out)
}

/// Builds a Delay_Req (44 bytes); the master ignores the timestamp, as t3 is recorded locally.
#[must_use]
pub fn delay_req(
    source: PortIdentity,
    domain: u8,
    sequence_id: u16,
    origin: Timestamp,
) -> [u8; SYNC_LEN] {
    let mut out = [0u8; SYNC_LEN];
    Header {
        transport_specific: 0,
        message_type: MessageType::DelayReq,
        version: VERSION,
        message_length: SYNC_LEN as u16,
        domain,
        flags: 0,
        correction: 0,
        source_port_identity: source,
        sequence_id,
        control: MessageType::DelayReq.control_field(),
        log_message_interval: DELAY_REQ_LOG_INTERVAL,
    }
    .encode_into(&mut out);
    out[HEADER_LEN..].copy_from_slice(&origin.encode());
    out
}

/// Builds a Sync, Follow_Up or Delay_Resp, for tests and loopback master doubles.
#[must_use]
pub fn encode_master_message(header: &Header, body: &Body) -> Vec<u8> {
    let mut payload = Vec::new();
    match body {
        Body::Sync { origin } | Body::DelayReq { origin } => payload.extend(origin.encode()),
        Body::FollowUp {
            precise_origin,
            tlvs,
        } => {
            payload.extend(precise_origin.encode());
            for tlv in tlvs {
                payload.extend(tlv.tlv_type.to_be_bytes());
                payload.extend((tlv.value.len() as u16).to_be_bytes());
                payload.extend(&tlv.value);
            }
        }
        Body::DelayResp {
            receive,
            requesting,
        } => {
            payload.extend(receive.encode());
            let mut id = [0u8; PORT_IDENTITY_LEN];
            requesting.encode_into(&mut id);
            payload.extend(id);
        }
        Body::Announce(_) | Body::Other => {}
    }
    let mut out = vec![0u8; HEADER_LEN];
    let mut header = *header;
    header.message_length = (HEADER_LEN + payload.len()) as u16;
    header.encode_into(&mut out);
    out.extend(payload);
    out
}

/// One offset measurement: `offset = local − master`, and the path delay if it was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClockSample {
    /// Local clock minus master clock, nanoseconds.
    pub offset_ns: i128,
    /// The mean one-way path delay, nanoseconds, when an end-to-end exchange measured it.
    pub mean_path_delay_ns: Option<i128>,
}

impl ClockSample {
    /// A sample; `mean_path_delay_ns` is `None` for a one-way estimate.
    #[must_use]
    pub fn new(offset_ns: i128, mean_path_delay_ns: Option<i128>) -> Self {
        Self {
            offset_ns,
            mean_path_delay_ns,
        }
    }
}

/// The four timestamps of an end-to-end exchange and the corrections that apply to them.
///
/// `t1` is when the Sync left the master (the Follow_Up's precise origin on a two-step clock),
/// `t2` when it reached us, `t3` when our Delay_Req left us, `t4` when it reached the master
/// (Delay_Resp's receive timestamp). `t2`/`t3` are on our clock, `t1`/`t4` on the master's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct E2eExchange {
    /// Master: Sync departure.
    pub t1: Timestamp,
    /// Local: Sync arrival.
    pub t2: Timestamp,
    /// Local: Delay_Req departure.
    pub t3: Timestamp,
    /// Master: Delay_Req arrival.
    pub t4: Timestamp,
    /// Sync + Follow_Up correction fields, nanoseconds.
    pub sync_correction_ns: i64,
    /// Delay_Resp correction field, nanoseconds.
    pub delay_resp_correction_ns: i64,
}

impl E2eExchange {
    /// An exchange with no corrections.
    #[must_use]
    pub fn new(t1: Timestamp, t2: Timestamp, t3: Timestamp, t4: Timestamp) -> Self {
        Self {
            t1,
            t2,
            t3,
            t4,
            sync_correction_ns: 0,
            delay_resp_correction_ns: 0,
        }
    }

    /// IEEE 1588-2008 §11.3.2:
    ///
    /// ```text
    ///   meanPathDelay    = [(t2 − t3) + (t4 − t1) − correctionSync − correctionDelayResp] / 2
    ///   offsetFromMaster = t2 − t1 − meanPathDelay − correctionSync
    /// ```
    ///
    /// Integer nanoseconds; the halving truncates toward zero.
    #[must_use]
    pub fn solve(&self) -> ClockSample {
        let (t1, t2, t3, t4) = (
            self.t1.to_nanos() as i128,
            self.t2.to_nanos() as i128,
            self.t3.to_nanos() as i128,
            self.t4.to_nanos() as i128,
        );
        let sync_corr = i128::from(self.sync_correction_ns);
        let resp_corr = i128::from(self.delay_resp_correction_ns);
        let delay = ((t2 - t3) + (t4 - t1) - sync_corr - resp_corr) / 2;
        ClockSample {
            offset_ns: t2 - t1 - delay - sync_corr,
            mean_path_delay_ns: Some(delay),
        }
    }
}

/// The one-way estimate `nqptp` uses, `reception − (preciseOrigin + correction)`, as local −
/// master; it exceeds the true offset by the path delay.
#[must_use]
pub fn one_way_offset(precise_origin: Timestamp, correction_ns: i64, reception: Timestamp) -> i128 {
    reception.to_nanos() as i128 - (precise_origin.to_nanos() as i128 + i128::from(correction_ns))
}

/// Keeps the best of the last few samples.
///
/// "Best" is the smallest path delay for end-to-end samples and the smallest `local − master` for
/// one-way samples (delay only adds to it).
#[derive(Debug, Clone)]
pub struct ClockFilter {
    window: usize,
    samples: std::collections::VecDeque<ClockSample>,
}

impl ClockFilter {
    /// A filter over the last `window` samples (at least 1).
    #[must_use]
    pub fn new(window: usize) -> Self {
        let window = window.max(1);
        Self {
            window,
            samples: std::collections::VecDeque::with_capacity(window),
        }
    }

    /// Adds a sample, dropping the oldest beyond the window.
    pub fn push(&mut self, sample: ClockSample) {
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// Clears the window — call when the grandmaster changes.
    pub fn reset(&mut self) {
        self.samples.clear();
    }

    /// The chosen sample, if any.
    #[must_use]
    pub fn best(&self) -> Option<ClockSample> {
        let measured = self
            .samples
            .iter()
            .filter(|s| s.mean_path_delay_ns.is_some())
            .min_by_key(|s| s.mean_path_delay_ns);
        measured
            .copied()
            .or_else(|| self.samples.iter().min_by_key(|s| s.offset_ns).copied())
    }

    /// Converts a local time to the master's timeline with the chosen sample.
    #[must_use]
    pub fn master_nanos(&self, local_nanos: u128) -> Option<u128> {
        let offset = self.best()?.offset_ns;
        let master = local_nanos as i128 - offset;
        u128::try_from(master).ok()
    }
}

/// A PTP time as `SETRATEANCHORTIME` carries it: whole seconds and a 64-bit binary fraction.
///
/// shairport-sync reads it as `ns = secs × 10^9 + (((frac >> 32) × 10^9) >> 32)`;
/// [`Self::from_nanos`] round-trips exactly through that read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct NetworkTime {
    /// `networkTimeSecs`.
    pub secs: u64,
    /// `networkTimeFrac`.
    pub frac: u64,
}

impl NetworkTime {
    /// From nanoseconds on the PTP timeline.
    #[must_use]
    pub fn from_nanos(nanos: u128) -> Self {
        let secs = (nanos / 1_000_000_000) as u64;
        let rem = nanos % 1_000_000_000;
        // shairport-sync reads only the top 32 bits of the fraction and truncates; rounding them up
        // lands its read on exactly this nanosecond. rem < 10^9, so the value stays below 2^32.
        let frac32 = (rem << 32).div_ceil(1_000_000_000) as u64;
        Self {
            secs,
            frac: frac32 << 32,
        }
    }

    /// Back to nanoseconds, the way shairport-sync reads it.
    #[must_use]
    pub fn to_nanos(&self) -> u128 {
        u128::from(self.secs) * 1_000_000_000
            + ((u128::from(self.frac >> 32) * 1_000_000_000) >> 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_through_ten_bytes() {
        let ts = Timestamp::new(0x0000_45B1_1159, 174_421_797);
        assert_eq!(Timestamp::parse(&ts.encode()).unwrap(), ts);
        assert_eq!(Timestamp::from_nanos(ts.to_nanos()), ts);
    }

    #[test]
    fn delay_req_is_44_bytes_with_control_1_and_interval_0x7f() {
        let bytes = delay_req(
            PortIdentity::new(0x0011_22FF_FE33_4455, 1),
            0,
            9,
            Timestamp::default(),
        );
        assert_eq!(bytes.len(), 44);
        let message = parse(&bytes).unwrap();
        assert_eq!(message.header.message_type, MessageType::DelayReq);
        assert_eq!(message.header.control, 1);
        assert_eq!(message.header.log_message_interval, 0x7F);
        assert_eq!(message.header.sequence_id, 9);
        assert_eq!(
            message.header.source_port_identity.clock_identity,
            0x0011_22FF_FE33_4455
        );
    }

    #[test]
    fn follow_up_tlvs_are_collected() {
        let header = Header {
            transport_specific: 1,
            message_type: MessageType::FollowUp,
            version: 2,
            message_length: 0,
            domain: 0,
            flags: 0,
            correction: 3 << 16,
            source_port_identity: PortIdentity::new(7, 1),
            sequence_id: 1,
            control: 2,
            log_message_interval: -3,
        };
        let bytes = encode_master_message(
            &header,
            &Body::FollowUp {
                precise_origin: Timestamp::new(10, 20),
                tlvs: vec![Tlv {
                    tlv_type: 3,
                    value: vec![0, 0x80, 0xC2, 0, 0, 1],
                }],
            },
        );
        let message = parse(&bytes).unwrap();
        assert_eq!(message.header.correction_nanos(), 3);
        match message.body {
            Body::FollowUp { tlvs, .. } => assert_eq!(tlvs[0].value, [0, 0x80, 0xC2, 0, 0, 1]),
            other => panic!("expected a Follow_Up, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_tlv_is_an_error_not_a_panic() {
        let mut bytes = encode_master_message(
            &Header {
                transport_specific: 0,
                message_type: MessageType::FollowUp,
                version: 2,
                message_length: 0,
                domain: 0,
                flags: 0,
                correction: 0,
                source_port_identity: PortIdentity::default(),
                sequence_id: 0,
                control: 2,
                log_message_interval: 0,
            },
            &Body::FollowUp {
                precise_origin: Timestamp::default(),
                tlvs: vec![Tlv {
                    tlv_type: 3,
                    value: vec![1, 2, 3, 4],
                }],
            },
        );
        bytes[HEADER_LEN + TIMESTAMP_LEN + 3] = 200; // claim a longer value than follows
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn network_time_round_trips_through_shairports_read() {
        for nanos in [
            0u128,
            1,
            999_999_999,
            1_500_000_000,
            1_169_232_217_174_421_797,
        ] {
            assert_eq!(NetworkTime::from_nanos(nanos).to_nanos(), nanos, "{nanos}");
        }
        assert_eq!(NetworkTime::from_nanos(500_000_000).frac, 1 << 63);
    }
}
