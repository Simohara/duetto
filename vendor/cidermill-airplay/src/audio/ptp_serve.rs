//! The grandmaster side of AirPlay PTP: the messages a sender that serves the session clock sends
//! and answers, sans-io. [`super::ptp`] is the follower side.
//!
//! Receivers follow only a clock named in the timing-peer list. Observed on an Apple TV (tvOS 26,
//! `AppleTV14,1`): once the sender announces [`Dataset::IOS`] the television stops announcing
//! its own clock and sends Delay_Req to the sender. It still refuses a rate-1
//! `SETRATEANCHORTIME` on this timeline, so it is not shown to be locked.
//!
//! Layouts follow IEEE 1588-2008 and 802.1AS with AirPlay specifics: `majorSdoId` 1 (gPTP),
//! `UNICAST` and `PTP_TIMESCALE` flags (plus `TWO_STEP` on a Sync), a PATH_TRACE TLV on Announce,
//! 802.1AS and Apple TLVs on Follow_Up, two Apple TLVs on Signaling. Observed from a real iPhone
//! (iOS 26.7) are the constants prefixed `IOS_26_7`; this module keeps announcing [`Dataset::IOS`]
//! because it is built to be the master. Timestamps are nanoseconds on the sender's clock.

use super::ptp::{self, MessageType, Timestamp};

/// `flagField` bit: `unicastFlag`.
pub const FLAG_UNICAST: u16 = 0x0400;
/// `flagField` bit: `ptpTimescale`.
pub const FLAG_PTP_TIMESCALE: u16 = 0x0008;
/// Our source port number; it must match `ClockPorts` in `SETPEERSX`.
pub const PORT_NUMBER: u16 = 0x8005;
/// The PTP source port number a real iPhone used in its first media session (0x8001), named in
/// `SETPEERSX`'s `ClockPorts`. Observed.
pub const IOS_26_7_FIRST_PORT_NUMBER: u16 = 0x8001;
/// `logMessageInterval` of a real iPhone's Announce: -2, four a second. Observed.
pub const IOS_26_7_LOG_ANNOUNCE_INTERVAL: i8 = -2;
/// `currentUtcOffset` in a real iPhone's Announce: 37. Observed.
pub const IOS_26_7_CURRENT_UTC_OFFSET: i16 = 37;
/// `logMessageInterval` of Sync / Follow_Up: 125 ms.
pub const LOG_SYNC_INTERVAL: i8 = -3;
/// `logMessageInterval` of Announce: 1 s.
pub const LOG_ANNOUNCE_INTERVAL: i8 = 0;
/// Length of an Announce with its PATH_TRACE TLV.
pub const ANNOUNCE_LEN: usize = ptp::ANNOUNCE_LEN + 12;
/// Length of a Follow_Up with its two TLVs.
pub const FOLLOW_UP_LEN: usize = ptp::SYNC_LEN + 32 + 20;
/// Length of a Signaling with its two Apple TLVs.
pub const SIGNALING_LEN: usize = ptp::HEADER_LEN + 10 + 26 + 36;
/// TLV type ORGANIZATION_EXTENSION.
pub const TLV_ORGANIZATION_EXTENSION: u16 = 0x0003;
/// TLV type PATH_TRACE.
pub const TLV_PATH_TRACE: u16 = 0x0008;
/// TLV type REQUEST_UNICAST_TRANSMISSION (IEEE 1588 §16.1).
pub const TLV_REQUEST_UNICAST: u16 = 0x0004;
/// TLV type GRANT_UNICAST_TRANSMISSION.
pub const TLV_GRANT_UNICAST: u16 = 0x0005;

/// A grandmaster dataset, as an Announce carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dataset {
    /// `grandmasterPriority1` (lower wins).
    pub priority1: u8,
    /// `clockClass`.
    pub clock_class: u8,
    /// `clockAccuracy`.
    pub clock_accuracy: u8,
    /// `offsetScaledLogVariance`.
    pub variance: u16,
    /// `grandmasterPriority2`.
    pub priority2: u8,
    /// `timeSource`.
    pub time_source: u8,
}

impl Dataset {
    /// The dataset iOS senders are reported to announce (priority1 128, clockClass 6, timeSource
    /// GPS); it beats an Apple TV's (priority1 248, observed) in the best-master comparison.
    pub const IOS: Self = Self {
        priority1: 128,
        clock_class: 6,
        clock_accuracy: 0x21,
        variance: 0x436A,
        priority2: 128,
        time_source: 0x20,
    };

    /// The dataset a real iPhone on iOS 26.7 announced (priority1 250, clockClass 248, timeSource
    /// 0xA0). Observed; it loses the best-master comparison to an Apple TV.
    pub const IOS_26_7_OBSERVED: Self = Self {
        priority1: 250,
        clock_class: 248,
        clock_accuracy: 0x21,
        variance: 0x436A,
        priority2: 246,
        time_source: 0xA0,
    };
}

#[allow(clippy::too_many_arguments)] // The header's fields, named.
fn header(
    out: &mut [u8],
    message_type: MessageType,
    flags: u16,
    clock: u64,
    sequence: u16,
    control: u8,
    log_interval: i8,
) {
    let length = out.len() as u16;
    out[..ptp::HEADER_LEN].fill(0);
    out[0] = 0x10 | message_type.code();
    out[1] = ptp::VERSION;
    out[2..4].copy_from_slice(&length.to_be_bytes());
    out[6..8].copy_from_slice(&flags.to_be_bytes());
    out[20..28].copy_from_slice(&clock.to_be_bytes());
    out[28..30].copy_from_slice(&PORT_NUMBER.to_be_bytes());
    out[30..32].copy_from_slice(&sequence.to_be_bytes());
    out[32] = control;
    out[33] = log_interval as u8;
}

/// An Announce naming `clock` as grandmaster, with a PATH_TRACE TLV ([`ANNOUNCE_LEN`] bytes).
#[must_use]
pub fn announce(clock: u64, sequence: u16, dataset: Dataset) -> Vec<u8> {
    let mut out = vec![0u8; ANNOUNCE_LEN];
    header(
        &mut out,
        MessageType::Announce,
        FLAG_UNICAST | FLAG_PTP_TIMESCALE,
        clock,
        sequence,
        5,
        LOG_ANNOUNCE_INTERVAL,
    );
    let body = &mut out[ptp::HEADER_LEN..];
    // originTimestamp 0 and currentUtcOffset 0.
    body[13] = dataset.priority1;
    body[14] = dataset.clock_class;
    body[15] = dataset.clock_accuracy;
    body[16..18].copy_from_slice(&dataset.variance.to_be_bytes());
    body[18] = dataset.priority2;
    body[19..27].copy_from_slice(&clock.to_be_bytes());
    // stepsRemoved 0.
    body[29] = dataset.time_source;
    body[30..32].copy_from_slice(&TLV_PATH_TRACE.to_be_bytes());
    body[32..34].copy_from_slice(&8u16.to_be_bytes());
    body[34..42].copy_from_slice(&clock.to_be_bytes());
    out
}

/// A two-step Sync (44 bytes, origin zero); its departure time goes in [`follow_up`].
#[must_use]
pub fn sync(clock: u64, sequence: u16) -> Vec<u8> {
    let mut out = vec![0u8; ptp::SYNC_LEN];
    header(
        &mut out,
        MessageType::Sync,
        FLAG_UNICAST | FLAG_PTP_TIMESCALE | ptp::FLAG_TWO_STEP,
        clock,
        sequence,
        0,
        LOG_SYNC_INTERVAL,
    );
    out
}

/// The Follow_Up for Sync `sequence`: when it left, and the two TLVs ([`FOLLOW_UP_LEN`] bytes).
#[must_use]
pub fn follow_up(clock: u64, sequence: u16, departure_nanos: u128) -> Vec<u8> {
    let mut out = vec![0u8; FOLLOW_UP_LEN];
    header(
        &mut out,
        MessageType::FollowUp,
        FLAG_UNICAST | FLAG_PTP_TIMESCALE,
        clock,
        sequence,
        2,
        LOG_SYNC_INTERVAL,
    );
    let at = ptp::HEADER_LEN;
    out[at..at + ptp::TIMESTAMP_LEN]
        .copy_from_slice(&Timestamp::from_nanos(departure_nanos).encode());
    // 802.1AS Follow_Up information TLV: OUI 00:80:C2 subtype 1, other fields zero.
    let tlv = at + ptp::TIMESTAMP_LEN;
    out[tlv..tlv + 10].copy_from_slice(&[0x00, 0x03, 0x00, 0x1C, 0x00, 0x80, 0xC2, 0, 0, 1]);
    // Apple TLV: OUI 00:0D:93 subtype 4, the clock identity.
    let apple = tlv + 32;
    out[apple..apple + 10].copy_from_slice(&[0x00, 0x03, 0x00, 0x10, 0x00, 0x0D, 0x93, 0, 0, 4]);
    out[apple + 10..apple + 18].copy_from_slice(&clock.to_be_bytes());
    out
}

/// A Signaling with the two Apple TLVs sent with each Announce ([`SIGNALING_LEN`] bytes).
#[must_use]
pub fn signaling(clock: u64, sequence: u16) -> Vec<u8> {
    let mut out = vec![0u8; SIGNALING_LEN];
    header(
        &mut out,
        MessageType::Signaling,
        FLAG_UNICAST | FLAG_PTP_TIMESCALE,
        clock,
        sequence,
        5,
        -128,
    );
    // targetPortIdentity: all zeros (wildcard).
    let tlv = ptp::HEADER_LEN + 10;
    out[tlv..tlv + 14].copy_from_slice(&[
        0x00, 0x03, 0x00, 0x16, 0x00, 0x0D, 0x93, 0, 0, 1, 0, 0, 3, 1,
    ]);
    let second = tlv + 26;
    out[second..second + 14].copy_from_slice(&[
        0x00, 0x03, 0x00, 0x20, 0x00, 0x0D, 0x93, 0, 0, 5, 0, 0, 3, 1,
    ]);
    out
}

/// The answer to a Delay_Req: when it reached us and whose it was ([`ptp::DELAY_RESP_LEN`]
/// bytes). `None` for anything that is not a Delay_Req or is too short to carry a port identity.
#[must_use]
pub fn delay_resp(clock: u64, request: &[u8], received_nanos: u128) -> Option<Vec<u8>> {
    if !is_type(request, MessageType::DelayReq) {
        return None;
    }
    respond(clock, request, received_nanos, MessageType::DelayResp, 3)
}

/// The two answers to a Pdelay_Req: Pdelay_Resp (event port; when the request reached us) and
/// Pdelay_Resp_Follow_Up (general port; when the response left). `None` for anything that is not
/// a Pdelay_Req or is too short.
#[must_use]
pub fn pdelay_resp(
    clock: u64,
    request: &[u8],
    received_nanos: u128,
    departed_nanos: u128,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if !is_type(request, MessageType::PdelayReq) {
        return None;
    }
    Some((
        respond(clock, request, received_nanos, MessageType::PdelayResp, 5)?,
        respond(
            clock,
            request,
            departed_nanos,
            MessageType::PdelayRespFollowUp,
            5,
        )?,
    ))
}

/// Whether `request`'s `messageType` nibble is `expected`. A responder answers only requests, so a
/// spoofed response cannot set two responders answering each other.
fn is_type(request: &[u8], expected: MessageType) -> bool {
    request
        .first()
        .is_some_and(|&first| MessageType::from_code(first) == expected)
}

fn respond(
    clock: u64,
    request: &[u8],
    nanos: u128,
    message_type: MessageType,
    control: u8,
) -> Option<Vec<u8>> {
    if request.len() < ptp::HEADER_LEN {
        return None;
    }
    let sequence = u16::from_be_bytes([request[30], request[31]]);
    let flags = match message_type {
        MessageType::PdelayRespFollowUp => FLAG_UNICAST | FLAG_PTP_TIMESCALE,
        _ => FLAG_UNICAST | FLAG_PTP_TIMESCALE | ptp::FLAG_TWO_STEP,
    };
    let mut out = vec![0u8; ptp::DELAY_RESP_LEN];
    header(
        &mut out,
        message_type,
        flags,
        clock,
        sequence,
        control,
        LOG_SYNC_INTERVAL,
    );
    let at = ptp::HEADER_LEN;
    out[at..at + ptp::TIMESTAMP_LEN].copy_from_slice(&Timestamp::from_nanos(nanos).encode());
    // requestingPortIdentity: the requester's clock identity and port number, verbatim.
    out[at + ptp::TIMESTAMP_LEN..].copy_from_slice(&request[20..30]);
    Some(out)
}

/// The grants for a Signaling's REQUEST_UNICAST_TRANSMISSION TLVs (IEEE 1588 §16.1): one GRANT
/// per request, echoing its message type, interval and duration (300 s when it asked for 0),
/// renewal invited. `None` when the message is not a Signaling or asks for nothing. Never panics
/// on any input.
#[must_use]
pub fn unicast_grant(clock: u64, request: &[u8]) -> Option<Vec<u8>> {
    if !is_type(request, MessageType::Signaling) {
        return None;
    }
    let mut at = ptp::HEADER_LEN + 10;
    let mut grants: Vec<[u8; 12]> = Vec::new();
    while at + 4 <= request.len() && grants.len() < 8 {
        let kind = u16::from_be_bytes([request[at], request[at + 1]]);
        let length = usize::from(u16::from_be_bytes([request[at + 2], request[at + 3]]));
        let Some(value) = request.get(at + 4..at + 4 + length) else {
            break;
        };
        if kind == TLV_REQUEST_UNICAST && length >= 6 {
            let mut grant = [0u8; 12];
            grant[0..2].copy_from_slice(&TLV_GRANT_UNICAST.to_be_bytes());
            grant[2..4].copy_from_slice(&8u16.to_be_bytes());
            grant[4] = value[0] & 0xF0;
            grant[5] = value[1];
            let duration = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
            let duration = if duration == 0 { 300 } else { duration };
            grant[6..10].copy_from_slice(&duration.to_be_bytes());
            grant[11] = 1;
            grants.push(grant);
        }
        at += 4 + length;
    }
    if grants.is_empty() {
        return None;
    }
    let mut out = vec![0u8; ptp::HEADER_LEN + 10 + grants.len() * 12];
    header(
        &mut out,
        MessageType::Signaling,
        FLAG_UNICAST,
        clock,
        u16::from_be_bytes([request[30], request[31]]),
        5,
        0x7F,
    );
    out[ptp::HEADER_LEN..ptp::HEADER_LEN + 10].copy_from_slice(&request[20..30]);
    for (i, grant) in grants.iter().enumerate() {
        let at = ptp::HEADER_LEN + 10 + i * 12;
        out[at..at + 12].copy_from_slice(grant);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: u64 = 0x0011_22FF_FE33_4455;

    #[test]
    fn every_message_parses_back_as_what_it_claims_to_be() {
        let announce = ptp::parse(&announce(CLOCK, 7, Dataset::IOS)).unwrap();
        match announce.body {
            ptp::Body::Announce(a) => {
                assert_eq!(a.grandmaster_identity, CLOCK);
                assert_eq!(a.grandmaster_priority1, 128);
                assert_eq!(a.clock_class, 6);
            }
            other => panic!("expected an Announce, got {other:?}"),
        }
        assert_eq!(announce.header.transport_specific, 1);
        assert_eq!(announce.header.sequence_id, 7);

        let sync = ptp::parse(&sync(CLOCK, 9)).unwrap();
        assert_eq!(sync.header.message_type, MessageType::Sync);
        assert_ne!(sync.header.flags & ptp::FLAG_TWO_STEP, 0);

        let follow = ptp::parse(&follow_up(CLOCK, 9, 1_500_000_000)).unwrap();
        match follow.body {
            ptp::Body::FollowUp {
                precise_origin,
                tlvs,
            } => {
                assert_eq!(precise_origin, Timestamp::new(1, 500_000_000));
                assert_eq!(tlvs.len(), 2);
                assert_eq!(&tlvs[1].value[..3], &[0x00, 0x0D, 0x93]);
                assert_eq!(&tlvs[1].value[6..14], &CLOCK.to_be_bytes());
            }
            other => panic!("expected a Follow_Up, got {other:?}"),
        }
        assert_eq!(
            ptp::parse(&signaling(CLOCK, 1))
                .unwrap()
                .header
                .message_type,
            MessageType::Signaling
        );
    }

    #[test]
    fn a_delay_resp_names_the_requester_and_echoes_its_sequence() {
        let request = ptp::delay_req(
            ptp::PortIdentity::new(0xAB, 0x8010),
            0,
            41,
            Timestamp::default(),
        );
        let reply = ptp::parse(&delay_resp(CLOCK, &request, 2_000_000_007).unwrap()).unwrap();
        assert_eq!(reply.header.sequence_id, 41);
        assert_eq!(reply.header.source_port_identity.clock_identity, CLOCK);
        match reply.body {
            ptp::Body::DelayResp {
                receive,
                requesting,
            } => {
                assert_eq!(receive, Timestamp::new(2, 7));
                assert_eq!(requesting, ptp::PortIdentity::new(0xAB, 0x8010));
            }
            other => panic!("expected a Delay_Resp, got {other:?}"),
        }
        assert!(delay_resp(CLOCK, &request[..20], 0).is_none());
    }

    #[test]
    fn only_requests_are_answered() {
        let request = ptp::delay_req(
            ptp::PortIdentity::new(0xAB, 0x8010),
            0,
            41,
            Timestamp::default(),
        );
        let reply = delay_resp(CLOCK, &request, 1).unwrap();
        assert!(delay_resp(CLOCK, &reply, 1).is_none(), "a Delay_Resp");
        assert!(pdelay_resp(CLOCK, &request, 1, 2).is_none(), "a Delay_Req");
        let mut pdelay = request;
        pdelay[0] = (pdelay[0] & 0xF0) | MessageType::PdelayReq.code();
        let (resp, follow) = pdelay_resp(CLOCK, &pdelay, 1, 2).unwrap();
        assert!(pdelay_resp(CLOCK, &resp, 1, 2).is_none(), "a Pdelay_Resp");
        assert!(pdelay_resp(CLOCK, &follow, 1, 2).is_none(), "a Follow_Up");
        assert!(unicast_grant(CLOCK, &reply).is_none(), "not a Signaling");
    }

    #[test]
    fn a_unicast_request_is_granted_and_anything_else_is_not() {
        let mut request = vec![0u8; ptp::HEADER_LEN + 10];
        request[0] = 0x1C;
        request[20..28].copy_from_slice(&0xABu64.to_be_bytes());
        request[30..32].copy_from_slice(&5u16.to_be_bytes());
        request.extend([0x00, 0x04, 0x00, 0x06, 0xB0, 0xFE, 0, 0, 0, 0]);
        let grant = unicast_grant(CLOCK, &request).unwrap();
        let tlv = ptp::HEADER_LEN + 10;
        assert_eq!(&grant[tlv..tlv + 4], &[0x00, 0x05, 0x00, 0x08]);
        assert_eq!(grant[tlv + 4], 0xB0, "message type echoed");
        assert_eq!(grant[tlv + 5], 0xFE, "interval echoed");
        assert_eq!(
            &grant[tlv + 6..tlv + 10],
            &300u32.to_be_bytes(),
            "0 becomes 300 s"
        );
        assert_eq!(grant[tlv + 11], 1, "renewal invited");
        assert_eq!(
            &grant[ptp::HEADER_LEN..ptp::HEADER_LEN + 8],
            &0xABu64.to_be_bytes()
        );
        assert!(unicast_grant(CLOCK, &signaling(0xAB, 1)).is_none());
    }
}
