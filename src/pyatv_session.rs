//! pyatv 0.18.0 AirPlayV2._setup_base and setup_audio_stream compatibility.
//! The base dictionary and audio-key derivation follow the Python implementation;
//! NTP and event sockets keep their independent readers throughout playback.
use cidermill_airplay::{
    AirPlayError, ControlChannel, OsRng, Result,
    session::{EventChannel, SetupParams, SetupResponse},
    timing::TimingServer,
};
use plist::{Dictionary, Value};
use std::sync::Arc;

pub struct Session {
    pub events: Option<EventChannel>,
    _timing: TimingServer,
}

fn setup_body(timing_port: u16, session_uuid: &str) -> Result<Vec<u8>> {
    let mut body = Dictionary::new();
    for (key, value) in [
        ("deviceID", "AA:BB:CC:DD:EE:FF"),
        ("sessionUUID", session_uuid),
        ("timingProtocol", "NTP"),
        ("macAddress", "AA:BB:CC:DD:EE:FF"),
        ("model", "iPhone14,3"),
        ("name", "pyatv"),
        ("osBuildVersion", "20F66"),
        ("osName", "iPhone OS"),
        ("osVersion", "16.5"),
        ("sourceVersion", "690.7.1"),
    ] {
        body.insert(key.into(), Value::String(value.into()));
    }
    body.insert("timingPort".into(), Value::Integer(timing_port.into()));
    for (key, value) in [
        ("isMultiSelectAirPlay", true),
        ("groupContainsGroupLeader", false),
        ("senderSupportsRelay", false),
        ("statsCollectionEnabled", false),
    ] {
        body.insert(key.into(), Value::Boolean(value));
    }
    let mut encoded = Vec::new();
    Value::Dictionary(body)
        .to_writer_binary(&mut encoded)
        .map_err(|error| AirPlayError::Protocol(format!("无法编码会话 SETUP：{error}")))?;
    Ok(encoded)
}

pub fn start(channel: &mut ControlChannel) -> Result<Session> {
    let timing = TimingServer::start_on(
        channel.connection().local_ip(),
        Arc::new(crate::playback_clock::ntp_now),
    )?;
    let uuid = cidermill_airplay::util::uuid_v4(&mut OsRng).to_uppercase();
    // Keep the existing RTSP/session headers and replace only the dictionary.
    let params = SetupParams::new("AA:BB:CC:DD:EE:FF".into(), uuid.clone(), "pyatv".into());
    let mut request = channel.connection().setup_request(&params)?;
    request.headers.set("User-Agent", "AirPlay/550.10");
    request.body = setup_body(timing.port(), &uuid)?;
    let reply = channel.request(request)?;
    if !reply.is_success() {
        return Err(AirPlayError::Status {
            path: "SETUP".into(),
            code: reply.status,
            reason: None,
        });
    }
    let opened = SetupResponse::parse(&reply.body).and_then(|setup| {
        if setup.event_port == 0 {
            Ok(None)
        } else {
            channel.open_event_channel(setup.event_port).map(Some)
        }
    });
    match opened {
        Ok(events) => Ok(Session {
            events,
            _timing: timing,
        }),
        Err(error) => {
            let _ = channel.teardown();
            Err(error)
        }
    }
}

/// Python derives the audio `shk` with Events-Write-Encryption-Key. The crate's
/// event transport crosses the labels, so this is its event *read* key.
pub fn audio_key(channel: &ControlChannel) -> Result<[u8; 32]> {
    let keys = channel
        .session_keys()
        .ok_or_else(|| AirPlayError::InvalidState("音频流需要已经验证的会话密钥".into()))?;
    Ok(keys.event_keys()?.read)
}

/// The empty HTTP request pyatv sends before transient M1. It is not the PIN-3
/// request used for persistent pairing, and does not add iPhone-only headers.
pub fn transient_pin_start(channel: &mut ControlChannel) -> Result<()> {
    use cidermill_airplay::rtsp::{Protocol, Request};
    let mut request = Request::new("POST", "/pair-pin-start", Protocol::Http, Vec::new());
    request.headers.set("User-Agent", "AirPlay/320.20");
    request.headers.set("Connection", "keep-alive");
    request.headers.set("X-Apple-HKP", "4");
    request
        .headers
        .set("Content-Type", "application/octet-stream");
    let response = channel.request(request)?;
    if !response.is_success() {
        return Err(AirPlayError::Status {
            path: "/pair-pin-start".into(),
            code: response.status,
            reason: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_style_matches_python_m1_and_header_flags() {
        use cidermill_airplay::pairing::{PairSetup, TransientStyle};
        let style = TransientStyle::Pyatv;
        assert_eq!(style.hkp(), "4");
        assert_eq!(style.content_type(), "application/octet-stream");
        assert!(!style.sends_pd());
        assert!(!style.sends_absolute_time());
        assert!(style.verify_probe_hkps().is_empty());
        let mut setup = PairSetup::transient(style, &mut OsRng);
        assert_eq!(
            setup.start().unwrap().encode(),
            [0, 1, 0, 6, 1, 1, 19, 1, 16]
        );
    }

    #[test]
    fn audio_stream_key_matches_python_hkdf_vector() {
        use cidermill_airplay::pairing::SessionKeys;
        let keys = SessionKeys::derive(&(0u8..32).collect::<Vec<_>>(), b"x", b"y", b"z").unwrap();
        // Actual pyatv.auth.hap_srp.hkdf_expand output for bytes(range(32)).
        let expected = [
            0x24, 0xee, 0x7b, 0xb1, 0xf7, 0x75, 0xcc, 0x08, 0xcc, 0x23, 0xe2, 0x5b, 0xee, 0x48,
            0xaf, 0xa4, 0x39, 0x25, 0x02, 0x99, 0xbc, 0x76, 0x54, 0x9e, 0x80, 0xc0, 0xb5, 0x4d,
            0x9c, 0xc6, 0x0b, 0x61,
        ];
        assert_eq!(keys.event_keys().unwrap().read, expected);
    }

    #[test]
    fn base_setup_matches_dictionary_captured_from_pyatv_018() {
        // Generated by executing the installed AirPlayV2._setup_base with a
        // capturing rtsp.setup, mocked verify_connection and fixed uuid4.
        let hex = "62706c6973743030df100f0102030405060708090a0b0c0d0e0f101112101314151617111819111a1b5864657669636549445f101867726f7570436f6e7461696e7347726f75704c65616465725f101469734d756c746953656c656374416972506c61795a6d616341646472657373556d6f64656c546e616d655e6f734275696c6456657273696f6e566f734e616d65596f7356657273696f6e5f101373656e646572537570706f72747352656c61795b73657373696f6e555549445d736f7572636556657273696f6e5f10167374617473436f6c6c656374696f6e456e61626c65645a74696d696e67506f72745e74696d696e6750726f746f636f6c5f101141413a42423a43433a44443a45453a464608095a6950686f6e6531342c33557079617476553230463636596950686f6e65204f535431362e355f102431323334353637382d313233342d313233342d313233342d313233343536373839414243573639302e372e31113039534e5450000800290032004d0064006f0075007a00890090009a00b000bc00ca00e300ee00fd011101120113011e0124012a0134013901600168016b0000000000000201000000000000001c0000000000000000000000000000016f";
        let captured: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let reference = Value::from_reader(std::io::Cursor::new(captured)).unwrap();
        let actual = Value::from_reader(std::io::Cursor::new(
            setup_body(12345, "12345678-1234-1234-1234-123456789ABC").unwrap(),
        ))
        .unwrap();
        assert_eq!(actual, reference);
    }
}
