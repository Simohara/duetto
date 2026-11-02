//! Respond to encrypted AirPlay event requests without blocking the audio sender.
use cidermill_airplay::{
    rtsp::{Decoder, Response},
    session::EventChannel,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Route keys whose receiver reported a volume change made elsewhere.
static VOLUME_CHANGED: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Tests that read the shared list take this lock first.
#[cfg(test)]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());
pub fn report_volume_change(host: &str) {
    VOLUME_CHANGED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(host.to_owned());
}
pub fn take_volume_changes() -> Vec<String> {
    std::mem::take(&mut *VOLUME_CHANGED.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Records a level just sent to the receiver in `sent`. The level sent before
/// it is kept too, as its echo may arrive after the next SET_PARAMETER.
pub fn note_sent(sent: &AtomicU32, level: u32) {
    let previous = sent.load(Ordering::Acquire) & 0xff;
    sent.store(previous << 8 | level.min(100), Ordering::Release);
}
/// Whether `db` lies within 0.5 dB of the span of the last two levels sent.
fn is_echo(sent: u32, db: f64) -> bool {
    let a = crate::receiver_db(sent & 0xff);
    let b = crate::receiver_db(sent >> 8 & 0xff);
    db >= a.min(b) - 0.5 && db <= a.max(b) + 0.5
}

struct Responder {
    decoder: Decoder,
    /// The last two levels this app sent, packed by `note_sent`.
    sent: Arc<AtomicU32>,
    warned: bool,
}
impl Responder {
    fn new(sent: Arc<AtomicU32>) -> Self {
        let mut decoder = Decoder::new();
        decoder.set_max_body(256 * 1024);
        Self {
            decoder,
            sent,
            warned: false,
        }
    }
    fn feed(&mut self, host: &str, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.decoder.push(data);
        if self.decoder.buffered() > 512 * 1024 {
            return Err("音响事件数据过大".into());
        }
        let mut responses = Vec::new();
        while let Some(request) = self
            .decoder
            .next_request()
            .map_err(|_| "音响事件格式无效")?
        {
            // Receivers announce why they end a session here; keep a record.
            crate::diagnostics::record_error(&format!(
                "音响 {host} 事件 {} {} {}",
                request.method,
                request.uri,
                describe(&request.body)
            ));
            // Warn once; the echo of our own SET_PARAMETER is not a change.
            if !self.warned
                && let Some(reported) = volume_change(&request.body)
                && reported.is_none_or(|db| !is_echo(self.sent.load(Ordering::Acquire), db))
            {
                report_volume_change(host);
                self.warned = true;
            }
            let mut response = Response::new(request.protocol, 200, "OK", Vec::new());
            response.headers.set("Content-Length", "0");
            response.headers.set("Audio-Latency", "0");
            for name in ["Server", "CSeq"] {
                if let Some(value) = request.headers.get(name) {
                    response.headers.set(name, value);
                }
            }
            responses.push(response.encode());
        }
        Ok(responses)
    }
}

/// Scalar plist fields only, two levels deep; data blobs are never logged.
fn describe(body: &[u8]) -> String {
    fn value(v: &plist::Value, depth: u8) -> String {
        match v {
            plist::Value::String(s) => s.chars().take(64).collect(),
            plist::Value::Integer(i) => i.to_string(),
            plist::Value::Real(r) => r.to_string(),
            plist::Value::Boolean(b) => b.to_string(),
            plist::Value::Dictionary(d) if depth > 0 => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{k}={}", value(v, depth - 1)))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            plist::Value::Array(a) => format!("[{} 项]", a.len()),
            plist::Value::Data(d) => format!("<{} 字节>", d.len()),
            _ => "…".into(),
        }
    }
    if body.is_empty() {
        return String::new();
    }
    match plist::Value::from_reader(std::io::Cursor::new(body)) {
        Ok(v) => value(&v, 2),
        Err(_) => format!("<{} 字节>", body.len()),
    }
}

/// A `dvlc` marker (as a string value or a key) in a dictionary up to two
/// levels deep, with the sibling `volume` in dB when the receiver sends one.
fn volume_change(body: &[u8]) -> Option<Option<f64>> {
    fn find(d: &plist::Dictionary, depth: u8) -> Option<Option<f64>> {
        let dvlc = |s: &str| s.eq_ignore_ascii_case("dvlc");
        if d.iter()
            .any(|(k, v)| dvlc(k) || v.as_string().is_some_and(dvlc))
        {
            return Some(d.get("volume").and_then(|v| {
                v.as_real()
                    .or_else(|| v.as_signed_integer().map(|i| i as f64))
            }));
        }
        if depth == 0 {
            return None;
        }
        d.values()
            .filter_map(plist::Value::as_dictionary)
            .find_map(|d| find(d, depth - 1))
    }
    let value = plist::Value::from_reader(std::io::Cursor::new(body)).ok()?;
    find(value.as_dictionary()?, 1)
}

pub struct EventPump {
    stop: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
}
impl EventPump {
    /// `host` labels this receiver's events in the diagnostics log; `sent`
    /// holds the levels this app sent (`note_sent`), to tell their echo from
    /// an outside change.
    pub fn start(mut channel: EventChannel, host: String, sent: Arc<AtomicU32>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let error = Arc::new(Mutex::new(None));
        let quit = stop.clone();
        let failure = error.clone();
        let handle = thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut responder = Responder::new(sent);
            while !quit.load(Ordering::Acquire) {
                let result = (|| -> Result<(), String> {
                    let data = channel
                        .poll()
                        .map_err(|e| format!("事件通道读取失败：{e}"))?;
                    for reply in responder.feed(&host, &data)? {
                        channel
                            .respond(&reply)
                            .map_err(|e| format!("事件通道回复失败：{e}"))?;
                    }
                    if let Some(reason) = channel.failure() {
                        return Err(format!("事件通道关闭：{reason}"));
                    }
                    Ok(())
                })();
                if let Err(message) = result {
                    if !quit.load(Ordering::Acquire) {
                        *failure.lock().unwrap() = Some(format!(
                            "事件通道建立后 {:.1} 秒：{message}",
                            started.elapsed().as_secs_f64()
                        ));
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        Self {
            stop,
            error,
            handle: Some(handle),
        }
    }
    pub fn failure(&self) -> Option<String> {
        self.error.lock().ok().and_then(|v| v.clone())
    }
}
impl Drop for EventPump {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_summary_keeps_scalars_and_hides_blobs() {
        let mut inner = plist::Dictionary::new();
        inner.insert("reason".into(), plist::Value::String("other".into()));
        inner.insert("key".into(), plist::Value::Data(vec![7; 32]));
        let mut body = plist::Dictionary::new();
        body.insert("type".into(), plist::Value::String("sessionEnded".into()));
        body.insert("value".into(), plist::Value::Dictionary(inner));
        let mut bytes = Vec::new();
        plist::Value::Dictionary(body)
            .to_writer_binary(&mut bytes)
            .unwrap();
        assert_eq!(
            describe(&bytes),
            "{type=sessionEnded value={reason=other key=<32 字节>}}"
        );
        assert_eq!(describe(b"junk"), "<4 字节>");
    }
    fn plist(entries: Vec<(&str, plist::Value)>) -> plist::Value {
        plist::Value::Dictionary(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }
    fn binary(value: plist::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        value.to_writer_binary(&mut bytes).unwrap();
        bytes
    }
    fn dvlc(volume: f64) -> Vec<u8> {
        binary(plist(vec![
            ("value", plist::Value::String("dvlc".into())),
            ("volume", plist::Value::Real(volume)),
        ]))
    }
    #[test]
    fn volume_changes_are_recognised() {
        assert_eq!(volume_change(&dvlc(-12.0)), Some(Some(-12.0)));
        let nested = plist(vec![
            ("type", plist::Value::String("x".into())),
            (
                "params",
                plist(vec![("value", plist::Value::String("DVLC".into()))]),
            ),
        ]);
        assert_eq!(volume_change(&binary(nested)), Some(None));
        let keyed = plist(vec![("dvlc", plist::Value::Integer((-7).into()))]);
        assert_eq!(volume_change(&binary(keyed)), Some(None));
        let ended = plist(vec![
            ("type", plist::Value::String("sessionEnded".into())),
            (
                "value",
                plist(vec![("reason", plist::Value::String("other".into()))]),
            ),
        ]);
        assert_eq!(volume_change(&binary(ended)), None);
        assert_eq!(volume_change(b"junk"), None);
        assert_eq!(volume_change(b""), None);
    }
    #[test]
    fn an_outside_volume_change_is_reported_once() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        take_volume_changes();
        let host = "192.0.2.51:7000";
        let request = |body: &[u8]| {
            let mut data = format!(
                "POST /command HTTP/1.1\r\nCSeq: 5\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            data.extend_from_slice(body);
            data
        };
        // 35 is -19.5 dB: the echo of our own SET_PARAMETER.
        let mut r = Responder::new(Arc::new(AtomicU32::new(35 * 0x101)));
        assert_eq!(r.feed(host, &request(&dvlc(-19.5))).unwrap().len(), 1);
        assert!(take_volume_changes().is_empty());
        for _ in 0..2 {
            let replies = r.feed(host, &request(&dvlc(-10.0))).unwrap();
            assert!(String::from_utf8_lossy(&replies[0]).starts_with("HTTP/1.1 200 OK\r\n"));
        }
        assert_eq!(take_volume_changes(), vec![host.to_owned()]);
    }
    #[test]
    fn echoes_of_the_last_two_levels_sent_are_not_outside_changes() {
        let sent = AtomicU32::new(35 * 0x101);
        // A slider drag: 40 (-18 dB) is sent, then 50 (-15 dB) before its echo.
        note_sent(&sent, 40);
        note_sent(&sent, 50);
        let sent = sent.load(Ordering::Acquire);
        assert!(is_echo(sent, -18.0) && is_echo(sent, -16.5) && is_echo(sent, -15.2));
        assert!(!is_echo(sent, -19.5) && !is_echo(sent, -10.0));
    }
    #[test]
    fn fragmented_and_multiple_requests_are_answered() {
        let mut r = Responder::new(Arc::new(AtomicU32::new(35)));
        assert!(
            r.feed(
                "test",
                b"POST /command HTTP/1.1\r\nCSeq: 17\r\nServer: HomePod\r\nContent-Len"
            )
            .unwrap()
            .is_empty()
        );
        let result = r
            .feed(
                "test",
                b"gth: 3\r\n\r\nabcPOST /event RTSP/1.0\r\nCSeq: 18\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        assert_eq!(result.len(), 2);
        let first = String::from_utf8(result[0].clone()).unwrap();
        assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(first.contains("CSeq: 17\r\n"));
        assert!(first.contains("Server: HomePod\r\n"));
        assert!(first.contains("Audio-Latency: 0\r\n"));
        let second = String::from_utf8(result[1].clone()).unwrap();
        assert!(second.starts_with("RTSP/1.0 200 OK\r\n"));
        assert!(second.contains("CSeq: 18\r\n"));
    }
    #[test]
    fn encrypted_socket_receives_correlated_response() {
        use cidermill_airplay::pairing::SessionKeys;
        use std::{
            io::{Read, Write},
            net::TcpListener,
            time::Duration,
        };
        let keys = SessionKeys {
            shared_secret: vec![0x37; 32],
            write_key: [0x11; 32],
            read_key: [0x22; 32],
        };
        let peer = keys.event_keys().unwrap().reversed();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut transport = peer.transport();
            let data = transport
                .seal(b"POST /command HTTP/1.1\r\nCSeq: 27\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            let split = data.len() / 2;
            socket.write_all(&data[..split]).unwrap();
            std::thread::sleep(Duration::from_millis(10));
            socket.write_all(&data[split..]).unwrap();
            let mut buf = [0u8; 4096];
            loop {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                transport.push(&buf[..n]);
                if let Some(reply) = transport.open_next().unwrap() {
                    break String::from_utf8(reply).unwrap();
                }
            }
        });
        let channel =
            EventChannel::connect("127.0.0.1", port, &keys, Duration::from_secs(3)).unwrap();
        let pump = EventPump::start(channel, "test".into(), Arc::new(AtomicU32::new(35)));
        let response = server.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("CSeq: 27\r\n"));
        drop(pump);
    }
}
