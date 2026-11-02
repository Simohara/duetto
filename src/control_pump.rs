//! Nonblocking RTSP exchange, matching pyatv's CSeq-dispatched request tasks.
//!
//! Pairing and session setup stay in the protocol library. Once those finish,
//! this pump takes the exact TCP stream and encrypted connection state. Waiting
//! for feedback or a volume reply never waits on the audio-sending thread.
use cidermill_airplay::{AirPlayError, ControlChannel, Request, Response, SenderConnection};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 16;
const MAX_OUTBOUND_BYTES: usize = 256 * 1024;
const IO_BUDGET: usize = 64 * 1024;

#[derive(Debug)]
pub struct RequestTimeout {
    pub cseq: u32,
}
impl fmt::Display for RequestTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "控制请求 CSeq {} 等待回复超时", self.cseq)
    }
}
impl std::error::Error for RequestTimeout {}

pub struct Completion {
    pub cseq: u32,
    pub result: Result<Response, RequestTimeout>,
}

struct Pending {
    started: Instant,
    deadline: Instant,
    // Only method is retained: never keep/log credentials or request bodies.
    method: String,
}
struct Outbound {
    bytes: Vec<u8>,
    offset: usize,
}

pub struct ControlPump {
    stream: TcpStream,
    connection: SenderConnection,
    pending: BTreeMap<u32, Pending>,
    outbound: VecDeque<Outbound>,
    outbound_bytes: usize,
}

impl ControlPump {
    pub fn new(channel: ControlChannel<TcpStream>) -> Result<Self, AirPlayError> {
        let (stream, connection) = channel.into_parts();
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            connection,
            pending: BTreeMap::new(),
            outbound: VecDeque::new(),
            outbound_bytes: 0,
        })
    }

    /// Queue a session request. The CSeq is allocated by the existing encrypted
    /// connection; pairing's counters and keys are not reset or duplicated.
    pub fn submit(&mut self, request: Request, timeout: Duration) -> Result<u32, AirPlayError> {
        if self.pending.len() >= MAX_PENDING {
            return Err(AirPlayError::Protocol(
                "too many pending control requests".into(),
            ));
        }
        // Leave enough room for encryption framing before advancing counters.
        if self.outbound_bytes + request.body.len() + 4096 > MAX_OUTBOUND_BYTES {
            return Err(AirPlayError::Protocol("control send buffer is full".into()));
        }
        let method = request.method.clone();
        let cseq = self.connection.next_sequence();
        let request = self.connection.with_session_headers(request);
        let bytes = self.connection.encode(request)?;
        if self.outbound_bytes + bytes.len() > MAX_OUTBOUND_BYTES {
            // Cannot discard sealed bytes and continue with the nonce advanced.
            return Err(AirPlayError::Protocol(
                "encoded control request exceeds send cap".into(),
            ));
        }
        let started = Instant::now();
        self.pending.insert(
            cseq,
            Pending {
                started,
                deadline: started + timeout,
                method,
            },
        );
        self.outbound_bytes += bytes.len();
        self.outbound.push_back(Outbound { bytes, offset: 0 });
        Ok(cseq)
    }

    /// Bounded, nonblocking I/O. A deadline only ends that request, as in
    /// pyatv. TCP EOF, framing/decryption and actual socket errors are fatal.
    pub fn poll(&mut self) -> Result<Vec<Completion>, AirPlayError> {
        let mut budget = IO_BUDGET;
        while let Some(front) = self.outbound.front_mut() {
            if budget == 0 {
                break;
            }
            let count = (front.bytes.len() - front.offset).min(budget);
            match self
                .stream
                .write(&front.bytes[front.offset..front.offset + count])
            {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "control socket stopped writing",
                    )
                    .into());
                }
                Ok(written) => {
                    front.offset += written;
                    self.outbound_bytes -= written;
                    budget -= written;
                    if front.offset == front.bytes.len() {
                        self.outbound.pop_front();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let mut completions = Vec::new();
        self.drain_replies(&mut completions)?;
        let mut buffer = [0u8; 16 * 1024];
        let mut received = 0;
        while received < IO_BUDGET {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "receiver closed the control connection",
                    )
                    .into());
                }
                Ok(read) => {
                    received += read;
                    self.connection.push(&buffer[..read])?;
                    self.drain_replies(&mut completions)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&cseq, request)| (now >= request.deadline).then_some(cseq))
            .collect();
        for cseq in expired {
            self.pending.remove(&cseq);
            self.connection.forget_response(cseq);
            completions.push(Completion {
                cseq,
                result: Err(RequestTimeout { cseq }),
            });
        }
        Ok(completions)
    }

    fn drain_replies(&mut self, completions: &mut Vec<Completion>) -> Result<(), AirPlayError> {
        while let Some(response) = self.connection.next_response_unordered()? {
            // Unknown/late replies are consumed, never assigned to the latest
            // request. In particular, old feedback cannot acknowledge volume.
            if let Some(cseq) = response.sequence() {
                if self.pending.remove(&cseq).is_some() {
                    completions.push(Completion {
                        cseq,
                        result: Ok(response),
                    });
                }
            }
        }
        Ok(())
    }

    /// Bounded local diagnostics without URI/body/header authentication data.
    pub fn status(&self) -> String {
        self.pending
            .iter()
            .map(|(cseq, pending)| {
                format!(
                    "{} CSeq {} 等待 {:.0} ms",
                    pending.method,
                    cseq,
                    pending.started.elapsed().as_secs_f64() * 1000.0
                )
            })
            .collect::<Vec<_>>()
            .join("；")
    }
}

impl Drop for ControlPump {
    fn drop(&mut self) {
        // No worker join or graceful-read wait: cancellation closes promptly.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cidermill_airplay::{OsRng, Protocol, rtsp::Decoder};
    use std::{
        net::{TcpListener, UdpSocket},
        sync::mpsc,
        thread,
    };

    fn pair() -> (ControlPump, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let connection =
            SenderConnection::new("127.0.0.1", client.local_addr().unwrap().ip(), &mut OsRng);
        (
            ControlPump::new(ControlChannel::from_stream(client, connection)).unwrap(),
            server,
        )
    }
    fn request(uri: &str) -> Request {
        Request::new("POST", uri, Protocol::Rtsp, vec![])
    }

    #[test]
    fn transient_pairing_wire_matches_pyatv_http_header_shape() {
        use cidermill_airplay::{Tlv8, client::PairingHeaders};
        let mut connection =
            SenderConnection::new("127.0.0.1", "127.0.0.1".parse().unwrap(), &mut OsRng);
        let headers = PairingHeaders {
            hkp: "4".into(),
            content_type: "application/octet-stream",
            pd: false,
            absolute_time: false,
        };
        let request = connection.pairing_request("/pair-setup", &Tlv8::new(), &headers);
        let wire = String::from_utf8(connection.encode(request).unwrap()).unwrap();
        assert!(wire.starts_with("POST /pair-setup HTTP/1.1\r\n"));
        assert!(wire.contains("User-Agent: AirPlay/320.20\r\n"));
        assert!(wire.contains("X-Apple-HKP: 4\r\n"));
        assert!(wire.contains("Connection: keep-alive\r\n"));
        assert!(!wire.contains("CSeq:"));
        assert!(!wire.contains("X-Apple-PD:"));
        assert!(!wire.contains("X-Apple-AbsoluteTime:"));
        assert!(!wire.contains("X-Apple-Client-Name:"));
    }
    fn receive(server: &mut TcpStream, decoder: &mut Decoder) -> Request {
        let mut bytes = [0; 4096];
        loop {
            if let Some(request) = decoder.next_request().unwrap() {
                return request;
            }
            let read = server.read(&mut bytes).unwrap();
            assert_ne!(read, 0);
            decoder.push(&bytes[..read]);
        }
    }
    fn reply(server: &mut TcpStream, cseq: u32, status: u16) {
        let mut response = Response::new(Protocol::Rtsp, status, "test", vec![]);
        response.headers.set("CSeq", cseq.to_string());
        server.write_all(&response.encode()).unwrap();
    }

    #[test]
    fn delayed_feedback_does_not_pause_udp_audio_for_a_second() {
        let (mut pump, mut server) = pair();
        let (finish, finished) = mpsc::channel();
        let peer = thread::spawn(move || {
            let incoming = receive(&mut server, &mut Decoder::new());
            let cseq = incoming.headers.get("CSeq").unwrap().parse().unwrap();
            thread::sleep(Duration::from_secs(1));
            reply(&mut server, cseq, 200);
            finished.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let cseq = pump
            .submit(request("/feedback"), Duration::from_secs(3))
            .unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(listener.local_addr().unwrap()).unwrap();
        let started = Instant::now();
        let mut packets = 0u32;
        loop {
            let events = pump.poll().unwrap();
            if let Some(event) = events.into_iter().next() {
                assert_eq!(event.cseq, cseq);
                assert_eq!(event.result.unwrap().status, 200);
                break;
            }
            sender.send(&packets.to_be_bytes()).unwrap();
            let mut packet = [0; 4];
            assert_eq!(listener.recv(&mut packet).unwrap(), 4);
            assert_eq!(u32::from_be_bytes(packet), packets);
            packets += 1;
            assert!(started.elapsed() < Duration::from_secs(3));
            thread::sleep(Duration::from_millis(8));
        }
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert!(
            packets >= 30,
            "audio must keep progressing while feedback waits"
        );
        finish.send(()).unwrap();
        peer.join().unwrap();
    }

    #[test]
    fn timed_out_feedback_and_late_reply_cannot_acknowledge_volume() {
        let (mut pump, mut server) = pair();
        let (finish, finished) = mpsc::channel();
        let peer = thread::spawn(move || {
            let mut decoder = Decoder::new();
            let feedback = receive(&mut server, &mut decoder);
            let volume = receive(&mut server, &mut decoder);
            // The newer volume reply may arrive first, like pyatv permits.
            reply(
                &mut server,
                volume.headers.get("CSeq").unwrap().parse().unwrap(),
                204,
            );
            reply(
                &mut server,
                feedback.headers.get("CSeq").unwrap().parse().unwrap(),
                200,
            );
            finished.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let old = pump
            .submit(request("/feedback"), Duration::from_millis(20))
            .unwrap();
        let started = Instant::now();
        loop {
            let events = pump.poll().unwrap();
            if let Some(event) = events.into_iter().next() {
                assert_eq!(event.cseq, old);
                assert!(event.result.is_err());
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(2));
        }
        let new = pump
            .submit(request("/volume"), Duration::from_secs(2))
            .unwrap();
        loop {
            let events = pump.poll().unwrap();
            if let Some(event) = events.into_iter().next() {
                assert_eq!(event.cseq, new);
                assert_eq!(event.result.unwrap().status, 204);
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(2));
        }
        finish.send(()).unwrap();
        peer.join().unwrap();
    }

    #[test]
    fn dropping_pending_control_does_not_wait_for_a_reply() {
        let (mut pump, mut server) = pair();
        pump.submit(request("/feedback"), Duration::from_secs(10))
            .unwrap();
        pump.poll().unwrap();
        receive(&mut server, &mut Decoder::new());
        let started = Instant::now();
        drop(pump);
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn non_success_feedback_is_a_reply_and_eof_is_a_transport_error() {
        let (mut pump, mut server) = pair();
        let cseq = pump
            .submit(request("/feedback"), Duration::from_secs(2))
            .unwrap();
        pump.poll().unwrap();
        receive(&mut server, &mut Decoder::new());
        reply(&mut server, cseq, 500);
        let started = Instant::now();
        loop {
            if let Some(event) = pump.poll().unwrap().into_iter().next() {
                assert_eq!(event.result.unwrap().status, 500);
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(2));
        }
        drop(server);
        let started = Instant::now();
        while pump.poll().is_ok() {
            assert!(started.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn switching_to_pump_preserves_existing_encryption_counters() {
        use cidermill_airplay::{cipher::EncryptedTransport, pairing::SessionKeys};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let keys = SessionKeys {
            shared_secret: vec![],
            write_key: [17; 32],
            read_key: [29; 32],
        };
        let mut connection =
            SenderConnection::new("127.0.0.1", client.local_addr().unwrap().ip(), &mut OsRng);
        connection.enable_encryption(&keys).unwrap();
        let mut channel = ControlChannel::from_stream(client, connection);
        let (finish, finished) = mpsc::channel();
        let peer = thread::spawn(move || {
            let mut encryption = EncryptedTransport::from_keys(&keys.read_key, &keys.write_key);
            let mut decoder = Decoder::new();
            for _ in 0..2 {
                let incoming = loop {
                    if let Some(request) = decoder.next_request().unwrap() {
                        break request;
                    }
                    let mut buffer = [0u8; 4096];
                    let read = server.read(&mut buffer).unwrap();
                    assert_ne!(read, 0);
                    encryption.push(&buffer[..read]);
                    while let Some(bytes) = encryption.open_next().unwrap() {
                        decoder.push(&bytes);
                    }
                };
                let mut response = Response::new(Protocol::Rtsp, 200, "OK", vec![]);
                response
                    .headers
                    .set("CSeq", incoming.headers.get("CSeq").unwrap());
                server
                    .write_all(&encryption.seal(&response.encode()).unwrap())
                    .unwrap();
            }
            finished.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        // Advance both encryption directions and CSeq before handing over.
        channel.session_request(request("/initial")).unwrap();
        let mut pump = ControlPump::new(channel).unwrap();
        let cseq = pump
            .submit(request("/feedback"), Duration::from_secs(2))
            .unwrap();
        let started = Instant::now();
        loop {
            if let Some(event) = pump.poll().unwrap().into_iter().next() {
                assert_eq!(event.cseq, cseq);
                assert_eq!(event.result.unwrap().status, 200);
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(2));
        }
        finish.send(()).unwrap();
        peer.join().unwrap();
    }
}
